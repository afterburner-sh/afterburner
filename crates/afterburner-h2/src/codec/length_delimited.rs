//! Splits a byte stream into HTTP/2 frames: a 3 byte big-endian payload length, then
//! the rest of the 9 byte frame header, then the payload. Each frame is returned whole
//! (header included).
//!
//! Invariants: the read buffer is reused across frames and holds at most one frame plus
//! one read chunk; a payload length over the configured maximum is rejected before any
//! of the payload is buffered.

use bytes::{Buf, BytesMut};
use futures_io::AsyncRead;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Bytes in the length field of a frame header
const LENGTH_FIELD_LEN: usize = 3;

/// Bytes in a whole frame header
const HEADER_LEN: usize = 9;

/// Bytes asked of the stream when more of a frame is needed
const READ_CHUNK: usize = 8 * 1024;

/// Largest payload accepted until `set_max_frame_length` says otherwise
const DEFAULT_MAX_FRAME_LENGTH: usize = 8 * 1024 * 1024;

/// A frame announced a payload longer than the maximum.
#[derive(Debug)]
pub(super) struct FrameTooLong;

impl std::fmt::Display for FrameTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("frame size too big")
    }
}

impl std::error::Error for FrameTooLong {}

#[derive(Debug)]
pub(super) struct FrameReader<T> {
    io: T,
    buf: BytesMut,
    max_frame_length: usize,
    /// Total size (header included) of the frame being read, once its header is in
    pending: Option<usize>,
    errored: bool,
}

impl<T> FrameReader<T> {
    pub(super) fn new(io: T) -> Self {
        Self {
            io,
            buf: BytesMut::with_capacity(READ_CHUNK),
            max_frame_length: DEFAULT_MAX_FRAME_LENGTH,
            pending: None,
            errored: false,
        }
    }

    pub(super) fn get_ref(&self) -> &T {
        &self.io
    }

    pub(super) fn get_mut(&mut self) -> &mut T {
        &mut self.io
    }

    pub(super) fn max_frame_length(&self) -> usize {
        self.max_frame_length
    }

    pub(super) fn set_max_frame_length(&mut self, val: usize) {
        self.max_frame_length = val;
    }

    /// The next whole frame if the buffer holds one.
    fn decode(&mut self) -> io::Result<Option<BytesMut>> {
        let total = match self.pending {
            Some(total) => total,
            None => {
                if self.buf.len() < LENGTH_FIELD_LEN {
                    return Ok(None);
                }
                let len = usize::from(self.buf[0]) << 16
                    | usize::from(self.buf[1]) << 8
                    | usize::from(self.buf[2]);
                if len > self.max_frame_length {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, FrameTooLong));
                }
                let total = len + HEADER_LEN;
                self.buf.reserve(total.saturating_sub(self.buf.len()));
                self.pending = Some(total);
                total
            }
        };
        if self.buf.len() < total {
            return Ok(None);
        }
        self.pending = None;
        Ok(Some(self.buf.split_to(total)))
    }
}

impl<T: AsyncRead + Unpin> FrameReader<T> {
    /// The next frame, `None` at a clean end of the stream, an error for a stream that
    /// ends inside a frame. After an error the reader yields `None`.
    pub(super) fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<BytesMut>>> {
        loop {
            if self.errored {
                return Poll::Ready(None);
            }
            match self.decode() {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
                Ok(None) => {}
                Err(e) => {
                    self.errored = true;
                    return Poll::Ready(Some(Err(e)));
                }
            }

            // vertexia: zero-fills the read window, a read into spare capacity if profiling shows it
            let start = self.buf.len();
            let want = self
                .pending
                .map_or(READ_CHUNK, |total| (total - start).max(READ_CHUNK));
            self.buf.resize(start + want, 0);
            let read = Pin::new(&mut self.io).poll_read(cx, &mut self.buf[start..]);
            let n = match read {
                Poll::Pending => {
                    self.buf.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.buf.truncate(start);
                    self.errored = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Ok(n)) => n,
            };
            self.buf.truncate(start + n);

            if n == 0 {
                self.errored = true;
                if self.buf.has_remaining() {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "bytes remaining on stream",
                    ))));
                }
                return Poll::Ready(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    /// A reader that hands out its bytes in fixed-size pieces.
    struct Pieces {
        data: Vec<u8>,
        piece: usize,
    }

    impl AsyncRead for Pieces {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.piece).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data.drain(..n);
            Poll::Ready(Ok(n))
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8];
        out.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        out.extend_from_slice(payload);
        out
    }

    fn collect(reader: &mut FrameReader<Pieces>) -> Vec<io::Result<BytesMut>> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut out = Vec::new();
        while let Poll::Ready(Some(item)) = reader.poll_frame(&mut cx) {
            out.push(item);
        }
        out
    }

    #[test]
    fn frames_split_at_any_read_size() {
        let mut data = frame(b"hello");
        data.extend(frame(b""));
        data.extend(frame(&[7u8; 20_000]));
        for piece in [1, 2, 9, 4096, usize::MAX] {
            let mut reader = FrameReader::new(Pieces {
                data: data.clone(),
                piece,
            });
            let frames: Vec<_> = collect(&mut reader)
                .into_iter()
                .map(|f| f.unwrap())
                .collect();
            assert_eq!(frames.len(), 3, "piece {piece}");
            assert_eq!(&frames[0][HEADER_LEN..], b"hello");
            assert_eq!(frames[1].len(), HEADER_LEN);
            assert_eq!(&frames[2][HEADER_LEN..], &[7u8; 20_000][..]);
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_the_payload() {
        let mut reader = FrameReader::new(Pieces {
            data: frame(&[0u8; 64]),
            piece: 4096,
        });
        reader.set_max_frame_length(63);
        let mut items = collect(&mut reader);
        assert_eq!(items.len(), 1);
        let err = items.remove(0).unwrap_err();
        assert!(err.get_ref().is_some_and(|e| e.is::<FrameTooLong>()));
    }

    #[test]
    fn a_stream_ending_inside_a_frame_is_an_error() {
        let mut data = frame(b"abcdef");
        data.truncate(data.len() - 2);
        let mut reader = FrameReader::new(Pieces { data, piece: 4096 });
        let items = collect(&mut reader);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].as_ref().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn a_stream_ending_between_frames_is_a_clean_end() {
        let mut reader = FrameReader::new(Pieces {
            data: frame(b"x"),
            piece: 4096,
        });
        let items = collect(&mut reader);
        assert_eq!(items.len(), 1);
        assert!(items[0].is_ok());
    }
}
