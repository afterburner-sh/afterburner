// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The colorful CLI sink for the runtime-bundle lazy fetch into `~/.burn`.
//!
//! `afterburner-wasi` performs the fetch and drives a [`BundleProgress`] sink
//! (one labeled line per runtime, byte-progress, then an assemble step). The
//! sink lives here, in the CLI crate, so it can reuse the brand styling in
//! [`crate::cli::style`] (the sunburst gradient bar + the shimmering spinner)
//! without `afterburner-wasi` depending on the CLI (that would be a circular
//! crate dependency).
//!
//! Like `cli::registry::progress`, the trait hooks (called from the fetch
//! thread) only push events onto a `kovan_channel`; a single background
//! [`Renderer`] thread drains them and repaints stderr, so the bar shimmers and
//! the spinner spins while a large download is mid-flight, and the fetch thread
//! never touches the terminal. Silent (a no-op) when animation is off (a
//! non-TTY stderr, `NO_COLOR`, `TERM=dumb`) - so pipes and CI logs stay clean.
//!
//! Installed process-globally via [`afterburner_wasi::bundle::set_progress_reporter`]
//! at the CLI entry, so EVERY runtime-resolve path the `burn` binary takes (a
//! `.py` / `.c` / `.rb` run, the REPL, a package run) renders the bar on a cold
//! cache. A library embed of `afterburner-wasi` installs nothing and gets the
//! silent default.

use crate::cli::style;
use afterburner_wasi::bundle::BundleProgress;
use kovan_channel::flavors::unbounded::{Receiver, Sender, channel};
use std::io::Write;
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::Duration;

/// Events the sink hooks push to the renderer thread.
enum Ev {
    /// A new bundle's download started: its label and the content length when
    /// the server reported one (`None` -> an indeterminate bar).
    Begin { label: String, total: Option<u64> },
    /// Cumulative bytes downloaded so far for the in-flight bundle.
    Bytes(u64),
    /// The download finished; the local assemble step (verify + translate +
    /// unpack) is running. Switches the line from the bar to the spinner.
    Assembling(String),
    /// This bundle is done (success or failure); clear the line.
    Finish,
}

/// The sink handed to `afterburner-wasi`. Hooks are cheap channel sends; when
/// animation is off the channel is absent and every hook is a no-op.
struct CliBundleProgress {
    tx: Option<Sender<Ev>>,
}

/// Install the colorful progress reporter process-globally, once. A no-op when
/// stderr is not an animated terminal (the reporter is then never created and
/// the fetch renders nothing). Idempotent: a second call does nothing.
pub fn install() {
    // The renderer thread handle is parked here so it is joined at process exit
    // implicitly (a detached daemon thread that exits when its channel closes);
    // we keep it alive for the process lifetime.
    static RENDERER: OnceLock<Option<JoinHandle<()>>> = OnceLock::new();

    if !style::animations_enabled() {
        // Leave the global reporter unset: the engine's NoProgress default
        // renders nothing, and we spawn no thread.
        return;
    }

    RENDERER.get_or_init(|| {
        let (tx, rx) = channel();
        let handle = std::thread::Builder::new()
            .name("burn-bundle-progress".to_string())
            .spawn(move || Renderer { rx }.run())
            .ok();
        afterburner_wasi::bundle::set_progress_reporter(Box::new(CliBundleProgress {
            tx: Some(tx),
        }));
        handle
    });
}

impl CliBundleProgress {
    fn emit(&self, ev: Ev) {
        if let Some(tx) = &self.tx {
            tx.send(ev);
        }
    }
}

impl BundleProgress for CliBundleProgress {
    fn begin(&self, label: &str, total: Option<u64>) {
        self.emit(Ev::Begin {
            label: label.to_string(),
            total,
        });
    }
    fn bytes(&self, downloaded: u64) {
        self.emit(Ev::Bytes(downloaded));
    }
    fn assembling(&self, label: &str) {
        self.emit(Ev::Assembling(label.to_string()));
    }
    fn finish(&self) {
        self.emit(Ev::Finish);
    }
}

/// Owns the receiver and the terminal; repaints one line at ~12 fps until the
/// channel closes (the process exits). One bundle is in flight at a time, so a
/// single line carries the current label + bar/spinner.
struct Renderer {
    rx: Receiver<Ev>,
}

/// The in-flight bundle's render state.
#[derive(Default)]
struct LineState {
    label: String,
    total: Option<u64>,
    downloaded: u64,
    /// True once the download is done and the local assemble step is running
    /// (the line shows the spinner, not the bar).
    assembling: bool,
    /// True between a `Begin` and its `Finish`: there is a line to paint.
    active: bool,
}

impl Renderer {
    fn run(self) {
        use crossterm::{cursor, execute, terminal};
        let mut err = std::io::stderr();
        let mut state = LineState::default();
        let mut frame = 0usize;
        let mut hidden_cursor = false;

        loop {
            // Drain every queued event so the bar reflects the latest byte count
            // (a fast link can enqueue many `Bytes` between repaints).
            let mut closed = false;
            loop {
                match self.rx.try_recv() {
                    Some(Ev::Begin { label, total }) => {
                        state = LineState {
                            label,
                            total,
                            downloaded: 0,
                            assembling: false,
                            active: true,
                        };
                        if !hidden_cursor {
                            let _ = execute!(err, cursor::Hide);
                            hidden_cursor = true;
                        }
                    }
                    Some(Ev::Bytes(n)) => state.downloaded = n,
                    Some(Ev::Assembling(label)) => {
                        state.label = label;
                        state.assembling = true;
                    }
                    Some(Ev::Finish) => {
                        // Clear the finished line; the next bundle opens a fresh one.
                        let _ = execute!(
                            err,
                            cursor::MoveToColumn(0),
                            terminal::Clear(terminal::ClearType::CurrentLine)
                        );
                        let _ = err.flush();
                        state.active = false;
                    }
                    None => {
                        // `try_recv` returns None on both "empty" and "closed".
                        // Distinguish: a disconnected sender means every Sender
                        // was dropped, which for our process-global reporter only
                        // happens at exit. We treat a None as "empty for now" and
                        // rely on the channel's closed signal below.
                        break;
                    }
                }
            }
            // Detect channel closure (all senders dropped) so the thread exits
            // at process teardown instead of spinning forever.
            if self.rx.is_disconnected() {
                closed = true;
            }

            if state.active {
                paint(&mut err, &state, frame);
                frame = frame.wrapping_add(1);
            }
            if closed {
                break;
            }
            std::thread::sleep(Duration::from_millis(80));
        }

        if hidden_cursor {
            let _ = execute!(err, cursor::Show);
            let _ = err.flush();
        }
    }
}

/// Repaint the current line: `<bar-or-spinner> <label> <bytes>`, gradient-styled.
fn paint(err: &mut impl Write, state: &LineState, frame: usize) {
    use crossterm::{cursor, execute, terminal};
    // `terminal::size()` can report 0 columns under a non-interactive PTY (e.g.
    // `script`); treat 0/unknown as 80 so the label is never truncated to
    // nothing. The bar is fixed-width, so only the label budget depends on this.
    let cols = match terminal::size() {
        Ok((c, _)) if c > 0 => c as usize,
        _ => 80,
    };
    let bar_w = 24usize;

    let lead = if state.assembling {
        // Local translate/unpack: an indeterminate spinner, no byte count.
        style::spinner_frame(frame)
    } else {
        // Download: a gradient bar driven by bytes / content-length. With no
        // content length, sweep an indeterminate shimmer so the user still sees
        // life (ratio cycles slowly rather than reading as a stuck 0%).
        let ratio = match state.total {
            Some(t) if t > 0 => state.downloaded as f32 / t as f32,
            _ => ((frame % 40) as f32 / 40.0).min(0.95),
        };
        style::flame_bar(ratio, bar_w, -(frame as f32) * 0.06)
    };

    let detail = if state.assembling {
        String::new()
    } else {
        match state.total {
            Some(t) if t > 0 => format!("  {}", style::muted(&human_pair(state.downloaded, t))),
            _ => format!("  {}", style::muted(&human_bytes(state.downloaded))),
        }
    };

    // Bound the label so the line never wraps (a wrap would break the in-place
    // repaint and leave orphaned fragments on the scrollback).
    let fixed = 1 + 1 + bar_w + 2 + detail.len() + 1;
    let label = truncate(&state.label, cols.saturating_sub(fixed));
    let line = format!("{lead} {}{detail}", style::value(&label));

    let _ = execute!(
        err,
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine)
    );
    let _ = write!(err, "{line}");
    let _ = err.flush();
}

/// `<downloaded> / <total>` in human units, e.g. `12.4 / 31.0 MiB`.
fn human_pair(downloaded: u64, total: u64) -> String {
    let (dv, du) = scale(downloaded);
    let (tv, tu) = scale(total);
    if du == tu {
        format!("{dv:.1} / {tv:.1} {tu}")
    } else {
        format!("{dv:.1} {du} / {tv:.1} {tu}")
    }
}

/// `<n>` in human units, e.g. `8.2 MiB` (used when no content length is known).
fn human_bytes(n: u64) -> String {
    let (v, u) = scale(n);
    format!("{v:.1} {u}")
}

/// Scale a byte count to the largest unit under 1024, returning the value and
/// its unit suffix. Binary units (MiB) to match disk-cache sizing.
fn scale(n: u64) -> (f64, &'static str) {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    (v, UNITS[i])
}

/// Truncate `s` to `max` display chars with a trailing ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 1 {
        return "…".to_string();
    }
    let kept: String = s.chars().take(max - 1).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_picks_binary_units() {
        assert_eq!(scale(512), (512.0, "B"));
        assert_eq!(scale(2048).1, "KiB");
        assert_eq!(scale(5 * 1024 * 1024).1, "MiB");
        assert_eq!(scale(3 * 1024 * 1024 * 1024).1, "GiB");
    }

    #[test]
    fn human_pair_collapses_matching_units() {
        // Same unit on both sides: the left value drops its suffix.
        let s = human_pair(12 * 1024 * 1024, 31 * 1024 * 1024);
        assert_eq!(s, "12.0 / 31.0 MiB");
    }

    #[test]
    fn truncate_bounds_width_and_adds_ellipsis() {
        assert_eq!(truncate("Fetching Python runtime", 8), "Fetchin…");
        assert_eq!(truncate("short", 20), "short");
        assert_eq!(truncate("x", 0), "");
    }
}
