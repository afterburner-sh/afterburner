// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Animated install progress for `burn install`'s concurrent fetch pool.
//!
//! The [`Progress`] hooks (called from worker threads) only push events onto a
//! `kovan_channel`; a single [`Renderer`] thread drains them and repaints one
//! sunburst-gradient bar on stderr. No `Mutex`, and workers never touch the
//! terminal. Silent when animation is off (non-TTY / `NO_COLOR`).

use crate::cli::style;
use afterburner_cloud::{Outcome, Progress};
use kovan_channel::flavors::unbounded::{Receiver, Sender, channel};
use std::io::Write;
use std::time::Duration;

enum Ev {
    Begin(usize),
    Started(String),
    Done,
    Finish,
}

/// The progress sink handed to `install_concurrent`.
pub struct InstallProgress {
    tx: Option<Sender<Ev>>,
}

/// Owns the receiver and the terminal; runs on its own thread until `finish`.
pub struct Renderer {
    rx: Receiver<Ev>,
}

impl InstallProgress {
    /// The sink plus its render driver. When animation is off the driver is
    /// `None` and every hook is a no-op.
    pub fn new() -> (Self, Option<Renderer>) {
        if !style::animations_enabled() {
            return (Self { tx: None }, None);
        }
        let (tx, rx) = channel();
        (Self { tx: Some(tx) }, Some(Renderer { rx }))
    }

    fn emit(&self, ev: Ev) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(ev);
        }
    }
}

impl Progress for InstallProgress {
    fn begin(&self, total: usize) {
        self.emit(Ev::Begin(total));
    }
    fn started(&self, coord: &str) {
        self.emit(Ev::Started(coord.to_string()));
    }
    fn done(&self, _coord: &str, _outcome: &Outcome) {
        self.emit(Ev::Done);
    }
    fn failed(&self, _coord: &str, _err: &str) {
        self.emit(Ev::Done);
    }
    fn finish(&self) {
        self.emit(Ev::Finish);
    }
}

impl Renderer {
    pub fn run(self) {
        use crossterm::{cursor, execute, terminal};
        let mut err = std::io::stderr();
        let _ = execute!(err, cursor::Hide);

        let (mut total, mut done, mut current) = (0usize, 0usize, String::new());
        let mut frame = 0usize;
        let mut finished = false;
        while !finished {
            while let Some(ev) = self.rx.try_recv() {
                match ev {
                    Ev::Begin(t) => total = t,
                    Ev::Started(c) => current = c,
                    Ev::Done => done += 1,
                    Ev::Finish => finished = true,
                }
            }
            paint(&mut err, total, done, &current, frame);
            if finished {
                break;
            }
            frame += 1;
            std::thread::sleep(Duration::from_millis(80));
        }

        let _ = execute!(
            err,
            cursor::MoveToColumn(0),
            terminal::Clear(terminal::ClearType::CurrentLine),
            cursor::Show
        );
        let _ = err.flush();
    }
}

fn paint(err: &mut impl Write, total: usize, done: usize, current: &str, frame: usize) {
    use crossterm::{cursor, execute, terminal};
    let cols = terminal::size().map(|(c, _)| c as usize).unwrap_or(80);

    let ratio = if total == 0 { 0.0 } else { done as f32 / total as f32 };
    let bar_w = 24usize;
    let glyph = style::spinner_frame(frame);
    let bar = style::flame_bar(ratio, bar_w, -(frame as f32) * 0.06);
    let counts = format!("{done}/{total}");

    // Bound the label so the line never wraps (a wrap defeats the single-line
    // repaint): cols minus the fixed glyph + bar + counts + spacing.
    let fixed = 1 + 1 + (bar_w + 2) + 2 + counts.len() + 2;
    let label = truncate(current, cols.saturating_sub(fixed + 1));

    let line = format!("{glyph} {bar}  {}  {}", style::muted(&counts), style::value(&label));
    let _ = execute!(
        err,
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine)
    );
    let _ = write!(err, "{line}");
    let _ = err.flush();
}

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
