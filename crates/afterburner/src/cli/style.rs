// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Terminal styling + animation for the `burn` CLI.
//!
//! Colors come straight from the afterburner.sh design system — the *sunburst
//! flame* gradient (pink-red → orange → gold) plus the supporting teal / violet
//! / green. Everything degrades gracefully: when `NO_COLOR` is set, the stream
//! isn't a TTY, or `TERM=dumb`, styling and animation are skipped and plain
//! text is emitted, so pipes and CI logs stay clean.

use crossterm::style::{Color, Stylize};
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

// ── brand palette (afterburner.sh) ──────────────────────────────────────────

/// Sunburst gradient start — `rgb(255,46,84)` (`#ff2e54`).
pub const FLAME_RED: Color = Color::Rgb {
    r: 255,
    g: 46,
    b: 84,
};
/// Primary accent — vibrant orange `#ff6118`.
pub const ACCENT: Color = Color::Rgb {
    r: 255,
    g: 97,
    b: 24,
};
/// Sunburst gradient end — gold `#ffcf5e`.
pub const GOLD: Color = Color::Rgb {
    r: 255,
    g: 207,
    b: 94,
};
/// Logo green `#5ec34c` — success.
pub const SUCCESS: Color = Color::Rgb {
    r: 94,
    g: 195,
    b: 76,
};
/// Logo teal `#27c7c7` — values / identifiers.
pub const TEAL: Color = Color::Rgb {
    r: 39,
    g: 199,
    b: 199,
};
/// Ghost gray `#64748d` — muted / secondary text.
pub const MUTED: Color = Color::Rgb {
    r: 100,
    g: 116,
    b: 141,
};

/// The three sunburst stops, for gradient interpolation.
const SUNBURST: [(u8, u8, u8); 3] = [(255, 46, 84), (255, 122, 0), (255, 207, 94)];

/// Whether to emit ANSI styling at all. Cached: `NO_COLOR` off, `FORCE_COLOR`
/// on, `TERM != dumb`, and at least one of stdout/stderr is a TTY.
pub fn colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if std::env::var_os("FORCE_COLOR").is_some() {
            return true;
        }
        if matches!(std::env::var("TERM").as_deref(), Ok("dumb")) {
            return false;
        }
        std::io::stdout().is_terminal() || std::io::stderr().is_terminal()
    })
}

fn animations_enabled() -> bool {
    colors_enabled() && std::io::stderr().is_terminal()
}

fn paint(s: &str, c: Color) -> String {
    if colors_enabled() {
        s.with(c).to_string()
    } else {
        s.to_string()
    }
}

fn paint_bold(s: &str, c: Color) -> String {
    if colors_enabled() {
        s.with(c).bold().to_string()
    } else {
        s.to_string()
    }
}

// ── semantic text helpers ───────────────────────────────────────────────────

/// Primary accent, bold (headings, brand words).
pub fn accent(s: &str) -> String {
    paint_bold(s, ACCENT)
}
/// A value / identifier (digests, URLs, coordinates).
pub fn value(s: &str) -> String {
    paint(s, TEAL)
}
/// Muted secondary text (labels, hints).
pub fn muted(s: &str) -> String {
    paint(s, MUTED)
}
/// Gold highlight.
pub fn gold(s: &str) -> String {
    paint(s, GOLD)
}

/// `✓ <msg>` in success green.
pub fn ok(msg: &str) -> String {
    format!("{} {}", paint_bold("✓", SUCCESS), msg)
}
/// `✗ <msg>` in alert red.
pub fn fail(msg: &str) -> String {
    format!("{} {}", paint_bold("✗", FLAME_RED), msg)
}
/// `! <msg>` in gold.
pub fn warn(msg: &str) -> String {
    format!("{} {}", paint_bold("!", GOLD), msg)
}
/// A `→` step bullet in accent.
pub fn bullet() -> String {
    paint("→", ACCENT)
}

/// The `burn:` error prefix in the brand alert color.
pub fn error_prefix() -> String {
    paint_bold("burn:", FLAME_RED)
}

/// The REPL prompt, accent-colored. Non-printing escapes are wrapped in
/// `\x01`/`\x02` so rustyline computes the cursor column correctly.
pub fn repl_prompt() -> String {
    if !colors_enabled() {
        return "burn> ".to_string();
    }
    use crossterm::style::{Attribute, ResetColor, SetAttribute, SetForegroundColor};
    let set = format!(
        "{}{}",
        SetAttribute(Attribute::Bold),
        SetForegroundColor(ACCENT)
    );
    let reset = format!("{ResetColor}");
    format!("\x01{set}\x02burn>\x01{reset}\x02 ")
}

// ── flame gradient ──────────────────────────────────────────────────────────

fn lerp_sunburst(t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    let (a, b, local) = if t < 0.5 {
        (SUNBURST[0], SUNBURST[1], t / 0.5)
    } else {
        (SUNBURST[1], SUNBURST[2], (t - 0.5) / 0.5)
    };
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * local).round() as u8;
    (mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))
}

/// Color each character of `s` along the sunburst flame gradient (bold).
pub fn flame(s: &str) -> String {
    if !colors_enabled() {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len().max(1);
    let mut out = String::new();
    for (i, ch) in chars.iter().enumerate() {
        let t = if n == 1 {
            0.0
        } else {
            i as f32 / (n - 1) as f32
        };
        let (r, g, b) = lerp_sunburst(t);
        out.push_str(
            &ch.to_string()
                .with(Color::Rgb { r, g, b })
                .bold()
                .to_string(),
        );
    }
    out
}

// ── spinner (animation for network ops) ─────────────────────────────────────

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A background-thread spinner. Animates on an interactive stderr; a no-op
/// otherwise. Cleared on drop.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    fn start(msg: &str) -> Spinner {
        if !animations_enabled() {
            return Spinner {
                stop: Arc::new(AtomicBool::new(true)),
                handle: None,
            };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let msg = msg.to_string();
        let handle = std::thread::spawn(move || {
            use crossterm::{cursor, execute, terminal};
            let mut err = std::io::stderr();
            let _ = execute!(err, cursor::Hide);
            let mut i = 0usize;
            while !flag.load(Ordering::Relaxed) {
                let frame = FRAMES[i % FRAMES.len()];
                // Shimmer the glyph color along the flame gradient.
                let (r, g, b) = lerp_sunburst((i % 20) as f32 / 19.0);
                let _ = execute!(
                    err,
                    cursor::MoveToColumn(0),
                    terminal::Clear(terminal::ClearType::CurrentLine)
                );
                let _ = write!(
                    err,
                    "{} {}",
                    frame.with(Color::Rgb { r, g, b }).bold(),
                    msg.as_str().with(MUTED)
                );
                let _ = err.flush();
                i += 1;
                std::thread::sleep(Duration::from_millis(80));
            }
            let _ = execute!(
                err,
                cursor::MoveToColumn(0),
                terminal::Clear(terminal::ClearType::CurrentLine),
                cursor::Show
            );
            let _ = err.flush();
        });
        Spinner {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Run `f` while showing an animated `msg` spinner; returns `f`'s value and
/// clears the spinner first, so the caller's own output prints cleanly.
pub fn spin<T>(msg: &str, f: impl FnOnce() -> T) -> T {
    let sp = Spinner::start(msg);
    let out = f();
    drop(sp);
    out
}

// ── REPL banner (animated) ──────────────────────────────────────────────────

const WORDMARK: [&str; 5] = [
    " _                      ",
    "| |__  _   _ _ __ _ __   ",
    "| '_ \\| | | | '__| '_ \\  ",
    "| |_) | |_| | |  | | | |  ",
    "|_.__/ \\__,_|_|  |_| |_|  ",
];

fn flame_phase(line: &str, phase: f32, width: usize) -> String {
    let mut out = String::new();
    for (col, ch) in line.chars().enumerate() {
        if ch == ' ' {
            out.push(' ');
            continue;
        }
        let t = ((col as f32 / width.max(1) as f32) + phase).rem_euclid(1.0);
        let (r, g, b) = lerp_sunburst(t);
        out.push_str(
            &ch.to_string()
                .with(Color::Rgb { r, g, b })
                .bold()
                .to_string(),
        );
    }
    out
}

/// Print the REPL welcome banner. On an interactive terminal the flame
/// wordmark animates (a flowing-gradient "ignition"); otherwise a single plain
/// line is printed.
pub fn repl_banner(version: &str) {
    if !animations_enabled() {
        eprintln!("burn {version} — Afterburner sandbox REPL. :help for commands, :exit to quit.");
        return;
    }

    use crossterm::{cursor, execute};
    let mut err = std::io::stderr();
    let width = WORDMARK
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1);

    let _ = execute!(err, cursor::Hide);
    let frames = 16;
    for f in 0..frames {
        if f > 0 {
            let _ = execute!(err, cursor::MoveUp(WORDMARK.len() as u16));
        }
        let phase = -(f as f32) * 0.07; // sweep the gradient rightward
        for line in WORDMARK {
            let _ = execute!(err, cursor::MoveToColumn(0));
            let _ = writeln!(err, "  {}", flame_phase(line, phase, width));
        }
        let _ = err.flush();
        std::thread::sleep(Duration::from_millis(45));
    }
    let _ = execute!(err, cursor::Show);

    eprintln!();
    eprintln!(
        "  {} {}",
        accent("Afterburner"),
        muted("· sandboxed JavaScript runtime")
    );
    eprintln!(
        "  {}",
        muted(&format!("v{version} · :help for commands · :exit to quit"))
    );
    eprintln!();
}
