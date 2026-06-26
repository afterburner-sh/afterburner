// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Level-gated logging on top of `fastrace`.
//!
//! Severity is read once from the `AFTERBURNER_LOG` env var
//! (case-insensitive: `off`, `error`, `warn`, `info`, `debug`, `trace`),
//! defaulting to `warn`. Output format is `AFTERBURNER_LOG_FORMAT`
//! (`text` default, or `json`).
//!
//! Library users do not need to call anything - events are emitted via
//! the [`crate::ab_event!`] macro and `#[fastrace::trace]` spans.
//! Applications that want output should call [`init`] once during
//! startup; it installs a fastrace reporter idempotently.

use fastrace::collector::{Config, Reporter, SpanRecord};
use serde_json::{Map, Value, json};
use std::borrow::Cow;
use std::env;
use std::io::{self, Write};
use std::sync::OnceLock;

type PropPairs = [(Cow<'static, str>, Cow<'static, str>)];

/// Severity ordering matches the conventional log-crate hierarchy:
/// lower values are more severe and always pass through if the configured
/// level admits a less-severe event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "0" => Some(Self::Off),
            "error" | "err" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }
}

/// Resolved log level for the running process. Cached after first read.
pub fn current_level() -> Level {
    static LEVEL: OnceLock<Level> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        env::var("AFTERBURNER_LOG")
            .ok()
            .and_then(|v| Level::parse(&v))
            .unwrap_or(Level::Warn)
    })
}

/// `true` if events at the given severity should be emitted.
#[inline]
pub fn enabled(level: Level) -> bool {
    level <= current_level()
}

/// Emit a fastrace event into the current local parent span, gated on the
/// configured log level.
///
/// ```ignore
/// use afterburner_core::ab_event;
/// use afterburner_core::log::Level;
///
/// ab_event!(Level::Info, "compile_succeeded");
/// ab_event!(Level::Warn, "fuel_exhausted", "script_hash" => "abcd");
/// ```
#[macro_export]
macro_rules! ab_event {
    ($level:expr, $name:expr) => {{
        if $crate::log::enabled($level) {
            ::fastrace::local::LocalSpan::add_event(
                ::fastrace::Event::new($name)
                    .with_property(|| ("level", $crate::log::level_str($level)))
            );
        }
    }};
    ($level:expr, $name:expr, $($k:expr => $v:expr),+ $(,)?) => {{
        if $crate::log::enabled($level) {
            let level_label = $crate::log::level_str($level);
            ::fastrace::local::LocalSpan::add_event(
                ::fastrace::Event::new($name).with_properties(|| {
                    let pairs: ::std::vec::Vec<(::std::borrow::Cow<'static, str>, ::std::borrow::Cow<'static, str>)> = vec![
                        (::std::borrow::Cow::Borrowed("level"), ::std::borrow::Cow::Borrowed(level_label)),
                        $((::std::borrow::Cow::Borrowed($k), ::std::borrow::Cow::Owned($v.to_string()))),+
                    ];
                    pairs
                })
            );
        }
    }};
}

/// String label for a level - used by the `ab_event!` macro and exposed
/// for downstream reporters that want to filter by level.
pub fn level_str(level: Level) -> &'static str {
    match level {
        Level::Off => "off",
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

/// Output format for the built-in reporters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable: one line per event/span to stderr.
    Text,
    /// One JSON object per span to stdout. Each line is a complete
    /// document; safe to pipe into `jq` or a log shipper.
    Json,
}

impl Format {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "human" | "" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    fn from_env() -> Self {
        env::var("AFTERBURNER_LOG_FORMAT")
            .ok()
            .and_then(|v| Self::parse(&v))
            .unwrap_or(Self::Text)
    }
}

static INIT_GUARD: OnceLock<()> = OnceLock::new();

/// Initialize the global fastrace reporter. Reads `AFTERBURNER_LOG` (level)
/// and `AFTERBURNER_LOG_FORMAT` (`text` or `json`). Idempotent - second and
/// later calls are no-ops, so it's safe to call from `main` even when the
/// process embeds Afterburner more than once.
///
/// Applications that want full control can install their own reporter
/// directly via `fastrace::set_reporter` and ignore this helper.
pub fn init() {
    init_with_format(Format::from_env());
}

/// Initialize with an explicit format, ignoring `AFTERBURNER_LOG_FORMAT`.
/// Level is still read from `AFTERBURNER_LOG`.
pub fn init_with_format(format: Format) {
    INIT_GUARD.get_or_init(|| {
        if current_level() == Level::Off {
            return;
        }
        match format {
            Format::Text => fastrace::set_reporter(TextReporter, Config::default()),
            Format::Json => fastrace::set_reporter(JsonReporter, Config::default()),
        }
    });
}

/// Plain-text reporter. Each span produces a one-line summary plus one
/// line per attached event, written to stderr.
pub struct TextReporter;

impl Reporter for TextReporter {
    fn report(&mut self, spans: Vec<SpanRecord>) {
        let stderr = io::stderr();
        let mut out = stderr.lock();
        for span in spans {
            let _ = writeln!(
                out,
                "[afterburner] span={} duration_us={} trace={:032x} props={}",
                span.name,
                span.duration_ns / 1_000,
                span.trace_id.0,
                fmt_props(&span.properties),
            );
            for event in span.events {
                let _ = writeln!(
                    out,
                    "[afterburner]   event={} props={}",
                    event.name,
                    fmt_props(&event.properties),
                );
            }
        }
    }
}

fn fmt_props(p: &PropPairs) -> String {
    if p.is_empty() {
        return String::from("{}");
    }
    let mut s = String::with_capacity(64);
    s.push('{');
    let mut first = true;
    for (k, v) in p {
        if !first {
            s.push_str(", ");
        }
        first = false;
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    s.push('}');
    s
}

/// One JSON document per span, written line-delimited to stdout.
/// Schema is stable; consumers can pipe into `jq` or any log shipper.
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn report(&mut self, spans: Vec<SpanRecord>) {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for span in spans {
            let value = json!({
                "name":           span.name,
                "trace_id":       format!("{:032x}", span.trace_id.0),
                "span_id":        span.span_id.0,
                "parent_span_id": span.parent_id.0,
                "begin_unix_ns":  span.begin_time_unix_ns,
                "duration_ns":    span.duration_ns,
                "properties":     props_to_json(&span.properties),
                "events":         span.events.iter().map(|e| json!({
                    "name":              e.name,
                    "timestamp_unix_ns": e.timestamp_unix_ns,
                    "properties":        props_to_json(&e.properties),
                })).collect::<Vec<_>>(),
            });
            let _ = writeln!(out, "{value}");
        }
    }
}

fn props_to_json(p: &PropPairs) -> Map<String, Value> {
    let mut m = Map::with_capacity(p.len());
    for (k, v) in p {
        m.insert(k.to_string(), Value::String(v.to_string()));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parse_round_trip() {
        for (s, expect) in [
            ("off", Level::Off),
            ("ERROR", Level::Error),
            ("warn", Level::Warn),
            ("Info", Level::Info),
            ("debug", Level::Debug),
            ("TRACE", Level::Trace),
        ] {
            assert_eq!(Level::parse(s), Some(expect));
        }
        assert_eq!(Level::parse("nonsense"), None);
    }

    #[test]
    fn enabled_compares_correctly() {
        assert!(Level::Error <= Level::Warn);
        assert!(Level::Warn <= Level::Info);
        assert!(Level::Debug > Level::Warn);
    }
}
