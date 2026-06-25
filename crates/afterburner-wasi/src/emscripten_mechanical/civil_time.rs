// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Deterministic civil-time breakdown for the Emscripten clock host functions
//! (`_gmtime_js`, `_localtime_js`, `_mktime_js`, `_timegm_js`, `_tzset_js`).
//!
//! A no-op for these leaves CPython's `struct tm` uninitialized, so
//! `time.localtime()` / `datetime.now()` read garbage and raise "month out of
//! range" - which blocks importing every package that touches the clock at
//! import (scikit-learn, statsmodels, ipython, sqlalchemy, ...). The runtime's
//! virtual clock is UTC, so gmtime == localtime and there is no zone offset.
//!
//! The calendar math is Howard Hinnant's `days_from_civil` / `civil_from_days`
//! (public domain), correct for the proleptic Gregorian calendar across the full
//! `i64` range.

use wasmtime::Caller;

use crate::embedder_vm::EmbedderState;

/// Days from the civil date 1970-01-01 to `y-m-d` (m in 1..=12).
pub(super) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: the civil date `(year, month, day)` for a
/// day count `z` since 1970-01-01.
pub(super) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Number of `struct tm` integer fields written: sec, min, hour, mday, mon
/// (0..11), year (since 1900), wday (0=Sun), yday (0..365), isdst. Each is a
/// 4-byte little-endian int, matching the Emscripten layout.
const TM_FIELDS: usize = 9;

/// Fill the `struct tm` at `tmptr` with the UTC breakdown of Unix time `t`
/// (seconds). Bounds-checked against guest memory; a short/oob struct is left
/// untouched (the caller's clock then fails loudly rather than corrupting heap).
pub(super) fn write_tm(caller: &mut Caller<'_, EmbedderState>, t: i64, tmptr: i32) {
    let Some(mem) = caller.data().pyodide_memory else {
        return;
    };
    // Floor-divide so a negative timestamp keeps a non-negative seconds-of-day.
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;
    // wday: 1970-01-01 was a Thursday (4). Keep it in 0..=6.
    let wday = (days + 4).rem_euclid(7);
    let yday = days - days_from_civil(year, 1, 1);

    let fields: [i32; TM_FIELDS] = [
        sec as i32,
        min as i32,
        hour as i32,
        day as i32,
        (month - 1) as i32,
        (year - 1900) as i32,
        wday as i32,
        yday as i32,
        0, // isdst: UTC, no daylight saving
    ];
    let base = tmptr as u32 as usize;
    let end = base + TM_FIELDS * 4;
    let data = mem.data_mut(caller);
    if end > data.len() {
        return;
    }
    for (i, v) in fields.iter().enumerate() {
        data[base + i * 4..base + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// The Unix timestamp (seconds, UTC) for the `struct tm` at `tmptr`. Reads the
/// first six fields (sec, min, hour, mday, mon, year); the rest are derived.
/// Returns -1 on an out-of-bounds struct (the libc convention for a bad time).
pub(super) fn read_tm_to_unix(caller: &Caller<'_, EmbedderState>, tmptr: i32) -> i64 {
    let Some(mem) = caller.data().pyodide_memory else {
        return -1;
    };
    let data = mem.data(caller);
    let base = tmptr as u32 as usize;
    if base + 6 * 4 > data.len() {
        return -1;
    }
    let f = |i: usize| -> i64 {
        i32::from_le_bytes(data[base + i * 4..base + i * 4 + 4].try_into().unwrap()) as i64
    };
    let (sec, min, hour, mday, mon, year) = (f(0), f(1), f(2), f(3), f(4), f(5));
    let days = days_from_civil(year + 1900, mon + 1, mday);
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Write the libc timezone globals for `_tzset_js`: the runtime is UTC with no
/// daylight saving, so `timezone = 0` (seconds west of UTC), `daylight = 0`, and
/// both zone names are "UTC". Each out-pointer is bounds-checked independently;
/// a null/oob pointer for one global is skipped without touching the others.
pub(super) fn write_tzset(
    caller: &mut Caller<'_, EmbedderState>,
    timezone_ptr: i32,
    daylight_ptr: i32,
    std_name_ptr: i32,
    dst_name_ptr: i32,
) {
    let Some(mem) = caller.data().pyodide_memory else {
        return;
    };
    let data = mem.data_mut(caller);
    let put_i32 = |data: &mut [u8], ptr: i32, v: i32| {
        let p = ptr as u32 as usize;
        if ptr != 0 && p + 4 <= data.len() {
            data[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
    };
    let put_name = |data: &mut [u8], ptr: i32| {
        let p = ptr as u32 as usize;
        if ptr != 0 && p + 4 <= data.len() {
            data[p..p + 4].copy_from_slice(b"UTC\0");
        }
    };
    put_i32(data, timezone_ptr, 0);
    put_i32(data, daylight_ptr, 0);
    put_name(data, std_name_ptr);
    put_name(data, dst_name_ptr);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `days_from_civil` matches known reference points.
    #[test]
    fn days_from_civil_known_points() {
        assert_eq!(days_from_civil(1970, 1, 1), 0, "epoch is day 0");
        assert_eq!(days_from_civil(1969, 12, 31), -1, "day before epoch");
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        // 2000-03-01 is 11017 days after the epoch (just past the 2000 leap-day,
        // exercising the century/400-year leap rules).
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2026, 1, 1), 20454);
    }

    /// `civil_from_days` is the exact inverse of `days_from_civil` across a wide
    /// range, including leap days and pre-epoch dates.
    #[test]
    fn civil_from_days_round_trips() {
        for &(y, m, d) in &[
            (1970, 1, 1),
            (1969, 12, 31),
            (2000, 2, 29), // leap day (divisible by 400)
            (1900, 2, 28), // NOT a leap year (divisible by 100, not 400)
            (2024, 2, 29), // leap day (divisible by 4)
            (2026, 6, 25),
            (1, 1, 1),
            (9999, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(
                civil_from_days(days),
                (y, m, d),
                "round-trip {y}-{m}-{d} via day {days}"
            );
        }
    }

    /// The virtual epoch the clock returns breaks down to a sane, in-range UTC
    /// date (the property the clock fix exists to guarantee: no "month out of
    /// range"). VIRTUAL_EPOCH_NS is the fixed deterministic now.
    #[test]
    fn virtual_epoch_breaks_down_in_range() {
        let secs = (crate::emscripten_abi::VIRTUAL_EPOCH_NS / 1_000_000_000) as i64;
        let days = secs.div_euclid(86400);
        let (year, month, day) = civil_from_days(days);
        assert!(
            (1..=9999).contains(&year),
            "year {year} must be a valid datetime year"
        );
        assert!((1..=12).contains(&month), "month {month} must be 1..=12");
        assert!((1..=31).contains(&day), "day {day} must be 1..=31");
        // The virtual epoch (VIRTUAL_EPOCH_NS) is pinned at 2025-12-31 UTC; assert
        // the full date concretely (independently confirmed via Python's datetime)
        // so a change to the constant that breaks the clock breakdown is caught.
        assert_eq!((year, month, day), (2025, 12, 31), "virtual epoch date");
    }
}
