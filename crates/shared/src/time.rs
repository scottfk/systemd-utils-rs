// SPDX-License-Identifier: LGPL-2.1-or-later
//! `time-util.c`: the timestamp formats the ported code prints.

use crate::sys;

pub const USEC_PER_SEC: u64 = 1_000_000;
pub const USEC_PER_MSEC: u64 = 1_000;
pub const USEC_INFINITY: u64 = u64::MAX;
/// `USEC_TIMESTAMP_FORMATTABLE_MAX` on 64-bit: 9999-12-30 23:59:59 UTC.
const USEC_TIMESTAMP_FORMATTABLE_MAX: u64 = 253_402_214_399_999_999;

/// `now(CLOCK_REALTIME)`.
pub fn now_realtime() -> u64 {
    sys::now_realtime_usec()
}

/// `localtime_or_gmtime_usec(t, utc)`.
pub fn localtime_or_gmtime_usec(t: u64, utc: bool) -> Option<libc::tm> {
    let sec = (t / USEC_PER_SEC) as i64;
    if utc { sys::gmtime(sec) } else { sys::localtime(sec) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampStyle {
    Pretty,
    Us,
    Utc,
    UsUtc,
    Unix,
    Date,
}

/// `format_timestamp_style(buf, FORMAT_TIMESTAMP_MAX, t, style)`.
pub fn format_timestamp_style(t: u64, style: TimestampStyle) -> Option<Vec<u8>> {
    if t == 0 || t == USEC_INFINITY {
        return None;
    }
    if style == TimestampStyle::Unix {
        return Some(format!("@{}", t / USEC_PER_SEC).into_bytes());
    }
    let utc = matches!(style, TimestampStyle::Utc | TimestampStyle::UsUtc | TimestampStyle::Date);
    let us = matches!(style, TimestampStyle::Us | TimestampStyle::UsUtc);
    if t > USEC_TIMESTAMP_FORMATTABLE_MAX {
        let s = match style {
            TimestampStyle::Pretty => "--- XXXX-XX-XX XX:XX:XX",
            TimestampStyle::Us => "--- XXXX-XX-XX XX:XX:XX.XXXXXX",
            TimestampStyle::Utc => "--- XXXX-XX-XX XX:XX:XX UTC",
            TimestampStyle::UsUtc => "--- XXXX-XX-XX XX:XX:XX.XXXXXX UTC",
            _ => "--- XXXX-XX-XX",
        };
        return Some(s.as_bytes().to_vec());
    }
    let tm = localtime_or_gmtime_usec(t, utc)?;
    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let wd = WEEKDAYS[if tm.tm_wday == 0 { 6 } else { tm.tm_wday as usize - 1 }];
    let mut buf = wd.as_bytes().to_vec();
    // FORMAT_TIMESTAMP_MAX is 3+1+10+1+8+1+6+1+6+1 = 38, minus the weekday.
    let room = 38 - 3;
    if style == TimestampStyle::Date {
        buf.extend(sys::strftime(c" %Y-%m-%d", &tm, room)?);
        return Some(buf);
    }
    buf.extend(sys::strftime(c" %Y-%m-%d %H:%M:%S", &tm, room)?);
    if us {
        buf.extend(format!(".{:06}", t % USEC_PER_SEC).into_bytes());
    }
    if utc {
        buf.extend_from_slice(b" UTC");
    } else if let Some(zone) = sys::tm_zone(&tm)
        // The zone and a NUL must fit in FORMAT_TIMESTAMP_MAX (38).
        && !zone.is_empty()
        && buf.len() + 1 + zone.len() < 38
    {
        buf.push(b' ');
        buf.extend_from_slice(&zone);
    }
    Some(buf)
}

/// `format_timestamp(buf, l, t)`.
pub fn format_timestamp(t: u64) -> Option<Vec<u8>> {
    format_timestamp_style(t, TimestampStyle::Pretty)
}

pub const USEC_PER_MINUTE: u64 = 60 * USEC_PER_SEC;
pub const USEC_PER_HOUR: u64 = 60 * USEC_PER_MINUTE;
pub const USEC_PER_DAY: u64 = 24 * USEC_PER_HOUR;
pub const USEC_PER_WEEK: u64 = 7 * USEC_PER_DAY;
pub const USEC_PER_MONTH: u64 = 2_629_800 * USEC_PER_SEC;
pub const USEC_PER_YEAR: u64 = 31_557_600 * USEC_PER_SEC;
pub const NSEC_PER_USEC: u64 = 1000;
pub const NSEC_INFINITY: u64 = u64::MAX;

/// `extract_multiplier()`: (multiplier, bytes of suffix).
fn extract_multiplier(p: &[u8]) -> Option<(u64, usize)> {
    const TABLE: &[(&str, u64)] = &[
        ("seconds", USEC_PER_SEC),
        ("second", USEC_PER_SEC),
        ("sec", USEC_PER_SEC),
        ("s", USEC_PER_SEC),
        ("minutes", USEC_PER_MINUTE),
        ("minute", USEC_PER_MINUTE),
        ("min", USEC_PER_MINUTE),
        ("months", USEC_PER_MONTH),
        ("month", USEC_PER_MONTH),
        ("M", USEC_PER_MONTH),
        ("msec", USEC_PER_MSEC),
        ("ms", USEC_PER_MSEC),
        ("m", USEC_PER_MINUTE),
        ("hours", USEC_PER_HOUR),
        ("hour", USEC_PER_HOUR),
        ("hr", USEC_PER_HOUR),
        ("h", USEC_PER_HOUR),
        ("days", USEC_PER_DAY),
        ("day", USEC_PER_DAY),
        ("d", USEC_PER_DAY),
        ("weeks", USEC_PER_WEEK),
        ("week", USEC_PER_WEEK),
        ("w", USEC_PER_WEEK),
        ("years", USEC_PER_YEAR),
        ("year", USEC_PER_YEAR),
        ("y", USEC_PER_YEAR),
        ("usec", 1),
        ("us", 1),
        ("μs", 1),
        ("µs", 1),
    ];
    TABLE.iter().find(|(s, _)| p.starts_with(s.as_bytes())).map(|(s, u)| (*u, s.len()))
}

/// `parse_time(t, &ret, default_unit)`.
pub fn parse_time(t: &[u8], default_unit: u64) -> Result<u64, i32> {
    use crate::string::{DIGITS, WHITESPACE, in_charset, skip_leading_chars};
    let t = crate::bytes::c_str_prefix(t);
    let mut p = skip_leading_chars(t, None);
    if let Some(s) = p.strip_prefix(b"infinity") {
        if !in_charset(s, WHITESPACE) {
            return Err(-libc::EINVAL);
        }
        return Ok(USEC_INFINITY);
    }
    let mut usec: u64 = 0;
    let mut something = false;
    loop {
        p = skip_leading_chars(p, None);
        if p.is_empty() {
            if !something {
                return Err(-libc::EINVAL);
            }
            break;
        }
        if p[0] == b'-' {
            return Err(-libc::ERANGE);
        }
        let (l, consumed, e) = crate::sys::strtoll(p, 10);
        if e > 0 {
            return Err(-e);
        }
        if l < 0 {
            return Err(-libc::ERANGE);
        }
        let epos = consumed;
        let dot = p.get(epos) == Some(&b'.');
        let (frac, after): (&[u8], &[u8]) = if dot {
            let q = &p[epos + 1..];
            let n = q.iter().take_while(|b| DIGITS.contains(b)).count();
            (&q[..n], &q[n..])
        } else if epos == 0 {
            return Err(-libc::EINVAL);
        } else {
            (&[], &p[epos..])
        };
        let ws = after.iter().take_while(|b| WHITESPACE.contains(b)).count();
        let (multiplier, s) = match extract_multiplier(&after[ws..]) {
            Some((m, n)) => (m, &after[ws + n..]),
            None => (default_unit, &after[ws..]),
        };
        // C compares s with p (just past the number and its fraction).
        if s.as_ptr() == after.as_ptr() && !s.is_empty() {
            return Err(-libc::EINVAL);
        }
        p = s;
        let l = l as u64;
        if l >= USEC_INFINITY / multiplier {
            return Err(-libc::ERANGE);
        }
        let k = l * multiplier;
        if k >= USEC_INFINITY - usec {
            return Err(-libc::ERANGE);
        }
        usec += k;
        something = true;
        if dot {
            let mut m = multiplier / 10;
            for &b in frac {
                let k = (b - b'0') as u64 * m;
                if k >= USEC_INFINITY - usec {
                    return Err(-libc::ERANGE);
                }
                usec += k;
                m /= 10;
            }
            if frac.is_empty() {
                return Err(-libc::EINVAL);
            }
        }
    }
    Ok(usec)
}

/// `parse_sec()`.
pub fn parse_sec(t: &[u8]) -> Result<u64, i32> {
    parse_time(t, USEC_PER_SEC)
}
