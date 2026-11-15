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
