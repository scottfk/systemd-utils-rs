// SPDX-License-Identifier: LGPL-2.1-or-later
//! `parse-util.c`: booleans and integers.

use crate::string::{WHITESPACE, startswith};
use crate::sys;

/// `parse_boolean()`.
pub fn parse_boolean(v: &[u8]) -> Result<bool, i32> {
    const YES: [&[u8]; 6] = [b"1", b"yes", b"y", b"true", b"t", b"on"];
    const NO: [&[u8]; 6] = [b"0", b"no", b"n", b"false", b"f", b"off"];
    if YES.iter().any(|y| y.eq_ignore_ascii_case(v)) {
        return Ok(true);
    }
    if NO.iter().any(|n| n.eq_ignore_ascii_case(v)) {
        return Ok(false);
    }
    Err(-libc::EINVAL)
}

pub const SAFE_ATO_REFUSE_PLUS_MINUS: u32 = 1 << 30;
pub const SAFE_ATO_REFUSE_LEADING_ZERO: u32 = 1 << 29;
pub const SAFE_ATO_REFUSE_LEADING_WHITESPACE: u32 = 1 << 28;
const SAFE_ATO_ALL_FLAGS: u32 =
    SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO | SAFE_ATO_REFUSE_LEADING_WHITESPACE;

fn mask_flags(base: u32) -> u32 {
    base & !SAFE_ATO_ALL_FLAGS
}

/// `mangle_base()`: Python-style "0b" and "0o" prefixes when no base is given.
fn mangle_base<'a>(s: &'a [u8], base: &mut u32) -> &'a [u8] {
    if mask_flags(*base) != 0 {
        return s;
    }
    if let Some(k) = startswith(s, b"0b").or_else(|| startswith(s, b"0B")) {
        *base = 2 | (*base & SAFE_ATO_ALL_FLAGS);
        return k;
    }
    if let Some(k) = startswith(s, b"0o").or_else(|| startswith(s, b"0O")) {
        *base = 8 | (*base & SAFE_ATO_ALL_FLAGS);
        return k;
    }
    s
}

fn skip_ws(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|b| WHITESPACE.contains(b)).count();
    &s[n..]
}

/// `safe_atou_full()`.
pub fn safe_atou_full(s: &[u8], mut base: u32) -> Result<u32, i32> {
    if base & SAFE_ATO_REFUSE_LEADING_WHITESPACE != 0 && (s.is_empty() || WHITESPACE.contains(&s[0])) {
        // strchr(WHITESPACE, s[0]) also matches the terminating NUL.
        return Err(-libc::EINVAL);
    }
    let s = skip_ws(s);
    if base & SAFE_ATO_REFUSE_PLUS_MINUS != 0 && matches!(s.first(), Some(b'+') | Some(b'-')) {
        return Err(-libc::EINVAL);
    }
    if base & SAFE_ATO_REFUSE_LEADING_ZERO != 0 && s.first() == Some(&b'0') && s != b"0" {
        return Err(-libc::EINVAL);
    }
    let s = mangle_base(s, &mut base);
    let (l, consumed, e) = sys::strtoul(s, mask_flags(base) as i32);
    if e > 0 {
        return Err(-e);
    }
    if consumed == 0 || consumed != s.len() || s.contains(&0) {
        return Err(-libc::EINVAL);
    }
    if l != 0 && s.first() == Some(&b'-') {
        return Err(-libc::ERANGE);
    }
    if l as u32 as u64 != l {
        return Err(-libc::ERANGE);
    }
    Ok(l as u32)
}

/// `safe_atou()`.
pub fn safe_atou(s: &[u8]) -> Result<u32, i32> {
    safe_atou_full(s, 0)
}

/// `safe_atou_bounded()`.
pub fn safe_atou_bounded(s: &[u8], min: u32, max: u32) -> Result<u32, i32> {
    let v = safe_atou(s)?;
    if v < min || v > max {
        return Err(-libc::ERANGE);
    }
    Ok(v)
}

/// `safe_atou64_full()` (with no flags: `safe_atou64()`).
pub fn safe_atou64_full(s: &[u8], mut base: u32) -> Result<u64, i32> {
    if base & SAFE_ATO_REFUSE_LEADING_WHITESPACE != 0 && (s.is_empty() || WHITESPACE.contains(&s[0])) {
        return Err(-libc::EINVAL);
    }
    let s = skip_ws(s);
    if base & SAFE_ATO_REFUSE_PLUS_MINUS != 0 && matches!(s.first(), Some(b'+') | Some(b'-')) {
        return Err(-libc::EINVAL);
    }
    if base & SAFE_ATO_REFUSE_LEADING_ZERO != 0 && s.first() == Some(&b'0') && s != b"0" {
        return Err(-libc::EINVAL);
    }
    let s = mangle_base(s, &mut base);
    let (l, consumed, e) = sys::strtoull(s, mask_flags(base) as i32);
    if e > 0 {
        return Err(-e);
    }
    if consumed == 0 || consumed != s.len() || s.contains(&0) {
        return Err(-libc::EINVAL);
    }
    if l != 0 && s.first() == Some(&b'-') {
        return Err(-libc::ERANGE);
    }
    Ok(l)
}

/// `safe_atou64()`.
pub fn safe_atou64(s: &[u8]) -> Result<u64, i32> {
    safe_atou64_full(s, 0)
}

/// `safe_atoi()`.
pub fn safe_atoi(s: &[u8]) -> Result<i32, i32> {
    let mut base = 0;
    let s = skip_ws(s);
    let s = mangle_base(s, &mut base);
    let (l, consumed, e) = sys::strtol(s, base as i32);
    if e > 0 {
        return Err(-e);
    }
    if consumed == 0 || consumed != s.len() || s.contains(&0) {
        return Err(-libc::EINVAL);
    }
    if l as i32 as i64 != l {
        return Err(-libc::ERANGE);
    }
    Ok(l as i32)
}

/// `parse_mode()`: octal, at most 07777.
pub fn parse_mode(s: &[u8]) -> Result<u32, i32> {
    let m = safe_atou_full(s, 8 | SAFE_ATO_REFUSE_PLUS_MINUS)?;
    if m > 0o7777 {
        return Err(-libc::ERANGE);
    }
    Ok(m)
}

/// `parse_ifindex()`.
pub fn parse_ifindex(s: &[u8]) -> Result<i32, i32> {
    let i = safe_atoi(s)?;
    if i <= 0 {
        return Err(-libc::EINVAL);
    }
    Ok(i)
}

/// `parse_devnum()`: "MAJOR:MINOR".
pub fn parse_devnum(s: &[u8]) -> Result<u64, i32> {
    let n = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if n == 0 || n > 20 || s.get(n) != Some(&b':') {
        return Err(-libc::EINVAL);
    }
    let x = safe_atou(&s[..n])?;
    let y = safe_atou(&s[n + 1..])?;
    if x > (1 << 12) - 1 || y > (1 << 20) - 1 {
        return Err(-libc::ERANGE);
    }
    Ok(libc::makedev(x, y))
}

/// `split_pair(s, sep)`.
pub fn split_pair<'a>(s: &'a [u8], sep: &[u8]) -> Result<(&'a [u8], &'a [u8]), i32> {
    let i = s.windows(sep.len()).position(|w| w == sep).ok_or(-libc::EINVAL)?;
    Ok((&s[..i], &s[i + sep.len()..]))
}

/// `parse_boolean_argument(optname, s, &ret)`: None stands for true.
pub fn parse_boolean_argument(optname: &str, s: Option<&[u8]>) -> Result<bool, i32> {
    match s {
        None => Ok(true),
        Some(s) => parse_boolean(s)
            .map_err(|r| crate::log_error_errno!(r, "Failed to parse boolean argument to '", optname, "': ", s)),
    }
}
