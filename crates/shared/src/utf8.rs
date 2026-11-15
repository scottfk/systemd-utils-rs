// SPDX-License-Identifier: LGPL-2.1-or-later
//! `utf8.c` and `gunicode.c`: UTF-8 decoding and console widths.
//!
//! C walks NUL-terminated strings; here a byte past the end of the slice
//! reads as NUL, which fails every continuation-byte check the same way.

fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `unichar_is_valid()`.
pub fn unichar_is_valid(ch: u32) -> bool {
    if ch >= 0x110000 {
        return false;
    }
    if (ch & 0xFFFFF800) == 0xD800 {
        return false;
    }
    if (0xFDD0..=0xFDEF).contains(&ch) {
        return false;
    }
    if (ch & 0xFFFE) == 0xFFFE {
        return false;
    }
    true
}

/// `utf8_encoded_expected_len()`.
fn encoded_expected_len(c: u8) -> usize {
    if c < 0x80 {
        1
    } else if (c & 0xe0) == 0xc0 {
        2
    } else if (c & 0xf0) == 0xe0 {
        3
    } else if (c & 0xf8) == 0xf0 {
        4
    } else if (c & 0xfc) == 0xf8 {
        5
    } else if (c & 0xfe) == 0xfc {
        6
    } else {
        0
    }
}

/// `utf8_encoded_to_unichar()`: (code point, encoded length).
pub fn encoded_to_unichar(s: &[u8]) -> Result<(u32, usize), i32> {
    let c0 = at(s, 0);
    let len = encoded_expected_len(c0);
    let mut u: u32 = match len {
        1 => return Ok((c0 as u32, 1)),
        2 => (c0 & 0x1f) as u32,
        3 => (c0 & 0x0f) as u32,
        4 => (c0 & 0x07) as u32,
        5 => (c0 & 0x03) as u32,
        6 => (c0 & 0x01) as u32,
        _ => return Err(-libc::EINVAL),
    };
    for i in 1..len {
        let b = at(s, i);
        if (b & 0xc0) != 0x80 {
            return Err(-libc::EINVAL);
        }
        u <<= 6;
        u |= (b & 0x3f) as u32;
    }
    Ok((u, len))
}

/// `utf8_unichar_to_encoded_len()`.
fn unichar_to_encoded_len(u: u32) -> usize {
    if u < 0x80 {
        1
    } else if u < 0x800 {
        2
    } else if u < 0x10000 {
        3
    } else if u < 0x200000 {
        4
    } else if u < 0x4000000 {
        5
    } else {
        6
    }
}

/// `utf8_encoded_valid_unichar(str, length)`: the length of the valid
/// character at the start of s, or None.
pub fn encoded_valid_unichar(s: &[u8]) -> Option<usize> {
    let len = encoded_expected_len(at(s, 0));
    if len == 0 || len > s.len() {
        return None;
    }
    if len == 1 {
        return Some(1);
    }
    for i in 0..len {
        if (at(s, i) & 0x80) != 0x80 {
            return None;
        }
    }
    let (u, _) = encoded_to_unichar(s).ok()?;
    if unichar_to_encoded_len(u) != len {
        return None;
    }
    if !unichar_is_valid(u) {
        return None;
    }
    Some(len)
}

/// `utf8_is_valid()` (stops at an embedded NUL, which makes it invalid).
pub fn is_valid(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == 0 {
            return false;
        }
        match encoded_valid_unichar(&s[i..]) {
            Some(n) => i += n,
            None => return false,
        }
    }
    true
}

/// `find_previous_unichar(start, end)`: index of the last complete
/// character in s, if it is valid.
pub fn find_previous_unichar(s: &[u8]) -> Option<usize> {
    let mut p = s.len();
    while p > 0 {
        p -= 1;
        if (s[p] & 0xc0) != 0x80 {
            break;
        }
    }
    let r = encoded_valid_unichar(&s[p..])?;
    if p + r != s.len() {
        return None;
    }
    Some(p)
}

/// gunicode's `utf8_skip_data[]`, as used by `utf8_next_char()`.
pub fn skip_len(c: u8) -> usize {
    match c {
        0x00..=0xbf => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        0xf8..=0xfb => 5,
        0xfc..=0xfd => 6,
        _ => 1,
    }
}

/// `unichar_iswide()`: gunicode's table (Unicode 6.0).
pub fn unichar_iswide(c: u32) -> bool {
    const WIDE: &[(u32, u32)] = &[
        (0x1100, 0x115F),
        (0x2329, 0x232A),
        (0x2E80, 0x2E99),
        (0x2E9B, 0x2EF3),
        (0x2F00, 0x2FD5),
        (0x2FF0, 0x2FFB),
        (0x3000, 0x303E),
        (0x3041, 0x3096),
        (0x3099, 0x30FF),
        (0x3105, 0x312D),
        (0x3131, 0x318E),
        (0x3190, 0x31BA),
        (0x31C0, 0x31E3),
        (0x31F0, 0x321E),
        (0x3220, 0x3247),
        (0x3250, 0x32FE),
        (0x3300, 0x4DBF),
        (0x4E00, 0xA48C),
        (0xA490, 0xA4C6),
        (0xA960, 0xA97C),
        (0xAC00, 0xD7A3),
        (0xF900, 0xFAFF),
        (0xFE10, 0xFE19),
        (0xFE30, 0xFE52),
        (0xFE54, 0xFE66),
        (0xFE68, 0xFE6B),
        (0xFF01, 0xFF60),
        (0xFFE0, 0xFFE6),
        (0x1B000, 0x1B001),
        (0x1F200, 0x1F202),
        (0x1F210, 0x1F23A),
        (0x1F240, 0x1F248),
        (0x1F250, 0x1F251),
        (0x1F300, 0x1F567),
        (0x20000, 0x2FFFD),
        (0x30000, 0x3FFFD),
    ];
    WIDE.iter().any(|&(a, b)| c >= a && c <= b)
}

/// `unichar_console_width()`.
pub fn unichar_console_width(c: u32) -> usize {
    if c == b'\t' as u32 {
        return 8;
    }
    if unichar_iswide(c) { 2 } else { 1 }
}

/// `utf8_console_width()`: `usize::MAX` on invalid UTF-8.
pub fn console_width(s: &[u8]) -> usize {
    let s = crate::bytes::c_str_prefix(s);
    let mut n = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        match encoded_to_unichar(&s[i..]) {
            Ok((c, _)) => n += unichar_console_width(c),
            Err(_) => return usize::MAX,
        }
        i += skip_len(s[i]);
    }
    n
}
