// SPDX-License-Identifier: LGPL-2.1-or-later
//! `string-util.c` (and fundamental's `string-util.h`): byte-string helpers.

use crate::locale::{Glyph, glyph_full, is_locale_utf8};
use crate::path::filename_is_valid;
use crate::utf8;

pub const WHITESPACE: &[u8] = b" \t\n\r";
pub const NEWLINE: &[u8] = b"\n\r";
pub const QUOTES: &[u8] = b"\"'";
pub const COMMENTS: &[u8] = b"#;";
pub const GLOB_CHARS: &[u8] = b"*?[";
pub const DIGITS: &[u8] = b"0123456789";
pub const ALPHANUMERICAL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `startswith(s, prefix)`: the rest after the prefix.
pub fn startswith<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    s.strip_prefix(prefix)
}

/// `endswith(s, suffix)`: true if s ends with suffix.
pub fn endswith(s: &[u8], suffix: &[u8]) -> bool {
    s.ends_with(suffix)
}

/// `skip_leading_chars(s, bad)` (bad = None means WHITESPACE).
pub fn skip_leading_chars<'a>(s: &'a [u8], bad: Option<&[u8]>) -> &'a [u8] {
    let bad = bad.unwrap_or(WHITESPACE);
    let n = s.iter().take_while(|b| bad.contains(b)).count();
    &s[n..]
}

/// `delete_trailing_chars(s, bad)`.
pub fn delete_trailing_chars<'a>(s: &'a [u8], bad: Option<&[u8]>) -> &'a [u8] {
    let bad = bad.unwrap_or(WHITESPACE);
    let n = s.iter().rposition(|b| !bad.contains(b)).map(|i| i + 1).unwrap_or(0);
    &s[..n]
}

/// `strstrip()`.
pub fn strstrip(s: &[u8]) -> &[u8] {
    delete_trailing_chars(skip_leading_chars(s, Some(WHITESPACE)), Some(WHITESPACE))
}

/// `in_charset(s, charset)`: every byte of s is in charset.
pub fn in_charset(s: &[u8], charset: &[u8]) -> bool {
    s.iter().all(|b| charset.contains(b))
}

/// `strpbrk(s, set)`: index of the first byte in set.
pub fn strpbrk(s: &[u8], set: &[u8]) -> Option<usize> {
    s.iter().position(|b| set.contains(b))
}

/// `string_is_glob()`.
pub fn string_is_glob(p: &[u8]) -> bool {
    strpbrk(p, GLOB_CHARS).is_some()
}

/// `streq_skip_trailing_chars(s1, s2, ok)`.
pub fn streq_skip_trailing_chars(s1: &[u8], s2: &[u8], ok: Option<&[u8]>) -> bool {
    let ok = ok.unwrap_or(WHITESPACE);
    let n = s1.iter().zip(s2.iter()).take_while(|(a, b)| a == b).count();
    in_charset(&s1[n..], ok) && in_charset(&s2[n..], ok)
}

pub const STRING_ASCII: u32 = 1 << 0;
pub const STRING_ALLOW_EMPTY: u32 = 1 << 1;
pub const STRING_ALLOW_NEWLINES: u32 = 1 << 2;
pub const STRING_ALLOW_BACKSLASHES: u32 = 1 << 3;
pub const STRING_ALLOW_QUOTES: u32 = 1 << 4;
pub const STRING_ALLOW_GLOBS: u32 = 1 << 5;
pub const STRING_FILENAME: u32 = 1 << 6;
pub const STRING_DISALLOW_WHITESPACE: u32 = 1 << 8;

/// `string_is_safe(p, flags)`.
pub fn string_is_safe(p: &[u8], flags: u32) -> bool {
    if flags & STRING_ALLOW_EMPTY == 0 && p.is_empty() {
        return false;
    }
    if flags & STRING_ASCII == 0 && !utf8::is_valid(p) {
        return false;
    }
    for &t in p {
        if (t > 0 && t < b' ' && t != b'\n') || t == 0x7f {
            return false;
        }
        if flags & STRING_ALLOW_NEWLINES == 0 && t == b'\n' {
            return false;
        }
        if flags & STRING_ALLOW_BACKSLASHES == 0 && t == b'\\' {
            return false;
        }
        if flags & STRING_ALLOW_QUOTES == 0 && QUOTES.contains(&t) {
            return false;
        }
        if flags & STRING_ALLOW_GLOBS == 0 && GLOB_CHARS.contains(&t) {
            return false;
        }
        if flags & STRING_DISALLOW_WHITESPACE != 0 && WHITESPACE.contains(&t) {
            return false;
        }
        if flags & STRING_ASCII != 0 && t >= 0x80 {
            return false;
        }
    }
    if flags & STRING_FILENAME != 0 && !filename_is_valid(p) {
        return false;
    }
    true
}

/// `write_ellipsis(buf, unicode)`.
fn ellipsis(unicode: bool) -> &'static [u8] {
    glyph_full(Glyph::Ellipsis, unicode)
}

/// `ascii_ellipsize_mem()`.
fn ascii_ellipsize_mem(s: &[u8], new_length: usize, percent: u32) -> Vec<u8> {
    let old_length = s.len();
    if old_length <= new_length {
        return s.to_vec();
    }
    match new_length {
        0 => return Vec::new(),
        1 => return if is_locale_utf8() { "…".as_bytes().to_vec() } else { b".".to_vec() },
        2 if !is_locale_utf8() => return b"..".to_vec(),
        _ => {}
    }
    let need_space = if is_locale_utf8() { 1 } else { 3 };
    let x = ((new_length - need_space) * percent as usize + 50) / 100;
    let mut t = s[..x].to_vec();
    t.extend_from_slice(ellipsis(false));
    let suffix_len = new_length - x - need_space;
    t.extend_from_slice(&s[old_length - suffix_len..]);
    t
}

/// `ellipsize_mem(s, old_length, new_length, percent)`, for strings
/// without ANSI sequences (the only kind ported callers pass).
pub fn ellipsize_mem(s: &[u8], new_length: usize, percent: u32) -> Option<Vec<u8>> {
    if new_length == usize::MAX {
        return Some(s.to_vec());
    }
    if new_length == 0 {
        return Some(Vec::new());
    }
    if s.is_ascii() {
        return Some(ascii_ellipsize_mem(s, new_length, percent));
    }
    // The UTF-8 path, without the ANSI sequence handling.
    let old_length = s.len();
    let x = (new_length - 1) * percent as usize / 100;
    let mut k = 0usize;
    let mut i = 0usize;
    while i < old_length {
        let r = utf8::encoded_valid_unichar(&s[i..])?;
        let c = utf8::encoded_to_unichar(&s[i..]).ok()?.0;
        let w = if utf8::unichar_iswide(c) { 2 } else { 1 };
        if k + w > x {
            break;
        }
        k += w;
        i += r;
    }
    let mut j = old_length;
    let mut t = old_length;
    while t > i && k < new_length {
        let tt = utf8::find_previous_unichar(&s[i..t])? + i;
        let c = utf8::encoded_to_unichar(&s[tt..t]).ok()?.0;
        let w = if utf8::unichar_iswide(c) { 2 } else { 1 };
        if k + w > new_length {
            break;
        }
        k += w;
        j = tt;
        t = tt;
    }
    if i >= j {
        return Some(s.to_vec());
    }
    // Make space for the ellipsis, if possible.
    if k >= new_length {
        if j < old_length {
            let r = utf8::encoded_valid_unichar(&s[j..])?;
            j += r;
        } else if i > 0 {
            i = utf8::find_previous_unichar(&s[..i])?;
        }
    }
    let mut e = s[..i].to_vec();
    e.extend_from_slice(ellipsis(true));
    e.extend_from_slice(&s[j..]);
    Some(e)
}

/// `ellipsize(s, length, percent)`.
pub fn ellipsize(s: &[u8], length: usize, percent: u32) -> Option<Vec<u8>> {
    ellipsize_mem(s, length, percent)
}

/// `yes_no(b)`.
pub fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// `strna(s)`: "n/a" for NULL.
pub fn strna(s: Option<&[u8]>) -> &[u8] {
    s.unwrap_or(b"n/a")
}

/// `strnull(s)`: "(null)" for NULL.
pub fn strnull(s: Option<&[u8]>) -> &[u8] {
    s.unwrap_or(b"(null)")
}

/// Split on any of `seps`, dropping empty words (`strv_split()`).
pub fn strv_split(s: &[u8], seps: &[u8]) -> Vec<Vec<u8>> {
    s.split(|b| seps.contains(b)).filter(|w| !w.is_empty()).map(|w| w.to_vec()).collect()
}

/// `strv_join(l, sep)`.
pub fn strv_join(l: &[Vec<u8>], sep: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, s) in l.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(s);
    }
    out
}

/// `strv_rebreak_lines(l, width)`.
pub fn strv_rebreak_lines(l: &[Vec<u8>], width: usize) -> Result<Vec<Vec<u8>>, i32> {
    if width == usize::MAX {
        return Ok(l.to_vec());
    }
    fn flush(
        broken: &mut Vec<Vec<u8>>,
        s: &[u8],
        start: usize,
        end: usize,
        in_prefix: bool,
        wb: Option<usize>,
        we: Option<usize>,
    ) {
        if in_prefix {
            broken.push(Vec::new());
            return;
        }
        let end = if let (Some(b), None) = (wb, we) { b } else { end };
        broken.push(s[start..end].to_vec());
    }
    let mut broken = Vec::new();
    for s in l {
        let s = crate::bytes::c_str_prefix(s);
        let mut start = 0usize;
        let mut wb: Option<usize> = None;
        let mut we: Option<usize> = None;
        let mut in_prefix = true;
        let mut after_newline = false;
        let mut w = 0usize;
        let mut p = 0usize;
        while p < s.len() {
            let ch = s[p];
            if NEWLINE.contains(&ch) {
                flush(&mut broken, s, start, p, in_prefix, wb, we);
                p += if ch == b'\r' && s.get(p + 1) == Some(&b'\n') { 2 } else { 1 };
                start = p;
                in_prefix = true;
                after_newline = true;
                wb = None;
                we = None;
                w = 0;
                continue;
            } else if WHITESPACE.contains(&ch) {
                if !in_prefix && (wb.is_none() || we.is_some()) {
                    wb = Some(p);
                    we = None;
                }
            } else {
                if wb.is_some() && we.is_none() {
                    we = Some(p);
                }
                in_prefix = false;
            }
            let (c, n) = match utf8::encoded_to_unichar(&s[p..]) {
                Ok(x) => x,
                Err(e) => {
                    crate::log_debug_errno!(
                        e,
                        "Line to break contains invalid UTF-8, refusing: ",
                        crate::errno::strerror(e)
                    );
                    return Err(e);
                }
            };
            w += utf8::unichar_console_width(c);
            if w > width
                && let (Some(b), Some(e)) = (wb, we)
            {
                broken.push(s[start..b].to_vec());
                p = e;
                start = e;
                after_newline = false;
                wb = None;
                we = None;
                w = 0;
                continue;
            }
            p += n;
        }
        if after_newline && in_prefix {
            continue;
        }
        flush(&mut broken, s, start, s.len(), in_prefix, wb, we);
    }
    Ok(broken)
}
