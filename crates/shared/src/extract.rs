// SPDX-License-Identifier: LGPL-2.1-or-later
//! `extract-word.c` and the parts of `escape.c` it uses.

use crate::string::WHITESPACE;
use crate::utf8;

pub const EXTRACT_RELAX: u32 = 1 << 0;
pub const EXTRACT_CUNESCAPE: u32 = 1 << 1;
pub const EXTRACT_UNESCAPE_RELAX: u32 = 1 << 2;
pub const EXTRACT_UNESCAPE_SEPARATORS: u32 = 1 << 3;
pub const EXTRACT_KEEP_QUOTE: u32 = 1 << 4;
pub const EXTRACT_UNQUOTE: u32 = 1 << 5;
pub const EXTRACT_DONT_COALESCE_SEPARATORS: u32 = 1 << 6;
pub const EXTRACT_RETAIN_ESCAPE: u32 = 1 << 7;
pub const EXTRACT_RETAIN_SEPARATORS: u32 = 1 << 8;

/// `unhexchar()`.
pub fn unhexchar(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

/// `unoctchar()`.
pub fn unoctchar(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'7' => Some((c - b'0') as u32),
        _ => None,
    }
}

/// `utf8_encode_unichar()`.
pub fn utf8_encode_unichar(out: &mut Vec<u8>, g: u32) -> usize {
    if g < (1 << 7) {
        out.push((g & 0x7f) as u8);
        1
    } else if g < (1 << 11) {
        out.push((0xc0 | ((g >> 6) & 0x1f)) as u8);
        out.push((0x80 | (g & 0x3f)) as u8);
        2
    } else if g < (1 << 16) {
        out.push((0xe0 | ((g >> 12) & 0x0f)) as u8);
        out.push((0x80 | ((g >> 6) & 0x3f)) as u8);
        out.push((0x80 | (g & 0x3f)) as u8);
        3
    } else if g < (1 << 21) {
        out.push((0xf0 | ((g >> 18) & 0x07)) as u8);
        out.push((0x80 | ((g >> 12) & 0x3f)) as u8);
        out.push((0x80 | ((g >> 6) & 0x3f)) as u8);
        out.push((0x80 | (g & 0x3f)) as u8);
        4
    } else {
        0
    }
}

/// `cunescape_one(p, length, &ret, &eight_bit, accept_nul)`:
/// (code, eight_bit, bytes consumed).  Bytes past the slice read as NUL.
pub fn cunescape_one(p: &[u8], length: usize, accept_nul: bool) -> Result<(u32, bool, usize), i32> {
    let at = |i: usize| p.get(i).copied().unwrap_or(0);
    let einval = Err(-libc::EINVAL);
    if length != usize::MAX && length < 1 {
        return einval;
    }
    let simple = |c: u8| Ok((c as u32, false, 1));
    match at(0) {
        b'a' => simple(0x07),
        b'b' => simple(0x08),
        b'f' => simple(0x0c),
        b'n' => simple(b'\n'),
        b'r' => simple(b'\r'),
        b't' => simple(b'\t'),
        b'v' => simple(0x0b),
        b'\\' => simple(b'\\'),
        b'"' => simple(b'"'),
        b'\'' => simple(b'\''),
        b's' => simple(b' '),
        b'x' => {
            if length != usize::MAX && length < 3 {
                return einval;
            }
            let (Some(a), Some(b)) = (unhexchar(at(1)), unhexchar(at(2))) else { return einval };
            if a == 0 && b == 0 && !accept_nul {
                return einval;
            }
            Ok(((a << 4) | b, true, 3))
        }
        b'u' => {
            if length != usize::MAX && length < 5 {
                return einval;
            }
            let mut c = 0u32;
            for i in 0..4 {
                c = (c << 4) | unhexchar(at(1 + i)).ok_or(-libc::EINVAL)?;
            }
            if c == 0 && !accept_nul {
                return einval;
            }
            if (0xD800..=0xDFFF).contains(&c) {
                return einval;
            }
            Ok((c, false, 5))
        }
        b'U' => {
            if length != usize::MAX && length < 9 {
                return einval;
            }
            let mut c = 0u32;
            for i in 0..8 {
                c = (c << 4) | unhexchar(at(1 + i)).ok_or(-libc::EINVAL)?;
            }
            if c == 0 && !accept_nul {
                return einval;
            }
            if !utf8::unichar_is_valid(c) {
                return einval;
            }
            Ok((c, false, 9))
        }
        b'0'..=b'7' => {
            if length != usize::MAX && length < 3 {
                return einval;
            }
            let (Some(a), Some(b), Some(c)) = (unoctchar(at(0)), unoctchar(at(1)), unoctchar(at(2))) else {
                return einval;
            };
            if a == 0 && b == 0 && c == 0 && !accept_nul {
                return einval;
            }
            let m = (a << 6) | (b << 3) | c;
            if m > 255 {
                return einval;
            }
            Ok((m, true, 3))
        }
        _ => einval,
    }
}

/// `extract_first_word(&p, &ret, separators, flags)`.
///
/// `p` is the unparsed rest (C's `*p`; `None` once C would set it to NULL).
/// Returns `Ok(None)` when there was no word (C's 0), `Ok(Some(word))` for
/// a word (C's 1).
pub fn extract_first_word(
    p: &mut Option<&[u8]>,
    separators: Option<&[u8]>,
    flags: u32,
) -> Result<Option<Vec<u8>>, i32> {
    let seps = separators.unwrap_or(WHITESPACE);
    let Some(mut cur) = *p else {
        return Ok(None);
    };
    let at = |s: &[u8]| s.first().copied().unwrap_or(0);
    let mut s: Option<Vec<u8>> = None;
    let mut quote: u8 = 0;
    let mut backslash = false;

    enum End {
        Terminate,
        Finish,
        Next,
    }

    if flags & EXTRACT_DONT_COALESCE_SEPARATORS != 0 {
        s = Some(Vec::new());
    }

    let end: End = 'outer: {
        loop {
            let c = at(cur);
            if c == 0 {
                break 'outer End::Terminate;
            } else if seps.contains(&c) {
                if flags & EXTRACT_DONT_COALESCE_SEPARATORS != 0 {
                    if flags & EXTRACT_RETAIN_SEPARATORS == 0 {
                        cur = &cur[1..];
                    }
                    break 'outer End::Next;
                }
            } else {
                if s.is_none() {
                    s = Some(Vec::new());
                }
                break;
            }
            cur = &cur[1..];
        }

        let buf = s.as_mut().expect("allocated above");
        loop {
            let c = at(cur);
            if backslash {
                if c == 0 {
                    if flags & EXTRACT_UNESCAPE_RELAX != 0 && (quote == 0 || flags & EXTRACT_RELAX != 0) {
                        buf.push(b'\\');
                        break 'outer End::Terminate;
                    }
                    if flags & EXTRACT_RELAX != 0 {
                        break 'outer End::Terminate;
                    }
                    return Err(-libc::EINVAL);
                }
                if flags & (EXTRACT_CUNESCAPE | EXTRACT_UNESCAPE_SEPARATORS | EXTRACT_UNESCAPE_RELAX) != 0 {
                    let un =
                        if flags & EXTRACT_CUNESCAPE != 0 { cunescape_one(cur, usize::MAX, false).ok() } else { None };
                    if let Some((u, eight_bit, r)) = un {
                        cur = &cur[r - 1..];
                        if eight_bit {
                            buf.push(u as u8);
                        } else {
                            utf8_encode_unichar(buf, u);
                        }
                    } else if flags & EXTRACT_UNESCAPE_SEPARATORS != 0 && (seps.contains(&c) || c == b'\\') {
                        buf.push(c);
                    } else if flags & EXTRACT_UNESCAPE_RELAX != 0 {
                        buf.push(b'\\');
                        buf.push(c);
                    } else {
                        return Err(-libc::EINVAL);
                    }
                } else {
                    buf.push(c);
                }
                backslash = false;
                cur = &cur[1..];
            } else if quote != 0 {
                loop {
                    let c = at(cur);
                    if c == 0 {
                        if flags & EXTRACT_RELAX != 0 {
                            break 'outer End::Terminate;
                        }
                        return Err(-libc::EINVAL);
                    } else if c == quote {
                        quote = 0;
                        if flags & EXTRACT_UNQUOTE != 0 {
                            break;
                        }
                    } else if c == b'\\' && flags & EXTRACT_RETAIN_ESCAPE == 0 {
                        backslash = true;
                        break;
                    }
                    buf.push(c);
                    if quote == 0 {
                        break;
                    }
                    cur = &cur[1..];
                }
                cur = &cur[1..];
            } else {
                loop {
                    let c = at(cur);
                    if c == 0 {
                        break 'outer End::Terminate;
                    } else if (c == b'\'' || c == b'"') && flags & (EXTRACT_KEEP_QUOTE | EXTRACT_UNQUOTE) != 0 {
                        quote = c;
                        if flags & EXTRACT_UNQUOTE != 0 {
                            break;
                        }
                    } else if c == b'\\' && flags & EXTRACT_RETAIN_ESCAPE == 0 {
                        backslash = true;
                        break;
                    } else if seps.contains(&c) {
                        if flags & EXTRACT_DONT_COALESCE_SEPARATORS != 0 {
                            if flags & EXTRACT_RETAIN_SEPARATORS == 0 {
                                cur = &cur[1..];
                            }
                            break 'outer End::Next;
                        }
                        if flags & EXTRACT_RETAIN_SEPARATORS == 0 {
                            loop {
                                let c = at(cur);
                                if c == 0 {
                                    break 'outer End::Terminate;
                                }
                                if !seps.contains(&c) {
                                    break;
                                }
                                cur = &cur[1..];
                            }
                        }
                        break 'outer End::Finish;
                    }
                    buf.push(c);
                    if quote != 0 {
                        break;
                    }
                    cur = &cur[1..];
                }
                cur = &cur[1..];
            }
        }
    };

    match end {
        End::Terminate => {
            *p = None;
            match s {
                None => Ok(None),
                Some(v) => Ok(Some(v)),
            }
        }
        End::Finish => {
            *p = Some(cur);
            match s {
                None => {
                    *p = None;
                    Ok(None)
                }
                Some(v) => Ok(Some(v)),
            }
        }
        End::Next => {
            *p = Some(cur);
            Ok(Some(s.unwrap_or_default()))
        }
    }
}

/// `strv_split_full(&l, s, separators, flags)`.
pub fn strv_split_full(s: &[u8], separators: Option<&[u8]>, flags: u32) -> Result<Vec<Vec<u8>>, i32> {
    let mut p = Some(s);
    let mut l = Vec::new();
    while let Some(w) = extract_first_word(&mut p, separators, flags)? {
        l.push(w);
    }
    Ok(l)
}

/// `cunescape(s, 0, &ret)`: undo C escapes; invalid ones are errors.
pub fn cunescape(s: &[u8]) -> Result<Vec<u8>, i32> {
    let s = crate::bytes::c_str_prefix(s);
    let mut out = Vec::with_capacity(s.len());
    let mut f = 0;
    while f < s.len() {
        if s[f] != b'\\' {
            out.push(s[f]);
            f += 1;
            continue;
        }
        let remaining = s.len() - f;
        if remaining == 1 {
            return Err(-libc::EINVAL);
        }
        let (u, eight_bit, r) = cunescape_one(&s[f + 1..], remaining - 1, false)?;
        f += r + 1;
        if eight_bit {
            out.push(u as u8);
        } else {
            utf8_encode_unichar(&mut out, u);
        }
    }
    Ok(out)
}

/// `extract_many_words(&p, NULL, flags, &w1, ..., &wn)`: the words found
/// (fewer than n if the line ran out) and what's left of p.
pub fn extract_many_words(
    p: &mut Option<&[u8]>,
    separators: Option<&[u8]>,
    flags: u32,
    n: usize,
) -> Result<Vec<Vec<u8>>, i32> {
    let mut out = Vec::new();
    for _ in 0..n {
        match extract_first_word(p, separators, flags)? {
            Some(w) => out.push(w),
            None => break,
        }
    }
    Ok(out)
}
