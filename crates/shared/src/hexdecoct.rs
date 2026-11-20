// SPDX-License-Identifier: LGPL-2.1-or-later
//! `hexdecoct.c`: base64 decoding.

/// `unbase64char()`.
fn unbase64char(c: u8) -> Result<u8, i32> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(-libc::EINVAL),
    }
}

/// `strchr(WHITESPACE, c)`, which also matches the terminating NUL.
fn is_ws(c: u8) -> bool {
    c == 0 || crate::string::WHITESPACE.contains(&c)
}

const PAD: i32 = i32::MAX;

/// `unbase64_next()`: the next value, PAD for '=', or -EPIPE at the end.
fn unbase64_next(p: &mut &[u8]) -> i32 {
    while let Some(&c) = p.first() {
        if !is_ws(c) {
            break;
        }
        *p = &p[1..];
    }
    let Some(&c) = p.first() else { return -libc::EPIPE };
    let ret = if c == b'=' {
        PAD
    } else {
        match unbase64char(c) {
            Ok(v) => v as i32,
            Err(e) => return e,
        }
    };
    *p = &p[1..];
    while let Some(&c) = p.first() {
        if !is_ws(c) {
            break;
        }
        *p = &p[1..];
    }
    ret
}

/// `unbase64mem_full(p, l, secure=false, &data, &size)`.
pub fn unbase64mem(input: &[u8]) -> Result<Vec<u8>, i32> {
    let mut x = input;
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    loop {
        let a = unbase64_next(&mut x);
        if a == -libc::EPIPE {
            break;
        }
        if a < 0 {
            return Err(a);
        }
        if a == PAD {
            return Err(-libc::EINVAL);
        }
        let b = unbase64_next(&mut x);
        if b < 0 {
            return Err(b);
        }
        if b == PAD {
            return Err(-libc::EINVAL);
        }
        let c = unbase64_next(&mut x);
        if c < 0 {
            return Err(c);
        }
        let d = unbase64_next(&mut x);
        if d < 0 {
            return Err(d);
        }
        let (a, b) = (a as u8, b as u8);
        if c == PAD {
            if d != PAD {
                return Err(-libc::EINVAL);
            }
            if b & 15 != 0 {
                return Err(-libc::EINVAL);
            }
            if !x.is_empty() {
                return Err(-libc::ENAMETOOLONG);
            }
            out.push(a << 2 | b >> 4);
            break;
        }
        let c = c as u8;
        if d == PAD {
            if c & 3 != 0 {
                return Err(-libc::EINVAL);
            }
            if !x.is_empty() {
                return Err(-libc::ENAMETOOLONG);
            }
            out.push(a << 2 | b >> 4);
            out.push(b << 4 | c >> 2);
            break;
        }
        let d = d as u8;
        out.push(a << 2 | b >> 4);
        out.push(b << 4 | c >> 2);
        out.push(c << 6 | d);
    }
    Ok(out)
}

/// `unhexmem(p, &ret, &size)`: an even number of hex digits.
pub fn unhexmem(p: &[u8]) -> Result<Vec<u8>, i32> {
    if !p.len().is_multiple_of(2) {
        return Err(-libc::EINVAL);
    }
    p.chunks(2)
        .map(|c| {
            let h = (c[0] as char).to_digit(16).ok_or(-libc::EINVAL)?;
            let l = (c[1] as char).to_digit(16).ok_or(-libc::EINVAL)?;
            Ok((h << 4 | l) as u8)
        })
        .collect()
}

/// `hexmem(p, l)`: lowercase hex.
pub fn hexmem(p: &[u8]) -> Vec<u8> {
    p.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// `base64mem(p, l, &ret)`: with padding, without line breaks.
pub fn base64mem(p: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(p.len().div_ceil(3) * 4);
    for c in p.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63]);
        out.push(T[(n >> 12) as usize & 63]);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if c.len() > 2 { T[n as usize & 63] } else { b'=' });
    }
    out
}
