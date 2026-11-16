// SPDX-License-Identifier: LGPL-2.1-or-later
//! `escape.c`: C-style escaping (the parts in use).

/// `cescape_char(c, buf)`.
pub fn cescape_char(c: u8, out: &mut Vec<u8>) {
    let esc = match c {
        0x07 => Some(b'a'),
        0x08 => Some(b'b'),
        0x0c => Some(b'f'),
        b'\n' => Some(b'n'),
        b'\r' => Some(b'r'),
        b'\t' => Some(b't'),
        0x0b => Some(b'v'),
        b'\\' => Some(b'\\'),
        b'"' => Some(b'"'),
        b'\'' => Some(b'\''),
        _ => None,
    };
    if let Some(e) = esc {
        out.extend_from_slice(&[b'\\', e]);
    } else if !(b' '..127).contains(&c) {
        // C compares a (signed) char, so bytes >= 128 count as < ' '.
        out.extend_from_slice(&[b'\\', b'0' + (c >> 6), b'0' + ((c >> 3) & 7), b'0' + (c & 7)]);
    } else {
        out.push(c);
    }
}

/// `cescape(s)`, stopping at a NUL as C's strlen() would.
pub fn cescape(s: &[u8]) -> Vec<u8> {
    let s = crate::bytes::c_str_prefix(s);
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        cescape_char(c, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(cescape(b"a\nb\"\\\x01\xff"), b"a\\nb\\\"\\\\\\001\\377".to_vec());
    }
}
