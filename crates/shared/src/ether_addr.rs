// SPDX-License-Identifier: LGPL-2.1-or-later
//! `ether-addr-util.c`: hardware addresses.

/// `HW_ADDR_MAX_SIZE`.
pub const HW_ADDR_MAX_SIZE: usize = 32;
const INFINIBAND_ALEN: usize = 20;
const ETH_ALEN: usize = 6;

/// `parse_hw_addr_one_field()`: Ok(true) if another field follows.
fn parse_one_field(s: &mut &[u8], sep: u8, len: usize, buf: &mut [u8]) -> Result<bool, i32> {
    let at = |p: &[u8], i: usize| p.get(i).copied().unwrap_or(0);
    let mut p = *s;
    let mut data: u16 = 0;
    for i in 0..len * 2 {
        let c = at(p, 0);
        if c == 0 || c == sep {
            if i == 0 {
                return Err(-libc::EINVAL);
            }
            break;
        }
        let x = (c as char).to_digit(16).ok_or(-libc::EINVAL)? as u16;
        data = (data << 4).wrapping_add(x);
        p = &p[1..];
    }
    let c = at(p, 0);
    if c != 0 && c != sep {
        return Err(-libc::EINVAL);
    }
    if len == 1 {
        buf[0] = data as u8;
    } else {
        buf[0] = (data >> 8) as u8;
        buf[1] = data as u8;
    }
    let cont = c == sep;
    *s = if cont { &p[1..] } else { p };
    Ok(cont)
}

/// `parse_hw_addr_full(s, expected_len, &ret)`; `None` is `SIZE_MAX`.
pub fn parse_hw_addr_full(s: &[u8], expected_len: Option<usize>) -> Result<Vec<u8>, i32> {
    if matches!(expected_len, Some(0 | 4 | 16)) {
        let a = match expected_len {
            Some(0) => crate::sys::inet_pton(libc::AF_INET, s).or_else(|| crate::sys::inet_pton(libc::AF_INET6, s)),
            Some(4) => crate::sys::inet_pton(libc::AF_INET, s),
            _ => crate::sys::inet_pton(libc::AF_INET6, s),
        };
        if let Some(a) = a {
            return Ok(a);
        }
    }
    let max_len = match expected_len {
        Some(0) => INFINIBAND_ALEN,
        None => HW_ADDR_MAX_SIZE,
        Some(n) => n,
    };
    let sep = s.iter().copied().find(|c| !c.is_ascii_hexdigit()).unwrap_or(0);
    let field_size = match sep {
        b'.' => 2,
        b':' | b'-' => 1,
        _ => return Err(-libc::EINVAL),
    };
    if max_len % field_size != 0 {
        return Err(-libc::EINVAL);
    }
    let mut bytes = [0u8; HW_ADDR_MAX_SIZE];
    let mut len = 0;
    let mut p = s;
    for i in 0..max_len / field_size {
        if !parse_one_field(&mut p, sep, field_size, &mut bytes[i * field_size..])? {
            len = (i + 1) * field_size;
            break;
        }
    }
    if len == 0 {
        return Err(-libc::EINVAL);
    }
    match expected_len {
        Some(0) => {
            if ![4, 16, ETH_ALEN, INFINIBAND_ALEN].contains(&len) {
                return Err(-libc::EINVAL);
            }
        }
        Some(n) if n != len => return Err(-libc::EINVAL),
        _ => {}
    }
    Ok(bytes[..len].to_vec())
}

/// `parse_hw_addr(s, &ret)`.
pub fn parse_hw_addr(s: &[u8]) -> Result<Vec<u8>, i32> {
    parse_hw_addr_full(s, Some(0))
}

/// `hw_addr_to_string_full(addr, flags)`: lowercase hex, with colons
/// unless `no_colon`.
pub fn hw_addr_to_string_full(a: &[u8], no_colon: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, b) in a.iter().enumerate() {
        if i > 0 && !no_colon {
            out.push(b':');
        }
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

/// `HW_ADDR_TO_STR()`.
pub fn hw_addr_to_string(a: &[u8]) -> Vec<u8> {
    hw_addr_to_string_full(a, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(parse_hw_addr(b"00:11:22:aa:BB:cc"), Ok(vec![0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]));
        assert_eq!(parse_hw_addr(b"0011.22aa.bbcc"), Ok(vec![0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]));
        assert_eq!(parse_hw_addr(b"0-1-2-3-4-5"), Ok(vec![0, 1, 2, 3, 4, 5]));
        assert_eq!(parse_hw_addr(b"10.0.0.1"), Ok(vec![10, 0, 0, 1]));
        assert_eq!(parse_hw_addr(b"00:11:22"), Err(-libc::EINVAL));
        assert_eq!(parse_hw_addr(b"001:11:22:33:44:55"), Err(-libc::EINVAL));
        assert_eq!(hw_addr_to_string(&[0, 0x11, 0xab]), b"00:11:ab");
        assert_eq!(hw_addr_to_string_full(&[0, 0x11, 0xab], true), b"0011ab");
    }
}
