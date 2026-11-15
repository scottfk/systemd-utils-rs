// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-id128.c` and `id128-util.c`: machine and boot IDs.

use crate::chase::{CHASE_MUST_BE_REGULAR, CHASE_PREFIX_ROOT, chase};
use crate::extract::unhexchar;
use crate::path::empty_or_root;
use crate::sys::{self, OwnedFd};

pub type Id128 = [u8; 16];

pub const ID128_FORMAT_PLAIN: u32 = 1 << 0;
pub const ID128_FORMAT_UUID: u32 = 1 << 1;
pub const ID128_REFUSE_NULL: u32 = 1 << 3;

/// `sd_id128_from_string()`.
pub fn from_string(s: &[u8]) -> Result<Id128, i32> {
    let (mut s, mut is_guid) = (s, false);
    if s.len() >= 9 && s[..9].eq_ignore_ascii_case(b"urn:uuid:") {
        s = &s[9..];
        is_guid = true;
    }
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut t = [0u8; 16];
    let (mut n, mut i) = (0, 0);
    while n < 16 {
        if at(i) == b'-' {
            if i == 8 {
                is_guid = true;
            } else if [13, 18, 23].contains(&i) {
                if !is_guid {
                    return Err(-libc::EINVAL);
                }
            } else {
                return Err(-libc::EINVAL);
            }
            i += 1;
            continue;
        }
        let a = unhexchar(at(i)).ok_or(-libc::EINVAL)?;
        let b = unhexchar(at(i + 1)).ok_or(-libc::EINVAL)?;
        i += 2;
        t[n] = ((a << 4) | b) as u8;
        n += 1;
    }
    if i != if is_guid { 36 } else { 32 } || s.len() != i {
        return Err(-libc::EINVAL);
    }
    Ok(t)
}

/// `sd_id128_to_string()`.
pub fn to_string(id: &Id128) -> Vec<u8> {
    id.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// `id128_read_fd(fd, flags, &ret)`.
pub fn read_fd(fd: i32, f: u32) -> Result<Id128, i32> {
    // loop_read() of up to 37 bytes.
    let mut buf = [0u8; 37];
    let mut l = 0;
    while l < buf.len() {
        match sys::read(fd, &mut buf[l..]) {
            Ok(0) => break,
            Ok(n) => l += n,
            Err(e) if e == -libc::EINTR => {}
            Err(e) => return Err(e),
        }
    }
    let b = &buf[..l];
    let s: &[u8] = match l {
        0 => return Err(-libc::ENOMEDIUM),
        13 | 14 => return Err(if b"uninitialized\n"[..l] == *b { -libc::ENOPKG } else { -libc::EINVAL }),
        33 | 32 => {
            if l == 33 && b[32] != b'\n' {
                return Err(-libc::EUCLEAN);
            }
            if f & ID128_FORMAT_PLAIN == 0 {
                return Err(-libc::EUCLEAN);
            }
            &b[..32]
        }
        37 | 36 => {
            if l == 37 && b[36] != b'\n' {
                return Err(-libc::EUCLEAN);
            }
            if f & ID128_FORMAT_UUID == 0 {
                return Err(-libc::EUCLEAN);
            }
            &b[..36]
        }
        _ => return Err(-libc::EUCLEAN),
    };
    let id = from_string(s).map_err(|e| if e == -libc::EINVAL { -libc::EUCLEAN } else { e })?;
    if f & ID128_REFUSE_NULL != 0 && id == [0; 16] {
        return Err(-libc::ENOMEDIUM);
    }
    Ok(id)
}

/// `id128_read(path, flags, &ret)`.
pub fn read(path: &[u8], f: u32) -> Result<Id128, i32> {
    let fd = OwnedFd::new(sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY, 0)?);
    read_fd(fd.raw(), f)
}

/// `id128_get_machine(root, &ret)`.
pub fn get_machine(root: Option<&[u8]>) -> Result<Id128, i32> {
    if empty_or_root(root) {
        return read(b"/etc/machine-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL);
    }
    let c = chase(b"/etc/machine-id", root, CHASE_PREFIX_ROOT | CHASE_MUST_BE_REGULAR, false, true)?;
    let pfd = c.fd.expect("requested");
    let fd = OwnedFd::new(crate::fd::fd_reopen(pfd.raw(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY)?);
    read_fd(fd.raw(), ID128_FORMAT_PLAIN | ID128_REFUSE_NULL)
}

/// `sd_id128_get_boot(&ret)`.
pub fn get_boot() -> Result<Id128, i32> {
    match read(b"/proc/sys/kernel/random/boot_id", ID128_FORMAT_UUID | ID128_REFUSE_NULL) {
        Err(e) if e == -libc::ENOENT && !crate::fs::proc_mounted() => Err(-libc::ENOSYS),
        r => r,
    }
}
