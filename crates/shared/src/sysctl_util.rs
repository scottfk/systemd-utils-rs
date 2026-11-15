// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sysctl-util.c`: normalizing sysctl names and reading/writing /proc/sys.

use crate::fileio::{
    WRITE_STRING_FILE_DISABLE_BUFFER, WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL,
    WRITE_STRING_FILE_VERIFY_ON_FAILURE, read_virtual_file, write_string_file,
};
use crate::path::{path_is_normalized, path_simplify};
use crate::string::{NEWLINE, delete_trailing_chars};
use crate::{bcat, log_debug};

/// `sysctl_normalize(s)`: "net.ipv4.ip_forward" -> "net/ipv4/ip_forward"
/// (dots and slashes swap if the first separator is a dot), simplified,
/// without a leading slash.
pub fn sysctl_normalize(s: &[u8]) -> Vec<u8> {
    let mut s = s.to_vec();
    if let Some(n) = s.iter().position(|&b| b == b'/' || b == b'.')
        && s[n] == b'.'
    {
        for b in s[n..].iter_mut() {
            if *b == b'.' {
                *b = b'/';
            } else if *b == b'/' {
                *b = b'.';
            }
        }
    }
    let mut s = path_simplify(&s);
    if s.first() == Some(&b'/') && s.len() > 1 {
        s.remove(0);
    }
    s
}

/// `/proc/sys/<property>`, simplified; `None` if not normalized.
fn proc_sys_path(property: &[u8]) -> Option<Vec<u8>> {
    let p = path_simplify(&bcat!("/proc/sys/", property));
    if path_is_normalized(&p) { Some(p) } else { None }
}

/// `sysctl_write(property, value)`.
pub fn sysctl_write(property: &[u8], value: &[u8]) -> Result<(), i32> {
    let p = proc_sys_path(property).ok_or(-libc::EINVAL)?;
    log_debug!("Setting '", p, "' to '", value, "'");
    write_string_file(
        &p,
        value,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE
            | WRITE_STRING_FILE_DISABLE_BUFFER
            | WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL,
    )
}

/// `sysctl_read(property, &ret)`.
pub fn sysctl_read(property: &[u8]) -> Result<Vec<u8>, i32> {
    let p = proc_sys_path(property).ok_or(-libc::EINVAL)?;
    let (v, _) = read_virtual_file(&p, usize::MAX)?;
    Ok(delete_trailing_chars(&v, Some(NEWLINE)).to_vec())
}

/// `sysctl_write_verify(property, value)`.
pub fn sysctl_write_verify(property: &[u8], value: &[u8]) -> Result<(), i32> {
    let original = sysctl_read(property).ok();
    if original.as_deref() == Some(value) {
        return Ok(());
    }
    let r = match sysctl_write(property, value) {
        Ok(()) => match sysctl_read(property) {
            Ok(current) if current == value => return Ok(()),
            Ok(_) => -libc::EINVAL,
            Err(r) => r,
        },
        Err(r) => r,
    };
    if let Some(o) = original {
        let _ = sysctl_write(property, &o);
    }
    Err(r)
}
