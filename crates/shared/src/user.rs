// SPDX-License-Identifier: LGPL-2.1-or-later
//! `user-util.c`: user and group names.

use crate::sys;

pub const UID_NOBODY: u32 = 65534;

/// `synthesize_nobody()`.
pub fn synthesize_nobody() -> bool {
    use std::sync::atomic::{AtomicI8, Ordering};
    static CACHE: AtomicI8 = AtomicI8::new(-1);
    let c = CACHE.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = sys::stat(b"/etc/systemd/dont-synthesize-nobody").is_err();
    CACHE.store(v as i8, Ordering::Relaxed);
    v
}

/// `uid_to_name()`.
pub fn uid_to_name(uid: u32) -> Vec<u8> {
    if uid == 0 {
        return b"root".to_vec();
    }
    if uid == UID_NOBODY && synthesize_nobody() {
        return b"nobody".to_vec();
    }
    if uid != u32::MAX
        && uid != 0xFFFF
        && let Some(n) = sys::getpwuid_name(uid)
    {
        return n;
    }
    uid.to_string().into_bytes()
}

/// `gid_to_name()`.
pub fn gid_to_name(gid: u32) -> Vec<u8> {
    if gid == 0 {
        return b"root".to_vec();
    }
    if gid == UID_NOBODY && synthesize_nobody() {
        return b"nobody".to_vec();
    }
    if gid != u32::MAX
        && gid != 0xFFFF
        && let Some(n) = sys::getgrgid_name(gid)
    {
        return n;
    }
    gid.to_string().into_bytes()
}

/// `uid_is_valid()`.
pub fn uid_is_valid(u: u32) -> bool {
    u != u32::MAX && u != 0xFFFF
}

/// `parse_uid()` (also `parse_gid()`): strict decimal, no sign or leading zero.
pub fn parse_uid(s: &[u8]) -> Result<u32, i32> {
    use crate::parse::{
        SAFE_ATO_REFUSE_LEADING_WHITESPACE, SAFE_ATO_REFUSE_LEADING_ZERO, SAFE_ATO_REFUSE_PLUS_MINUS, safe_atou_full,
    };
    let u = safe_atou_full(
        s,
        10 | SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO | SAFE_ATO_REFUSE_LEADING_WHITESPACE,
    )?;
    if !uid_is_valid(u) {
        return Err(-libc::ENXIO);
    }
    Ok(u)
}

/// `errno_is_user_doesnt_exist()`.
fn doesnt_exist(r: i32) -> bool {
    matches!(r.abs(), libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM)
}

/// `get_user_creds(name, 0, NULL, &uid, NULL, NULL, NULL)`.
pub fn get_user_uid(name: &[u8]) -> Result<u32, i32> {
    if name == b"root" || name == b"0" {
        return Ok(0);
    }
    if (name == b"nobody" || name == b"65534") && synthesize_nobody() {
        return Ok(UID_NOBODY);
    }
    if let Ok(u) = parse_uid(name) {
        return match sys::getpwuid_exists(u) {
            Ok(true) => Ok(u),
            Ok(false) => Err(-libc::ESRCH),
            Err(e) if doesnt_exist(e) => Err(-libc::ESRCH),
            Err(e) => Err(e),
        };
    }
    if name.is_empty() {
        return Err(-libc::EINVAL);
    }
    {
        match sys::getpwnam_ids(name) {
            Ok(Some((u, _, _))) => {
                if !uid_is_valid(u) {
                    return Err(-libc::EBADMSG);
                }
                Ok(u)
            }
            Ok(None) => Err(-libc::ESRCH),
            Err(e) if doesnt_exist(e) => Err(-libc::ESRCH),
            Err(e) => Err(e),
        }
    }
}

/// `get_group_creds(name, 0, NULL, &gid)`.
pub fn get_group_gid(name: &[u8]) -> Result<u32, i32> {
    if name == b"root" || name == b"0" {
        return Ok(0);
    }
    if (name == b"nobody" || name == b"65534") && synthesize_nobody() {
        return Ok(UID_NOBODY);
    }
    if let Ok(g) = parse_uid(name) {
        return match sys::getgrgid_exists(g) {
            Ok(true) => Ok(g),
            Ok(false) => Err(-libc::ESRCH),
            Err(e) if doesnt_exist(e) => Err(-libc::ESRCH),
            Err(e) => Err(e),
        };
    }
    if name.is_empty() {
        return Err(-libc::EINVAL);
    }
    match sys::getgrnam_id(name) {
        Ok(Some(g)) => {
            if !uid_is_valid(g) {
                return Err(-libc::EBADMSG);
            }
            Ok(g)
        }
        Ok(None) => Err(-libc::ESRCH),
        Err(e) if doesnt_exist(e) => Err(-libc::ESRCH),
        Err(e) => Err(e),
    }
}

/// `strerror_user()` / `strerror_group()`.
pub fn strerror_account(r: i32, what: &str) -> Vec<u8> {
    match r.abs() {
        libc::ESRCH => format!("Unknown {what}").into_bytes(),
        libc::ENOEXEC => format!("Not a system {what}").into_bytes(),
        e => crate::errno::strerror(e),
    }
}
