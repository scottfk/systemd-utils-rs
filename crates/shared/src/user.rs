// SPDX-License-Identifier: LGPL-2.1-or-later
//! `user-util.c`: user and group names.

use crate::sys;

const UID_NOBODY: u32 = 65534;

/// `synthesize_nobody()`.
fn synthesize_nobody() -> bool {
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
