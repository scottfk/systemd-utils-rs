// SPDX-License-Identifier: LGPL-2.1-or-later
//! `errno-util.h` and the errno parts of `log.h`.
//!
//! Errors are negative errno values, as in systemd's C (`int r`).  A
//! "synthetic" error (`SYNTHETIC_ERRNO()`) has bit 30 set: it is logged the
//! same, but not reported as `ERRNO=` to the journal.

use libc::{EACCES, EPERM, EROFS};

/// `SYNTHETIC_ERRNO(num)`.
pub const fn synthetic(num: i32) -> i32 {
    num.abs() | (1 << 30)
}

/// `IS_SYNTHETIC_ERRNO(val)`.
pub const fn is_synthetic(val: i32) -> bool {
    (val >> 30) == 1
}

/// `ERRNO_VALUE(val)`.
pub const fn errno_value(val: i32) -> i32 {
    val.abs() & !(1 << 30)
}

/// `ERRNO_IS_NEG_NOT_SUPPORTED(r)`.
pub fn is_neg_not_supported(r: i32) -> bool {
    matches!(
        -r,
        libc::EOPNOTSUPP
            | libc::ENOTTY
            | libc::ENOSYS
            | libc::EAFNOSUPPORT
            | libc::EPFNOSUPPORT
            | libc::EPROTONOSUPPORT
            | libc::ESOCKTNOSUPPORT
            | libc::ENOPROTOOPT
    )
}

/// `ERRNO_IS_NEG_PRIVILEGE(r)`.
pub fn is_neg_privilege(r: i32) -> bool {
    r == -EACCES || r == -EPERM
}

/// `ERRNO_IS_PRIVILEGE(r)`.
pub fn is_privilege(r: i32) -> bool {
    r != i32::MIN && is_neg_privilege(-r.abs())
}

/// `ERRNO_IS_NEG_FS_WRITE_REFUSED(r)`.
pub fn is_neg_fs_write_refused(r: i32) -> bool {
    r == -EROFS || is_neg_privilege(r)
}

/// `RET_GATHER(ret, r)`: keep the first error.
pub fn ret_gather(ret: &mut i32, r: i32) {
    if *ret >= 0 && r < 0 {
        *ret = r;
    }
}

/// `STRERROR(e)` / `%m`: the message for an (absolute, possibly synthetic) error.
pub fn strerror(e: i32) -> Vec<u8> {
    crate::sys::strerror(errno_value(e))
}

/// `errno_or_else(fallback)`: `-errno` if errno is set, else `-fallback`.
pub fn errno_or_else(fallback: i32) -> i32 {
    let e = crate::sys::errno();
    if e > 0 { -e } else { -fallback.abs() }
}
