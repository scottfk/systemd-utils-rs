// SPDX-License-Identifier: LGPL-2.1-or-later
//! `chattr-util.c`: file attributes (FS_IOC_GETFLAGS/SETFLAGS).

use crate::errno::strerror;
use crate::sys::{self, OwnedFd};

pub const FS_SECRM_FL: u32 = 0x1;
pub const FS_UNRM_FL: u32 = 0x2;
pub const FS_COMPR_FL: u32 = 0x4;
pub const FS_SYNC_FL: u32 = 0x8;
pub const FS_IMMUTABLE_FL: u32 = 0x10;
pub const FS_APPEND_FL: u32 = 0x20;
pub const FS_NODUMP_FL: u32 = 0x40;
pub const FS_NOATIME_FL: u32 = 0x80;
pub const FS_JOURNAL_DATA_FL: u32 = 0x4000;
pub const FS_NOTAIL_FL: u32 = 0x8000;
pub const FS_DIRSYNC_FL: u32 = 0x10000;
pub const FS_TOPDIR_FL: u32 = 0x20000;
pub const FS_EXTENT_FL: u32 = 0x80000;
pub const FS_NOCOW_FL: u32 = 0x800000;
pub const FS_PROJINHERIT_FL: u32 = 0x20000000;
pub const CHATTR_ALL_FL: u32 = FS_NOATIME_FL
    | FS_SYNC_FL
    | FS_DIRSYNC_FL
    | FS_APPEND_FL
    | FS_COMPR_FL
    | FS_NODUMP_FL
    | FS_EXTENT_FL
    | FS_IMMUTABLE_FL
    | FS_JOURNAL_DATA_FL
    | FS_SECRM_FL
    | FS_UNRM_FL
    | FS_NOTAIL_FL
    | FS_TOPDIR_FL
    | FS_NOCOW_FL
    | FS_PROJINHERIT_FL;

pub const CHATTR_FALLBACK_BITWISE: u32 = 1 << 0;
pub const CHATTR_WARN_UNSUPPORTED_FLAGS: u32 = 1 << 1;

/// `ERRNO_IS_NEG_NOT_SUPPORTED()`.
pub fn is_neg_not_supported(r: i32) -> bool {
    [
        libc::EOPNOTSUPP,
        libc::ENOTTY,
        libc::ENOSYS,
        libc::EAFNOSUPPORT,
        libc::EPFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT,
        libc::ENOPROTOOPT,
    ]
    .iter()
    .any(|&e| r == -e)
}

/// `ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED()`.
pub fn is_neg_ioctl_not_supported(r: i32) -> bool {
    is_neg_not_supported(r) || r == -libc::EINVAL
}

/// `chattr_full(fd, NULL, value, mask, &previous, &final, flags)` on an
/// open (non-O_PATH) fd: (result, previous, final).
pub fn chattr_fd(dir_fd: i32, value: u32, mask: u32, flags: u32) -> (i32, u32, u32) {
    let fd = match crate::fd::fd_reopen(dir_fd, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) {
        Ok(fd) => OwnedFd::new(fd),
        Err(e) => return (e, 0, 0),
    };
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return (e, 0, 0),
    };
    let t = st.st_mode & libc::S_IFMT;
    if t != libc::S_IFREG && t != libc::S_IFDIR {
        return (-libc::ENOTTY, 0, 0);
    }
    let old = match sys::fs_ioc_getflags(fd.raw()) {
        Ok(v) => v,
        Err(e) => return (e, 0, 0),
    };
    let new = (old & !mask) | (value & mask);
    if new == old {
        return (0, old, old);
    }
    let err = match sys::fs_ioc_setflags(fd.raw(), new) {
        Ok(()) => match sys::fs_ioc_getflags(fd.raw()) {
            Err(e) => return (e, 0, 0),
            Ok(attr) if attr == new => return (1, old, new),
            Ok(_) => -libc::EINVAL,
        },
        Err(e) => e,
    };
    if !is_neg_ioctl_not_supported(err) || flags & CHATTR_FALLBACK_BITWISE == 0 {
        return (err, 0, 0);
    }
    let mut current = old;
    let mut set_flags_errno = 0;
    for i in 0..32 {
        let m = 1u32 << i;
        if mask & m == 0 {
            continue;
        }
        let new_one = if value & m != 0 { current | m } else { current & !m };
        if new_one == current {
            continue;
        }
        if let Err(e) = sys::fs_ioc_setflags(fd.raw(), new_one) {
            if !is_neg_ioctl_not_supported(e) {
                return (e, 0, 0);
            }
            crate::log_full_errno!(
                if flags & CHATTR_WARN_UNSUPPORTED_FLAGS != 0 { libc::LOG_WARNING } else { libc::LOG_DEBUG },
                e,
                "Unable to set file attribute 0x",
                format!("{m:x}"),
                " on n/a, ignoring: ",
                strerror(e)
            );
            if set_flags_errno == 0 || !is_neg_ioctl_not_supported(e) {
                set_flags_errno = e;
            }
            continue;
        }
        match sys::fs_ioc_getflags(fd.raw()) {
            Ok(v) => current = v,
            Err(e) => return (e, 0, 0),
        }
    }
    let r = if current == new {
        1
    } else if is_neg_ioctl_not_supported(set_flags_errno) {
        set_flags_errno
    } else {
        -libc::ENOANO
    };
    (r, old, current)
}
