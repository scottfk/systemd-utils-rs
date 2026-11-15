// SPDX-License-Identifier: LGPL-2.1-or-later
//! `xattr-util.c`: extended attributes on (possibly O_PATH) fds.

use crate::fd::proc_fd_path;
use crate::sys;

/// `getxattr_at_malloc(fd, NULL, name, AT_EMPTY_PATH)`: O_PATH fds go
/// through /proc/self/fd.
pub fn fgetxattr_malloc(fd: i32, name: &[u8]) -> Result<Vec<u8>, i32> {
    if sys::fd_is_opath(fd)? {
        sys::getxattr_any(None, &proc_fd_path(fd), name)
    } else {
        sys::getxattr_any(Some(fd), b"", name)
    }
}

/// `xsetxattr_full(fd, NULL, AT_EMPTY_PATH, name, value, size, flags)`.
pub fn fsetxattr_full(fd: i32, name: &[u8], value: &[u8], flags: i32) -> Result<(), i32> {
    // Skip the write if the value is already there (plain replace mode only).
    if flags == 0
        && let Ok(old) = fgetxattr_malloc(fd, name)
        && old == value
    {
        return Ok(());
    }
    if sys::fd_is_opath(fd)? {
        sys::setxattr_any(None, &proc_fd_path(fd), name, value, flags)
    } else {
        sys::setxattr_any(Some(fd), b"", name, value, flags)
    }
}
