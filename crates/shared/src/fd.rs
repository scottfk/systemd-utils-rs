// SPDX-License-Identifier: LGPL-2.1-or-later
//! `fd-util.c`: the special dir fds and fd helpers.

use crate::path::safe_getcwd;
use crate::sys;

pub const AT_FDCWD: i32 = libc::AT_FDCWD;
/// `XAT_FDROOT`: "the host's root directory".
pub const XAT_FDROOT: i32 = -8192;

/// `wildcard_fd_is_valid()`.
pub fn wildcard_fd_is_valid(fd: i32) -> bool {
    fd >= 0 || fd == AT_FDCWD || fd == XAT_FDROOT
}

/// `xstatx()` on a wildcard fd.
fn statx_wild(fd: i32) -> Result<sys::Statx, i32> {
    if fd == XAT_FDROOT { sys::statx_at(AT_FDCWD, b"/", 0) } else { sys::statx_fd(fd) }
}

/// `fds_inode_and_mount_same(fd1, fd2)`.
pub fn fds_inode_and_mount_same(fd1: i32, fd2: i32) -> Result<bool, i32> {
    let a = statx_wild(fd1)?;
    if fd1 == fd2 {
        return Ok(true);
    }
    let b = statx_wild(fd2)?;
    let mount_same = match (a.mnt_id, b.mnt_id) {
        (Some(x), Some(y)) => x == y,
        _ => return Err(-libc::ENODATA),
    };
    if !mount_same {
        return Ok(false);
    }
    Ok(a.ino == b.ino && a.dev_major == b.dev_major && a.dev_minor == b.dev_minor)
}

fn is_literal_root(p: &[u8]) -> bool {
    let n = p.iter().take_while(|&&b| b == b'/').count();
    n >= 1 && n == p.len()
}

/// `path_is_root_at(dir_fd, path)`.
pub fn path_is_root_at(dir_fd: i32, path: &[u8]) -> Result<bool, i32> {
    if dir_fd == XAT_FDROOT && path.is_empty() {
        return Ok(true);
    }
    if (dir_fd == XAT_FDROOT || dir_fd == AT_FDCWD) && is_literal_root(path) {
        return Ok(true);
    }
    let mut _owned = None;
    let mut dir_fd = dir_fd;
    if !path.is_empty() {
        let d = if dir_fd == XAT_FDROOT && !crate::path::path_is_absolute(path) { AT_FDCWD } else { dir_fd };
        let p = if dir_fd == XAT_FDROOT && !crate::path::path_is_absolute(path) {
            [b"/", path].concat()
        } else {
            path.to_vec()
        };
        match sys::openat(d, &p, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0) {
            Ok(fd) => {
                dir_fd = fd;
                _owned = Some(sys::OwnedFd::new(fd));
            }
            Err(e) if e == -libc::ENOTDIR => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    fds_inode_and_mount_same(dir_fd, XAT_FDROOT)
}

/// `dir_fd_is_root()`.
pub fn dir_fd_is_root(dir_fd: i32) -> Result<bool, i32> {
    if dir_fd == XAT_FDROOT { Ok(true) } else { path_is_root_at(dir_fd, b"") }
}

/// `proc_fd_enoent_errno()`: ENOENT on /proc/self/fd means /proc is missing.
fn proc_fd_enoent_errno() -> i32 {
    match sys::stat(b"/proc/self/fd/") {
        Err(e) if e == -libc::ENOENT => -libc::ENOSYS,
        _ => -libc::EBADF,
    }
}

/// `fd_reopen(fd, flags)`.
pub fn fd_reopen(fd: i32, flags: i32) -> Result<i32, i32> {
    if flags & libc::O_NOFOLLOW != 0 {
        return Err(-libc::ELOOP);
    }
    if fd == XAT_FDROOT {
        return sys::open(b"/", flags | libc::O_DIRECTORY, 0);
    }
    if flags & libc::O_DIRECTORY != 0 || fd == AT_FDCWD {
        return sys::openat(fd, b".", flags | libc::O_DIRECTORY, 0);
    }
    match sys::open(format!("/proc/self/fd/{fd}").as_bytes(), flags, 0) {
        Ok(n) => Ok(n),
        Err(e) if e == -libc::ENOENT => Err(proc_fd_enoent_errno()),
        Err(e) => Err(e),
    }
}

/// `fd_get_path(fd)`.
pub fn fd_get_path(fd: i32) -> Result<Vec<u8>, i32> {
    if fd == AT_FDCWD {
        return safe_getcwd();
    }
    if fd == XAT_FDROOT {
        return Ok(b"/".to_vec());
    }
    match sys::readlinkat(AT_FDCWD, format!("/proc/self/fd/{fd}").as_bytes()) {
        Ok(p) => Ok(p),
        Err(e) if e == -libc::ENOENT => Err(proc_fd_enoent_errno()),
        Err(e) => Err(e),
    }
}

/// `FORMAT_PROC_FD_PATH(fd)`.
pub fn proc_fd_path(fd: i32) -> Vec<u8> {
    format!("/proc/self/fd/{fd}").into_bytes()
}
