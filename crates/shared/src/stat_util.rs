// SPDX-License-Identifier: LGPL-2.1-or-later
//! `stat-util.c`, `mountpoint-util.c`'s `is_mount_point_at()`, and the
//! `fs-util.c`/`fileio.c` open helpers built on them.

use crate::fd::{AT_FDCWD, XAT_FDROOT, fd_reopen, proc_fd_path};
use crate::path::{dot_or_dot_dot, path_equal, path_is_absolute};
use crate::sys::{self, Dir, Fd, OwnedFd};
use crate::{errno::strerror, log_debug_errno};

pub const BTRFS_SUPER_MAGIC: i64 = 0x9123683e;
pub const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
pub const PROC_SUPER_MAGIC: i64 = 0x9fa0;
pub const TMPFS_MAGIC: i64 = 0x01021994;
pub const RAMFS_MAGIC: i64 = 0x858458f6;
pub const CGROUP2_SUPER_MAGIC: i64 = 0x63677270;

pub const NSEC_INFINITY: u64 = u64::MAX;

/// `statx_timestamp_load_nsec()`.
pub fn statx_timestamp_nsec(ts: &libc::statx_timestamp) -> u64 {
    (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
}

/// The four timestamps of a statx result, `NSEC_INFINITY` where missing:
/// (atime, mtime, ctime, btime).
pub fn statx_times(sx: &libc::statx) -> (u64, u64, u64, u64) {
    let get = |bit: u32, ts: &libc::statx_timestamp| {
        if sx.stx_mask & bit != 0 { statx_timestamp_nsec(ts) } else { NSEC_INFINITY }
    };
    (
        get(libc::STATX_ATIME, &sx.stx_atime),
        get(libc::STATX_MTIME, &sx.stx_mtime),
        get(libc::STATX_CTIME, &sx.stx_ctime),
        get(libc::STATX_BTIME, &sx.stx_btime),
    )
}

/// `xstatx_full(fd, path, flags, 0, mandatory_mask, optional_mask, mandatory_attributes, &sx)`.
///
/// The kernels this targets support every mask and attribute tmpfiles asks
/// for; a missing one is EUNATCH as in C (without C's debug line naming it).
pub fn xstatx_full(
    fd: Fd,
    path: Option<&[u8]>,
    flags: i32,
    mandatory_mask: u32,
    optional_mask: u32,
    mandatory_attributes: u64,
) -> Result<libc::statx, i32> {
    let path = path.unwrap_or_default();
    let (fd, path): (Fd, Vec<u8>) = if fd == XAT_FDROOT {
        if path.is_empty() {
            (AT_FDCWD, b"/".to_vec())
        } else if path_is_absolute(path) {
            (AT_FDCWD, path.to_vec())
        } else {
            (AT_FDCWD, crate::bcat!("/", path))
        }
    } else {
        (fd, path.to_vec())
    };
    let sx = sys::statx_raw(
        fd,
        &path,
        flags | if path.is_empty() { libc::AT_EMPTY_PATH } else { 0 },
        mandatory_mask | optional_mask,
    )?;
    if sx.stx_mask & mandatory_mask != mandatory_mask {
        return Err(-libc::EUNATCH);
    }
    if sx.stx_attributes_mask & mandatory_attributes != mandatory_attributes {
        return Err(-libc::EUNATCH);
    }
    Ok(sx)
}

/// `statx_inode_same()`.
pub fn statx_inode_same(a: &libc::statx, b: &libc::statx) -> bool {
    let need = libc::STATX_TYPE | libc::STATX_INO;
    a.stx_mask & need == need
        && b.stx_mask & need == need
        && (a.stx_mode as u32 ^ b.stx_mode as u32) & libc::S_IFMT == 0
        && a.stx_dev_major == b.stx_dev_major
        && a.stx_dev_minor == b.stx_dev_minor
        && a.stx_ino == b.stx_ino
}

/// `stat_inode_same()`.
pub fn stat_inode_same(a: &sys::Stat, b: &sys::Stat) -> bool {
    let set = |s: &sys::Stat| s.st_dev != 0 || s.st_ino != 0;
    set(a) && set(b) && (a.st_mode ^ b.st_mode) & libc::S_IFMT == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// `inode_same_at(fda, filea, fdb, fileb, flags)`.
///
/// Without AT_NO_AUTOMOUNT, C compares file handles from
/// `name_to_handle_at()`; this compares `fstat()` results of the same
/// pinned inodes, which gives the same answer (an open failure is reported
/// the same way, without a log line).
pub fn inode_same_at(
    fda: Fd,
    filea: Option<&[u8]>,
    fdb: Fd,
    fileb: Option<&[u8]>,
    mut flags: i32,
) -> Result<bool, i32> {
    let mut filea = filea.unwrap_or_default();
    let mut fileb = fileb.unwrap_or_default();
    let (mut fda, mut fdb) = (fda, fdb);
    if (filea.is_empty() || fileb.is_empty()) && flags & libc::AT_EMPTY_PATH == 0 {
        return Err(-libc::EINVAL);
    }
    if fda >= 0 && fda == fdb && filea.is_empty() && fileb.is_empty() && flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        return Ok(true);
    }
    let (_pa, _pb);
    if flags & libc::AT_NO_AUTOMOUNT == 0 {
        let nofollow = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 { libc::O_NOFOLLOW } else { 0 };
        if !filea.is_empty() {
            _pa = OwnedFd::new(sys::openat(fda, filea, libc::O_PATH | libc::O_CLOEXEC | nofollow, 0)?);
            fda = _pa.raw();
            filea = b"";
            flags |= libc::AT_EMPTY_PATH;
        }
        if !fileb.is_empty() {
            _pb = OwnedFd::new(sys::openat(fdb, fileb, libc::O_PATH | libc::O_CLOEXEC | nofollow, 0)?);
            fdb = _pb.raw();
            fileb = b"";
            flags |= libc::AT_EMPTY_PATH;
        }
    }
    let sta = match sys::fstatat(fda, filea, flags) {
        Ok(s) => s,
        Err(e) => {
            return Err(log_debug_errno!(
                e,
                "Cannot stat ",
                crate::string::strna(Some(filea).filter(|f| !f.is_empty())),
                ": ",
                strerror(e)
            ));
        }
    };
    let stb = match sys::fstatat(fdb, fileb, flags) {
        Ok(s) => s,
        Err(e) => {
            return Err(log_debug_errno!(
                e,
                "Cannot stat ",
                crate::string::strna(Some(fileb).filter(|f| !f.is_empty())),
                ": ",
                strerror(e)
            ));
        }
    };
    Ok(stat_inode_same(&sta, &stb))
}

/// `fd_inode_same(fda, fdb)`.
pub fn fd_inode_same(fda: Fd, fdb: Fd) -> Result<bool, i32> {
    inode_same_at(fda, None, fdb, None, libc::AT_EMPTY_PATH)
}

/// `xopenat(dir_fd, path, flags)` without O_CREAT: an empty path reopens.
pub fn xopenat(dir_fd: Fd, path: Option<&[u8]>, flags: i32) -> Result<OwnedFd, i32> {
    match path {
        None | Some(b"") => Ok(OwnedFd::new(fd_reopen(dir_fd, flags & !libc::O_NOFOLLOW)?)),
        Some(p) => {
            let (dir_fd, p) = if dir_fd == XAT_FDROOT {
                (AT_FDCWD, if path_is_absolute(p) { p.to_vec() } else { crate::bcat!("/", p) })
            } else {
                (dir_fd, p.to_vec())
            };
            Ok(OwnedFd::new(sys::openat(dir_fd, &p, flags, 0)?))
        }
    }
}

/// `xopendirat(dir_fd, path, flags)`.
pub fn xopendirat(dir_fd: Fd, path: &[u8], flags: i32) -> Result<Dir, i32> {
    if (dir_fd == AT_FDCWD || path_is_absolute(path)) && flags & !libc::O_DIRECTORY == 0 {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?;
        return Dir::from_fd(fd);
    }
    let (path, flags) = if path.is_empty() { (&b"."[..], flags | libc::O_NOFOLLOW) } else { (path, flags) };
    let fd = sys::openat(dir_fd, path, libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC | flags, 0)?;
    Dir::from_fd(fd)
}

/// `dir_is_empty_at(dir_fd, path, ignore_hidden_or_backup)`.
pub fn dir_is_empty_at(dir_fd: Fd, path: Option<&[u8]>, ignore_hidden_or_backup: bool) -> Result<bool, i32> {
    let fd = xopenat(dir_fd, path, libc::O_DIRECTORY | libc::O_CLOEXEC)?;
    let has = sys::dir_has_entry(fd.raw(), &|name| {
        if ignore_hidden_or_backup { crate::conf_files::hidden_or_backup_file(name) } else { dot_or_dot_dot(name) }
    })?;
    Ok(!has)
}

/// `is_fs_type_at(dir_fd, path, magic)`.
pub fn is_fs_type_at(dir_fd: Fd, path: Option<&[u8]>, magic: i64) -> Result<bool, i32> {
    Ok(sys::f_type(&xstatfsat(dir_fd, path)?) == magic)
}

/// `xstatfsat(dir_fd, path, &s)`.
pub fn xstatfsat(dir_fd: Fd, path: Option<&[u8]>) -> Result<sys::StatFs, i32> {
    match path {
        Some(p) if !p.is_empty() => {
            let fd = xopenat(dir_fd, Some(p), libc::O_PATH | libc::O_CLOEXEC)?;
            sys::fstatfs(fd.raw())
        }
        _ => {
            if dir_fd == AT_FDCWD || dir_fd == XAT_FDROOT {
                let fd = OwnedFd::new(sys::open(
                    if dir_fd == AT_FDCWD { b"." } else { b"/" },
                    libc::O_PATH | libc::O_CLOEXEC,
                    0,
                )?);
                return sys::fstatfs(fd.raw());
            }
            sys::fstatfs(dir_fd)
        }
    }
}

/// `is_temporary_fs()`.
pub fn is_temporary_fs(s: &sys::StatFs) -> bool {
    matches!(sys::f_type(s), TMPFS_MAGIC | RAMFS_MAGIC)
}

/// `is_mount_point_at(dir_fd, path, flags)`.
pub fn is_mount_point_at(dir_fd: Fd, path: Option<&[u8]>, flags: i32) -> Result<bool, i32> {
    if let Some(p) = path
        && path_equal(p, b"/")
    {
        return Ok(true);
    }
    if dir_fd == XAT_FDROOT && path.is_none_or(|p| p.is_empty()) {
        return Ok(true);
    }
    let nofollow = if flags & libc::AT_SYMLINK_FOLLOW != 0 { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let sx = xstatx_full(
        dir_fd,
        path,
        nofollow | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC,
        libc::STATX_TYPE | libc::STATX_INO,
        0,
        libc::STATX_ATTR_MOUNT_ROOT as u64,
    )?;
    if sx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 {
        return Ok(true);
    }
    let sx2 = xstatx_full(AT_FDCWD, Some(b"/"), libc::AT_STATX_DONT_SYNC, libc::STATX_TYPE | libc::STATX_INO, 0, 0)?;
    Ok(statx_inode_same(&sx, &sx2))
}

/// `fchmod_opath(fd, m)`.
pub fn fchmod_opath(fd: Fd, m: u32) -> Result<(), i32> {
    let e = match sys::fchmodat_flags(fd, b"", m, libc::AT_EMPTY_PATH) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    let e = if e == -libc::EINVAL {
        match sys::fchmodat2(fd, b"", m, libc::AT_EMPTY_PATH) {
            Ok(()) => return Ok(()),
            Err(e2) => e2,
        }
    } else {
        e
    };
    if e != -libc::ENOSYS && e != -libc::EPERM {
        return Err(e);
    }
    match sys::chmod(&proc_fd_path(fd), m) {
        Ok(()) => Ok(()),
        Err(e) if e == -libc::ENOENT => Err(crate::fd::proc_fd_enoent_errno()),
        Err(e) => Err(e),
    }
}

/// `inode_type_can_acl()`.
pub fn inode_type_can_acl(mode: u32) -> bool {
    matches!(
        mode & libc::S_IFMT,
        libc::S_IFSOCK | libc::S_IFREG | libc::S_IFBLK | libc::S_IFCHR | libc::S_IFDIR | libc::S_IFIFO
    )
}

/// `hardlink_vulnerable()`'s first half (the sysctl check is the caller's).
pub fn may_be_hardlinked(st: &sys::Stat) -> bool {
    st.st_mode & libc::S_IFMT != libc::S_IFDIR && st.st_nlink > 1
}

/// `stat_verify_regular()`.
pub fn stat_verify_regular(st: &sys::Stat) -> Result<(), i32> {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Err(-libc::EISDIR),
        libc::S_IFLNK => Err(-libc::ELOOP),
        libc::S_IFREG => Ok(()),
        _ => Err(-libc::EBADFD),
    }
}

/// `fd_verify_regular(fd)`.
pub fn fd_verify_regular(fd: Fd) -> Result<(), i32> {
    stat_verify_regular(&sys::fstat(fd)?)
}

/// `verify_regular_at(dir_fd, path, follow)`.
pub fn verify_regular_at(dir_fd: Fd, path: &[u8], follow: bool) -> Result<(), i32> {
    let flags =
        if path.is_empty() { libc::AT_EMPTY_PATH } else { 0 } | if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    stat_verify_regular(&sys::fstatat(dir_fd, path, flags)?)
}

/// `stat_inode_unmodified(a, b)`.
pub fn stat_inode_unmodified(a: &sys::Stat, b: &sys::Stat) -> bool {
    let fmt = a.st_mode & libc::S_IFMT;
    stat_inode_same(a, b)
        && sys::stat_mtime(a) == sys::stat_mtime(b)
        && (fmt != libc::S_IFREG || a.st_size == b.st_size)
        && (!(fmt == libc::S_IFCHR || fmt == libc::S_IFBLK) || a.st_rdev == b.st_rdev)
}

/// `null_or_empty(st)`: an empty regular file or a character device.
pub fn null_or_empty(st: &sys::Stat) -> bool {
    let fmt = st.st_mode & libc::S_IFMT;
    (fmt == libc::S_IFREG && st.st_size <= 0) || fmt == libc::S_IFCHR
}
