// SPDX-License-Identifier: LGPL-2.1-or-later
//! `copy.c`: `copy_tree_at()` for what tmpfiles' `C` lines ask for —
//! COPY_MERGE or COPY_MERGE_EMPTY, COPY_MAC_CREATE (a no-op without
//! SELinux) and COPY_HARDLINKS, with no denylist, subvolumes or clamping.

use crate::fd::AT_FDCWD;
use crate::path::path_join;
use crate::stat_util::{dir_is_empty_at, xopenat};
use crate::sys::{self, Dir, Fd, OwnedFd, Stat};
use crate::{errno::strerror, log_debug_errno};

pub const COPY_MERGE: u32 = 1 << 0;
pub const COPY_REPLACE: u32 = 1 << 1;
pub const COPY_MERGE_EMPTY: u32 = 1 << 3;
pub const COPY_MAC_CREATE: u32 = 1 << 7;
pub const COPY_HARDLINKS: u32 = 1 << 8;

const COPY_DEPTH_MAX: u32 = 2048;

fn ids(st: &Stat, uid: u32, gid: u32) -> (u32, u32) {
    (if uid != u32::MAX { uid } else { st.st_uid }, if gid != u32::MAX { gid } else { st.st_gid })
}

fn times(st: &Stat) -> ((i64, i64), (i64, i64)) {
    (crate::sys::stat_atime(st), crate::sys::stat_mtime(st))
}

/// `HardlinkContext`: a directory below the target holding a hard link of
/// every copied inode with more than one link, named by device and inode.
struct HardlinkContext {
    dir_fd: Option<OwnedFd>,
    parent_fd: Option<Fd>,
    subdir: Vec<u8>,
    _parent_owner: Option<OwnedFd>,
}

impl HardlinkContext {
    /// `hardlink_context_setup()`.
    fn setup(dt: Fd, to: &[u8], copy_flags: u32) -> Result<Option<HardlinkContext>, i32> {
        if copy_flags & COPY_HARDLINKS == 0 {
            return Ok(None);
        }
        let (parent, owner) = if dt == AT_FDCWD {
            (AT_FDCWD, None)
        } else {
            let d = OwnedFd::new(sys::dup_cloexec(dt, 3)?);
            (d.raw(), Some(d))
        };
        // tempfn_random_child(to, "hardlink")
        let subdir = path_join(&[to, format!(".#hardlink{:016x}", random()).as_bytes()]);
        Ok(Some(HardlinkContext { dir_fd: None, parent_fd: Some(parent), subdir, _parent_owner: owner }))
    }

    /// `hardlink_context_realize()`.
    fn realize(&mut self) -> Result<(), i32> {
        if self.dir_fd.is_some() {
            return Ok(());
        }
        let Some(parent) = self.parent_fd else { return Ok(()) };
        sys::mkdirat(parent, &self.subdir, 0o700)?;
        self.dir_fd = Some(OwnedFd::new(sys::openat(
            parent,
            &self.subdir,
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY,
            0,
        )?));
        Ok(())
    }

    /// `hardlink_context_destroy()`.
    fn destroy(&mut self) {
        if let Some(fd) = self.dir_fd.take() {
            if let Err(e) = sys::lseek(fd.raw(), 0, libc::SEEK_SET) {
                log_debug_errno!(e, "Failed to lseek on file descriptor, ignoring: ", strerror(e));
            }
            if let Err(r) = crate::rm_rf::rm_rf_children(fd, crate::rm_rf::REMOVE_PHYSICAL, None) {
                log_debug_errno!(
                    r,
                    "Failed to remove hardlink store (",
                    self.subdir,
                    ") contents, ignoring: ",
                    strerror(r)
                );
            }
            if let Some(parent) = self.parent_fd
                && let Err(e) = sys::unlinkat(parent, &self.subdir, libc::AT_REMOVEDIR)
            {
                log_debug_errno!(
                    e,
                    "Failed to remove hardlink store (",
                    self.subdir,
                    ") directory, ignoring: ",
                    strerror(e)
                );
            }
        }
        self.parent_fd = None;
    }

    fn key(st: &Stat) -> Vec<u8> {
        format!("{}:{}:{}", libc::major(st.st_dev), libc::minor(st.st_dev), st.st_ino).into_bytes()
    }
}

fn random() -> u64 {
    let mut b = [0u8; 8];
    let _ = sys::getrandom(&mut b);
    u64::from_ne_bytes(b)
}

/// `try_hardlink()`.
fn try_hardlink(c: Option<&HardlinkContext>, st: &Stat, dt: Fd, to: &[u8]) -> bool {
    let Some(c) = c else { return false };
    if st.st_nlink <= 1 {
        return false;
    }
    let Some(dir) = &c.dir_fd else { return false };
    let key = HardlinkContext::key(st);
    match sys::linkat(dir.raw(), &key, dt, to, 0) {
        Ok(()) => true,
        Err(e) => {
            if e != -libc::ENOENT {
                log_debug_errno!(e, "Failed to hardlink ", key, " to ", to, ", ignoring: ", strerror(e));
            }
            false
        }
    }
}

/// `memorize_hardlink()`.
fn memorize_hardlink(c: Option<&mut HardlinkContext>, st: &Stat, dt: Fd, to: &[u8]) {
    let Some(c) = c else { return };
    if st.st_nlink <= 1 || c.realize().is_err() {
        return;
    }
    let Some(dir) = &c.dir_fd else { return };
    let key = HardlinkContext::key(st);
    if let Err(e) = sys::linkat(dt, to, dir.raw(), &key, 0) {
        log_debug_errno!(e, "Failed to hardlink ", to, " to ", key, ", ignoring: ", strerror(e));
    }
}

/// `copy_xattr(fdf, NULL, fdt, NULL, 0)`: the user.* attributes.
fn copy_xattr_fd(fdf: Fd, fdt: Fd) {
    let Ok(names) = sys::flistxattr(fdf) else { return };
    for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        if !name.starts_with(b"user.") {
            continue;
        }
        match crate::xattr::fgetxattr_malloc(fdf, name) {
            Err(e) if e == -libc::ENODATA => continue,
            Err(_) => return,
            Ok(v) => {
                let _ = crate::xattr::fsetxattr_full(fdt, name, &v, 0);
            }
        }
    }
}

/// `copy_bytes_full(fdf, fdt, UINT64_MAX, ...)`: reflink if possible, else
/// copy_file_range(), else read()/write().
fn copy_bytes(fdf: Fd, fdt: Fd) -> Result<(), i32> {
    if sys::ficlone(fdt, fdf).is_ok() {
        return Ok(());
    }
    let mut try_cfr = true;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if try_cfr {
            match sys::copy_file_range(fdf, fdt, 1 << 30) {
                Ok(0) => return Ok(()),
                Ok(_) => continue,
                Err(e)
                    if [-libc::EINVAL, -libc::EXDEV, -libc::ENOSYS, -libc::EOPNOTSUPP, -libc::EBADF].contains(&e) =>
                {
                    try_cfr = false;
                }
                Err(e) => return Err(e),
            }
        }
        let n = sys::read(fdf, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        sys::write_all(fdt, &buf[..n])?;
    }
}

/// `fd_copy_regular()`.
fn fd_copy_regular(
    df: Fd,
    from: &[u8],
    st: &Stat,
    dt: Fd,
    to: &[u8],
    uid: u32,
    gid: u32,
    hl: Option<&mut HardlinkContext>,
) -> i32 {
    if try_hardlink(hl.as_deref(), st, dt, to) {
        return 0;
    }
    let fdf = match sys::openat(df, from, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(e) => return e,
    };
    match sys::fstat(fdf.raw()) {
        Ok(s) if s.st_mode & libc::S_IFMT != libc::S_IFREG => {
            return if s.st_mode & libc::S_IFMT == libc::S_IFDIR { -libc::EISDIR } else { -libc::EBADFD };
        }
        Err(e) => return e,
        _ => {}
    }
    let fdt = match sys::openat(
        dt,
        to,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW,
        st.st_mode & 0o7777,
    ) {
        Ok(fd) => OwnedFd::new(fd),
        Err(e) => return e,
    };
    // prepare_nocow(): carry FS_NOCOW_FL over.
    if let Ok(attrs) = sys::fs_ioc_getflags(fdf.raw())
        && attrs & crate::chattr::FS_NOCOW_FL != 0
    {
        let _ = crate::chattr::chattr_fd(fdt.raw(), crate::chattr::FS_NOCOW_FL, crate::chattr::FS_NOCOW_FL, 0);
    }
    if let Err(r) = copy_bytes(fdf.raw(), fdt.raw()) {
        let _ = sys::unlinkat(dt, to, 0);
        return r;
    }
    let mut r = 0;
    let (u, g) = ids(st, uid, gid);
    if let Err(e) = sys::fchown(fdt.raw(), u, g) {
        r = e;
    }
    if let Err(e) = sys::fchmod(fdt.raw(), st.st_mode & 0o7777) {
        r = e;
    }
    let (a, m) = times(st);
    let _ = sys::futimens_ts(fdt.raw(), a, m);
    copy_xattr_fd(fdf.raw(), fdt.raw());
    drop(fdt);
    memorize_hardlink(hl, st, dt, to);
    r
}

/// `fd_copy_symlink()`.
fn fd_copy_symlink(df: Fd, from: &[u8], st: &Stat, dt: Fd, to: &[u8], uid: u32, gid: u32) -> i32 {
    let target = match sys::readlinkat(df, from) {
        Ok(t) => t,
        Err(e) => return e,
    };
    if let Err(e) = sys::symlinkat(&target, dt, to) {
        return e;
    }
    let mut r = 0;
    let (u, g) = ids(st, uid, gid);
    if let Err(e) = sys::fchownat(dt, to, u, g, libc::AT_SYMLINK_NOFOLLOW) {
        r = e;
    }
    // copy_xattr(): symlinks cannot carry user.* attributes, so there is
    // nothing to copy.
    let (a, m) = times(st);
    let _ = sys::utimensat(dt, to, a, m, libc::AT_SYMLINK_NOFOLLOW);
    r
}

/// `fd_copy_fifo()` and `fd_copy_node()`.
fn fd_copy_special(st: &Stat, dt: Fd, to: &[u8], uid: u32, gid: u32, hl: Option<&mut HardlinkContext>) -> i32 {
    if try_hardlink(hl.as_deref(), st, dt, to) {
        return 0;
    }
    let made = if st.st_mode & libc::S_IFMT == libc::S_IFIFO {
        sys::mkfifoat(dt, to, st.st_mode & 0o7777)
    } else {
        sys::mknodat(dt, to, st.st_mode, st.st_rdev)
    };
    if let Err(e) = made {
        return e;
    }
    let mut r = 0;
    let (u, g) = ids(st, uid, gid);
    if let Err(e) = sys::fchownat(dt, to, u, g, libc::AT_SYMLINK_NOFOLLOW) {
        r = e;
    }
    if let Err(e) = sys::fchmodat_flags(dt, to, st.st_mode & 0o7777, libc::AT_SYMLINK_NOFOLLOW) {
        r = e;
    }
    let (a, m) = times(st);
    let _ = sys::utimensat(dt, to, a, m, libc::AT_SYMLINK_NOFOLLOW);
    memorize_hardlink(hl, st, dt, to);
    r
}

/// `fd_copy_leaf()`.
fn fd_copy_leaf(
    df: Fd,
    from: &[u8],
    st: &Stat,
    dt: Fd,
    to: &[u8],
    uid: u32,
    gid: u32,
    hl: Option<&mut HardlinkContext>,
) -> i32 {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => fd_copy_regular(df, from, st, dt, to, uid, gid, hl),
        libc::S_IFLNK => fd_copy_symlink(df, from, st, dt, to, uid, gid),
        libc::S_IFIFO | libc::S_IFBLK | libc::S_IFCHR | libc::S_IFSOCK => fd_copy_special(st, dt, to, uid, gid, hl),
        _ => -libc::EOPNOTSUPP,
    }
}

/// `fd_copy_directory()`.
fn fd_copy_directory(
    df: Fd,
    from: &[u8],
    st: &Stat,
    dt: Fd,
    to: &[u8],
    depth_left: u32,
    uid: u32,
    gid: u32,
    copy_flags: u32,
    hl: Option<&mut HardlinkContext>,
) -> i32 {
    if depth_left == 0 {
        return -libc::ENAMETOOLONG;
    }
    let fdf = match xopenat(
        df,
        Some(from),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW,
    ) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let mut ours: Option<HardlinkContext> = None;
    let hl: Option<&mut HardlinkContext> = match hl {
        Some(h) => Some(h),
        None => {
            match HardlinkContext::setup(dt, to, copy_flags) {
                Err(e) => return e,
                Ok(c) => ours = c,
            }
            ours.as_mut()
        }
    };
    let mut d = match Dir::from_fd(fdf.into_raw()) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let exists = match dir_is_empty_at(dt, Some(to), false) {
        Err(e) if e != -libc::ENOENT => return e,
        Err(_) => false,
        Ok(empty) => {
            if (empty && copy_flags & (COPY_MERGE | COPY_MERGE_EMPTY) == 0) || (!empty && copy_flags & COPY_MERGE == 0)
            {
                return -libc::EEXIST;
            }
            true
        }
    };
    if !exists {
        match sys::mkdirat(dt, to, st.st_mode & 0o7777) {
            Ok(()) => {}
            Err(e) => return e,
        }
    }
    let fdt = match sys::openat(
        dt,
        to,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(fd) => OwnedFd::new(fd),
        Err(e) => return e,
    };

    let mut ret = 0;
    // readdir_all(RECURSE_DIR_SORT): children in strcmp() order.
    let mut names: Vec<Vec<u8>> = Vec::new();
    loop {
        match d.next_entry() {
            Ok(Some((n, _))) => {
                if !crate::path::dot_or_dot_dot(&n) {
                    names.push(n);
                }
            }
            Ok(None) => break,
            Err(e) => return e,
        }
    }
    names.sort();
    let mut hl = hl;
    for name in &names {
        let buf = match sys::fstatat(d.fd(), name, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(b) => b,
            Err(e) => {
                crate::errno::ret_gather(&mut ret, e);
                continue;
            }
        };
        let mut r = fd_copy_tree_generic(
            d.fd(),
            name,
            &buf,
            fdt.raw(),
            name,
            depth_left - 1,
            uid,
            gid,
            copy_flags,
            hl.as_deref_mut(),
        );
        if r == -libc::EINTR || r == -libc::ENOSPC || r == -libc::ESOCKTNOSUPPORT {
            return r;
        }
        if r == -libc::EEXIST && copy_flags & COPY_MERGE != 0 {
            r = 0;
        }
        crate::errno::ret_gather(&mut ret, r);
    }

    if !exists {
        let (u, g) = ids(st, uid, gid);
        if let Err(e) = sys::fchown(fdt.raw(), u, g) {
            crate::errno::ret_gather(&mut ret, e);
        }
        if let Err(e) = sys::fchmod(fdt.raw(), st.st_mode & 0o7777) {
            crate::errno::ret_gather(&mut ret, e);
        }
        if let Some(c) = ours.as_mut() {
            c.destroy();
        }
        copy_xattr_fd(d.fd(), fdt.raw());
        let (a, m) = times(st);
        let _ = sys::futimens_ts(fdt.raw(), a, m);
    }
    if let Some(c) = ours.as_mut() {
        c.destroy();
    }
    if ret < 0 { ret } else { 0 }
}

/// `fd_copy_tree_generic()`.
fn fd_copy_tree_generic(
    df: Fd,
    from: &[u8],
    st: &Stat,
    dt: Fd,
    to: &[u8],
    depth_left: u32,
    uid: u32,
    gid: u32,
    copy_flags: u32,
    hl: Option<&mut HardlinkContext>,
) -> i32 {
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return fd_copy_directory(df, from, st, dt, to, depth_left - 1, uid, gid, copy_flags, hl);
    }
    let r = fd_copy_leaf(df, from, st, dt, to, uid, gid, hl);
    if r == -libc::EEXIST && copy_flags & COPY_REPLACE != 0 {
        // Not used by tmpfiles; kept for the shape of the C code.
        return r;
    }
    r
}

/// `copy_tree_at(fdf, from, fdt, to, override_uid, override_gid, copy_flags, NULL, NULL)`.
pub fn copy_tree_at(fdf: Fd, from: &[u8], fdt: Fd, to: &[u8], uid: u32, gid: u32, copy_flags: u32) -> i32 {
    let st = match sys::fstatat(
        fdf,
        from,
        libc::AT_SYMLINK_NOFOLLOW | if from.is_empty() { libc::AT_EMPTY_PATH } else { 0 },
    ) {
        Ok(st) => st,
        Err(e) => return e,
    };
    let r = fd_copy_tree_generic(fdf, from, &st, fdt, to, COPY_DEPTH_MAX, uid, gid, copy_flags, None);
    if r < 0 { r } else { 0 }
}
