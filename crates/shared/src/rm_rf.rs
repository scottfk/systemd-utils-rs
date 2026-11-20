// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rm-rf.c`: `rm_rf_at()`, `rm_rf_safe()`, `rm_rf_child()`,
//! `rm_rf_children()` and the `*_harder()` helpers.

use crate::btrfs::{BTRFS_REMOVE_QUOTA, BTRFS_REMOVE_RECURSIVE, might_be_subvol, subvol_remove_at};
use crate::fd::fd_get_path;
use crate::path::{dot_or_dot_dot, filename_is_valid};
use crate::stat_util::{CGROUP2_SUPER_MAGIC, fchmod_opath, is_mount_point_at, is_temporary_fs};
use crate::sys::{self, Dir, Fd, OwnedFd, Stat};

pub const REMOVE_ONLY_DIRECTORIES: u32 = 1 << 0;
pub const REMOVE_ROOT: u32 = 1 << 1;
pub const REMOVE_PHYSICAL: u32 = 1 << 2;
pub const REMOVE_SUBVOLUME: u32 = 1 << 3;
pub const REMOVE_MISSING_OK: u32 = 1 << 4;
pub const REMOVE_CHMOD: u32 = 1 << 5;
pub const REMOVE_CHMOD_RESTORE: u32 = 1 << 6;
pub const REMOVE_SYNCFS: u32 = 1 << 7;

/// `is_physical_fs()`.
fn is_physical_fs(s: &crate::sys::StatFs) -> bool {
    !is_temporary_fs(s) && crate::sys::f_type(s) != CGROUP2_SUPER_MAGIC
}

/// `patch_dirfd_mode()`: Ok((changed, old_mode)).
fn patch_dirfd_mode(dfd: Fd, refuse_already_set: bool) -> Result<(bool, u32), i32> {
    let st = sys::fstat(dfd)?;
    crate::chase::mode_verify_directory(st.st_mode)?;
    if st.st_mode & 0o700 == 0o700 {
        if refuse_already_set {
            return Err(-libc::EACCES);
        }
        return Ok((false, st.st_mode));
    }
    if st.st_uid != sys::geteuid() {
        return Err(-libc::EACCES);
    }
    fchmod_opath(dfd, (st.st_mode | 0o700) & 0o7777)?;
    Ok((true, st.st_mode))
}

/// `unlinkat_harder(dfd, filename, unlink_flags, remove_flags)`.
pub fn unlinkat_harder(dfd: Fd, filename: &[u8], unlink_flags: i32, remove_flags: u32) -> Result<(), i32> {
    match sys::unlinkat(dfd, filename, unlink_flags) {
        Ok(()) => return Ok(()),
        Err(e) if e != -libc::EACCES || remove_flags & REMOVE_CHMOD == 0 => return Err(e),
        Err(_) => {}
    }
    let (_, old_mode) = patch_dirfd_mode(dfd, true)?;
    if let Err(e) = sys::unlinkat(dfd, filename, unlink_flags) {
        let _ = sys::fchmod(dfd, old_mode & 0o7777);
        return Err(e);
    }
    if remove_flags & REMOVE_CHMOD_RESTORE != 0 {
        sys::fchmod(dfd, old_mode & 0o7777)?;
    }
    Ok(())
}

/// `fstatat_harder(dfd, filename, &st, fstatat_flags, remove_flags)`.
pub fn fstatat_harder(dfd: Fd, filename: &[u8], fstatat_flags: i32, remove_flags: u32) -> Result<Stat, i32> {
    match sys::fstatat(dfd, filename, fstatat_flags) {
        Ok(st) => return Ok(st),
        Err(e) if e != -libc::EACCES || remove_flags & REMOVE_CHMOD == 0 => return Err(e),
        Err(_) => {}
    }
    let (_, old_mode) = patch_dirfd_mode(dfd, true)?;
    let st = match sys::fstatat(dfd, filename, fstatat_flags) {
        Ok(st) => st,
        Err(e) => {
            let _ = sys::fchmod(dfd, old_mode & 0o7777);
            return Err(e);
        }
    };
    if remove_flags & REMOVE_CHMOD_RESTORE != 0 {
        sys::fchmod(dfd, old_mode & 0o7777)?;
    }
    Ok(st)
}

/// `openat_harder(dfd, path, open_flags, remove_flags, &old_mode)`.
fn openat_harder(dfd: Fd, path: &[u8], open_flags: i32, remove_flags: u32) -> Result<(OwnedFd, u32), i32> {
    if open_flags & libc::O_PATH != 0 || open_flags & libc::O_DIRECTORY == 0 || remove_flags & REMOVE_CHMOD == 0 {
        let fd = OwnedFd::new(sys::openat(dfd, path, open_flags, 0)?);
        let st = sys::fstat(fd.raw())?;
        return Ok((fd, st.st_mode));
    }
    let pfd = OwnedFd::new(sys::openat(
        dfd,
        path,
        (open_flags & (libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)) | libc::O_PATH,
        0,
    )?);
    let (chmod_done, old_mode) = patch_dirfd_mode(pfd.raw(), false)?;
    match crate::fd::fd_reopen(pfd.raw(), open_flags & !libc::O_NOFOLLOW) {
        Ok(fd) => Ok((OwnedFd::new(fd), old_mode)),
        Err(e) => {
            if chmod_done {
                let _ = fchmod_opath(pfd.raw(), old_mode & 0o7777);
            }
            Err(e)
        }
    }
}

const SUBDIR_FLAGS: i32 =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOATIME;

/// `rm_rf_inner_child(fd, fname, is_dir, flags, root_dev, allow_recursion)`.
fn rm_rf_inner_child(
    fd: Fd,
    fname: &[u8],
    is_dir: Option<bool>,
    flags: u32,
    root_dev: Option<&Stat>,
    allow_recursion: bool,
) -> Result<bool, i32> {
    let mut st: Option<Stat> = None;
    let mut is_dir = is_dir;
    // C: is_dir < 0 || root_dev || (is_dir > 0 && (root_dev || REMOVE_SUBVOLUME))
    if is_dir.is_none() || root_dev.is_some() || (is_dir == Some(true) && flags & REMOVE_SUBVOLUME != 0) {
        let s = fstatat_harder(fd, fname, libc::AT_SYMLINK_NOFOLLOW, flags)?;
        is_dir = Some(s.st_mode & libc::S_IFMT == libc::S_IFDIR);
        st = Some(s);
    }
    let is_dir = is_dir.expect("set");
    let mut q: Result<(), i32> = Ok(());
    if is_dir {
        if let (Some(rd), Some(s)) = (root_dev, &st)
            && s.st_dev != rd.st_dev
        {
            return Ok(false);
        }
        if is_mount_point_at(fd, Some(fname), 0)? {
            return Ok(false);
        }
        if flags & REMOVE_SUBVOLUME != 0 && st.as_ref().is_some_and(might_be_subvol) {
            match subvol_remove_at(fd, fname, BTRFS_REMOVE_RECURSIVE | BTRFS_REMOVE_QUOTA) {
                Ok(()) => return Ok(true),
                Err(r) if [-libc::ENOTTY, -libc::EINVAL, -libc::EPERM, -libc::EACCES].contains(&r) => {}
                Err(r) => return Err(r),
            }
        }
        if !allow_recursion {
            return Err(-libc::EISDIR);
        }
        let (subdir_fd, old_mode) = openat_harder(fd, fname, SUBDIR_FLAGS, flags)?;
        q = rm_rf_children_impl(subdir_fd, flags | REMOVE_PHYSICAL, root_dev, old_mode);
    } else if flags & REMOVE_ONLY_DIRECTORIES != 0 {
        return Ok(false);
    }
    unlinkat_harder(fd, fname, if is_dir { libc::AT_REMOVEDIR } else { 0 }, flags)?;
    q?;
    Ok(true)
}

/// `rm_rf_children(fd, flags, root_dev)`: takes ownership of fd.
pub fn rm_rf_children(fd: OwnedFd, flags: u32, root_dev: Option<&Stat>) -> Result<(), i32> {
    let st = sys::fstat(fd.raw())?;
    rm_rf_children_impl(fd, flags, root_dev, st.st_mode)
}

/// `rm_rf_children_impl()`: iterative, with an explicit stack of the
/// directories being worked on, as in C.
fn rm_rf_children_impl(fd: OwnedFd, flags: u32, root_dev: Option<&Stat>, old_mode: u32) -> Result<(), i32> {
    struct Todo {
        dir: Dir,
        dirname: Option<Vec<u8>>,
        old_mode: u32,
    }
    let mut todos: Vec<Todo> = Vec::new();
    let mut dirname: Option<Vec<u8>> = None;
    let mut old_mode = old_mode;
    let mut ret = 0i32;
    let mut next_fd: Option<OwnedFd> = Some(fd);
    loop {
        let mut d = match next_fd.take() {
            Some(fd) => {
                let d = Dir::from_fd(fd.into_raw())?;
                if flags & REMOVE_PHYSICAL == 0 {
                    let sfs = sys::fstatfs(d.fd())?;
                    if is_physical_fs(&sfs) {
                        let path = fd_get_path(d.fd()).ok();
                        return Err(crate::log_error_errno!(
                            crate::errno::synthetic(libc::EPERM),
                            "Attempted to remove disk file system under \"",
                            crate::string::strna(path.as_deref()),
                            "\", and we can't allow that."
                        ));
                    }
                }
                d
            }
            None => {
                // Remove the inner directory we were working on, and back
                // out one level.
                let t = todos.pop().expect("in recursion");
                let name = dirname.take().expect("in recursion");
                if let Err(r) = unlinkat_harder(t.dir.fd(), &name, libc::AT_REMOVEDIR, flags)
                    && r != -libc::ENOENT
                {
                    if ret == 0 {
                        ret = r;
                    }
                    if flags & REMOVE_CHMOD_RESTORE != 0 {
                        let _ = sys::fchmodat(t.dir.fd(), &name, old_mode & 0o7777);
                    }
                }
                dirname = t.dirname;
                old_mode = t.old_mode;
                t.dir
            }
        };
        let fd = d.fd();
        let mut descend: Option<(OwnedFd, Vec<u8>, u32)> = None;
        while let Some((name, ty)) = d.next_entry()? {
            if dot_or_dot_dot(&name) {
                continue;
            }
            let is_dir = if ty == libc::DT_UNKNOWN { None } else { Some(ty == libc::DT_DIR) };
            match rm_rf_inner_child(fd, &name, is_dir, flags, root_dev, false) {
                Err(r) if r == -libc::EISDIR => match openat_harder(fd, &name, SUBDIR_FLAGS, flags) {
                    Ok((newfd, mode)) => {
                        descend = Some((newfd, name, mode));
                        break;
                    }
                    Err(e) if e != -libc::ENOENT && ret == 0 => ret = e,
                    Err(_) => {}
                },
                Err(r) if r != -libc::ENOENT && ret == 0 => ret = r,
                _ => {}
            }
        }
        if let Some((newfd, name, mode)) = descend {
            // Push the current working state and go one level down.
            todos.push(Todo { dir: d, dirname: dirname.take(), old_mode });
            next_fd = Some(newfd);
            dirname = Some(name);
            old_mode = mode;
            continue;
        }
        if flags & REMOVE_SYNCFS != 0
            && let Err(e) = sys::syncfs(fd)
            && ret >= 0
        {
            ret = e;
        }
        if todos.is_empty() {
            if flags & REMOVE_CHMOD_RESTORE != 0
                && let Err(e) = sys::fchmod(fd, old_mode & 0o7777)
                && ret >= 0
            {
                ret = e;
            }
            break;
        }
        // Drop this level's DIR (C closes it when backing out).
        drop(d);
    }
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// `rm_rf_child(fd, name, flags)`.
pub fn rm_rf_child(fd: Fd, name: &[u8], flags: u32) -> Result<bool, i32> {
    if fd < 0 {
        return Err(-libc::EBADF);
    }
    if !filename_is_valid(name) {
        return Err(-libc::EINVAL);
    }
    if flags & (REMOVE_ROOT | REMOVE_MISSING_OK) != 0 {
        return Err(-libc::EINVAL);
    }
    if flags & (REMOVE_ONLY_DIRECTORIES | REMOVE_SUBVOLUME) == REMOVE_ONLY_DIRECTORIES | REMOVE_SUBVOLUME {
        return Err(-libc::EINVAL);
    }
    rm_rf_inner_child(fd, name, None, flags, None, true)
}

/// `rm_rf_at(dir_fd, path, flags)`.
pub fn rm_rf_at(dir_fd: Fd, path: &[u8], flags: u32) -> Result<(), i32> {
    if flags & (REMOVE_ONLY_DIRECTORIES | REMOVE_SUBVOLUME) == REMOVE_ONLY_DIRECTORIES | REMOVE_SUBVOLUME {
        return Err(-libc::EINVAL);
    }
    // Never the root file system.
    let r = match crate::fd::path_is_root_at(dir_fd, path) {
        Err(e) if e == -libc::ENOENT => {
            sys::faccessat(dir_fd, path, libc::F_OK, libc::AT_SYMLINK_NOFOLLOW).map(|()| false)
        }
        x => x,
    };
    match r {
        Err(e) if e == -libc::ENOENT && flags & REMOVE_MISSING_OK != 0 => return Ok(()),
        Err(e) => {
            let lvl = if e == -libc::ENOENT { crate::log::LOG_DEBUG } else { crate::log::LOG_ERR };
            let p = String::from_utf8_lossy(path).into_owned();
            return Err(crate::log_full_errno!(
                lvl,
                e,
                "Failed to determine whether '",
                p,
                "' is the root file system: ",
                crate::errno::strerror(e)
            ));
        }
        Ok(true) => {
            return Err(crate::log_error_errno!(
                -libc::EPERM,
                "Attempted to remove entire root file system, and we can't allow that."
            ));
        }
        Ok(false) => {}
    }
    let all = REMOVE_SUBVOLUME | REMOVE_ROOT | REMOVE_PHYSICAL;
    if flags & all == all {
        match subvol_remove_at(dir_fd, path, BTRFS_REMOVE_RECURSIVE | BTRFS_REMOVE_QUOTA) {
            Ok(()) => return Ok(()),
            Err(e) if e == -libc::ENOENT && flags & REMOVE_MISSING_OK != 0 => return Ok(()),
            Err(e) if ![-libc::ENOTTY, -libc::EINVAL, -libc::ENOTDIR, -libc::EPERM, -libc::EACCES].contains(&e) => {
                return Err(e);
            }
            Err(_) => {}
        }
    }
    if flags & (REMOVE_ROOT | REMOVE_PHYSICAL) == REMOVE_ROOT | REMOVE_PHYSICAL
        && sys::unlinkat(dir_fd, path, libc::AT_REMOVEDIR).is_ok()
    {
        return Ok(());
    }
    let (r, q) = match openat_harder(dir_fd, path, SUBDIR_FLAGS, flags) {
        Ok((fd, old_mode)) => {
            let r = rm_rf_children_impl(fd, flags, None, old_mode);
            let q = if flags & REMOVE_ROOT != 0 { sys::unlinkat(dir_fd, path, libc::AT_REMOVEDIR) } else { Ok(()) };
            (r, q)
        }
        Err(r) => {
            if flags & REMOVE_MISSING_OK != 0 && r == -libc::ENOENT {
                return Ok(());
            }
            if r != -libc::ENOTDIR && r != -libc::ELOOP {
                return Err(r);
            }
            if flags & REMOVE_ONLY_DIRECTORIES != 0 || flags & REMOVE_ROOT == 0 {
                return Ok(());
            }
            if flags & REMOVE_PHYSICAL == 0 {
                let s = crate::stat_util::xstatfsat(dir_fd, Some(path))?;
                if is_physical_fs(&s) {
                    let p = String::from_utf8_lossy(path).into_owned();
                    return Err(crate::log_error_errno!(
                        -libc::EPERM,
                        "Attempted to remove files from a disk file system under \"",
                        p,
                        "\", refusing."
                    ));
                }
            }
            (Ok(()), sys::unlinkat(dir_fd, path, 0))
        }
    };
    r?;
    match q {
        Err(e) if e != -libc::ENOENT || flags & REMOVE_MISSING_OK == 0 => Err(e),
        _ => Ok(()),
    }
}

/// `rm_rf_safe(p)` (errno is not touched: the port has no errno to protect).
pub fn rm_rf_safe(p: &[u8]) {
    let _ = rm_rf_at(libc::AT_FDCWD, p, REMOVE_ROOT | REMOVE_MISSING_OK | REMOVE_CHMOD);
}
