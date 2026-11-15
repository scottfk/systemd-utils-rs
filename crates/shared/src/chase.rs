// SPDX-License-Identifier: LGPL-2.1-or-later
//! `chase.c`: resolve a path one component at a time, pinning each step
//! with an O_PATH fd, optionally inside a root directory.
//!
//! Not ported: CHASE_STEP and CHASE_TRIGGER_AUTOFS
//! (nothing in systemd-utils uses them).

use crate::fd::{AT_FDCWD, XAT_FDROOT, dir_fd_is_root, fd_reopen, wildcard_fd_is_valid};
use crate::path::{
    dot_or_dot_dot, empty_or_root, path_extract_directory, path_extract_filename, path_find_first_component,
    path_is_absolute, path_is_safe, path_is_valid, path_join, path_make_absolute_cwd, path_simplify, path_startswith,
};
use crate::sys::{self, OwnedFd, Statx};

pub const CHASE_PREFIX_ROOT: u32 = 1 << 0;
pub const CHASE_NONEXISTENT: u32 = 1 << 1;
pub const CHASE_NO_AUTOFS: u32 = 1 << 2;
pub const CHASE_TRIGGER_AUTOFS: u32 = 1 << 3;
pub const CHASE_SAFE: u32 = 1 << 4;
pub const CHASE_TRAIL_SLASH: u32 = 1 << 5;
pub const CHASE_STEP: u32 = 1 << 6;
pub const CHASE_NOFOLLOW: u32 = 1 << 7;
pub const CHASE_WARN: u32 = 1 << 8;
pub const CHASE_PROHIBIT_SYMLINKS: u32 = 1 << 9;
pub const CHASE_PARENT: u32 = 1 << 10;
pub const CHASE_MKDIR_0755: u32 = 1 << 11;
pub const CHASE_EXTRACT_FILENAME: u32 = 1 << 12;
pub const CHASE_MUST_BE_DIRECTORY: u32 = 1 << 13;
pub const CHASE_MUST_BE_REGULAR: u32 = 1 << 14;
pub const CHASE_MUST_BE_SOCKET: u32 = 1 << 15;

const CHASE_MAX: u32 = 128;
const CHASE_NO_SHORTCUT_MASK: u32 = CHASE_NONEXISTENT
    | CHASE_NO_AUTOFS
    | CHASE_SAFE
    | CHASE_STEP
    | CHASE_PROHIBIT_SYMLINKS
    | CHASE_PARENT
    | CHASE_MKDIR_0755;

fn s_isdir(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFDIR
}
fn s_isreg(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFREG
}
fn s_islnk(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFLNK
}
fn s_issock(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFSOCK
}

/// `stat_verify_regular()`'s errors on a mode.
pub fn mode_verify_regular(m: u32) -> Result<(), i32> {
    if s_isdir(m) {
        return Err(-libc::EISDIR);
    }
    if s_islnk(m) {
        return Err(-libc::ELOOP);
    }
    if !s_isreg(m) {
        return Err(-libc::EBADFD);
    }
    Ok(())
}

/// `stat_verify_directory()`'s errors on a mode.
pub fn mode_verify_directory(m: u32) -> Result<(), i32> {
    if s_islnk(m) {
        return Err(-libc::ELOOP);
    }
    if !s_isdir(m) {
        return Err(-libc::ENOTDIR);
    }
    Ok(())
}

/// `stat_verify_socket()`'s errors on a mode.
pub fn mode_verify_socket(m: u32) -> Result<(), i32> {
    if s_isdir(m) {
        return Err(-libc::EISDIR);
    }
    if s_islnk(m) {
        return Err(-libc::ELOOP);
    }
    if !s_issock(m) {
        return Err(-libc::ENOTSOCK);
    }
    Ok(())
}

fn statx_inode_same(a: &Statx, b: &Statx) -> bool {
    a.ino == b.ino && a.dev_major == b.dev_major && a.dev_minor == b.dev_minor
}

/// `statx_mount_same()`.
fn statx_mount_same(a: &Statx, b: &Statx) -> Result<bool, i32> {
    match (a.mnt_id, b.mnt_id) {
        (Some(x), Some(y)) => Ok(x == y),
        _ => Err(-libc::ENODATA),
    }
}

/// `statx_unsafe_transition()`.
fn statx_unsafe_transition(a: &Statx, b: &Statx) -> bool {
    a.uid != 0 && a.uid != b.uid
}

/// `chase_openat2()`: the openat2() shortcut; `Err(-EOPNOTSUPP)` means "use the loop".
fn chase_openat2(root_fd: i32, dir_fd: i32, path: &[u8], flags: u32) -> Result<OwnedFd, i32> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CAN_OPENAT2: AtomicBool = AtomicBool::new(true);
    if !CAN_OPENAT2.load(Ordering::Relaxed) {
        return Err(-libc::EOPNOTSUPP);
    }
    if flags & (CHASE_NO_SHORTCUT_MASK & !CHASE_PROHIBIT_SYMLINKS) != 0 || flags & CHASE_TRIGGER_AUTOFS != 0 {
        return Err(-libc::EOPNOTSUPP);
    }
    if root_fd != XAT_FDROOT && root_fd != dir_fd {
        return Err(-libc::EOPNOTSUPP);
    }
    let mut _local = None;
    let mut dir_fd = dir_fd;
    if dir_fd == XAT_FDROOT {
        if path_is_absolute(path) {
            dir_fd = AT_FDCWD;
        } else {
            let fd = sys::open(b"/", libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0)?;
            dir_fd = fd;
            _local = Some(OwnedFd::new(fd));
        }
    }
    let mut oflags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    if flags & CHASE_NOFOLLOW != 0 {
        oflags |= libc::O_NOFOLLOW as u64;
    }
    if flags & CHASE_MUST_BE_DIRECTORY != 0 {
        oflags |= libc::O_DIRECTORY as u64;
    }
    let mut resolve = 0u64;
    if root_fd != XAT_FDROOT {
        resolve |= libc::RESOLVE_IN_ROOT;
    }
    if flags & CHASE_PROHIBIT_SYMLINKS != 0 {
        resolve |= libc::RESOLVE_NO_SYMLINKS;
    }
    let fd = match sys::openat2(dir_fd, path, oflags, 0, resolve) {
        Ok(fd) => OwnedFd::new(fd),
        Err(e) => {
            if e == -libc::ENOSYS {
                CAN_OPENAT2.store(false, Ordering::Relaxed);
            }
            if e == -libc::ENOSYS || e == -libc::EPERM || e == -libc::EAGAIN {
                return Err(-libc::EOPNOTSUPP);
            }
            return Err(e);
        }
    };
    if flags & CHASE_MUST_BE_REGULAR != 0 {
        mode_verify_regular(sys::fstat(fd.raw())?.st_mode)?;
    }
    if flags & CHASE_MUST_BE_SOCKET != 0 {
        mode_verify_socket(sys::fstat(fd.raw())?.st_mode)?;
    }
    Ok(fd)
}

/// `xopenat_full()` for the O_PATH opens chase() does (no O_CREAT except O_DIRECTORY|O_CREAT).
fn xopenat_path(
    dir_fd: i32,
    path: &[u8],
    open_flags: i32,
    must_regular: bool,
    must_socket: bool,
) -> Result<OwnedFd, i32> {
    if path.is_empty() {
        if must_regular {
            mode_verify_regular(sys::fstat(dir_fd)?.st_mode)?;
        }
        if must_socket {
            mode_verify_socket(sys::fstat(dir_fd)?.st_mode)?;
        }
        return fd_reopen(dir_fd, open_flags & !libc::O_NOFOLLOW).map(OwnedFd::new);
    }
    let mut _local = None;
    let mut dir_fd = dir_fd;
    if dir_fd == XAT_FDROOT {
        if path_is_absolute(path) {
            dir_fd = AT_FDCWD;
        } else {
            let fd = sys::open(b"/", libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0)?;
            dir_fd = fd;
            _local = Some(OwnedFd::new(fd));
        }
    }
    let mut flags = open_flags;
    if flags & libc::O_DIRECTORY != 0 && flags & libc::O_CREAT != 0 {
        match sys::mkdirat(dir_fd, path, 0o755) {
            Ok(()) => {}
            Err(e) if e == -libc::EEXIST => {
                if flags & libc::O_EXCL != 0 {
                    return Err(-libc::EEXIST);
                }
            }
            Err(e) => return Err(e),
        }
        flags &= !(libc::O_EXCL | libc::O_CREAT);
    }
    let fd = OwnedFd::new(sys::openat(dir_fd, path, flags, 0o644)?);
    if must_regular {
        mode_verify_regular(sys::fstat(fd.raw())?.st_mode)?;
    }
    if must_socket {
        mode_verify_socket(sys::fstat(fd.raw())?.st_mode)?;
    }
    Ok(fd)
}

fn log_unsafe_transition(a: i32, b: i32, path: &[u8], flags: u32) -> i32 {
    if flags & CHASE_WARN == 0 {
        return -libc::ENOLINK;
    }
    let n1 = crate::fd::fd_get_path(a).ok();
    let n2 = crate::fd::fd_get_path(b).ok();
    let ua = sys::fstat(a).ok().map(|st| crate::user::uid_to_name(st.st_uid));
    let ub = sys::fstat(b).ok().map(|st| crate::user::uid_to_name(st.st_uid));
    crate::log_warning_errno!(
        crate::errno::synthetic(libc::ENOLINK),
        "Detected unsafe path transition ",
        crate::string::strna(n1.as_deref()),
        " (owned by ",
        crate::string::strna(ua.as_deref()),
        ") ",
        crate::locale::glyph(crate::locale::Glyph::ArrowRight),
        " ",
        crate::string::strna(n2.as_deref()),
        " (owned by ",
        crate::string::strna(ub.as_deref()),
        ") during canonicalization of ",
        path,
        "."
    )
}

fn log_prohibited_symlink(fd: i32, flags: u32) -> i32 {
    if flags & CHASE_WARN == 0 {
        return -libc::ELOOP;
    }
    let n1 = crate::fd::fd_get_path(fd).ok();
    crate::log_warning_errno!(
        crate::errno::synthetic(libc::ELOOP),
        "Detected symlink where no symlink is allowed at '",
        crate::string::strna(n1.as_deref()),
        "', refusing."
    )
}

/// The result of `chaseat()`: C's return value (1/0 for found/nonexistent),
/// the normalized path and the O_PATH fd, each if asked for.
#[derive(Debug)]
pub struct Chased {
    pub exists: bool,
    pub path: Option<Vec<u8>>,
    pub fd: Option<OwnedFd>,
}

const AUTOFS_SUPER_MAGIC: i64 = 0x0187;

/// `log_autofs_mount_point()`.
fn log_autofs_mount_point(fd: i32, path: &[u8], flags: u32) -> i32 {
    if flags & CHASE_WARN == 0 {
        return -libc::EREMOTE;
    }
    let n1 = crate::fd::fd_get_path(fd).ok();
    crate::log_warning_errno!(
        crate::errno::synthetic(libc::EREMOTE),
        "Detected autofs mount point '",
        crate::string::strna(n1.as_deref()),
        "' during canonicalization of '",
        path,
        "'."
    )
}

/// `chaseat(root_fd, dir_fd, path, flags, ret_path, ret_fd)`.
pub fn chaseat(
    root_fd: i32,
    dir_fd: i32,
    path: &[u8],
    mut flags: u32,
    want_path: bool,
    want_fd: bool,
) -> Result<Chased, i32> {
    assert!(flags & (CHASE_PREFIX_ROOT | CHASE_STEP | CHASE_TRIGGER_AUTOFS) == 0);
    assert!(wildcard_fd_is_valid(dir_fd) && wildcard_fd_is_valid(root_fd));

    let mut root_fd = root_fd;
    let mut dir_fd = dir_fd;
    if root_fd == AT_FDCWD {
        root_fd = XAT_FDROOT;
    } else if dir_fd_is_root(root_fd)? {
        root_fd = XAT_FDROOT;
    }
    if dir_fd_is_root(dir_fd)? && root_fd == XAT_FDROOT {
        dir_fd = XAT_FDROOT;
    }
    if dir_fd == XAT_FDROOT || path_is_absolute(path) {
        dir_fd = root_fd;
    }
    let path: &[u8] = if path.is_empty() { b"." } else { path };

    let mut append_trail_slash = false;
    if path.ends_with(b"/") || path.ends_with(b"/.") {
        flags |= CHASE_MUST_BE_DIRECTORY;
        if flags & CHASE_TRAIL_SLASH != 0 {
            append_trail_slash = true;
        }
    } else if dot_or_dot_dot(path) || path.ends_with(b"/..") {
        flags |= CHASE_MUST_BE_DIRECTORY;
    }
    if flags & CHASE_PARENT != 0 {
        flags |= CHASE_MUST_BE_DIRECTORY;
    }
    let n_must = [CHASE_MUST_BE_DIRECTORY, CHASE_MUST_BE_REGULAR, CHASE_MUST_BE_SOCKET]
        .iter()
        .filter(|&&f| flags & f != 0)
        .count();
    if n_must > 1 {
        return Err(-libc::EBADSLT);
    }

    if !want_path {
        match chase_openat2(root_fd, dir_fd, path, flags) {
            Ok(fd) => return Ok(Chased { exists: true, path: None, fd: if want_fd { Some(fd) } else { None } }),
            Err(e) if e != -libc::EOPNOTSUPP => return Err(e),
            Err(_) => {}
        }
    }

    if root_fd == XAT_FDROOT && !want_path && flags & CHASE_NO_SHORTCUT_MASK == 0 {
        let mut of = libc::O_PATH | libc::O_CLOEXEC;
        if flags & CHASE_NOFOLLOW != 0 {
            of |= libc::O_NOFOLLOW;
        }
        if flags & CHASE_MUST_BE_DIRECTORY != 0 {
            of |= libc::O_DIRECTORY;
        }
        let fd = xopenat_path(dir_fd, path, of, flags & CHASE_MUST_BE_REGULAR != 0, flags & CHASE_MUST_BE_SOCKET != 0)?;
        return Ok(Chased { exists: true, path: None, fd: if want_fd { Some(fd) } else { None } });
    }

    let mut need_absolute =
        (root_fd == XAT_FDROOT || dir_fd != root_fd) && (dir_fd == XAT_FDROOT || path_is_absolute(path));
    let mut done: Option<Vec<u8>> = if need_absolute { Some(b"/".to_vec()) } else { None };

    let mut fd = xopenat_path(dir_fd, b"", libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, false, false)?;
    let mut stx = sys::statx_fd(fd.raw())?;
    let root_stx = if root_fd != XAT_FDROOT {
        if root_fd == dir_fd { Some(stx) } else { Some(sys::statx_fd(root_fd)?) }
    } else {
        None
    };

    let mut buffer = path.to_vec();
    let mut todo_off = 0usize;
    let mut exists = true;
    let mut n_steps = 0u32;
    loop {
        if n_steps > CHASE_MAX {
            return Err(-libc::ELOOP);
        }
        n_steps += 1;
        let mut todo = &buffer[todo_off..];
        let (r, e) = path_find_first_component(&mut todo, true)?;
        let todo_rest = todo.to_vec();
        todo_off = buffer.len() - todo.len();
        if r == 0 {
            break;
        }
        let first = e[..r].to_vec();

        if first == b".." {
            if let Some(root_stx) = &root_stx {
                let mut is_root = root_fd == dir_fd && empty_or_root(done.as_deref());
                if !is_root && statx_inode_same(&stx, root_stx) {
                    is_root = statx_mount_same(&stx, root_stx)?;
                }
                if is_root {
                    continue;
                }
            }
            let fd_parent = OwnedFd::new(sys::openat(
                fd.raw(),
                b"..",
                libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH | libc::O_DIRECTORY,
                0,
            )?);
            let stx_parent = sys::statx_fd(fd_parent.raw())?;
            if statx_inode_same(&stx_parent, &stx) && dir_fd_is_root(fd.raw())? {
                continue;
            }
            match path_extract_directory(done.as_deref().unwrap_or_default()) {
                Ok(parent) => done = Some(parent),
                Err(e) if e == -libc::EDESTADDRREQ => done = None,
                Err(e) if e == -libc::EINVAL => {
                    if let Some(d) = &done
                        && !d.is_empty()
                        && !path_is_valid(d)
                    {
                        return Err(-libc::EINVAL);
                    }
                    let d = done.take().unwrap_or_default();
                    done = Some(path_join(&[&d, b".."]));
                }
                Err(e) => return Err(e),
            }
            if flags & CHASE_SAFE != 0 && statx_unsafe_transition(&stx, &stx_parent) {
                return Err(log_unsafe_transition(fd.raw(), fd_parent.raw(), path, flags));
            }
            if flags & CHASE_PARENT != 0 && todo_rest.is_empty() {
                let fd_gp = OwnedFd::new(sys::openat(
                    fd_parent.raw(),
                    b"..",
                    libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH | libc::O_DIRECTORY,
                    0,
                )?);
                let stx_gp = sys::statx_fd(fd_gp.raw())?;
                if flags & CHASE_SAFE != 0 && statx_unsafe_transition(&stx_parent, &stx_gp) {
                    return Err(log_unsafe_transition(fd_parent.raw(), fd_gp.raw(), path, flags));
                }
                stx = stx_gp;
                fd = fd_gp;
                break;
            }
            stx = stx_parent;
            fd = fd_parent;
            continue;
        }

        let child = match sys::openat(fd.raw(), &first, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0) {
            Ok(c) => OwnedFd::new(c),
            Err(r) => {
                if r != -libc::ENOENT {
                    return Err(r);
                }
                if !todo_rest.is_empty() && !path_is_safe(&todo_rest) {
                    return Err(r);
                }
                if flags & CHASE_MKDIR_0755 != 0
                    && (!todo_rest.is_empty() || flags & (CHASE_PARENT | CHASE_NONEXISTENT) == 0)
                {
                    xopenat_path(
                        fd.raw(),
                        &first,
                        libc::O_DIRECTORY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_PATH
                            | libc::O_CLOEXEC,
                        false,
                        false,
                    )?
                } else if flags & CHASE_PARENT != 0 && todo_rest.is_empty() {
                    let d = done.take().unwrap_or_default();
                    done = Some(path_join(&[&d, &first]));
                    break;
                } else if flags & CHASE_NONEXISTENT != 0 {
                    let d = done.take().unwrap_or_default();
                    done = Some(path_join(&[&d, &first, &todo_rest]));
                    exists = false;
                    break;
                } else {
                    return Err(r);
                }
            }
        };

        let stx_child = sys::statx_fd(child.raw())?;
        if flags & CHASE_SAFE != 0 && statx_unsafe_transition(&stx, &stx_child) {
            return Err(log_unsafe_transition(fd.raw(), child.raw(), path, flags));
        }

        if flags & CHASE_NO_AUTOFS != 0
            && crate::stat_util::is_fs_type_at(child.raw(), None, AUTOFS_SUPER_MAGIC).unwrap_or(false)
        {
            return Err(log_autofs_mount_point(child.raw(), path, flags));
        }

        if s_islnk(stx_child.mode) && !(flags & CHASE_NOFOLLOW != 0 && todo_rest.is_empty()) {
            if flags & CHASE_PROHIBIT_SYMLINKS != 0 {
                return Err(log_prohibited_symlink(child.raw(), flags));
            }
            let destination = sys::readlinkat(fd.raw(), &first)?;
            if destination.is_empty() {
                return Err(-libc::EINVAL);
            }
            if path_is_absolute(&destination) {
                fd = OwnedFd::new(fd_reopen(root_fd, libc::O_CLOEXEC | libc::O_PATH | libc::O_DIRECTORY)?);
                stx = sys::statx_fd(fd.raw())?;
                if flags & CHASE_SAFE != 0 && statx_unsafe_transition(&stx_child, &stx) {
                    return Err(log_unsafe_transition(child.raw(), fd.raw(), path, flags));
                }
                if dir_fd != root_fd {
                    need_absolute = true;
                }
                done = if need_absolute { Some(b"/".to_vec()) } else { None };
            }
            buffer = path_join(&[&destination, &todo_rest]);
            todo_off = 0;
            continue;
        }

        let d = done.take().unwrap_or_default();
        done = Some(path_join(&[&d, &first]));
        if flags & CHASE_PARENT != 0 && todo_rest.is_empty() {
            break;
        }
        stx = stx_child;
        fd = child;
    }

    if exists {
        if flags & CHASE_MUST_BE_DIRECTORY != 0 {
            mode_verify_directory(stx.mode)?;
        }
        if flags & CHASE_MUST_BE_REGULAR != 0 {
            mode_verify_regular(stx.mode)?;
        }
        if flags & CHASE_MUST_BE_SOCKET != 0 {
            mode_verify_socket(stx.mode)?;
        }
    }

    let mut ret_path = None;
    if want_path {
        if flags & CHASE_EXTRACT_FILENAME != 0
            && let Some(d) = &done
        {
            done = match path_extract_filename(d) {
                Ok(f) => Some(f),
                Err(e) if e == -libc::EADDRNOTAVAIL => None,
                Err(e) => return Err(e),
            };
        }
        let mut d = done.take().unwrap_or_else(|| b".".to_vec());
        if append_trail_slash {
            d.push(b'/');
        }
        ret_path = Some(d);
    }
    let ret_fd = if want_fd && exists { Some(fd) } else { None };
    Ok(Chased { exists, path: ret_path, fd: ret_fd })
}

/// `empty_or_root_harder_to_null()`: map a root that *is* "/" (by path or
/// by inode) to None.
pub fn empty_or_root_harder_to_null(root: Option<&[u8]>) -> Result<Option<&[u8]>, i32> {
    let Some(r) = root else { return Ok(None) };
    if empty_or_root(Some(r)) {
        return Ok(None);
    }
    match crate::fd::path_is_root_at(AT_FDCWD, r) {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(r)),
        Err(e) if e == -libc::ENOENT => Ok(Some(r)),
        Err(e) => Err(e),
    }
}

/// `chase(path, root, flags, ret_path, ret_fd)`.
pub fn chase(path: &[u8], root: Option<&[u8]>, flags: u32, want_path: bool, want_fd: bool) -> Result<Chased, i32> {
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    let root = empty_or_root_harder_to_null(root)?;
    let root: Vec<u8> = match root {
        None => b"/".to_vec(),
        Some(r) => path_simplify(&path_make_absolute_cwd(r)?),
    };
    let is_root = empty_or_root(Some(&root));
    let absolute = if !is_root && flags & CHASE_PREFIX_ROOT != 0 {
        path_join(&[&root, path])
    } else {
        path_make_absolute_cwd(path)?
    };
    let Some(rel) = path_startswith(&absolute, &root) else {
        let lvl = if flags & CHASE_WARN != 0 { libc::LOG_WARNING } else { libc::LOG_DEBUG };
        return Err(crate::log_full_errno!(
            lvl,
            crate::errno::synthetic(libc::ECHRNG),
            "Specified path '",
            absolute,
            "' is outside of specified root directory '",
            root,
            "', refusing to resolve."
        ));
    };
    let rel = rel.to_vec();
    let _root_fd;
    let fd = if is_root {
        XAT_FDROOT
    } else {
        _root_fd = OwnedFd::new(sys::open(&root, libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0)?);
        _root_fd.raw()
    };
    let mut c = chaseat(fd, fd, &rel, flags & !CHASE_PREFIX_ROOT, want_path, want_fd)?;
    if let Some(p) = c.path.take() {
        c.path = Some(if flags & CHASE_EXTRACT_FILENAME != 0 || is_root {
            p
        } else {
            let skip = if p == b"." || p == b"./" { 1 } else { 0 };
            path_join(&[&root, &p[skip..]])
        });
    }
    Ok(c)
}

/// `chaseat_prefix_root(path, root)`.
pub fn chaseat_prefix_root(path: &[u8], root: Option<&[u8]>) -> Result<Vec<u8>, i32> {
    if path_is_absolute(path) {
        return Ok(path.to_vec());
    }
    let root = match empty_or_root_harder_to_null(root) {
        Ok(r) => r,
        Err(e) if e == -libc::ENOENT => root,
        Err(e) => return Err(e),
    };
    if empty_or_root(root) {
        return Err(-libc::EINVAL);
    }
    let root = path_simplify(&path_make_absolute_cwd(root.unwrap_or_default())?);
    let skip = if path.first() == Some(&b'.') && matches!(path.get(1), Some(b'/') | None) { 1 } else { 0 };
    Ok(path_join(&[&root, &path[skip..]]))
}

/// `chase_and_opendirat(root_fd, dir_fd, path, flags, ret_path, ret_dir)`.
pub fn chase_and_opendirat(
    root_fd: i32,
    dir_fd: i32,
    path: &[u8],
    flags: u32,
    want_path: bool,
) -> Result<(Option<Vec<u8>>, sys::Dir), i32> {
    if root_fd == XAT_FDROOT && dir_fd == AT_FDCWD && !want_path && flags & CHASE_NO_SHORTCUT_MASK == 0 {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?;
        return Ok((None, sys::Dir::from_fd(fd)?));
    }
    let c = chaseat(root_fd, dir_fd, path, flags, want_path, true)?;
    let pfd = c.fd.expect("chaseat() returns an fd for an existing path");
    let fd =
        sys::openat(pfd.raw(), b".", libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0)?;
    Ok((c.path, sys::Dir::from_fd(fd)?))
}
