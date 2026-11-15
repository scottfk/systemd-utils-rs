// SPDX-License-Identifier: LGPL-2.1-or-later
//! `mkdir.c`, `tmpfile-util.c` and parts of `fs-util.c`.

use crate::fd::AT_FDCWD;
use crate::path::{
    NAME_MAX, path_find_first_component, path_find_last_component, path_is_safe, path_is_valid, path_join,
    path_simplify, path_split_prefix_filename,
};
use crate::sys::{self, OwnedFd};

/// `is_dir_at(dir_fd, path, follow)`.
pub fn is_dir_at(dir_fd: i32, path: &[u8], follow: bool) -> Result<bool, i32> {
    let st = sys::fstatat(dir_fd, path, if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW })?;
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// `mkdirat_safe_internal()` for `uid`/`gid` = invalid and the flags mkdir_p() uses.
fn mkdirat_safe_ignore_existing(dir_fd: i32, path: &[u8], mode: u32) -> Result<(), i32> {
    match sys::mkdirat(dir_fd, path, mode) {
        Ok(()) => {
            // chmod_and_chown_at(): apply the exact mode if the umask changed it.
            let st = sys::fstatat(dir_fd, path, libc::AT_SYMLINK_NOFOLLOW)?;
            if st.st_mode & 0o7777 != mode & 0o7777 {
                sys::fchmodat(dir_fd, path, mode)?;
            }
            Ok(())
        }
        Err(e) if e != -libc::EEXIST => Err(e),
        Err(_) => {
            let st = sys::fstatat(dir_fd, path, libc::AT_SYMLINK_NOFOLLOW)?;
            if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                let c = crate::chase::chaseat(
                    crate::fd::XAT_FDROOT,
                    dir_fd,
                    path,
                    crate::chase::CHASE_NONEXISTENT,
                    true,
                    false,
                )?;
                if !c.exists {
                    let p = c.path.expect("requested");
                    return mkdirat_safe_ignore_existing(dir_fd, &p, mode);
                }
            }
            Ok(())
        }
    }
}

/// `mkdirat_parents_internal(dir_fd, path, mode, ...)`.
fn mkdirat_parents(dir_fd: i32, path: &[u8], mode: u32) -> Result<(), i32> {
    if path.is_empty() {
        return Ok(());
    }
    if !path_is_safe(path) {
        return Err(-libc::ENOTDIR);
    }
    let (r, _, e) = path_find_last_component(path, false)?;
    if r == 0 || e == 0 {
        return Ok(());
    }
    let parent = &path[..e];
    match is_dir_at(dir_fd, parent, true) {
        Ok(true) => return Ok(()),
        Ok(false) => return Err(-libc::ENOTDIR),
        Err(_) => {}
    }
    let mut p = parent;
    loop {
        let (n, s) = path_find_first_component(&mut p, false)?;
        if n == 0 {
            return Ok(());
        }
        let upto = parent.len() - s.len() + n;
        match mkdirat_safe_ignore_existing(dir_fd, &parent[..upto], mode) {
            Ok(()) => {}
            Err(e) if e == -libc::EEXIST => {}
            Err(e) => return Err(e),
        }
    }
}

/// `mkdir_p(path, mode)`.
pub fn mkdir_p(path: &[u8], mode: u32) -> Result<(), i32> {
    mkdirat_parents(AT_FDCWD, path, mode)?;
    match sys::mkdirat(AT_FDCWD, path, mode) {
        Ok(()) => Ok(()),
        Err(e) if e == -libc::EEXIST && is_dir_at(AT_FDCWD, path, true).unwrap_or(false) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `random_u64()`.
fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = sys::getrandom(&mut b);
    u64::from_ne_bytes(b)
}

/// `tempfn_build(p, pre, post, child=false)`.
fn tempfn_build(p: &[u8], pre: Option<&[u8]>, post: &[u8]) -> Result<Vec<u8>, i32> {
    let len_pre = pre.map(|x| x.len()).unwrap_or(0);
    let len_add = len_pre + post.len() + 2;
    let (d, f, _) = path_split_prefix_filename(p, true, true)?;
    let mut fn_ = f.expect("requested");
    if fn_.len() > NAME_MAX - len_add {
        fn_.truncate(NAME_MAX - len_add);
    }
    let nf = crate::bcat!(".#", pre.unwrap_or_default(), fn_, post);
    let result = match d {
        Some(d) => path_simplify(&path_join(&[&d, &nf])),
        None => nf,
    };
    if !path_is_valid(&result) {
        return Err(-libc::EINVAL);
    }
    Ok(result)
}

/// `tempfn_random(p, extra)`.
pub fn tempfn_random(p: &[u8], extra: Option<&[u8]>) -> Result<Vec<u8>, i32> {
    tempfn_build(p, extra, format!("{:016x}", random_u64()).as_bytes())
}

/// `fopen_temporary(path, &f, &temp)`: the fd and the temporary name.
pub fn fopen_temporary(path: &[u8]) -> Result<(OwnedFd, Vec<u8>), i32> {
    let t = tempfn_random(path, None)?;
    let fd = sys::openat(
        AT_FDCWD,
        &t,
        libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    Ok((OwnedFd::new(fd), t))
}

/// `conservative_renameat(AT_FDCWD, old, AT_FDCWD, new)`.
pub fn conservative_rename(old: &[u8], new: &[u8]) -> Result<bool, i32> {
    let same = (|| -> Option<bool> {
        let ofd =
            OwnedFd::new(sys::open(old, libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOCTTY | libc::O_NOFOLLOW, 0).ok()?);
        let nfd =
            OwnedFd::new(sys::open(new, libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOCTTY | libc::O_NOFOLLOW, 0).ok()?);
        let os = sys::fstat(ofd.raw()).ok()?;
        if os.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        let ns = sys::fstat(nfd.raw()).ok()?;
        if os.st_dev == ns.st_dev && os.st_ino == ns.st_ino {
            return Some(true);
        }
        if os.st_mode != ns.st_mode || os.st_size != ns.st_size || os.st_uid != ns.st_uid || os.st_gid != ns.st_gid {
            return None;
        }
        let mut b1 = vec![0u8; 16 * 1024];
        let mut b2 = vec![0u8; 16 * 1024];
        loop {
            let l1 = sys::read(ofd.raw(), &mut b1).ok()?;
            let l2 = if l1 == b1.len() {
                sys::read(nfd.raw(), &mut b2[..l1]).ok()?
            } else {
                sys::read(nfd.raw(), &mut b2[..l1 + 1]).ok()?
            };
            if l2 != l1 || b1[..l1] != b2[..l1] {
                return None;
            }
            if l1 < b1.len() {
                return Some(true);
            }
        }
    })();
    if same == Some(true) && sys::unlinkat(AT_FDCWD, old, 0).is_ok() {
        return Ok(false);
    }
    sys::renameat(AT_FDCWD, old, AT_FDCWD, new)?;
    Ok(true)
}
