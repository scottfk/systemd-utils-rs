// SPDX-License-Identifier: LGPL-2.1-or-later
//! tmpfiles.c: what each line does — create, adjust, remove, clean, purge.
//!
//! Functions keep C's `int` convention: negative errno on failure (already
//! logged where C logs), zero or positive otherwise.

use std::cell::Cell;
use std::collections::HashSet;

use shared::chase::{
    CHASE_NO_AUTOFS, CHASE_NOFOLLOW, CHASE_NONEXISTENT, CHASE_PREFIX_ROOT, CHASE_SAFE, CHASE_WARN, chase,
};
use shared::errno::{is_privilege, ret_gather, strerror, synthetic};
use shared::fd::{AT_FDCWD, fd_get_path, proc_fd_path};
use shared::path::{
    dot_or_dot_dot, filename_is_valid, is_path, path_extract_directory, path_is_absolute, path_is_normalized,
    path_join, path_simplify, path_split_prefix_filename,
};
use shared::rm_rf::{REMOVE_CHMOD, REMOVE_CHMOD_RESTORE, REMOVE_PHYSICAL, REMOVE_ROOT, REMOVE_SUBVOLUME};
use shared::stat_util::{NSEC_INFINITY, statx_times, xopendirat, xstatx_full};
use shared::sys::{self, Dir, OwnedFd, Stat};
use shared::time::{TimestampStyle, format_timestamp_style};
use shared::{
    log_debug, log_debug_errno, log_error_errno, log_full_errno, log_info, log_notice, log_notice_errno, log_warning,
    log_warning_errno,
};

use crate::item::*;
use crate::{Context, args, log_action};

const MAX_DEPTH: i32 = 256;
const NSEC_PER_USEC: u64 = 1000;

/// `CreationMode` (`_CREATION_MODE_INVALID` is `Invalid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationMode {
    Normal,
    Existing,
    Force,
    Invalid,
}

/// `creation_mode_verb_to_string()`.
fn creation_mode_verb(c: CreationMode) -> &'static str {
    match c {
        CreationMode::Normal => "Created",
        CreationMode::Existing => "Found existing",
        CreationMode::Force => "Created replacement",
        CreationMode::Invalid => "(null)",
    }
}

fn s_isdir(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFDIR
}

fn s_isreg(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFREG
}

fn s_islnk(m: u32) -> bool {
    m & libc::S_IFMT == libc::S_IFLNK
}

fn root() -> Option<&'static [u8]> {
    args().root.as_deref()
}

/// `FORMAT_TIMESTAMP_STYLE(nsec / NSEC_PER_USEC, TIMESTAMP_US)`, with
/// glibc's "(null)" for a timestamp that does not format.
fn fmt_ts_nsec(nsec: u64) -> Vec<u8> {
    format_timestamp_style(nsec / NSEC_PER_USEC, TimestampStyle::Us).unwrap_or_else(|| b"(null)".to_vec())
}

/// `WITH_UMASK(mask) { ... }`.
fn with_umask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    let saved = sys::umask(mask);
    let r = f();
    sys::umask(saved);
    r
}

/// `RET_NERRNO(openat(...))` as an owned fd.
fn openat(dir_fd: i32, path: &[u8], flags: i32, mode: u32) -> Result<OwnedFd, i32> {
    sys::openat(dir_fd, path, flags, mode).map(OwnedFd::new)
}

/// `path_extract_filename()`, with C's O_DIRECTORY result as the flag.
fn extract_filename(path: &[u8]) -> Result<(Vec<u8>, bool), i32> {
    let (_, f, dir) = path_split_prefix_filename(path, false, true)?;
    Ok((f.expect("requested"), dir))
}

/// `load_unix_sockets()`.
fn load_unix_sockets(c: &Context) -> i32 {
    if c.unix_sockets.borrow().is_some() {
        return 0;
    }
    let mut f = match shared::fileio::fopen_re(b"/proc/net/unix") {
        Ok(f) => f,
        Err(e) => {
            return log_full_errno!(
                if e == -libc::ENOENT { libc::LOG_DEBUG } else { libc::LOG_WARNING },
                e,
                "Failed to open ",
                "/proc/net/unix",
                ", ignoring: ",
                strerror(e)
            );
        }
    };
    match shared::fileio::read_line(&mut f, shared::fileio::LONG_LINE_MAX) {
        Err(r) => return log_warning_errno!(r, "Failed to skip /proc/net/unix header line: ", strerror(r)),
        Ok((0, _)) => {
            return log_warning_errno!(synthetic(libc::EIO), "Premature end of file reading /proc/net/unix.");
        }
        Ok(_) => {}
    }
    let mut sockets = HashSet::new();
    loop {
        let line = match shared::fileio::read_line(&mut f, shared::fileio::LONG_LINE_MAX) {
            Err(r) => return log_warning_errno!(r, "Failed to read /proc/net/unix line, ignoring: ", strerror(r)),
            Ok((0, _)) => break,
            Ok((_, l)) => l,
        };
        let line = shared::bytes::c_str_prefix(&line);
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let mut p = &line[colon..];
        if p.len() < 37 {
            continue;
        }
        p = &p[37..];
        let ws = shared::string::WHITESPACE;
        let skip = |p: &[u8], want_ws: bool| p.iter().position(|b| ws.contains(b) != want_ws).unwrap_or(p.len());
        p = &p[skip(p, true)..];
        p = &p[skip(p, false)..];
        p = &p[skip(p, true)..];
        if !path_is_absolute(p) {
            continue;
        }
        sockets.insert(path_simplify(p));
    }
    *c.unix_sockets.borrow_mut() = Some(sockets);
    1
}

/// `unix_socket_alive()`.
fn unix_socket_alive(c: &Context, path: &[u8]) -> bool {
    if load_unix_sockets(c) < 0 {
        return true; // We don't know, so assume yes.
    }
    c.unix_sockets.borrow().as_ref().expect("loaded").contains(&path_simplify(path))
}

/// `find_glob()`.
fn find_glob(c: &Context, m: &[u8]) -> bool {
    c.globs_order.iter().any(|&j| {
        c.arrays[j].items.iter().any(|i| sys::fnmatch(&i.path, m, libc::FNM_PATHNAME | libc::FNM_PERIOD) == 0)
    })
}

/// `xopendirat_nomod(dirfd, path)`.
fn xopendirat_nomod(dirfd: i32, path: &[u8]) -> Result<Dir, i32> {
    let sub = if dirfd == AT_FDCWD { "" } else { "sub" };
    match xopendirat(dirfd, path, libc::O_NOFOLLOW | libc::O_NOATIME) {
        Ok(d) => return Ok(d),
        Err(e) => {
            if e != -libc::ENOENT && e != -libc::ELOOP {
                log_debug_errno!(e, "Cannot open ", sub, "directory \"", path, "\" with O_NOATIME: ", strerror(e));
            }
            if !is_privilege(-e) {
                return Err(e);
            }
        }
    }
    xopendirat(dirfd, path, libc::O_NOFOLLOW).inspect_err(|&e| {
        log_debug_errno!(e, "Cannot open ", sub, "directory \"", path, "\" with or without O_NOATIME: ", strerror(e));
    })
}

/// `opendir_nomod(path)`.
fn opendir_nomod(path: &[u8]) -> Result<Dir, i32> {
    xopendirat_nomod(AT_FDCWD, path)
}

/// `opendir_and_stat()`: Ok(None) if missing or not a directory.
fn opendir_and_stat(path: &[u8]) -> Result<Option<(Dir, libc::statx, bool)>, i32> {
    let d = match opendir_nomod(path) {
        Ok(d) => d,
        Err(e) => {
            let ignore = e == -libc::ENOENT || e == -libc::ENOTDIR;
            let r = log_full_errno!(
                if ignore { libc::LOG_DEBUG } else { libc::LOG_ERR },
                e,
                "Failed to open directory ",
                path,
                ": ",
                strerror(e)
            );
            return if ignore { Ok(None) } else { Err(r) };
        }
    };
    let sx = match xstatx_full(
        d.fd(),
        None,
        libc::AT_EMPTY_PATH,
        libc::STATX_MODE | libc::STATX_INO,
        libc::STATX_ATIME | libc::STATX_MTIME,
        libc::STATX_ATTR_MOUNT_ROOT as u64,
    ) {
        Ok(sx) => sx,
        Err(r) => return Err(log_error_errno!(r, "statx(", path, ") failed: ", strerror(r))),
    };
    let mountpoint = sx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0;
    Ok(Some((d, sx, mountpoint)))
}

/// `needs_cleanup()`.
fn needs_cleanup(
    atime: u64,
    btime: u64,
    ctime: u64,
    mtime: u64,
    cutoff: u64,
    sub_path: &[u8],
    age_by: u32,
    is_dir: bool,
) -> bool {
    let kind = if is_dir { "Directory" } else { "File" };
    let checks = [
        (AGE_BY_MTIME, mtime, "modify"),
        (AGE_BY_ATIME, atime, "access"),
        (AGE_BY_CTIME, ctime, "change"),
        (AGE_BY_BTIME, btime, "birth"),
    ];
    for (flag, t, what) in checks {
        if age_by & flag != 0 && t != NSEC_INFINITY && t >= cutoff {
            log_debug!(kind, " \"", sub_path, "\": ", what, " time ", fmt_ts_nsec(t), " is too new.");
            return false;
        }
    }
    true
}

/// `dir_cleanup()`.
fn dir_cleanup(
    c: &Context,
    _i: &Item,
    p: &[u8],
    d: &mut Dir,
    self_atime_nsec: u64,
    self_mtime_nsec: u64,
    cutoff_nsec: u64,
    mountpoint: bool,
    maxdepth: i32,
    keep_this_level: bool,
    age_by_file: u32,
    age_by_dir: u32,
) -> i32 {
    let mut deleted = false;
    let mut r = 0;
    let dfd = d.fd();
    loop {
        let name = match d.next_entry() {
            Ok(Some((n, _))) => n,
            _ => break,
        };
        if dot_or_dot_dot(&name) {
            continue;
        }
        // QUIRK: as in C, r takes the result of each entry's statx() (1 if
        // all optional timestamps came back, else 0, or the error), so an
        // error from an earlier entry is forgotten by the next one, and
        // only the last entry decides what dir_cleanup() returns.
        const OPTIONAL: u32 = libc::STATX_ATIME | libc::STATX_MTIME | libc::STATX_CTIME | libc::STATX_BTIME;
        let res = xstatx_full(
            dfd,
            Some(&name),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_UID,
            OPTIONAL,
            libc::STATX_ATTR_MOUNT_ROOT as u64,
        );
        r = match &res {
            Ok(sx) => (sx.stx_mask & OPTIONAL == OPTIONAL) as i32,
            Err(e) => *e,
        };
        let sx = match res {
            Ok(sx) => sx,
            Err(e) if e == -libc::ENOENT => continue,
            Err(e) => {
                log_full_errno!(
                    if e == -libc::EACCES { libc::LOG_DEBUG } else { libc::LOG_ERR },
                    e,
                    "statx(",
                    p,
                    "/",
                    name,
                    ") failed: ",
                    strerror(e)
                );
                continue;
            }
        };
        if sx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0 {
            log_debug!("Ignoring \"", p, "/", name, "\": different mount points.");
            continue;
        }
        let (atime_nsec, mtime_nsec, ctime_nsec, btime_nsec) = statx_times(&sx);
        let sub_path = path_join(&[p, &name]);

        if c.items.contains_key(&sub_path) {
            log_debug!("Ignoring \"", sub_path, "\": a separate entry exists.");
            continue;
        }
        if find_glob(c, &sub_path) {
            log_debug!("Ignoring \"", sub_path, "\": a separate glob exists.");
            continue;
        }

        let mode = sx.stx_mode as u32;
        if s_isdir(mode) {
            if mountpoint && name == b"lost+found" && sx.stx_uid == 0 {
                log_debug!("Ignoring directory \"", sub_path, "\".");
                continue;
            }
            if maxdepth <= 0 {
                log_warning!("Reached max depth on \"", sub_path, "\".");
            } else {
                let mut sub_dir = match xopendirat_nomod(dfd, &name) {
                    Ok(sd) => sd,
                    Err(e) => {
                        if e != -libc::ENOENT {
                            r = log_warning_errno!(
                                e,
                                "Opening directory \"",
                                sub_path,
                                "\" failed, ignoring: ",
                                strerror(e)
                            );
                        }
                        continue;
                    }
                };
                if !args().dry_run
                    && let Err(e) = sys::flock(sub_dir.fd(), libc::LOCK_EX | libc::LOCK_NB)
                {
                    log_debug_errno!(
                        e,
                        "Couldn't acquire exclusive BSD lock on directory \"",
                        sub_path,
                        "\", skipping: ",
                        strerror(e)
                    );
                    continue;
                }
                let q = dir_cleanup(
                    c,
                    _i,
                    &sub_path,
                    &mut sub_dir,
                    atime_nsec,
                    mtime_nsec,
                    cutoff_nsec,
                    false,
                    maxdepth - 1,
                    false,
                    age_by_file,
                    age_by_dir,
                );
                if q < 0 {
                    r = q;
                }
            }
            if keep_this_level {
                log_debug!("Keeping directory \"", sub_path, "\".");
                continue;
            }
            if !needs_cleanup(atime_nsec, btime_nsec, ctime_nsec, mtime_nsec, cutoff_nsec, &sub_path, age_by_dir, true)
            {
                continue;
            }
            log_action!("Would remove", "Removing", " directory \"", sub_path, "\"");
            if !args().dry_run
                && let Err(e) = sys::unlinkat(dfd, &name, libc::AT_REMOVEDIR)
            {
                if e == -libc::ENOTEMPTY {
                    continue;
                }
                if e != -libc::ENOENT {
                    r = log_warning_errno!(e, "Failed to remove directory \"", sub_path, "\", ignoring: ", strerror(e));
                }
            }
            deleted = true;
        } else {
            // The lock taken below is held until after the unlink.
            let mut _lock: Option<OwnedFd> = None;
            if mode & libc::S_ISVTX != 0 {
                log_debug!("Skipping \"", sub_path, "\": sticky bit set.");
                continue;
            }
            if mountpoint
                && s_isreg(mode)
                && sx.stx_uid == 0
                && [&b".journal"[..], b"aquota.user", b"aquota.group"].contains(&&name[..])
            {
                log_debug!("Skipping \"", sub_path, "\".");
                continue;
            }
            if mode & libc::S_IFMT == libc::S_IFSOCK && unix_socket_alive(c, &sub_path) {
                log_debug!("Skipping \"", sub_path, "\": live socket.");
                continue;
            }
            if matches!(mode & libc::S_IFMT, libc::S_IFCHR | libc::S_IFBLK) {
                log_debug!("Skipping \"", sub_path, "\": a device.");
                continue;
            }
            if keep_this_level {
                log_debug!("Keeping \"", sub_path, "\".");
                continue;
            }
            if !needs_cleanup(
                atime_nsec,
                btime_nsec,
                ctime_nsec,
                mtime_nsec,
                cutoff_nsec,
                &sub_path,
                age_by_file,
                false,
            ) {
                continue;
            }
            if !args().dry_run {
                match openat(
                    dfd,
                    &name,
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NOATIME
                        | libc::O_NONBLOCK
                        | libc::O_NOCTTY,
                    0,
                ) {
                    Err(e) => {
                        if e != -libc::ENOENT && e != -libc::ELOOP {
                            log_warning_errno!(
                                e,
                                "Opening file \"",
                                sub_path,
                                "\" failed, proceeding without lock: ",
                                strerror(e)
                            );
                        }
                    }
                    Ok(fd) => {
                        if let Err(e) = sys::flock(fd.raw(), libc::LOCK_EX | libc::LOCK_NB)
                            && e == -libc::EAGAIN
                        {
                            log_debug_errno!(
                                e,
                                "Couldn't acquire exclusive BSD lock on file \"",
                                sub_path,
                                "\", skipping: ",
                                strerror(e)
                            );
                            continue;
                        }
                        _lock = Some(fd);
                    }
                }
            }
            log_action!("Would remove", "Removing", " \"", sub_path, "\"");
            if !args().dry_run
                && let Err(e) = sys::unlinkat(dfd, &name, 0)
                && e != -libc::ENOENT
            {
                r = log_warning_errno!(e, "Failed to remove \"", sub_path, "\", ignoring: ", strerror(e));
            }
            deleted = true;
        }
    }

    if deleted && (self_atime_nsec < NSEC_INFINITY || self_mtime_nsec < NSEC_INFINITY) {
        let show = |t: u64| if t != NSEC_INFINITY { fmt_ts_nsec(t) } else { b"(omitted)".to_vec() };
        log_action!(
            "Would restore",
            "Restoring",
            " access and modification time on \"",
            p,
            "\": ",
            show(self_atime_nsec),
            ", ",
            show(self_mtime_nsec)
        );
        let opt = |t: u64| if t != NSEC_INFINITY { Some(t) } else { None };
        if !args().dry_run
            && let Err(e) = sys::futimens(dfd, opt(self_atime_nsec), opt(self_mtime_nsec))
        {
            log_warning_errno!(e, "Failed to revert timestamps of '", p, "', ignoring: ", strerror(e));
        }
    }
    r
}

thread_local! {
    static HARDLINKS_PROTECTED: Cell<i32> = const { Cell::new(-1) };
}

/// `hardlinks_protected()`.
fn hardlinks_protected() -> bool {
    let cached = HARDLINKS_PROTECTED.with(|c| c.get());
    if cached >= 0 {
        return cached > 0;
    }
    let value = match shared::sysctl_util::sysctl_read(b"fs/protected_hardlinks") {
        Ok(v) => v,
        Err(r) => {
            log_debug_errno!(r, "Failed to read fs.protected_hardlinks sysctl, assuming disabled: ", strerror(r));
            return false;
        }
    };
    let cached = match shared::parse::parse_boolean(&value) {
        Ok(b) => b as i32,
        Err(r) => {
            log_debug_errno!(r, "Failed to parse fs.protected_hardlinks sysctl, assuming disabled: ", strerror(r));
            r
        }
    };
    HARDLINKS_PROTECTED.with(|c| c.set(cached));
    cached > 0
}

/// `hardlink_vulnerable()`.
pub fn hardlink_vulnerable(st: &Stat) -> bool {
    shared::stat_util::may_be_hardlinked(st) && !hardlinks_protected()
}

/// `process_mask_perms()`.
fn process_mask_perms(mut mode: u32, current: u32) -> u32 {
    if current & 0o111 == 0 {
        mode &= !0o111;
    }
    if current & 0o222 == 0 {
        mode &= !0o222;
    }
    if current & 0o444 == 0 {
        mode &= !0o444;
    }
    if !s_isdir(current) {
        mode &= !0o7000;
    }
    mode
}

/// `fd_set_perms()`.
pub fn fd_set_perms(_c: &Context, i: &Item, fd: i32, path: &[u8], st: Option<&Stat>, creation: CreationMode) -> i32 {
    if i.mode_set || i.uid_set || i.gid_set {
        let stbuf;
        let st = match st {
            Some(s) => s,
            None => match sys::fstat(fd) {
                Ok(s) => {
                    stbuf = s;
                    &stbuf
                }
                Err(e) => return log_error_errno!(e, "fstat(", path, ") failed: ", strerror(e)),
            },
        };
        if hardlink_vulnerable(st) {
            return log_error_errno!(
                synthetic(libc::EPERM),
                "Refusing to set permissions on hardlinked file ",
                path,
                " while the fs.protected_hardlinks sysctl is turned off."
            );
        }
        let existing = creation == CreationMode::Existing;
        let new_uid = if i.uid_set && (!existing || !i.uid_only_create) { i.uid } else { st.st_uid };
        let new_gid = if i.gid_set && (!existing || !i.gid_only_create) { i.gid } else { st.st_gid };
        let do_chown = new_uid != st.st_uid || new_gid != st.st_gid;
        let new_mode = if i.mode_set && (!existing || !i.mode_only_create) {
            if i.mask_perms { process_mask_perms(i.mode, st.st_mode) } else { i.mode }
        } else {
            st.st_mode & 0o7777
        };
        let do_chmod = (new_mode ^ st.st_mode) & 0o7777 != 0;

        if do_chmod && do_chown {
            if s_islnk(st.st_mode) {
                log_debug!("Skipping temporary mode fix for symlink ", path, ".");
            } else {
                let m = new_mode & st.st_mode;
                if (m ^ st.st_mode) & 0o7777 == 0 {
                    log_debug!("\"", path, "\" matches temporary mode ", format!("{m:o}"), " already.");
                } else {
                    log_action!(
                        "Would temporarily change",
                        "Temporarily changing",
                        " \"",
                        path,
                        "\" to mode ",
                        format!("{m:o}")
                    );
                    if !args().dry_run
                        && let Err(r) = shared::stat_util::fchmod_opath(fd, m)
                    {
                        return log_error_errno!(r, "fchmod() of ", path, " failed: ", strerror(r));
                    }
                }
            }
        }

        if do_chown {
            log_action!(
                "Would change",
                "Changing",
                " \"",
                path,
                "\" to owner ",
                new_uid.to_string(),
                ":",
                new_gid.to_string()
            );
            if !args().dry_run
                && let Err(e) = sys::fchownat(
                    fd,
                    b"",
                    if new_uid != st.st_uid { new_uid } else { u32::MAX },
                    if new_gid != st.st_gid { new_gid } else { u32::MAX },
                    libc::AT_EMPTY_PATH,
                )
            {
                return log_error_errno!(e, "fchownat() of ", path, " failed: ", strerror(e));
            }
        }

        if do_chmod || do_chown {
            if s_islnk(st.st_mode) {
                log_debug!("Skipping mode fix for symlink ", path, ".");
            } else {
                log_action!("Would change", "Changing", " \"", path, "\" to mode ", format!("{new_mode:o}"));
                if !args().dry_run
                    && let Err(r) = shared::stat_util::fchmod_opath(fd, new_mode)
                {
                    return log_error_errno!(r, "fchmod() of ", path, " failed: ", strerror(r));
                }
            }
        }
    }

    // shortcut:
    if args().dry_run {
        log_debug!("Would relabel \"", path, "\"");
        return 0;
    }
    log_debug!("Relabelling \"", path, "\"");
    // label_fix_full(): no SELinux or SMACK labels in this build.
    0
}

/// `path_open_parent_safe()`.
fn path_open_parent_safe(path: &[u8], allow_failure: bool) -> Result<OwnedFd, i32> {
    let lvl = if allow_failure { libc::LOG_INFO } else { libc::LOG_ERR };
    let ign = if allow_failure { ", ignoring" } else { "" };
    if !path_is_normalized(path) {
        return Err(log_full_errno!(
            lvl,
            synthetic(libc::EINVAL),
            "Failed to open parent of '",
            path,
            "': path not normalized",
            ign,
            "."
        ));
    }
    let dn = match path_extract_directory(path) {
        Ok(d) => d,
        Err(r) => {
            return Err(log_full_errno!(
                lvl,
                r,
                "Unable to determine parent directory of '",
                path,
                "'",
                ign,
                ": ",
                strerror(r)
            ));
        }
    };
    let flags = if allow_failure { CHASE_SAFE } else { CHASE_SAFE | CHASE_WARN };
    match chase(&dn, root(), flags, false, true) {
        Ok(c) => Ok(c.fd.expect("requested")),
        Err(r) if r == -libc::ENOLINK => Err(r),
        Err(r) => Err(log_full_errno!(lvl, r, "Failed to open path '", dn, "'", ign, ": ", strerror(r))),
    }
}

/// `path_open_safe()`.
fn path_open_safe(path: &[u8]) -> Result<OwnedFd, i32> {
    if !path_is_normalized(path) {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Failed to open invalid path '", path, "'."));
    }
    match chase(path, root(), CHASE_SAFE | CHASE_WARN | CHASE_NOFOLLOW, false, true) {
        Ok(c) => Ok(c.fd.expect("requested")),
        Err(r) if r == -libc::ENOLINK => Err(r),
        Err(r) => {
            let missing = r == -libc::ENOENT;
            Err(log_full_errno!(
                if missing { libc::LOG_DEBUG } else { libc::LOG_ERR },
                r,
                "Failed to open path ",
                path,
                if missing { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            ))
        }
    }
}

/// An fd-based action (`fdaction_t`).
pub type FdAction = fn(&Context, &Item, i32, &[u8], Option<&Stat>, CreationMode) -> i32;
/// A path-based action (`action_t`).
pub type Action = fn(&Context, &Item, &[u8], CreationMode) -> i32;

/// The `path_set_*()` wrappers: open the path safely, then run the fd action.
fn path_do(c: &Context, i: &Item, path: &[u8], creation: CreationMode, action: FdAction) -> i32 {
    match path_open_safe(path) {
        Err(r) if r == -libc::ENOENT => 0,
        Err(r) => r,
        Ok(fd) => action(c, i, fd.raw(), path, None, creation),
    }
}

fn path_set_perms(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    path_do(c, i, path, creation, fd_set_perms)
}

/// `fd_set_xattrs()`.
fn fd_set_xattrs(_c: &Context, i: &Item, fd: i32, path: &[u8], _st: Option<&Stat>, _cr: CreationMode) -> i32 {
    for (name, value) in &i.xattrs {
        log_action!("Would set", "Setting", " extended attribute '", name, "=", value, "' on ", path);
        if !args().dry_run
            && let Err(r) = shared::xattr::fsetxattr_full(fd, name, value, 0)
        {
            return log_error_errno!(
                r,
                "Failed to set extended attribute ",
                name,
                "=",
                value,
                " on '",
                path,
                "': ",
                strerror(r)
            );
        }
    }
    0
}

fn path_set_xattrs(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    path_do(c, i, path, creation, fd_set_xattrs)
}

/// `path_set_acl()`: 0, a positive errno if already warned, or negative.
fn path_set_acl(path: &[u8], pretty: &[u8], ty: u32, acl: &shared::sys_acl::Acl, modify: bool) -> i32 {
    use shared::sys_acl::{ACL_TYPE_ACCESS, prepare_acl, set_file};
    let (dup, t) = match prepare_acl(path, ty, acl, modify) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let kind = if ty == ACL_TYPE_ACCESS { "access" } else { "default" };
    let t = t.unwrap_or_else(|| b"n/a".to_vec());
    log_action!("Would set", "Setting", " ", kind, " ACL ", t, " on ", pretty);
    if !args().dry_run
        && let Err(r) = set_file(path, ty, &dup)
    {
        if shared::chattr::is_neg_not_supported(r) {
            return r;
        }
        if r == -libc::EINVAL && crate::running_in_chroot() > 0 {
            return log_warning_errno!(
                synthetic(libc::EOPNOTSUPP),
                "Setting ",
                kind,
                " ACL \"",
                t,
                "\" on ",
                pretty,
                " failed. A chroot environment was detected, ignoring."
            );
        }
        return -log_error_errno!(r, "Setting ", kind, " ACL \"", t, "\" on ", pretty, " failed: ", strerror(r));
    }
    0
}

/// `fd_set_acls()`.
fn fd_set_acls(_c: &Context, item: &Item, fd: i32, path: &[u8], st: Option<&Stat>, _cr: CreationMode) -> i32 {
    use shared::sys_acl::{ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT, parse_acl_cond_exec};
    let stbuf;
    let st = match st {
        Some(s) => s,
        None => match sys::fstat(fd) {
            Ok(s) => {
                stbuf = s;
                &stbuf
            }
            Err(e) => return log_error_errno!(e, "fstat(", path, ") failed: ", strerror(e)),
        },
    };
    if hardlink_vulnerable(st) {
        return log_error_errno!(
            synthetic(libc::EPERM),
            "Refusing to set ACLs on hardlinked file ",
            path,
            " while the fs.protected_hardlinks sysctl is turned off."
        );
    }
    if !shared::stat_util::inode_type_can_acl(st.st_mode) {
        log_debug!("Skipping ACL fix for '", path, "' (inode type does not support ACLs).");
        return 0;
    }
    let pfd = proc_fd_path(fd);
    let mut r = 0;
    if let Some(exec) = &item.acl.access_exec {
        let parsed = match parse_acl_cond_exec(
            &pfd,
            s_isdir(st.st_mode),
            exec,
            item.acl.access.as_ref(),
            item.append_or_force,
        ) {
            Ok(p) => p,
            Err(e) => {
                return log_error_errno!(
                    e,
                    "Failed to parse conditionalized execute bit for \"",
                    path,
                    "\": ",
                    strerror(e)
                );
            }
        };
        r = path_set_acl(&pfd, path, ACL_TYPE_ACCESS, &parsed, item.append_or_force);
    } else if let Some(access) = &item.acl.access {
        r = path_set_acl(&pfd, path, ACL_TYPE_ACCESS, access, item.append_or_force);
    }
    if r == 0
        && let Some(def) = &item.acl.default
        && s_isdir(st.st_mode)
    {
        r = path_set_acl(&pfd, path, ACL_TYPE_DEFAULT, def, item.append_or_force);
    }
    if shared::chattr::is_neg_not_supported(r) {
        log_debug_errno!(r, "ACLs not supported by file system at ", path);
        return 0;
    }
    if r > 0 {
        return -r;
    }
    if r < 0 {
        return log_error_errno!(r, "ACL operation on \"", path, "\" failed: ", strerror(r));
    }
    r
}

fn path_set_acls(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    path_do(c, i, path, creation, fd_set_acls)
}

/// `fd_set_caps()`.
fn fd_set_caps(_c: &Context, item: &Item, fd: i32, path: &[u8], _st: Option<&Stat>, _cr: CreationMode) -> i32 {
    if !item.fcaps_set {
        return 0;
    }
    crate::fcaps::apply_fcaps(fd, path, item.append_or_force, &item.fcaps)
}

fn path_set_caps(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    if !i.fcaps_set {
        return 0;
    }
    path_do(c, i, path, creation, fd_set_caps)
}

/// `fd_set_attribute()`.
fn fd_set_attribute(_c: &Context, item: &Item, fd: i32, path: &[u8], st: Option<&Stat>, _cr: CreationMode) -> i32 {
    use shared::chattr::{CHATTR_FALLBACK_BITWISE, FS_DIRSYNC_FL, chattr_fd, is_neg_ioctl_not_supported};
    if !item.attribute_set || item.attribute_mask == 0 {
        return 0;
    }
    let stbuf;
    let st = match st {
        Some(s) => s,
        None => match sys::fstat(fd) {
            Ok(s) => {
                stbuf = s;
                &stbuf
            }
            Err(e) => return log_error_errno!(e, "fstat(", path, ") failed: ", strerror(e)),
        },
    };
    if !s_isreg(st.st_mode) && !s_isdir(st.st_mode) {
        return log_error_errno!(
            synthetic(libc::EINVAL),
            "Setting file flags is only supported on regular files and directories, cannot set on '",
            path,
            "'."
        );
    }
    let mut f = item.attribute_value & item.attribute_mask;
    if !s_isdir(st.st_mode) {
        f &= !FS_DIRSYNC_FL;
    }
    log_action!(
        "Would try to set",
        "Trying to set",
        " file attributes 0x",
        format!("{:08x}", f & item.attribute_mask),
        " on ",
        path
    );
    if !args().dry_run {
        let procfs_fd = match shared::fd::fd_reopen(fd, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOATIME) {
            Ok(fd) => OwnedFd::new(fd),
            Err(r) => return log_error_errno!(r, "Failed to reopen '", path, "': ", strerror(r)),
        };
        let (r, previous, current) = chattr_fd(procfs_fd.raw(), f, item.attribute_mask, CHATTR_FALLBACK_BITWISE);
        if r == -libc::ENOANO {
            log_warning!(
                "Cannot set file attributes for '",
                path,
                "', maybe due to incompatibility in specified attributes, previous=0x",
                format!("{previous:08x}"),
                ", current=0x",
                format!("{current:08x}"),
                ", expected=0x",
                format!("{:08x}", (previous & !item.attribute_mask) | (f & item.attribute_mask)),
                ", ignoring."
            );
        } else if r < 0 {
            log_full_errno!(
                if is_neg_ioctl_not_supported(r) { libc::LOG_DEBUG } else { libc::LOG_WARNING },
                r,
                "Cannot set file attributes for '",
                path,
                "', value=0x",
                format!("{:08x}", item.attribute_value),
                ", mask=0x",
                format!("{:08x}", item.attribute_mask),
                ", ignoring: ",
                strerror(r)
            );
        }
    }
    0
}

fn path_set_attribute(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    if !i.attribute_set || i.attribute_mask == 0 {
        return 0;
    }
    path_do(c, i, path, creation, fd_set_attribute)
}

/// `write_argument_data()`.
fn write_argument_data(i: &Item, fd: i32, path: &[u8]) -> i32 {
    if i.binary_argument_size() == 0 {
        return 0;
    }
    log_action!("Would write", "Writing", " to \"", path, "\"");
    if !args().dry_run
        && let Err(r) = sys::write_all(fd, i.binary_argument().unwrap_or_default())
    {
        return log_error_errno!(r, "Failed to write file \"", path, "\": ", strerror(r));
    }
    0
}

/// `write_one_file()`.
fn write_one_file(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    let bn = match extract_filename(path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                path,
                "' for writing, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", path, "': ", strerror(r)),
    };
    let dir_fd = match path_open_parent_safe(path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    let flags = libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | libc::O_WRONLY
        | libc::O_NOCTTY
        | if i.append_or_force { libc::O_APPEND } else { 0 }
        | if args().dry_run { libc::O_PATH } else { 0 };
    let fd = match openat(dir_fd.raw(), &bn, flags, i.mode) {
        Ok(fd) => fd,
        Err(e) if e == -libc::ENOENT => {
            log_debug_errno!(e, "Not writing missing file \"", path, "\": ", strerror(e));
            return 0;
        }
        Err(e) if i.allow_failure => {
            return log_debug_errno!(e, "Failed to open file \"", path, "\", ignoring: ", strerror(e));
        }
        Err(e) => return log_error_errno!(e, "Failed to open file \"", path, "\": ", strerror(e)),
    };
    let r = write_argument_data(i, fd.raw(), path);
    if r < 0 {
        return r;
    }
    fd_set_perms(c, i, fd.raw(), path, None, creation)
}

/// `create_file()`.
fn create_file(c: &Context, i: &Item, path: &[u8]) -> i32 {
    let bn = match extract_filename(path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                path,
                "' for writing, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", path, "': ", strerror(r)),
    };
    if args().dry_run {
        log_info!("Would create file ", path);
        return 0;
    }
    let dir_fd = match path_open_parent_safe(path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    let created = with_umask(0, || {
        openat(
            dir_fd.raw(),
            &bn,
            libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC
                | libc::O_WRONLY
                | libc::O_NOCTTY,
            i.mode,
        )
    });
    let (fd, st, creation) = match created {
        Err(e) if e != -libc::EEXIST => return log_error_errno!(e, "Failed to create file ", path, ": ", strerror(e)),
        Err(_) => {
            let fd = match openat(dir_fd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, i.mode) {
                Ok(fd) => fd,
                Err(e) => return log_error_errno!(e, "Failed to reopen file ", path, ": ", strerror(e)),
            };
            let st = match sys::fstat(fd.raw()) {
                Ok(st) => st,
                Err(e) => return log_error_errno!(e, "stat(", path, ") failed: ", strerror(e)),
            };
            if !s_isreg(st.st_mode) {
                return log_error_errno!(synthetic(libc::EEXIST), path, " exists and is not a regular file.");
            }
            (fd, Some(st), CreationMode::Existing)
        }
        Ok(fd) => {
            let r = write_argument_data(i, fd.raw(), path);
            if r < 0 {
                return r;
            }
            (fd, None, CreationMode::Normal)
        }
    };
    fd_set_perms(c, i, fd.raw(), path, st.as_ref(), creation)
}

/// `truncate_file()`.
fn truncate_file(c: &Context, i: &Item, path: &[u8]) -> i32 {
    let bn = match extract_filename(path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                path,
                "' for truncation, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", path, "': ", strerror(r)),
    };
    let dir_fd = match path_open_parent_safe(path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    if args().dry_run {
        log_info!("Would truncate ", path);
        return 0;
    }
    let base = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_WRONLY | libc::O_NOCTTY;
    let mut creation = CreationMode::Existing;
    let mut res = openat(dir_fd.raw(), &bn, base, i.mode);
    if res.as_ref().err() == Some(&-libc::ENOENT) {
        creation = CreationMode::Normal;
        res = with_umask(0, || openat(dir_fd.raw(), &bn, libc::O_CREAT | base, i.mode));
    }
    let mut erofs = false;
    let fd = match res {
        Ok(fd) => fd,
        Err(e) if e != -libc::EROFS => {
            return log_error_errno!(e, "Failed to open/create file ", path, ": ", strerror(e));
        }
        Err(_) => match openat(dir_fd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, i.mode) {
            Ok(fd) => {
                erofs = true;
                creation = CreationMode::Existing;
                fd
            }
            Err(e) if e == -libc::ENOENT => {
                return log_error_errno!(
                    synthetic(libc::EROFS),
                    "Cannot create file ",
                    path,
                    " on a read-only file system."
                );
            }
            Err(e) => return log_error_errno!(e, "Failed to reopen file ", path, ": ", strerror(e)),
        },
    };
    let stbuf = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "stat(", path, ") failed: ", strerror(e)),
    };
    if !s_isreg(stbuf.st_mode) {
        return log_error_errno!(synthetic(libc::EEXIST), path, " exists and is not a regular file.");
    }
    let mut st = None;
    if stbuf.st_size > 0 {
        if let Err(e) = sys::ftruncate(fd.raw(), 0) {
            let r = if erofs { -libc::EROFS } else { e };
            return log_error_errno!(r, "Failed to truncate file ", path, ": ", strerror(r));
        }
    } else {
        st = Some(stbuf);
    }
    log_debug!("\"", path, "\" has been created.");
    if i.binary_argument().is_some() {
        let r = write_argument_data(i, fd.raw(), path);
        if r < 0 {
            return r;
        }
    }
    fd_set_perms(c, i, fd.raw(), path, st.as_ref(), creation)
}

/// `copy_files()`.
fn copy_files(c: &Context, i: &Item) -> i32 {
    let src = i.argument.as_deref().unwrap_or_default();
    log_action!("Would copy", "Copying", " tree \"", src, "\" to \"", i.path, "\"");
    if args().dry_run {
        return 0;
    }
    let bn = match shared::path::path_extract_filename(&i.path) {
        Ok(b) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", i.path, "': ", strerror(r)),
    };
    let dfd = match path_open_parent_safe(&i.path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    use shared::copy::{COPY_HARDLINKS, COPY_MAC_CREATE, COPY_MERGE, COPY_MERGE_EMPTY, copy_tree_at};
    let r = copy_tree_at(
        AT_FDCWD,
        src,
        dfd.raw(),
        &bn,
        if i.uid_set { i.uid } else { u32::MAX },
        if i.gid_set { i.gid } else { u32::MAX },
        (if i.append_or_force { COPY_MERGE } else { COPY_MERGE_EMPTY }) | COPY_MAC_CREATE | COPY_HARDLINKS,
    );
    let fd = match openat(dfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if r < 0 {
                return log_error_errno!(r, "Failed to copy files to ", i.path, ": ", strerror(r));
            }
            return log_error_errno!(e, "Failed to openat(", i.path, "): ", strerror(e));
        }
    };
    if r < 0 && r != -libc::EEXIST && r != -libc::EROFS {
        return log_error_errno!(r, "Failed to copy files to ", i.path, ": ", strerror(r));
    }
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
    };
    let a = match sys::fstatat(AT_FDCWD, src, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(a) => a,
        Err(e) => return log_error_errno!(e, "Failed to lstat(", src, "): ", strerror(e)),
    };
    if (st.st_mode ^ a.st_mode) & libc::S_IFMT != 0 {
        log_debug!("Can't copy to ", i.path, ", file exists already and is of different type");
        return 0;
    }
    fd_set_perms(c, i, fd.raw(), &i.path, Some(&st), CreationMode::Invalid)
}

/// `create_directory_or_subvolume()`.
fn create_directory_or_subvolume(
    path: &[u8],
    mode: u32,
    subvol: bool,
    allow_failure: bool,
) -> Result<Option<(OwnedFd, Stat, CreationMode)>, i32> {
    let bn = match shared::path::path_extract_filename(path) {
        Ok(b) => b,
        Err(r) => {
            return Err(log_error_errno!(r, "Failed to extract filename from path '", path, "': ", strerror(r)));
        }
    };
    let pfd = path_open_parent_safe(path, allow_failure)?;
    let mut subvol = subvol;
    let mut r: Result<(), i32> = Ok(());
    if subvol {
        let want = match shared::env::getenv_bool("SYSTEMD_TMPFILES_FORCE_SUBVOL") {
            Ok(b) => b,
            Err(e) => {
                if e != -libc::ENXIO {
                    log_warning_errno!(e, "Cannot parse value of $SYSTEMD_TMPFILES_FORCE_SUBVOL, ignoring.");
                }
                let rt = match root() {
                    Some(r) if !r.is_empty() => r,
                    _ => b"/",
                };
                shared::btrfs::is_subvol_at(AT_FDCWD, Some(rt)).unwrap_or(false)
            }
        };
        if !want {
            subvol = false;
        } else {
            log_action!("Would create", "Creating", " btrfs subvolume ", path);
            if !args().dry_run {
                r = with_umask(!mode & 0o777, || shared::btrfs::subvol_make(pfd.raw(), &bn));
            }
        }
    }
    if !subvol || r.is_err_and(shared::chattr::is_neg_not_supported) {
        log_action!("Would create", "Creating", " directory \"", path, "\"");
        if !args().dry_run {
            r = with_umask(0, || sys::mkdirat(pfd.raw(), &bn, mode));
        }
    }
    if args().dry_run {
        return Ok(None);
    }
    let creation = if r.is_ok() { CreationMode::Normal } else { CreationMode::Existing };
    let fd = match openat(pfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if e == -libc::ENOTDIR {
                return Err(log_error_errno!(
                    synthetic(libc::EEXIST),
                    "\"",
                    path,
                    "\" already exists and is not a directory."
                ));
            }
            if let Err(r) = r {
                return Err(log_full_errno!(
                    if allow_failure { libc::LOG_INFO } else { libc::LOG_ERR },
                    r,
                    "Failed to create directory or subvolume \"",
                    path,
                    "\"",
                    if allow_failure { ", ignoring" } else { "" },
                    ": ",
                    strerror(r)
                ));
            }
            return Err(log_error_errno!(
                e,
                "Failed to open directory/subvolume we just created '",
                path,
                "': ",
                strerror(e)
            ));
        }
    };
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return Err(log_error_errno!(e, "Failed to fstat(", path, "): ", strerror(e))),
    };
    log_debug!(creation_mode_verb(creation), " directory \"", path, "\".");
    Ok(Some((fd, st, creation)))
}

/// `create_directory()`.
fn create_directory(c: &Context, i: &Item, path: &[u8]) -> i32 {
    if args().dry_run {
        log_info!("Would create directory ", path);
        return 0;
    }
    match create_directory_or_subvolume(path, i.mode, false, i.allow_failure) {
        Err(r) if r == -libc::EEXIST => 0,
        Err(r) => r,
        Ok(None) => 0,
        Ok(Some((fd, st, creation))) => fd_set_perms(c, i, fd.raw(), path, Some(&st), creation),
    }
}

/// `create_subvolume()`.
fn create_subvolume(c: &Context, i: &Item, path: &[u8]) -> i32 {
    if args().dry_run {
        log_info!("Would create subvolume ", path);
        return 0;
    }
    let (fd, st, creation) = match create_directory_or_subvolume(path, i.mode, true, i.allow_failure) {
        Err(r) if r == -libc::EEXIST => return 0,
        Err(r) => return r,
        Ok(None) => return 0,
        Ok(Some(x)) => x,
    };
    let mut q = 0;
    if creation == CreationMode::Normal && matches!(i.ty, CREATE_SUBVOLUME_NEW_QUOTA | CREATE_SUBVOLUME_INHERIT_QUOTA) {
        match shared::btrfs::subvol_auto_qgroup_fd(fd.raw(), 0, i.ty == CREATE_SUBVOLUME_NEW_QUOTA) {
            Err(r) if r == -libc::ENOTTY => {
                log_debug_errno!(
                    r,
                    "Couldn't adjust quota for subvolume \"",
                    i.path,
                    "\" (unsupported fs or dir not a subvolume): ",
                    strerror(r)
                );
            }
            Err(r) if r == -libc::EROFS => {
                log_debug_errno!(r, "Couldn't adjust quota for subvolume \"", i.path, "\" (fs is read-only).");
            }
            Err(r) if r == -libc::ENOTCONN => {
                log_debug_errno!(
                    r,
                    "Couldn't adjust quota for subvolume \"",
                    i.path,
                    "\" (quota support is disabled)."
                );
            }
            Err(r) => {
                q = log_error_errno!(r, "Failed to adjust quota for subvolume \"", i.path, "\": ", strerror(r));
            }
            Ok(true) => {
                log_debug!("Adjusted quota for subvolume \"", i.path, "\".");
            }
            Ok(false) => {
                log_debug!("Quota for subvolume \"", i.path, "\" already in place, no change made.");
            }
        }
    }
    let r = fd_set_perms(c, i, fd.raw(), path, Some(&st), creation);
    if q < 0 { q } else { r }
}

/// `empty_directory()`.
fn empty_directory(c: &Context, i: &Item, path: &[u8], creation: CreationMode) -> i32 {
    let fd = match chase(path, root(), CHASE_SAFE | CHASE_WARN, false, true) {
        Err(r) if r == -libc::ENOLINK => return r,
        Err(r) if r == -libc::ENOENT => {
            log_debug_errno!(r, "Skipping missing directory: ", path);
            return 0;
        }
        Err(r) => return log_error_errno!(r, "Failed to open directory '", path, "': ", strerror(r)),
        Ok(ch) => ch.fd.expect("requested"),
    };
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", path, "): ", strerror(e)),
    };
    if !s_isdir(st.st_mode) {
        log_warning!("'", path, "' already exists and is not a directory.");
        return 0;
    }
    fd_set_perms(c, i, fd.raw(), path, Some(&st), creation)
}

/// `create_device()`.
fn create_device(c: &Context, i: &Item, file_type: u32) -> i32 {
    let bn = match extract_filename(&i.path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                i.path,
                "' for creating device node, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", i.path, "': ", strerror(r)),
    };
    if args().dry_run {
        log_info!("Would create device node ", i.path);
        return 0;
    }
    let dfd = match path_open_parent_safe(&i.path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    let handle_privilege = |r: i32| -> i32 {
        log_debug_errno!(
            r,
            "We lack permissions, possibly because of cgroup configuration; skipping creation of device node '",
            i.path,
            "'."
        );
        0
    };
    let r = with_umask(0, || sys::mknodat(dfd.raw(), &bn, i.mode | file_type, i.major_minor));
    let mut creation = if r.is_ok() { CreationMode::Normal } else { CreationMode::Existing };
    let mut fd = match openat(dfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if let Err(r) = r {
                if is_privilege(-r) {
                    return handle_privilege(r);
                }
                return log_error_errno!(r, "Failed to create device node '", i.path, "': ", strerror(r));
            }
            return log_error_errno!(e, "Failed to open device node '", i.path, "' we just created: ", strerror(e));
        }
    };
    let mut st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
    };
    if (st.st_mode ^ file_type) & libc::S_IFMT != 0 {
        if !i.append_or_force {
            log_warning!("\"", i.path, "\" already exists and is not a device node.");
            return 0;
        }
        drop(fd);
        let mut r = with_umask(0, || shared::fs::mknodat_atomic(dfd.raw(), &bn, i.mode | file_type, i.major_minor));
        if let Err(e) = r
            && is_privilege(-e)
        {
            return handle_privilege(e);
        }
        if let Err(e) = r
            && [-libc::EISDIR, -libc::EEXIST, -libc::ENOTEMPTY].contains(&e)
        {
            if let Err(e) = shared::rm_rf::rm_rf_child(dfd.raw(), &bn, REMOVE_PHYSICAL) {
                return log_error_errno!(e, "rm -rf ", i.path, " failed: ", strerror(e));
            }
            r = sys::mknodat(dfd.raw(), &bn, i.mode | file_type, i.major_minor);
        }
        if let Err(e) = r {
            return log_error_errno!(e, "Failed to create device node '", i.path, "': ", strerror(e));
        }
        fd = match openat(dfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
            Ok(fd) => fd,
            Err(e) => {
                return log_error_errno!(e, "Failed to open device node we just created '", i.path, "': ", strerror(e));
            }
        };
        st = match sys::fstat(fd.raw()) {
            Ok(st) => st,
            Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
        };
        if (st.st_mode ^ file_type) & libc::S_IFMT != 0 {
            return log_error_errno!(
                synthetic(libc::EBADF),
                "Device node we just created is not a device node, refusing."
            );
        }
        creation = CreationMode::Force;
    }
    log_debug!(
        creation_mode_verb(creation),
        " ",
        if i.ty == CREATE_BLOCK_DEVICE { "block" } else { "char" },
        " device node \"",
        i.path,
        "\" ",
        libc::major(i.major_minor).to_string(),
        ":",
        libc::minor(i.major_minor).to_string(),
        "."
    );
    fd_set_perms(c, i, fd.raw(), &i.path, Some(&st), creation)
}

/// `create_fifo()`.
fn create_fifo(c: &Context, i: &Item) -> i32 {
    let bn = match extract_filename(&i.path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                i.path,
                "' for creating FIFO, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", i.path, "': ", strerror(r)),
    };
    if args().dry_run {
        log_info!("Would create fifo ", i.path);
        return 0;
    }
    let pfd = match path_open_parent_safe(&i.path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    let r = with_umask(0, || sys::mkfifoat(pfd.raw(), &bn, i.mode));
    let mut creation = if r.is_ok() { CreationMode::Normal } else { CreationMode::Existing };
    let mut fd = match openat(pfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if let Err(r) = r {
                return log_error_errno!(r, "Failed to create FIFO ", i.path, ": ", strerror(r));
            }
            return log_error_errno!(e, "Failed to open FIFO we just created ", i.path, ": ", strerror(e));
        }
    };
    let mut st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        if !i.append_or_force {
            log_warning!("\"", i.path, "\" already exists and is not a FIFO.");
            return 0;
        }
        drop(fd);
        let mut r = with_umask(0, || shared::fs::mkfifoat_atomic(pfd.raw(), &bn, i.mode));
        if let Err(e) = r
            && [-libc::EISDIR, -libc::EEXIST, -libc::ENOTEMPTY].contains(&e)
        {
            if let Err(e) = shared::rm_rf::rm_rf_child(pfd.raw(), &bn, REMOVE_PHYSICAL) {
                return log_error_errno!(e, "rm -rf ", i.path, " failed: ", strerror(e));
            }
            r = sys::mkfifoat(pfd.raw(), &bn, i.mode);
        }
        if let Err(e) = r {
            return log_error_errno!(e, "Failed to create FIFO ", i.path, ": ", strerror(e));
        }
        fd = match openat(pfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
            Ok(fd) => fd,
            Err(e) => return log_error_errno!(e, "Failed to open FIFO we just created '", i.path, "': ", strerror(e)),
        };
        st = match sys::fstat(fd.raw()) {
            Ok(st) => st,
            Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
        };
        if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return log_error_errno!(synthetic(libc::EBADF), "FIFO inode we just created is not a FIFO, refusing.");
        }
        creation = CreationMode::Force;
    }
    log_debug!(creation_mode_verb(creation), " fifo \"", i.path, "\".");
    fd_set_perms(c, i, fd.raw(), &i.path, Some(&st), creation)
}

/// `create_symlink()`.
fn create_symlink(c: &Context, i: &Item) -> i32 {
    let arg = i.argument.as_deref().unwrap_or_default();
    if i.ignore_if_target_missing {
        let mut flags = CHASE_SAFE | CHASE_NOFOLLOW;
        let target = if !path_is_absolute(arg) {
            match path_extract_directory(&i.path) {
                Ok(dn) => path_join(&[&dn, arg]),
                Err(r) => {
                    return log_error_errno!(r, "Failed to extract directory from path '", i.path, "': ", strerror(r));
                }
            }
        } else {
            flags |= CHASE_PREFIX_ROOT;
            arg.to_vec()
        };
        match chase(&target, root(), flags, false, false) {
            Err(r) if r == -libc::ENOENT => {
                log_debug_errno!(r, "Symlink source path '", arg, "' does not exist, skipping line.");
                return 0;
            }
            Err(r) => {
                return log_error_errno!(r, "Failed to check if symlink source path '", arg, "' exists: ", strerror(r));
            }
            Ok(_) => {}
        }
    }
    let bn = match extract_filename(&i.path) {
        Ok((_, true)) => {
            return log_error_errno!(
                synthetic(libc::EISDIR),
                "Cannot open path '",
                i.path,
                "' for creating symlink, is a directory."
            );
        }
        Ok((b, false)) => b,
        Err(r) => return log_error_errno!(r, "Failed to extract filename from path '", i.path, "': ", strerror(r)),
    };
    if args().dry_run {
        log_info!("Would create symlink ", i.path, " -> ", arg);
        return 0;
    }
    let pfd = match path_open_parent_safe(&i.path, i.allow_failure) {
        Ok(fd) => fd,
        Err(r) => return r,
    };
    let r = sys::symlinkat(arg, pfd.raw(), &bn);
    let mut creation = if r.is_ok() { CreationMode::Normal } else { CreationMode::Existing };
    let mut fd = match openat(pfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if let Err(r) = r {
                return log_error_errno!(r, "Failed to create symlink '", i.path, "': ", strerror(r));
            }
            return log_error_errno!(e, "Failed to open symlink we just created '", i.path, "': ", strerror(e));
        }
    };
    let mut st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
    };
    let good = if s_islnk(st.st_mode) {
        match sys::readlinkat(fd.raw(), b"") {
            Ok(x) => x == arg,
            Err(r) => return log_error_errno!(r, "readlinkat(", i.path, ") failed: ", strerror(r)),
        }
    } else {
        false
    };
    if !good {
        if !i.append_or_force {
            log_debug!("\"", i.path, "\" is not a symlink or does not point to the correct path.");
            return 0;
        }
        drop(fd);
        let mut r = shared::fs::symlinkat_atomic(arg, pfd.raw(), &bn);
        if let Err(e) = r
            && [-libc::EISDIR, -libc::EEXIST, -libc::ENOTEMPTY].contains(&e)
        {
            if let Err(e) = shared::rm_rf::rm_rf_child(pfd.raw(), &bn, REMOVE_PHYSICAL) {
                return log_error_errno!(e, "rm -rf ", i.path, " failed: ", strerror(e));
            }
            r = shared::fs::symlinkat_atomic(arg, pfd.raw(), &bn);
        }
        if let Err(e) = r {
            return log_error_errno!(e, "symlink(", arg, ", ", i.path, ") failed: ", strerror(e));
        }
        fd = match openat(pfd.raw(), &bn, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
            Ok(fd) => fd,
            Err(e) => {
                return log_error_errno!(e, "Failed to open symlink we just created '", i.path, "': ", strerror(e));
            }
        };
        st = match sys::fstat(fd.raw()) {
            Ok(st) => st,
            Err(e) => return log_error_errno!(e, "Failed to fstat(", i.path, "): ", strerror(e)),
        };
        if !s_islnk(st.st_mode) {
            return log_error_errno!(synthetic(libc::EBADF), "Symlink we just created is not a symlink, refusing.");
        }
        creation = CreationMode::Force;
    }
    log_debug!(creation_mode_verb(creation), " symlink \"", i.path, "\".");
    fd_set_perms(c, i, fd.raw(), &i.path, Some(&st), creation)
}

/// `item_do()`: run action on fd, and recursively on everything below it.
fn item_do(c: &Context, i: &Item, fd: OwnedFd, path: &[u8], creation: CreationMode, action: FdAction) -> i32 {
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "fstat() on file failed: ", strerror(e)),
    };
    let mut r = action(c, i, fd.raw(), path, Some(&st), creation);
    if s_isdir(st.st_mode) {
        let pfd = proc_fd_path(fd.raw());
        let mut d = match sys::open(&pfd, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)
            .and_then(Dir::from_fd)
        {
            Ok(d) => d,
            Err(e) => {
                ret_gather(&mut r, log_error_errno!(e, "Failed to opendir() '", pfd, "': ", strerror(e)));
                return r;
            }
        };
        loop {
            let name = match d.next_entry() {
                Ok(Some((n, _))) => n,
                Ok(None) => break,
                Err(e) => {
                    ret_gather(&mut r, e);
                    return r;
                }
            };
            if dot_or_dot_dot(&name) {
                continue;
            }
            let de_fd = match openat(fd.raw(), &name, libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_PATH, 0) {
                Ok(f) => f,
                Err(e) => {
                    if e != -libc::ENOENT {
                        ret_gather(&mut r, log_error_errno!(e, "Failed to open file '", name, "': ", strerror(e)));
                    }
                    continue;
                }
            };
            let de_path = path_join(&[path, &name]);
            ret_gather(&mut r, item_do(c, i, de_fd, &de_path, CreationMode::Existing, action));
        }
    }
    r
}

/// `safe_glob_full(i->path, GLOB_NOSORT|GLOB_BRACE, opendir_nomod, &paths)`.
fn glob_paths(i: &Item) -> Result<Vec<Vec<u8>>, i32> {
    match shared::glob::safe_glob_full(&i.path, libc::GLOB_NOSORT | libc::GLOB_BRACE, Some(opendir_nomod)) {
        Err(r) if r == -libc::ENOENT => Ok(Vec::new()),
        Err(r) => Err(log_error_errno!(r, "Failed to glob '", i.path, "': ", strerror(r))),
        Ok(p) => Ok(p),
    }
}

/// `glob_item()`.
fn glob_item(c: &Context, i: &Item, action: Action) -> i32 {
    let paths = match glob_paths(i) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut r = 0;
    for p in &paths {
        // Globbed paths always exist, hence CREATION_EXISTING.
        ret_gather(&mut r, action(c, i, p, CreationMode::Existing));
    }
    r
}

/// `glob_item_recursively()`.
fn glob_item_recursively(c: &Context, i: &Item, action: FdAction) -> i32 {
    let paths = match glob_paths(i) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut r = 0;
    for p in &paths {
        match path_open_safe(p) {
            Err(e) => ret_gather(&mut r, e),
            Ok(fd) => ret_gather(&mut r, item_do(c, i, fd, p, CreationMode::Existing, action)),
        }
    }
    r
}

/// `rm_if_wrong_type_safe(mode, parent_fd, parent_st, name, flags)`.
fn rm_if_wrong_type_safe(mode: u32, parent_fd: i32, parent_st: Option<&Stat>, name: &[u8], flags: i32) -> i32 {
    use shared::rm_rf::{fstatat_harder, rm_rf_children, unlinkat_harder};
    let follow_links = flags & libc::AT_SYMLINK_NOFOLLOW == 0;
    if mode == 0 {
        return 0;
    }
    if !filename_is_valid(name) {
        return log_error_errno!(synthetic(libc::EINVAL), "\"", name, "\" is not a valid filename.");
    }
    let pname = || fd_get_path(parent_fd).unwrap_or_else(|_| b"...".to_vec());
    let mut st = match fstatat_harder(parent_fd, name, flags, REMOVE_CHMOD | REMOVE_CHMOD_RESTORE) {
        Ok(st) => st,
        Err(r) => {
            return log_full_errno!(
                if r == -libc::ENOENT { libc::LOG_DEBUG } else { libc::LOG_ERR },
                r,
                "Failed to stat \"",
                pname(),
                "/",
                name,
                "\": ",
                strerror(r)
            );
        }
    };
    // stat_unsafe_transition(): never from unprivileged to privileged.
    if follow_links
        && let Some(ps) = parent_st
        && ps.st_uid != 0
        && ps.st_uid != st.st_uid
    {
        return log_error_errno!(
            synthetic(libc::ENOLINK),
            "Unsafe transition from \"",
            pname(),
            "\" to \"",
            name,
            "\"."
        );
    }
    if st.st_mode & libc::S_IFMT == mode {
        return 0;
    }
    let parent_name = pname();
    log_notice!(
        "Wrong file type 0o",
        format!("{:o}", st.st_mode & libc::S_IFMT),
        "; rm -rf \"",
        parent_name,
        "/",
        name,
        "\""
    );
    if follow_links {
        st = match fstatat_harder(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW, REMOVE_CHMOD | REMOVE_CHMOD_RESTORE) {
            Ok(st) => st,
            Err(r) => return log_error_errno!(r, "Failed to stat \"", parent_name, "/", name, "\": ", strerror(r)),
        };
    }
    match shared::stat_util::is_mount_point_at(
        parent_fd,
        Some(name),
        if follow_links { libc::AT_SYMLINK_FOLLOW } else { 0 },
    ) {
        Err(r) => {
            log_warning_errno!(
                r,
                "Failed to check if  \"",
                parent_name,
                "/",
                name,
                "\" is a mount point: ",
                strerror(r),
                "; continuing."
            );
        }
        Ok(true) => {
            return log_error_errno!(
                synthetic(libc::EBUSY),
                "Not removing  \"",
                parent_name,
                "/",
                name,
                "\" because it is a mount point."
            );
        }
        Ok(false) => {}
    }
    log_action!("Would remove", "Removing", " ", parent_name, "/", name);
    if !args().dry_run {
        let r = if s_isdir(st.st_mode) {
            let child_fd = match openat(parent_fd, name, libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY, 0) {
                Ok(fd) => fd,
                Err(e) => return log_error_errno!(e, "Failed to open \"", parent_name, "/", name, "\": ", strerror(e)),
            };
            if let Err(r) = rm_rf_children(child_fd, REMOVE_ROOT | REMOVE_SUBVOLUME | REMOVE_PHYSICAL, Some(&st)) {
                return log_error_errno!(
                    r,
                    "Failed to remove contents of \"",
                    parent_name,
                    "/",
                    name,
                    "\": ",
                    strerror(r)
                );
            }
            unlinkat_harder(parent_fd, name, libc::AT_REMOVEDIR, REMOVE_CHMOD | REMOVE_CHMOD_RESTORE)
        } else {
            unlinkat_harder(parent_fd, name, 0, REMOVE_CHMOD | REMOVE_CHMOD_RESTORE)
        };
        if let Err(r) = r {
            return log_error_errno!(r, "Failed to remove \"", parent_name, "/", name, "\": ", strerror(r));
        }
    }
    // Covered by the "Wrong file type" notice above.
    -libc::ENOENT
}

/// `mkdir_parents_rm_if_wrong_type(child_mode, path)`.
fn mkdir_parents_rm_if_wrong_type(child_mode: u32, path: &[u8]) -> i32 {
    if !is_path(path) {
        return rm_if_wrong_type_safe(child_mode, AT_FDCWD, None, path, libc::AT_SYMLINK_NOFOLLOW);
    }
    if child_mode != 0 && path.ends_with(b"/") {
        return log_error_errno!(
            synthetic(libc::EINVAL),
            "Trailing path separators are only allowed if child_mode is not set; got \"",
            path,
            "\""
        );
    }
    let mut parent_fd = match openat(
        AT_FDCWD,
        if path_is_absolute(path) { b"/" } else { b"." },
        libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY,
        0,
    ) {
        Ok(fd) => fd,
        Err(e) => return log_error_errno!(e, "Failed to open root: ", strerror(e)),
    };
    let mut parent_st = match sys::fstat(parent_fd.raw()) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to stat root: ", strerror(e)),
    };
    let mut e = 0usize;
    loop {
        let s = e + path[e..].iter().take_while(|&&b| b == b'/').count();
        e = s + path[s..].iter().take_while(|&&b| b != b'/').count();
        let t = &path[s..e];
        if e == path.len() {
            return rm_if_wrong_type_safe(child_mode, parent_fd.raw(), Some(&parent_st), t, libc::AT_SYMLINK_NOFOLLOW);
        }
        let mut r = rm_if_wrong_type_safe(libc::S_IFDIR, parent_fd.raw(), Some(&parent_st), t, 0);
        if r == -libc::ENOENT {
            r = rm_if_wrong_type_safe(libc::S_IFDIR, parent_fd.raw(), Some(&parent_st), t, libc::AT_SYMLINK_NOFOLLOW);
        }
        if r == -libc::ENOENT {
            if !args().dry_run
                && let Err(r) = with_umask(0, || sys::mkdirat(parent_fd.raw(), t, 0o755))
            {
                let pn = fd_get_path(parent_fd.raw()).ok();
                return log_error_errno!(
                    r,
                    "Failed to mkdir \"",
                    t,
                    "\" at \"",
                    shared::string::strnull(pn.as_deref()),
                    "\": ",
                    strerror(r)
                );
            }
        } else if r < 0 {
            return r;
        }
        let next_fd = match openat(parent_fd.raw(), t, libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY, 0) {
            Ok(fd) => fd,
            Err(r) => {
                let pn = fd_get_path(parent_fd.raw()).ok();
                return log_error_errno!(
                    r,
                    "Failed to open \"",
                    t,
                    "\" at \"",
                    shared::string::strnull(pn.as_deref()),
                    "\": ",
                    strerror(r)
                );
            }
        };
        parent_st = match sys::fstat(next_fd.raw()) {
            Ok(st) => st,
            Err(r) => {
                let pn = fd_get_path(parent_fd.raw()).ok();
                return log_error_errno!(
                    r,
                    "Failed to stat \"",
                    t,
                    "\" at \"",
                    shared::string::strnull(pn.as_deref()),
                    "\": ",
                    strerror(r)
                );
            }
        };
        parent_fd = next_fd;
    }
}

/// `mkdir_parents_item()`.
fn mkdir_parents_item(i: &Item, child_mode: u32) -> i32 {
    if i.try_replace {
        let r = mkdir_parents_rm_if_wrong_type(child_mode, &i.path);
        if r < 0 && r != -libc::ENOENT {
            return r;
        }
    } else if !args().dry_run {
        let _ = with_umask(0, || shared::fs::mkdirat_parents(AT_FDCWD, &i.path, 0o755));
    }
    0
}

/// `create_item()`.
fn create_item(c: &Context, i: &Item) -> i32 {
    log_debug!("Running create action for entry ", [i.ty], " ", i.path);
    macro_rules! try_r {
        ($e:expr) => {{
            let r = $e;
            if r < 0 {
                return r;
            }
        }};
    }
    match i.ty {
        IGNORE_PATH | IGNORE_DIRECTORY_PATH | REMOVE_PATH | RECURSIVE_REMOVE_PATH => return 0,
        TRUNCATE_FILE | CREATE_FILE => {
            try_r!(mkdir_parents_item(i, libc::S_IFREG));
            if (i.ty == CREATE_FILE && i.append_or_force) || i.ty == TRUNCATE_FILE {
                try_r!(truncate_file(c, i, &i.path));
            } else {
                try_r!(create_file(c, i, &i.path));
            }
        }
        COPY_FILES => {
            try_r!(mkdir_parents_item(i, 0));
            try_r!(copy_files(c, i));
        }
        WRITE_FILE => try_r!(glob_item(c, i, write_one_file)),
        CREATE_DIRECTORY | TRUNCATE_DIRECTORY => {
            try_r!(mkdir_parents_item(i, libc::S_IFDIR));
            try_r!(create_directory(c, i, &i.path));
        }
        CREATE_SUBVOLUME | CREATE_SUBVOLUME_INHERIT_QUOTA | CREATE_SUBVOLUME_NEW_QUOTA => {
            try_r!(mkdir_parents_item(i, libc::S_IFDIR));
            try_r!(create_subvolume(c, i, &i.path));
        }
        EMPTY_DIRECTORY => try_r!(glob_item(c, i, empty_directory)),
        CREATE_FIFO => {
            try_r!(mkdir_parents_item(i, libc::S_IFIFO));
            try_r!(create_fifo(c, i));
        }
        CREATE_SYMLINK => {
            try_r!(mkdir_parents_item(i, libc::S_IFLNK));
            try_r!(create_symlink(c, i));
        }
        CREATE_BLOCK_DEVICE | CREATE_CHAR_DEVICE => {
            const CAP_MKNOD: u32 = 27;
            if sys::have_effective_cap(CAP_MKNOD) != Ok(true) {
                log_debug!("We lack CAP_MKNOD, skipping creation of device node ", i.path, ".");
                return 0;
            }
            let ft = if i.ty == CREATE_BLOCK_DEVICE { libc::S_IFBLK } else { libc::S_IFCHR };
            try_r!(mkdir_parents_item(i, ft));
            try_r!(create_device(c, i, ft));
        }
        ADJUST_MODE | RELABEL_PATH => try_r!(glob_item(c, i, path_set_perms)),
        RECURSIVE_RELABEL_PATH => try_r!(glob_item_recursively(c, i, fd_set_perms)),
        SET_XATTR => try_r!(glob_item(c, i, path_set_xattrs)),
        RECURSIVE_SET_XATTR => try_r!(glob_item_recursively(c, i, fd_set_xattrs)),
        SET_ACL => try_r!(glob_item(c, i, path_set_acls)),
        RECURSIVE_SET_ACL => try_r!(glob_item_recursively(c, i, fd_set_acls)),
        SET_FCAPS => try_r!(glob_item(c, i, path_set_caps)),
        RECURSIVE_SET_FCAPS => try_r!(glob_item_recursively(c, i, fd_set_caps)),
        SET_ATTRIBUTE => try_r!(glob_item(c, i, path_set_attribute)),
        RECURSIVE_SET_ATTRIBUTE => try_r!(glob_item_recursively(c, i, fd_set_attribute)),
        _ => {}
    }
    0
}

/// `remove_recursive()`.
fn remove_recursive(c: &Context, i: &Item, instance: &[u8], remove_instance: bool) -> i32 {
    let (mut d, sx, mountpoint) = match opendir_and_stat(instance) {
        Err(r) => return r,
        Ok(None) => {
            if remove_instance {
                log_action!("Would remove", "Removing", " file \"", instance, "\".");
                if !args().dry_run
                    && let Err(e) = sys::remove(instance)
                    && e != -libc::ENOENT
                {
                    return log_error_errno!(e, "rm ", instance, ": ", strerror(e));
                }
            }
            return 0;
        }
        Ok(Some(x)) => x,
    };
    let _ = sx;
    let r = dir_cleanup(
        c,
        i,
        instance,
        &mut d,
        NSEC_INFINITY,
        NSEC_INFINITY,
        NSEC_INFINITY,
        mountpoint,
        MAX_DEPTH,
        false,
        0,
        0,
    );
    if r < 0 {
        return r;
    }
    if remove_instance {
        log_action!("Would remove", "Removing", " directory \"", instance, "\".");
        if !args().dry_run
            && let Err(r) = sys::rmdir(instance)
        {
            let fatal = r != -libc::ENOENT && r != -libc::ENOTEMPTY;
            log_full_errno!(
                if fatal { libc::LOG_ERR } else { libc::LOG_DEBUG },
                r,
                "Failed to remove ",
                instance,
                ": ",
                strerror(r)
            );
            if fatal {
                return r;
            }
        }
    }
    0
}

fn purge_item_instance(c: &Context, i: &Item, instance: &[u8], _cr: CreationMode) -> i32 {
    remove_recursive(c, i, instance, true)
}

/// `purge_item()`.
fn purge_item(c: &Context, i: &Item) -> i32 {
    if !needs_purge(i.ty) || !i.purge {
        return 0;
    }
    log_debug!("Running purge action for entry ", [i.ty], " ", i.path);
    if needs_glob(i.ty) {
        return glob_item(c, i, purge_item_instance);
    }
    purge_item_instance(c, i, &i.path, CreationMode::Existing)
}

/// `remove_item_instance()`.
fn remove_item_instance(c: &Context, i: &Item, instance: &[u8], _cr: CreationMode) -> i32 {
    match i.ty {
        REMOVE_PATH => {
            log_action!("Would remove", "Removing", " \"", instance, "\".");
            if !args().dry_run
                && let Err(e) = sys::remove(instance)
                && e != -libc::ENOENT
            {
                return log_error_errno!(e, "rm ", instance, ": ", strerror(e));
            }
            0
        }
        RECURSIVE_REMOVE_PATH => remove_recursive(c, i, instance, true),
        _ => unreachable!(),
    }
}

/// `item_instance_needs_cleanup()`.
fn item_instance_needs_cleanup(i: &Item, instance: &[u8], sx: &libc::statx) -> bool {
    if !i.age_set {
        return false;
    }
    let n = sys::now_realtime_usec();
    if n < i.age {
        return false;
    }
    let cutoff = n - i.age;
    let (atime, mtime, ctime, btime) = statx_times(sx);
    let is_dir = s_isdir(sx.stx_mode as u32);
    needs_cleanup(
        atime,
        btime,
        ctime,
        mtime,
        cutoff.wrapping_mul(NSEC_PER_USEC),
        instance,
        if is_dir { i.age_by_dir } else { i.age_by_file },
        is_dir,
    )
}

/// `item_instance_open_parent()`: (parent fd, name, must be a directory).
fn item_instance_open_parent(i: &Item, instance: &[u8]) -> Result<(OwnedFd, Vec<u8>, bool), i32> {
    let (name, must_be_dir) = match extract_filename(instance) {
        Ok(x) => x,
        Err(r) => {
            return Err(log_error_errno!(r, "Failed to extract filename from path '", instance, "': ", strerror(r)));
        }
    };
    let parent_fd = path_open_parent_safe(instance, i.allow_failure)?;
    Ok((parent_fd, name, must_be_dir))
}

/// `item_instance_open_opath()`: Ok(None) if it is gone.
fn item_instance_open_opath(
    parent_fd: i32,
    name: &[u8],
    instance: &[u8],
) -> Result<Option<(OwnedFd, libc::statx)>, i32> {
    let fd = match openat(parent_fd, name, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0) {
        Err(e) if e == -libc::ENOENT || e == -libc::ENOTDIR => return Ok(None),
        Err(e) => return Err(log_error_errno!(e, "Failed to open \"", instance, "\": ", strerror(e))),
        Ok(fd) => fd,
    };
    let sx = match xstatx_full(
        fd.raw(),
        None,
        libc::AT_EMPTY_PATH,
        libc::STATX_TYPE | libc::STATX_MODE,
        libc::STATX_ATIME | libc::STATX_MTIME | libc::STATX_CTIME | libc::STATX_BTIME,
        0,
    ) {
        Ok(sx) => sx,
        Err(r) => return Err(log_error_errno!(r, "statx(", instance, ") failed: ", strerror(r))),
    };
    Ok(Some((fd, sx)))
}

/// `item_instance_still_current()`.
fn item_instance_still_current(fd: i32, parent_fd: i32, name: &[u8], instance: &[u8]) -> bool {
    match shared::stat_util::inode_same_at(
        fd,
        None,
        parent_fd,
        Some(name),
        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
    ) {
        Err(r) if r == -libc::ENOENT || r == -libc::ENOTDIR => false,
        Err(r) => {
            log_debug_errno!(
                r,
                "Failed to verify that \"",
                instance,
                "\" still refers to the same inode, skipping: ",
                strerror(r)
            );
            false
        }
        Ok(false) => {
            log_debug!("Skipping \"", instance, "\": inode changed.");
            false
        }
        Ok(true) => true,
    }
}

/// `item_instance_fd_still_current()`.
fn item_instance_fd_still_current(fd: i32, other_fd: i32, instance: &[u8]) -> bool {
    match shared::stat_util::fd_inode_same(fd, other_fd) {
        Err(r) => {
            log_debug_errno!(
                r,
                "Failed to verify that \"",
                instance,
                "\" still refers to the same inode, skipping: ",
                strerror(r)
            );
            false
        }
        Ok(false) => {
            log_debug!("Skipping \"", instance, "\": inode changed.");
            false
        }
        Ok(true) => true,
    }
}

/// `item_instance_open_directory_and_lock()`: Ok(None) to skip.
fn item_instance_open_directory_and_lock(
    parent_fd: i32,
    name: &[u8],
    fd: i32,
    instance: &[u8],
) -> Result<Option<Dir>, i32> {
    let d = match xopendirat_nomod(parent_fd, name) {
        Ok(d) => d,
        Err(e) if [-libc::ENOENT, -libc::ENOTDIR, -libc::ELOOP].contains(&e) => return Ok(None),
        Err(e) => return Err(log_error_errno!(e, "Failed to open directory \"", instance, "\": ", strerror(e))),
    };
    if !item_instance_fd_still_current(fd, d.fd(), instance) {
        return Ok(None);
    }
    if !args().dry_run
        && let Err(e) = sys::flock(d.fd(), libc::LOCK_EX | libc::LOCK_NB)
    {
        log_debug_errno!(
            e,
            "Couldn't acquire exclusive BSD lock on directory \"",
            instance,
            "\", skipping: ",
            strerror(e)
        );
        return Ok(None);
    }
    Ok(Some(d))
}

/// `item_instance_remove_empty_directory()`.
fn item_instance_remove_empty_directory(parent_fd: i32, name: &[u8], instance: &[u8]) -> i32 {
    if args().dry_run {
        return 0;
    }
    if let Err(r) = sys::unlinkat(parent_fd, name, libc::AT_REMOVEDIR) {
        let fatal = ![-libc::ENOENT, -libc::ENOTEMPTY, -libc::EBUSY].contains(&r);
        log_full_errno!(
            if fatal { libc::LOG_ERR } else { libc::LOG_DEBUG },
            r,
            "Failed to remove ",
            instance,
            ": ",
            strerror(r)
        );
        if fatal {
            return r;
        }
    }
    0
}

/// `item_instance_remove_directory_if_empty()`.
fn item_instance_remove_directory_if_empty(
    parent_fd: i32,
    name: &[u8],
    d: &Dir,
    instance: &[u8],
    assume_empty: bool,
) -> i32 {
    if !assume_empty {
        match shared::stat_util::dir_is_empty_at(d.fd(), None, false) {
            Err(r) if r == -libc::ENOENT || r == -libc::ENOTDIR => return 0,
            Err(r) => {
                return log_error_errno!(r, "Failed to determine whether \"", instance, "\" is empty: ", strerror(r));
            }
            Ok(false) => return 0,
            Ok(true) => {}
        }
    }
    if !item_instance_still_current(d.fd(), parent_fd, name, instance) {
        return 0;
    }
    log_action!("Would remove", "Removing", " directory \"", instance, "\".");
    let r = item_instance_remove_empty_directory(parent_fd, name, instance);
    if r < 0 {
        return r;
    }
    0
}

/// `clean_remove_item_instance_at()`.
fn clean_remove_item_instance_at(
    i: &Item,
    parent_fd: i32,
    name: &[u8],
    fd: i32,
    instance: &[u8],
    sx: &libc::statx,
    must_be_directory: bool,
) -> i32 {
    if must_be_directory && !s_isdir(sx.stx_mode as u32) {
        return log_error_errno!(synthetic(libc::ENOTDIR), "\"", instance, "\" is not a directory.");
    }
    if !item_instance_needs_cleanup(i, instance, sx) {
        return 0;
    }
    if s_isdir(sx.stx_mode as u32) {
        return match item_instance_open_directory_and_lock(parent_fd, name, fd, instance) {
            Err(r) => r,
            Ok(None) => 0,
            Ok(Some(d)) => item_instance_remove_directory_if_empty(parent_fd, name, &d, instance, false),
        };
    }
    let mut _lock: Option<OwnedFd> = None;
    if !args().dry_run {
        match openat(
            parent_fd,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        ) {
            Err(e) => {
                if e != -libc::ENOENT && e != -libc::ELOOP {
                    log_warning_errno!(
                        e,
                        "Opening file \"",
                        instance,
                        "\" failed, proceeding without lock: ",
                        strerror(e)
                    );
                }
            }
            Ok(lock_fd) => {
                if !item_instance_fd_still_current(fd, lock_fd.raw(), instance) {
                    return 0;
                }
                if let Err(e) = sys::flock(lock_fd.raw(), libc::LOCK_EX | libc::LOCK_NB)
                    && e == -libc::EAGAIN
                {
                    log_debug_errno!(
                        e,
                        "Couldn't acquire shared BSD lock on file \"",
                        instance,
                        "\", skipping: ",
                        strerror(e)
                    );
                    return 0;
                }
                _lock = Some(lock_fd);
            }
        }
        if !item_instance_still_current(fd, parent_fd, name, instance) {
            return 0;
        }
    }
    if i.ty == RECURSIVE_REMOVE_PATH {
        log_action!("Would remove", "Removing", " file \"", instance, "\".");
    } else {
        log_action!("Would remove", "Removing", " \"", instance, "\".");
    }
    if !args().dry_run
        && let Err(e) = sys::unlinkat(parent_fd, name, 0)
        && e != -libc::ENOENT
    {
        log_warning_errno!(e, "Failed to remove \"", instance, "\", ignoring: ", strerror(e));
    }
    0
}

/// `clean_remove_item_instance()`.
fn clean_remove_item_instance(_c: &Context, i: &Item, instance: &[u8], _cr: CreationMode) -> i32 {
    if !i.age_set {
        return 0;
    }
    let (parent_fd, name, must_be_dir) = match item_instance_open_parent(i, instance) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match item_instance_open_opath(parent_fd.raw(), &name, instance) {
        Err(r) => r,
        Ok(None) => 0,
        Ok(Some((fd, sx))) => {
            clean_remove_item_instance_at(i, parent_fd.raw(), &name, fd.raw(), instance, &sx, must_be_dir)
        }
    }
}

/// `remove_item()`.
fn remove_item(c: &Context, i: &Item) -> i32 {
    log_debug!("Running remove action for entry ", [i.ty], " ", i.path);
    match i.ty {
        TRUNCATE_DIRECTORY => remove_recursive(c, i, &i.path, false),
        REMOVE_PATH | RECURSIVE_REMOVE_PATH => glob_item(c, i, remove_item_instance),
        _ => 0,
    }
}

/// `age_by_to_string()`.
fn age_by_to_string(ab: u32, is_dir: bool) -> Vec<u8> {
    let map = *b"abcm";
    (0..4).filter(|&k| ab & (1 << k) != 0).map(|k| if is_dir { map[k].to_ascii_uppercase() } else { map[k] }).collect()
}

/// `clean_item_instance_from_dir()`.
fn clean_item_instance_from_dir(
    c: &Context,
    i: &Item,
    instance: &[u8],
    d: &mut Dir,
    sx: &libc::statx,
    mountpoint: bool,
) -> i32 {
    if !i.age_set {
        return 0;
    }
    let n = sys::now_realtime_usec();
    if n < i.age {
        return 0;
    }
    let cutoff = n - i.age;
    let (atime_nsec, mtime_nsec, _, _) = statx_times(sx);
    if shared::log::enabled(libc::LOG_DEBUG) {
        log_debug!(
            "Cleanup threshold for ",
            if mountpoint { "mount point" } else { "directory" },
            " \"",
            instance,
            "\" is ",
            format_timestamp_style(cutoff, TimestampStyle::Us).unwrap_or_else(|| b"(null)".to_vec()),
            "; age-by: ",
            age_by_to_string(i.age_by_file, false),
            age_by_to_string(i.age_by_dir, true)
        );
    }
    dir_cleanup(
        c,
        i,
        instance,
        d,
        atime_nsec,
        mtime_nsec,
        cutoff.wrapping_mul(NSEC_PER_USEC),
        mountpoint,
        MAX_DEPTH,
        i.keep_first_level,
        i.age_by_file,
        i.age_by_dir,
    )
}

/// `clean_item_instance()`.
fn clean_item_instance(c: &Context, i: &Item, instance: &[u8], _cr: CreationMode) -> i32 {
    match opendir_and_stat(instance) {
        Err(r) => r,
        Ok(None) => 0,
        Ok(Some((mut d, sx, mountpoint))) => clean_item_instance_from_dir(c, i, instance, &mut d, &sx, mountpoint),
    }
}

/// `clean_recursive_remove_item_instance()`.
fn clean_recursive_remove_item_instance(c: &Context, i: &Item, instance: &[u8], _cr: CreationMode) -> i32 {
    if !i.age_set {
        return 0;
    }
    let (parent_fd, name, must_be_dir) = match item_instance_open_parent(i, instance) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (fd, sx) = match item_instance_open_opath(parent_fd.raw(), &name, instance) {
        Err(r) => return r,
        Ok(None) => return 0,
        Ok(Some(x)) => x,
    };
    if !s_isdir(sx.stx_mode as u32) {
        return clean_remove_item_instance_at(i, parent_fd.raw(), &name, fd.raw(), instance, &sx, must_be_dir);
    }
    let mut d = match item_instance_open_directory_and_lock(parent_fd.raw(), &name, fd.raw(), instance) {
        Err(r) => return r,
        Ok(None) => return 0,
        Ok(Some(d)) => d,
    };
    let dir_sx = match xstatx_full(
        d.fd(),
        None,
        libc::AT_EMPTY_PATH,
        libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_INO,
        libc::STATX_ATIME | libc::STATX_MTIME | libc::STATX_CTIME | libc::STATX_BTIME,
        libc::STATX_ATTR_MOUNT_ROOT as u64,
    ) {
        Ok(sx) => sx,
        Err(r) => return log_error_errno!(r, "statx(", instance, ") failed: ", strerror(r)),
    };
    let cleanup_needed = item_instance_needs_cleanup(i, instance, &dir_sx);
    let mp = dir_sx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0;
    let r = clean_item_instance_from_dir(c, i, instance, &mut d, &dir_sx, mp);
    if r < 0 {
        return r;
    }
    if i.keep_first_level || !cleanup_needed {
        return 0;
    }
    item_instance_remove_directory_if_empty(parent_fd.raw(), &name, &d, instance, args().dry_run)
}

/// `clean_item()`.
fn clean_item(c: &Context, i: &Item) -> i32 {
    log_debug!("Running clean action for entry ", [i.ty], " ", i.path);
    match i.ty {
        CREATE_DIRECTORY
        | TRUNCATE_DIRECTORY
        | CREATE_SUBVOLUME
        | CREATE_SUBVOLUME_INHERIT_QUOTA
        | CREATE_SUBVOLUME_NEW_QUOTA
        | COPY_FILES => clean_item_instance(c, i, &i.path, CreationMode::Existing),
        EMPTY_DIRECTORY | IGNORE_PATH | IGNORE_DIRECTORY_PATH => glob_item(c, i, clean_item_instance),
        REMOVE_PATH => glob_item(c, i, clean_remove_item_instance),
        RECURSIVE_REMOVE_PATH => glob_item(c, i, clean_recursive_remove_item_instance),
        _ => 0,
    }
}

/// `process_item()`.
fn process_item(c: &Context, i: &Item, operation: u32) -> i32 {
    let todo = operation & !i.done.get();
    if todo == 0 {
        return 0;
    }
    i.done.set(i.done.get() | operation);

    let mut path = i.path.clone();
    if shared::string::string_is_glob(&path) {
        // Only the non-glob part can be checked for autofs.
        match shared::glob::glob_non_glob_prefix(&path) {
            Ok(p) => path = p,
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return log_debug_errno!(r, "Failed to deglob path: ", strerror(r)),
        }
    }
    match chase(&path, root(), CHASE_NO_AUTOFS | CHASE_NONEXISTENT | CHASE_WARN, false, false) {
        Err(r) if r == -libc::EREMOTE => {
            log_notice_errno!(r, "Skipping ", i.path);
            return 0;
        }
        Err(r) => {
            log_debug_errno!(r, "Failed to determine whether '", i.path, "' is below autofs, ignoring: ", strerror(r));
        }
        Ok(_) => {}
    }

    let mut r = if operation & OPERATION_CREATE != 0 { create_item(c, i) } else { 0 };
    // Failure can only be tolerated for create.
    if i.allow_failure {
        r = 0;
    }
    ret_gather(&mut r, if operation & OPERATION_REMOVE != 0 { remove_item(c, i) } else { 0 });
    ret_gather(&mut r, if operation & OPERATION_CLEAN != 0 { clean_item(c, i) } else { 0 });
    ret_gather(&mut r, if operation & OPERATION_PURGE != 0 { purge_item(c, i) } else { 0 });
    r
}

/// `process_item_array()`.
pub fn process_item_array(c: &Context, a: usize, operation: u32) -> i32 {
    let array = &c.arrays[a];
    let mut r = 0;
    // Create any parent first.
    if operation & OPERATION_CREATE != 0
        && let Some(p) = array.parent
    {
        r = process_item_array(c, p, operation & OPERATION_CREATE);
    }
    // Clean up all children first.
    let rcp = OPERATION_REMOVE | OPERATION_CLEAN | OPERATION_PURGE;
    if operation & rcp != 0 {
        for &child in &array.children {
            ret_gather(&mut r, process_item_array(c, child, operation & rcp));
        }
    }
    for item in &array.items {
        ret_gather(&mut r, process_item(c, item, operation));
    }
    r
}
