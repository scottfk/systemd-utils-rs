// SPDX-License-Identifier: LGPL-2.1-or-later
//! `conf-files.c`: list configuration files across the /etc, /run,
//! /usr/local/lib, /usr/lib hierarchy, with overriding and masking, and
//! `conf_file_read()` for flat line-based formats.

use std::collections::{BTreeMap, BTreeSet};

use crate::chase::{
    CHASE_MUST_BE_DIRECTORY, CHASE_NONEXISTENT, chase_and_opendirat, chaseat, chaseat_prefix_root,
    empty_or_root_harder_to_null, mode_verify_directory, mode_verify_regular,
};
use crate::errno::{ret_gather, strerror, synthetic};
use crate::fd::{XAT_FDROOT, fd_get_path};
use crate::fileio::{CReader, LONG_LINE_MAX, read_stripped_line, search_and_fopen};
use crate::locale::{Glyph, glyph};
use crate::path::{
    empty_or_root, is_path, path_equal, path_extract_directory, path_extract_filename, path_join,
    path_make_absolute_cwd, path_simplify, skip_leading_slash,
};
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_debug_errno, log_error_errno, log_full_errno};

pub const CONF_FILES_EXECUTABLE: u32 = 1 << 0;
pub const CONF_FILES_REGULAR: u32 = 1 << 1;
pub const CONF_FILES_DIRECTORY: u32 = 1 << 2;
pub const CONF_FILES_BASENAME: u32 = 1 << 3;
pub const CONF_FILES_FILTER_MASKED_BY_SYMLINK: u32 = 1 << 4;
pub const CONF_FILES_FILTER_MASKED_BY_EMPTY: u32 = 1 << 5;
pub const CONF_FILES_FILTER_MASKED: u32 = CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_FILTER_MASKED_BY_EMPTY;
pub const CONF_FILES_TRUNCATE_SUFFIX: u32 = 1 << 6;
pub const CONF_FILES_WARN: u32 = 1 << 7;
pub const CONF_FILES_DONT_PREFIX_ROOT: u32 = 1 << 8;

/// `CONF_PATHS_STRV(n)`.
pub fn conf_paths(n: &str) -> Vec<Vec<u8>> {
    ["/etc/", "/run/", "/usr/local/lib/", "/usr/lib/"].iter().map(|p| format!("{p}{n}").into_bytes()).collect()
}

/// `ConfFile`.
#[derive(Debug)]
pub struct ConfFile {
    pub filename: Vec<u8>,
    pub result: Vec<u8>,
    pub original_path: Vec<u8>,
    pub resolved_path: Vec<u8>,
    pub fd: OwnedFd,
    pub st: sys::Stat,
}

fn log_level(flags: u32) -> i32 {
    if flags & CONF_FILES_WARN != 0 { libc::LOG_WARNING } else { libc::LOG_DEBUG }
}

fn root_str(root: Option<&[u8]>) -> &[u8] {
    match root {
        Some(r) if !r.is_empty() => r,
        _ => b"/",
    }
}

/// `prepare_dirs()`: (absolute root or None, root fd, absolute dirs).
fn prepare_dirs(
    root: Option<&[u8]>,
    flags: u32,
    dirs: Option<&[Vec<u8>]>,
) -> Result<(Option<Vec<u8>>, OwnedFd, Vec<Vec<u8>>), i32> {
    let lvl = log_level(flags);
    let root = empty_or_root_harder_to_null(root).map_err(|r| {
        log_full_errno!(
            lvl,
            r,
            "Failed to determine if '",
            root.unwrap_or_default(),
            "' points to the root directory: ",
            strerror(r)
        )
    })?;
    let mut dirs_abs: Vec<Vec<u8>> = dirs.map(|d| d.to_vec()).unwrap_or_default();
    let mut rfd = OwnedFd::new(XAT_FDROOT);
    let mut root_abs = None;
    if let Some(root) = root {
        let ra = path_make_absolute_cwd(root)
            .map_err(|r| log_full_errno!(lvl, r, "Failed to make '", root, "' absolute: ", strerror(r)))?;
        let ra = path_simplify(&ra);
        match sys::open(root, libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0) {
            Ok(fd) => rfd = OwnedFd::new(fd),
            Err(e) => return Err(log_full_errno!(lvl, e, "Failed to open '", ra, "': ", strerror(e))),
        }
        root_abs = Some(ra);
    } else if dirs.is_some() {
        for d in dirs_abs.iter_mut() {
            let a = path_make_absolute_cwd(d)
                .map_err(|r| log_full_errno!(lvl, r, "Failed to make directories absolute: ", strerror(r)))?;
            *d = path_simplify(&a);
        }
    }
    Ok((root_abs, rfd, dirs_abs))
}

/// `conf_file_prefix_root()`.
fn conf_file_prefix_root(c: &mut ConfFile, root: Option<&[u8]>, flags: u32) -> Result<(), i32> {
    if flags & CONF_FILES_DONT_PREFIX_ROOT != 0 {
        return Ok(());
    }
    let lvl = log_level(flags);
    c.result = chaseat_prefix_root(&c.result, root).map_err(|r| {
        log_full_errno!(
            lvl,
            r,
            "Failed to prefix '",
            c.result,
            "' with root '",
            root.unwrap_or(b"(null)"),
            "': ",
            strerror(r)
        )
    })?;
    c.resolved_path = chaseat_prefix_root(&c.resolved_path, root).map_err(|r| {
        log_full_errno!(
            lvl,
            r,
            "Failed to prefix '",
            c.resolved_path,
            "' with root '",
            root.unwrap_or(b"(null)"),
            "': ",
            strerror(r)
        )
    })?;
    c.original_path = path_simplify(&path_join(&[root_str(root), skip_leading_slash(&c.original_path)]));
    Ok(())
}

fn need_stat(flags: u32) -> bool {
    flags & (CONF_FILES_FILTER_MASKED | CONF_FILES_REGULAR | CONF_FILES_DIRECTORY | CONF_FILES_EXECUTABLE) != 0
}

fn chase_flags(flags: u32) -> u32 {
    if !need_stat(flags) || flags & CONF_FILES_FILTER_MASKED_BY_SYMLINK != 0 { CHASE_NONEXISTENT } else { 0 }
}

/// `conf_file_chase_and_verify()`: (resolved path, fd, stat).
fn chase_and_verify(
    root: Option<&[u8]>,
    rfd: i32,
    original_path: &[u8],
    path: &[u8],
    name: &[u8],
    masked: Option<&mut BTreeSet<Vec<u8>>>,
    flags: u32,
) -> Result<(Vec<u8>, OwnedFd, sys::Stat), i32> {
    let lvl = log_level(flags);
    let root = root_str(root);
    let op = skip_leading_slash(original_path);
    let c = chaseat(rfd, rfd, path, chase_flags(flags), true, true)
        .map_err(|r| log_full_errno!(lvl, r, "Failed to chase '", root, op, "': ", strerror(r)))?;
    let resolved = c.path.expect("requested");
    if !c.exists {
        if flags & CONF_FILES_FILTER_MASKED_BY_SYMLINK != 0 && path_equal(skip_leading_slash(&resolved), b"dev/null") {
            if let Some(m) = masked {
                m.insert(name.to_vec());
            }
            return Err(log_debug_errno!(
                synthetic(libc::ERFKILL),
                "File '",
                root,
                op,
                "' is a mask (symlink to /dev/null)."
            ));
        }
        if need_stat(flags) {
            let e = synthetic(libc::ENOENT);
            return Err(log_full_errno!(lvl, e, "Failed to chase '", root, op, "': ", strerror(e)));
        }
    }
    let fd = c.fd.unwrap_or_else(|| OwnedFd::new(-1));
    let st = if fd.raw() >= 0 {
        sys::fstat(fd.raw()).map_err(|e| log_full_errno!(lvl, e, "Failed to stat '", root, op, "': ", strerror(e)))?
    } else {
        sys::stat_zero()
    };
    let fmt = st.st_mode & libc::S_IFMT;
    if flags & CONF_FILES_FILTER_MASKED_BY_SYMLINK != 0 && fmt == libc::S_IFCHR {
        if let Some(m) = masked {
            m.insert(name.to_vec());
        }
        return Err(log_debug_errno!(
            synthetic(libc::ERFKILL),
            "File '",
            root,
            op,
            "' is a mask (symlink to /dev/null)."
        ));
    }
    if flags & CONF_FILES_FILTER_MASKED_BY_EMPTY != 0 && fmt == libc::S_IFREG && st.st_size <= 0 {
        if let Some(m) = masked {
            m.insert(name.to_vec());
        }
        return Err(log_debug_errno!(synthetic(libc::ERFKILL), "File '", root, op, "' is a mask (an empty file)."));
    }
    if flags & CONF_FILES_REGULAR != 0 && flags & CONF_FILES_DIRECTORY != 0 {
        if fmt != libc::S_IFREG && fmt != libc::S_IFDIR {
            return Err(log_debug_errno!(
                synthetic(libc::EBADFD),
                "File '",
                root,
                op,
                "' is neither a regular file or directory."
            ));
        }
    } else {
        if flags & CONF_FILES_REGULAR != 0
            && let Err(r) = mode_verify_regular(st.st_mode)
        {
            return Err(log_debug_errno!(r, "File '", root, op, "' is not a regular file: ", strerror(r)));
        }
        if flags & CONF_FILES_DIRECTORY != 0
            && let Err(r) = mode_verify_directory(st.st_mode)
        {
            return Err(log_debug_errno!(r, "File '", root, op, "' is not a directory: ", strerror(r)));
        }
    }
    if flags & CONF_FILES_EXECUTABLE != 0 && st.st_mode & 0o111 == 0 {
        return Err(log_debug_errno!(synthetic(libc::ENOEXEC), "File '", root, op, "' is not marked executable."));
    }
    Ok((resolved, fd, st))
}

/// `conf_file_new_at()`.
fn conf_file_new_at(path: &[u8], root: Option<&[u8]>, rfd: i32, flags: u32) -> Result<ConfFile, i32> {
    let lvl = log_level(flags);
    let debug_root;
    let root = if crate::log::debug_logging() && root.is_none() {
        debug_root = fd_get_path(rfd).ok();
        debug_root.as_deref()
    } else {
        root
    };
    let filename = path_extract_filename(path)
        .map_err(|r| log_full_errno!(lvl, r, "Failed to extract filename from '", path, "': ", strerror(r)))?;
    let resolved_dir = match path_extract_directory(path) {
        Ok(dirpath) => {
            let c = chaseat(rfd, rfd, &dirpath, CHASE_MUST_BE_DIRECTORY | chase_flags(flags), true, false).map_err(
                |r| {
                    log_full_errno!(
                        lvl,
                        r,
                        "Failed to chase '",
                        root_str(root),
                        skip_leading_slash(&dirpath),
                        "': ",
                        strerror(r)
                    )
                },
            )?;
            c.path
        }
        Err(r) if r == -libc::EDESTADDRREQ => None,
        Err(r) => return Err(log_full_errno!(lvl, r, "Failed to extract directory from '", path, "': ", strerror(r))),
    };
    let result = path_join(&[resolved_dir.as_deref().unwrap_or_default(), &filename]);
    let (resolved_path, fd, st) = chase_and_verify(root, rfd, path, &result, &filename, None, flags)?;
    Ok(ConfFile { filename, result, original_path: path.to_vec(), resolved_path, fd, st })
}

/// `conf_file_new(path, root, flags)`.
pub fn conf_file_new(path: &[u8], root: Option<&[u8]>, flags: u32) -> Result<ConfFile, i32> {
    let (root_abs, rfd, _) = prepare_dirs(root, flags, None)?;
    let path_abs;
    let path = if root_abs.is_none() {
        path_abs = path_make_absolute_cwd(path)
            .map_err(|r| log_full_errno!(log_level(flags), r, "Failed to make '", path, "' absolute: ", strerror(r)))?;
        &path_abs[..]
    } else {
        path
    };
    let mut c = conf_file_new_at(path, root_abs.as_deref(), rfd.raw(), flags)?;
    conf_file_prefix_root(&mut c, root_abs.as_deref(), flags)?;
    Ok(c)
}

/// `hidden_or_backup_file()`.
pub fn hidden_or_backup_file(f: &[u8]) -> bool {
    if f.first() == Some(&b'.')
        || f == b"lost+found"
        || f == b"aquota.user"
        || f == b"aquota.group"
        || f.ends_with(b"~")
    {
        return true;
    }
    let Some(dot) = f.iter().rposition(|&b| b == b'.') else {
        return false;
    };
    const SUFFIXES: &[&[u8]] = &[
        b"ignore",
        b"rpmnew",
        b"rpmsave",
        b"rpmorig",
        b"dpkg-old",
        b"dpkg-new",
        b"dpkg-tmp",
        b"dpkg-dist",
        b"dpkg-bak",
        b"dpkg-backup",
        b"dpkg-remove",
        b"ucf-new",
        b"ucf-old",
        b"ucf-dist",
        b"swp",
        b"bak",
        b"old",
        b"new",
    ];
    SUFFIXES.contains(&&f[dot + 1..])
}

/// `readdir_ensure_type()` + the `FOREACH_DIRENT()` hidden-file filter.
pub fn foreach_dirent(dir: &mut sys::Dir) -> Result<Option<(Vec<u8>, u8)>, i32> {
    loop {
        let Some((name, mut ty)) = dir.next_entry()? else {
            return Ok(None);
        };
        if ty == libc::DT_UNKNOWN {
            match sys::fstatat(dir.fd(), &name, libc::AT_SYMLINK_NOFOLLOW) {
                Ok(st) => ty = mode_to_dt(st.st_mode),
                Err(e) if e == -libc::ENOENT => continue,
                Err(e) => return Err(e),
            }
        }
        if hidden_or_backup_file(&name) {
            continue;
        }
        return Ok(Some((name, ty)));
    }
}

/// `readdir_ensure_type()` (`FOREACH_DIRENT_ALL()`): every entry, "." and
/// ".." included.
pub fn foreach_dirent_all(dir: &mut sys::Dir) -> Result<Option<(Vec<u8>, u8)>, i32> {
    loop {
        let Some((name, mut ty)) = dir.next_entry()? else {
            return Ok(None);
        };
        if ty == libc::DT_UNKNOWN {
            match sys::fstatat(dir.fd(), &name, libc::AT_SYMLINK_NOFOLLOW) {
                Ok(st) => ty = mode_to_dt(st.st_mode),
                Err(e) if e == -libc::ENOENT => continue,
                Err(e) => return Err(e),
            }
        }
        return Ok(Some((name, ty)));
    }
}

/// `IFTODT()`.
pub fn mode_to_dt(m: u32) -> u8 {
    ((m & libc::S_IFMT) >> 12) as u8
}

/// `files_add()`.
fn files_add(
    dir: &mut sys::Dir,
    original_dirpath: &[u8],
    resolved_dirpath: &[u8],
    root: Option<&[u8]>,
    rfd: i32,
    files: &mut BTreeMap<Vec<u8>, ConfFile>,
    masked: &mut BTreeSet<Vec<u8>>,
    suffix: Option<&[u8]>,
    flags: u32,
) -> Result<(), i32> {
    let lvl = log_level(flags);
    let rs = root_str(root);
    loop {
        let entry = match foreach_dirent(dir) {
            Ok(e) => e,
            Err(e) => {
                return Err(log_full_errno!(
                    lvl,
                    e,
                    "Failed to read directory '",
                    rs,
                    skip_leading_slash(original_dirpath),
                    "': ",
                    strerror(e)
                ));
            }
        };
        let Some((name, _)) = entry else { break };
        let original_path = path_join(&[original_dirpath, &name]);
        if let Some(sfx) = suffix
            && !name.ends_with(sfx)
        {
            log_debug!("Skipping file '", rs, skip_leading_slash(&original_path), "', suffix is not '", sfx, "'.");
            continue;
        }
        if files.contains_key(&name) {
            log_debug!("Skipping overridden file '", rs, skip_leading_slash(&original_path), "'.");
            continue;
        }
        if flags & CONF_FILES_FILTER_MASKED != 0 && masked.contains(&name) {
            log_debug!("File '", rs, skip_leading_slash(&original_path), "' is masked by previous entry.");
            continue;
        }
        let p = path_join(&[resolved_dirpath, &name]);
        let Ok((resolved_path, fd, st)) = chase_and_verify(root, rfd, &original_path, &p, &name, Some(masked), flags)
        else {
            continue;
        };
        files.insert(name.clone(), ConfFile { filename: name, result: p, original_path, resolved_path, fd, st });
    }
    Ok(())
}

/// `conf_files_list_impl()` without a replacement.
fn conf_files_list_impl(
    suffix: Option<&[u8]>,
    root: Option<&[u8]>,
    rfd: i32,
    flags: u32,
    dirs: &[Vec<u8>],
) -> Result<BTreeMap<Vec<u8>, ConfFile>, i32> {
    let mut fh = BTreeMap::new();
    let mut masked = BTreeSet::new();
    let rs = root_str(root);
    for p in dirs {
        let (path, mut dir) = match chase_and_opendirat(rfd, rfd, p, 0, true) {
            Ok(x) => x,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_full_errno!(
                        log_level(flags),
                        r,
                        "Failed to chase and open directory '",
                        rs,
                        skip_leading_slash(p),
                        "', ignoring: ",
                        strerror(r)
                    );
                }
                continue;
            }
        };
        files_add(&mut dir, p, &path.expect("requested"), root, rfd, &mut fh, &mut masked, suffix, flags)?;
    }
    Ok(fh)
}

/// `copy_and_sort_files_from_hashmap()`.
fn copy_and_sort(
    fh: BTreeMap<Vec<u8>, ConfFile>,
    suffix: Option<&[u8]>,
    root: Option<&[u8]>,
    flags: u32,
) -> Result<Vec<Vec<u8>>, i32> {
    let lvl = log_level(flags);
    let mut results = Vec::new();
    for c in fh.into_values() {
        let add: Vec<u8> = if flags & CONF_FILES_BASENAME != 0 {
            c.filename.clone()
        } else if !empty_or_root(root) && flags & CONF_FILES_DONT_PREFIX_ROOT == 0 {
            let mut p = chaseat_prefix_root(&c.result, root).map_err(|r| {
                log_full_errno!(
                    lvl,
                    r,
                    "Failed to prefix '",
                    c.result,
                    "' with root '",
                    root.unwrap_or_default(),
                    "': ",
                    strerror(r)
                )
            })?;
            if flags & CONF_FILES_TRUNCATE_SUFFIX != 0
                && let Some(sfx) = suffix
            {
                if !p.ends_with(sfx) {
                    continue;
                }
                p.truncate(p.len() - sfx.len());
            }
            results.push(p);
            continue;
        } else {
            c.result.clone()
        };
        if flags & CONF_FILES_TRUNCATE_SUFFIX != 0 {
            let sfx = suffix.unwrap_or_default();
            if !add.ends_with(sfx) {
                continue;
            }
            results.push(add[..add.len() - sfx.len()].to_vec());
        } else {
            results.push(add);
        }
    }
    Ok(results)
}

/// `conf_files_list_strv(&ret, suffix, root, flags, dirs)`.
pub fn conf_files_list_strv(
    suffix: Option<&[u8]>,
    root: Option<&[u8]>,
    flags: u32,
    dirs: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, i32> {
    let (root_abs, rfd, dirs_abs) = prepare_dirs(root, flags, Some(dirs))?;
    let fh = conf_files_list_impl(suffix, root_abs.as_deref(), rfd.raw(), flags, &dirs_abs)?;
    copy_and_sort(fh, suffix, Some(root_str(root_abs.as_deref())), flags)
}

/// `conf_files_list_strv_full(suffix, root, flags, dirs, &files, &n)`.
pub fn conf_files_list_strv_full(
    suffix: Option<&[u8]>,
    root: Option<&[u8]>,
    flags: u32,
    dirs: &[Vec<u8>],
) -> Result<Vec<ConfFile>, i32> {
    let (root_abs, rfd, dirs_abs) = prepare_dirs(root, flags, Some(dirs))?;
    let fh = conf_files_list_impl(suffix, root_abs.as_deref(), rfd.raw(), flags, &dirs_abs)?;
    let root = root_str(root_abs.as_deref()).to_vec();
    let mut out = Vec::new();
    for mut c in fh.into_values() {
        if !root.is_empty() {
            conf_file_prefix_root(&mut c, Some(&root), flags)?;
        }
        out.push(c);
    }
    Ok(out)
}

/// `conf_file_read(root, config_dirs, fn, parse_line, userdata, ignore_enoent, invalid_config)`.
///
/// `parse_line(fname, line_no, line, &invalid_line)` returns C's int.
/// Returns 0 if the file was skipped, 1 or the first parse error otherwise.
/// A failed line that set `invalid_line` sets `invalid_config` instead of
/// becoming the result.
pub fn conf_file_read(
    root: Option<&[u8]>,
    config_dirs: &[Vec<u8>],
    path: &[u8],
    parse_line: &mut dyn FnMut(&[u8], u32, &[u8], &mut bool) -> i32,
    ignore_enoent: bool,
    mut invalid_config: Option<&mut bool>,
) -> i32 {
    let ellipsis = glyph(Glyph::Ellipsis);
    let opened: Result<(CReader, Vec<u8>), (i32, Vec<u8>)> = if path == b"-" {
        log_debug!("Reading config from stdin", ellipsis);
        Ok((CReader::stdin(), b"<stdin>".to_vec()))
    } else if is_path(path) {
        let abs = match path_make_absolute_cwd(path) {
            Ok(a) => a,
            Err(r) => return log_error_errno!(r, "Failed to make path absolute: ", strerror(r)),
        };
        match crate::fileio::fopen_re(&abs) {
            Ok(f) => {
                log_debug!("Reading config file \"", abs, "\"", ellipsis);
                Ok((f, abs))
            }
            Err(e) => Err((e, abs)),
        }
    } else {
        match search_and_fopen(path, "re", root, config_dirs) {
            Ok((f, p)) => {
                log_debug!("Reading config file \"", p, "\"", ellipsis);
                Ok((f, p))
            }
            Err(e) => Err((e, path.to_vec())),
        }
    };
    let (mut f, fname) = match opened {
        Ok(x) => x,
        Err((e, fname)) => {
            if e == -libc::ENOENT && ignore_enoent {
                log_debug_errno!(e, "Failed to open \"", fname, "\", ignoring: ", strerror(e));
                return 0;
            }
            return log_error_errno!(e, "Failed to read '", fname, "': ", strerror(e));
        }
    };
    let mut r = 1;
    let mut v = 0u32;
    loop {
        let line = match read_stripped_line(&mut f, LONG_LINE_MAX) {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(k) => return log_error_errno!(k, "Failed to read '", fname, "': ", strerror(k)),
        };
        v += 1;
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let mut invalid_line = false;
        let k = parse_line(&fname, v, &line, &mut invalid_line);
        match invalid_config.as_deref_mut() {
            Some(ic) if k < 0 && invalid_line => *ic = true,
            _ => ret_gather(&mut r, k),
        }
    }
    if f.has_error() {
        ret_gather(&mut r, log_error_errno!(synthetic(libc::EIO), "Failed to read from file ", fname, "."));
    }
    r
}

/// `conf_files_list_with_replacement(root, config_dirs, replacement, &files, &inserted)`.
pub fn conf_files_list_with_replacement(
    root: Option<&[u8]>,
    config_dirs: &[Vec<u8>],
    replacement: Option<&[u8]>,
) -> Result<(Vec<Vec<u8>>, Option<Vec<u8>>), i32> {
    let flags = CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_WARN;
    let (root_abs, rfd, dirs_abs) = prepare_dirs(root, flags, Some(config_dirs))?;
    let root_l = root_abs.as_deref();
    let rs = root_str(root_l).to_vec();
    let mut c = match replacement {
        Some(rep) => Some(conf_file_new_at(rep, Some(&rs), rfd.raw(), flags & CONF_FILES_WARN)?),
        None => None,
    };
    let mut fh = BTreeMap::new();
    let mut masked = BTreeSet::new();
    let mut inserted: Option<Vec<u8>> = None;
    let insert = |fh: &mut BTreeMap<Vec<u8>, ConfFile>, c: ConfFile, inserted: &mut Option<Vec<u8>>| {
        if let Some(existing) = fh.get(&c.filename) {
            log_debug!(
                "An entry with higher priority '",
                existing.filename,
                "' -> '",
                existing.result,
                "' already exists, ignoring the replacement: ",
                c.original_path
            );
            *inserted = None;
            return;
        }
        log_debug!("Inserted replacement: '", c.filename, "' -> '", c.result, "'");
        *inserted = Some(c.result.clone());
        fh.insert(c.filename.clone(), c);
    };
    for p in &dirs_abs {
        let (path, mut dir) = match chase_and_opendirat(rfd.raw(), rfd.raw(), p, 0, true) {
            Ok(x) => x,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_full_errno!(
                        log_level(flags),
                        r,
                        "Failed to chase and open directory '",
                        rs,
                        skip_leading_slash(p),
                        "', ignoring: ",
                        strerror(r)
                    );
                }
                continue;
            }
        };
        let path = path.expect("requested");
        if let Some(cf) = &c
            && crate::path::path_startswith(&cf.result, &path) == Some(&cf.filename[..])
        {
            let cf = c.take().expect("checked");
            insert(&mut fh, cf, &mut inserted);
        }
        files_add(&mut dir, p, &path, Some(&rs), rfd.raw(), &mut fh, &mut masked, Some(b".conf"), flags)?;
    }
    if let Some(cf) = c.take() {
        insert(&mut fh, cf, &mut inserted);
    }
    let ins = match inserted {
        Some(r) => Some(chaseat_prefix_root(&r, root_l).map_err(|e| {
            log_full_errno!(log_level(flags), e, "Failed to prefix '", r, "' with root '", rs, "': ", strerror(e))
        })?),
        None => None,
    };
    let files = copy_and_sort(fh, Some(b".conf"), Some(&rs), flags)?;
    Ok((files, ins))
}
