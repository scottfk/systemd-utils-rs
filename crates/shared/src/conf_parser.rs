// SPDX-License-Identifier: LGPL-2.1-or-later
//! `conf-parser.c`: the parts the udev programs use, the `KEY=VALUE`
//! files without sections (`udev.conf` and its drop-ins), and
//! `stat_warn_permissions()` (`fs-util.c`).

use crate::chase::{CHASE_MUST_BE_REGULAR, chase};
use crate::errno::{strerror, synthetic};
use crate::fileio::{CReader, LONG_LINE_MAX, read_line};
use crate::log::{LOG_DEBUG, LOG_ERR, LOG_WARNING, getpid_cached};
use crate::string::{COMMENTS, WHITESPACE, skip_leading_chars, strstrip};
use crate::sys::{self, OwnedFd};
use crate::{bcat, log_full_errno, log_syntax, log_warning};

pub const CONFIG_PARSE_RELAXED: u32 = 1 << 0;
pub const CONFIG_PARSE_WARN: u32 = 1 << 1;

/// What a table lookup found for a key: `None` for an unknown key, else
/// the parser's result (keys without a parser give `Some(0)`).
pub type Lookup<'a> = dyn FnMut(&[u8], u32, Option<&[u8]>, &[u8], &[u8]) -> Option<i32> + 'a;

/// `stat_warn_permissions(path, st)`.
pub fn stat_warn_permissions(path: &[u8], st: &sys::Stat) {
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return;
    }
    if st.st_mode & 0o111 != 0 {
        log_warning!(
            "Configuration file ",
            path,
            " is marked executable. Please remove executable permission bits. Proceeding anyway."
        );
    }
    if st.st_mode & 0o002 != 0 {
        log_warning!(
            "Configuration file ",
            path,
            " is marked world-writable. Please remove world writability permission bits. Proceeding anyway."
        );
    }
    if getpid_cached() == 1 && st.st_mode & 0o044 != 0o044 {
        log_warning!(
            "Configuration file ",
            path,
            " is marked world-inaccessible. This has no effect as configuration data is accessible via APIs without restrictions. Proceeding anyway."
        );
    }
}

/// `log_syntax_parse_error(unit=NULL, file, line, error, lvalue, rvalue)`.
pub fn log_syntax_parse_error(file: &[u8], line: u32, error: i32, lvalue: &[u8], rvalue: &[u8]) -> i32 {
    let valid = crate::utf8::is_valid(rvalue);
    let escaped = if valid { Vec::new() } else { crate::utf8::escape_invalid(rvalue) };
    let rv: &[u8] = if valid { rvalue } else { b" (escaped)" };
    log_syntax!(
        LOG_WARNING,
        Some(file),
        line,
        error,
        "Failed to parse ",
        lvalue,
        "=",
        escaped,
        rv,
        ", ignoring",
        if error == 0 { "." } else { ": " },
        if error == 0 { Vec::new() } else { strerror(error) }
    );
    0
}

/// `parse_line()` with `sections=NULL`.  `section` is the current
/// section, if the file has a header anyway.
fn parse_line(
    filename: &[u8],
    line: u32,
    flags: u32,
    section: &mut Option<Vec<u8>>,
    l: &[u8],
    lookup: &mut Lookup,
) -> i32 {
    let l = strstrip(l);
    if l.is_empty() || l[0] == b'\n' {
        return 0;
    }
    if !crate::utf8::is_valid(l) {
        return log_syntax!(
            LOG_WARNING,
            Some(filename),
            line,
            synthetic(libc::EINVAL),
            "String is not UTF-8 clean, ignoring assignment: ",
            crate::utf8::escape_invalid(l)
        );
    }
    if l[0] == b'[' {
        let k = l.len();
        if l[k - 1] != b']' {
            return log_syntax!(
                LOG_ERR,
                Some(filename),
                line,
                synthetic(libc::EBADMSG),
                "Invalid section header '",
                l,
                "'"
            );
        }
        let n = &l[1..k - 1];
        if !crate::string::string_is_safe(n, 0) {
            return log_syntax!(
                LOG_ERR,
                Some(filename),
                line,
                synthetic(libc::EBADMSG),
                "Section header invalid '",
                l,
                "'"
            );
        }
        *section = Some(n.to_vec());
        return 0;
    }
    let Some(e) = l.iter().position(|&b| b == b'=') else {
        return log_syntax!(LOG_WARNING, Some(filename), line, 0, "Missing '=', ignoring line.");
    };
    if e == 0 {
        return log_syntax!(LOG_WARNING, Some(filename), line, 0, "Missing key name before '=', ignoring line.");
    }
    let lvalue = strstrip(&l[..e]);
    let rvalue = strstrip(&l[e + 1..]);
    // next_assignment()
    match lookup(filename, line, section.as_deref(), lvalue, rvalue) {
        Some(r) => r,
        None => {
            if flags & CONFIG_PARSE_RELAXED == 0 && !lvalue.starts_with(b"X-") {
                let sec = section.as_deref();
                log_syntax!(
                    LOG_WARNING,
                    Some(filename),
                    line,
                    0,
                    "Unknown key '",
                    lvalue,
                    "'",
                    if sec.is_some() { " in section [" } else { "" },
                    sec.unwrap_or_default(),
                    if sec.is_some() { "]" } else { "" },
                    ", ignoring."
                );
            }
            0
        }
    }
}

/// `config_parse(unit=NULL, filename, f, sections=NULL, ...)`.
fn config_parse(filename: &[u8], f: &mut CReader, st: &sys::Stat, flags: u32, lookup: &mut Lookup) -> i32 {
    stat_warn_permissions(filename, st);
    let mut section: Option<Vec<u8>> = None;
    let mut continuation: Option<Vec<u8>> = None;
    let mut line = 0u32;
    let mut bom_seen = false;
    let fail = |r: i32, line: u32| {
        if flags & CONFIG_PARSE_WARN != 0 {
            crate::log_warning_errno!(r, filename, ":", line.to_string(), ": Failed to parse file: ", strerror(r));
        }
        r
    };
    loop {
        let buf = match read_line(f, LONG_LINE_MAX) {
            Ok((0, _)) => break,
            Ok((_, b)) => b,
            Err(r) if r == -libc::ENOBUFS => {
                if flags & CONFIG_PARSE_WARN != 0 {
                    crate::log_error_errno!(r, filename, ":", line.to_string(), ": Line too long");
                }
                return r;
            }
            Err(r) => {
                if flags & CONFIG_PARSE_WARN != 0 {
                    crate::log_error_errno!(
                        r,
                        filename,
                        ":",
                        line.to_string(),
                        ": Error while reading configuration file: ",
                        strerror(r)
                    );
                }
                return r;
            }
        };
        line += 1;
        let l0 = skip_leading_chars(&buf, Some(WHITESPACE));
        if !l0.is_empty() && COMMENTS.contains(&l0[0]) {
            continue;
        }
        let mut l: &[u8] = &buf;
        if !bom_seen && let Some(q) = l.strip_prefix(b"\xef\xbb\xbf") {
            l = q;
            bom_seen = true;
        }
        if let Some(c) = continuation.as_mut() {
            if c.len() + l.len() > LONG_LINE_MAX {
                if flags & CONFIG_PARSE_WARN != 0 {
                    crate::log_error!(filename, ":", line.to_string(), ": Continuation line too long");
                }
                return -libc::ENOBUFS;
            }
            c.extend_from_slice(l);
        }
        let p: &[u8] = continuation.as_deref().unwrap_or(l);
        let mut escaped = false;
        for &b in p {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            }
        }
        if escaped {
            match continuation.as_mut() {
                Some(c) => {
                    let n = c.len();
                    c[n - 1] = b' ';
                }
                None => {
                    let mut c = l.to_vec();
                    let n = c.len();
                    c[n - 1] = b' ';
                    continuation = Some(c);
                }
            }
            continue;
        }
        let p = p.to_vec();
        let r = parse_line(filename, line, flags, &mut section, &p, lookup);
        if r < 0 {
            return fail(r, line);
        }
        continuation = None;
    }
    if let Some(c) = continuation {
        line += 1;
        let r = parse_line(filename, line, flags, &mut section, &c, lookup);
        if r < 0 {
            return fail(r, line);
        }
    }
    1
}

fn open_regular(path: &[u8]) -> Result<(CReader, sys::Stat), i32> {
    let c = chase(path, None, CHASE_MUST_BE_REGULAR, false, true)?;
    let fd: OwnedFd = c.fd.expect("requested");
    let path = crate::fd::proc_fd_path(fd.raw());
    let f = crate::fileio::fopen_re(&path)?;
    let st = sys::fstat(f.fd())?;
    Ok((f, st))
}

/// `config_parse_standard_file_with_dropins(main_file, sections=NULL,
/// ..., flags, ...)` for a file without sections.
pub fn config_parse_standard_file_with_dropins(main_file: &str, flags: u32, lookup: &mut Lookup) -> i32 {
    let level = if flags & CONFIG_PARSE_WARN != 0 { LOG_WARNING } else { LOG_DEBUG };
    let conf_file_dirs = crate::conf_files::conf_paths("");
    let conf_files: Vec<Vec<u8>> = conf_file_dirs.iter().map(|d| bcat!(d, main_file)).collect();
    let dropin_dirs: Vec<Vec<u8>> = conf_file_dirs.iter().map(|d| bcat!(d, "/", main_file, ".d")).collect();
    let files = match crate::conf_files::conf_files_list_strv(
        Some(b".conf"),
        None,
        if flags & CONFIG_PARSE_WARN != 0 { crate::conf_files::CONF_FILES_WARN } else { 0 },
        &dropin_dirs,
    ) {
        Ok(f) => f,
        Err(r) => {
            return log_full_errno!(level, r, "Failed to list drop-ins in ", main_file, ".d: ", strerror(r));
        }
    };
    // Pin and stat() all drop-ins.
    let mut dropins: Vec<(Vec<u8>, CReader, sys::Stat)> = Vec::new();
    for f in &files {
        match open_regular(f) {
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => return log_full_errno!(level, r, "Failed to open ", f, ": ", strerror(r)),
            Ok((rd, st)) => dropins.push((f.clone(), rd, st)),
        }
    }
    for f in &conf_files {
        let (mut rd, st) = match open_regular(f) {
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => return log_full_errno!(level, r, "Failed to open ", f, ": ", strerror(r)),
            Ok(x) => x,
        };
        if !dropins.is_empty() && dropins.iter().any(|(_, _, s)| s.st_dev == st.st_dev && s.st_ino == st.st_ino) {
            crate::log_debug!(f, ": symlink to/symlinked as drop-in, will be read later.");
            break;
        }
        let r = config_parse(f, &mut rd, &st, flags, lookup);
        if r < 0 {
            return r;
        }
        break;
    }
    for (p, mut rd, st) in dropins {
        let r = config_parse(&p, &mut rd, &st, flags, lookup);
        if r < 0 {
            return r;
        }
    }
    0
}

/// `config_parse_log_level()`: into `*o`.
pub fn config_parse_log_level(filename: &[u8], line: u32, lvalue: &[u8], rvalue: &[u8], o: &mut i32) -> i32 {
    match crate::log::log_level_from_string(rvalue) {
        Err(x) => log_syntax_parse_error(filename, line, x, lvalue, rvalue),
        Ok(x) => {
            if *o < 0 {
                *o = x;
            } else {
                *o = (*o & libc::LOG_FACMASK) | x;
            }
            1
        }
    }
}
