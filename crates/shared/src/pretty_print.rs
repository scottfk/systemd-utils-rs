// SPDX-License-Identifier: LGPL-2.1-or-later
//! `pretty-print.c`: `cat_files()` (`--cat-config`/`--tldr`) and the
//! terminal hyperlink helpers.
//!
//! Gentoo builds with `-Durlify=false`, so `urlify_enabled()` is always
//! false and links are plain text.

use crate::conf_files::{CONF_FILES_FILTER_MASKED, CONF_FILES_REGULAR, CONF_FILES_WARN, ConfFile, conf_file_new};
use crate::errno::{ret_gather, strerror};
use crate::fd::proc_fd_path;
use crate::fileio::{LONG_LINE_MAX, fopen_re, read_line};
use crate::path::path_equal;
use crate::string::{COMMENTS, WHITESPACE, skip_leading_chars};
use crate::terminal::ansi;
use crate::{log_error_errno, printo};

pub const CAT_CONFIG_OFF: u32 = 0;
pub const CAT_CONFIG_ON: u32 = 1 << 0;
pub const CAT_FORMAT_HAS_SECTIONS: u32 = 1 << 1;
pub const CAT_TLDR: u32 = 1 << 2;

/// `urlify_enabled()`: ENABLE_URLIFY is 0 in this build.
pub fn urlify_enabled() -> bool {
    false
}

/// `terminal_urlify(url, text)`.
pub fn terminal_urlify(url: &[u8], text: Option<&[u8]>) -> Vec<u8> {
    let text = match text {
        Some(t) if !t.is_empty() => t,
        _ => url,
    };
    text.to_vec()
}

/// `terminal_urlify_path(path, text)`.
pub fn terminal_urlify_path(path: &[u8], text: Option<&[u8]>) -> Result<Vec<u8>, i32> {
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    let text = match text {
        Some(t) if !t.is_empty() => t,
        _ => path,
    };
    Ok(text.to_vec())
}

/// `terminal_urlify_man_full(page, section, suffix)`.
pub fn terminal_urlify_man_full(page: &[u8], section: Option<&[u8]>, suffix: &[u8]) -> Vec<u8> {
    let (url, text) = match section {
        Some(s) => (crate::bcat!("man:", page, "(", s, ")"), crate::bcat!(page, "(", s, ")", suffix)),
        None => (crate::bcat!("man:", page), crate::bcat!(page, suffix)),
    };
    terminal_urlify(&url, Some(&text))
}

/// `terminal_urlify_man(page, section)`: with the " man page" suffix.
pub fn terminal_urlify_man(page: &[u8], section: Option<&[u8]>) -> Vec<u8> {
    terminal_urlify_man_full(page, section, b" man page")
}

/// `cat_file()`.
fn cat_file(c: &ConfFile, newline: &mut bool, flags: u32) -> i32 {
    if *newline {
        printo!("\n");
    }
    *newline = true;
    let resolved = !path_equal(&c.original_path, &c.resolved_path);
    let urlified = match terminal_urlify_path(&c.resolved_path, None) {
        Ok(u) => u,
        Err(r) => return log_error_errno!(r, "Failed to urlify path \"", c.resolved_path, "\": ", strerror(r)),
    };
    printo!(
        ansi::highlight_blue(),
        "# ",
        if resolved { &c.original_path[..] } else { b"" },
        if resolved { " -> " } else { "" },
        urlified,
        ansi::normal(),
        "\n"
    );
    let mut f = match fopen_re(&proc_fd_path(c.fd.raw())) {
        Ok(f) => f,
        Err(e) => return log_error_errno!(e, "Failed to open \"", c.resolved_path, "\": ", strerror(e)),
    };
    let tldr = flags & CAT_TLDR != 0;
    let sections = flags & CAT_FORMAT_HAS_SECTIONS != 0;
    let mut section: Option<Vec<u8>> = None;
    let mut old_section: Option<Vec<u8>> = None;
    let mut continued = false;
    loop {
        let mut line = match read_line(&mut f, LONG_LINE_MAX) {
            Ok((0, _)) => break,
            Ok((_, l)) => l,
            Err(r) => return log_error_errno!(r, "Failed to read \"", c.resolved_path, "\": ", strerror(r)),
        };
        let l = skip_leading_chars(&line, Some(WHITESPACE));
        if !l.is_empty() && COMMENTS.contains(&l[0]) {
            if !tldr {
                printo!(ansi::highlight_grey(), line, ansi::normal(), "\n");
            }
            continue;
        }
        if tldr && (l.is_empty() || l == b"\\") {
            continue;
        }
        if sections && l.first() == Some(&b'[') && !continued {
            if tldr {
                section = Some(line);
            } else {
                printo!(ansi::highlight_cyan(), line, ansi::normal(), "\n");
            }
            continue;
        }
        if tldr && let Some(s) = section.take() {
            if old_section.as_ref() != Some(&s) {
                printo!(ansi::highlight_cyan(), s, ansi::normal(), "\n");
            }
            old_section = Some(s);
        }
        let mut escaped = false;
        for &b in &line {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            }
        }
        if escaped {
            line.pop();
            line.extend_from_slice(ansi::highlight_red().as_bytes());
            line.push(b'\\');
            line.extend_from_slice(ansi::normal().as_bytes());
        }
        if sections
            && !continued
            && let Some(i) = line.iter().position(|&b| b == b'=')
        {
            printo!(ansi::highlight_green(), &line[..i], "=", ansi::normal(), &line[i + 1..], "\n");
            continued = escaped;
            continue;
        }
        printo!(line, "\n");
        continued = escaped;
    }
    0
}

/// `cat_file_by_path()`.
fn cat_file_by_path(p: &[u8], newline: &mut bool, flags: u32) -> i32 {
    match conf_file_new(p, None, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN) {
        Err(r) if r == -libc::ERFKILL => {
            if *newline {
                printo!("\n");
            }
            *newline = true;
            printo!(ansi::highlight_magenta(), "# ", p, " is a mask.", ansi::normal(), "\n");
            0
        }
        Err(r) => r,
        Ok(c) => cat_file(&c, newline, flags),
    }
}

/// `cat_files(file, dropins, flags)`.
pub fn cat_files(file: Option<&[u8]>, dropins: &[Vec<u8>], flags: u32) -> i32 {
    let mut newline = false;
    let mut ret = 0;
    if let Some(f) = file {
        ret = cat_file_by_path(f, &mut newline, flags);
    }
    for p in dropins {
        ret_gather(&mut ret, cat_file_by_path(p, &mut newline, flags));
    }
    ret
}

/// `cat_files_full(file, dropins, n, flags)`.
pub fn cat_files_full(file: Option<&ConfFile>, dropins: &[ConfFile], flags: u32) -> i32 {
    let mut newline = false;
    let mut ret = 0;
    if let Some(f) = file {
        ret = cat_file(f, &mut newline, flags);
    }
    for d in dropins {
        ret_gather(&mut ret, cat_file(d, &mut newline, flags));
    }
    ret
}

/// `guess_type()`: (name, prefixes, is_collection, extension).
fn guess_type(name: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>, bool, &'static [u8]) {
    let name: &[u8] = if path_equal(name, b"environment.d") { b"environment" } else { name };
    let n = crate::string::delete_trailing_chars(name, Some(b"/")).to_vec();
    let mut coll = n.ends_with(b".d");
    let mut run = false;
    let mut ext: &[u8] = b".conf";
    if path_equal(&n, b"udev/hwdb.d") {
        ext = b".hwdb";
    } else if path_equal(&n, b"udev/rules.d") {
        ext = b".rules";
    } else if path_equal(&n, b"kernel/install.d") {
        ext = b".install";
    } else if path_equal(&n, b"systemd/ntp-units.d") {
        coll = true;
        ext = b".list";
    } else if path_equal(&n, b"systemd/relabel-extra.d") {
        coll = true;
        run = true;
        ext = b".relabel";
    } else if [&b"systemd/system-preset"[..], b"systemd/user-preset", b"systemd/initrd-preset"]
        .iter()
        .any(|p| path_equal(&n, p))
    {
        coll = true;
        ext = b".preset";
    }
    let prefixes = if run { vec![b"/run/".to_vec()] } else { crate::conf_files::conf_paths("") };
    (name.to_vec(), prefixes, coll, ext)
}

/// `conf_files_cat(root, name, flags)`.
pub fn conf_files_cat(root: Option<&[u8]>, name: &[u8], mut flags: u32) -> i32 {
    let (name, prefixes, is_collection, extension) = guess_type(name);
    let dirs: Vec<Vec<u8>> =
        prefixes.iter().map(|p| crate::bcat!(p, &name, if is_collection { "" } else { ".d" })).collect();
    if crate::log::debug_logging() {
        crate::log_debug!("Looking for configuration in:");
        if !is_collection {
            for p in &prefixes {
                crate::log_debug!("   ", root.unwrap_or_default(), p, &name);
            }
        }
        for t in &dirs {
            crate::log_debug!("   ", root.unwrap_or_default(), t, "/*", extension);
        }
    }
    let mut c = None;
    if !is_collection {
        for p in &prefixes {
            let path = crate::path::path_join(&[p, &name]);
            match conf_file_new(&path, root, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED) {
                Ok(x) => {
                    c = Some(x);
                    break;
                }
                Err(r) if r == -libc::ERFKILL => break,
                Err(_) => {}
            }
        }
        if c.is_none() {
            printo!(ansi::highlight_magenta(), "# Main configuration file ", &name, " not found", ansi::normal(), "\n");
        }
    }
    let dropins = match crate::conf_files::conf_files_list_strv_full(
        Some(extension),
        root,
        CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
        &dirs,
    ) {
        Ok(d) => d,
        Err(r) => return log_error_errno!(r, "Failed to query file list: ", strerror(r)),
    };
    if is_collection {
        flags |= CAT_FORMAT_HAS_SECTIONS;
    }
    cat_files_full(c.as_ref(), &dropins, flags)
}
