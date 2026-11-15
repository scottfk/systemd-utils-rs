// SPDX-License-Identifier: LGPL-2.1-or-later
//! `env-file.c`: shell-like `KEY=value` files (os-release, machine-info),
//! and `os-util.c`'s os-release lookup.

use crate::chase::{Chased, chaseat};
use crate::fd::XAT_FDROOT;
use crate::path::empty_or_root;
use crate::string::{COMMENTS, NEWLINE, WHITESPACE};
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_error_errno, utf8};

/// `SHELL_NEED_ESCAPE`.
const SHELL_NEED_ESCAPE: &[u8] = b"\"\\`$";

/// `parse_env_file_internal()`: every (line, key, value) in order; a value
/// of None means "KEY=" with nothing after it.
fn parse_internal(
    contents: &[u8],
    push: &mut dyn FnMut(u32, &[u8], Option<Vec<u8>>) -> Result<(), i32>,
) -> Result<(), i32> {
    #[derive(PartialEq, Clone, Copy)]
    enum S {
        PreKey,
        Key,
        PreValue,
        Value,
        ValueEscape,
        SingleQuote,
        DoubleQuote,
        DoubleQuoteEscape,
        Comment,
        CommentEscape,
    }
    let mut state = S::PreKey;
    let mut key: Vec<u8> = Vec::new();
    let mut value: Option<Vec<u8>> = None;
    let mut last_key_ws = usize::MAX;
    let mut last_value_ws = usize::MAX;
    let mut line = 1u32;
    let contents = crate::bytes::c_str_prefix(contents);
    let finish_key = |key: &mut Vec<u8>, lkw: usize| {
        if lkw != usize::MAX {
            key.truncate(lkw);
        }
    };
    for &c in contents {
        match state {
            S::PreKey => {
                if COMMENTS.contains(&c) {
                    state = S::Comment;
                } else if !WHITESPACE.contains(&c) {
                    state = S::Key;
                    last_key_ws = usize::MAX;
                    key.push(c);
                }
            }
            S::Key => {
                if NEWLINE.contains(&c) {
                    state = S::PreKey;
                    line += 1;
                    key.clear();
                } else if c == b'=' {
                    state = S::PreValue;
                    last_value_ws = usize::MAX;
                } else {
                    if !WHITESPACE.contains(&c) {
                        last_key_ws = usize::MAX;
                    } else if last_key_ws == usize::MAX {
                        last_key_ws = key.len();
                    }
                    key.push(c);
                }
            }
            S::PreValue => {
                if NEWLINE.contains(&c) {
                    state = S::PreKey;
                    line += 1;
                    finish_key(&mut key, last_key_ws);
                    push(line, &key, value.take())?;
                    key.clear();
                } else if c == b'\'' {
                    state = S::SingleQuote;
                } else if c == b'"' {
                    state = S::DoubleQuote;
                } else if c == b'\\' {
                    state = S::ValueEscape;
                } else if !WHITESPACE.contains(&c) {
                    state = S::Value;
                    value.get_or_insert_with(Vec::new).push(c);
                }
            }
            S::Value => {
                if NEWLINE.contains(&c) {
                    state = S::PreKey;
                    line += 1;
                    if let Some(v) = value.as_mut()
                        && last_value_ws != usize::MAX
                    {
                        v.truncate(last_value_ws);
                    }
                    finish_key(&mut key, last_key_ws);
                    push(line, &key, value.take())?;
                    key.clear();
                } else if c == b'\\' {
                    state = S::ValueEscape;
                    last_value_ws = usize::MAX;
                } else {
                    let v = value.get_or_insert_with(Vec::new);
                    if !WHITESPACE.contains(&c) {
                        last_value_ws = usize::MAX;
                    } else if last_value_ws == usize::MAX {
                        last_value_ws = v.len();
                    }
                    v.push(c);
                }
            }
            S::ValueEscape => {
                state = S::Value;
                if !NEWLINE.contains(&c) {
                    value.get_or_insert_with(Vec::new).push(c);
                }
            }
            S::SingleQuote => {
                if c == b'\'' {
                    state = S::PreValue;
                } else {
                    value.get_or_insert_with(Vec::new).push(c);
                }
            }
            S::DoubleQuote => {
                if c == b'"' {
                    state = S::PreValue;
                } else if c == b'\\' {
                    state = S::DoubleQuoteEscape;
                } else {
                    value.get_or_insert_with(Vec::new).push(c);
                }
            }
            S::DoubleQuoteEscape => {
                state = S::DoubleQuote;
                if SHELL_NEED_ESCAPE.contains(&c) {
                    value.get_or_insert_with(Vec::new).push(c);
                } else if c != b'\n' {
                    let v = value.get_or_insert_with(Vec::new);
                    v.push(b'\\');
                    v.push(c);
                }
            }
            S::Comment => {
                if c == b'\\' {
                    state = S::CommentEscape;
                } else if NEWLINE.contains(&c) {
                    state = S::PreKey;
                    line += 1;
                }
            }
            S::CommentEscape => {
                log_debug!(
                    "The line which doesn't begin with \";\" or \"#\", but follows a comment line trailing with escape is now treated as a non comment line since v254."
                );
                if NEWLINE.contains(&c) {
                    state = S::PreKey;
                    line += 1;
                } else {
                    state = S::Comment;
                }
            }
        }
    }
    if matches!(state, S::PreValue | S::Value | S::ValueEscape | S::SingleQuote | S::DoubleQuote | S::DoubleQuoteEscape)
    {
        if state == S::Value
            && let Some(v) = value.as_mut()
            && last_value_ws != usize::MAX
        {
            v.truncate(last_value_ws);
        }
        finish_key(&mut key, last_key_ws);
        push(line, &key, value.take())?;
    }
    Ok(())
}

/// `parse_env_file(f, fname, key, &value, ...)` for the given keys.
pub fn parse_env_contents(contents: &[u8], fname: Option<&[u8]>, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, i32> {
    let mut out: Vec<Option<Vec<u8>>> = vec![None; keys.len()];
    parse_internal(contents, &mut |line, key, value| {
        // check_utf8ness_and_warn()
        if !utf8::is_valid(key) {
            return Err(log_error_errno!(
                crate::errno::synthetic(libc::EINVAL),
                crate::string::strna(fname),
                ":",
                line.to_string(),
                ": invalid UTF-8 in key '",
                crate::utf8::escape_invalid(key),
                "', ignoring."
            ));
        }
        if let Some(v) = &value
            && !utf8::is_valid(v)
        {
            return Err(log_error_errno!(
                crate::errno::synthetic(libc::EINVAL),
                crate::string::strna(fname),
                ":",
                line.to_string(),
                ": invalid UTF-8 value for key ",
                key,
                ": '",
                crate::utf8::escape_invalid(v),
                "', ignoring."
            ));
        }
        if let Some(i) = keys.iter().position(|k| k.as_bytes() == key) {
            out[i] = value;
        }
        Ok(())
    })?;
    Ok(out)
}

/// `parse_env_file(NULL, fname, ...)`.
pub fn parse_env_file(fname: &[u8], keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, i32> {
    let data = crate::fileio::fopen_re(fname)?.read_to_end()?;
    parse_env_contents(&data, Some(fname), keys)
}

/// `open_os_release_at(rfd, &path, &fd)`.
fn open_os_release_at(rfd: i32) -> Result<Chased, i32> {
    if let Some(e) = sys::secure_getenv("SYSTEMD_OS_RELEASE") {
        return chaseat(rfd, rfd, &e, 0, true, true);
    }
    for path in [&b"/etc/os-release"[..], b"/usr/lib/os-release"] {
        match chaseat(rfd, rfd, path, 0, true, true) {
            Err(e) if e == -libc::ENOENT => continue,
            r => return r,
        }
    }
    Err(-libc::ENOENT)
}

/// `parse_os_release(root, key, &value)` for one key.
pub fn parse_os_release(root: Option<&[u8]>, key: &str) -> Result<Option<Vec<u8>>, i32> {
    let _rfd;
    let rfd = if empty_or_root(root) {
        XAT_FDROOT
    } else {
        _rfd =
            OwnedFd::new(sys::open(root.unwrap_or_default(), libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH, 0)?);
        _rfd.raw()
    };
    let c = open_os_release_at(rfd)?;
    let fd = c.fd.expect("requested");
    let p = c.path.expect("requested");
    // fdopen_independent(): a fresh fd on the same file.
    let data = crate::fileio::fopen_re(&crate::fd::proc_fd_path(fd.raw()))?.read_to_end()?;
    Ok(parse_env_contents(&data, Some(&p), &[key])?.pop().expect("one key"))
}
