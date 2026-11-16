// SPDX-License-Identifier: LGPL-2.1-or-later
//! `proc-cmdline.c`, `initrd-util.c` and `argv-util.c`'s `invoked_by_systemd()`.

use std::sync::atomic::{AtomicI8, Ordering};

use crate::env::secure_getenv_bool;
use crate::errno::strerror;
use crate::extract::{EXTRACT_RELAX, EXTRACT_RETAIN_ESCAPE, EXTRACT_UNQUOTE, strv_split_full};
use crate::{log_debug_errno, log_warning, sys};

static IN_INITRD: AtomicI8 = AtomicI8::new(-1);
static INVOKED_BY_SYSTEMD: AtomicI8 = AtomicI8::new(-1);

/// `in_initrd()`.
pub fn in_initrd() -> bool {
    let c = IN_INITRD.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = match secure_getenv_bool("SYSTEMD_IN_INITRD") {
        Ok(b) => b,
        Err(r) => {
            if r != -libc::ENXIO {
                log_debug_errno!(r, "Failed to parse $SYSTEMD_IN_INITRD, ignoring: ", strerror(r));
            }
            match crate::sys::stat(b"/etc/initrd-release") {
                Ok(_) => true,
                Err(e) => {
                    if e != -libc::ENOENT {
                        log_debug_errno!(
                            e,
                            "Failed to check if /etc/initrd-release exists, assuming it does not: ",
                            strerror(e)
                        );
                    }
                    false
                }
            }
        }
    };
    IN_INITRD.store(v as i8, Ordering::Relaxed);
    v
}

/// `invoked_by_systemd()`.
pub fn invoked_by_systemd() -> bool {
    let c = INVOKED_BY_SYSTEMD.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = match sys::getenv("SYSTEMD_EXEC_PID") {
        None => false,
        Some(e) if e == b"*" => true,
        Some(e) => {
            // parse_pid(): safe_atolu(), then the pid_t range and pid_is_valid().
            let r = match crate::parse::safe_atou64(&e) {
                Ok(p) if p > 0 && p <= i32::MAX as u64 => Ok(p),
                Ok(_) => Err(-libc::ERANGE),
                Err(r) => Err(r),
            };
            match r {
                Ok(p) => sys::getpid() as u64 == p,
                Err(r) => {
                    log_debug_errno!(r, "Failed to parse \"SYSTEMD_EXEC_PID=", e, "\", ignoring: ", strerror(r));
                    false
                }
            }
        }
    };
    INVOKED_BY_SYSTEMD.store(v as i8, Ordering::Relaxed);
    v
}

/// `proc_cmdline_strv_internal()`.
pub fn proc_cmdline_strv() -> Result<Vec<Vec<u8>>, i32> {
    let flags = EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE;
    if let Some(e) = sys::secure_getenv("SYSTEMD_PROC_CMDLINE") {
        return strv_split_full(&e, None, flags);
    }
    if crate::virt::detect_container().is_ok_and(|v| v != crate::virt::NONE) {
        let raw = crate::fileio::read_full_file_with_nuls(b"/proc/1/cmdline")?;
        let mut args: Vec<Vec<u8>> = raw.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
        if args.last().is_some_and(|a| a.is_empty()) {
            args.pop();
        }
        return Ok(filter_pid1_args(&args));
    }
    let s = crate::fileio::read_full_file(b"/proc/cmdline")?;
    strv_split_full(&s, None, flags)
}

/// `proc_cmdline_filter_pid1_args()`: drop systemd's own options from PID
/// 1's argv.
fn filter_pid1_args(argv: &[Vec<u8>]) -> Vec<Vec<u8>> {
    #[derive(Clone, Copy, PartialEq)]
    enum Arg {
        No,
        Required,
        Optional,
    }
    use Arg::*;
    const OPTIONS: &[(&[u8], Arg)] = &[
        (b"log-level", Required),
        (b"log-target", Required),
        (b"log-color", Optional),
        (b"log-location", Optional),
        (b"log-time", Optional),
        (b"unit", Required),
        (b"system", No),
        (b"user", No),
        (b"test", No),
        (b"no-pager", No),
        (b"help", No),
        (b"version", No),
        (b"introspect-cli", No),
        (b"dump-configuration-items", No),
        (b"dump-bus-properties", No),
        (b"bus-introspect", Required),
        (b"dump-core", Optional),
        (b"crash-chvt", Required),
        (b"crash-vt", Required),
        (b"crash-shell", Optional),
        (b"crash-reboot", Optional),
        (b"crash-action", Required),
        (b"confirm-spawn", Optional),
        (b"show-status", Optional),
        (b"deserialize", Required),
        (b"switched-root", No),
        (b"default-standard-output", Required),
        (b"default-standard-error", Required),
        (b"machine-id", Required),
        (b"service-watchdogs", Required),
        (b"exit-code", Required),
        (b"timeout", Required),
    ];
    const SHORT: &[u8] = b"hDbsz:";
    let mut filtered = Vec::new();
    let mut state = No;
    let rest = if argv.is_empty() { argv } else { &argv[1..] };
    for (i, a) in rest.iter().enumerate() {
        let prev = state;
        state = No;
        if prev == Required || (prev == Optional && a.first() != Some(&b'-')) {
            continue;
        }
        if a.first() != Some(&b'-') {
            filtered.push(a.clone());
            continue;
        }
        if a.get(1) == Some(&b'-') {
            if a.len() == 2 {
                filtered.extend(rest[i + 1..].iter().cloned());
                break;
            }
            for (name, has_arg) in OPTIONS {
                let Some(q) = a[2..].strip_prefix(*name) else { continue };
                if !matches!(q.first(), None | Some(b'=')) {
                    continue;
                }
                if q.is_empty() && *has_arg == Required {
                    state = Required;
                }
                break;
            }
            continue;
        }
        let mut k = 1;
        while k < a.len() {
            if let Some(p) = SHORT.iter().position(|&c| c == a[k])
                && SHORT.get(p + 1) == Some(&b':')
            {
                state = if k + 1 < a.len() {
                    No
                } else if SHORT.get(p + 2) == Some(&b':') {
                    Optional
                } else {
                    Required
                };
                break;
            }
            k += 1;
        }
    }
    filtered
}

/// `mangle_word()` with `PROC_CMDLINE_STRIP_RD_PREFIX` (when `strip_rd`).
fn mangle_word(word: &[u8], strip_rd: bool) -> Option<&[u8]> {
    if let Some(c) = word.strip_prefix(b"rd.") {
        if !in_initrd() {
            return None;
        }
        if strip_rd {
            return Some(c);
        }
    }
    Some(word)
}

/// `proc_cmdline_parse(parse_item, data, flags)`.
pub fn proc_cmdline_parse(parse_item: fn(&[u8], Option<&[u8]>) -> i32, strip_rd: bool) -> Result<(), i32> {
    let args = proc_cmdline_strv()?;
    for word in &args {
        let Some(key) = mangle_word(word, strip_rd) else {
            continue;
        };
        let (k, v) = match key.iter().position(|&b| b == b'=') {
            Some(i) => (&key[..i], Some(&key[i + 1..])),
            None => (key, None),
        };
        let r = parse_item(k, v);
        if r < 0 {
            return Err(r);
        }
    }
    Ok(())
}

fn relaxed_equal_char(a: u8, b: u8) -> bool {
    a == b || (a == b'_' && b == b'-') || (a == b'-' && b == b'_')
}

/// `proc_cmdline_key_streq()`: "-" and "_" compare equal.
pub fn key_streq(x: &[u8], y: &[u8]) -> bool {
    x.len() == y.len() && x.iter().zip(y).all(|(&a, &b)| relaxed_equal_char(a, b))
}

/// `proc_cmdline_value_missing()`.
pub fn value_missing(key: &[u8], value: Option<&[u8]>) -> bool {
    if value.is_none() {
        log_warning!("Missing argument for ", key, "= kernel command line switch, ignoring.");
        return true;
    }
    false
}

/// `proc_cmdline_key_startswith(s, prefix)`: what follows the prefix
/// ('-' and '_' compare equal).
fn key_startswith<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() < prefix.len() {
        return None;
    }
    if s.iter().zip(prefix).all(|(&a, &b)| relaxed_equal_char(a, b)) { Some(&s[prefix.len()..]) } else { None }
}

/// `proc_cmdline_get_key(key, PROC_CMDLINE_VALUE_OPTIONAL, &value)`:
/// None if the key isn't there, Some(None) if it is without a value.
pub fn proc_cmdline_get_key(key: &[u8], value_optional: bool) -> Result<Option<Option<Vec<u8>>>, i32> {
    if key.is_empty() {
        return Err(-libc::EINVAL);
    }
    let args = proc_cmdline_strv()?;
    let mut v: Option<Vec<u8>> = None;
    let mut found = false;
    for a in &args {
        let Some(word) = mangle_word(a, false) else { continue };
        let Some(e) = key_startswith(word, key) else { continue };
        if e.first() == Some(&b'=') {
            v = Some(e[1..].to_vec());
            found = true;
        } else if e.is_empty() && value_optional {
            found = true;
        }
    }
    Ok(if found { Some(v) } else { None })
}
