// SPDX-License-Identifier: LGPL-2.1-or-later
//! `proc-cmdline.c`, `initrd-util.c` and `argv-util.c`'s `invoked_by_systemd()`.
//!
//! Known difference: `detect_container()` is not ported, so inside a
//! container the kernel command line is still read from /proc/cmdline
//! rather than from PID 1's argv.  (Only PID 1 and programs started by
//! systemd with `$SYSTEMD_EXEC_PID` read the command line at all.)

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
fn proc_cmdline_strv() -> Result<Vec<Vec<u8>>, i32> {
    let flags = EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE;
    if let Some(e) = sys::secure_getenv("SYSTEMD_PROC_CMDLINE") {
        return strv_split_full(&e, None, flags);
    }
    let s = crate::fileio::read_full_file(b"/proc/cmdline")?;
    strv_split_full(&s, None, flags)
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
