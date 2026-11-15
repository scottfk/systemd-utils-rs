// SPDX-License-Identifier: LGPL-2.1-or-later
//! `hostname-util.c` and `hostname-setup.c`: the hostname specifiers.

use crate::{log_debug, log_debug_errno, sys};

const FALLBACK_HOSTNAME: &[u8] = b"localhost";
const VALID_HOSTNAME_TRAILING_DOT: u32 = 1 << 0;
const VALID_HOSTNAME_QUESTION_MARK: u32 = 1 << 2;
const VALID_HOSTNAME_WORD_TOKEN: u32 = 1 << 3;

fn valid_ldh_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

/// `hostname_is_valid(s, flags)`.
pub fn hostname_is_valid(s: &[u8], flags: u32) -> bool {
    if s.is_empty() {
        return false;
    }
    if s == b".host" {
        return false;
    }
    let (mut dot, mut hyphen, mut n_dots) = (true, true, 0);
    for &c in s {
        if c == b'.' {
            if dot || hyphen {
                return false;
            }
            dot = true;
            hyphen = false;
            n_dots += 1;
        } else if c == b'-' {
            if dot {
                return false;
            }
            dot = false;
            hyphen = true;
        } else {
            if !valid_ldh_char(c)
                && (c != b'?' || flags & VALID_HOSTNAME_QUESTION_MARK == 0)
                && (c != b'$' || flags & VALID_HOSTNAME_WORD_TOKEN == 0)
            {
                return false;
            }
            dot = false;
            hyphen = false;
        }
    }
    if dot && (n_dots < 2 || flags & VALID_HOSTNAME_TRAILING_DOT == 0) {
        return false;
    }
    if hyphen {
        return false;
    }
    s.len() <= 64
}

/// `get_default_hostname()`.  Wildcards ("?", "$...") in a configured
/// default are not substituted: such a name falls back to "localhost".
fn get_default_hostname() -> Vec<u8> {
    let raw = (|| {
        if let Some(e) = sys::secure_getenv("SYSTEMD_DEFAULT_HOSTNAME") {
            if hostname_is_valid(&e, VALID_HOSTNAME_QUESTION_MARK | VALID_HOSTNAME_WORD_TOKEN) {
                return e;
            }
            log_debug!("Invalid hostname in $SYSTEMD_DEFAULT_HOSTNAME, ignoring: ", e);
        }
        match crate::env_file::parse_os_release(None, "DEFAULT_HOSTNAME") {
            Err(r) => {
                log_debug_errno!(r, "Failed to parse os-release, ignoring: ", crate::errno::strerror(r));
            }
            Ok(Some(f)) => {
                if hostname_is_valid(&f, VALID_HOSTNAME_QUESTION_MARK | VALID_HOSTNAME_WORD_TOKEN) {
                    return f;
                }
                log_debug!("Invalid hostname in os-release, ignoring: ", f);
            }
            Ok(None) => {}
        }
        FALLBACK_HOSTNAME.to_vec()
    })();
    if !hostname_is_valid(&raw, VALID_HOSTNAME_TRAILING_DOT) {
        log_debug!("Substituted hostname '", raw, "' is invalid, falling back to built-in name.");
        return FALLBACK_HOSTNAME.to_vec();
    }
    raw
}

/// `gethostname_full(ALLOW_LOCALHOST|FALLBACK_DEFAULT [|SHORT])`.
pub fn gethostname(short: bool) -> Result<Vec<u8>, i32> {
    let s = sys::uname_nodename()?;
    let s = if s.is_empty() || s == b"(none)" || (short && s[0] == b'.') {
        let f = get_default_hostname();
        if short && f.first() == Some(&b'.') {
            return Err(-libc::ENXIO);
        }
        f
    } else {
        s
    };
    if short {
        let n = s.iter().position(|&b| b == b'.').unwrap_or(s.len());
        return Ok(s[..n].to_vec());
    }
    Ok(s)
}

/// `get_pretty_hostname()`.
pub fn get_pretty_hostname() -> Result<Vec<u8>, i32> {
    let path = sys::secure_getenv("SYSTEMD_ETC_MACHINE_INFO").unwrap_or_else(|| b"/etc/machine-info".to_vec());
    let v = crate::env_file::parse_env_file(&path, &["PRETTY_HOSTNAME"])?;
    match v.into_iter().next().flatten() {
        Some(n) if !n.is_empty() => Ok(n),
        _ => Err(-libc::ENXIO),
    }
}
