// SPDX-License-Identifier: LGPL-2.1-or-later
//! `userdb_by_name()` and `groupdb_by_name()` (`userdb.c`) with
//! `USERDB_SUPPRESS_SHADOW | USERDB_PARSE_NUMERIC |
//! USERDB_SYNTHESIZE_NUMERIC`, as udev resolves `OWNER=`/`GROUP=`.
//!
//! Without systemd there are no userdb varlink services; the lookups go
//! to the fallbacks: NSS, then the intrinsic `root` and `nobody`, the
//! foreign range, and numeric names.  JSON user records in `userdb/`
//! drop-in directories are not read.

use crate::sys;
use crate::user::{UID_NOBODY, parse_uid, synthesize_nobody};

/// `FOREIGN_UID_BASE`.
const FOREIGN_UID_BASE: u32 = 0x7FFE_0000;

/// `valid_user_group_name(u, VALID_USER_RELAX)`.
pub fn valid_user_group_name_relaxed(u: &[u8]) -> bool {
    if u.is_empty() || parse_uid(u).is_ok() {
        return false;
    }
    if u.starts_with(b" ") || u.ends_with(b" ") {
        return false;
    }
    if !crate::utf8::is_valid(u) {
        return false;
    }
    if u.iter().any(|&c| c < b' ' || c == 127) {
        return false;
    }
    if u.iter().any(|&c| c == b':' || c == b'/') {
        return false;
    }
    if crate::string::in_charset(u, crate::string::DIGITS) {
        return false;
    }
    if u[0] == b'-' && crate::string::in_charset(&u[1..], crate::string::DIGITS) {
        return false;
    }
    !crate::path::dot_or_dot_dot(u)
}

/// `user_name_foreign_extract_uid()`.
fn foreign_extract(name: &[u8]) -> Option<u32> {
    let e = name.strip_prefix(b"foreign-")?;
    let u = parse_uid(e).ok()?;
    if u > 0xFFFF { None } else { Some(u) }
}

/// `userdb_by_uid_fallbacks()` with `USERDB_SYNTHESIZE_NUMERIC`: always
/// finds something.
fn by_id(id: u32) -> Result<u32, i32> {
    if id == u32::MAX { Err(-libc::EINVAL) } else { Ok(id) }
}

/// `userdb_start_query()`: there are no userdb services without systemd,
/// so this only fails, with C's debug logging.
fn start_query() {
    if let Some(e) = crate::env::getenv("SYSTEMD_BYPASS_USERDB")
        && crate::parse::parse_boolean(&e) == Ok(true)
    {
        return;
    }
    const MULTIPLEXER: &[u8] = b"/run/systemd/userdb/io.systemd.Multiplexer";
    let except = crate::env::getenv("SYSTEMD_BYPASS_USERDB").filter(|e| crate::parse::parse_boolean(e).is_err());
    let only = crate::env::getenv("SYSTEMD_ONLY_USERDB");
    let listed = |l: &Option<Vec<u8>>| {
        l.as_ref().is_some_and(|l| l.split(|&c| c == b':').any(|x| x == b"io.systemd.Multiplexer"))
    };
    if !listed(&except) && (only.is_none() || listed(&only)) {
        let r = match crate::sys_net::unix_connect_probe(MULTIPLEXER) {
            Err(e) => e,
            // Something listens, but this port speaks no varlink.
            Ok(()) => -libc::EPROTONOSUPPORT,
        };
        crate::log_debug_errno!(r, "json-stream: Failed to connect to ", MULTIPLEXER, ": ", crate::errno::strerror(r));
        crate::log_debug_errno!(r, "Unable to connect to ", MULTIPLEXER, ": ", crate::errno::strerror(r));
    }
}

/// `userdb_block_nss_systemd(b)`: libnss_systemd is probed (and its
/// absence logged), never called.
fn block_nss_systemd() {
    const LIB: &[u8] = b"/usr/lib64/libnss_systemd.so.2";
    match crate::sys_acl::dlopen_probe(LIB) {
        Err((r, dle)) => {
            crate::log_debug_errno!(
                r,
                "Failed to dlopen(libnss_systemd.so.2), ignoring: ",
                dle.unwrap_or_else(|| crate::errno::strerror(r))
            );
        }
        Ok(()) => {
            crate::log_debug!("Loaded '", LIB, "' via dlopen()");
        }
    }
}

fn by_name(name: &[u8], group: bool) -> Result<u32, i32> {
    if let Ok(u) = parse_uid(name) {
        if u == u32::MAX {
            return Err(-libc::EINVAL);
        }
        // userdb_by_uid(): the query, then the fallbacks with NSS
        // blocked and unblocked around them.
        start_query();
        block_nss_systemd();
        block_nss_systemd();
        return by_id(u);
    }
    if !valid_user_group_name_relaxed(name) {
        return Err(-libc::EINVAL);
    }
    start_query();
    block_nss_systemd();
    let r = by_name_fallbacks(name, group);
    block_nss_systemd();
    r
}

fn by_name_fallbacks(name: &[u8], group: bool) -> Result<u32, i32> {
    let nss = if group { sys::getgrnam_id(name) } else { sys::getpwnam_ids(name).map(|o| o.map(|(u, _, _)| u)) };
    if let Ok(Some(id)) = nss {
        return Ok(id);
    }
    if name == b"root" {
        return Ok(0);
    }
    if name == b"nobody" && synthesize_nobody() {
        return Ok(UID_NOBODY);
    }
    if let Some(f) = foreign_extract(name) {
        return Ok(FOREIGN_UID_BASE + f);
    }
    Err(-libc::ESRCH)
}

/// `userdb_by_name(name, NULL, flags, &ur)`: the UID.
pub fn userdb_uid_by_name(name: &[u8]) -> Result<u32, i32> {
    by_name(name, false)
}

/// `groupdb_by_name(name, NULL, flags, &gr)`: the GID.
pub fn groupdb_gid_by_name(name: &[u8]) -> Result<u32, i32> {
    by_name(name, true)
}

/// `uid_is_system()` / `gid_is_system()`: `SYSTEM_UID_MAX` and
/// `SYSTEM_GID_MAX` are 999 in this build (and not read from
/// `login.defs`).
pub fn id_is_system(id: u32) -> bool {
    id <= 999
}
