// SPDX-License-Identifier: LGPL-2.1-or-later
//! `offline-passwd.c`: user and group lookups in the passwd and group files
//! below --root=, without NSS.

use std::collections::HashMap;

use shared::path::path_extract_filename;
use shared::{log_debug, sys};

const PASSWD_FILES: [&[u8]; 2] = [b"/etc/passwd", b"/usr/lib/passwd"];
const GROUP_FILES: [&[u8]; 2] = [b"/etc/group", b"/usr/lib/group"];

/// `open_passwd_file()`: an fd to read from.
fn open_passwd_file(root: Option<&[u8]>, fname: &[u8]) -> Result<i32, i32> {
    let c = crate::chase_prefix_root(fname, root)?;
    let fd = c.fd.expect("requested");
    let rfd = shared::fd::fd_reopen(fd.raw(), libc::O_RDONLY | libc::O_CLOEXEC)?;
    if shared::log::enabled(libc::LOG_DEBUG) {
        let bn = path_extract_filename(fname).ok();
        log_debug!(
            "Reading ",
            shared::string::strna(bn.as_deref()),
            " entries from ",
            c.path.as_deref().unwrap_or_default(),
            "..."
        );
    }
    Ok(rfd)
}

/// `populate_uid_cache()`/`populate_gid_cache()`: the first entry for a
/// name wins.
pub fn populate_cache(root: Option<&[u8]>, users: bool) -> Result<HashMap<Vec<u8>, u32>, i32> {
    let mut cache = HashMap::new();
    for fname in if users { PASSWD_FILES } else { GROUP_FILES } {
        let fd = match open_passwd_file(root, fname) {
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => return Err(r),
            Ok(fd) => fd,
        };
        let entries = if users { sys::fgetpwent_all(fd) } else { sys::fgetgrent_all(fd) };
        for (name, id) in entries {
            cache.entry(name).or_insert(id);
        }
    }
    Ok(cache)
}
