// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `sd-login.c` and `login-util.c` that udev's uaccess builtin
//! uses: logind's (or elogind's) state files under /run/systemd.

use crate::env_file::parse_env_file;

/// `logind_running()`.
pub fn logind_running() -> bool {
    crate::sys::faccessat(libc::AT_FDCWD, b"/run/systemd/seats/", libc::F_OK, 0).is_ok()
}

/// `session_id_valid()`.
pub fn session_id_valid(id: &[u8]) -> bool {
    !id.is_empty() && id.iter().all(u8::is_ascii_alphanumeric)
}

fn file_of_session(session: &[u8]) -> Result<Vec<u8>, i32> {
    if !session_id_valid(session) {
        return Err(-libc::EINVAL);
    }
    Ok(crate::bcat!("/run/systemd/sessions/", session))
}

fn session_field(session: &[u8], key: &str) -> Result<Option<Vec<u8>>, i32> {
    let p = file_of_session(session)?;
    match parse_env_file(&p, &[key]) {
        Err(r) if r == -libc::ENOENT => Err(-libc::ENXIO),
        Err(r) => Err(r),
        Ok(mut v) => Ok(v.remove(0)),
    }
}

/// `sd_seat_get_active(seat, NULL, &uid)`.
pub fn seat_get_active_uid(seat: &[u8]) -> Result<u32, i32> {
    if !crate::path::filename_is_valid(seat) {
        return Err(-libc::EINVAL);
    }
    let p = crate::bcat!("/run/systemd/seats/", seat);
    let v = match parse_env_file(&p, &["ACTIVE", "ACTIVE_UID"]) {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENXIO),
        Err(r) => return Err(r),
        Ok(v) => v,
    };
    let t = v[1].as_ref().ok_or(-libc::ENODATA)?;
    crate::user::parse_uid(t)
}

/// `sd_get_sessions()`.
pub fn get_sessions() -> Result<Vec<Vec<u8>>, i32> {
    let mut dir = match crate::sys_net::opendir(b"/run/systemd/sessions/") {
        Ok(d) => d,
        Err(r) if r == -libc::ENOENT => return Ok(Vec::new()),
        Err(r) => return Err(r),
    };
    let mut out = Vec::new();
    while let Some((n, t)) = crate::conf_files::foreach_dirent_all(&mut dir)? {
        // dirent_is_file()
        if !(t == libc::DT_REG || t == libc::DT_LNK || t == libc::DT_UNKNOWN)
            || crate::conf_files::hidden_or_backup_file(&n)
        {
            continue;
        }
        out.push(n);
    }
    Ok(out)
}

/// `sd_session_get_state()`.
pub fn session_get_state(session: &[u8]) -> Result<Vec<u8>, i32> {
    match session_field(session, "STATE")? {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(-libc::EIO),
    }
}

/// `sd_session_get_uid()`.
pub fn session_get_uid(session: &[u8]) -> Result<u32, i32> {
    match session_field(session, "UID")? {
        Some(s) if !s.is_empty() => crate::user::parse_uid(&s),
        _ => Err(-libc::EIO),
    }
}

/// `sd_session_get_extra_device_access()`.
pub fn session_get_extra_device_access(session: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    Ok(match session_field(session, "EXTRA_DEVICE_ACCESS")? {
        Some(s) if !s.is_empty() => crate::string::strv_split(&s, crate::string::WHITESPACE),
        _ => Vec::new(),
    })
}
