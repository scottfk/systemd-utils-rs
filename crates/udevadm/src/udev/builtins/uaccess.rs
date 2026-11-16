// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-uaccess.c`: device node ACLs for the seat's active user
//! and for sessions with extra device access.

use shared::errno::strerror;
use shared::log::{LOG_DEBUG, LOG_ERR, LOG_WARNING};
use shared::sd_login;
use shared::{log_device_debug, log_device_debug_errno, log_device_error_errno, log_device_full_errno};

use super::super::def::EventMode;
use super::super::event::Event;

/// `builtin_uaccess()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if event.event_mode != EventMode::UdevWorker {
        log_device_debug!(dev, "Running in test mode, skipping execution of 'uaccess' builtin command.");
        return Ok(());
    }
    shared::sys::umask(0o022);
    if !sd_login::logind_running() {
        return Ok(());
    }
    let fd = match shared::blockdev::sd_device_open(&dev, libc::O_CLOEXEC | libc::O_PATH) {
        Ok(f) => f,
        Err(r) => {
            let ignore = shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM;
            log_device_full_errno!(
                dev,
                if ignore { LOG_DEBUG } else { LOG_WARNING },
                r,
                "Failed to open device node",
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { Ok(()) } else { Err(r) };
        }
    };
    let mut uids: Vec<u32> = Vec::new();
    let put = |uids: &mut Vec<u32>, u: u32| {
        if !uids.contains(&u) {
            uids.push(u);
        }
    };
    if dev.has_tag(b"uaccess") {
        // device_get_seat()
        let seat = match dev.get_property_value(b"ID_SEAT") {
            Ok(s) if !s.bytes().is_empty() => s.bytes().to_vec(),
            Ok(_) => b"seat0".to_vec(),
            Err(r) if r == -libc::ENOENT => b"seat0".to_vec(),
            Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get seat: ", strerror(r))),
        };
        match sd_login::seat_get_active_uid(&seat) {
            Ok(u) => put(&mut uids, u),
            Err(r) if r == -libc::ENXIO || r == -libc::ENODATA => {}
            Err(r) => {
                log_device_error_errno!(
                    dev,
                    r,
                    "Failed to determine active user on seat ",
                    &seat[..],
                    ", ignoring: ",
                    strerror(r)
                );
            }
        }
    }
    if dev.current_tags().iter().any(|t| t.bytes().starts_with(b"xaccess-")) {
        let sessions = sd_login::get_sessions()
            .map_err(|r| log_device_error_errno!(dev, r, "Failed to list sessions: ", strerror(r)))?;
        for s in &sessions {
            let state = match sd_login::session_get_state(s) {
                Ok(st) => st,
                Err(r) => {
                    log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to query state for session ",
                        &s[..],
                        ", ignoring: ",
                        strerror(r)
                    );
                    continue;
                }
            };
            if state == b"closing" {
                continue;
            }
            let uid = match sd_login::session_get_uid(s) {
                Ok(u) => u,
                Err(r) => {
                    log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to query uid for session ",
                        &s[..],
                        ", ignoring: ",
                        strerror(r)
                    );
                    continue;
                }
            };
            let extra = match sd_login::session_get_extra_device_access(s) {
                Ok(e) => e,
                Err(r) => {
                    log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to query extra device access for session ",
                        &s[..],
                        ", ignoring: ",
                        strerror(r)
                    );
                    continue;
                }
            };
            if extra.iter().any(|id| dev.has_current_tag(&shared::bcat!("xaccess-", &id[..]))) {
                put(&mut uids, uid);
            }
        }
    }
    let lvl = |r: i32| if r == -libc::ENOENT { LOG_DEBUG } else { LOG_ERR };
    let Err(r) = shared::sys_acl::devnode_acl(fd.raw(), &uids) else { return Ok(()) };
    log_device_full_errno!(dev, lvl(r), r, "Failed to apply ACL: ", strerror(r));
    // Better be safe than sorry and reset the ACL.
    if let Err(k) = shared::sys_acl::devnode_acl(fd.raw(), &[]) {
        log_device_full_errno!(dev, lvl(k), k, "Failed to flush ACLs: ", strerror(k));
    }
    Err(r)
}
