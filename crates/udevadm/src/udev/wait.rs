// SPDX-License-Identifier: LGPL-2.1-or-later
//! `device_wait_for_initialization()` and `device_is_processed()`
//! (`udev-util.c`), with a poll loop in place of sd-event.

use shared::device_monitor::Monitor;
use shared::errno::strerror;
use shared::sd_device::{Action, Dev, Device};
use shared::time::{USEC_INFINITY, now_monotonic};
use shared::{log_device_error_errno, log_error_errno};

/// `device_is_processed(dev)`.
pub fn device_is_processed(dev: &Device) -> Result<bool, i32> {
    if !dev.get_is_initialized()? {
        return Ok(false);
    }
    match dev.get_property_bool(b"ID_PROCESSING") {
        Err(r) if r == -libc::ENOENT => Ok(true),
        Err(r) => Err(r),
        Ok(b) => Ok(!b),
    }
}

/// `device_wait_for_initialization(device, subsystem=NULL, timeout_usec, &ret)`.
pub fn device_wait_for_initialization(device: &Dev, timeout_usec: u64) -> Result<Dev, i32> {
    if device_is_processed(device).unwrap_or(false) {
        return Ok(device.clone());
    }
    let sysname = device.get_sysname().ok().map(|s| s.bytes().to_vec());
    let mut monitor = match Monitor::new() {
        Ok(m) => m,
        Err(r) => return Err(log_error_errno!(r, "Failed to acquire monitor: ", strerror(r))),
    };
    let subsystem = match device.get_subsystem() {
        Ok(s) => Some(s.bytes().to_vec()),
        Err(r) if r == -libc::ENOENT => None,
        Err(r) => return Err(log_device_error_errno!(device, r, "Failed to get subsystem: ", strerror(r))),
    };
    if let Some(s) = &subsystem {
        monitor.filter_add_match_subsystem_devtype(s, None);
    }
    let desc = shared::bcat!(sysname.as_deref().or(subsystem.as_deref()).unwrap_or_default(), ":initialization");
    monitor.set_description(Some(&desc));
    // sd_device_monitor_start()
    if let Err(r) = monitor.filter_update() {
        return Err(log_error_errno!(r, "Failed to start device monitor: ", strerror(r)));
    }
    let deadline = if timeout_usec == USEC_INFINITY { u64::MAX } else { now_monotonic().saturating_add(timeout_usec) };
    // Check again, maybe things changed.
    if device_is_processed(device).unwrap_or(false) {
        return Ok(device.clone());
    }
    loop {
        let wait = if deadline == u64::MAX { u64::MAX } else { deadline.saturating_sub(now_monotonic()) };
        if wait == 0 {
            let r = -libc::ETIMEDOUT;
            return Err(log_error_errno!(r, "Failed to wait for device to be initialized: ", strerror(r)));
        }
        match shared::sys_net::poll_one(monitor.get_fd(), libc::POLLIN, wait) {
            Err(r) if r == -libc::EINTR => continue,
            Err(r) => return Err(log_error_errno!(r, "Failed to wait for device to be initialized: ", strerror(r))),
            Ok(0) => continue,
            Ok(_) => {}
        }
        let Ok(Some(d)) = monitor.receive() else { continue };
        if super::util::device_for_action(&d, Action::Remove) {
            continue;
        }
        if let Some(s) = &sysname
            && d.get_sysname().is_ok_and(|n| n.bytes() == &s[..])
        {
            return Ok(d);
        }
    }
}
