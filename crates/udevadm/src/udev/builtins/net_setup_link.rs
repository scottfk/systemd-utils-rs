// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-net_setup_link.c`: apply the matching `.link` file.

use std::cell::RefCell;

use shared::errno::{strerror, synthetic};
use shared::netif_naming_scheme::{NAMING_USE_INTERFACE_PROPERTY, naming_scheme_has};
use shared::sd_device::{Action, device_action_to_string};
use shared::{log_debug, log_device_debug, log_device_debug_errno, log_device_error_errno, log_device_warning_errno};

use super::super::builtin::{udev_builtin_add_property, udev_builtin_import_property};
use super::super::event::Event;
use super::super::net::link::{link_apply_config, link_get_config, link_new};
use super::super::net::link_config::LinkConfigContext;

thread_local! {
    static CTX: RefCell<Option<LinkConfigContext>> = const { RefCell::new(None) };
}

/// `builtin_net_setup_link()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if argv.len() > 1 {
        return Err(log_device_error_errno!(dev, synthetic(libc::EINVAL), "This program takes no arguments."));
    }
    let action =
        dev.get_action().map_err(|r| log_device_error_errno!(dev, r, "Failed to get action: ", strerror(r)))?;
    if !matches!(action, Action::Add | Action::Bind | Action::Move) {
        log_device_debug!(dev, "Not applying .link settings on '", device_action_to_string(action), "' uevent.");
        let _ = udev_builtin_import_property(event, b"ID_NET_LINK_FILE");
        let _ = udev_builtin_import_property(event, b"ID_NET_LINK_FILE_DROPINS");
        let value = if naming_scheme_has(NAMING_USE_INTERFACE_PROPERTY) {
            dev.get_ifname().map(|v| v.bytes().to_vec())
        } else {
            dev.get_sysname().map(|v| v.bytes().to_vec())
        };
        if let Ok(v) = value {
            let _ = udev_builtin_add_property(event, b"ID_NET_NAME", Some(&v));
        }
        return Ok(());
    }
    CTX.with(|c| {
        let mut guard = c.borrow_mut();
        let ctx = guard.as_mut().ok_or(-libc::EINVAL)?;
        let mut link = match link_new(ctx, event) {
            Err(r) if r == -libc::ENODEV => {
                log_device_debug_errno!(dev, r, "Link vanished while getting information, ignoring.");
                return Ok(());
            }
            Err(r) => {
                return Err(log_device_warning_errno!(dev, r, "Failed to get link information: ", strerror(r)));
            }
            Ok(l) => l,
        };
        match link_get_config(ctx, &mut link, event) {
            Err(r) if r == -libc::ENOENT => {
                log_device_debug_errno!(dev, r, "No matching link configuration found, ignoring device.");
                return Ok(());
            }
            Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get link config: ", strerror(r))),
            Ok(()) => {}
        }
        match link_apply_config(ctx, &mut link, event) {
            Err(r) if r == -libc::ENODEV => {
                log_device_debug_errno!(dev, r, "Link vanished while applying configuration, ignoring.");
            }
            Err(r) => {
                log_device_warning_errno!(dev, r, "Could not apply link configuration, ignoring: ", strerror(r));
            }
            Ok(()) => {}
        }
        Ok(())
    })
}

/// `builtin_net_setup_link_init()`.
pub fn init() {
    CTX.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_some() {
            return;
        }
        let mut ctx = LinkConfigContext::default();
        if ctx.load() < 0 {
            return;
        }
        *c = Some(ctx);
        log_debug!("Loaded link configuration context.");
    });
}

/// `builtin_net_setup_link_exit()`.
pub fn exit() {
    CTX.with(|c| *c.borrow_mut() = None);
    log_debug!("Unloaded link configuration context.");
}

/// `builtin_net_setup_link_should_reload()`.
pub fn should_reload() -> bool {
    CTX.with(|c| {
        let c = c.borrow();
        let Some(ctx) = c.as_ref() else { return false };
        if ctx.should_reload() {
            log_debug!("Link configuration context needs reloading.");
            return true;
        }
        false
    })
}
