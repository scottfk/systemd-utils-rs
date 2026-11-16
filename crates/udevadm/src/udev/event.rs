// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-event.c`: one event and what running the rules on it does.

use shared::errno::strerror;
use shared::sd_device::{Action, Dev};
use shared::{log_device_debug_errno, log_device_error_errno, log_device_warning_errno};

use super::builtin::BuiltinCommand;
use super::def::{Escape, EventMode, GID_INVALID, MODE_INVALID, UID_INVALID};
use super::rules::Rules;

/// `UdevEvent`.
#[derive(Debug)]
pub struct Event {
    pub dev: Dev,
    pub dev_parent: Option<Dev>,
    pub dev_db_clone: Option<Dev>,
    pub name: Option<Vec<u8>>,
    pub altnames: Vec<Vec<u8>>,
    pub program_result: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// `seclabel_list`, in insertion order.
    pub seclabel_list: Vec<(Vec<u8>, Vec<u8>)>,
    /// `run_list`: command → builtin, in insertion order.
    pub run_list: Vec<(Vec<u8>, Option<BuiltinCommand>)>,
    /// `written_sysattrs`, in insertion order (C's hash order varies).
    pub written_sysattrs: Vec<(Vec<u8>, Vec<u8>)>,
    pub written_sysctls: Vec<(Vec<u8>, Vec<u8>)>,
    pub birth_usec: u64,
    pub builtin_run: u32,
    pub builtin_ret: u32,
    pub esc: Escape,
    pub inotify_watch: bool,
    pub inotify_watch_final: bool,
    pub group_final: bool,
    pub owner_final: bool,
    pub mode_final: bool,
    pub name_final: bool,
    pub devlink_final: bool,
    pub run_final: bool,
    pub trace: bool,
    pub log_level_was_debug: bool,
    pub default_log_level: i32,
    pub event_mode: EventMode,
    /// The worker's global properties (`udevadm control -p`), for udevd.
    pub worker_properties: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    /// The worker's `timeout_usec`, `timeout_signal` and `exec_delay_usec`.
    pub worker_timeouts: Option<(u64, i32, u64)>,
}

/// `DEFAULT_WORKER_TIMEOUT_USEC`.
pub const DEFAULT_WORKER_TIMEOUT_USEC: u64 = 180 * shared::time::USEC_PER_SEC;

impl Event {
    /// `udev_event_new(dev, worker=NULL, mode)`.
    pub fn new(dev: &Dev, mode: EventMode) -> Event {
        let log_level = shared::log::log_get_max_level();
        Event {
            dev: dev.clone(),
            dev_parent: None,
            dev_db_clone: None,
            name: None,
            altnames: Vec::new(),
            program_result: None,
            mode: MODE_INVALID,
            uid: UID_INVALID,
            gid: GID_INVALID,
            seclabel_list: Vec::new(),
            run_list: Vec::new(),
            written_sysattrs: Vec::new(),
            written_sysctls: Vec::new(),
            birth_usec: shared::time::now_monotonic(),
            builtin_run: 0,
            builtin_ret: 0,
            esc: Escape::Unset,
            inotify_watch: false,
            inotify_watch_final: false,
            group_final: false,
            owner_final: false,
            mode_final: false,
            name_final: false,
            devlink_final: false,
            run_final: false,
            trace: false,
            log_level_was_debug: log_level == shared::log::LOG_DEBUG,
            default_log_level: log_level,
            event_mode: mode,
            worker_properties: None,
            worker_timeouts: None,
        }
    }

    /// `EVENT_MODE_DESTRUCTIVE(event)`.
    pub fn destructive(&self) -> bool {
        matches!(self.event_mode, EventMode::UdevWorker | EventMode::TestRuleRunner)
    }
}

/// `update_devnode()`.
fn update_devnode(event: &mut Event) -> Result<(), i32> {
    if !event.destructive() {
        return Ok(());
    }
    let dev = event.dev.clone();
    match dev.get_devnum() {
        Err(r) if r == -libc::ENOENT => return Ok(()),
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get devnum: ", strerror(r))),
        Ok(_) => {}
    }
    if event.uid == UID_INVALID {
        match dev.get_devnode_uid() {
            Ok(u) => event.uid = u,
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get devnode UID: ", strerror(r))),
        }
    }
    if event.gid == GID_INVALID {
        match dev.get_devnode_gid() {
            Ok(g) => event.gid = g,
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get devnode GID: ", strerror(r))),
        }
    }
    if event.mode == MODE_INVALID {
        match dev.get_devnode_mode() {
            Ok(m) => event.mode = m,
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get devnode mode: ", strerror(r))),
        }
    }
    let apply_mac = super::util::device_for_action(&dev, Action::Add);
    if let Err(r) = super::node::udev_node_apply_permissions(
        &dev,
        apply_mac,
        event.mode,
        event.uid,
        event.gid,
        &event.seclabel_list,
    ) {
        return Err(log_device_error_errno!(dev, r, "Failed to apply devnode permissions: ", strerror(r)));
    }
    let old = event.dev_db_clone.clone().expect("cloned");
    super::node::udev_node_update(&dev, &old)
}

/// `event_execute_rules_on_remove()`.
fn event_execute_rules_on_remove(event: &mut Event, rules: &Rules) -> Result<(), i32> {
    let dev = event.dev.clone();
    if let Err(r) = dev.read_db_internal(true) {
        log_device_debug_errno!(dev, r, "Failed to read database under /run/udev/data/: ", strerror(r));
    }
    if event.destructive() {
        if let Err(r) = dev.tag_index(false) {
            log_device_debug_errno!(
                dev,
                r,
                "Failed to remove corresponding tag files under /run/udev/tag/, ignoring: ",
                strerror(r)
            );
        }
        if let Err(r) = dev.delete_db() {
            log_device_debug_errno!(dev, r, "Failed to delete database under /run/udev/data/, ignoring: ", strerror(r));
        }
    }
    let r = rules.apply_to_event(event);
    if event.destructive() && dev.get_devnum().is_ok() {
        let _ = super::node::udev_node_remove(&dev);
    }
    r
}

/// `update_clone()`.
fn update_clone(event: &mut Event) -> Result<(), i32> {
    if !event.destructive() {
        return Ok(());
    }
    let dev = event.dev_db_clone.clone().expect("cloned");
    if let Err(r) = dev.add_property(b"ID_RENAMING", None) {
        return Err(log_device_debug_errno!(dev, r, "Failed to remove 'ID_RENAMING' property: ", strerror(r)));
    }
    if dev.has_db().unwrap_or(false) {
        if let Err(r) = dev.add_property(b"ID_PROCESSING", Some(b"1")) {
            return Err(log_device_warning_errno!(dev, r, "Failed to add 'ID_PROCESSING' property: ", strerror(r)));
        }
        if let Err(r) = dev.update_db() {
            return Err(log_device_warning_errno!(
                dev,
                r,
                "Failed to update database under /run/udev/data/: ",
                strerror(r)
            ));
        }
    }
    Ok(())
}

/// `udev_event_execute_rules(event, rules)`.
pub fn udev_event_execute_rules(event: &mut Event, rules: &Rules) -> Result<(), i32> {
    let dev = event.dev.clone();
    let action = match dev.get_action() {
        Ok(a) => a,
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get ACTION: ", strerror(r))),
    };
    if action == Action::Remove {
        return event_execute_rules_on_remove(event, rules);
    }
    let clone = match dev.clone_with_db() {
        Ok(c) => c,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to clone sd_device object: ", strerror(r))),
    };
    event.dev_db_clone = Some(clone.clone());
    if let Err(r) = dev.copy_all_tags(Some(&clone)) {
        log_device_warning_errno!(dev, r, "Failed to copy all tags from old database entry, ignoring: ", strerror(r));
    }
    update_clone(event)?;
    if let Err(r) = rules.apply_to_event(event) {
        return Err(log_device_debug_errno!(dev, r, "Failed to apply udev rules: ", strerror(r)));
    }
    if action == Action::Add {
        // rename_netif() and assign_altnames() only do something in
        // destructive mode, which is udevd's (phase 6).
        if event.destructive()
            && let Some(name) = &event.name
            && dev.get_ifindex().is_ok()
            && dev.get_ifname().is_ok_and(|n| n.bytes() != &name[..])
        {
            return Err(log_device_error_errno!(
                dev,
                shared::errno::synthetic(libc::EOPNOTSUPP),
                "Renaming network interfaces is not ported yet."
            ));
        }
    }
    update_devnode(event)?;
    if let Err(r) = dev.ensure_usec_initialized(Some(&clone)) {
        return Err(log_device_debug_errno!(dev, r, "Failed to set initialization timestamp: ", strerror(r)));
    }
    if event.destructive()
        && let Err(r) = dev.tag_index(true)
    {
        return Err(log_device_debug_errno!(dev, r, "Failed to update tags under /run/udev/tag/: ", strerror(r)));
    }
    if dev.should_have_db()
        && !event.run_list.is_empty()
        && let Err(r) = dev.add_property(b"ID_PROCESSING", Some(b"1"))
    {
        return Err(log_device_warning_errno!(dev, r, "Failed to add 'ID_PROCESSING' property: ", strerror(r)));
    }
    if event.destructive()
        && let Err(r) = dev.update_db()
    {
        return Err(log_device_debug_errno!(dev, r, "Failed to update database under /run/udev/data/: ", strerror(r)));
    }
    dev.set_is_initialized();
    Ok(())
}
