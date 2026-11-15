// SPDX-License-Identifier: LGPL-2.1-or-later
//! `capability-list.c` and the parts of `capability-util.c` tmpfiles uses.

use std::sync::atomic::{AtomicI32, Ordering};

use crate::errno::strerror;
use crate::log_debug_errno;

/// `CAP_LIMIT`.
pub const CAP_LIMIT: i32 = 62;

/// The kernel's capability names (`capability-list.txt`), by number.
const CAPABILITY_NAMES: [&str; 41] = [
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// `CAP_LAST_CAP` of the kernel headers systemd was built with.
const CAP_LAST_CAP: i32 = 40;

/// `capability_from_name()`: numbers 0..=CAP_LIMIT, or a name matched
/// case-insensitively (gperf --ignore-case).
pub fn capability_from_name(name: &[u8]) -> Result<i32, i32> {
    if let Ok(i) = crate::parse::safe_atoi(name) {
        if !(0..=CAP_LIMIT).contains(&i) {
            return Err(-libc::EINVAL);
        }
        return Ok(i);
    }
    CAPABILITY_NAMES.iter().position(|n| n.as_bytes().eq_ignore_ascii_case(name)).map(|i| i as i32).ok_or(-libc::EINVAL)
}

static SAVED_LAST_CAP: AtomicI32 = AtomicI32::new(i32::MAX);

/// `cap_last_cap()`.
pub fn cap_last_cap() -> i32 {
    let c = SAVED_LAST_CAP.load(Ordering::Relaxed);
    if c != i32::MAX {
        return c;
    }
    match crate::fileio::read_one_line_file(b"/proc/sys/kernel/cap_last_cap") {
        Err(r) => {
            log_debug_errno!(r, "Failed to read /proc/sys/kernel/cap_last_cap, ignoring: ", strerror(r));
        }
        Ok(content) => match crate::parse::safe_atoi(&content) {
            Err(r) => {
                log_debug_errno!(r, "Failed to parse /proc/sys/kernel/cap_last_cap, ignoring: ", strerror(r));
            }
            Ok(c) => {
                let c = c.min(CAP_LIMIT);
                SAVED_LAST_CAP.store(c, Ordering::Relaxed);
                return c;
            }
        },
    }
    // Fall back to probing with prctl(PR_CAPBSET_READ).
    let mut p = CAP_LAST_CAP.min(CAP_LIMIT);
    if crate::sys::capbset_read(p).is_err() {
        p -= 1;
        while p > 0 {
            if crate::sys::capbset_read(p).is_ok() {
                break;
            }
            p -= 1;
        }
    } else {
        while p < CAP_LIMIT {
            if crate::sys::capbset_read(p + 1).is_err() {
                break;
            }
            p += 1;
        }
    }
    SAVED_LAST_CAP.store(p, Ordering::Relaxed);
    p
}

/// `all_capabilities()`.
pub fn all_capabilities() -> u64 {
    u64::MAX >> (63 - cap_last_cap())
}
