// SPDX-License-Identifier: LGPL-2.1-or-later
//! `common-signal.c`'s `sigrtmin18_handler()`, and `sd_event_trim_memory()`.

use crate::sys::SignalInfo;
use crate::{log_debug, log_notice};

/// `sd_event_trim_memory()`.
pub fn trim_memory() {
    log_debug!("Memory pressure event, trimming malloc() memory.");
    let before = crate::time::now_monotonic();
    let (trimmed, l) = crate::sys::malloc_trim_info();
    let after = crate::time::now_monotonic();
    if trimmed {
        log_debug!("Successfully trimmed some memory.");
    } else {
        log_debug!("Couldn't trim any memory.");
    }
    log_debug!(
        "Memory trimming took ",
        crate::time::format_timespan(after - before, 0),
        ", returned ",
        crate::time::format_bytes(l as u64),
        " to OS."
    );
}

/// `si_code_from_process()`.
fn si_code_from_process(code: i32) -> bool {
    matches!(code, libc::SI_USER | libc::SI_QUEUE | libc::SI_TKILL)
}

/// `sigrtmin18_handler(s, si, NULL)`.
pub fn sigrtmin18_handler(si: &SignalInfo) -> i32 {
    let sig = crate::signal::signal_to_string(si.signo as i32);
    if !si_code_from_process(si.code) {
        log_notice!("Received control signal ", sig, " with unexpected .si_code ", si.code.to_string(), ", ignoring.");
        return 0;
    }
    let comm = crate::fileio::read_one_line_file(format!("/proc/{}/comm", si.pid).as_bytes()).ok();
    let comm = comm.as_deref().unwrap_or(b"n/a");
    if si.code != libc::SI_QUEUE {
        log_notice!(
            "Received control signal ",
            sig,
            " from process ",
            si.pid.to_string(),
            " (",
            comm,
            ") without command value, ignoring."
        );
        return 0;
    }
    log_debug!(
        "Received control signal ",
        &sig[..],
        " from process ",
        si.pid.to_string(),
        " (",
        comm,
        ") with command ",
        format!("0x{:08x}", si.int as u32),
        "."
    );
    use crate::log::LogTarget;
    match si.int {
        0x100..=0x107 => {
            crate::log::log_set_max_level(si.int - 0x100);
        }
        0x200 => crate::log::log_set_target_and_open(LogTarget::Console),
        0x201 => crate::log::log_set_target_and_open(LogTarget::Journal),
        0x202 => crate::log::log_set_target_and_open(LogTarget::Kmsg),
        0x203 => crate::log::log_set_target_and_open(LogTarget::Null),
        0x300 => trim_memory(),
        _ => {
            // COMMON_SIGNAL_COMMAND_MALLOC_INFO is not ported: malloc_info()
            // writes XML of glibc's internals, which is answered as unknown.
            log_notice!(
                "Received control signal ",
                sig,
                " with unknown command ",
                format!("0x{:08x}", si.int as u32),
                ", ignoring."
            );
        }
    }
    0
}
