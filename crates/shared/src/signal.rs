// SPDX-License-Identifier: LGPL-2.1-or-later
//! `signal-util.c`: signal names.

/// `signal_to_string()`: "INT", "TERM", ... (or "RTMIN+n").
pub fn signal_to_string(sig: i32) -> String {
    const NAMES: [&str; 32] = [
        "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
        "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF",
        "WINCH", "IO", "PWR", "SYS",
    ];
    if (1..32).contains(&sig) {
        return NAMES[sig as usize].to_string();
    }
    let min = libc::SIGRTMIN();
    let max = libc::SIGRTMAX();
    if sig >= min && sig <= max {
        if sig == min {
            return "RTMIN".to_string();
        }
        if sig == max {
            return "RTMAX".to_string();
        }
        return format!("RTMIN+{}", sig - min);
    }
    format!("{sig}")
}
