// SPDX-License-Identifier: LGPL-2.1-or-later
//! `signal-util.c`: signal names.

const NAMES: [&str; 32] = [
    "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
    "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
    "IO", "PWR", "SYS",
];

/// `signal_to_string()`: "INT", "TERM", ... (or "RTMIN+n").
pub fn signal_to_string(sig: i32) -> String {
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

/// `signal_from_string()`: a positive signal number, or a negative errno.
pub fn signal_from_string(s: &[u8]) -> i32 {
    if let Ok(n) = crate::parse::safe_atoi(s) {
        return if (1..=64).contains(&n) { n } else { -libc::ERANGE };
    }
    let s = s.strip_prefix(b"SIG").unwrap_or(s);
    if let Some(i) = NAMES.iter().skip(1).position(|n| n.as_bytes() == s) {
        return i as i32 + 1;
    }
    let min = libc::SIGRTMIN();
    let max = libc::SIGRTMAX();
    if let Some(p) = s.strip_prefix(b"RTMIN") {
        if p.is_empty() {
            return min;
        }
        if p[0] != b'+' {
            return -libc::EINVAL;
        }
        return match crate::parse::safe_atoi(p) {
            Err(r) => r,
            Ok(n) if n < 0 || n > max - min => -libc::ERANGE,
            Ok(n) => n + min,
        };
    }
    if let Some(p) = s.strip_prefix(b"RTMAX") {
        if p.is_empty() {
            return max;
        }
        if p[0] != b'-' {
            return -libc::EINVAL;
        }
        return match crate::parse::safe_atoi(p) {
            Err(r) => r,
            Ok(n) if n > 0 || n < min - max => -libc::ERANGE,
            Ok(n) => n + max,
        };
    }
    -libc::EINVAL
}
