// SPDX-License-Identifier: LGPL-2.1-or-later
//! `process-util.c`: `safe_fork()` for the flags the ported code uses.
//!
//! Known difference: `rename_process()` only sets the comm name
//! (`PR_SET_NAME`); it does not rewrite argv[0] in place.

use crate::errno::strerror;
use crate::{log_debug, log_full_errno, sys};

pub const FORK_RESET_SIGNALS: u32 = 1 << 0;
pub const FORK_DEATHSIG_SIGTERM: u32 = 1 << 2;
pub const FORK_DEATHSIG_SIGINT: u32 = 1 << 3;
pub const FORK_DEATHSIG_SIGKILL: u32 = 1 << 4;
pub const FORK_LOG: u32 = 1 << 7;
pub const FORK_WAIT: u32 = 1 << 8;
pub const FORK_RLIMIT_NOFILE_SAFE: u32 = 1 << 11;
pub const FORK_CLOSE_ALL_FDS: u32 = 1 << 1;
pub const FORK_REARRANGE_STDIO: u32 = 1 << 5;

fn deathsig(flags: u32) -> Option<i32> {
    if flags & FORK_DEATHSIG_SIGTERM != 0 {
        Some(libc::SIGTERM)
    } else if flags & FORK_DEATHSIG_SIGINT != 0 {
        Some(libc::SIGINT)
    } else if flags & FORK_DEATHSIG_SIGKILL != 0 {
        Some(libc::SIGKILL)
    } else {
        None
    }
}

/// `pidref_safe_fork(name, flags, &pid)`: `Ok(0)` in the child, the pid in the parent.
pub fn safe_fork(name: &str, flags: u32) -> Result<i32, i32> {
    safe_fork_full(name, None, &[], flags)
}

/// `pidref_safe_fork_full(name, stdio_fds, except_fds, n, flags, &pid)`.
pub fn safe_fork_full(name: &str, stdio: Option<[i32; 3]>, except: &[i32], flags: u32) -> Result<i32, i32> {
    let prio = if flags & FORK_LOG != 0 { libc::LOG_ERR } else { libc::LOG_DEBUG };
    let original_pid = sys::getpid();
    let block = flags & (FORK_RESET_SIGNALS | FORK_DEATHSIG_SIGTERM | FORK_DEATHSIG_SIGINT) != 0;
    let saved = if block { Some(sys::block_all_signals()) } else { None };
    let pid = match sys::fork() {
        Ok(p) => p,
        Err(e) => {
            if let Some(s) = saved {
                sys::restore_signal_mask(&s);
            }
            return Err(log_full_errno!(prio, e, "Failed to fork off '", name, "': ", strerror(e)));
        }
    };
    if pid > 0 {
        if let Some(s) = saved {
            sys::restore_signal_mask(&s);
        }
        log_debug!("Successfully forked off '", name, "' as PID ", pid.to_string(), ".");
        if flags & FORK_WAIT != 0 {
            let _ = sys::wait_for_terminate(pid);
        }
        return Ok(pid);
    }
    let r = crate::argv::rename_process(name.as_bytes());
    if r < 0 {
        log_full_errno!(
            if flags & FORK_LOG != 0 { libc::LOG_WARNING } else { libc::LOG_DEBUG },
            r,
            "Failed to rename process, ignoring: ",
            strerror(r)
        );
    }
    crate::sys_acl::block_dlopen();
    if let Some(sig) = deathsig(flags)
        && let Err(r) = sys::set_pdeathsig(sig)
    {
        log_full_errno!(prio, r, "Failed to set death signal: ", strerror(r));
        sys::exit_now(libc::EXIT_FAILURE);
    }
    if flags & FORK_RESET_SIGNALS != 0 {
        sys::reset_signals();
    } else if let Some(s) = saved {
        sys::restore_signal_mask(&s);
    }
    if let Some(sig) = deathsig(flags) {
        let ppid = sys::getppid();
        if ppid != 0 && ppid != original_pid {
            log_debug!("Parent died early, raising ", crate::signal::signal_to_string(sig), ".");
            let _ = sys::kill(sys::getpid(), sig);
            sys::exit_now(libc::EXIT_FAILURE);
        }
    }
    if flags & FORK_REARRANGE_STDIO != 0 {
        let fds = stdio.unwrap_or([-libc::EBADF; 3]);
        if let Err(r) = sys::rearrange_stdio(fds) {
            log_full_errno!(prio, r, "Failed to rearrange stdio fds: ", strerror(r));
            sys::exit_now(libc::EXIT_FAILURE);
        }
    }
    if flags & FORK_CLOSE_ALL_FDS != 0 {
        crate::log::log_close();
        if let Err(r) = sys::close_all_fds_except(except) {
            log_full_errno!(prio, r, "Failed to close all file descriptors: ", strerror(r));
            sys::exit_now(libc::EXIT_FAILURE);
        }
    }
    if flags & FORK_RLIMIT_NOFILE_SAFE != 0 {
        let r = rlimit_nofile_safe();
        if r < 0 {
            log_full_errno!(prio, r, "Failed to lower RLIMIT_NOFILE's soft limit to 1K: ", strerror(r));
            sys::exit_now(libc::EXIT_FAILURE);
        }
    }
    if let Err(r) = sys::unsetenv(b"NOTIFY_SOCKET") {
        log_full_errno!(prio, r, "Failed to unset $NOTIFY_SOCKET: ", strerror(r));
        sys::exit_now(libc::EXIT_FAILURE);
    }
    Ok(0)
}

/// `read_nr_open()`.
fn read_nr_open() -> u64 {
    match crate::fileio::read_one_line_file(b"/proc/sys/fs/nr_open") {
        Err(r) => {
            crate::log_debug_errno!(r, "Failed to read /proc/sys/fs/nr_open, ignoring: ", strerror(r));
        }
        Ok(v) => match crate::parse::safe_atou(&v) {
            Ok(n) => return n as u64,
            Err(r) => {
                crate::log_debug_errno!(
                    r,
                    "Failed to parse /proc/sys/fs/nr_open value '",
                    v,
                    "', ignoring: ",
                    strerror(r)
                );
            }
        },
    }
    1024 * 1024
}

/// `rlimit_nofile_safe()`.
pub fn rlimit_nofile_safe() -> i32 {
    let (cur, max) = match sys::getrlimit_nofile() {
        Ok(x) => x,
        Err(e) => return crate::log_debug_errno!(e, "Failed to query RLIMIT_NOFILE: ", strerror(e)),
    };
    if cur <= 1024 {
        return 0;
    }
    let max = max.min(read_nr_open());
    let cur = 1024u64.min(max);
    if let Err(e) = sys::setrlimit_nofile(cur, max) {
        return crate::log_debug_errno!(
            e,
            "Failed to lower RLIMIT_NOFILE's soft limit to ",
            cur.to_string(),
            ": ",
            strerror(e)
        );
    }
    1
}
