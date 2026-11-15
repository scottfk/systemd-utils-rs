// SPDX-License-Identifier: LGPL-2.1-or-later
//! `pager.c`: pipe stdout and stderr through `less` (or $SYSTEMD_PAGER,
//! $PAGER) when they are a terminal.
//!
//! Known difference: `sd_pid_get_owner_uid()` is approximated by looking
//! for a `user-UID.slice` in our own unified cgroup path; without systemd
//! (OpenRC) both find no owner, so secure mode is chosen.

use std::cell::Cell;

use crate::env::{getenv, secure_getenv_bool, set_unset_env};
use crate::errno::strerror;
use crate::fileio::{CReader, LONG_LINE_MAX, read_line_full};
use crate::locale::{is_locale_utf8, is_main_thread};
use crate::process::{FORK_DEATHSIG_SIGINT, FORK_LOG, FORK_RESET_SIGNALS, FORK_RLIMIT_NOFILE_SAFE, safe_fork};
use crate::string::{WHITESPACE, strv_split, yes_no};
use crate::terminal::{columns, lines, terminal_is_dumb};
use crate::{log_debug, log_debug_errno, log_error_errno, log_full_errno, log_warning_errno, sys};

pub const PAGER_DISABLE: u32 = 1 << 0;
pub const PAGER_JUMP_TO_END: u32 = 1 << 1;

thread_local! {
    static PAGER_PID: Cell<i32> = const { Cell::new(0) };
    static STORED_STDOUT: Cell<i32> = const { Cell::new(-1) };
    static STORED_STDERR: Cell<i32> = const { Cell::new(-1) };
    static STDOUT_REDIRECTED: Cell<bool> = const { Cell::new(false) };
    static STDERR_REDIRECTED: Cell<bool> = const { Cell::new(false) };
}

/// `pager_fallback()`: copy stdin to stdout.
fn pager_fallback() -> ! {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match sys::read(0, &mut buf) {
            Ok(0) => sys::exit_now(libc::EXIT_SUCCESS),
            Ok(n) => {
                if let Err(r) = sys::write_all(1, &buf[..n]) {
                    log_error_errno!(r, "Internal pager failed: ", strerror(r));
                    sys::exit_now(libc::EXIT_FAILURE);
                }
            }
            Err(e) if e == -libc::EINTR => {}
            Err(r) => {
                log_error_errno!(r, "Internal pager failed: ", strerror(r));
                sys::exit_now(libc::EXIT_FAILURE);
            }
        }
    }
}

/// `no_quit_on_interrupt()`: did we end up running `less` without "K"?
fn no_quit_on_interrupt(exe_name_fd: i32, less_opts: &[u8]) -> Result<bool, i32> {
    let mut f = CReader::from_fd(exe_name_fd);
    let mut line: Option<Vec<u8>> = None;
    loop {
        match read_line_full(&mut f, LONG_LINE_MAX, false) {
            Ok((0, _)) => break,
            Ok((_, t)) => line = Some(t),
            Err(r) => return Err(log_error_errno!(r, "Failed to read from socket: ", strerror(r))),
        }
    }
    let r = line.as_deref() == Some(b"less") && !less_opts.contains(&b'K');
    log_debug!(
        "Pager executable is \"",
        crate::string::strnull(line.as_deref()),
        "\", options \"",
        less_opts,
        "\", quit_on_interrupt: ",
        yes_no(!r)
    );
    Ok(r)
}

/// `sd_pid_get_owner_uid(0, &uid)`, approximated (see the module docs).
fn sd_pid_get_owner_uid() -> Result<u32, i32> {
    let data = crate::fileio::read_full_file(b"/proc/self/cgroup")?;
    let path = data
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"0::"))
        .ok_or(-libc::ENOMEDIUM)
        .map_err(|_| -libc::ENODATA)?;
    let mut p = path;
    let mut slice: Option<Vec<u8>> = None;
    loop {
        let Ok((n, s)) = crate::path::path_find_first_component(&mut p, false) else {
            break;
        };
        if n == 0 || !s[..n].ends_with(b".slice") {
            break;
        }
        slice = Some(s[..n].to_vec());
    }
    let s = slice.ok_or(-libc::ENODATA)?;
    let uid = s
        .strip_prefix(b"user-")
        .and_then(|r| r.strip_suffix(b".slice"))
        .and_then(|u| crate::parse::safe_atou(u).ok())
        .ok_or(-libc::ENODATA)?;
    Ok(uid)
}

/// `running_with_escalated_privileges()`.
fn running_with_escalated_privileges() -> bool {
    if getenv("SUDO_UID").is_some() {
        return true;
    }
    match sd_pid_get_owner_uid() {
        Err(r) => {
            log_debug_errno!(r, "sd_pid_get_owner_uid() failed, enabling pager secure mode: ", strerror(r));
            true
        }
        Ok(uid) => uid != sys::geteuid(),
    }
}

/// `pager_open(flags)`.
pub fn pager_open(flags: u32) {
    if flags & PAGER_DISABLE != 0 || PAGER_PID.with(|p| p.get()) > 0 || terminal_is_dumb() {
        return;
    }
    if !is_main_thread() {
        log_error_errno!(crate::errno::synthetic(libc::EPERM), "Pager invoked from wrong thread.");
        return;
    }
    let pager = getenv("SYSTEMD_PAGER").or_else(|| getenv("PAGER"));
    let pager_args = pager.map(|p| strv_split(&p, WHITESPACE));
    if let Some(a) = &pager_args
        && (a.is_empty() || (a.len() == 1 && a[0] == b"cat"))
    {
        return;
    }
    columns();
    lines();
    let (fd0, fd1) = match sys::pipe2(libc::O_CLOEXEC) {
        Ok(p) => p,
        Err(e) => {
            log_error_errno!(e, "Failed to create pager pipe: ", strerror(e));
            return;
        }
    };
    let (ex0, ex1) = match sys::pipe2(libc::O_CLOEXEC) {
        Ok(p) => p,
        Err(e) => {
            sys::close(fd0);
            sys::close(fd1);
            log_error_errno!(e, "Failed to create exe_name pipe: ", strerror(e));
            return;
        }
    };
    let mut less_opts = getenv("SYSTEMD_LESS").unwrap_or_else(|| b"FRSXMK".to_vec());
    if flags & PAGER_JUMP_TO_END != 0 {
        less_opts.extend_from_slice(b" +G");
    }
    let pid = match safe_fork("(pager)", FORK_RESET_SIGNALS | FORK_DEATHSIG_SIGINT | FORK_RLIMIT_NOFILE_SAFE | FORK_LOG)
    {
        Ok(p) => p,
        Err(_) => {
            for fd in [fd0, fd1, ex0, ex1] {
                sys::close(fd);
            }
            return;
        }
    };
    if pid == 0 {
        if let Err(e) = sys::dup2(fd0, 0) {
            log_error_errno!(e, "Failed to duplicate file descriptor to STDIN: ", strerror(e));
            sys::exit_now(libc::EXIT_FAILURE);
        }
        sys::close(fd0);
        sys::close(fd1);
        if let Err(e) = sys::setenv(b"LESS", &less_opts) {
            log_error_errno!(e, "Failed to set environment variable LESS: ", strerror(e));
            sys::exit_now(libc::EXIT_FAILURE);
        }
        let mut less_charset = getenv("SYSTEMD_LESSCHARSET");
        if less_charset.is_none() && is_locale_utf8() {
            less_charset = Some(b"utf-8".to_vec());
        }
        if let Some(cs) = less_charset
            && let Err(e) = sys::setenv(b"LESSCHARSET", &cs)
        {
            log_error_errno!(e, "Failed to set environment variable LESSCHARSET: ", strerror(e));
            sys::exit_now(libc::EXIT_FAILURE);
        }
        let env = secure_getenv_bool("SYSTEMD_PAGERSECURE");
        let trust_pager = env.is_ok();
        let use_secure_mode = match env {
            Ok(b) => b,
            Err(r) if r == -libc::ENXIO => running_with_escalated_privileges(),
            Err(r) => {
                log_warning_errno!(r, "Unable to parse $SYSTEMD_PAGERSECURE, assuming true: ", strerror(r));
                true
            }
        };
        if let Err(r) = set_unset_env(b"LESSSECURE", if use_secure_mode { Some(b"1") } else { None }) {
            log_error_errno!(r, "Failed to adjust environment variable LESSSECURE: ", strerror(r));
            sys::exit_now(libc::EXIT_FAILURE);
        }
        if trust_pager && let Some(args) = &pager_args {
            let mut name = args[0].clone();
            name.push(0);
            if let Err(r) = sys::write_all(ex1, &name) {
                log_error_errno!(r, "Failed to write pager name to socket: ", strerror(r));
                sys::exit_now(libc::EXIT_FAILURE);
            }
            sys::execvp(&args[0], args);
            let e = sys::errno();
            log_full_errno!(
                if e == libc::ENOENT { libc::LOG_DEBUG } else { libc::LOG_WARNING },
                e,
                "Failed to execute '",
                args[0],
                "', using fallback pagers: ",
                strerror(e)
            );
        }
        const PAGERS: [&str; 4] = ["pager", "less", "more", "(built-in)"];
        for (i, p) in PAGERS.iter().enumerate() {
            if use_secure_mode && !matches!(*p, "less" | "(built-in)") {
                continue;
            }
            let mut name = p.as_bytes().to_vec();
            name.push(0);
            if let Err(r) = sys::write_all(ex1, &name) {
                log_error_errno!(r, "Failed to write pager name to socket: ", strerror(r));
                sys::exit_now(libc::EXIT_FAILURE);
            }
            if i < PAGERS.len() - 1 {
                sys::execvp(p.as_bytes(), &[p.as_bytes().to_vec()]);
                let e = sys::errno();
                log_full_errno!(
                    if e == libc::ENOENT { libc::LOG_DEBUG } else { libc::LOG_WARNING },
                    e,
                    "Failed to execute '",
                    *p,
                    "', will try '",
                    PAGERS[i + 1],
                    "' next: ",
                    strerror(e)
                );
            } else {
                sys::close(ex0);
                sys::close(ex1);
                pager_fallback();
            }
        }
        sys::exit_now(libc::EXIT_FAILURE);
    }

    PAGER_PID.with(|p| p.set(pid));
    sys::close(fd0);
    sys::close(ex1);
    let so = sys::dup_cloexec(1, 3).unwrap_or(-1);
    STORED_STDOUT.with(|s| s.set(so));
    if let Err(e) = sys::dup2(fd1, 1) {
        if so >= 0 {
            sys::close(so);
        }
        STORED_STDOUT.with(|s| s.set(-1));
        sys::close(fd1);
        sys::close(ex0);
        log_error_errno!(e, "Failed to duplicate pager pipe: ", strerror(e));
        return;
    }
    STDOUT_REDIRECTED.with(|s| s.set(true));
    let se = sys::dup_cloexec(2, 3).unwrap_or(-1);
    STORED_STDERR.with(|s| s.set(se));
    if let Err(e) = sys::dup2(fd1, 2) {
        if se >= 0 {
            sys::close(se);
        }
        STORED_STDERR.with(|s| s.set(-1));
        sys::close(fd1);
        sys::close(ex0);
        log_error_errno!(e, "Failed to duplicate pager pipe: ", strerror(e));
        return;
    }
    STDERR_REDIRECTED.with(|s| s.set(true));
    sys::close(fd1);
    if let Ok(true) = no_quit_on_interrupt(ex0, &less_opts) {
        sys::ignore_signal(libc::SIGINT);
    }
}

/// `pager_close()`.
pub fn pager_close() {
    let pid = PAGER_PID.with(|p| p.get());
    if pid <= 0 {
        return;
    }
    crate::stdio::flush_stdout();
    if STDOUT_REDIRECTED.with(|s| s.get()) {
        let so = STORED_STDOUT.with(|s| s.get());
        if so < 0 || sys::dup2(so, 1).is_err() {
            sys::close(1);
        }
    }
    let so = STORED_STDOUT.with(|s| s.replace(-1));
    if so >= 0 {
        sys::close(so);
    }
    if STDERR_REDIRECTED.with(|s| s.get()) {
        let se = STORED_STDERR.with(|s| s.get());
        if se < 0 || sys::dup2(se, 2).is_err() {
            sys::close(2);
        }
    }
    let se = STORED_STDERR.with(|s| s.replace(-1));
    if se >= 0 {
        sys::close(se);
    }
    STDOUT_REDIRECTED.with(|s| s.set(false));
    STDERR_REDIRECTED.with(|s| s.set(false));
    let _ = sys::kill(pid, libc::SIGCONT);
    let _ = sys::wait_for_terminate(pid);
    PAGER_PID.with(|p| p.set(0));
}

/// `pager_have()`.
pub fn pager_have() -> bool {
    PAGER_PID.with(|p| p.get()) > 0
}
