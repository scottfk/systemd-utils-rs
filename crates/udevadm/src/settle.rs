// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-settle.c`.
//!
//! Known difference: there is no D-Bus, so when run from
//! systemd-udev-settle.service the deprecation notice never names the
//! units that pull it in.

use shared::errno::{strerror, synthetic};
use shared::event::{Event, Fired};
use shared::options::{Opt, OptionParser, common};
use shared::{log_debug_errno, log_error_errno, log_warning_errno, sys};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const TIMEOUT: i32 = 0x102;
const EXISTS: i32 = 0x103;
const SEQ_START: i32 = 0x104;
const SEQ_END: i32 = 0x105;
const QUIET: i32 = 0x106;
const INTROSPECT: i32 = 0x107;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(TIMEOUT, b't', Some("timeout"), Some("SEC"), Some("Maximum time to wait for events")),
    Opt::new(EXISTS, b'E', Some("exit-if-exists"), Some("FILE"), Some("Stop waiting if file exists")),
    Opt::new(SEQ_START, b's', Some("seq-start"), Some("ARG"), None),
    Opt::new(SEQ_END, b'e', Some("seq-end"), Some("ARG"), None),
    Opt::new(QUIET, b'q', Some("quiet"), None, None),
    common::introspect_cli(INTROSPECT),
];

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(u64, Option<Vec<u8>>)>, i32> {
    let mut timeout = 120 * 1_000_000;
    let mut exists = None;
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("settle");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            TIMEOUT => match shared::time::parse_sec(&arg) {
                Ok(t) => timeout = t,
                Err(r) => {
                    return Err(log_error_errno!(r, "Failed to parse timeout value '", &arg[..], "': ", strerror(r)));
                }
            },
            EXISTS => {
                if !shared::path::path_is_valid(&arg) {
                    return Err(log_error_errno!(synthetic(libc::EINVAL), "Invalid path: ", &arg[..]));
                }
                exists = Some(arg);
            }
            SEQ_START | SEQ_END | QUIET => {
                let short = match c {
                    SEQ_START => "s",
                    SEQ_END => "e",
                    _ => "q",
                };
                return Err(shared::log_info_errno!(
                    synthetic(libc::EINVAL),
                    "Option -",
                    short,
                    " no longer supported."
                ));
            }
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    if !opts.args().is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "This subprogram takes no positional arguments."));
    }
    Ok(Some((timeout, exists)))
}

/// `emit_deprecation_warning()`.
fn emit_deprecation_warning() {
    match shared::cgroup::sd_pid_get_unit(0) {
        Err(r) => {
            log_debug_errno!(r, "Failed to determine unit we run in, ignoring: ", strerror(r));
        }
        Ok(u) if u == b"systemd-udev-settle.service" => {
            shared::log_notice!("systemd-udev-settle.service is deprecated.");
        }
        Ok(_) => {}
    }
}

/// `udev_queue_is_empty()`.
pub fn udev_queue_is_empty() -> Result<bool, i32> {
    match shared::sys_net::access(b"/run/udev/queue", libc::F_OK) {
        Ok(()) => Ok(false),
        Err(r) if r == -libc::ENOENT => Ok(true),
        Err(r) => Err(r),
    }
}

/// `check()`.
fn check(exists: Option<&[u8]>) -> bool {
    if let Some(e) = exists {
        match shared::sys_net::access(e, libc::F_OK) {
            Ok(()) => return true,
            Err(r) if r != -libc::ENOENT => {
                log_warning_errno!(r, "Failed to check the existence of \"", e, "\", ignoring: ", strerror(r));
            }
            Err(_) => {}
        }
    }
    match udev_queue_is_empty() {
        Err(r) => {
            log_warning_errno!(r, "Failed to check if udev queue is empty, ignoring: ", strerror(r));
            false
        }
        Ok(b) => b,
    }
}

/// `udev_ping(timeout, ignore_connection_failure)`: Ok(false) if the
/// connection failure was ignored.
pub fn udev_ping(timeout: u64, ignore_connection_failure: bool) -> Result<bool, i32> {
    let mut link = match crate::udev::varlink::udev_varlink_connect(timeout) {
        Ok(l) => l,
        Err(r) => {
            let ignore = ignore_connection_failure && (shared::varlink::is_disconnect(r) || r == -libc::ENOENT);
            shared::log_full_errno!(
                if ignore { shared::log::LOG_DEBUG } else { shared::log::LOG_ERR },
                r,
                "Failed to connect to udev via varlink",
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { Ok(false) } else { Err(r) };
        }
    };
    link.call_and_log("io.systemd.service.Ping", None)?;
    Ok(true)
}

/// `verb_settle_main()`.
pub fn verb_settle_main(argv: Vec<Vec<u8>>) -> i32 {
    let (timeout, exists) = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    if shared::virt::running_in_chroot() > 0 {
        shared::log_info!("Running in chroot, ignoring request.");
        return 0;
    }
    emit_deprecation_warning();
    if sys::getuid() == 0 {
        match udev_ping(timeout.max(5 * 1_000_000), true) {
            Err(r) => return r,
            Ok(false) => return 0,
            Ok(true) => {}
        }
    } else if let Err(r) = shared::sys_net::access(b"/run/udev/control", libc::F_OK) {
        return if r == -libc::ENOENT {
            log_error_errno!(r, "systemd-udevd is not running.")
        } else {
            log_error_errno!(r, "Failed to check if /run/udev/control exists: ", strerror(r))
        };
    }
    let mut event: Event<Option<Vec<u8>>> = match Event::new() {
        Ok(e) => e,
        Err(r) => return log_error_errno!(r, "Failed to get default sd-event object: ", strerror(r)),
    };
    let ifd = match shared::sys_net::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) {
        Ok(fd) => sys::OwnedFd::new(fd),
        Err(r) => return log_error_errno!(r, "Failed to add inotify watch for /run/udev: ", strerror(r)),
    };
    if let Err(r) = shared::sys_net::inotify_add_watch(ifd.raw(), b"/run/udev", libc::IN_DELETE) {
        return log_error_errno!(r, "Failed to add inotify watch for /run/udev: ", strerror(r));
    }
    let r = event.add_io(
        ifd.raw(),
        libc::EPOLLIN as u32,
        Box::new(|exists: &mut Option<Vec<u8>>, ev, _id, f| {
            let Fired::Io { fd, .. } = f else { return 0 };
            let mut buf = vec![0u8; 64 * 1024];
            let n = match sys::read(fd, &mut buf) {
                Ok(n) => n,
                Err(r) if r == -libc::EAGAIN || r == -libc::EINTR => return 0,
                Err(r) => return r,
            };
            // One callback per inotify event, as sd_event_add_inotify() does.
            let mut p = 0;
            while p + 16 <= n {
                let len = u32::from_ne_bytes(buf[p + 12..p + 16].try_into().expect("4 bytes")) as usize;
                p += 16 + len;
                if check(exists.as_deref()) {
                    ev.exit(0);
                    return 0;
                }
            }
            0
        }),
    );
    if let Err(r) = r {
        return log_error_errno!(r, "Failed to add inotify watch for /run/udev: ", strerror(r));
    }
    if timeout != u64::MAX {
        let r = event.add_time_relative(
            libc::CLOCK_BOOTTIME,
            timeout,
            Box::new(|_s, ev, _id, _f| {
                ev.exit(-libc::ETIMEDOUT);
                0
            }),
        );
        if let Err(r) = r {
            return log_error_errno!(r, "Failed to add timer event source: ", strerror(r));
        }
    }
    let mut state = exists;
    if check(state.as_deref()) {
        return 0;
    }
    match event.run_loop(&mut state) {
        Err(r) | Ok(r) if r == -libc::ETIMEDOUT => {
            log_error_errno!(r, "Timed out while waiting for udev queue to empty.")
        }
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Event loop failed: ", strerror(r)),
        _ => 0,
    }
}
