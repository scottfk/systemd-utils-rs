// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-wait.c`.

use shared::device_monitor::{Monitor, MonitorGroup};
use shared::errno::{strerror, synthetic};
use shared::event::{Event, Id};
use shared::options::{Opt, OptionParser, common};
use shared::sd_device::{Action, Device};
use shared::sys;
use shared::{log_debug, log_error_errno, log_warning_errno};

use crate::udev::util::device_for_action;
use crate::udev::wait::device_is_processed;

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const TIMEOUT: i32 = 0x102;
const INITIALIZED: i32 = 0x103;
const REMOVED: i32 = 0x104;
const SETTLE: i32 = 0x105;
const INTROSPECT: i32 = 0x106;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(TIMEOUT, b't', Some("timeout"), Some("SEC"), Some("Maximum time to wait for the device")),
    Opt::long(INITIALIZED, "initialized", Some("BOOL"), Some("Wait for devices being initialized by systemd-udevd")),
    Opt::long(REMOVED, "removed", None, Some("Wait for devices being removed")),
    Opt::long(SETTLE, "settle", None, Some("Also wait for all queued events being processed")),
    common::introspect_cli(INTROSPECT),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitUntil {
    Initialized,
    Added,
    Removed,
}

impl WaitUntil {
    fn name(self) -> &'static str {
        match self {
            WaitUntil::Initialized => "initialized",
            WaitUntil::Added => "added",
            WaitUntil::Removed => "removed",
        }
    }
}

struct State {
    until: WaitUntil,
    settle: bool,
    devices: Vec<Vec<u8>>,
    monitors: Vec<Monitor>,
    counter: u32,
    periodic: Option<Id>,
}

/// `check_device()`.
fn check_device(st: &State, path: &[u8]) -> Result<bool, i32> {
    if st.until == WaitUntil::Removed {
        return match sys::faccessat(libc::AT_FDCWD, path, libc::F_OK, libc::AT_SYMLINK_NOFOLLOW) {
            Err(r) if r == -libc::ENOENT => Ok(true),
            Err(r) => Err(r),
            Ok(()) => Ok(false),
        };
    }
    let dev = match Device::new_from_path(path) {
        Err(r) if r == -libc::ENODEV => return Ok(false),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    if st.until == WaitUntil::Initialized {
        return device_is_processed(&dev);
    }
    Ok(true)
}

/// `check()`.
fn check(st: &State) -> bool {
    if st.settle {
        match crate::settle::udev_queue_is_empty() {
            Ok(false) => return false,
            Err(r) => {
                log_warning_errno!(r, "Failed to check if udev queue is empty, assuming empty: ", strerror(r));
            }
            Ok(true) => {}
        }
    }
    for p in &st.devices {
        match check_device(st, p) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(r) => {
                let w = st.until.name();
                log_warning_errno!(
                    r,
                    "Failed to check if device \"",
                    &p[..],
                    "\" is ",
                    w,
                    ", assuming not ",
                    w,
                    ": ",
                    strerror(r)
                );
                return false;
            }
        }
    }
    true
}

/// `check_and_exit()`.
fn check_and_exit(st: &State, ev: &mut Event<State>) {
    if check(st) {
        ev.exit(0);
    }
}

/// `device_monitor_handler()`.
fn monitor_handler(st: &mut State, ev: &mut Event<State>, i: usize) {
    let Ok(Some(device)) = st.monitors[i].receive() else { return };
    if device_for_action(&device, Action::Remove) != (st.until == WaitUntil::Removed) {
        return;
    }
    if st.until == WaitUntil::Removed {
        return check_and_exit(st, ev);
    }
    let name = match device.get_sysname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => {
            shared::log_device_warning_errno!(
                device,
                r,
                "Failed to get sysname of received device, ignoring: ",
                strerror(r)
            );
            return;
        }
    };
    for p in &st.devices {
        if shared::path::path_startswith(p, b"/sys").is_none() {
            continue;
        }
        let (len, start, _) = match shared::path::path_find_last_component(p, false) {
            Ok(x) => x,
            Err(r) => {
                log_warning_errno!(r, "Failed to extract filename from \"", &p[..], "\", ignoring: ", strerror(r));
                continue;
            }
        };
        if len == 0 {
            continue;
        }
        // strneq(s, name, r)
        let s = &p[start..start + len];
        let n = &name[..name.len().min(len)];
        if s == n {
            return check_and_exit(st, ev);
        }
    }
    let devname = match device.get_devname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => {
            if r != -libc::ENOENT {
                shared::log_device_warning_errno!(
                    device,
                    r,
                    "Failed to get devname of received device, ignoring: ",
                    strerror(r)
                );
            }
            return;
        }
    };
    let contains = |x: &[u8]| st.devices.iter().any(|p| shared::path::path_equal(p, x));
    if contains(&devname) || device.devlinks().iter().any(|l| contains(l.bytes())) {
        check_and_exit(st, ev);
    }
}

/// `reset_timer()`: a 250ms periodic check.
fn reset_timer(ev: &mut Event<State>, st: &mut State) -> Result<(), i32> {
    if let Some(id) = st.periodic
        && ev.exists(id)
    {
        if ev.get_enabled(id) != Some(shared::event::Enabled::Off) {
            return Ok(());
        }
        ev.set_time_relative(id, 250_000)?;
        return ev.set_enabled(id, shared::event::Enabled::Oneshot);
    }
    let id = ev.add_time_relative(
        libc::CLOCK_BOOTTIME,
        250_000,
        Box::new(|st: &mut State, ev, _id, _f| {
            if check(st) {
                st.counter += 1;
            } else {
                st.counter = 0;
            }
            if st.counter >= 2 {
                log_debug!("All requested devices popped up without receiving kernel uevents.");
                ev.exit(0);
                return 0;
            }
            if let Err(r) = reset_timer(ev, st) {
                log_warning_errno!(r, "Failed to reset periodic timer event source, ignoring: ", strerror(r));
            }
            0
        }),
    )?;
    ev.set_description(id, b"periodic-timer-event-source");
    st.periodic = Some(id);
    Ok(())
}

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(State, u64)>, i32> {
    let mut until = WaitUntil::Initialized;
    let mut timeout = u64::MAX;
    let mut removed = false;
    let mut settle = false;
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("wait");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            TIMEOUT => {
                timeout = shared::time::parse_sec(&arg)
                    .map_err(|r| log_error_errno!(r, "Failed to parse -t/--timeout= parameter: ", &arg[..]))?;
            }
            INITIALIZED => {
                let b = shared::parse::parse_boolean(&arg)
                    .map_err(|r| log_error_errno!(r, "Failed to parse --initialized= parameter: ", &arg[..]))?;
                until = if b { WaitUntil::Initialized } else { WaitUntil::Added };
            }
            REMOVED => removed = true,
            SETTLE => settle = true,
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    if removed {
        until = WaitUntil::Removed;
    }
    if opts.args().is_empty() {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Too few arguments, expected at least one device path or device symlink."
        ));
    }
    let devices = opts.args().to_vec();
    Ok(Some((State { until, settle, devices, monitors: Vec::new(), counter: 0, periodic: None }, timeout)))
}

/// `verb_wait_main()`.
pub fn verb_wait_main(argv: Vec<Vec<u8>>) -> i32 {
    let (mut st, timeout) = match parse_argv(argv) {
        Ok(Some(x)) => x,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    for p in &mut st.devices {
        *p = shared::path::path_simplify(p);
        if !shared::path::path_is_safe(p) {
            return log_error_errno!(synthetic(libc::EINVAL), "Device path cannot contain \"..\".");
        }
        if shared::path::path_startswith(p, b"/dev/").is_none() && shared::path::path_startswith(p, b"/sys/").is_none()
        {
            return log_error_errno!(
                synthetic(libc::EINVAL),
                "Specified path \"",
                &p[..],
                "\" does not start with \"/dev/\" or \"/sys/\"."
            );
        }
    }
    if check(&st) {
        return 0;
    }
    let mut ev: Event<State> = match Event::new() {
        Ok(e) => e,
        Err(r) => return log_error_errno!(r, "Failed to initialize sd-event: ", strerror(r)),
    };
    if timeout != u64::MAX {
        let r = ev.add_time_relative(
            libc::CLOCK_BOOTTIME,
            timeout,
            Box::new(|_st: &mut State, ev, _id, _f| {
                ev.exit(-libc::ETIMEDOUT);
                0
            }),
        );
        if let Err(r) = r {
            return log_error_errno!(r, "Failed to set up timeout: ", strerror(r));
        }
    }
    let _ifd;
    if st.settle {
        let r = (|| -> Result<sys::OwnedFd, i32> {
            let fd = sys::OwnedFd::new(shared::sys_net::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC)?);
            shared::sys_net::inotify_add_watch(fd.raw(), b"/run/udev", libc::IN_CREATE | libc::IN_DELETE)?;
            ev.add_io(
                fd.raw(),
                libc::EPOLLIN as u32,
                Box::new(|st: &mut State, ev, _id, f| {
                    let shared::event::Fired::Io { fd, .. } = f else { return 0 };
                    let mut buf = vec![0u8; 64 * 1024];
                    let n = sys::read(fd, &mut buf).unwrap_or(0);
                    let mut p = 0;
                    while p + 16 <= n {
                        let len = u32::from_ne_bytes(buf[p + 12..p + 16].try_into().expect("4 bytes")) as usize;
                        p += 16 + len;
                        check_and_exit(st, ev);
                    }
                    0
                }),
            )?;
            Ok(fd)
        })();
        match r {
            Ok(fd) => _ifd = fd,
            Err(r) => return log_error_errno!(r, "Failed to set up inotify: ", strerror(r)),
        }
    }
    let mut groups = vec![(MonitorGroup::Udev, &b"udev-uevent-monitor-event-source"[..], "udev")];
    if st.until == WaitUntil::Added {
        groups.push((MonitorGroup::Kernel, b"kernel-uevent-monitor-event-source", "kernel"));
    }
    for (group, desc, what) in groups {
        let r = (|| -> Result<(), i32> {
            let mut m = Monitor::new_full(group)?;
            m.set_description(Some(desc));
            m.filter_update()?;
            let i = st.monitors.len();
            ev.add_io(
                m.get_fd(),
                libc::EPOLLIN as u32,
                Box::new(move |st: &mut State, ev, _id, _f| {
                    monitor_handler(st, ev, i);
                    0
                }),
            )?;
            st.monitors.push(m);
            Ok(())
        })();
        if let Err(r) = r {
            return log_error_errno!(r, "Failed to set up ", what, " uevent monitor: ", strerror(r));
        }
    }
    if st.until == WaitUntil::Added {
        let r = reset_timer(&mut ev, &mut st)
            .and_then(|_| ev.set_priority(st.periodic.expect("timer"), shared::event::SD_EVENT_PRIORITY_NORMAL + 1));
        if let Err(r) = r {
            return log_error_errno!(r, "Failed to set up periodic timer: ", strerror(r));
        }
    }
    if check(&st) {
        return 0;
    }
    match ev.run_loop(&mut st) {
        Err(r) | Ok(r) if r == -libc::ETIMEDOUT => {
            log_error_errno!(r, "Timed out for waiting devices being ", st.until.name(), ".")
        }
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Event loop failed: ", strerror(r)),
        _ => 0,
    }
}
