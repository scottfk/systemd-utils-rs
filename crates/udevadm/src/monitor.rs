// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-monitor.c`.

use shared::device_monitor::{Monitor, MonitorGroup};
use shared::errno::strerror;
use shared::event::Event;
use shared::options::{Opt, OptionParser, common};
use shared::sd_device::device_action_to_string;
use shared::{log_error_errno, printo};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const PROPERTY: i32 = 0x102;
const KERNEL: i32 = 0x103;
const UDEV: i32 = 0x104;
const SUBSYSTEM: i32 = 0x105;
const TAG: i32 = 0x106;
const INTROSPECT: i32 = 0x107;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(PROPERTY, b'e', Some("environment"), None, None),
    Opt::new(PROPERTY, b'p', Some("property"), None, Some("Print the event properties")),
    Opt::new(KERNEL, b'k', Some("kernel"), None, Some("Print kernel uevents")),
    Opt::new(UDEV, b'u', Some("udev"), None, Some("Print udev events")),
    Opt::new(SUBSYSTEM, b's', Some("subsystem-match"), Some("SUBSYSTEM[/DEVTYPE]"), Some("Filter events by subsystem")),
    Opt::new(TAG, b't', Some("tag-match"), Some("TAG"), Some("Filter events by tag")),
    common::introspect_cli(INTROSPECT),
];

#[derive(Default)]
struct Args {
    show_property: bool,
    print_kernel: bool,
    print_udev: bool,
    subsystem_filter: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    tag_filter: Vec<Vec<u8>>,
}

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
    let mut a = Args::default();
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("monitor");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            PROPERTY => a.show_property = true,
            KERNEL => a.print_kernel = true,
            UDEV => a.print_udev = true,
            SUBSYSTEM => match arg.iter().position(|&b| b == b'/') {
                Some(i) => a.subsystem_filter.push((arg[..i].to_vec(), Some(arg[i + 1..].to_vec()))),
                None => a.subsystem_filter.push((arg, None)),
            },
            TAG => {
                if !a.tag_filter.contains(&arg) {
                    a.tag_filter.push(arg);
                }
            }
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    if !a.print_kernel && !a.print_udev {
        a.print_kernel = true;
        a.print_udev = true;
    }
    Ok(Some(a))
}

struct State {
    show_property: bool,
    monitors: Vec<(Monitor, MonitorGroup)>,
}

/// `device_monitor_handler()`.
fn handler(st: &mut State, i: usize) {
    let (m, group) = &mut st.monitors[i];
    let group = *group;
    let Ok(Some(device)) = m.receive() else { return };
    let action = device.get_action().ok().map(device_action_to_string);
    let devpath = device.get_devpath();
    let subsystem = device.get_subsystem().ok();
    let now = shared::time::now_monotonic();
    printo!(
        format!("{:<6}", if group == MonitorGroup::Udev { "UDEV" } else { "KERNEL" }),
        format!("[{}.{:06}] ", now / 1_000_000, now % 1_000_000),
        format!("{:<8}", action.unwrap_or("n/a")),
        " ",
        devpath.bytes(),
        " (",
        subsystem.as_ref().map_or(&b"(null)"[..], |s| s.bytes()),
        ")\n"
    );
    if st.show_property {
        for (k, v) in device.properties() {
            printo!(k.bytes(), "=", v.bytes(), "\n");
        }
        printo!("\n");
    }
    shared::stdio::flush_stdout();
}

/// `setup_monitor()`.
fn setup_monitor(a: &Args, sender: MonitorGroup) -> Result<Monitor, i32> {
    let mut m =
        Monitor::new_full(sender).map_err(|r| log_error_errno!(r, "Failed to create netlink socket: ", strerror(r)))?;
    for (subsystem, devtype) in &a.subsystem_filter {
        m.filter_add_match_subsystem_devtype(subsystem, devtype.as_deref());
    }
    for t in &a.tag_filter {
        m.filter_add_match_tag(t);
    }
    if let Err(r) = m.filter_update() {
        let r = shared::log_debug_errno!(r, "sd-device-monitor(n/a): Failed to update filter: ", strerror(r));
        return Err(log_error_errno!(r, "Failed to start device monitor: ", strerror(r)));
    }
    m.set_description(Some(if sender == MonitorGroup::Udev { b"udev" } else { b"kernel" }));
    Ok(m)
}

/// `verb_monitor_main()`.
pub fn verb_monitor_main(argv: Vec<Vec<u8>>) -> i32 {
    let a = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    if shared::virt::running_in_chroot() > 0 {
        shared::log_info!("Running in chroot, ignoring request.");
        return 0;
    }
    let mut event: Event<State> = match Event::new() {
        Ok(e) => e,
        Err(r) => return log_error_errno!(r, "Failed to initialize event: ", strerror(r)),
    };
    for sig in [libc::SIGINT, libc::SIGTERM] {
        if let Err(r) = event.add_signal(sig, None) {
            return log_error_errno!(r, "Failed to install SIGINT/SIGTERM handling: ", strerror(r));
        }
    }
    let mut st = State { show_property: a.show_property, monitors: Vec::new() };
    printo!("monitor will print the received events for:\n");
    for (want, group, text) in [
        (a.print_udev, MonitorGroup::Udev, "UDEV - the event which udev sends out after rule processing\n"),
        (a.print_kernel, MonitorGroup::Kernel, "KERNEL - the kernel uevent\n"),
    ] {
        if !want {
            continue;
        }
        let m = match setup_monitor(&a, group) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let i = st.monitors.len();
        let fd = m.get_fd();
        st.monitors.push((m, group));
        if let Err(r) = event.add_io(
            fd,
            libc::EPOLLIN as u32,
            Box::new(move |st: &mut State, _ev, _id, _f| {
                handler(st, i);
                0
            }),
        ) {
            return log_error_errno!(r, "Failed to start device monitor: ", strerror(r));
        }
        printo!(text);
    }
    printo!("\n");
    shared::stdio::flush_stdout();
    match event.run_loop(&mut st) {
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Failed to run event loop: ", strerror(r)),
        _ => 0,
    }
}
