// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-trigger.c`.

use shared::blockdev::sd_device_trigger_with_uuid;
use shared::device_enumerator::{Enumerator, MatchInitialized};
use shared::device_monitor::Monitor;
use shared::errno::{strerror, synthetic};
use shared::event::Event;
use shared::id128::{Id128, to_uuid_string};
use shared::options::{OPTION_HELP_ENTRY_VERBATIM, OPTION_OPTIONAL_ARG, Opt, OptionParser, common};
use shared::sd_device::{Action, device_action_to_string};
use shared::{log_debug_errno, log_device_debug, log_device_debug_errno, log_error_errno, printo};

use crate::util::{find_device, parse_device_action, parse_key_value_argument};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const VERBOSE: i32 = 0x102;
const DRY_RUN: i32 = 0x103;
const QUIET: i32 = 0x104;
const TYPE: i32 = 0x105;
const ACTION: i32 = 0x106;
const SUBSYSTEM_MATCH: i32 = 0x107;
const SUBSYSTEM_NOMATCH: i32 = 0x108;
const ATTR_MATCH: i32 = 0x109;
const ATTR_NOMATCH: i32 = 0x10a;
const PROPERTY_MATCH: i32 = 0x10b;
const TAG_MATCH: i32 = 0x10c;
const SYSNAME_MATCH: i32 = 0x10d;
const NAME_MATCH: i32 = 0x10e;
const PARENT_MATCH: i32 = 0x10f;
const INCLUDE_PARENTS: i32 = 0x110;
const INITIALIZED_MATCH: i32 = 0x111;
const INITIALIZED_NOMATCH: i32 = 0x112;
const SETTLE: i32 = 0x113;
const WAIT_DAEMON: i32 = 0x114;
const UUID: i32 = 0x115;
const PRIORITIZED: i32 = 0x116;
const INTROSPECT: i32 = 0x117;

const fn verbatim(long: &'static str, help: &'static str) -> Opt {
    Opt::long(TYPE, long, None, Some(help)).with_flags(OPTION_HELP_ENTRY_VERBATIM)
}

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(VERBOSE, b'v', Some("verbose"), None, Some("Print the list of devices while running")),
    Opt::new(DRY_RUN, b'n', Some("dry-run"), None, Some("Do not actually trigger the events")),
    Opt::new(QUIET, b'q', Some("quiet"), None, Some("Suppress error logging in triggering events")),
    Opt::new(TYPE, b't', Some("type"), Some("TYPE"), Some("Type of sysfs events to trigger:")),
    verbatim("        devices", "- devices (default)"),
    verbatim("        subsystems", "- subsystems and drivers"),
    verbatim("        all", "- devices, subsystems, and drivers"),
    Opt::new(ACTION, b'c', Some("action"), Some("ACTION|help"), Some("Event action value, default is \"change\"")),
    Opt::new(
        SUBSYSTEM_MATCH,
        b's',
        Some("subsystem-match"),
        Some("SUBSYSTEM"),
        Some("Trigger devices from a matching subsystem"),
    ),
    Opt::new(
        SUBSYSTEM_NOMATCH,
        b'S',
        Some("subsystem-nomatch"),
        Some("SUBSYSTEM"),
        Some("Exclude devices from a matching subsystem"),
    ),
    Opt::new(
        ATTR_MATCH,
        b'a',
        Some("attr-match"),
        Some("FILE[=VALUE]"),
        Some("Trigger devices with a matching attribute"),
    ),
    Opt::new(
        ATTR_NOMATCH,
        b'A',
        Some("attr-nomatch"),
        Some("FILE[=VALUE]"),
        Some("Exclude devices with a matching attribute"),
    ),
    Opt::new(
        PROPERTY_MATCH,
        b'p',
        Some("property-match"),
        Some("KEY=VALUE"),
        Some("Trigger devices with a matching property"),
    ),
    Opt::new(TAG_MATCH, b'g', Some("tag-match"), Some("TAG"), Some("Trigger devices with a matching tag")),
    Opt::new(SYSNAME_MATCH, b'y', Some("sysname-match"), Some("NAME"), Some("Trigger devices with this /sys path")),
    Opt::long(NAME_MATCH, "name-match", Some("NAME"), Some("Trigger devices with this /dev name")),
    Opt::new(PARENT_MATCH, b'b', Some("parent-match"), Some("NAME"), Some("Trigger devices with that parent device")),
    Opt::long(INCLUDE_PARENTS, "include-parents", None, Some("Trigger parent devices of found devices")),
    Opt::long(INITIALIZED_MATCH, "initialized-match", None, Some("Trigger devices that are already initialized")),
    Opt::long(INITIALIZED_NOMATCH, "initialized-nomatch", None, Some("Trigger devices that are not initialized yet")),
    Opt::new(SETTLE, b'w', Some("settle"), None, Some("Wait for the triggered events to complete")),
    Opt::long(
        WAIT_DAEMON,
        "wait-daemon",
        Some("SECONDS"),
        Some("Wait for udevd daemon to be initialized before triggering uevents"),
    )
    .with_flags(OPTION_OPTIONAL_ARG),
    Opt::long(UUID, "uuid", None, Some("Print synthetic uevent UUID")),
    Opt::long(
        PRIORITIZED,
        "prioritized-subsystem",
        Some("SUBSYSTEM[,SUBSYSTEM\u{2026}]"),
        Some("Trigger devices from a matching subsystem first"),
    ),
    common::introspect_cli(INTROSPECT),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanType {
    Devices,
    Subsystems,
    All,
}

struct Args {
    verbose: bool,
    dry_run: bool,
    quiet: bool,
    uuid: bool,
    settle: bool,
    scan_type: ScanType,
    action: Action,
    devices: Vec<Vec<u8>>,
    attr_match: Vec<Vec<u8>>,
    attr_nomatch: Vec<Vec<u8>>,
    name_match: Vec<Vec<u8>>,
    parent_match: Vec<Vec<u8>>,
    property_match: Vec<Vec<u8>>,
    subsystem_match: Vec<Vec<u8>>,
    subsystem_nomatch: Vec<Vec<u8>>,
    sysname_match: Vec<Vec<u8>>,
    tag_match: Vec<Vec<u8>>,
    prioritized: Vec<Vec<u8>>,
    initialized_match: Option<MatchInitialized>,
    include_parents: bool,
    ping: bool,
    ping_timeout: u64,
}

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
    let mut a = Args {
        verbose: false,
        dry_run: false,
        quiet: false,
        uuid: false,
        settle: false,
        scan_type: ScanType::Devices,
        action: Action::Change,
        devices: Vec::new(),
        attr_match: Vec::new(),
        attr_nomatch: Vec::new(),
        name_match: Vec::new(),
        parent_match: Vec::new(),
        property_match: Vec::new(),
        subsystem_match: Vec::new(),
        subsystem_nomatch: Vec::new(),
        sysname_match: Vec::new(),
        tag_match: Vec::new(),
        prioritized: Vec::new(),
        initialized_match: None,
        include_parents: false,
        ping: false,
        ping_timeout: 5 * 1_000_000,
    };
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone();
        let s = arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("trigger");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERBOSE => a.verbose = true,
            DRY_RUN => a.dry_run = true,
            QUIET => a.quiet = true,
            TYPE => {
                a.scan_type = match &s[..] {
                    b"devices" => ScanType::Devices,
                    b"subsystems" => ScanType::Subsystems,
                    b"all" => ScanType::All,
                    _ => return Err(log_error_errno!(synthetic(libc::EINVAL), "Unknown type --type=", &s[..])),
                }
            }
            ACTION => match parse_device_action(&s)? {
                None => return Ok(None),
                Some(x) => a.action = x,
            },
            SUBSYSTEM_MATCH => a.subsystem_match.push(s),
            SUBSYSTEM_NOMATCH => a.subsystem_nomatch.push(s),
            ATTR_MATCH => a.attr_match.push(s),
            ATTR_NOMATCH => a.attr_nomatch.push(s),
            PROPERTY_MATCH => a.property_match.push(s),
            TAG_MATCH => a.tag_match.push(s),
            SYSNAME_MATCH => a.sysname_match.push(s),
            NAME_MATCH => a.name_match.push(s),
            PARENT_MATCH => a.parent_match.push(s),
            INCLUDE_PARENTS => a.include_parents = true,
            INITIALIZED_MATCH => a.initialized_match = Some(MatchInitialized::Yes),
            INITIALIZED_NOMATCH => a.initialized_match = Some(MatchInitialized::No),
            SETTLE => a.settle = true,
            WAIT_DAEMON => {
                a.ping = true;
                if let Some(t) = &arg {
                    a.ping_timeout = shared::time::parse_sec(t).map_err(|r| {
                        log_error_errno!(r, "Failed to parse timeout value '", &t[..], "': ", strerror(r))
                    })?;
                }
            }
            UUID => a.uuid = true,
            PRIORITIZED => a.prioritized.extend(s.split(|&c| c == b',').map(<[u8]>::to_vec)),
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    a.devices.extend(opts.args().iter().cloned());
    Ok(Some(a))
}

/// `add_device_match()`.
fn add_device_match(e: &mut Enumerator, s: &[u8], prefix: Option<&[u8]>) -> Result<(), i32> {
    let dev = find_device(s, prefix)
        .map_err(|r| log_error_errno!(r, "Failed to open the device '", s, "': ", strerror(r)))?;
    e.add_match_parent_incremental(&dev);
    Ok(())
}

/// `setup_matches()`.
fn setup_matches(a: &Args, e: &mut Enumerator) -> Result<(), i32> {
    for d in &a.devices {
        add_device_match(e, d, None)?;
    }
    for n in &a.name_match {
        add_device_match(e, n, Some(b"/dev/"))?;
    }
    for p in &a.parent_match {
        add_device_match(e, p, Some(b"/sys/"))?;
    }
    for s in &a.subsystem_match {
        e.add_match_subsystem(s, true);
    }
    for s in &a.subsystem_nomatch {
        e.add_match_subsystem(s, false);
    }
    for x in &a.attr_match {
        let (k, v) = parse_key_value_argument(x, false)?;
        e.add_match_sysattr(&k, v.as_deref(), true);
    }
    for x in &a.attr_nomatch {
        let (k, v) = parse_key_value_argument(x, false)?;
        e.add_match_sysattr(&k, v.as_deref(), false);
    }
    for p in &a.property_match {
        let (k, v) = parse_key_value_argument(p, true)?;
        e.add_match_property(&k, v.as_deref());
    }
    for t in &a.tag_match {
        e.add_match_tag(t);
    }
    for s in &a.sysname_match {
        e.add_match_sysname(s, true);
    }
    for p in &a.prioritized {
        e.add_prioritized_subsystem(p);
    }
    if let Some(m) = a.initialized_match {
        e.add_match_is_initialized(m);
    }
    if a.include_parents {
        e.add_all_parents();
    }
    Ok(())
}

/// `exec_list()`.
fn exec_list(a: &Args, e: &mut Enumerator, mut settle_ids: Option<&mut Vec<Id128>>) -> i32 {
    let action_str = device_action_to_string(a.action);
    let mut ret = 0;
    let mut d = e.get_first();
    while let Some(dev) = d {
        let syspath = dev.get_syspath();
        if a.verbose {
            printo!(syspath.bytes(), "\n");
        }
        if !a.dry_run {
            match sd_device_trigger_with_uuid(&dev, a.action) {
                Err(r) => {
                    let ignore = r == -libc::ENOENT || r == -libc::ENODEV;
                    let level = if a.quiet || r == -libc::ENOENT {
                        shared::log::LOG_DEBUG
                    } else if r == -libc::ENODEV {
                        shared::log::LOG_WARNING
                    } else {
                        shared::log::LOG_ERR
                    };
                    shared::sd_device::log_device_full(
                        Some(&dev),
                        level,
                        r,
                        shared::bcat!(
                            "Failed to write '",
                            action_str,
                            "' to '",
                            syspath.bytes(),
                            "/uevent'",
                            if ignore { ", ignoring" } else { "" },
                            ": ",
                            strerror(r)
                        ),
                    );
                    if r == -libc::EROFS {
                        return r;
                    }
                    if !ignore {
                        shared::errno::ret_gather(&mut ret, r);
                    }
                }
                Ok(id) => {
                    log_device_debug!(dev, "Triggered device with action '", action_str, "'.");
                    if a.uuid {
                        printo!(to_uuid_string(&id), "\n");
                    }
                    if let Some(s) = settle_ids.as_deref_mut()
                        && !s.contains(&id)
                    {
                        s.push(id);
                    }
                }
            }
        }
        d = e.get_next();
    }
    ret
}

struct Settle {
    verbose: bool,
    uuid: bool,
    ids: Vec<Id128>,
    monitor: Monitor,
}

/// `device_monitor_handler()`.
fn settle_handler(st: &mut Settle, ev: &mut Event<Settle>) {
    let Ok(Some(dev)) = st.monitor.receive() else { return };
    let id = match dev.get_trigger_uuid().and_then(|u| shared::id128::from_string(&u)) {
        Ok(id) => id,
        Err(r) => {
            log_device_debug_errno!(dev, r, "Got uevent without UUID, ignoring: ", strerror(r));
            return;
        }
    };
    let Some(i) = st.ids.iter().position(|x| *x == id) else {
        log_device_debug!(dev, "Got uevent with unexpected UUID, ignoring.");
        return;
    };
    st.ids.remove(i);
    if st.verbose {
        printo!("settle ", dev.get_syspath().bytes(), "\n");
    }
    if st.uuid {
        printo!("settle ", to_uuid_string(&id), "\n");
    }
    if st.ids.is_empty() {
        ev.exit(0);
    }
}

/// `verb_trigger_main()`.
pub fn verb_trigger_main(argv: Vec<Vec<u8>>) -> i32 {
    if shared::virt::running_in_chroot() > 0 {
        shared::log_info!("Running in chroot, ignoring request.");
        return 0;
    }
    let a = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    let mut e = Enumerator::new();
    e.allow_uninitialized();
    if let Err(r) = setup_matches(&a, &mut e) {
        return r;
    }
    if a.ping
        && let Err(r) = crate::settle::udev_ping(a.ping_timeout, false)
    {
        return r;
    }
    let mut settle = None;
    let mut event: Option<Event<Settle>> = None;
    if a.settle {
        let ev = match Event::new() {
            Ok(ev) => ev,
            Err(r) => return log_error_errno!(r, "Failed to get default event: ", strerror(r)),
        };
        let mut m = match Monitor::new() {
            Ok(m) => m,
            Err(r) => return log_error_errno!(r, "Failed to create device monitor object: ", strerror(r)),
        };
        if let Err(r) = m.filter_update() {
            log_debug_errno!(r, "sd-device-monitor(n/a): Failed to update filter: ", strerror(r));
            return log_error_errno!(r, "Failed to start device monitor: ", strerror(r));
        }
        settle = Some(Settle { verbose: a.verbose, uuid: a.uuid, ids: Vec::new(), monitor: m });
        event = Some(ev);
    }
    let r = match a.scan_type {
        ScanType::Subsystems => e.scan_subsystems(),
        ScanType::Devices => e.scan_devices(),
        ScanType::All => e.scan_devices_and_subsystems(),
    };
    if r < 0 {
        let what = match a.scan_type {
            ScanType::Subsystems => "subsystems",
            ScanType::Devices => "devices",
            ScanType::All => "devices and subsystems",
        };
        return log_error_errno!(r, "Failed to scan ", what, ": ", strerror(r));
    }
    let r = exec_list(&a, &mut e, settle.as_mut().map(|s| &mut s.ids));
    if r < 0 {
        return r;
    }
    let (Some(mut st), Some(mut ev)) = (settle, event) else { return 0 };
    if st.ids.is_empty() {
        return 0;
    }
    let fd = st.monitor.get_fd();
    if let Err(r) = ev.add_io(
        fd,
        libc::EPOLLIN as u32,
        Box::new(|st: &mut Settle, ev, _id, _f| {
            settle_handler(st, ev);
            0
        }),
    ) {
        return log_error_errno!(r, "Failed to start device monitor: ", strerror(r));
    }
    match ev.run_loop(&mut st) {
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Event loop failed: ", strerror(r)),
        _ => 0,
    }
}
