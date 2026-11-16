// SPDX-License-Identifier: GPL-2.0-or-later
//! The verbs of later phases (`trigger`, `settle`, `control`, `monitor`,
//! `test-builtin`, `wait`, `lock`) and udevd.  Their option tables are
//! here already, so `--help` and `--introspect-cli` match C; running
//! them fails until they're ported.

use shared::errno::synthetic;
use shared::log_error_errno;
use shared::options::{OPTION_HELP_ENTRY_VERBATIM, OPTION_OPTIONAL_ARG, Opt, OptionParser, common};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const INTROSPECT: i32 = 0x102;
/// Every option that only matters once the verb runs.
const OTHER: i32 = 0x103;

const fn o(short: u8, long: &'static str, metavar: Option<&'static str>, help: Option<&'static str>) -> Opt {
    Opt::new(OTHER, short, Some(long), metavar, help)
}
const fn l(long: &'static str, metavar: Option<&'static str>, help: Option<&'static str>) -> Opt {
    Opt::long(OTHER, long, metavar, help)
}
const fn verbatim(long: &'static str, help: &'static str) -> Opt {
    Opt::long(OTHER, long, None, Some(help)).with_flags(OPTION_HELP_ENTRY_VERBATIM)
}

pub const TRIGGER: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'v', "verbose", None, Some("Print the list of devices while running")),
    o(b'n', "dry-run", None, Some("Do not actually trigger the events")),
    o(b'q', "quiet", None, Some("Suppress error logging in triggering events")),
    o(b't', "type", Some("TYPE"), Some("Type of sysfs events to trigger:")),
    verbatim("        devices", "- devices (default)"),
    verbatim("        subsystems", "- subsystems and drivers"),
    verbatim("        all", "- devices, subsystems, and drivers"),
    o(b'c', "action", Some("ACTION|help"), Some("Event action value, default is \"change\"")),
    o(b's', "subsystem-match", Some("SUBSYSTEM"), Some("Trigger devices from a matching subsystem")),
    o(b'S', "subsystem-nomatch", Some("SUBSYSTEM"), Some("Exclude devices from a matching subsystem")),
    o(b'a', "attr-match", Some("FILE[=VALUE]"), Some("Trigger devices with a matching attribute")),
    o(b'A', "attr-nomatch", Some("FILE[=VALUE]"), Some("Exclude devices with a matching attribute")),
    o(b'p', "property-match", Some("KEY=VALUE"), Some("Trigger devices with a matching property")),
    o(b'g', "tag-match", Some("TAG"), Some("Trigger devices with a matching tag")),
    o(b'y', "sysname-match", Some("NAME"), Some("Trigger devices with this /sys path")),
    l("name-match", Some("NAME"), Some("Trigger devices with this /dev name")),
    o(b'b', "parent-match", Some("NAME"), Some("Trigger devices with that parent device")),
    l("include-parents", None, Some("Trigger parent devices of found devices")),
    l("initialized-match", None, Some("Trigger devices that are already initialized")),
    l("initialized-nomatch", None, Some("Trigger devices that are not initialized yet")),
    o(b'w', "settle", None, Some("Wait for the triggered events to complete")),
    l("wait-daemon", Some("SECONDS"), Some("Wait for udevd daemon to be initialized before triggering uevents"))
        .with_flags(OPTION_OPTIONAL_ARG),
    l("uuid", None, Some("Print synthetic uevent UUID")),
    l(
        "prioritized-subsystem",
        Some("SUBSYSTEM[,SUBSYSTEM\u{2026}]"),
        Some("Trigger devices from a matching subsystem first"),
    ),
    common::introspect_cli(INTROSPECT),
];

pub const SETTLE: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b't', "timeout", Some("SEC"), Some("Maximum time to wait for events")),
    o(b'E', "exit-if-exists", Some("FILE"), Some("Stop waiting if file exists")),
    o(b's', "seq-start", Some("ARG"), None),
    o(b'e', "seq-end", Some("ARG"), None),
    o(b'q', "quiet", None, None),
    common::introspect_cli(INTROSPECT),
];

pub const CONTROL: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'e', "exit", None, Some("Instruct the daemon to cleanup and exit")),
    l("log-priority", Some("LEVEL"), None),
    o(b'l', "log-level", Some("LEVEL"), Some("Set the udev log level for the daemon")),
    o(b's', "stop-exec-queue", None, Some("Do not execute events, queue only")),
    o(b'S', "start-exec-queue", None, Some("Execute events, flush queue")),
    l("reload-rules", None, None),
    o(b'R', "reload", None, Some("Reload rules and databases")),
    l("env", Some("KEY=VALUE"), None),
    o(b'p', "property", Some("KEY=VALUE"), Some("Set a global property for all events")),
    o(b'm', "children-max", Some("N"), Some("Maximum number of children")),
    l("ping", None, Some("Wait for udev to respond to a ping message")),
    l("trace", Some("BOOL"), Some("Enable/disable trace logging")),
    l("revert", None, Some("Revert previously set configurations")),
    o(b't', "timeout", Some("SECONDS"), Some("Maximum time to block for a reply")),
    l("load-credentials", None, Some("Load udev rules from credentials")),
    common::introspect_cli(INTROSPECT),
];

pub const MONITOR: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'e', "environment", None, None),
    o(b'p', "property", None, Some("Print the event properties")),
    o(b'k', "kernel", None, Some("Print kernel uevents")),
    o(b'u', "udev", None, Some("Print udev events")),
    o(b's', "subsystem-match", Some("SUBSYSTEM[/DEVTYPE]"), Some("Filter events by subsystem")),
    o(b't', "tag-match", Some("TAG"), Some("Filter events by tag")),
    common::introspect_cli(INTROSPECT),
];

pub const TEST_BUILTIN: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'a', "action", Some("ACTION|help"), Some("Set action string")),
    common::introspect_cli(INTROSPECT),
];

pub const WAIT: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b't', "timeout", Some("SEC"), Some("Maximum time to wait for the device")),
    l("initialized", Some("BOOL"), Some("Wait for devices being initialized by systemd-udevd")),
    l("removed", None, Some("Wait for devices being removed")),
    l("settle", None, Some("Also wait for all queued events being processed")),
    common::introspect_cli(INTROSPECT),
];

pub const LOCK: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'd', "device", Some("DEVICE"), Some("Block device to lock")),
    o(b'b', "backing", Some("FILE"), Some("File whose backing block device to lock")),
    o(b't', "timeout", Some("SECS"), Some("Block at most the specified time waiting for lock")),
    o(b'p', "print", None, Some("Only show which device would be locked, without running the command")),
    common::introspect_cli(INTROSPECT),
];

/// A verb of a later phase: its `--help`, `--version` and
/// `--introspect-cli` work, anything else fails.
pub fn verb_main(name: &str, argv: Vec<Vec<u8>>) -> i32 {
    let options = crate::VERBS.iter().find(|v| v.verb == name).and_then(|v| v.options).expect("verb has options");
    let mut opts = OptionParser::new(argv, options);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(HELP)) => {
                let r = crate::print_verb_help(name);
                if r < 0 || name != "test-builtin" {
                    return r;
                }
                shared::options::help_section("Commands");
                crate::udev::builtin::udev_builtin_list();
                return 0;
            }
            Ok(Some(VERSION)) => return shared::build::version_only(),
            Ok(Some(INTROSPECT)) => return crate::introspect(shared::json::SD_JSON_FORMAT_OFF),
            Ok(Some(_)) => {}
        }
    }
    log_error_errno!(synthetic(libc::EOPNOTSUPP), "udevadm ", name, " is not ported yet.")
}

/// `run_udevd()`.
pub fn run_udevd(_argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_setup();
    log_error_errno!(synthetic(libc::EOPNOTSUPP), "systemd-udevd is not ported yet.")
}
