// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm`: a port of systemd's `src/udev/udevadm*.c` (v262), with the
//! rules engine in [`udev`].

use std::sync::atomic::{AtomicU32, Ordering};

use shared::options::{
    Command, Opt, OptionParser, ParserMode, VERB_ANY, VERB_DEPRECATED, VERB_OPTION_REQUIRED, Verb, command_print_help,
    common, dispatch_verb, introspect_cli_commands,
};

mod cat;
mod control;
mod hwdb;
mod info;
mod lock;
mod monitor;
mod settle;
mod test;
mod test_builtin;
mod trigger;
mod udevd;
mod verify;
mod wait;

pub use udevadm::{udev, util};

/// `arg_pager_flags`.
pub static PAGER_FLAGS: AtomicU32 = AtomicU32::new(0);

pub fn pager_flags() -> u32 {
    PAGER_FLAGS.load(Ordering::Relaxed)
}

const OPT_HELP: i32 = 0x100;
const OPT_VERSION: i32 = 0x101;
const OPT_DEBUG: i32 = 0x102;
const OPT_INTROSPECT_CLI: i32 = 0x103;

/// The `udevadm` namespace of `parse_argv()`.
const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version_with_v(OPT_VERSION),
    Opt::new(OPT_DEBUG, b'd', Some("debug"), None, Some("Enable debug logging")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

/// `UDEVADM_VERB(fn, name, args, flags, help, footer)`.
const fn udevadm_verb(
    name: &'static str,
    argspec: &'static [&'static str],
    flags: u32,
    help: &'static str,
    options: &'static [Opt],
    footer: Option<&'static str>,
) -> Verb {
    Verb::new(name, argspec, VERB_ANY, VERB_ANY, flags, Some(help)).with_options(options, footer)
}

/// The verbs, in the order of `udevadm.c`.
pub const VERBS: &[Verb] = &[
    Verb::new("help", &[], VERB_ANY, VERB_ANY, 0, Some("Show this help")),
    udevadm_verb("info", &["[DEVPATH|FILE]"], 0, "Query sysfs or the udev database", info::OPTIONS, None),
    udevadm_verb("trigger", &["DEVPATH"], 0, "Request events from the kernel", trigger::OPTIONS, None),
    udevadm_verb("settle", &[], 0, "Wait for pending udev events", settle::OPTIONS, None),
    udevadm_verb("control", &[], VERB_OPTION_REQUIRED, "Control the udev daemon", control::OPTIONS, None),
    udevadm_verb("monitor", &[], 0, "Listen to kernel and udev events", monitor::OPTIONS, None),
    udevadm_verb("test", &["DEVPATH"], 0, "Test an event run", test::OPTIONS, None),
    udevadm_verb("test-builtin", &["COMMAND DEVPATH"], 0, "Test a built-in command", test_builtin::OPTIONS, None),
    udevadm_verb("verify", &["[FILE\u{2026}]"], 0, "Verify udev rules files", verify::OPTIONS, None),
    udevadm_verb("cat", &["[FILE\u{2026}]"], 0, "Show udev rules files", cat::OPTIONS, None),
    udevadm_verb("wait", &["DEVICE [DEVICE\u{2026}]"], 0, "Wait for device or device symlink", wait::OPTIONS, None),
    udevadm_verb("lock", &["COMMAND", "--print"], 0, "Lock a block device and run a command", lock::OPTIONS, None),
    udevadm_verb(
        "hwdb",
        &[],
        VERB_DEPRECATED,
        "Update or query the hardware database",
        hwdb::OPTIONS,
        Some("Verb 'hwdb' is deprecated. Use systemd-hwdb instead."),
    ),
    Verb::new("version", &[], VERB_ANY, 1, 0, None),
];

pub const COMMAND: Command = Command {
    names: &["udevadm"],
    abstract_: "Send control commands or test the device manager.",
    argspec: &["COMMAND [COMMAND OPTION\u{2026}]"],
    footer: None,
    man_pages: &["udevadm(8)"],
    verbs: VERBS,
};

/// `command_print_help_name("udevadm")`.
pub fn print_help() -> i32 {
    command_print_help(&COMMAND, OPTIONS, Some(pager_flags()))
}

/// `command_print_verb_help(name)`.
pub fn print_verb_help(name: &str) -> i32 {
    shared::options::command_print_verb_help(&COMMAND, name, Some(pager_flags()))
}

const UDEVD_OPTIONS: &[Opt] = udevd::config::OPTIONS;

/// The `COMMAND()` of `udev-config.c`.
pub const UDEVD_COMMAND: Command = Command {
    names: &["systemd-udevd"],
    abstract_: "Rule-based manager for device events and files.",
    argspec: &[],
    footer: None,
    man_pages: &["systemd-udevd.service(8)"],
    verbs: &[],
};

/// `command_print_help_name("systemd-udevd")`.
pub fn print_udevd_help() -> i32 {
    command_print_help(&UDEVD_COMMAND, UDEVD_OPTIONS, Some(pager_flags()))
}

/// `introspect_cli(flags)`: udevadm, then systemd-udevd.
pub fn introspect(flags: u32) -> i32 {
    introspect_cli_commands(&[(&COMMAND, OPTIONS), (&UDEVD_COMMAND, UDEVD_OPTIONS)], flags)
}

/// `parse_argv()`: the arguments left for the verb, or `Err(r)`/`Ok(None)`
/// to return `r`/0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Vec<Vec<u8>>>, i32> {
    let mut opts = OptionParser::new(argv, OPTIONS);
    opts.mode = ParserMode::StopAtFirstNonoption;
    while let Some(c) = opts.next()? {
        match c {
            OPT_HELP => {
                let r = print_help();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            OPT_VERSION => {
                shared::build::version_only();
                return Ok(None);
            }
            OPT_DEBUG => {
                shared::log::log_set_max_level(shared::log::LOG_DEBUG);
            }
            OPT_INTROSPECT_CLI => {
                let r = introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            _ => unreachable!("option id {c}"),
        }
    }
    Ok(Some(opts.args().to_vec()))
}

/// `run()`.
fn run(argv: Vec<Vec<u8>>) -> i32 {
    if util::invoked_as(&argv, b"udevd") {
        return udevd::run_udevd(argv);
    }
    let _ = udev::util::udev_parse_config();
    shared::log::log_setup();
    let args = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    // mac_init(): no SELinux in this build.
    let (verb, vargs) = match dispatch_verb(&args, VERBS) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match verb.verb {
        "help" => print_help(),
        "info" => info::verb_info_main(vargs),
        "test" => test::verb_test_main(vargs),
        "verify" => verify::verb_verify_main(vargs),
        "cat" => cat::verb_cat_main(vargs),
        "hwdb" => hwdb::verb_hwdb_main(vargs),
        "control" => control::verb_control_main(vargs),
        "settle" => settle::verb_settle_main(vargs),
        "monitor" => monitor::verb_monitor_main(vargs),
        "trigger" => trigger::verb_trigger_main(vargs),
        "wait" => wait::verb_wait_main(vargs),
        "lock" => lock::verb_lock_main(vargs),
        "version" => shared::build::version_only(),
        "test-builtin" => test_builtin::verb_test_builtin_main(vargs),
        _ => unreachable!("every verb is handled"),
    }
}

fn main() {
    shared::main_func::main_with_positive_failure(run)
}
