// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-test.c`.

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_INFO, LogTarget, log_get_max_level, log_get_target};
use shared::options::{Opt, OptionParser, common};
use shared::sd_device::Action;
use shared::{log_error_errno, log_info};

use crate::udev::def::{EventMode, ResolveNameTiming};
use crate::udev::event::{Event, udev_event_execute_rules};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const ACTION: i32 = 0x102;
const RESOLVE_NAMES: i32 = 0x103;
const EXTRA_RULES_DIR: i32 = 0x104;
const VERBOSE: i32 = 0x105;
const JSON: i32 = 0x106;
const INTROSPECT: i32 = 0x107;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(ACTION, b'a', Some("action"), Some("ACTION|help"), Some("Set action string")),
    crate::verify::resolve_names(RESOLVE_NAMES),
    Opt::new(EXTRA_RULES_DIR, b'D', Some("extra-rules-dir"), Some("DIR"), Some("Also load rules from the directory")),
    Opt::new(VERBOSE, b'v', Some("verbose"), None, Some("Show verbose logs")),
    Opt::long(JSON, "json", Some("FORMAT"), Some("Generate JSON output (pretty, short, or off)")),
    common::introspect_cli(INTROSPECT),
];

/// `maybe_insert_empty_line()`.
fn maybe_insert_empty_line() {
    if log_get_max_level() < LOG_INFO {
        return;
    }
    let target = log_get_target();
    if !matches!(target, LogTarget::Console | LogTarget::ConsolePrefixed | LogTarget::Auto) {
        return;
    }
    if target == LogTarget::Auto && shared::log::stderr_is_journal() {
        return;
    }
    shared::stdio::err(b"\n");
}

/// `verb_test_main()`.
pub fn verb_test_main(argv: Vec<Vec<u8>>) -> i32 {
    let mut action = Action::Add;
    let mut timing = ResolveNameTiming::Early;
    let mut extra_rules_dir: Vec<Vec<u8>> = Vec::new();
    let mut verbose = false;
    let mut json = shared::json::SD_JSON_FORMAT_OFF;
    shared::log::log_set_max_level(LOG_DEBUG);
    shared::log::log_setup();
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        let c = opts.next();
        let arg = || opts.arg.clone().unwrap_or_default();
        match c {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(HELP)) => return crate::print_verb_help("test"),
            Ok(Some(VERSION)) => return shared::build::version_only(),
            Ok(Some(ACTION)) => match crate::util::parse_device_action(&arg()) {
                Ok(Some(a)) => action = a,
                Ok(None) => return 0,
                Err(r) => return r,
            },
            Ok(Some(RESOLVE_NAMES)) => match crate::util::parse_resolve_name_timing(&arg()) {
                Ok(Some(t)) => timing = t,
                Ok(None) => return 0,
                Err(r) => return r,
            },
            Ok(Some(EXTRA_RULES_DIR)) => match crate::util::parse_path_argument(&arg(), false) {
                Ok(Some(p)) => extra_rules_dir.push(p),
                Ok(None) => {}
                Err(r) => return r,
            },
            Ok(Some(VERBOSE)) => verbose = true,
            Ok(Some(JSON)) => match shared::json::parse_json_argument(&arg()) {
                Ok(Some(f)) => json = f,
                Ok(None) => return 0,
                Err(r) => return r,
            },
            Ok(Some(INTROSPECT)) => return crate::introspect(json),
            Ok(Some(c)) => unreachable!("option id {c}"),
        }
    }
    let Some(syspath) = opts.args().first().cloned() else {
        return log_error_errno!(synthetic(libc::EINVAL), "syspath parameter missing.");
    };

    log_info!(
        "This program is for debugging only, it does not run any program\n",
        "specified by a RUN key. It may show incorrect results, because\n",
        "some values may be different, or not available at a simulation run."
    );

    maybe_insert_empty_line();
    log_info!("Loading builtins...");
    crate::udev::builtin::udev_builtin_init();
    log_info!("Loading builtins done.");

    maybe_insert_empty_line();
    log_info!("Loading udev rules files...");
    let rules = match crate::udev::rules::udev_rules_load(timing, &extra_rules_dir) {
        Ok(r) => r,
        Err(r) => {
            // C's cleanup runs the exit hooks after the error is logged.
            let r = log_error_errno!(r, "Failed to read udev rules: ", strerror(r));
            crate::udev::builtin::udev_builtin_exit();
            return r;
        }
    };
    log_info!("Loading udev rules files done.");

    let dev = match crate::util::find_device_with_action(&syspath, action) {
        Ok(d) => d,
        Err(r) => {
            let r = log_error_errno!(r, "Failed to open device '", &syspath, "': ", strerror(r));
            crate::udev::builtin::udev_builtin_exit();
            return r;
        }
    };
    // Don't read info from the db.
    dev.seal();

    let mut event = Event::new(&dev, EventMode::UdevadmTest);
    event.trace = verbose;
    let _mask = shared::sys::block_all_signals();

    maybe_insert_empty_line();
    log_info!(
        "Processing udev rules",
        if verbose { "" } else { " (verbose logs can be shown by -v/--verbose)" },
        "..."
    );
    let _ = udev_event_execute_rules(&mut event, &rules);
    log_info!("Processing udev rules done.");

    maybe_insert_empty_line();
    let r = match crate::udev::dump::dump_event(&event, json) {
        Ok(text) => {
            shared::stdio::out(&text);
            0
        }
        Err(r) => log_error_errno!(r, "Failed to dump result: ", strerror(r)),
    };
    if r < 0 {
        crate::udev::builtin::udev_builtin_exit();
        return r;
    }
    maybe_insert_empty_line();
    crate::udev::builtin::udev_builtin_exit();
    0
}
