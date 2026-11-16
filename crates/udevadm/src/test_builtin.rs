// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-test-builtin.c`.

use shared::errno::{strerror, synthetic};
use shared::options::{Opt, OptionParser, common};
use shared::sd_device::Action;
use shared::{log_debug_errno, log_device_error_errno, log_error_errno};

use crate::udev::builtin::{
    udev_builtin_exit, udev_builtin_init, udev_builtin_list, udev_builtin_lookup, udev_builtin_run,
};
use crate::udev::def::EventMode;
use crate::udev::event::Event;
use crate::util::{find_device_with_action, parse_device_action};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const ACTION: i32 = 0x102;
const INTROSPECT: i32 = 0x103;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(ACTION, b'a', Some("action"), Some("ACTION|help"), Some("Set action string")),
    common::introspect_cli(INTROSPECT),
];

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(Action, Vec<u8>, Vec<u8>)>, i32> {
    let mut action = Action::Add;
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("test-builtin");
                if r < 0 {
                    return Err(r);
                }
                shared::options::help_section("Commands");
                udev_builtin_list();
                return Ok(None);
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            ACTION => match parse_device_action(&arg)? {
                None => return Ok(None),
                Some(a) => action = a,
            },
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    let args = opts.args();
    if args.len() != 2 {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Expected two arguments: command string and device path."
        ));
    }
    Ok(Some((action, args[0].clone(), args[1].clone())))
}

/// `verb_builtin_main()`.
pub fn verb_test_builtin_main(argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_set_max_level(shared::log::LOG_DEBUG);
    shared::log::log_setup();
    let (action, command, syspath) = match parse_argv(argv) {
        Ok(Some(x)) => x,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    udev_builtin_init();
    let r = run(action, &command, &syspath);
    udev_builtin_exit();
    r
}

fn run(action: Action, command: &[u8], syspath: &[u8]) -> i32 {
    let Some(cmd) = udev_builtin_lookup(command) else {
        return log_error_errno!(synthetic(libc::EINVAL), "Unknown command '", command, "'");
    };
    let dev = match find_device_with_action(syspath, action) {
        Ok(d) => d,
        Err(r) => return log_error_errno!(r, "Failed to open device '", syspath, "': ", strerror(r)),
    };
    let mut event = Event::new(&dev, EventMode::UdevadmTestBuiltin);
    if action != Action::Remove {
        match dev.clone_with_db() {
            Ok(c) => event.dev_db_clone = Some(c),
            Err(r) => return log_device_error_errno!(dev, r, "Failed to clone device: ", strerror(r)),
        }
    }
    if let Err(r) = udev_builtin_run(&mut event, cmd, command) {
        return log_debug_errno!(r, "Builtin command '", command, "' fails: ", strerror(r));
    }
    0
}
