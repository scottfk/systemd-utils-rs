// SPDX-License-Identifier: GPL-2.0-or-later
//! The verbs of later phases (`test-builtin`).  Their option tables are
//! here already, so `--help` and `--introspect-cli` match C; running
//! them fails until they're ported.

use shared::errno::synthetic;
use shared::log_error_errno;
use shared::options::{Opt, OptionParser, common};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const INTROSPECT: i32 = 0x102;
/// Every option that only matters once the verb runs.
const OTHER: i32 = 0x103;

const fn o(short: u8, long: &'static str, metavar: Option<&'static str>, help: Option<&'static str>) -> Opt {
    Opt::new(OTHER, short, Some(long), metavar, help)
}

pub const TEST_BUILTIN: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    o(b'a', "action", Some("ACTION|help"), Some("Set action string")),
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
