// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udevadm-hwdb.c`: the deprecated `udevadm hwdb`.

use shared::errno::synthetic;
use shared::hwdb::{hwdb_bypass, hwdb_query, hwdb_update};
use shared::options::{Opt, OptionParser, common};
use shared::{log_error_errno, log_notice};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const UPDATE: i32 = 0x102;
const STRICT: i32 = 0x103;
const USR: i32 = 0x104;
const TEST: i32 = 0x105;
const ROOT: i32 = 0x106;
const INTROSPECT: i32 = 0x107;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(UPDATE, b'u', Some("update"), None, Some("Update the hardware database")),
    Opt::new(
        STRICT,
        b's',
        Some("strict"),
        None,
        Some("When updating, return non-zero exit value on any parsing error"),
    ),
    Opt::long(USR, "usr", None, Some("Generate in /usr/lib/udev instead of /etc/udev")),
    Opt::new(TEST, b't', Some("test"), Some("MODALIAS"), Some("Query database and print result")),
    Opt::new(ROOT, b'r', Some("root"), Some("PATH"), Some("Alternative root path in the filesystem")),
    common::introspect_cli(INTROSPECT),
];

/// `verb_hwdb_main()`.
pub fn verb_hwdb_main(argv: Vec<Vec<u8>>) -> i32 {
    let mut test: Option<Vec<u8>> = None;
    let mut root: Option<Vec<u8>> = None;
    let mut bin_dir: Option<&[u8]> = None;
    let mut update = false;
    let mut strict = false;
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(HELP)) => return crate::print_verb_help("hwdb"),
            Ok(Some(VERSION)) => return shared::build::version_only(),
            Ok(Some(UPDATE)) => update = true,
            Ok(Some(STRICT)) => strict = true,
            Ok(Some(USR)) => bin_dir = Some(b"/usr/lib/udev"),
            Ok(Some(TEST)) => test = opts.arg.clone(),
            Ok(Some(ROOT)) => root = opts.arg.clone(),
            Ok(Some(INTROSPECT)) => return crate::introspect(shared::json::SD_JSON_FORMAT_OFF),
            Ok(Some(c)) => unreachable!("option id {c}"),
        }
    }
    if !update && test.is_none() {
        return log_error_errno!(synthetic(libc::EINVAL), "Either --update or --test must be used.");
    }
    log_notice!("udevadm hwdb is deprecated. Use systemd-hwdb instead.");
    if update && !hwdb_bypass() {
        let r = hwdb_update(root.as_deref(), bin_dir, strict, true);
        if r < 0 {
            return r;
        }
    }
    if let Some(t) = test {
        return hwdb_query(&t, root.as_deref());
    }
    0
}
