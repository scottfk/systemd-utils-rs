// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-cat.c`.

use shared::errno::synthetic;
use shared::log_error_errno;
use shared::options::{Opt, OptionParser, common};
use shared::pretty_print::{CAT_TLDR, cat_files_full, conf_files_cat};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const ROOT: i32 = 0x102;
const TLDR: i32 = 0x103;
const CONFIG: i32 = 0x104;
const INTROSPECT: i32 = 0x105;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::long(ROOT, "root", Some("PATH"), Some("Operate on an alternate filesystem root")),
    Opt::long(TLDR, "tldr", None, Some("Skip comments and empty lines")),
    Opt::long(CONFIG, "config", None, Some("Show udev.conf rather than udev rules files")),
    common::introspect_cli(INTROSPECT),
];

/// `verb_cat_main()`.
pub fn verb_cat_main(argv: Vec<Vec<u8>>) -> i32 {
    let mut root: Option<Vec<u8>> = None;
    let mut cat_flags = 0;
    let mut config = false;
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(HELP)) => return crate::print_verb_help("cat"),
            Ok(Some(VERSION)) => return shared::build::version_only(),
            Ok(Some(ROOT)) => match crate::util::parse_path_argument(opts.arg.as_deref().unwrap_or_default(), true) {
                Ok(p) => root = p,
                Err(r) => return r,
            },
            Ok(Some(TLDR)) => cat_flags = CAT_TLDR,
            Ok(Some(CONFIG)) => config = true,
            Ok(Some(INTROSPECT)) => return crate::introspect(shared::json::SD_JSON_FORMAT_OFF),
            Ok(Some(c)) => unreachable!("option id {c}"),
        }
    }
    let args = opts.args().to_vec();
    if config && !args.is_empty() {
        return log_error_errno!(synthetic(libc::EINVAL), "Combination of --config and FILEs is not supported.");
    }
    if config {
        return conf_files_cat(root.as_deref(), b"udev/udev.conf", cat_flags);
    }
    let files = match crate::util::search_rules_files(&args, root.as_deref()) {
        Ok(f) => f,
        Err(r) => return r,
    };
    cat_files_full(None, &files, cat_flags)
}
