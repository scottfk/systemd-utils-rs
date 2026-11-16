// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-verify.c`.

use shared::conf_files::ConfFile;
use shared::errno::{ret_gather, strerror, synthetic};
use shared::log::{LOG_ERR, LOG_NOTICE, LOG_WARNING};
use shared::options::{Opt, OptionParser, common};
use shared::terminal::ansi;
use shared::{log_error_errno, log_warning_errno, printo};

use crate::udev::def::ResolveNameTiming;
use crate::udev::rules::Rules;

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const RESOLVE_NAMES: i32 = 0x102;
const ROOT: i32 = 0x103;
const NO_SUMMARY: i32 = 0x104;
const NO_STYLE: i32 = 0x105;
const INTROSPECT: i32 = 0x106;

/// `OPTION_COMMON_RESOLVE_NAMES`.
pub const fn resolve_names(id: i32) -> Opt {
    Opt::new(
        id,
        b'N',
        Some("resolve-names"),
        Some("MODE"),
        Some("When to resolve users and groups (early, late, or never)"),
    )
}

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    resolve_names(RESOLVE_NAMES),
    Opt::long(ROOT, "root", Some("PATH"), Some("Operate on an alternate filesystem root")),
    Opt::long(NO_SUMMARY, "no-summary", None, Some("Do not show summary")),
    Opt::long(NO_STYLE, "no-style", None, Some("Ignore style issues")),
    common::introspect_cli(INTROSPECT),
];

/// `verify_rules_file()`.
fn verify_rules_file(rules: &mut Rules, c: &ConfFile, style: bool) -> i32 {
    let index = match rules.parse_file(c, true) {
        Ok(i) => i,
        Err(r) => {
            return log_error_errno!(r, "Failed to parse rules file ", c.original_path, ": ", strerror(r));
        }
    };
    let issues = rules.file_issues(index);
    let mask = (1u32 << LOG_ERR) | (1u32 << LOG_WARNING);
    if issues & mask != 0 {
        return log_error_errno!(synthetic(libc::EINVAL), c.original_path, ": udev rules check failed.");
    }
    if style && issues & (1u32 << LOG_NOTICE) != 0 {
        return log_warning_errno!(synthetic(libc::EINVAL), c.original_path, ": udev rules have style issues.");
    }
    0
}

/// `verb_verify_main()`.
pub fn verb_verify_main(argv: Vec<Vec<u8>>) -> i32 {
    let mut timing = ResolveNameTiming::Early;
    let mut root: Option<Vec<u8>> = None;
    let mut summary = true;
    let mut style = true;
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(HELP)) => return crate::print_verb_help("verify"),
            Ok(Some(VERSION)) => return shared::build::version_only(),
            Ok(Some(RESOLVE_NAMES)) => {
                match crate::util::parse_resolve_name_timing(opts.arg.as_deref().unwrap_or_default()) {
                    Ok(Some(t)) => timing = t,
                    Ok(None) => return 0,
                    Err(r) => return r,
                }
            }
            Ok(Some(ROOT)) => match crate::util::parse_path_argument(opts.arg.as_deref().unwrap_or_default(), true) {
                Ok(p) => root = p,
                Err(r) => return r,
            },
            Ok(Some(NO_SUMMARY)) => summary = false,
            Ok(Some(NO_STYLE)) => style = false,
            Ok(Some(INTROSPECT)) => return crate::introspect(shared::json::SD_JSON_FORMAT_OFF),
            Ok(Some(c)) => unreachable!("option id {c}"),
        }
    }
    let args = opts.args().to_vec();
    let mut rules = Rules::new(timing);
    let files = match crate::util::search_rules_files(&args, root.as_deref()) {
        Ok(f) => f,
        Err(r) => return r,
    };
    // verify_rules()
    let mut fail_count = 0usize;
    let mut success_count = 0usize;
    let mut ret = 0;
    for c in &files {
        let r = verify_rules_file(&mut rules, c, style);
        if r < 0 {
            fail_count += 1;
        } else {
            success_count += 1;
        }
        ret_gather(&mut ret, r);
    }
    if summary {
        printo!(
            "\n",
            ansi::highlight(),
            (fail_count + success_count).to_string(),
            " udev rules files have been checked.",
            ansi::normal(),
            "\n  Success: ",
            success_count.to_string(),
            "\n",
            if fail_count > 0 { ansi::highlight_red() } else { "" },
            "  Fail:    ",
            fail_count.to_string(),
            if fail_count > 0 { ansi::normal() } else { "" },
            "\n"
        );
    }
    ret
}
