// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-hwdb`: update or query the hardware database.  A port of
//! systemd's `src/hwdb/hwdb.c` (v262); the work is in `shared::hwdb`.

use std::sync::OnceLock;

use shared::hwdb::{hwdb_bypass, hwdb_query, hwdb_update};
use shared::options::{Command, Opt, OptionParser, Verb, command_print_help, common, dispatch_verb, introspect_cli};

const OPT_HELP: i32 = 0x100;
const OPT_VERSION: i32 = 0x101;
const OPT_STRICT: i32 = 0x102;
const OPT_ROOT: i32 = 0x103;
const OPT_USR: i32 = 0x104;
const OPT_INTROSPECT_CLI: i32 = 0x105;

/// The `OPTION()` table of `parse_argv()`, in source order.
const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::new(
        OPT_STRICT,
        b's',
        Some("strict"),
        None,
        Some("When updating, return non-zero exit value on any parsing error"),
    ),
    Opt::new(OPT_ROOT, b'r', Some("root"), Some("PATH"), Some("Alternative root path in the filesystem")),
    Opt::long(OPT_USR, "usr", None, Some("Generate in /usr/lib/udev instead of /etc/udev")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

/// The `VERB()` table, in source order.
const VERBS: &[Verb] = &[
    Verb::new("query", &["MODALIAS"], 2, 2, 0, Some("Query database and print result")),
    Verb::noarg("update", "Update the hwdb database"),
    Verb::help_hidden(),
];

const COMMAND: Command = Command {
    names: &["systemd-hwdb"],
    abstract_: "Update or query the hardware database.",
    argspec: &[],
    footer: None,
    man_pages: &["systemd-hwdb(8)"],
    verbs: VERBS,
};

/// The `arg_*` globals.
#[derive(Debug, Default)]
struct Args {
    hwdb_bin_dir: Option<Vec<u8>>,
    root: Option<Vec<u8>>,
    strict: bool,
}

static ARGS: OnceLock<Args> = OnceLock::new();

fn args() -> &'static Args {
    ARGS.get().expect("parse_argv() ran")
}

/// `parse_argv()`: `Ok(Some(args))` to go on, `Ok(None)` to exit successfully.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(Args, Vec<Vec<u8>>)>, i32> {
    let mut a = Args::default();
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            OPT_HELP => {
                let r = command_print_help(&COMMAND, OPTIONS, None);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            OPT_VERSION => {
                shared::build::version();
                return Ok(None);
            }
            OPT_STRICT => a.strict = true,
            OPT_ROOT => a.root = Some(arg),
            OPT_USR => a.hwdb_bin_dir = Some(b"/usr/lib/udev".to_vec()),
            OPT_INTROSPECT_CLI => {
                let r = introspect_cli(&COMMAND, OPTIONS, shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            _ => unreachable!("option id {c}"),
        }
    }
    Ok(Some((a, opts.args().to_vec())))
}

/// `run()`.
fn run(argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_setup();
    let (a, rest) = match parse_argv(argv) {
        Ok(Some(x)) => x,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    ARGS.set(a).expect("set once");
    let (verb, vargs) = match dispatch_verb(&rest, VERBS) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match verb.verb {
        "query" => hwdb_query(&vargs[1], args().root.as_deref()),
        "update" => {
            if hwdb_bypass() {
                return 0;
            }
            hwdb_update(args().root.as_deref(), args().hwdb_bin_dir.as_deref(), args().strict, false)
        }
        // verb_help_auto()
        _ => command_print_help(&COMMAND, OPTIONS, None),
    }
}

fn main() {
    shared::main_func::main_with(run)
}
