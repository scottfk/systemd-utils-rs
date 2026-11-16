// SPDX-License-Identifier: GPL-2.0-or-later
//! What the udev helper programs share: the `COMMAND()` options every one
//! of them takes (`--help`, `--version`, `--introspect-cli`).

use shared::options::{Command, Opt, OptionParser, command_print_help, common, introspect_cli};

pub const OPT_HELP: i32 = 0x100;
pub const OPT_VERSION: i32 = 0x101;
pub const OPT_INTROSPECT_CLI: i32 = 0x102;

/// `OPTION_COMMON_HELP`, `OPTION_COMMON_VERSION` and
/// `OPTION_COMMON_INTROSPECT_CLI`.
pub const COMMON_OPTIONS: &[Opt] =
    &[common::help(OPT_HELP), common::version(OPT_VERSION), common::introspect_cli(OPT_INTROSPECT_CLI)];

/// Handles a common option: `Some(r)` to return `r` from `parse_argv()`
/// (0 to exit successfully).
pub fn common_option(c: i32, cmd: &Command, options: &[Opt]) -> Option<i32> {
    match c {
        OPT_HELP => Some(command_print_help(cmd, options, None)),
        OPT_VERSION => {
            shared::build::version();
            Some(0)
        }
        OPT_INTROSPECT_CLI => Some(introspect_cli(cmd, options, shared::json::SD_JSON_FORMAT_OFF)),
        _ => None,
    }
}

/// `parse_argv()` of a helper that only takes the common options: the
/// positional arguments, or Err(r) to return r (0 to exit successfully).
pub fn parse_common_argv(argv: Vec<Vec<u8>>, cmd: &Command) -> Result<Vec<Vec<u8>>, i32> {
    let mut opts = OptionParser::new(argv, COMMON_OPTIONS);
    while let Some(c) = opts.next()? {
        if let Some(r) = common_option(c, cmd, COMMON_OPTIONS) {
            return Err(r.min(0));
        }
    }
    Ok(opts.args().to_vec())
}

/// `printf()` to stdout.
#[macro_export]
macro_rules! out {
    ($($e:expr),* $(,)?) => {{
        use std::io::Write as _;
        let _ = std::io::stdout().write_all(&shared::bcat!($($e),*));
    }};
}
