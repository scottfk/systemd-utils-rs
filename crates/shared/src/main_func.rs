// SPDX-License-Identifier: LGPL-2.1-or-later
//! `main-func.c`: what `DEFINE_MAIN_FUNCTION()` does around `run()`.

use std::os::unix::ffi::OsStringExt;

/// `main_prepare()` + `run(argc, argv)` + `main_finalize()`, then exit
/// with `exit_failure_if_negative()`.
pub fn main_with(run: fn(Vec<Vec<u8>>) -> i32) -> ! {
    let argv: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    assert!(!argv.is_empty() && !argv[0].is_empty());
    crate::log::set_program_name(&argv[0]);
    crate::argv::save_argc_argv(&argv);
    let r = run(argv);
    let s = if r < 0 { libc::EXIT_FAILURE } else { libc::EXIT_SUCCESS };
    finalize(r, s);
    exit(s)
}

/// `main_finalize(r, exit_status)`.
fn finalize(r: i32, s: i32) {
    if r < 0 {
        crate::notify::sd_notify(format!("ERRNO={}", -r).as_bytes());
    }
    crate::notify::sd_notify(format!("EXIT_STATUS={s}").as_bytes());
    crate::pager::pager_close();
}

/// `exit()`: flush stdout, then leave.
pub fn exit(code: i32) -> ! {
    crate::stdio::flush_stdout();
    crate::sys::exit_now(code)
}
