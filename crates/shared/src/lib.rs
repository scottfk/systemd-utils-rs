// SPDX-License-Identifier: LGPL-2.1-or-later
//! Ports of the parts of systemd's `src/basic`, `src/shared` and
//! `src/libsystemd` that the systemd-utils programs use.  Each module names
//! the C file it ports; each function names the C function.

pub mod argv;
pub mod build;
pub mod bytes;
pub mod chase;
pub mod conf_files;
pub mod creds;
pub mod env;
pub mod errno;
pub mod extract;
pub mod fd;
pub mod fileio;
pub mod fs;
pub mod glob;
pub mod json;
pub mod locale;
pub mod log;
pub mod main_func;
pub mod notify;
pub mod options;
pub mod pager;
pub mod parse;
pub mod path;
pub mod pretty_print;
pub mod proc_cmdline;
pub mod process;
pub mod signal;
pub mod stdio;
pub mod string;
pub mod sys;
pub mod sysctl_util;
pub mod table;
pub mod terminal;
pub mod time;
pub mod user;
pub mod utf8;
