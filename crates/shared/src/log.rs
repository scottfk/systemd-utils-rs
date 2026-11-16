// SPDX-License-Identifier: LGPL-2.1-or-later
//! `log.c`: log targets, levels and the console/syslog/kmsg/journal writers.
//!
//! Messages are byte strings assembled by the caller (`%m` becomes
//! `errno::strerror(e)`).  Like C's `vsnprintf()` into `char buffer[LINE_MAX]`,
//! each message is cut at `LINE_MAX - 1` bytes.
//!
//! Known difference: `SYSTEMD_LOG_LOCATION=1` and the journal's `CODE_FILE=`
//! name the Rust source location, not the C one.

use std::sync::Mutex;

use crate::errno::{errno_value, is_synthetic, strerror};
use crate::extract::{EXTRACT_DONT_COALESCE_SEPARATORS, extract_first_word};
use crate::parse::{parse_boolean, safe_atou, safe_atou64};
use crate::string::NEWLINE;
use crate::terminal::{self, ansi, get_log_colors};
use crate::{bcat, sys};

pub use libc::{LOG_ALERT, LOG_CRIT, LOG_DEBUG, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING};

/// `LINE_MAX`.
pub const LINE_MAX: usize = 2048;
const SNDBUF_SIZE: i32 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    Console,
    ConsolePrefixed,
    Kmsg,
    Journal,
    JournalOrKmsg,
    Syslog,
    SyslogOrKmsg,
    Auto,
    Null,
}

const LOG_TARGET_TABLE: [(LogTarget, &str); 9] = [
    (LogTarget::Console, "console"),
    (LogTarget::ConsolePrefixed, "console-prefixed"),
    (LogTarget::Kmsg, "kmsg"),
    (LogTarget::Journal, "journal"),
    (LogTarget::JournalOrKmsg, "journal-or-kmsg"),
    (LogTarget::Syslog, "syslog"),
    (LogTarget::SyslogOrKmsg, "syslog-or-kmsg"),
    (LogTarget::Auto, "auto"),
    (LogTarget::Null, "null"),
];

/// `log_target_from_string()`.
pub fn log_target_from_string(s: &[u8]) -> Option<LogTarget> {
    LOG_TARGET_TABLE.iter().find(|(_, n)| n.as_bytes() == s).map(|(t, _)| *t)
}

/// `log_target_to_string()`.
pub fn log_target_to_string(t: LogTarget) -> &'static str {
    LOG_TARGET_TABLE.iter().find(|(x, _)| *x == t).map(|(_, n)| *n).unwrap_or("auto")
}

/// Index into `log_target_max_level[]`: console, kmsg, journal, syslog
/// (`_LOG_TARGET_SINGLE_MAX` is 4).
fn single_index(t: LogTarget) -> Option<usize> {
    match t {
        LogTarget::Console => Some(0),
        LogTarget::Kmsg => Some(1),
        LogTarget::Journal => Some(2),
        LogTarget::Syslog => Some(3),
        _ => None,
    }
}

const LOG_LEVEL_TABLE: [&str; 8] = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

/// `log_level_from_string()` (names, or numbers up to LOG_DEBUG).
pub fn log_level_from_string(s: &[u8]) -> Result<i32, i32> {
    if let Some(i) = LOG_LEVEL_TABLE.iter().position(|n| n.as_bytes() == s) {
        return Ok(i as i32);
    }
    let u = safe_atou(s).map_err(|_| -libc::EINVAL)?;
    if u > LOG_DEBUG as u32 {
        return Err(-libc::EINVAL);
    }
    Ok(u as i32)
}

/// `LOG_PRI()`.
pub const fn log_pri(level: i32) -> i32 {
    level & 0x07
}

/// `LOG_FAC()`.
pub const fn log_fac(level: i32) -> i32 {
    (level & 0x03f8) >> 3
}

/// `RateLimit` as used by `write_to_kmsg()`: 200 messages per 5 seconds.
#[derive(Debug)]
struct RateLimit {
    interval: u64,
    burst: u32,
    num: u32,
    begin: u64,
}

impl RateLimit {
    /// `ratelimit_below()`.
    fn below(&mut self) -> bool {
        let ts = sys::clock_usec(libc::CLOCK_MONOTONIC);
        if self.begin == 0 || ts.saturating_sub(self.begin) > self.interval {
            self.begin = ts;
            self.num = 1;
            return true;
        }
        if self.num < self.burst {
            self.num += 1;
            return true;
        }
        self.num = self.num.saturating_add(1);
        false
    }

    /// `ratelimit_num_dropped()`.
    fn num_dropped(&self) -> u32 {
        if self.num == u32::MAX {
            return u32::MAX;
        }
        self.num.saturating_sub(self.burst)
    }
}

#[derive(Debug)]
struct LogState {
    target: LogTarget,
    max_level: i32,
    target_max_level: [i32; 4],
    facility: i32,
    ratelimit_kmsg: bool,
    console_fd: i32,
    console_fd_is_tty: i32,
    syslog_fd: i32,
    kmsg_fd: i32,
    journal_fd: i32,
    syslog_is_stream: bool,
    show_color: i32,
    show_location: bool,
    show_time: bool,
    show_tid: bool,
    upgrade_syslog_to_journal: bool,
    always_reopen_console: bool,
    open_when_needed: bool,
    prohibit_ipc: bool,
    prefix: Option<Vec<u8>>,
    dumb: i32,
    kmsg_ratelimit: RateLimit,
}

// A process global, as in C: a library's callers may log from any thread.
static LOG: Mutex<LogState> = Mutex::new(LogState {
    target: LogTarget::Console,
    max_level: LOG_INFO,
    target_max_level: [i32::MAX; 4],
    facility: libc::LOG_DAEMON,
    ratelimit_kmsg: true,
    console_fd: 2,
    console_fd_is_tty: -1,
    syslog_fd: -1,
    kmsg_fd: -1,
    journal_fd: -1,
    syslog_is_stream: false,
    show_color: -1,
    show_location: false,
    show_time: false,
    show_tid: false,
    upgrade_syslog_to_journal: false,
    always_reopen_console: false,
    open_when_needed: false,
    prohibit_ipc: false,
    prefix: None,
    dumb: -1,
    kmsg_ratelimit: RateLimit { interval: 5_000_000, burst: 200, num: 0, begin: 0 },
});
static PROGRAM: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn with<R>(f: impl FnOnce(&mut LogState) -> R) -> R {
    f(&mut LOG.lock().unwrap_or_else(|e| e.into_inner()))
}

/// `program_invocation_short_name`.
pub fn program_name() -> Vec<u8> {
    let p = PROGRAM.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // In a library, nothing set it: use glibc's, as C does.
    if p.is_empty() { sys::program_invocation_short_name() } else { p }
}

/// `save_argc_argv()`'s effect on `program_invocation_short_name`: the
/// last component of argv[0].
pub fn set_program_name(argv0: &[u8]) {
    let short = match argv0.iter().rposition(|&b| b == b'/') {
        Some(i) => &argv0[i + 1..],
        None => argv0,
    };
    *PROGRAM.lock().unwrap_or_else(|e| e.into_inner()) = short.to_vec();
}

/// Set `program_invocation_short_name` directly (after `rename_process()`).
pub fn set_short_name(short: &[u8]) {
    *PROGRAM.lock().unwrap_or_else(|e| e.into_inner()) = short.to_vec();
}

/// `getpid_cached()`.
pub fn getpid_cached() -> i32 {
    sys::getpid()
}

/// `fd_move_above_stdio()`.
fn fd_move_above_stdio(fd: i32) -> i32 {
    if !(0..=2).contains(&fd) {
        return fd;
    }
    match sys::dup_cloexec(fd, 3) {
        Ok(copy) => {
            sys::close(fd);
            copy
        }
        Err(_) => fd,
    }
}

/// `safe_close_above_stdio()`.
fn safe_close_above_stdio(fd: i32) {
    if fd >= 3 {
        sys::close(fd);
    }
}

fn close_fd(fd: &mut i32) {
    if *fd >= 0 {
        sys::close(*fd);
    }
    *fd = -1;
}

fn log_close_console(s: &mut LogState) {
    safe_close_above_stdio(s.console_fd);
    s.console_fd = -1;
    s.console_fd_is_tty = -1;
}

fn log_open_console(s: &mut LogState) -> i32 {
    if !s.always_reopen_console {
        s.console_fd = 2;
        s.console_fd_is_tty = -1;
        return 0;
    }
    if s.console_fd < 3 {
        match sys::open(b"/dev/console", libc::O_WRONLY | libc::O_NOCTTY | libc::O_CLOEXEC, 0) {
            Ok(fd) => {
                s.console_fd = fd_move_above_stdio(fd);
                s.console_fd_is_tty = 1;
            }
            Err(e) => return e,
        }
    }
    0
}

fn log_close_kmsg(s: &mut LogState) {
    close_fd(&mut s.kmsg_fd);
}

fn log_open_kmsg(s: &mut LogState) -> i32 {
    if s.kmsg_fd >= 0 {
        return 0;
    }
    match sys::open(b"/dev/kmsg", libc::O_WRONLY | libc::O_NOCTTY | libc::O_CLOEXEC, 0) {
        Ok(fd) => {
            s.kmsg_fd = fd_move_above_stdio(fd);
            0
        }
        Err(e) => e,
    }
}

fn log_close_syslog(s: &mut LogState) {
    close_fd(&mut s.syslog_fd);
}

/// `create_log_socket()`.
fn create_log_socket(ty: i32) -> Result<i32, i32> {
    let fd = sys::socket(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0)?;
    let fd = fd_move_above_stdio(fd);
    // fd_inc_sndbuf(): only grow, and try SO_SNDBUFFORCE if needed.
    if let Ok(v) = sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF)
        && v < SNDBUF_SIZE * 2
        && sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, SNDBUF_SIZE).is_err()
    {
        let _ = sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, SNDBUF_SIZE);
    }
    let tv = if getpid_cached() == 1 { 10_000 } else { 10_000_000 };
    let _ = sys::set_sndtimeo(fd, tv);
    Ok(fd)
}

fn log_open_syslog(s: &mut LogState) -> i32 {
    if s.syslog_fd >= 0 {
        return 0;
    }
    let r = (|| -> Result<(), i32> {
        let fd = create_log_socket(libc::SOCK_DGRAM)?;
        s.syslog_fd = fd;
        if sys::connect_unix(fd, b"/dev/log").is_err() {
            sys::close(fd);
            s.syslog_fd = -1;
            let fd = create_log_socket(libc::SOCK_STREAM)?;
            s.syslog_fd = fd;
            sys::connect_unix(fd, b"/dev/log")?;
            s.syslog_is_stream = true;
        } else {
            s.syslog_is_stream = false;
        }
        Ok(())
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            log_close_syslog(s);
            e
        }
    }
}

fn log_close_journal(s: &mut LogState) {
    close_fd(&mut s.journal_fd);
}

fn log_open_journal(s: &mut LogState) -> i32 {
    if s.journal_fd >= 0 {
        return 0;
    }
    let r = (|| -> Result<(), i32> {
        let fd = create_log_socket(libc::SOCK_DGRAM)?;
        s.journal_fd = fd;
        sys::connect_unix(fd, b"/run/systemd/journal/socket")
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            log_close_journal(s);
            e
        }
    }
}

/// `stderr_is_journal()`.
pub fn stderr_is_journal() -> bool {
    let Some(e) = sys::getenv("JOURNAL_STREAM") else {
        return false;
    };
    let mut p = Some(&e[..]);
    let Ok(Some(w)) = extract_first_word(&mut p, Some(b":"), EXTRACT_DONT_COALESCE_SEPARATORS) else {
        return false;
    };
    let Some(rest) = p else {
        return false;
    };
    let (Ok(dev), Ok(ino)) = (safe_atou64(&w), safe_atou64(rest)) else {
        return false;
    };
    match sys::fstat(2) {
        Ok(st) => st.st_dev == dev && st.st_ino == ino,
        Err(_) => false,
    }
}

fn log_open_impl(s: &mut LogState) -> i32 {
    use LogTarget::*;
    let saved = sys::errno();
    let r = (|| {
        if s.target == Null {
            log_close_journal(s);
            log_close_syslog(s);
            log_close_console(s);
            return 0;
        }
        if getpid_cached() == 1
            || stderr_is_journal()
            || matches!(s.target, Kmsg | Journal | JournalOrKmsg | Syslog | SyslogOrKmsg)
        {
            if !s.prohibit_ipc {
                if matches!(s.target, Auto | JournalOrKmsg | Journal) {
                    let r = log_open_journal(s);
                    if r >= 0 {
                        log_close_syslog(s);
                        log_close_console(s);
                        return r;
                    }
                }
                if matches!(s.target, SyslogOrKmsg | Syslog) {
                    let r = log_open_syslog(s);
                    if r >= 0 {
                        log_close_journal(s);
                        log_close_console(s);
                        return r;
                    }
                }
            }
            if matches!(s.target, Auto | JournalOrKmsg | SyslogOrKmsg | Kmsg) {
                let r = log_open_kmsg(s);
                if r >= 0 {
                    log_close_journal(s);
                    log_close_syslog(s);
                    log_close_console(s);
                    return r;
                }
            }
        }
        log_close_journal(s);
        log_close_syslog(s);
        log_open_console(s)
    })();
    sys::set_errno(saved);
    r
}

/// `log_open()`.
pub fn log_open() -> i32 {
    with(log_open_impl)
}

/// `log_close()`.
pub fn log_close() {
    with(|s| {
        log_close_journal(s);
        log_close_syslog(s);
        log_close_kmsg(s);
        log_close_console(s);
    })
}

/// `log_forget_fds()`.
pub fn log_forget_fds() {
    with(|s| {
        s.console_fd = -1;
        s.kmsg_fd = -1;
        s.syslog_fd = -1;
        s.journal_fd = -1;
        s.console_fd_is_tty = -1;
    })
}

/// `log_set_target()`.
pub fn log_set_target(mut t: LogTarget) {
    with(|s| {
        if s.upgrade_syslog_to_journal {
            if t == LogTarget::Syslog {
                t = LogTarget::Journal;
            } else if t == LogTarget::SyslogOrKmsg {
                t = LogTarget::JournalOrKmsg;
            }
        }
        s.target = t;
    })
}

/// `log_get_target()`.
pub fn log_get_target() -> LogTarget {
    with(|s| s.target)
}

/// `log_set_max_level()`.
pub fn log_set_max_level(level: i32) -> i32 {
    let old = with(|s| std::mem::replace(&mut s.max_level, level));
    sys::setlogmask_upto(level);
    old
}

/// `log_get_max_level()`.
pub fn log_get_max_level() -> i32 {
    with(|s| s.max_level)
}

/// `DEBUG_LOGGING`.
pub fn debug_logging() -> bool {
    log_get_max_level() >= LOG_DEBUG
}

/// Would a message at `level` be logged at all?
pub fn enabled(level: i32) -> bool {
    log_pri(level) <= log_get_max_level()
}

pub fn log_set_facility(f: i32) {
    with(|s| s.facility = f)
}

pub fn log_show_color(b: bool) {
    with(|s| s.show_color = b as i32)
}

/// `log_get_show_color()`.
pub fn log_get_show_color() -> bool {
    with(|s| s.show_color > 0)
}

pub fn log_show_location(b: bool) {
    with(|s| s.show_location = b)
}

pub fn log_show_time(b: bool) {
    with(|s| s.show_time = b)
}

pub fn log_show_tid(b: bool) {
    with(|s| s.show_tid = b)
}

pub fn log_set_always_reopen_console(b: bool) {
    with(|s| s.always_reopen_console = b)
}

pub fn log_set_open_when_needed(b: bool) {
    with(|s| s.open_when_needed = b)
}

pub fn log_set_prohibit_ipc(b: bool) {
    with(|s| s.prohibit_ipc = b)
}

/// `log_set_upgrade_syslog_to_journal()`.
pub fn log_set_upgrade_syslog_to_journal(b: bool) {
    with(|s| {
        s.upgrade_syslog_to_journal = b;
        if b {
            if s.target == LogTarget::Syslog {
                s.target = LogTarget::Journal;
            } else if s.target == LogTarget::SyslogOrKmsg {
                s.target = LogTarget::JournalOrKmsg;
            }
        }
    })
}

/// `log_set_prefix()`; returns the old prefix.
pub fn log_set_prefix(prefix: Option<Vec<u8>>) -> Option<Vec<u8>> {
    with(|s| std::mem::replace(&mut s.prefix, prefix))
}

/// `log_on_console()`.
pub fn log_on_console() -> bool {
    with(|s| {
        if matches!(s.target, LogTarget::Console | LogTarget::ConsolePrefixed) {
            return true;
        }
        s.syslog_fd < 0 && s.kmsg_fd < 0 && s.journal_fd < 0
    })
}

/// `log_dup_console()`.
pub fn log_dup_console() -> i32 {
    with(|s| {
        if s.console_fd < 0 || s.console_fd >= 3 {
            return 0;
        }
        match sys::dup_cloexec(s.console_fd, 3) {
            Ok(c) => {
                s.console_fd = c;
                0
            }
            Err(e) => e,
        }
    })
}

/// `log_set_target_from_string()`.
pub fn log_set_target_from_string(e: &[u8]) -> Result<(), i32> {
    let t = log_target_from_string(e).ok_or(-libc::EINVAL)?;
    log_set_target(t);
    Ok(())
}

/// `log_set_max_level_from_string()`: "level" or "target:level", comma-separated.
pub fn log_set_max_level_from_string(e: &[u8]) -> Result<(), i32> {
    let mut p = Some(e);
    loop {
        let Some(word) = extract_first_word(&mut p, Some(b","), 0)? else {
            break;
        };
        match word.iter().position(|&b| b == b':') {
            None => {
                let l = log_level_from_string(&word)?;
                log_set_max_level(l);
            }
            Some(i) => {
                let target = log_target_from_string(&word[..i]).ok_or(-libc::EINVAL)?;
                let idx = single_index(target).ok_or(-libc::EINVAL)?;
                let l = log_level_from_string(&word[i + 1..])?;
                with(|s| s.target_max_level[idx] = l);
            }
        }
    }
    Ok(())
}

fn bool_from_string(e: &[u8], f: fn(bool)) -> Result<(), i32> {
    f(parse_boolean(e)?);
    Ok(())
}

fn set_ratelimit_kmsg(b: bool) {
    with(|s| s.ratelimit_kmsg = b)
}

/// `parse_proc_cmdline_item()`.
fn parse_proc_cmdline_item(key: &[u8], value: Option<&[u8]>) -> i32 {
    use crate::proc_cmdline::{key_streq, value_missing};
    if key == b"debug" && value.is_none() {
        log_set_max_level(LOG_DEBUG);
    } else if key_streq(key, b"systemd.log_target") {
        if value_missing(key, value) {
            return 0;
        }
        let v = value.unwrap_or_default();
        if log_set_target_from_string(v).is_err() {
            crate::log_warning!("Failed to parse log target '", v, "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_level") {
        if value_missing(key, value) {
            return 0;
        }
        let v = value.unwrap_or_default();
        if log_set_max_level_from_string(v).is_err() {
            crate::log_warning!("Failed to parse log level setting '", v, "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_color") {
        if bool_from_string(value.unwrap_or(b"1"), log_show_color).is_err() {
            crate::log_warning!("Failed to parse log color setting '", value.unwrap_or(b"(null)"), "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_location") {
        if bool_from_string(value.unwrap_or(b"1"), log_show_location).is_err() {
            crate::log_warning!("Failed to parse log location setting '", value.unwrap_or(b"(null)"), "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_tid") {
        if bool_from_string(value.unwrap_or(b"1"), log_show_tid).is_err() {
            crate::log_warning!("Failed to parse log tid setting '", value.unwrap_or(b"(null)"), "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_time") {
        if bool_from_string(value.unwrap_or(b"1"), log_show_time).is_err() {
            crate::log_warning!("Failed to parse log time setting '", value.unwrap_or(b"(null)"), "', ignoring.");
        }
    } else if key_streq(key, b"systemd.log_ratelimit_kmsg")
        && bool_from_string(value.unwrap_or(b"1"), set_ratelimit_kmsg).is_err()
    {
        crate::log_warning!("Failed to parse log ratelimit kmsg boolean '", value.unwrap_or(b"(null)"), "', ignoring.");
    }
    0
}

/// `should_parse_proc_cmdline()`.
fn should_parse_proc_cmdline() -> bool {
    if getpid_cached() == 1 {
        return true;
    }
    crate::proc_cmdline::invoked_by_systemd()
}

/// `log_parse_environment_variables()`.
pub fn log_parse_environment_variables() {
    if let Some(e) = sys::getenv("SYSTEMD_LOG_TARGET")
        && log_set_target_from_string(&e).is_err()
    {
        crate::log_warning!("Failed to parse log target '", e, "', ignoring.");
    }
    if let Some(e) = sys::getenv("SYSTEMD_LOG_LEVEL") {
        if let Err(r) = log_set_max_level_from_string(&e) {
            crate::log_warning_errno!(r, "Failed to parse log level '", e, "', ignoring: ", strerror(r));
        }
    } else {
        match crate::env::getenv_bool("DEBUG_INVOCATION") {
            Err(r) if r != -libc::ENXIO => {
                crate::log_warning_errno!(r, "Failed to parse $DEBUG_INVOCATION value, ignoring: ", strerror(r));
            }
            Ok(true) => {
                log_set_max_level(LOG_DEBUG);
            }
            _ => {}
        }
    }
    let flags: [(&str, fn(bool), &str); 4] = [
        ("SYSTEMD_LOG_COLOR", log_show_color, "color"),
        ("SYSTEMD_LOG_LOCATION", log_show_location, "location"),
        ("SYSTEMD_LOG_TIME", log_show_time, "time"),
        ("SYSTEMD_LOG_TID", log_show_tid, "tid"),
    ];
    for (var, f, what) in flags {
        if let Some(e) = sys::getenv(var)
            && bool_from_string(&e, f).is_err()
        {
            crate::log_warning!("Failed to parse log ", what, " '", e, "', ignoring.");
        }
    }
    if let Some(e) = sys::getenv("SYSTEMD_LOG_RATELIMIT_KMSG")
        && bool_from_string(&e, set_ratelimit_kmsg).is_err()
    {
        crate::log_warning!("Failed to parse log ratelimit kmsg boolean '", e, "', ignoring.");
    }
}

/// `log_parse_environment()`.
pub fn log_parse_environment() {
    if should_parse_proc_cmdline() {
        let _ = crate::proc_cmdline::proc_cmdline_parse(parse_proc_cmdline_item, true);
    }
    log_parse_environment_variables();
}

/// `log_setup()`.
pub fn log_setup() {
    log_set_target(LogTarget::Auto);
    log_parse_environment();
    log_open();
    if log_on_console() && with(|s| s.show_color) < 0 {
        log_show_color(true);
    }
}

/// `log_settle_target()`.
pub fn log_settle_target() {
    if log_get_target() != LogTarget::Auto {
        return;
    }
    let pi = with(|s| s.prohibit_ipc);
    let t = if getpid_cached() == 1 || stderr_is_journal() {
        if pi { LogTarget::Kmsg } else { LogTarget::JournalOrKmsg }
    } else {
        LogTarget::Console
    };
    log_set_target(t);
}

/// `vsnprintf(buffer, LINE_MAX, ...)`: cut at LINE_MAX - 1 bytes.
pub fn truncate_line(mut m: Vec<u8>) -> Vec<u8> {
    m.truncate(LINE_MAX - 1);
    m
}

/// Source location for `SYSTEMD_LOG_LOCATION` and the journal.
#[derive(Debug, Clone, Copy)]
pub struct Loc {
    pub file: &'static str,
    pub line: u32,
    pub func: &'static str,
}

fn write_to_console(s: &mut LogState, level: i32, loc: Loc, buffer: &[u8]) -> i32 {
    if s.console_fd < 0 {
        return 0;
    }
    if s.dumb < 0 {
        s.dumb = terminal::getenv_terminal_is_dumb() as i32;
    }
    if log_pri(level) > s.target_max_level[0] {
        return 0;
    }
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if s.target == LogTarget::ConsolePrefixed {
        parts.push(format!("<{level}>").into_bytes());
    }
    if s.show_time
        && let Some(t) = crate::time::format_timestamp(sys::now_realtime_usec())
    {
        parts.push(t);
        parts.push(b" ".to_vec());
    }
    if s.show_tid {
        parts.push(format!("({}) ", sys::gettid()).into_bytes());
    }
    let color = s.show_color > 0;
    let (on, off, _) = if color { get_log_colors(log_pri(level)) } else { (None, None, None) };
    if s.show_location {
        let (lon, loff) = if color { (ansi::highlight_yellow4(), ansi::normal()) } else { ("", "") };
        let mut l = format!("{lon}{}:{}{loff}: ", loc.file, loc.line).into_bytes();
        l.truncate(255);
        parts.push(l);
    }
    if let Some(on) = on {
        parts.push(on.as_bytes().to_vec());
    }
    if let Some(p) = &s.prefix {
        parts.push(p.clone());
        parts.push(b": ".to_vec());
    }
    parts.push(buffer.to_vec());
    if let Some(off) = off {
        parts.push(off.as_bytes().to_vec());
    }
    if s.console_fd_is_tty < 0 {
        s.console_fd_is_tty = terminal::isatty_safe(s.console_fd) as i32;
    }
    let tty = s.console_fd >= 0 && s.console_fd_is_tty > 0;
    parts.push(if tty && s.dumb == 0 { b"\r\n".to_vec() } else { b"\n".to_vec() });
    let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
    if let Err(e) = sys::writev(s.console_fd, &refs) {
        if e == -libc::EIO && getpid_cached() == 1 {
            log_close_console(s);
            log_open_console(s);
            if s.console_fd < 0 {
                return 0;
            }
            if let Err(e) = sys::writev(s.console_fd, &refs) {
                return e;
            }
        } else {
            return e;
        }
    }
    1
}

fn write_to_syslog(s: &mut LogState, level: i32, buffer: &[u8]) -> i32 {
    if s.syslog_fd < 0 {
        return 0;
    }
    if log_pri(level) > s.target_max_level[3] {
        return 0;
    }
    let Some(tm) = crate::time::localtime_or_gmtime_usec(sys::now_realtime_usec(), false) else {
        return -libc::EINVAL;
    };
    let Some(header_time) = sys::strftime(c"%h %e %T ", &tm, 64) else {
        return -libc::EINVAL;
    };
    let prio = format!("<{level}>").into_bytes();
    let pid = format!("[{}]: ", getpid_cached()).into_bytes();
    let prog = program_name();
    let prefix = s.prefix.clone().unwrap_or_default();
    let sep: &[u8] = if s.prefix.is_some() { b": " } else { b"" };
    let mut msg = buffer.to_vec();
    if s.syslog_is_stream {
        msg.push(0);
    }
    if !s.syslog_is_stream {
        let parts: Vec<&[u8]> = vec![&prio, &header_time, &prog, &pid, &prefix, sep, &msg];
        return match sys::sendmsg_iov(s.syslog_fd, &parts) {
            Ok(_) => 1,
            Err(e) => e,
        };
    }
    let all = bcat!(prio, header_time, prog, pid, prefix, sep, msg);
    let mut rest: &[u8] = &all;
    while !rest.is_empty() {
        match sys::sendmsg_iov(s.syslog_fd, &[rest]) {
            Ok(n) => rest = &rest[n..],
            Err(e) => return e,
        }
    }
    1
}

fn write_to_kmsg(s: &mut LogState, level: i32, buffer: &[u8]) -> i32 {
    if s.kmsg_fd < 0 {
        return 0;
    }
    if log_pri(level) > s.target_max_level[1] {
        return 0;
    }
    let mut buffer = buffer;
    if s.ratelimit_kmsg && !s.kmsg_ratelimit.below() {
        if s.kmsg_ratelimit.num_dropped() > 1 {
            return 0;
        }
        buffer = b"Too many messages being logged to kmsg, ignoring";
    }
    let prio = format!("<{level}>").into_bytes();
    let pid = format!("[{}]: ", getpid_cached()).into_bytes();
    let prog = program_name();
    let prefix = s.prefix.clone().unwrap_or_default();
    let sep: &[u8] = if s.prefix.is_some() { b": " } else { b"" };
    match sys::writev(s.kmsg_fd, &[&prio, &prog, &pid, &prefix, sep, buffer, b"\n"]) {
        Ok(_) => 1,
        Err(e) => e,
    }
}

/// `log_do_header()`.
fn log_do_header(level: i32, error: i32, loc: Option<Loc>, extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let error = if is_synthetic(error) { 0 } else { errno_value(error) };
    let mut h = format!("PRIORITY={}\nSYSLOG_FACILITY={}\nTID={}\n", log_pri(level), log_fac(level), sys::gettid())
        .into_bytes();
    if let Some(loc) = loc {
        if !loc.file.is_empty() {
            h.extend(format!("CODE_FILE={:.256}\n", loc.file).into_bytes());
        }
        if loc.line != 0 {
            h.extend(format!("CODE_LINE={}\n", loc.line).into_bytes());
        }
        if !loc.func.is_empty() {
            h.extend(format!("CODE_FUNC={:.256}\n", loc.func).into_bytes());
        }
    }
    if error != 0 {
        h.extend(format!("ERRNO={error}\n").into_bytes());
    }
    for (field, value) in extra {
        if !value.is_empty() {
            h.extend_from_slice(field);
            h.extend_from_slice(&value[..value.len().min(256)]);
            h.push(b'\n');
        }
    }
    let prog = program_name();
    h.extend_from_slice(b"SYSLOG_IDENTIFIER=");
    h.extend_from_slice(&prog[..prog.len().min(256)]);
    h.push(b'\n');
    h
}

fn write_to_journal(
    s: &mut LogState,
    level: i32,
    error: i32,
    loc: Loc,
    object: &[(&[u8], &[u8])],
    buffer: &[u8],
) -> i32 {
    if s.journal_fd < 0 {
        return 0;
    }
    if log_pri(level) > s.target_max_level[2] {
        return 0;
    }
    let header = log_do_header(level, error, Some(loc), object);
    let prefix = s.prefix.clone();
    let mut parts: Vec<&[u8]> = vec![&header, b"MESSAGE="];
    if let Some(p) = &prefix {
        parts.push(p);
        parts.push(b": ");
    }
    parts.push(buffer);
    parts.push(b"\n");
    match sys::sendmsg_iov(s.journal_fd, &parts) {
        Ok(_) => 1,
        Err(e) => e,
    }
}

/// `log_dispatch_internal()`: one message, split at newlines.
pub fn log_dispatch(level: i32, error: i32, loc: Loc, buffer: &[u8]) -> i32 {
    log_dispatch_object(level, error, loc, &[], buffer)
}

/// `log_dispatch_internal()` with an object field (`DEVICE=` and the like),
/// which only the journal sees.
pub fn log_dispatch_object(mut level: i32, error: i32, loc: Loc, object: &[(&[u8], &[u8])], buffer: &[u8]) -> i32 {
    use LogTarget::*;
    let ret = -errno_value(error);
    with(|s| {
        if s.target == Null {
            return;
        }
        if log_fac(level) == 0 {
            level |= s.facility;
        }
        if s.open_when_needed {
            log_open_impl(s);
        }
        let mut buf = buffer;
        loop {
            let skip = buf.iter().take_while(|b| NEWLINE.contains(b)).count();
            buf = &buf[skip..];
            if buf.is_empty() || buf[0] == 0 {
                break;
            }
            let (line, rest) = match buf.iter().position(|b| NEWLINE.contains(b)) {
                Some(i) => (&buf[..i], Some(&buf[i + 1..])),
                None => (buf, None),
            };
            let line = crate::bytes::c_str_prefix(line);
            let mut k = 0;
            if matches!(s.target, Auto | JournalOrKmsg | Journal) {
                k = write_to_journal(s, level, error, loc, object, line);
                if k < 0 && k != -libc::EAGAIN {
                    log_close_journal(s);
                }
            }
            if matches!(s.target, SyslogOrKmsg | Syslog) {
                k = write_to_syslog(s, level, line);
                if k < 0 && k != -libc::EAGAIN {
                    log_close_syslog(s);
                }
            }
            if k <= 0 && matches!(s.target, Auto | SyslogOrKmsg | JournalOrKmsg | Kmsg) {
                if k < 0 {
                    log_open_kmsg(s);
                }
                k = write_to_kmsg(s, level, line);
                if k < 0 {
                    log_close_kmsg(s);
                    log_open_console(s);
                }
            }
            if k <= 0 {
                write_to_console(s, level, loc, line);
            }
            match rest {
                Some(r) => buf = r,
                None => break,
            }
        }
        if s.open_when_needed {
            log_close_journal(s);
            log_close_syslog(s);
            log_close_kmsg(s);
            log_close_console(s);
        }
    });
    ret
}

/// `log_internal()`: level check, LINE_MAX cut, dispatch.  Returns `-ERRNO_VALUE(error)`.
pub fn log_internal(level: i32, error: i32, loc: Loc, msg: Vec<u8>) -> i32 {
    if log_pri(level) > log_get_max_level() {
        return -errno_value(error);
    }
    log_dispatch(level, error, loc, &truncate_line(msg))
}

/// `log_object_internal(level, error, ..., object_field, object, NULL, NULL, ...)`:
/// like [`log_internal`], with an object field for the journal.
pub fn log_object_internal(level: i32, error: i32, loc: Loc, object: Option<(&[u8], &[u8])>, msg: Vec<u8>) -> i32 {
    if log_pri(level) > log_get_max_level() {
        return -errno_value(error);
    }
    let o: Vec<(&[u8], &[u8])> = object.into_iter().collect();
    // LOG_SET_PREFIX(object): the object prefixes the message, on every target.
    let saved = log_set_prefix(object.map(|(_, v)| v.to_vec()));
    let r = log_dispatch_object(level, error, loc, &o, &truncate_line(msg));
    log_set_prefix(saved);
    r
}

/// `log_assert_failed(text, file, line, func)`: a failed `assert()`, logged
/// with C's source location, then abort().
pub fn log_assert_failed(text: &str, file: &'static str, line: u32, func: &'static str) -> ! {
    if log_pri(LOG_CRIT) <= log_get_max_level() {
        let msg = format!("Assertion '{text}' failed at {file}:{line}, function {func}(). Aborting.").into_bytes();
        log_dispatch(LOG_CRIT, 0, Loc { file, line, func }, &truncate_line(msg));
    }
    std::process::abort()
}

/// `log_assert_failed_return(text, file, line, func)`, which `assert_return()`
/// calls: a debug message naming the C source location (the caller passes
/// C's, so the message is the same).
pub fn log_assert_failed_return(text: &str, file: &'static str, line: u32, func: &'static str) {
    let e = sys::errno();
    if log_pri(LOG_DEBUG) <= log_get_max_level() {
        let msg = format!("Assertion '{text}' failed at {file}:{line}, function {func}(), ignoring.").into_bytes();
        log_dispatch(LOG_DEBUG, 0, Loc { file, line, func }, &truncate_line(msg));
    }
    sys::set_errno(e);
}

/// `log_struct_internal()` for the common case: extra journal fields plus a
/// `MESSAGE=`.  Without a journal, the message (cut to fit `LINE_MAX`
/// together with its "MESSAGE=" prefix) goes through `log_dispatch()`.
pub fn log_struct(mut level: i32, error: i32, loc: Loc, fields: &[Vec<u8>], message: &[u8]) -> i32 {
    use LogTarget::*;
    let ret = -errno_value(error);
    if log_pri(level) > log_get_max_level() || log_get_target() == Null {
        return ret;
    }
    let journal_sent = with(|s| {
        if log_fac(level) == 0 {
            level |= s.facility;
        }
        if !matches!(s.target, Auto | JournalOrKmsg | Journal) {
            return false;
        }
        if s.open_when_needed {
            log_open_journal(s);
        }
        if s.journal_fd < 0 {
            return false;
        }
        let header = log_do_header(level, error, Some(loc), &[]);
        let mut parts: Vec<Vec<u8>> = vec![header];
        for f in fields {
            parts.push(f.clone());
            parts.push(b"\n".to_vec());
        }
        parts.push(bcat!("MESSAGE=", message));
        parts.push(b"\n".to_vec());
        let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        let _ = sys::sendmsg_iov(s.journal_fd, &refs);
        if s.open_when_needed {
            log_close_journal(s);
            log_close_syslog(s);
            log_close_kmsg(s);
            log_close_console(s);
        }
        true
    });
    if journal_sent {
        return ret;
    }
    let full = truncate_line(bcat!("MESSAGE=", message));
    log_dispatch(level, error, loc, &full[8..])
}

/// `log_syntax_internal(unit=NULL, level, config_file, config_line, error, ...)`.
pub fn log_syntax(level: i32, config_file: Option<&[u8]>, config_line: u32, error: i32, loc: Loc, msg: Vec<u8>) -> i32 {
    if log_pri(level) > log_get_max_level() || log_get_target() == LogTarget::Null {
        return -errno_value(error);
    }
    let buffer = truncate_line(msg);
    const MID: &str = "MESSAGE_ID=c772d24e9a884cbeb9ea12625c306c01";
    match config_file {
        Some(f) if config_line > 0 => log_struct(
            level,
            error,
            loc,
            &[MID.as_bytes().to_vec(), bcat!("CONFIG_FILE=", f), format!("CONFIG_LINE={config_line}").into_bytes()],
            &bcat!(f, ":", config_line.to_string(), ": ", buffer),
        ),
        Some(f) => {
            log_struct(level, error, loc, &[MID.as_bytes().to_vec(), bcat!("CONFIG_FILE=", f)], &bcat!(f, ": ", buffer))
        }
        None => log_struct(level, error, loc, &[MID.as_bytes().to_vec()], &buffer),
    }
}

/// `log_emergency_level()`.
pub fn log_emergency_level() -> i32 {
    if getpid_cached() == 1 { LOG_EMERG } else { LOG_ERR }
}

/// Assemble and log a message: `log_full_errno!(level, error, pieces...)`.
/// The pieces are only evaluated if the level is enabled.
#[macro_export]
macro_rules! log_full_errno {
    ($level:expr, $err:expr, $($e:expr),* $(,)?) => {{
        let level: i32 = $level;
        let err: i32 = $err;
        if $crate::log::enabled(level) {
            $crate::log::log_internal(
                level,
                err,
                $crate::log::Loc { file: file!(), line: line!(), func: "" },
                $crate::bcat!($($e),*),
            )
        } else {
            -$crate::errno::errno_value(err)
        }
    }};
}

#[macro_export]
macro_rules! log_full {
    ($level:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($level, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_debug {
    ($($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_DEBUG, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_info {
    ($($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_INFO, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_notice {
    ($($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_NOTICE, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_warning {
    ($($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_WARNING, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_error {
    ($($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_ERR, 0, $($e),*) };
}
#[macro_export]
macro_rules! log_debug_errno {
    ($err:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_DEBUG, $err, $($e),*) };
}
#[macro_export]
macro_rules! log_info_errno {
    ($err:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_INFO, $err, $($e),*) };
}
#[macro_export]
macro_rules! log_notice_errno {
    ($err:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_NOTICE, $err, $($e),*) };
}
#[macro_export]
macro_rules! log_warning_errno {
    ($err:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_WARNING, $err, $($e),*) };
}
#[macro_export]
macro_rules! log_error_errno {
    ($err:expr, $($e:expr),* $(,)?) => { $crate::log_full_errno!($crate::log::LOG_ERR, $err, $($e),*) };
}

/// `log_syntax(unit=NULL, level, file, line, error, pieces...)`.
#[macro_export]
macro_rules! log_syntax {
    ($level:expr, $file:expr, $line:expr, $err:expr, $($e:expr),* $(,)?) => {{
        let level: i32 = $level;
        let err: i32 = $err;
        if $crate::log::enabled(level) {
            $crate::log::log_syntax(
                level,
                $file,
                $line,
                err,
                $crate::log::Loc { file: file!(), line: line!(), func: "" },
                $crate::bcat!($($e),*),
            )
        } else {
            -$crate::errno::errno_value(err)
        }
    }};
}
