// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-control.c`.

use shared::errno::{strerror, synthetic};
use shared::json::Json;
use shared::log_error_errno;
use shared::options::{Opt, OptionParser, common};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const EXIT: i32 = 0x102;
const LOG_LEVEL: i32 = 0x103;
const STOP: i32 = 0x104;
const START: i32 = 0x105;
const RELOAD: i32 = 0x106;
const PROPERTY: i32 = 0x107;
const CHILDREN_MAX: i32 = 0x108;
const PING: i32 = 0x109;
const TRACE: i32 = 0x10a;
const REVERT: i32 = 0x10b;
const TIMEOUT: i32 = 0x10c;
const LOAD_CREDENTIALS: i32 = 0x10d;
const INTROSPECT: i32 = 0x10e;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(EXIT, b'e', Some("exit"), None, Some("Instruct the daemon to cleanup and exit")),
    Opt::long(LOG_LEVEL, "log-priority", Some("LEVEL"), None),
    Opt::new(LOG_LEVEL, b'l', Some("log-level"), Some("LEVEL"), Some("Set the udev log level for the daemon")),
    Opt::new(STOP, b's', Some("stop-exec-queue"), None, Some("Do not execute events, queue only")),
    Opt::new(START, b'S', Some("start-exec-queue"), None, Some("Execute events, flush queue")),
    Opt::long(RELOAD, "reload-rules", None, None),
    Opt::new(RELOAD, b'R', Some("reload"), None, Some("Reload rules and databases")),
    Opt::long(PROPERTY, "env", Some("KEY=VALUE"), None),
    Opt::new(PROPERTY, b'p', Some("property"), Some("KEY=VALUE"), Some("Set a global property for all events")),
    Opt::new(CHILDREN_MAX, b'm', Some("children-max"), Some("N"), Some("Maximum number of children")),
    Opt::long(PING, "ping", None, Some("Wait for udev to respond to a ping message")),
    Opt::long(TRACE, "trace", Some("BOOL"), Some("Enable/disable trace logging")),
    Opt::long(REVERT, "revert", None, Some("Revert previously set configurations")),
    Opt::new(TIMEOUT, b't', Some("timeout"), Some("SECONDS"), Some("Maximum time to block for a reply")),
    Opt::long(LOAD_CREDENTIALS, "load-credentials", None, Some("Load udev rules from credentials")),
    common::introspect_cli(INTROSPECT),
];

#[derive(Default)]
struct Args {
    env: Vec<Vec<u8>>,
    timeout: u64,
    ping: bool,
    reload: bool,
    exit: bool,
    max_children: Option<u32>,
    log_level: Option<i32>,
    start_exec_queue: Option<bool>,
    trace: Option<bool>,
    revert: bool,
    load_credentials: bool,
}

impl Args {
    /// `arg_has_control_commands()`.
    fn has_control_commands(&self) -> bool {
        self.exit
            || self.log_level.is_some()
            || self.start_exec_queue.is_some()
            || self.reload
            || !self.env.is_empty()
            || self.max_children.is_some()
            || self.ping
            || self.trace.is_some()
            || self.revert
    }
}

/// `parse_argv()`: Ok(None) to exit successfully.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
    let mut a = Args { timeout: 60 * 1_000_000, ..Default::default() };
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        let c = match opts.next()? {
            None => break,
            Some(c) => c,
        };
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => return crate::print_verb_help("control").map_none(),
            VERSION => return shared::build::version_only().map_none(),
            EXIT => a.exit = true,
            LOG_LEVEL => match shared::log::log_level_from_string(&arg) {
                Ok(l) => a.log_level = Some(l),
                Err(r) => return Err(log_error_errno!(r, "Failed to parse log level '", &arg[..], "': ", strerror(r))),
            },
            STOP => a.start_exec_queue = Some(false),
            START => a.start_exec_queue = Some(true),
            RELOAD => a.reload = true,
            PROPERTY => {
                if !arg.contains(&b'=') {
                    return Err(log_error_errno!(
                        synthetic(libc::EINVAL),
                        "expect <KEY>=<value> instead of '",
                        &arg[..],
                        "'"
                    ));
                }
                a.env.push(arg);
            }
            CHILDREN_MAX => match shared::parse::safe_atou(&arg) {
                Err(r) => {
                    return Err(log_error_errno!(
                        r,
                        "Failed to parse maximum number of children '",
                        &arg[..],
                        "': ",
                        strerror(r)
                    ));
                }
                Ok(i) if i > i32::MAX as u32 => {
                    return Err(log_error_errno!(
                        synthetic(libc::ERANGE),
                        "Maximum number of children is too large: ",
                        &arg[..]
                    ));
                }
                Ok(i) => a.max_children = Some(i),
            },
            PING => a.ping = true,
            TRACE => a.trace = Some(shared::parse::parse_boolean_argument("--trace=", Some(&arg))?),
            REVERT => a.revert = true,
            TIMEOUT => match shared::time::parse_sec(&arg) {
                Ok(t) => a.timeout = t,
                Err(r) => {
                    return Err(log_error_errno!(r, "Failed to parse timeout value '", &arg[..], "': ", strerror(r)));
                }
            },
            LOAD_CREDENTIALS => a.load_credentials = true,
            INTROSPECT => return crate::introspect(shared::json::SD_JSON_FORMAT_OFF).map_none(),
            c => unreachable!("option id {c}"),
        }
    }
    if !a.has_control_commands() && !a.load_credentials {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "No control command option is specified."));
    }
    if !opts.args().is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "This subprogram takes no positional arguments."));
    }
    Ok(Some(a))
}

/// A help/version/introspect result as the parse outcome.
trait MapNone {
    fn map_none(self) -> Result<Option<Args>, i32>;
}

impl MapNone for i32 {
    fn map_none(self) -> Result<Option<Args>, i32> {
        if self < 0 { Err(self) } else { Ok(None) }
    }
}

/// `send_control_commands()`.
fn send_control_commands(a: &Args) -> Result<(), i32> {
    let mut link = match crate::udev::varlink::udev_varlink_connect(a.timeout) {
        Ok(l) => l,
        Err(r) => return Err(log_error_errno!(r, "Failed to connect to udev via varlink: ", strerror(r))),
    };
    let obj = |k: &str, v: Json| Some(Json::Object(vec![(k.as_bytes().to_vec(), v)]));
    if a.exit {
        return link.call_and_log("io.systemd.Udev.Exit", None).map(|_| ());
    }
    if a.revert {
        link.call_and_log("io.systemd.Udev.Revert", None)?;
    }
    if let Some(l) = a.log_level {
        link.call_and_log("io.systemd.service.SetLogLevel", obj("level", Json::Integer(l as i64)))?;
    }
    if let Some(s) = a.start_exec_queue {
        let m = if s { "io.systemd.Udev.StartExecQueue" } else { "io.systemd.Udev.StopExecQueue" };
        link.call_and_log(m, None)?;
    }
    if a.reload {
        link.call_and_log("io.systemd.service.Reload", None)?;
    }
    if !a.env.is_empty() {
        link.call_and_log("io.systemd.Udev.SetEnvironment", obj("assignments", Json::strv(&a.env)))?;
    }
    if let Some(n) = a.max_children {
        link.call_and_log("io.systemd.Udev.SetChildrenMax", obj("number", Json::Unsigned(n as u64)))?;
    }
    if a.ping {
        link.call_and_log("io.systemd.service.Ping", None)?;
    }
    if let Some(t) = a.trace {
        link.call_and_log("io.systemd.Udev.SetTrace", obj("enable", Json::Bool(t)))?;
    }
    Ok(())
}

/// `verb_control_main()`.
pub fn verb_control_main(argv: Vec<Vec<u8>>) -> i32 {
    if shared::virt::running_in_chroot() > 0 {
        shared::log_info!("Running in chroot, ignoring request.");
        return 0;
    }
    let a = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    if a.load_credentials {
        let r = shared::creds::pick_up_credentials(&[
            ("udev.conf.", "/run/udev/udev.conf.d/", ".conf"),
            ("udev.rules.", "/run/udev/rules.d/", ".rules"),
        ]);
        if r < 0 {
            return r;
        }
    }
    if a.has_control_commands()
        && let Err(r) = send_control_commands(&a)
    {
        return r;
    }
    0
}
