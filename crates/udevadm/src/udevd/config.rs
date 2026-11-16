// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-config.c`: udevd's settings from udev.conf, the command line,
//! the kernel command line and `udevadm control`.

use shared::conf_parser::{CONFIG_PARSE_WARN, config_parse_log_level, log_syntax_parse_error};
use shared::errno::strerror;
use shared::options::{Opt, OptionParser, common};
use shared::proc_cmdline::{key_streq, value_missing};
use shared::time::{format_timespan, parse_sec};
use shared::{log_debug, log_debug_errno, log_notice, log_warning, log_warning_errno};

use crate::udev::def::ResolveNameTiming;

/// `DEFAULT_WORKER_TIMEOUT_USEC`.
pub const DEFAULT_WORKER_TIMEOUT_USEC: u64 = 3 * 60 * 1_000_000;
/// `MIN_WORKER_TIMEOUT_USEC`.
const MIN_WORKER_TIMEOUT_USEC: u64 = 1000;
/// `WORKER_NUM_MAX`.
const WORKER_NUM_MAX: u64 = 2048;

/// `UdevConfig`; `UDEV_CONFIG_INIT` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdevConfig {
    pub log_level: i32,
    pub resolve_name_timing: Option<ResolveNameTiming>,
    pub children_max: u32,
    pub exec_delay_usec: u64,
    pub timeout_usec: u64,
    pub timeout_signal: i32,
    pub blockdev_read_only: bool,
    pub trace: bool,
}

impl Default for UdevConfig {
    fn default() -> UdevConfig {
        UdevConfig {
            log_level: -1,
            resolve_name_timing: None,
            children_max: 0,
            exec_delay_usec: 0,
            timeout_usec: 0,
            timeout_signal: 0,
            blockdev_read_only: false,
            trace: false,
        }
    }
}

/// The configuration layers and the merged result.
#[derive(Debug, Default)]
pub struct Configs {
    pub by_udev_conf: UdevConfig,
    pub by_command: UdevConfig,
    pub by_kernel: UdevConfig,
    pub by_control: UdevConfig,
    pub config: UdevConfig,
    /// `default_log_level`.
    pub default_log_level: i32,
}

/// `UdevReloadFlags`: a bit per builtin, then these.
pub const UDEV_RELOAD_KILL_WORKERS: u32 = 1 << 30;
pub const UDEV_RELOAD_RULES: u32 = 1 << 31;

/// `manager_parse_udev_config()`.
fn parse_udev_config(config: &mut UdevConfig) {
    let mut lookup = |file: &[u8], line: u32, section: Option<&[u8]>, lvalue: &[u8], rvalue: &[u8]| -> Option<i32> {
        if section.is_some() {
            return None;
        }
        let err = |r: i32| log_syntax_parse_error(file, line, r, lvalue, rvalue);
        Some(match lvalue {
            b"udev_log" => config_parse_log_level(file, line, lvalue, rvalue, &mut config.log_level),
            b"children_max" => match shared::parse::safe_atou(rvalue) {
                Ok(v) => {
                    config.children_max = v;
                    1
                }
                Err(r) => err(r),
            },
            b"exec_delay" => match parse_sec(rvalue) {
                Ok(v) => {
                    config.exec_delay_usec = v;
                    1
                }
                Err(r) => err(r),
            },
            b"event_timeout" => match parse_sec(rvalue) {
                Ok(v) => {
                    config.timeout_usec = v;
                    1
                }
                Err(r) => err(r),
            },
            b"resolve_names" => match ResolveNameTiming::from_string(rvalue) {
                Some(v) => {
                    config.resolve_name_timing = Some(v);
                    1
                }
                None => err(-libc::EINVAL),
            },
            b"timeout_signal" => {
                let r = shared::signal::signal_from_string(rvalue);
                if r <= 0 {
                    err(r)
                } else {
                    config.timeout_signal = r;
                    1
                }
            }
            _ => return None,
        })
    };
    let _ =
        shared::conf_parser::config_parse_standard_file_with_dropins("udev/udev.conf", CONFIG_PARSE_WARN, &mut lookup);
}

thread_local! {
    static KERNEL: std::cell::RefCell<UdevConfig> = std::cell::RefCell::new(UdevConfig::default());
}

/// `parse_proc_cmdline_item()`.
fn parse_proc_cmdline_item(key: &[u8], value: Option<&[u8]>) -> i32 {
    KERNEL.with(|k| {
        let mut config = k.borrow_mut();
        let r: Result<(), i32> = if key_streq(key, b"udev.log_level") || key_streq(key, b"udev.log_priority") {
            if value_missing(key, value) {
                return 0;
            }
            if let Ok(l) = shared::log::log_level_from_string(value.unwrap_or_default()) {
                config.log_level = l;
            }
            Ok(())
        } else if key_streq(key, b"udev.event_timeout") {
            if value_missing(key, value) {
                return 0;
            }
            parse_sec(value.unwrap_or_default()).map(|v| config.timeout_usec = v)
        } else if key_streq(key, b"udev.children_max") {
            if value_missing(key, value) {
                return 0;
            }
            shared::parse::safe_atou(value.unwrap_or_default()).map(|v| config.children_max = v)
        } else if key_streq(key, b"udev.exec_delay") {
            if value_missing(key, value) {
                return 0;
            }
            parse_sec(value.unwrap_or_default()).map(|v| config.exec_delay_usec = v)
        } else if key_streq(key, b"udev.timeout_signal") {
            if value_missing(key, value) {
                return 0;
            }
            let r = shared::signal::signal_from_string(value.unwrap_or_default());
            if r > 0 {
                config.timeout_signal = r;
            }
            if r < 0 { Err(r) } else { Ok(()) }
        } else if key_streq(key, b"udev.blockdev_read_only") {
            match value {
                None => config.blockdev_read_only = true,
                Some(v) => match shared::parse::parse_boolean(v) {
                    Err(r) => {
                        log_warning_errno!(r, "Failed to parse udev.blockdev-read-only argument, ignoring: ", v);
                    }
                    Ok(b) => config.blockdev_read_only = b,
                },
            }
            if config.blockdev_read_only {
                log_notice!("All physical block devices will be marked read-only.");
            }
            return 0;
        } else if key_streq(key, b"udev.trace") {
            match value {
                None => config.trace = true,
                Some(v) => match shared::parse::parse_boolean(v) {
                    Err(r) => {
                        log_warning_errno!(r, "Failed to parse udev.trace argument, ignoring: ", v);
                    }
                    Ok(b) => config.trace = b,
                },
            }
            return 0;
        } else {
            if key.starts_with(b"udev.") {
                log_warning!("Unknown udev kernel command line option \"", key, "\", ignoring.");
            }
            return 0;
        };
        if let Err(r) = r {
            log_warning_errno!(
                r,
                "Failed to parse \"",
                key,
                "=",
                value.unwrap_or(b"(null)"),
                "\", ignoring: ",
                strerror(r)
            );
        }
        0
    })
}

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const DAEMON: i32 = 0x102;
const DEBUG: i32 = 0x103;
const CHILDREN_MAX: i32 = 0x104;
const EXEC_DELAY: i32 = 0x105;
const EVENT_TIMEOUT: i32 = 0x106;
const RESOLVE_NAMES: i32 = 0x107;
const TIMEOUT_SIGNAL: i32 = 0x108;
const INTROSPECT: i32 = 0x109;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(DAEMON, b'd', Some("daemon"), None, Some("Detach and run in the background")),
    Opt::new(DEBUG, b'D', Some("debug"), None, Some("Enable debug output")),
    Opt::new(CHILDREN_MAX, b'c', Some("children-max"), Some("INT"), Some("Set maximum number of workers")),
    Opt::new(EXEC_DELAY, b'e', Some("exec-delay"), Some("SECONDS"), Some("Seconds to wait before executing RUN=")),
    Opt::new(
        EVENT_TIMEOUT,
        b't',
        Some("event-timeout"),
        Some("SECONDS"),
        Some("Seconds to wait before terminating an event"),
    ),
    crate::verify::resolve_names(RESOLVE_NAMES),
    Opt::long(TIMEOUT_SIGNAL, "timeout-signal", Some("SIGNAL"), Some("Signal used when terminating an event")),
    common::introspect_cli(INTROSPECT),
];

/// What `parse_argv()` found besides the settings.
#[derive(Debug, Default)]
pub struct Args {
    pub daemonize: bool,
    pub debug: bool,
}

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>, config: &mut UdevConfig) -> Result<Option<Args>, i32> {
    let mut a = Args::default();
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_udevd_help();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            DAEMON => a.daemonize = true,
            DEBUG => {
                a.debug = true;
                config.log_level = shared::log::LOG_DEBUG;
            }
            CHILDREN_MAX => match shared::parse::safe_atou(&arg) {
                Ok(v) => config.children_max = v,
                Err(r) => {
                    log_warning_errno!(
                        r,
                        "Failed to parse --children-max= value '",
                        &arg[..],
                        "', ignoring: ",
                        strerror(r)
                    );
                }
            },
            EXEC_DELAY => match parse_sec(&arg) {
                Ok(v) => config.exec_delay_usec = v,
                Err(r) => {
                    log_warning_errno!(
                        r,
                        "Failed to parse --exec-delay= value '",
                        &arg[..],
                        "', ignoring: ",
                        strerror(r)
                    );
                }
            },
            EVENT_TIMEOUT => match parse_sec(&arg) {
                Ok(v) => config.timeout_usec = v,
                Err(r) => {
                    log_warning_errno!(
                        r,
                        "Failed to parse --event-timeout= value '",
                        &arg[..],
                        "', ignoring: ",
                        strerror(r)
                    );
                }
            },
            RESOLVE_NAMES => match ResolveNameTiming::from_string(&arg) {
                None => {
                    log_warning!("Invalid --resolve-names= value '", &arg[..], "', ignoring.");
                }
                Some(t) => config.resolve_name_timing = Some(t),
            },
            TIMEOUT_SIGNAL => {
                let r = shared::signal::signal_from_string(&arg);
                if r <= 0 {
                    log_warning_errno!(
                        r,
                        "Failed to parse --timeout-signal= value '",
                        &arg[..],
                        "', ignoring: ",
                        strerror(r)
                    );
                } else {
                    config.timeout_signal = r;
                }
            }
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    Ok(Some(a))
}

impl Configs {
    /// `manager_merge_config_log_level()`.
    fn merge_log_level(&mut self) {
        let c = &mut self.config;
        c.trace = self.by_control.trace || self.by_kernel.trace || self.by_command.trace || self.by_udev_conf.trace;
        if c.trace {
            c.log_level = shared::log::LOG_DEBUG;
        } else {
            c.log_level = [self.by_control, self.by_kernel, self.by_command, self.by_udev_conf]
                .iter()
                .map(|x| x.log_level)
                .find(|&l| l >= 0)
                .unwrap_or(self.default_log_level);
        }
    }

    /// `manager_merge_config()`.
    pub fn merge(&mut self) {
        self.merge_log_level();
        let layers = [self.by_control, self.by_kernel, self.by_command, self.by_udev_conf];
        let c = &mut self.config;
        c.resolve_name_timing =
            Some(layers.iter().find_map(|x| x.resolve_name_timing).unwrap_or(ResolveNameTiming::Early));
        c.children_max = layers.iter().map(|x| x.children_max).find(|&v| v != 0).unwrap_or(0);
        c.exec_delay_usec = layers.iter().map(|x| x.exec_delay_usec).find(|&v| v != 0).unwrap_or(0);
        c.timeout_usec = layers.iter().map(|x| x.timeout_usec).find(|&v| v != 0).unwrap_or(DEFAULT_WORKER_TIMEOUT_USEC);
        c.timeout_signal = layers.iter().map(|x| x.timeout_signal).find(|&v| v != 0).unwrap_or(libc::SIGKILL);
        c.blockdev_read_only = layers.iter().any(|x| x.blockdev_read_only);
    }

    /// `manager_load()`: Ok(None) to exit with 0.
    pub fn load(&mut self, argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
        self.default_log_level = shared::log::log_get_max_level();
        parse_udev_config(&mut self.by_udev_conf);
        let Some(args) = parse_argv(argv, &mut self.by_command)? else { return Ok(None) };
        KERNEL.with(|k| *k.borrow_mut() = UdevConfig::default());
        if let Err(r) = shared::proc_cmdline::proc_cmdline_parse(parse_proc_cmdline_item, true) {
            log_warning_errno!(r, "Failed to parse kernel command line, ignoring: ", strerror(r));
        }
        self.by_kernel = KERNEL.with(|k| *k.borrow());
        self.merge();
        if args.debug {
            shared::log::log_set_target(shared::log::LogTarget::Console);
        }
        adjust_config(&mut self.config);
        Ok(Some(args))
    }

    /// `manager_needs_reload()`.
    fn needs_reload(&self, old: &UdevConfig) -> u32 {
        let c = &self.config;
        if c.resolve_name_timing != old.resolve_name_timing {
            return UDEV_RELOAD_RULES | UDEV_RELOAD_KILL_WORKERS;
        }
        if c.log_level != old.log_level
            || c.exec_delay_usec != old.exec_delay_usec
            || c.timeout_usec != old.timeout_usec
            || c.timeout_signal != old.timeout_signal
            || c.blockdev_read_only != old.blockdev_read_only
            || c.trace != old.trace
        {
            return UDEV_RELOAD_KILL_WORKERS;
        }
        0
    }

    /// `manager_reload_config()`.
    pub fn reload(&mut self) -> u32 {
        let old = self.config;
        self.by_udev_conf = UdevConfig::default();
        parse_udev_config(&mut self.by_udev_conf);
        self.merge();
        adjust_config(&mut self.config);
        self.needs_reload(&old)
    }

    /// The config half of `manager_revert_config()`.
    pub fn revert(&mut self) -> u32 {
        let old = self.config;
        self.by_control = UdevConfig::default();
        self.merge();
        adjust_config(&mut self.config);
        self.needs_reload(&old)
    }

    /// `manager_set_children_max()` without `notify_ready()`.
    pub fn set_children_max(&mut self, n: u32) {
        self.by_control.children_max = n;
        set_default_children_max(&mut self.by_control);
        self.config.children_max = self.by_control.children_max;
    }

    /// `manager_set_log_level()`: true if the workers need to be killed.
    pub fn set_log_level(&mut self, level: i32) -> bool {
        let old = shared::log::log_get_max_level();
        self.by_control.log_level = level;
        self.merge_log_level();
        if self.config.log_level == old {
            return false;
        }
        shared::log::log_set_max_level(self.config.log_level);
        true
    }

    /// `manager_set_trace()`: true if the workers need to be killed.
    pub fn set_trace(&mut self, enable: bool) -> bool {
        let old = self.config.trace;
        self.by_control.trace = enable;
        self.merge_log_level();
        if self.config.trace == old {
            return false;
        }
        shared::log::log_set_max_level(self.config.log_level);
        true
    }
}

/// `udev_config_set_default_children_max()`.
fn set_default_children_max(config: &mut UdevConfig) {
    if config.children_max != 0 {
        return;
    }
    let cpu_count = match shared::sys::cpus_in_affinity_mask() {
        Ok(n) => n as u64,
        Err(r) => {
            log_warning_errno!(r, "Failed to determine number of local CPUs, ignoring: ", strerror(r));
            1
        }
    };
    let cpu_limit = cpu_count * 2 + 16;
    let mem_limit = (shared::cgroup::physical_memory() / (128 * 1024 * 1024)).max(10);
    config.children_max = cpu_limit.min(mem_limit).min(WORKER_NUM_MAX) as u32;
    log_debug!("Set children_max to ", config.children_max.to_string());
}

/// `manager_adjust_config()`.
pub fn adjust_config(config: &mut UdevConfig) {
    shared::log::log_set_max_level(config.log_level);
    if config.timeout_usec < MIN_WORKER_TIMEOUT_USEC {
        log_debug!(
            "Timeout (",
            format_timespan(config.timeout_usec, 1),
            ") for processing event is too small, using the default: ",
            format_timespan(DEFAULT_WORKER_TIMEOUT_USEC, 1)
        );
        config.timeout_usec = DEFAULT_WORKER_TIMEOUT_USEC;
    }
    if config.exec_delay_usec >= config.timeout_usec {
        log_debug!(
            "Delay (",
            format_timespan(config.exec_delay_usec, 1),
            ") for executing RUN= commands is too large compared with the timeout (",
            format_timespan(config.timeout_usec, 1),
            ") for event execution, ignoring the delay."
        );
        config.exec_delay_usec = 0;
    }
    set_default_children_max(config);
}

/// `extra_timeout_usec()`.
pub fn extra_timeout_usec() -> u64 {
    thread_local! {
        static SAVED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }
    if let Some(v) = SAVED.with(|s| s.get()) {
        return v;
    }
    let mut saved = 10 * 1_000_000;
    if let Some(e) = shared::sys::secure_getenv("SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC") {
        let timeout = match parse_sec(&e) {
            Ok(t) => t,
            Err(r) => {
                log_debug_errno!(
                    r,
                    "Failed to parse $SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=",
                    &e[..],
                    ", ignoring: ",
                    strerror(r)
                );
                // C goes on with the uninitialized value; take the default.
                saved
            }
        };
        if timeout > 5 * 3600 * 1_000_000 {
            log_debug!("Parsed $SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=", &e[..], " is too large, ignoring.");
        } else {
            saved = timeout;
        }
    }
    SAVED.with(|s| s.set(Some(saved)));
    saved
}
