// SPDX-License-Identifier: GPL-2.0-or-later
//! systemd-udevd: `udevd.c`, `udev-manager.c` and friends.
//!
//! The manager runs on `shared::event::Event<Manager>`; the handlers get
//! the `Manager` and the loop.  Workers are forked children that run their
//! own loop (`worker.rs`).
//!
//! Known differences:
//! - Events that have been processed are dropped from the queue at once;
//!   C keeps them (in state PROCESSED) while later events still reference
//!   them as blockers.  The blocker search starts from the same place.
//! - The workers are kept in the order they were spawned; C iterates a
//!   hashmap of them, so which idle worker gets the next event differs.
//! - There is no service manager file descriptor store: the inotify fd,
//!   the configuration and the queued events are not pushed to one on
//!   exit (only with $NOTIFY_SOCKET set does C try).  Passed fds
//!   (`$LISTEN_FDS`) are taken as C does.

pub mod config;
mod control;
mod manager;
mod watch;
mod worker;

use shared::device_monitor::Monitor;
use shared::errno::strerror;
use shared::event::{Enabled, Event, Fired, Id, SD_EVENT_PRIORITY_NORMAL};
use shared::sd_device::{Action, Dev};
use shared::sys::{self, OwnedFd};
use shared::{log_debug, log_debug_errno, log_error_errno, log_full_errno, log_info, log_warning_errno};

use crate::udev::rules::Rules;
use config::Configs;

/// `EVENT_PRIORITY_*`.
pub const EVENT_PRIORITY_SIGTERM: i64 = SD_EVENT_PRIORITY_NORMAL - 6;
pub const EVENT_PRIORITY_DEVICE_MONITOR: i64 = SD_EVENT_PRIORITY_NORMAL - 5;
pub const EVENT_PRIORITY_INOTIFY_WATCH: i64 = SD_EVENT_PRIORITY_NORMAL - 4;
pub const EVENT_PRIORITY_WORKER_NOTIFY: i64 = SD_EVENT_PRIORITY_NORMAL - 3;
pub const EVENT_PRIORITY_WORKER_EXIT: i64 = SD_EVENT_PRIORITY_NORMAL - 2;
pub const EVENT_PRIORITY_WORKER_TIMER: i64 = SD_EVENT_PRIORITY_NORMAL - 1;
pub const EVENT_PRIORITY_SIGHUP: i64 = SD_EVENT_PRIORITY_NORMAL + 1;
pub const EVENT_PRIORITY_VARLINK: i64 = SD_EVENT_PRIORITY_NORMAL + 2;
pub const EVENT_PRIORITY_REQUEUE_EVENT: i64 = SD_EVENT_PRIORITY_NORMAL + 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Queued,
    Running,
    Locked,
}

/// `Event` of the manager's queue.
#[derive(Debug)]
pub struct QEvent {
    pub dev: Dev,
    pub seqnum: u64,
    pub action: Action,
    pub id: Option<Vec<u8>>,
    pub devpath: Vec<u8>,
    pub devpath_old: Option<Vec<u8>>,
    pub devnode: Option<Vec<u8>>,
    pub state: EventState,
    /// The pid of the worker processing it.
    pub worker: Option<i32>,
    pub requeue_next_usec: u64,
    pub requeue_timeout_usec: u64,
    pub whole_disk: Option<Vec<u8>>,
    /// The seqnum of the last blocker found.
    pub blocker: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Undef,
    Running,
    Idle,
    Killed,
}

/// `Worker`.
#[derive(Debug)]
pub struct Worker {
    pub pid: i32,
    pub address: (u32, u32),
    pub state: WorkerState,
    /// The seqnum of the event it processes.
    pub event: Option<u64>,
    pub child_source: Option<Id>,
    pub warn_source: Option<Id>,
    pub kill_source: Option<Id>,
}

/// `Manager`.
pub struct Manager {
    pub configs: Configs,
    pub workers: Vec<Worker>,
    /// The queue, ordered by seqnum.
    pub events: Vec<QEvent>,
    pub workers_cgroup: Option<Vec<u8>>,
    pub rules: Option<Rules>,
    /// Global properties set by `udevadm control -p`.
    pub properties: Vec<(Vec<u8>, Vec<u8>)>,
    pub monitor: Option<Monitor>,
    pub monitor_source: Option<Id>,
    pub varlink: Option<shared::varlink::Server<Manager>>,
    pub worker_notify_socket_path: Vec<u8>,
    pub worker_notify_fd: Option<OwnedFd>,
    pub inotify_fd: i32,
    pub inotify_source: Option<Id>,
    pub synthesize_change_children: Vec<Id>,
    pub synthesized_events: Vec<shared::id128::Id128>,
    pub synthesized_events_clear_source: Option<Id>,
    pub kill_workers_source: Option<Id>,
    /// `locked_events_by_disk`: the whole disk, and the seqnums of the
    /// events locked on it, newest first.
    pub locked_events_by_disk: Vec<(Vec<u8>, Vec<u64>)>,
    pub requeue_locked_events_source: Option<Id>,
    pub last_usec: u64,
    pub queue_file_created: bool,
    pub stop_exec_queue: bool,
    pub exit: bool,
    pub children_max_reached_logged: bool,
}

impl Manager {
    /// `manager_new()`.
    fn new() -> Manager {
        Manager {
            configs: Configs::default(),
            workers: Vec::new(),
            events: Vec::new(),
            workers_cgroup: None,
            rules: None,
            properties: Vec::new(),
            monitor: None,
            monitor_source: None,
            varlink: None,
            worker_notify_socket_path: Vec::new(),
            worker_notify_fd: None,
            inotify_fd: -1,
            inotify_source: None,
            synthesize_change_children: Vec::new(),
            synthesized_events: Vec::new(),
            synthesized_events_clear_source: None,
            kill_workers_source: None,
            locked_events_by_disk: Vec::new(),
            requeue_locked_events_source: None,
            last_usec: 0,
            queue_file_created: false,
            stop_exec_queue: false,
            exit: false,
            children_max_reached_logged: false,
        }
    }
}

pub type Handler = shared::event::Handler<Manager>;
pub type Ev = Event<Manager>;

/// `event_reset_time(e, &s, clock, usec, accuracy, callback, userdata,
/// priority, description, force_reset)`.
pub fn event_reset_time(
    ev: &mut Ev,
    slot: &mut Option<Id>,
    usec: u64,
    handler: impl FnOnce() -> Handler,
    priority: i64,
    description: &[u8],
    force_reset: bool,
) -> Result<(), i32> {
    if let Some(id) = *slot
        && ev.exists(id)
    {
        if !force_reset && ev.get_enabled(id) != Some(Enabled::Off) {
            return Ok(());
        }
        ev.set_time(id, usec)?;
        ev.set_enabled(id, Enabled::Oneshot)?;
        return Ok(());
    }
    let id = ev.add_time(libc::CLOCK_MONOTONIC, usec, handler())?;
    ev.set_priority(id, priority)?;
    ev.set_description(id, description);
    *slot = Some(id);
    Ok(())
}

/// `event_reset_time_relative()`.
pub fn event_reset_time_relative(
    ev: &mut Ev,
    slot: &mut Option<Id>,
    usec: u64,
    handler: impl FnOnce() -> Handler,
    priority: i64,
    description: &[u8],
    force_reset: bool,
) -> Result<(), i32> {
    let now = ev.now(libc::CLOCK_MONOTONIC);
    event_reset_time(ev, slot, now.saturating_add(usec), handler, priority, description, force_reset)
}

/// `event_source_disable()`.
pub fn event_source_disable(ev: &mut Ev, slot: Option<Id>) {
    if let Some(id) = slot {
        let _ = ev.set_enabled(id, Enabled::Off);
    }
}

/// `dlopen_*(LOG_DEBUG)` of the libraries C loads before forking workers.
/// libmount isn't used by anything ported, so it's only probed, for the
/// same log line.
fn dlopen_libraries() {
    let _ = shared::sys_acl::dlopen_libacl(shared::log::LOG_DEBUG);
    let _ = shared::sys_blkid::dlopen_libblkid(shared::log::LOG_DEBUG);
    let _ = shared::sys_kmod::dlopen_libkmod(shared::log::LOG_DEBUG);
    for lib in ["libmount.so.1"] {
        match shared::sys_acl::dlopen_probe(lib.as_bytes()) {
            Ok(()) => {
                log_debug!("Loaded shared library '", lib, "' via dlopen().");
            }
            Err((r, dle)) => {
                log_debug!("Shared library '", lib, "' is not available: ", dle.unwrap_or_else(|| strerror(r)));
            }
        }
    }
    log_debug_errno!(shared::errno::synthetic(libc::EOPNOTSUPP), "TPM2 support is not compiled in.");
}

/// `rlimit_nofile_bump(-1)`.
fn rlimit_nofile_bump() {
    let nr_open = shared::fileio::read_one_line_file(b"/proc/sys/fs/nr_open")
        .ok()
        .and_then(|v| shared::parse::safe_atou64(&v).ok())
        .unwrap_or(1024 * 1024);
    let Ok((soft, hard)) = sys::getrlimit_nofile() else { return };
    // setrlimit_closest(): as close as the hard limit allows.
    let want = nr_open.max(3).min(hard);
    if want == soft {
        return;
    }
    if let Err(r) = sys::setrlimit_nofile(want, hard) {
        log_debug_errno!(r, "Failed to set RLIMIT_NOFILE: ", strerror(r));
    }
}

/// `run_udevd()`.
pub fn run_udevd(argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_setup();
    let mut manager = Manager::new();
    let args = match manager.configs.load(argv) {
        Err(r) => return r,
        Ok(None) => return 0,
        Ok(Some(a)) => a,
    };
    if sys::geteuid() != 0 {
        return log_error_errno!(shared::errno::synthetic(libc::EPERM), "Need to be root.");
    }
    sys::umask(0o022);
    rlimit_nofile_bump();
    match sys::mkdirat(libc::AT_FDCWD, b"/run/udev", 0o755) {
        Err(r) if r != -libc::EEXIST => return log_error_errno!(r, "Failed to create /run/udev: ", strerror(r)),
        _ => {}
    }
    dlopen_libraries();
    if args.daemonize {
        log_info!("Starting systemd-udevd version ", shared::build::GIT_VERSION);
        if shared::log::log_get_max_level() < shared::log::LOG_DEBUG
            && let Err(r) = sys::rearrange_stdio([-1, -1, -1])
        {
            log_warning_errno!(r, "Failed to redirect standard streams to /dev/null: ", strerror(r));
        }
        match sys::fork() {
            Err(r) => return log_error_errno!(r, "Failed to fork daemon: ", strerror(r)),
            Ok(pid) if pid > 0 => return 0,
            Ok(_) => sys::setsid_detach(),
        }
    }
    manager_main(manager)
}

/// `manager_setup_event()`.
fn setup_event(ev: &mut Ev) -> Result<(), i32> {
    let signals: [(i32, i64, &[u8], fn(&mut Manager, &mut Ev)); 3] = [
        (libc::SIGINT, EVENT_PRIORITY_SIGTERM, b"sigint-event-source", |m, ev| m.exit(ev)),
        (libc::SIGTERM, EVENT_PRIORITY_SIGTERM, b"sigterm-event-source", |m, ev| m.exit(ev)),
        (libc::SIGHUP, EVENT_PRIORITY_SIGHUP, b"sighup-event-source", |m, ev| m.reload(ev, true)),
    ];
    for (sig, prio, desc, f) in signals {
        let name = shared::signal::signal_to_string(sig);
        let id = ev
            .add_signal(
                sig,
                Some(Box::new(move |m: &mut Manager, ev: &mut Ev, _id, _f| {
                    f(m, ev);
                    1
                })),
            )
            .and_then(|id| ev.set_priority(id, prio).map(|_| id))
            .map_err(|r| log_error_errno!(r, "Failed to create SIG", name, " event source: ", strerror(r)))?;
        ev.set_description(id, desc);
    }
    ev.add_post(Box::new(|m: &mut Manager, ev: &mut Ev, _id, _f| m.on_post(ev)))
        .map_err(|r| log_error_errno!(r, "Failed to create post event source: ", strerror(r)))?;
    if let Err(r) = add_memory_pressure(ev) {
        let quiet =
            shared::errno::is_neg_not_supported(r) || shared::errno::is_neg_privilege(r) || r == -libc::EHOSTDOWN;
        log_full_errno!(
            if quiet { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
            r,
            "Failed to allocate memory pressure watch, ignoring: ",
            strerror(r)
        );
    }
    ev.add_signal(
        libc::SIGRTMIN() + 18,
        Some(Box::new(|_m: &mut Manager, _ev: &mut Ev, _id, f| {
            if let Fired::Signal(si) = f {
                shared::common_signal::sigrtmin18_handler(&si);
            }
            0
        })),
    )
    .map_err(|r| log_error_errno!(r, "Failed to allocate SIGRTMIN+18 event source, ignoring: ", strerror(r)))?;
    Ok(())
}

/// `sd_event_add_memory_pressure(e, NULL, NULL, NULL)`.
fn add_memory_pressure(ev: &mut Ev) -> Result<(), i32> {
    let (watch, fallback, write): (Vec<u8>, Option<Vec<u8>>, Vec<u8>) =
        if let Some(env) = sys::secure_getenv("MEMORY_PRESSURE_WATCH") {
            if env.is_empty() || env == b"/dev/null" {
                return Err(log_debug_errno!(
                    shared::errno::synthetic(libc::EHOSTDOWN),
                    "Pressure logic is explicitly disabled via $MEMORY_PRESSURE_WATCH."
                ));
            }
            if !shared::path::path_is_absolute(&env) || !shared::path::path_is_normalized(&env) {
                return Err(log_debug_errno!(
                    shared::errno::synthetic(libc::EBADMSG),
                    "$MEMORY_PRESSURE_WATCH set to invalid path: ",
                    &env[..]
                ));
            }
            let write = match sys::secure_getenv("MEMORY_PRESSURE_WRITE") {
                Some(w) => shared::hexdecoct::unbase64mem(&w)?,
                None => Vec::new(),
            };
            (env, None, write)
        } else {
            for p in ["/proc/pressure/cpu", "/proc/pressure/io", "/proc/pressure/memory"] {
                match shared::fileio::read_full_file(p.as_bytes()) {
                    Err(r) if r == -libc::ENOENT || shared::errno::is_neg_not_supported(r) => {
                        return Err(-libc::EOPNOTSUPP);
                    }
                    Err(r) => return Err(r),
                    Ok(_) => {}
                }
            }
            let cg = shared::cgroup::cg_pid_get_path(0)?;
            let w = shared::path::path_join(&[b"/sys/fs/cgroup", &cg, b"memory.pressure"]);
            let mut buf = b"some 200000 2000000".to_vec();
            buf.push(0);
            (w, Some(b"/proc/pressure/memory".to_vec()), buf)
        };
    let path_fd = match sys::open(&watch, libc::O_PATH | libc::O_CLOEXEC, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) if r != -libc::ENOENT => return Err(r),
        Err(r) => {
            let Some(f) = fallback else { return Err(r) };
            match sys::open(&f, libc::O_PATH | libc::O_CLOEXEC, 0) {
                Ok(fd) => OwnedFd::new(fd),
                Err(r) if r == -libc::ENOENT => return Err(-libc::EOPNOTSUPP),
                Err(r) => return Err(r),
            }
        }
    };
    let st = sys::fstat(path_fd.raw())?;
    let fmt = st.st_mode & libc::S_IFMT;
    let (fd, events) = match fmt {
        libc::S_IFREG | libc::S_IFIFO | libc::S_IFCHR => {
            let flags = if write.is_empty() { libc::O_RDONLY } else { libc::O_RDWR };
            let fd = OwnedFd::new(shared::fd::fd_reopen(
                path_fd.raw(),
                flags | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
            )?);
            if fmt == libc::S_IFREG {
                let t = sys::fstatfs_type(fd.raw())?;
                // PROC_SUPER_MAGIC, CGROUP2_SUPER_MAGIC
                if t != 0x9fa0 && t != 0x63677270 {
                    return Err(-libc::ENOTTY);
                }
                (fd, libc::EPOLLPRI as u32)
            } else {
                (fd, libc::EPOLLIN as u32)
            }
        }
        libc::S_IFDIR => return Err(-libc::EISDIR),
        libc::S_IFSOCK => {
            // AF_UNIX pressure sockets are not supported here.
            return Err(-libc::EOPNOTSUPP);
        }
        _ => return Err(-libc::EBADF),
    };
    if !write.is_empty() {
        sys::write_all(fd.raw(), &write)?;
    }
    let raw = fd.into_raw();
    ev.add_io(
        raw,
        events,
        Box::new(move |_m: &mut Manager, _ev: &mut Ev, _id, _f| {
            if events == libc::EPOLLIN as u32 {
                // Drain what the socket or fifo sent.
                let mut buf = [0u8; 256];
                let _ = sys::read(raw, &mut buf);
            }
            shared::common_signal::trim_memory();
            0
        }),
    )?;
    Ok(())
}

/// `sd_listen_fds_with_names(true, &names)`: (fd, name) pairs.
fn listen_fds_with_names() -> Result<Vec<(i32, Vec<u8>)>, i32> {
    let pid = sys::getenv("LISTEN_PID");
    let n = sys::getenv("LISTEN_FDS");
    let names = sys::getenv("LISTEN_FDNAMES");
    for v in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        let _ = sys::unsetenv(v.as_bytes());
    }
    let (Some(pid), Some(n)) = (pid, n) else { return Ok(Vec::new()) };
    let pid = shared::parse::safe_atoi(&pid)?;
    if pid != sys::getpid() {
        return Ok(Vec::new());
    }
    let n = shared::parse::safe_atou(&n)?;
    let names: Vec<Vec<u8>> = names.map(|s| s.split(|&c| c == b':').map(<[u8]>::to_vec).collect()).unwrap_or_default();
    Ok((0..n as i32).map(|i| (3 + i, names.get(i as usize).cloned().unwrap_or_else(|| b"unknown".to_vec()))).collect())
}

/// `manager_listen_fds()`: the varlink fd, if passed.
fn listen_fds(m: &mut Manager) -> Result<Option<i32>, i32> {
    let fds = listen_fds_with_names().map_err(|r| log_error_errno!(r, "Failed to listen on fds: ", strerror(r)))?;
    let mut varlink_fd = None;
    for (fd, name) in fds {
        let r = match &name[..] {
            b"varlink" => {
                varlink_fd = Some(fd);
                Ok(())
            }
            b"systemd-udevd-kernel.socket" => manager::init_device_monitor(m, Some(fd)),
            b"inotify" => watch::init_inotify(m, Some(fd)),
            b"config-serialization" => m.deserialize_config(fd),
            b"event-serialization" => m.deserialize_events(fd),
            _ => Err(log_debug_errno!(
                shared::errno::synthetic(libc::EINVAL),
                "Received unexpected fd (",
                &name[..],
                "), ignoring."
            )),
        };
        if r.is_err() {
            // close_and_notify_warn()
            sys::close(fd);
            let r = shared::notify::sd_notify(&shared::bcat!("FDSTOREREMOVE=1\nFDNAME=", &name[..]));
            if r < 0 {
                log_full_errno!(
                    if shared::varlink::is_disconnect(r) { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                    r,
                    "Failed to remove file descriptor \"",
                    &name[..],
                    "\" from the store, ignoring: ",
                    strerror(r)
                );
            }
        }
    }
    Ok(varlink_fd)
}

/// `notify_remove_fd_warn(name)`.
pub fn notify_remove_fd_warn(name: &[u8]) {
    let r = shared::notify::sd_notify(&shared::bcat!("FDSTOREREMOVE=1\nFDNAME=", name));
    if r < 0 {
        log_full_errno!(
            if shared::varlink::is_disconnect(r) { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
            r,
            "Failed to remove file descriptor \"",
            name,
            "\" from the store, ignoring: ",
            strerror(r)
        );
    }
}

/// `manager_main()`.
fn manager_main(mut m: Manager) -> i32 {
    match shared::cgroup::cg_pid_get_path(0) {
        Err(r) => {
            log_debug_errno!(r, "Failed to get cgroup, ignoring: ", strerror(r));
        }
        Ok(cgroup) if cgroup.ends_with(b"/udev") => {
            log_debug!("Running in delegated subcgroup '", &cgroup[..], "'.");
            let parent = match shared::path::path_extract_directory(&cgroup) {
                Ok(p) => p,
                Err(r) => {
                    return log_warning_errno!(
                        r,
                        "Failed to extract parent of cgroup '",
                        &cgroup[..],
                        "': ",
                        strerror(r)
                    );
                }
            };
            let workers = shared::path::path_join(&[&parent, b"workers"]);
            let fs = shared::path::path_join(&[b"/sys/fs/cgroup", &workers]);
            let r = shared::fs::mkdirat_parents(libc::AT_FDCWD, &fs, 0o755).and_then(|_| {
                match sys::mkdirat(libc::AT_FDCWD, &fs, 0o755) {
                    Err(r) if r == -libc::EEXIST => Ok(()),
                    x => x,
                }
            });
            match r {
                Err(r) => {
                    log_warning_errno!(
                        r,
                        "Failed to create workers cgroup '",
                        &workers[..],
                        "', ignoring: ",
                        strerror(r)
                    );
                }
                Ok(()) => {
                    log_debug!("Running workers in delegated subcgroup '", &workers[..], "'.");
                    m.workers_cgroup = Some(workers);
                }
            }
        }
        Ok(_) => {}
    }
    let mut ev: Ev = match Event::new() {
        Ok(e) => e,
        Err(r) => return log_error_errno!(r, "Failed to allocate event loop: ", strerror(r)),
    };
    if let Err(r) = setup_event(&mut ev) {
        return r;
    }
    let varlink_fd = match listen_fds(&mut m) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = control::start_varlink_server(&mut m, &mut ev, varlink_fd) {
        return r;
    }
    if let Err(r) = manager::start_device_monitor(&mut m, &mut ev) {
        return r;
    }
    if let Err(r) = watch::start_inotify(&mut m, &mut ev) {
        return r;
    }
    if let Err(r) = manager::start_worker_notify(&mut m, &mut ev) {
        return r;
    }
    m.last_usec = shared::time::now_monotonic();
    crate::udev::builtin::udev_builtin_init();
    let timing = m.configs.config.resolve_name_timing.unwrap_or(crate::udev::def::ResolveNameTiming::Early);
    match crate::udev::rules::udev_rules_load(timing, &[]) {
        Err(r) => return log_error_errno!(r, "Failed to read udev rules: ", strerror(r)),
        Ok(r) => m.rules = Some(r),
    }
    if let Some(rules) = &m.rules
        && let Err(r) = rules.apply_static_dev_perms()
    {
        log_warning_errno!(r, "Failed to apply permissions on static device nodes, ignoring: ", strerror(r));
    }
    shared::notify::sd_notify(b"READY=1\nSTATUS=Processing requests...");
    notify_remove_fd_warn(b"event-serialization");
    let r = match ev.run_loop(&mut m) {
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Event loop failed: ", strerror(r)),
        _ => 0,
    };
    shared::notify::sd_notify(b"STOPPING=1\nSTATUS=Shutting down...");
    // manager_free()
    crate::udev::builtin::udev_builtin_exit();
    r
}
