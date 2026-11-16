// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-manager.c`: the event queue, the workers, and what drives them.

use shared::device_monitor::{Monitor, MonitorGroup};
use shared::errno::{strerror, synthetic};
use shared::event::Fired;
use shared::sd_device::{Dev, device_action_to_string};
use shared::sys::{self, OwnedFd};
use shared::{
    log_debug, log_debug_errno, log_device_debug, log_device_error, log_device_error_errno, log_device_warning,
    log_device_warning_errno, log_error_errno, log_warning, log_warning_errno,
};

use super::config::{UDEV_RELOAD_KILL_WORKERS, UDEV_RELOAD_RULES};
use super::{
    EVENT_PRIORITY_DEVICE_MONITOR, EVENT_PRIORITY_REQUEUE_EVENT, EVENT_PRIORITY_WORKER_EXIT,
    EVENT_PRIORITY_WORKER_NOTIFY, EVENT_PRIORITY_WORKER_TIMER, Ev, EventState, Manager, QEvent, Worker, WorkerState,
    event_reset_time, event_reset_time_relative, event_source_disable,
};
use crate::udev::util::log_device_uevent;

/// `EVENT_REQUEUE_INTERVAL_USEC`.
const EVENT_REQUEUE_INTERVAL_USEC: u64 = 200 * 1000;
/// `EVENT_REQUEUE_TIMEOUT_USEC`.
const EVENT_REQUEUE_TIMEOUT_USEC: u64 = 3 * 60 * 1_000_000;

/// `udev_warn_timeout()`.
fn udev_warn_timeout(timeout: u64) -> u64 {
    if timeout == u64::MAX { u64::MAX } else { timeout.div_ceil(3) }
}

/// `devpath_conflict(a, b)`: equal, or one is a parent of the other.
pub fn devpath_conflict(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    let (Some(a), Some(b)) = (a, b) else { return false };
    let n = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let ca = a.get(n).copied().unwrap_or(0);
    let cb = b.get(n).copied().unwrap_or(0);
    if ca != 0 && cb != 0 {
        return false;
    }
    ca == b'/' || cb == b'/' || ca == cb
}

/// `device_add_errno(dev, error)`.
pub fn device_add_errno(dev: &Dev, error: i32) -> Result<(), i32> {
    if error == 0 {
        return Ok(());
    }
    let e = error.abs();
    let mut r = dev.add_property(b"UDEV_WORKER_FAILED", Some(b"1"));
    let r2 = dev.add_property(b"UDEV_WORKER_ERRNO", Some(e.to_string().as_bytes()));
    r = r.and(r2);
    if let Some(s) = sys::errno_name(e) {
        r = r.and(dev.add_property(b"UDEV_WORKER_ERRNO_NAME", Some(&s)));
    }
    r
}

/// `device_add_exit_status(dev, status)`.
fn device_add_exit_status(dev: &Dev, status: i32) {
    if status == 0 {
        return;
    }
    let _ = dev.add_property(b"UDEV_WORKER_FAILED", Some(b"1"));
    let _ = dev.add_property(b"UDEV_WORKER_EXIT_STATUS", Some(status.to_string().as_bytes()));
}

/// `device_add_signal(dev, signo)`.
fn device_add_signal(dev: &Dev, signo: i32) {
    let _ = dev.add_property(b"UDEV_WORKER_FAILED", Some(b"1"));
    let _ = dev.add_property(b"UDEV_WORKER_SIGNAL", Some(signo.to_string().as_bytes()));
    let _ = dev.add_property(b"UDEV_WORKER_SIGNAL_NAME", Some(shared::signal::signal_to_string(signo).as_bytes()));
}

/// `device_broadcast_on_error(dev, monitor)`.
pub fn device_broadcast_on_error(dev: &Dev, monitor: Option<&Monitor>) {
    let _ = dev.delete_db();
    let _ = dev.tag_index(false);
    let Some(monitor) = monitor else { return };
    if let Err(r) = monitor.send(None, dev) {
        let seqnum = dev.get_seqnum().unwrap_or(0);
        log_device_warning_errno!(
            dev,
            r,
            "Failed to broadcast event (SEQNUM=",
            seqnum.to_string(),
            ") to libudev listeners: ",
            strerror(r)
        );
    }
}

impl Manager {
    fn event_index(&self, seqnum: u64) -> Option<usize> {
        self.events.iter().position(|e| e.seqnum == seqnum)
    }

    fn worker_index(&self, pid: i32) -> Option<usize> {
        self.workers.iter().position(|w| w.pid == pid)
    }

    /// `event_unset_whole_disk()`.
    fn event_unset_whole_disk(&mut self, seqnum: u64) {
        let Some(i) = self.event_index(seqnum) else { return };
        let Some(disk) = self.events[i].whole_disk.take() else { return };
        if let Some(p) = self.locked_events_by_disk.iter().position(|(d, _)| *d == disk) {
            self.locked_events_by_disk[p].1.retain(|&s| s != seqnum);
            if self.locked_events_by_disk[p].1.is_empty() {
                self.locked_events_by_disk.remove(p);
            }
        }
    }

    /// `event_enter_processed()` (and `event_free()`): drops the event.
    pub fn event_enter_processed(&mut self, seqnum: u64) {
        self.event_unset_whole_disk(seqnum);
        let Some(i) = self.event_index(seqnum) else { return };
        let e = self.events.remove(i);
        if let Some(pid) = e.worker
            && let Some(w) = self.worker_index(pid)
        {
            self.workers[w].event = None;
        }
    }

    /// `manager_kill_workers(manager, signo)`.
    pub fn kill_workers(&mut self, sig: i32) {
        for w in &mut self.workers {
            w.state = WorkerState::Killed;
            let _ = sys::kill(w.pid, sig);
        }
    }

    /// `manager_reset_kill_workers_timer()`.
    pub fn reset_kill_workers_timer(&mut self, ev: &mut Ev) {
        if self.workers.is_empty() {
            event_source_disable(ev, self.kill_workers_source);
            return;
        }
        let mut slot = self.kill_workers_source;
        let r = event_reset_time_relative(
            ev,
            &mut slot,
            3 * 1_000_000,
            || {
                Box::new(|m: &mut Manager, _ev: &mut Ev, _id, _f| {
                    log_debug!("Cleaning up idle workers.");
                    m.kill_workers(libc::SIGTERM);
                    0
                })
            },
            EVENT_PRIORITY_WORKER_TIMER,
            b"kill-workers-event",
            false,
        );
        self.kill_workers_source = slot;
        if let Err(r) = r {
            log_warning_errno!(r, "Failed to enable timer event source for cleaning up workers: ", strerror(r));
        }
    }

    /// `manager_exit()`.
    pub fn exit(&mut self, ev: &mut Ev) {
        if self.exit {
            return;
        }
        self.exit = true;
        shared::notify::sd_notify(b"STOPPING=1\nSTATUS=Shutting down...");
        shared::varlink::Server::release(|m: &mut Manager| &mut m.varlink, self, ev);
        let _ = self.serialize_config();
        if let Some(id) = self.inotify_source.take() {
            ev.remove(id);
        }
        if let Some(id) = self.monitor_source.take() {
            ev.remove(id);
        }
        self.kill_workers(libc::SIGTERM);
        if let Some(id) = self.kill_workers_source.take() {
            ev.remove(id);
        }
        event_source_disable(ev, self.requeue_locked_events_source);
    }

    /// `notify_ready()`.
    pub fn notify_ready(&self) {
        if self.exit {
            return;
        }
        let r = shared::notify::sd_notify(
            format!("READY=1\nSTATUS=Processing with {} children at max", self.configs.config.children_max).as_bytes(),
        );
        if r < 0 {
            log_warning_errno!(r, "Failed to send readiness notification, ignoring: ", strerror(r));
        }
    }

    /// `manager_reload(manager, force)`.
    pub fn reload(&mut self, ev: &mut Ev, force: bool) {
        if self.exit {
            return;
        }
        let now = ev.now(libc::CLOCK_MONOTONIC);
        if !force && now < self.last_usec.saturating_add(3 * 1_000_000) {
            return;
        }
        self.last_usec = now;
        let mut flags = 0u32;
        if crate::udev::rules::udev_rules_should_reload(self.rules.as_ref()) {
            flags |= UDEV_RELOAD_RULES | UDEV_RELOAD_KILL_WORKERS;
        }
        if flags == 0 && !force {
            return;
        }
        // notify_reloading()
        let mono = shared::time::now_monotonic();
        shared::notify::sd_notify(
            format!("RELOADING=1\nSTATUS=Reloading configuration...\nMONOTONIC_USEC={mono}").as_bytes(),
        );
        flags |= self.configs.reload();
        if flags & UDEV_RELOAD_KILL_WORKERS != 0 {
            self.kill_workers(libc::SIGTERM);
        }
        if flags & UDEV_RELOAD_RULES != 0 {
            let timing = self.configs.config.resolve_name_timing.unwrap_or(crate::udev::def::ResolveNameTiming::Early);
            match crate::udev::rules::udev_rules_load(timing, &[]) {
                Err(r) => {
                    log_warning_errno!(
                        r,
                        "Failed to read udev rules, using the previously loaded rules, ignoring: ",
                        strerror(r)
                    );
                }
                Ok(r) => self.rules = Some(r),
            }
        }
        self.notify_ready();
    }

    /// `manager_revert()`.
    pub fn revert(&mut self) {
        let mut flags = 0;
        if !self.properties.is_empty() {
            flags |= UDEV_RELOAD_KILL_WORKERS;
            self.properties.clear();
        }
        flags |= self.configs.revert();
        if flags == 0 {
            return;
        }
        self.kill_workers(libc::SIGTERM);
    }

    /// `worker_attach_event()`.
    fn worker_attach_event(&mut self, ev: &mut Ev, wi: usize, seqnum: u64) {
        let pid = self.workers[wi].pid;
        self.workers[wi].state = WorkerState::Running;
        self.workers[wi].event = Some(seqnum);
        if let Some(i) = self.event_index(seqnum) {
            self.events[i].state = EventState::Running;
            self.events[i].worker = Some(pid);
        }
        let timeout = self.configs.config.timeout_usec;
        let kill_timeout = timeout.saturating_add(super::config::extra_timeout_usec());
        let mut slot = self.workers[wi].warn_source;
        let _ = event_reset_time_relative(
            ev,
            &mut slot,
            udev_warn_timeout(timeout),
            || {
                Box::new(move |m: &mut Manager, _ev: &mut Ev, _id, _f| {
                    if let Some(w) = m.worker_index(pid)
                        && let Some(s) = m.workers[w].event
                        && let Some(e) = m.event_index(s)
                    {
                        log_device_warning!(
                            m.events[e].dev,
                            "Worker [",
                            pid.to_string(),
                            "] processing SEQNUM=",
                            s.to_string(),
                            " is taking a long time."
                        );
                    }
                    0
                })
            },
            EVENT_PRIORITY_WORKER_TIMER,
            b"worker-timeout-warn",
            true,
        );
        self.workers[wi].warn_source = slot;
        let mut slot = self.workers[wi].kill_source;
        let _ = event_reset_time_relative(
            ev,
            &mut slot,
            kill_timeout,
            || {
                Box::new(move |m: &mut Manager, _ev: &mut Ev, _id, _f| {
                    let Some(w) = m.worker_index(pid) else { return 0 };
                    let sig = m.configs.config.timeout_signal;
                    // pidref_kill_and_sigcont()
                    let _ = sys::kill(pid, sig);
                    if sig != libc::SIGCONT && sig != libc::SIGKILL {
                        let _ = sys::kill(pid, libc::SIGCONT);
                    }
                    m.workers[w].state = WorkerState::Killed;
                    if let Some(s) = m.workers[w].event
                        && let Some(e) = m.event_index(s)
                    {
                        log_device_error!(
                            m.events[e].dev,
                            "Worker [",
                            pid.to_string(),
                            "] processing SEQNUM=",
                            s.to_string(),
                            " killed."
                        );
                    }
                    0
                })
            },
            EVENT_PRIORITY_WORKER_TIMER,
            b"worker-timeout-kill",
            true,
        );
        self.workers[wi].kill_source = slot;
    }

    /// `worker_detach_event()`: the seqnum of the event it had.
    fn worker_detach_event(&mut self, ev: &mut Ev, wi: usize) -> Option<u64> {
        let seqnum = self.workers[wi].event.take();
        if let Some(s) = seqnum
            && let Some(i) = self.event_index(s)
        {
            self.events[i].worker = None;
        }
        if self.workers[wi].state != WorkerState::Killed {
            self.workers[wi].state = WorkerState::Idle;
        }
        event_source_disable(ev, self.workers[wi].warn_source);
        event_source_disable(ev, self.workers[wi].kill_source);
        seqnum
    }

    /// `worker_free()`.
    fn worker_free(&mut self, ev: &mut Ev, pid: i32) {
        let Some(wi) = self.worker_index(pid) else { return };
        let w = self.workers.remove(wi);
        if let Some(s) = w.event
            && let Some(i) = self.event_index(s)
        {
            self.events[i].worker = None;
        }
        for id in [w.child_source, w.warn_source, w.kill_source].into_iter().flatten() {
            ev.remove(id);
        }
    }

    /// `on_worker_exit()`.
    fn on_worker_exit(&mut self, ev: &mut Ev, pid: i32, ci: sys::ChildInfo) {
        let Some(wi) = self.worker_index(pid) else { return };
        let seqnum = self.worker_detach_event(ev, wi);
        let dev = seqnum.and_then(|s| self.event_index(s)).map(|i| self.events[i].dev.clone());
        let d = dev.as_deref();
        match ci.code {
            libc::CLD_EXITED => {
                if ci.status == 0 {
                    shared::sd_device::log_device_full(
                        d,
                        shared::log::LOG_DEBUG,
                        0,
                        shared::bcat!("Worker [", ci.pid.to_string(), "] exited."),
                    );
                } else {
                    shared::sd_device::log_device_full(
                        d,
                        shared::log::LOG_WARNING,
                        0,
                        shared::bcat!(
                            "Worker [",
                            ci.pid.to_string(),
                            "] exited with return code ",
                            ci.status.to_string(),
                            "."
                        ),
                    );
                    if let Some(dev) = &dev {
                        device_add_exit_status(dev, ci.status);
                        device_broadcast_on_error(dev, self.monitor.as_ref());
                    }
                }
            }
            _ => {
                shared::sd_device::log_device_full(
                    d,
                    shared::log::LOG_WARNING,
                    0,
                    shared::bcat!(
                        "Worker [",
                        ci.pid.to_string(),
                        "] terminated by signal ",
                        ci.status.to_string(),
                        " (",
                        shared::signal::signal_to_string(ci.status),
                        ")."
                    ),
                );
                if let Some(dev) = &dev {
                    device_add_signal(dev, ci.status);
                    device_broadcast_on_error(dev, self.monitor.as_ref());
                }
            }
        }
        if let Some(s) = seqnum {
            self.event_enter_processed(s);
        }
        self.worker_free(ev, pid);
    }

    /// `worker_spawn()`.
    fn worker_spawn(&mut self, ev: &mut Ev, seqnum: u64) -> Result<(), i32> {
        let mut worker_monitor = Monitor::new_full(MonitorGroup::None)?;
        worker_monitor.set_description(Some(b"worker"));
        if let Some(m) = &self.monitor {
            worker_monitor.allow_unicast_sender(m);
        }
        let manager_pid = sys::getpid();
        let pid = match shared::process::safe_fork("(udev-worker)", shared::process::FORK_DEATHSIG_SIGTERM) {
            Err(r) => {
                if let Some(i) = self.event_index(seqnum) {
                    self.events[i].state = EventState::Queued;
                }
                return Err(log_error_errno!(r, "Failed to fork() worker: ", strerror(r)));
            }
            Ok(p) => p,
        };
        if pid == 0 {
            let dev = self.events[self.event_index(seqnum).expect("event")].dev.clone();
            if let Some(cg) = &self.workers_cgroup {
                let p = shared::path::path_join(&[b"/sys/fs/cgroup", cg, b"cgroup.procs"]);
                if let Err(r) = shared::fileio::write_string_file(&p, format!("{}\n", sys::getpid()).as_bytes(), 0) {
                    log_error_errno!(r, "Failed to move worker into cgroup '", &cg[..], "': ", strerror(r));
                    sys::exit_now(libc::EXIT_FAILURE);
                }
            }
            if let Err(r) = sys::setenv(b"NOTIFY_SOCKET", &self.worker_notify_socket_path) {
                log_error_errno!(r, "Failed to set $NOTIFY_SOCKET: ", strerror(r));
                sys::exit_now(libc::EXIT_FAILURE);
            }
            let w = super::worker::UdevWorker {
                monitor: worker_monitor,
                properties: std::mem::take(&mut self.properties),
                rules: self.rules.take(),
                config: self.configs.config,
                manager_pid,
            };
            let r = super::worker::udev_worker_main(w, &dev);
            shared::log::log_close();
            sys::exit_now(if r < 0 { libc::EXIT_FAILURE } else { libc::EXIT_SUCCESS });
        }
        let address = worker_monitor.get_address();
        drop(worker_monitor);
        let child = ev.add_child(
            pid,
            libc::WEXITED,
            Box::new(move |m: &mut Manager, ev: &mut Ev, _id, f| {
                if let Fired::Child(ci) = f {
                    m.on_worker_exit(ev, pid, ci);
                }
                0
            }),
        );
        let child = match child.and_then(|id| ev.set_priority(id, EVENT_PRIORITY_WORKER_EXIT).map(|_| id)) {
            Ok(c) => c,
            Err(r) => return Err(log_error_errno!(r, "Failed to create worker object: ", strerror(r))),
        };
        self.workers.push(Worker {
            pid,
            address,
            state: WorkerState::Undef,
            event: None,
            child_source: Some(child),
            warn_source: None,
            kill_source: None,
        });
        let wi = self.workers.len() - 1;
        self.worker_attach_event(ev, wi, seqnum);
        let i = self.event_index(seqnum).expect("event");
        log_device_debug!(
            self.events[i].dev,
            "Worker [",
            pid.to_string(),
            "] is forked for processing SEQNUM=",
            seqnum.to_string(),
            "."
        );
        Ok(())
    }

    /// `event_run()`.
    fn event_run(&mut self, ev: &mut Ev, seqnum: u64) -> Result<(), i32> {
        let i = self.event_index(seqnum).expect("event");
        let dev = self.events[i].dev.clone();
        log_device_uevent(&dev, b"Device ready for processing");
        for wi in 0..self.workers.len() {
            if self.workers[wi].state != WorkerState::Idle {
                continue;
            }
            let addr = self.workers[wi].address;
            let r = match &self.monitor {
                Some(m) => m.send(Some(addr), &dev),
                None => Err(-libc::ENOTCONN),
            };
            if let Err(r) = r {
                log_device_error_errno!(
                    dev,
                    r,
                    "Worker [",
                    self.workers[wi].pid.to_string(),
                    "] did not accept message, killing the worker: ",
                    strerror(r)
                );
                let _ = sys::kill(self.workers[wi].pid, libc::SIGKILL);
                self.workers[wi].state = WorkerState::Killed;
                continue;
            }
            self.worker_attach_event(ev, wi, seqnum);
            return Ok(());
        }
        if self.workers.len() >= self.configs.config.children_max as usize {
            return Ok(());
        }
        self.worker_spawn(ev, seqnum)
    }

    /// `event_find_blocker()`.
    fn event_find_blocker(&mut self, i: usize) {
        let e = &self.events[i];
        if let Some(b) = e.blocker
            && self.event_index(b).is_some()
        {
            return;
        }
        // Search backwards from before the (processed) blocker, or before
        // this event.
        let start = e.blocker.unwrap_or(e.seqnum);
        let found = self.events[..i].iter().rev().filter(|x| x.seqnum < start).find(|x| {
            e.id.is_some() && x.id == e.id
                || devpath_conflict(Some(&e.devpath), Some(&x.devpath))
                || devpath_conflict(Some(&e.devpath), x.devpath_old.as_deref())
                || devpath_conflict(e.devpath_old.as_deref(), Some(&x.devpath))
                || e.devnode.is_some() && e.devnode == x.devnode
        });
        match found.map(|x| x.seqnum) {
            Some(b) => {
                log_device_debug!(e.dev, "SEQNUM=", e.seqnum.to_string(), " blocked by SEQNUM=", b.to_string());
                self.events[i].blocker = Some(b);
            }
            None => self.events[i].blocker = None,
        }
    }

    /// `manager_can_process_event()`.
    fn can_process_event(&mut self) -> bool {
        if self.workers.len() < self.configs.config.children_max as usize
            || self.workers.iter().any(|w| w.state == WorkerState::Idle)
        {
            self.children_max_reached_logged = false;
            return true;
        }
        if !self.children_max_reached_logged {
            log_debug!("Maximum number (", self.workers.len().to_string(), ") of children reached.");
            self.children_max_reached_logged = true;
        }
        false
    }

    /// `event_queue_start()`.
    fn event_queue_start(&mut self, ev: &mut Ev) -> Result<(), i32> {
        if self.events.is_empty() || self.stop_exec_queue {
            return Ok(());
        }
        event_source_disable(ev, self.kill_workers_source);
        self.reload(ev, false);
        if !self.can_process_event() {
            return Ok(());
        }
        let mut i = 0;
        while i < self.events.len() {
            if self.events[i].state != EventState::Queued {
                i += 1;
                continue;
            }
            self.event_find_blocker(i);
            if self.events[i].blocker.is_some() {
                i += 1;
                continue;
            }
            let seqnum = self.events[i].seqnum;
            self.event_run(ev, seqnum)?;
            if !self.can_process_event() {
                break;
            }
            i = self.event_index(seqnum).map_or(i, |x| x + 1);
        }
        Ok(())
    }

    /// `manager_requeue_locked_events()`.
    fn requeue_locked_events(&mut self, ev: &mut Ev) {
        let mut now = 0;
        loop {
            let next = self
                .events
                .iter()
                .filter(|e| e.state == EventState::Locked && e.whole_disk.is_some())
                .min_by_key(|e| e.requeue_next_usec)
                .map(|e| (e.seqnum, e.requeue_next_usec));
            let Some((seqnum, at)) = next else {
                event_source_disable(ev, self.requeue_locked_events_source);
                return;
            };
            if now == 0 {
                now = ev.now(libc::CLOCK_MONOTONIC);
            }
            if at > now {
                let mut slot = self.requeue_locked_events_source;
                let _ = event_reset_time(
                    ev,
                    &mut slot,
                    at,
                    || Box::new(|_m: &mut Manager, _ev: &mut Ev, _id, _f| 1),
                    EVENT_PRIORITY_REQUEUE_EVENT,
                    b"requeue-locked-events",
                    true,
                );
                self.requeue_locked_events_source = slot;
                return;
            }
            self.event_unset_whole_disk(seqnum);
            if let Some(i) = self.event_index(seqnum) {
                self.events[i].state = EventState::Queued;
            }
        }
    }

    /// `manager_requeue_locked_events_by_device()`.
    pub fn requeue_locked_events_by_device(&mut self, dev: &Dev) {
        if self.locked_events_by_disk.is_empty() {
            return;
        }
        let Ok(Some((_, devname))) = super::worker::udev_get_whole_disk(dev) else { return };
        let Some(p) = self.locked_events_by_disk.iter().position(|(d, _)| *d == devname) else { return };
        let (_, seqnums) = self.locked_events_by_disk.remove(p);
        for s in seqnums {
            if let Some(i) = self.event_index(s) {
                self.events[i].whole_disk = None;
                self.events[i].state = EventState::Queued;
            }
        }
    }

    /// `event_enter_locked()`.
    fn event_enter_locked(&mut self, ev: &mut Ev, seqnum: u64, whole_disk: Option<&[u8]>) -> Result<(), i32> {
        let now = ev.now(libc::CLOCK_MONOTONIC);
        let i = self.event_index(seqnum).expect("event");
        let e = &mut self.events[i];
        let action = device_action_to_string(e.action);
        if e.requeue_timeout_usec > 0 && e.requeue_timeout_usec <= now {
            return Err(log_device_warning_errno!(
                e.dev,
                synthetic(libc::ETIMEDOUT),
                "The underlying block device is locked by a process more than ",
                shared::time::format_timespan(EVENT_REQUEUE_TIMEOUT_USEC, 60 * 1_000_000),
                ", skipping event (SEQNUM=",
                seqnum.to_string(),
                ", ACTION=",
                action,
                ")."
            ));
        }
        e.requeue_next_usec = now.saturating_add(EVENT_REQUEUE_INTERVAL_USEC);
        if e.requeue_timeout_usec == 0 {
            e.requeue_timeout_usec = now.saturating_add(EVENT_REQUEUE_TIMEOUT_USEC);
        }
        let Some(disk) = whole_disk.filter(|d| !d.is_empty()) else {
            return Err(log_device_warning_errno!(
                e.dev,
                synthetic(libc::EBADMSG),
                "Unexpected notify message received, skipping event (SEQNUM=",
                seqnum.to_string(),
                ", ACTION=",
                action,
                ")."
            ));
        };
        e.whole_disk = Some(disk.to_vec());
        e.state = EventState::Locked;
        match self.locked_events_by_disk.iter_mut().find(|(d, _)| d == disk) {
            Some((_, l)) => l.insert(0, seqnum),
            None => self.locked_events_by_disk.push((disk.to_vec(), vec![seqnum])),
        }
        Ok(())
    }

    /// `event_queue_insert()`.
    pub fn event_queue_insert(&mut self, dev: &Dev) -> Result<(), i32> {
        if let Ok(uuid) = dev.get_trigger_uuid()
            && let Ok(id) = shared::id128::from_string(&uuid)
        {
            self.synthesized_events.retain(|u| *u != id);
        }
        let seqnum = dev.get_seqnum()?;
        let action = dev.get_action()?;
        let devpath = dev.get_devpath().bytes().to_vec();
        let opt = |r: Result<shared::sd_device::DStr, i32>| -> Result<Option<Vec<u8>>, i32> {
            match r {
                Ok(v) => Ok(Some(v.bytes().to_vec())),
                Err(e) if e == -libc::ENOENT => Ok(None),
                Err(e) => Err(e),
            }
        };
        let devpath_old = opt(dev.get_property_value(b"DEVPATH_OLD"))?;
        let id = opt(dev.get_device_id())?;
        let devnode = opt(dev.get_devname())?;
        let event = QEvent {
            dev: dev.clone(),
            seqnum,
            action,
            id,
            devpath,
            devpath_old,
            devnode,
            state: EventState::Queued,
            worker: None,
            requeue_next_usec: 0,
            requeue_timeout_usec: 0,
            whole_disk: None,
            blocker: None,
        };
        // Reorder events the kernel sent out of order.
        let mut pos = self.events.len();
        while pos > 0 {
            let e = &mut self.events[pos - 1];
            if e.seqnum < seqnum {
                break;
            }
            if e.seqnum == seqnum {
                return Err(log_device_warning_errno!(
                    dev,
                    synthetic(libc::EALREADY),
                    "The event (SEQNUM=",
                    seqnum.to_string(),
                    ") has been already queued."
                ));
            }
            e.blocker = None;
            pos -= 1;
        }
        if pos != self.events.len() {
            log_device_debug!(
                dev,
                "Unordered event is received (last queued event seqnum=",
                self.events.last().map_or(0, |e| e.seqnum).to_string(),
                ", newly received event seqnum=",
                seqnum.to_string(),
                "), reordering."
            );
        }
        self.events.insert(pos, event);
        log_device_uevent(dev, b"Device is queued");
        Ok(())
    }

    /// `manager_create_queue_file()`.
    pub fn create_queue_file(&mut self) {
        if self.queue_file_created {
            return;
        }
        if let Err(r) = shared::fs::touch_file(b"/run/udev/queue", false, u64::MAX, u32::MAX, u32::MAX, u32::MAX) {
            log_warning_errno!(r, "Failed to touch /run/udev/queue: ", strerror(r));
            return;
        }
        self.queue_file_created = true;
    }

    /// `manager_unlink_queue_file()`.
    fn unlink_queue_file(&mut self) {
        if !self.events.is_empty() || !self.synthesize_change_children.is_empty() || !self.synthesized_events.is_empty()
        {
            return;
        }
        match sys::unlink(b"/run/udev/queue") {
            Err(r) if r != -libc::ENOENT => {
                log_warning_errno!(r, "Failed to unlink /run/udev/queue: ", strerror(r));
                return;
            }
            Err(_) => {}
            Ok(()) => {
                log_debug!("No events are queued, removed /run/udev/queue.");
            }
        }
        self.queue_file_created = false;
    }

    /// `on_post_exit()`.
    fn on_post_exit(&mut self, ev: &mut Ev) -> i32 {
        if self.events.iter().any(|e| e.state == EventState::Running) {
            return 0;
        }
        self.unlink_queue_file();
        if !self.workers.is_empty() {
            return 0;
        }
        let _ = self.serialize_events();
        super::watch::udev_watch_dump();
        ev.exit(0);
        0
    }

    /// `on_post()`.
    pub fn on_post(&mut self, ev: &mut Ev) -> i32 {
        if self.exit {
            return self.on_post_exit(ev);
        }
        if !self.events.is_empty() {
            self.requeue_locked_events(ev);
            let _ = self.event_queue_start(ev);
            return 0;
        }
        self.unlink_queue_file();
        self.reset_kill_workers_timer(ev);
        if !self.workers.is_empty() {
            return 0;
        }
        if let Some(cg) = &self.workers_cgroup
            && self.synthesize_change_children.is_empty()
        {
            // cg_kill_kernel_sigkill(); the cg_kill() fallback for kernels
            // without cgroup.kill is not ported.
            let p = shared::path::path_join(&[b"/sys/fs/cgroup", cg, b"cgroup.kill"]);
            if let Err(r) = shared::fileio::write_string_file(&p, b"1", 0) {
                log_debug_errno!(r, "Failed to write to cgroup.kill for cgroup '", &cg[..], "': ", strerror(r));
            }
        }
        0
    }

    /// `on_uevent()`.
    fn on_uevent(&mut self, dev: &Dev) {
        self.create_queue_file();
        let _ = dev.ensure_usec_initialized(None);
        if let Err(r) = self.event_queue_insert(dev) {
            log_device_error_errno!(dev, r, "Failed to insert device into event queue: ", strerror(r));
            return;
        }
        self.requeue_locked_events_by_device(dev);
    }

    /// `on_worker_notify()`.
    fn on_worker_notify(&mut self, ev: &mut Ev, fd: i32) -> i32 {
        let (l, sender) = match shared::notify::notify_recv_strv(fd) {
            Err(r) if r == -libc::EAGAIN => return 0,
            Err(r) => return r,
            Ok(x) => x,
        };
        let Some(wi) = self.worker_index(sender) else {
            log_warning!("Received notify datagram of unknown process [", sender.to_string(), "], ignoring.");
            return 0;
        };
        let has = |s: &[u8]| l.iter().any(|x| x == s);
        for (msg, add) in [(&b"INOTIFY_WATCH_ADD=1"[..], true), (b"INOTIFY_WATCH_REMOVE=1", false)] {
            if !has(msg) {
                continue;
            }
            let Some(dev) =
                self.workers[wi].event.and_then(|s| self.event_index(s)).map(|i| self.events[i].dev.clone())
            else {
                return 0;
            };
            let mut r = if add {
                super::watch::manager_add_watch(self, &dev)
            } else {
                super::watch::manager_remove_watch(self, &dev)
            };
            if add && r.is_err_and(shared::sd_device::errno_is_neg_device_absent) {
                r = Ok(());
            }
            if let Err(e) = r {
                log_device_warning_errno!(
                    dev,
                    e,
                    "Failed to ",
                    if add { "add" } else { "remove" },
                    " inotify watch, ignoring: ",
                    strerror(e)
                );
            }
            let value = r.err().unwrap_or(0);
            if let Err(e) = sys::sigqueue(sender, libc::SIGUSR1, value) {
                log_device_warning_errno!(
                    dev,
                    e,
                    "Failed to send signal to worker process [",
                    sender.to_string(),
                    "], killing the worker process: ",
                    strerror(e)
                );
                let _ = sys::kill(sender, libc::SIGTERM);
                self.workers[wi].state = WorkerState::Killed;
            }
            return 0;
        }
        let Some(seqnum) = self.worker_detach_event(ev, wi) else { return 0 };
        if has(b"TRY_AGAIN=1") {
            let disk = l.iter().find_map(|x| x.strip_prefix(b"WHOLE_DISK=")).map(<[u8]>::to_vec);
            match self.event_enter_locked(ev, seqnum, disk.as_deref()) {
                Ok(()) => return 0,
                Err(r) => {
                    let dev = self.events[self.event_index(seqnum).expect("event")].dev.clone();
                    let _ = device_add_errno(&dev, r);
                    device_broadcast_on_error(&dev, self.monitor.as_ref());
                }
            }
        }
        self.event_enter_processed(seqnum);
        0
    }
}

/// `manager_init_device_monitor()`: takes `fd` on success.
pub fn init_device_monitor(m: &mut Manager, fd: Option<i32>) -> Result<(), i32> {
    if let Some(fd) = fd {
        if m.monitor.is_some() {
            return Err(log_warning_errno!(
                synthetic(libc::EALREADY),
                "Received multiple netlink socket (",
                fd.to_string(),
                "), ignoring."
            ));
        }
        match shared::sys_net::is_netlink_raw_socket(fd) {
            Err(r) => {
                return Err(log_warning_errno!(
                    r,
                    "Failed to verify socket type of ",
                    fd.to_string(),
                    ", ignoring: ",
                    strerror(r)
                ));
            }
            Ok(false) => {
                return Err(log_warning_errno!(
                    synthetic(libc::EINVAL),
                    "Received invalid netlink socket (",
                    fd.to_string(),
                    "), ignoring."
                ));
            }
            Ok(true) => {}
        }
    } else if m.monitor.is_some() {
        return Ok(());
    }
    match Monitor::new_full_fd(MonitorGroup::Kernel, fd) {
        Ok(mon) => {
            m.monitor = Some(mon);
            Ok(())
        }
        Err(r) => Err(log_error_errno!(r, "Failed to initialize device monitor: ", strerror(r))),
    }
}

/// `manager_start_device_monitor()`.
pub fn start_device_monitor(m: &mut Manager, ev: &mut Ev) -> Result<(), i32> {
    init_device_monitor(m, None)?;
    let mon = m.monitor.as_mut().expect("monitor");
    mon.set_description(Some(b"manager"));
    if let Err(r) = mon.filter_update() {
        return Err(log_error_errno!(r, "Failed to start device monitor: ", strerror(r)));
    }
    let fd = mon.get_fd();
    let id = ev
        .add_io(
            fd,
            libc::EPOLLIN as u32,
            Box::new(|m: &mut Manager, _ev: &mut Ev, _id, _f| {
                let r = m.monitor.as_mut().map(|mon| mon.receive());
                if let Some(Ok(Some(dev))) = r {
                    m.on_uevent(&dev);
                }
                1
            }),
        )
        .map_err(|r| log_error_errno!(r, "Failed to start device monitor: ", strerror(r)))?;
    ev.set_description(id, b"manager");
    if let Err(r) = ev.set_priority(id, EVENT_PRIORITY_DEVICE_MONITOR) {
        return Err(log_error_errno!(r, "Failed to set priority to device monitor: ", strerror(r)));
    }
    m.monitor_source = Some(id);
    Ok(())
}

/// `manager_start_worker_notify()`.
pub fn start_worker_notify(m: &mut Manager, ev: &mut Ev) -> Result<(), i32> {
    let r = (|| -> Result<(OwnedFd, Vec<u8>), i32> {
        let (fd, path) = shared::notify::notify_socket_new()?;
        let id = ev
            .add_io(
                fd.raw(),
                libc::EPOLLIN as u32,
                Box::new(|m: &mut Manager, ev: &mut Ev, _id, f| {
                    let Fired::Io { fd, .. } = f else { return 0 };
                    m.on_worker_notify(ev, fd)
                }),
            )
            .map_err(|r| log_debug_errno!(r, "Failed to create notification event source: ", strerror(r)))?;
        ev.set_priority(id, EVENT_PRIORITY_WORKER_NOTIFY)
            .map_err(|r| log_debug_errno!(r, "Failed to set priority to notification event source: ", strerror(r)))?;
        ev.set_description(id, b"notify-socket");
        Ok((fd, path))
    })();
    match r {
        Err(r) => Err(log_error_errno!(r, "Failed to prepare worker notification socket: ", strerror(r))),
        Ok((fd, path)) => {
            m.worker_notify_fd = Some(fd);
            m.worker_notify_socket_path = path;
            Ok(())
        }
    }
}

impl Manager {
    /// `manager_serialize_config()`.
    pub fn serialize_config(&self) -> Result<(), i32> {
        let fd = match sys::memfd_create(b"systemd-udevd") {
            Ok(fd) => OwnedFd::new(fd),
            Err(r) => return Err(log_warning_errno!(r, "Failed to open new serialization file: ", strerror(r))),
        };
        log_debug!("Serializing systemd-udevd to memfd.");
        let c = &self.configs.by_control;
        let mut s = Vec::new();
        if c.log_level >= 0 {
            s.extend_from_slice(format!("log-level={}\n", c.log_level).as_bytes());
        }
        if c.children_max > 0 {
            s.extend_from_slice(format!("children-max={}\n", c.children_max).as_bytes());
        }
        if c.trace {
            s.extend_from_slice(b"trace=yes\n");
        }
        for (k, v) in &self.properties {
            s.extend_from_slice(&shared::bcat!("property=", k, "=", v, "\n"));
        }
        if let Err(r) = sys::write_all(fd.raw(), &s).and_then(|_| sys::lseek(fd.raw(), 0, libc::SEEK_SET).map(|_| ())) {
            return Err(log_warning_errno!(r, "Failed to finalize serialization file: ", strerror(r)));
        }
        if let Err(r) = notify_push_fd(b"config-serialization") {
            return Err(log_debug_errno!(r, "Failed to push serialization fd to service manager: ", strerror(r)));
        }
        log_debug!("Serialized configurations.");
        Ok(())
    }

    /// `manager_deserialize_config()`: takes `fd`.
    pub fn deserialize_config(&mut self, fd: i32) -> Result<(), i32> {
        let fd = OwnedFd::new(fd);
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match sys::read(fd.raw(), &mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(r) => return Err(log_warning_errno!(r, "Failed to open serialization fd: ", strerror(r))),
            }
        }
        for l in data.split(|&c| c == b'\n') {
            if l.is_empty() {
                break;
            }
            if let Some(v) = l.strip_prefix(b"log-level=") {
                match shared::log::log_level_from_string(v) {
                    Ok(x) => self.configs.by_control.log_level = x,
                    Err(r) => {
                        log_debug_errno!(r, "Failed to parse serialized log level (", v, "), ignoring: ", strerror(r));
                    }
                }
            } else if let Some(v) = l.strip_prefix(b"children-max=") {
                match shared::parse::safe_atou(v) {
                    Ok(x) => self.configs.by_control.children_max = x,
                    Err(r) => {
                        log_debug_errno!(
                            r,
                            "Failed to parse serialized children max (",
                            v,
                            "), ignoring: ",
                            strerror(r)
                        );
                    }
                }
            } else if let Some(v) = l.strip_prefix(b"trace=") {
                match shared::parse::parse_boolean(v) {
                    Ok(x) => self.configs.by_control.trace = x,
                    Err(r) => {
                        log_debug_errno!(r, "Failed to parse serialized trace (", v, "), ignoring: ", strerror(r));
                    }
                }
            } else if let Some(v) = l.strip_prefix(b"property=") {
                let r = if crate::udev::util::udev_property_assignment_is_valid(v) {
                    super::control::set_environment_one(self, v)
                } else {
                    Err(-libc::EINVAL)
                };
                if let Err(r) = r {
                    log_debug_errno!(r, "Failed to deserialize property (", v, "), ignoring: ", strerror(r));
                }
            } else {
                log_debug!("Unknown serialization item, ignoring: ", l);
            }
        }
        self.configs.merge();
        super::config::adjust_config(&mut self.configs.config);
        log_debug!("Deserialized configurations.");
        Ok(())
    }

    /// `manager_serialize_events()`.
    fn serialize_events(&self) -> Result<(), i32> {
        let storage = match Monitor::new_full(MonitorGroup::None) {
            Ok(s) => s,
            Err(r) => {
                return Err(log_warning_errno!(r, "Failed to create new device monitor instance: ", strerror(r)));
            }
        };
        let a = storage.get_address();
        let mut n = 0u64;
        for e in self.events.iter().filter(|e| e.state == EventState::Queued) {
            if let Err(r) = storage.send(Some(a), &e.dev) {
                log_device_warning_errno!(e.dev, r, "Failed to save event to socket storage, ignoring: ", strerror(r));
                continue;
            }
            n += 1;
        }
        if n == 0 {
            return Ok(());
        }
        if let Err(r) = notify_push_fd(b"event-serialization") {
            return Err(log_warning_errno!(
                r,
                "Failed to push event serialization fd to service manager: ",
                strerror(r)
            ));
        }
        log_debug!("Serialized ", n.to_string(), " events.");
        Ok(())
    }

    /// `manager_deserialize_events()`: takes `fd`.
    pub fn deserialize_events(&mut self, fd: i32) -> Result<(), i32> {
        if !self.events.is_empty() {
            return Err(log_warning_errno!(
                synthetic(libc::EALREADY),
                "Received multiple event storage socket (",
                fd.to_string(),
                ")."
            ));
        }
        match shared::sys_net::is_netlink_raw_socket(fd) {
            Err(r) => {
                return Err(log_warning_errno!(
                    r,
                    "Failed to verify type of event storage socket (",
                    fd.to_string(),
                    "): ",
                    strerror(r)
                ));
            }
            Ok(false) => {
                return Err(log_warning_errno!(
                    synthetic(libc::EINVAL),
                    "Received invalid event storage socket (",
                    fd.to_string(),
                    ")."
                ));
            }
            Ok(true) => {}
        }
        let mut storage = match Monitor::new_full_fd(MonitorGroup::None, Some(fd)) {
            Ok(s) => s,
            Err(r) => return Err(log_warning_errno!(r, "Failed to initialize event storage: ", strerror(r))),
        };
        let own = Monitor::address_of(&storage);
        storage.allow_unicast_sender_pid(own);
        let mut n = 0u64;
        loop {
            match shared::sys_net::poll_one(storage.get_fd(), libc::POLLIN, 0) {
                Err(r) if r == -libc::EINTR => continue,
                Err(r) => {
                    return Err(log_warning_errno!(r, "Failed to wait for event from event storage: ", strerror(r)));
                }
                Ok(0) => break,
                Ok(_) => {}
            }
            let dev = match storage.receive() {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(r) => {
                    log_warning_errno!(r, "Failed to receive device from event storage, ignoring: ", strerror(r));
                    continue;
                }
            };
            if let Err(r) = self.event_queue_insert(&dev) {
                log_device_warning_errno!(dev, r, "Failed to insert device into event queue, ignoring: ", strerror(r));
                continue;
            }
            n += 1;
        }
        if n > 0 {
            self.create_queue_file();
        }
        log_debug!("Deserialized ", n.to_string(), " events.");
        Ok(())
    }
}

/// `notify_push_fd(fd, name)`: without a service manager (no
/// $NOTIFY_SOCKET) this does nothing; the fd store is not supported.
fn notify_push_fd(name: &[u8]) -> Result<(), i32> {
    if sys::getenv("NOTIFY_SOCKET").is_none() {
        return Ok(());
    }
    super::notify_remove_fd_warn(name);
    Err(-libc::EOPNOTSUPP)
}
