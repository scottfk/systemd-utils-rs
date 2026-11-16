// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-event.c`: an event loop with sd-event's dispatch semantics for the
//! source types the ported daemons use (io, time, signal, child, defer,
//! post, exit).
//!
//! Each `run()` dispatches at most one source: the pending one that is
//! enabled, has the lowest priority value, and became pending in the
//! earliest iteration.  Dispatching a non-post source marks every enabled
//! post source pending.  After `exit()`, exit sources run in priority
//! order and then the loop finishes.
//!
//! Known differences: timers fire at their exact time (no coalescing
//! within the accuracy window), and sources pending in the same iteration
//! with the same priority are dispatched in the order they became pending
//! (C's priority queue leaves that unspecified).  There is no rate
//! limiting, inotify source type, watchdog or memory-pressure source.
//!
//! Handlers get the loop's user state (`T`) and the loop itself, so they
//! can add and remove sources, including their own.

use crate::errno::strerror;
use crate::sys::{self, ChildInfo, Fd, SignalInfo};

pub const SD_EVENT_PRIORITY_IMPORTANT: i64 = -100;
pub const SD_EVENT_PRIORITY_NORMAL: i64 = 0;
pub const SD_EVENT_PRIORITY_IDLE: i64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enabled {
    Off,
    On,
    Oneshot,
}

/// What a handler is called with.
#[derive(Debug, Clone, Copy)]
pub enum Fired {
    Io { fd: Fd, revents: u32 },
    Time(u64),
    Signal(SignalInfo),
    Child(ChildInfo),
    Defer,
    Post,
    Exit,
}

/// A source's handle; stale handles (of removed sources) are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id {
    index: u32,
    generation: u32,
}

pub type Handler<T> = Box<dyn FnMut(&mut T, &mut Event<T>, Id, Fired) -> i32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Io { fd: Fd, events: u32, revents: u32, registered: bool },
    Time { clock: libc::clockid_t, next: u64 },
    Signal { sig: i32, info: SignalInfo },
    Child { pidfd: Fd, options: i32, info: ChildInfo, exited: bool, registered: bool },
    Defer,
    Post,
    Exit,
}

impl Kind {
    fn type_name(&self) -> &'static str {
        match self {
            Kind::Io { .. } => "io",
            Kind::Time { clock, .. } => match *clock {
                libc::CLOCK_REALTIME => "realtime",
                libc::CLOCK_BOOTTIME => "boottime",
                _ => "monotonic",
            },
            Kind::Signal { .. } => "signal",
            Kind::Child { .. } => "child",
            Kind::Defer => "defer",
            Kind::Post => "post",
            Kind::Exit => "exit",
        }
    }
}

struct Source<T> {
    generation: u32,
    kind: Kind,
    priority: i64,
    enabled: Enabled,
    pending: bool,
    pending_iteration: u64,
    pending_seq: u64,
    description: Option<Vec<u8>>,
    exit_on_failure: bool,
    handler: Option<Handler<T>>,
    prepare: Option<Handler<T>>,
}

/// One signalfd per priority, as `struct signal_data`.
struct SignalData {
    priority: i64,
    fd: Fd,
    sigs: Vec<i32>,
    current: Option<Id>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    Finished,
}

const TAG_SOURCE: u64 = 0;
const TAG_SIGNAL: u64 = 1 << 56;
const TAG_MASK: u64 = 0xff << 56;

pub struct Event<T> {
    epoll_fd: Fd,
    sources: Vec<Option<Source<T>>>,
    free: Vec<u32>,
    signals: Vec<SignalData>,
    iteration: u64,
    seq: u64,
    exit_requested: bool,
    exit_code: i32,
    state: State,
    /// realtime, boottime, monotonic, as `triple_timestamp` (0 = unset).
    timestamp: Option<(u64, u64, u64)>,
    blocked: Vec<i32>,
}

impl<T> Drop for Event<T> {
    fn drop(&mut self) {
        for s in self.sources.iter().flatten() {
            if let Kind::Child { pidfd, .. } = s.kind {
                sys::close(pidfd);
            }
        }
        for d in &self.signals {
            sys::close(d.fd);
        }
        sys::close(self.epoll_fd);
    }
}

impl<T> Event<T> {
    /// `sd_event_new()`.
    pub fn new() -> Result<Event<T>, i32> {
        Ok(Event {
            epoll_fd: sys::epoll_create()?,
            sources: Vec::new(),
            free: Vec::new(),
            signals: Vec::new(),
            iteration: 0,
            seq: 0,
            exit_requested: false,
            exit_code: 0,
            state: State::Initial,
            timestamp: None,
            blocked: Vec::new(),
        })
    }

    fn get(&self, id: Id) -> Option<&Source<T>> {
        self.sources.get(id.index as usize)?.as_ref().filter(|s| s.generation == id.generation)
    }

    fn get_mut(&mut self, id: Id) -> Option<&mut Source<T>> {
        self.sources.get_mut(id.index as usize)?.as_mut().filter(|s| s.generation == id.generation)
    }

    fn insert(&mut self, kind: Kind, handler: Option<Handler<T>>, enabled: Enabled) -> Id {
        let index = match self.free.pop() {
            Some(i) => i,
            None => {
                self.sources.push(None);
                (self.sources.len() - 1) as u32
            }
        };
        let generation = self.iteration as u32 ^ (self.seq as u32).wrapping_mul(2654435761);
        self.seq += 1;
        self.sources[index as usize] = Some(Source {
            generation,
            kind,
            priority: SD_EVENT_PRIORITY_NORMAL,
            enabled,
            pending: false,
            pending_iteration: 0,
            pending_seq: 0,
            description: None,
            exit_on_failure: false,
            handler,
            prepare: None,
        });
        Id { index, generation }
    }

    fn set_pending(&mut self, id: Id, b: bool) {
        let iteration = self.iteration;
        self.seq += 1;
        let seq = self.seq;
        let Some(s) = self.get_mut(id) else { return };
        if s.pending == b {
            return;
        }
        s.pending = b;
        if b {
            s.pending_iteration = iteration;
            s.pending_seq = seq;
        } else if let Kind::Signal { .. } = s.kind {
            let prio = s.priority;
            if let Some(d) = self.signals.iter_mut().find(|d| d.priority == prio)
                && d.current == Some(id)
            {
                d.current = None;
            }
        }
    }

    fn online(s: &Source<T>) -> bool {
        s.enabled != Enabled::Off
    }

    /// Registers or unregisters the fd of an io or child source with
    /// epoll, following its enabled state.
    fn sync_epoll(&mut self, id: Id) -> Result<(), i32> {
        let epoll_fd = self.epoll_fd;
        let Some(s) = self.get_mut(id) else { return Ok(()) };
        let want = s.enabled != Enabled::Off;
        let data = TAG_SOURCE | id.index as u64;
        match &mut s.kind {
            Kind::Io { fd, events, registered, .. } => {
                if want && !*registered {
                    sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, *fd, *events, data)?;
                    *registered = true;
                } else if want {
                    sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_MOD, *fd, *events, data)?;
                } else if *registered {
                    let _ = sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, *fd, 0, 0);
                    *registered = false;
                }
            }
            Kind::Child { pidfd, registered, exited, .. } => {
                let want = want && !*exited;
                if want && !*registered {
                    sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, *pidfd, libc::EPOLLIN as u32, data)?;
                    *registered = true;
                } else if !want && *registered {
                    let _ = sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, *pidfd, 0, 0);
                    *registered = false;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Rebuilds the per-priority signalfds from the signal sources.
    fn sync_signals(&mut self) -> Result<(), i32> {
        let mut want: Vec<(i64, Vec<i32>)> = Vec::new();
        for s in self.sources.iter().flatten() {
            if let Kind::Signal { sig, .. } = s.kind {
                match want.iter_mut().find(|(p, _)| *p == s.priority) {
                    Some((_, v)) => v.push(sig),
                    None => want.push((s.priority, vec![sig])),
                }
            }
        }
        let epoll_fd = self.epoll_fd;
        // Drop the signalfds of priorities without signal sources.
        self.signals.retain(|d| {
            if want.iter().any(|(p, _)| *p == d.priority) {
                true
            } else {
                let _ = sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, d.fd, 0, 0);
                sys::close(d.fd);
                false
            }
        });
        for (prio, mut sigs) in want {
            sigs.sort_unstable();
            sigs.dedup();
            match self.signals.iter().position(|d| d.priority == prio) {
                Some(i) => {
                    if self.signals[i].sigs != sigs {
                        sys::signalfd(self.signals[i].fd, &sigs)?;
                        self.signals[i].sigs = sigs;
                    }
                }
                None => {
                    let fd = sys::signalfd(-1, &sigs)?;
                    let i = self.signals.len();
                    if let Err(r) =
                        sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, TAG_SIGNAL | i as u64)
                    {
                        sys::close(fd);
                        return Err(r);
                    }
                    self.signals.push(SignalData { priority: prio, fd, sigs, current: None });
                }
            }
        }
        // Positions may have moved: re-point the epoll data.
        for (i, d) in self.signals.iter().enumerate() {
            sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_MOD, d.fd, libc::EPOLLIN as u32, TAG_SIGNAL | i as u64)?;
        }
        Ok(())
    }

    /// `sd_event_add_io(e, &s, fd, events, callback, userdata)`.
    pub fn add_io(&mut self, fd: Fd, events: u32, handler: Handler<T>) -> Result<Id, i32> {
        let id = self.insert(Kind::Io { fd, events, revents: 0, registered: false }, Some(handler), Enabled::On);
        if let Err(r) = self.sync_epoll(id) {
            self.remove(id);
            return Err(r);
        }
        Ok(id)
    }

    /// `sd_event_add_time(e, &s, clock, usec, accuracy, callback, userdata)`.
    pub fn add_time(&mut self, clock: libc::clockid_t, usec: u64, handler: Handler<T>) -> Result<Id, i32> {
        Ok(self.insert(Kind::Time { clock, next: usec }, Some(handler), Enabled::Oneshot))
    }

    /// `sd_event_add_time_relative()`.
    pub fn add_time_relative(&mut self, clock: libc::clockid_t, usec: u64, handler: Handler<T>) -> Result<Id, i32> {
        let now = self.now(clock);
        self.add_time(clock, now.saturating_add(usec), handler)
    }

    /// `sd_event_add_signal(e, &s, sig | SD_EVENT_SIGNAL_PROCMASK, callback, userdata)`:
    /// a None handler exits the loop with code 0.
    pub fn add_signal(&mut self, sig: i32, handler: Option<Handler<T>>) -> Result<Id, i32> {
        if self.sources.iter().flatten().any(|s| matches!(s.kind, Kind::Signal { sig: x, .. } if x == sig)) {
            return Err(-libc::EBUSY);
        }
        if !self.blocked.contains(&sig) {
            sys::block_signals(&[sig])?;
            self.blocked.push(sig);
        }
        let id = self.insert(Kind::Signal { sig, info: SignalInfo::default() }, handler, Enabled::On);
        if let Err(r) = self.sync_signals() {
            self.remove(id);
            return Err(r);
        }
        Ok(id)
    }

    /// `sd_event_add_child_pidfd(e, &s, pidfd, options, callback, userdata)`:
    /// takes the pidfd.
    pub fn add_child_pidfd(&mut self, pidfd: Fd, options: i32, handler: Handler<T>) -> Result<Id, i32> {
        let kind = Kind::Child { pidfd, options, info: ChildInfo::default(), exited: false, registered: false };
        let id = self.insert(kind, Some(handler), Enabled::Oneshot);
        if let Err(r) = self.sync_epoll(id) {
            self.remove(id);
            return Err(r);
        }
        Ok(id)
    }

    /// `sd_event_add_child(e, &s, pid, options, callback, userdata)`.
    pub fn add_child(&mut self, pid: i32, options: i32, handler: Handler<T>) -> Result<Id, i32> {
        let pidfd = sys::pidfd_open(pid)?;
        self.add_child_pidfd(pidfd, options, handler)
    }

    /// `sd_event_add_defer()`.
    pub fn add_defer(&mut self, handler: Handler<T>) -> Result<Id, i32> {
        let id = self.insert(Kind::Defer, Some(handler), Enabled::Oneshot);
        self.set_pending(id, true);
        Ok(id)
    }

    /// `sd_event_add_post()`.
    pub fn add_post(&mut self, handler: Handler<T>) -> Result<Id, i32> {
        Ok(self.insert(Kind::Post, Some(handler), Enabled::On))
    }

    /// `sd_event_add_exit()`.
    pub fn add_exit(&mut self, handler: Handler<T>) -> Result<Id, i32> {
        Ok(self.insert(Kind::Exit, Some(handler), Enabled::Oneshot))
    }

    /// `sd_event_source_unref()` of the last reference (or `disable_unref`).
    pub fn remove(&mut self, id: Id) {
        let Some(s) = self.get(id) else { return };
        let kind = s.kind;
        match kind {
            Kind::Io { fd, registered: true, .. } => {
                let _ = sys::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, fd, 0, 0);
            }
            Kind::Child { pidfd, registered, .. } => {
                if registered {
                    let _ = sys::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, pidfd, 0, 0);
                }
                sys::close(pidfd);
            }
            _ => {}
        }
        if let Kind::Signal { .. } = kind {
            self.set_pending(id, false);
        }
        self.sources[id.index as usize] = None;
        self.free.push(id.index);
        if let Kind::Signal { .. } = kind {
            let _ = self.sync_signals();
        }
    }

    /// Whether `id` still names a source.
    pub fn exists(&self, id: Id) -> bool {
        self.get(id).is_some()
    }

    /// `sd_event_source_set_enabled()`.
    pub fn set_enabled(&mut self, id: Id, enabled: Enabled) -> Result<(), i32> {
        let Some(s) = self.get_mut(id) else { return Err(-libc::ENOENT) };
        if s.enabled == enabled {
            return Ok(());
        }
        s.enabled = enabled;
        if enabled != Enabled::Off
            && let Kind::Defer = s.kind
        {
            self.set_pending(id, true);
        }
        self.sync_epoll(id)
    }

    /// `sd_event_source_get_enabled()`.
    pub fn get_enabled(&self, id: Id) -> Option<Enabled> {
        self.get(id).map(|s| s.enabled)
    }

    /// `sd_event_source_set_priority()`.
    pub fn set_priority(&mut self, id: Id, priority: i64) -> Result<(), i32> {
        let Some(s) = self.get_mut(id) else { return Err(-libc::ENOENT) };
        if s.priority == priority {
            return Ok(());
        }
        let was_pending_signal = matches!(s.kind, Kind::Signal { .. }) && s.pending;
        s.priority = priority;
        if let Kind::Signal { .. } = s.kind {
            if was_pending_signal {
                self.set_pending(id, false);
            }
            self.sync_signals()?;
        }
        Ok(())
    }

    /// `sd_event_source_set_prepare()`: run before each poll while enabled
    /// (called with `Fired::Defer`).
    pub fn set_prepare(&mut self, id: Id, prepare: Handler<T>) {
        if let Some(s) = self.get_mut(id) {
            s.prepare = Some(prepare);
        }
    }

    /// `event_prepare()`: the prepare callbacks of the enabled sources, by priority.
    fn run_prepare(&mut self, state: &mut T) {
        let mut ids: Vec<(i64, Id)> = self
            .sources
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                Some(s) if s.prepare.is_some() && Self::online(s) => {
                    Some((s.priority, Id { index: i as u32, generation: s.generation }))
                }
                _ => None,
            })
            .collect();
        ids.sort_by_key(|(p, _)| *p);
        for (_, id) in ids {
            let Some(mut h) = self.get_mut(id).and_then(|s| s.prepare.take()) else { continue };
            let r = h(state, self, id, Fired::Defer);
            if let Some(s) = self.get_mut(id) {
                if s.prepare.is_none() {
                    s.prepare = Some(h);
                }
                if r < 0 {
                    s.enabled = Enabled::Off;
                    let _ = self.sync_epoll(id);
                }
            }
        }
    }

    /// `sd_event_source_set_description()`.
    pub fn set_description(&mut self, id: Id, d: &[u8]) {
        if let Some(s) = self.get_mut(id) {
            s.description = Some(d.to_vec());
        }
    }

    /// `sd_event_source_get_description()`.
    pub fn get_description(&self, id: Id) -> Option<&[u8]> {
        self.get(id)?.description.as_deref()
    }

    /// `sd_event_source_set_exit_on_failure()`.
    pub fn set_exit_on_failure(&mut self, id: Id, b: bool) {
        if let Some(s) = self.get_mut(id) {
            s.exit_on_failure = b;
        }
    }

    /// `sd_event_source_set_time()`: also re-arms a fired one-shot timer
    /// only when enabled again.
    pub fn set_time(&mut self, id: Id, usec: u64) -> Result<(), i32> {
        let Some(s) = self.get_mut(id) else { return Err(-libc::ENOENT) };
        if let Kind::Time { next, .. } = &mut s.kind {
            *next = usec;
        }
        self.set_pending(id, false);
        Ok(())
    }

    /// `sd_event_source_set_time_relative()`.
    pub fn set_time_relative(&mut self, id: Id, usec: u64) -> Result<(), i32> {
        let clock = match self.get(id).map(|s| s.kind) {
            Some(Kind::Time { clock, .. }) => clock,
            _ => return Err(-libc::EDOM),
        };
        let now = self.now(clock);
        self.set_time(id, now.saturating_add(usec))
    }

    /// `sd_event_source_get_time()`.
    pub fn get_time(&self, id: Id) -> Option<u64> {
        match self.get(id)?.kind {
            Kind::Time { next, .. } => Some(next),
            _ => None,
        }
    }

    /// `sd_event_source_set_io_events()`.
    pub fn set_io_events(&mut self, id: Id, ev: u32) -> Result<(), i32> {
        let Some(s) = self.get_mut(id) else { return Err(-libc::ENOENT) };
        if let Kind::Io { events, .. } = &mut s.kind {
            if *events == ev {
                return Ok(());
            }
            *events = ev;
        }
        self.set_pending(id, false);
        self.sync_epoll(id)
    }

    /// `sd_event_source_get_io_fd()`.
    pub fn get_io_fd(&self, id: Id) -> Option<Fd> {
        match self.get(id)?.kind {
            Kind::Io { fd, .. } => Some(fd),
            _ => None,
        }
    }

    /// `sd_event_source_get_child_pidfd()`.
    pub fn get_child_pidfd(&self, id: Id) -> Option<Fd> {
        match self.get(id)?.kind {
            Kind::Child { pidfd, .. } => Some(pidfd),
            _ => None,
        }
    }

    /// `sd_event_source_send_child_signal(s, sig, NULL, 0)`.
    pub fn send_child_signal(&self, id: Id, sig: i32) -> Result<(), i32> {
        match self.get(id).map(|s| s.kind) {
            Some(Kind::Child { pidfd, exited: false, .. }) => sys::pidfd_send_signal(pidfd, sig),
            Some(Kind::Child { .. }) => Err(-libc::ESRCH),
            _ => Err(-libc::EDOM),
        }
    }

    /// `sd_event_exit(e, code)`.
    pub fn exit(&mut self, code: i32) {
        self.exit_requested = true;
        self.exit_code = code;
    }

    /// `sd_event_get_exit_code()`.
    pub fn exit_code(&self) -> Option<i32> {
        if self.exit_requested { Some(self.exit_code) } else { None }
    }

    pub fn is_finished(&self) -> bool {
        self.state == State::Finished
    }

    /// `sd_event_now(e, clock, &usec)`.
    pub fn now(&self, clock: libc::clockid_t) -> u64 {
        match (self.timestamp, clock) {
            (None, _) => sys::clock_usec(clock),
            (Some((r, _, _)), libc::CLOCK_REALTIME) => r,
            (Some((_, b, _)), libc::CLOCK_BOOTTIME) => b,
            (Some((_, _, m)), _) => m,
        }
    }

    /// The pending source to dispatch next (`event_next_pending()`).
    fn next_pending(&self) -> Option<Id> {
        let mut best: Option<(bool, i64, u64, u64, Id)> = None;
        for (i, s) in self.sources.iter().enumerate() {
            let Some(s) = s else { continue };
            if !s.pending {
                continue;
            }
            let key = (!Self::online(s), s.priority, s.pending_iteration, s.pending_seq);
            if best.is_none_or(|b| key < (b.0, b.1, b.2, b.3)) {
                best = Some((key.0, key.1, key.2, key.3, Id { index: i as u32, generation: s.generation }));
            }
        }
        match best {
            Some((false, _, _, _, id)) => Some(id),
            _ => None,
        }
    }

    /// The epoll timeout until the earliest enabled, not pending timer.
    fn timer_timeout(&self) -> u64 {
        let mut timeout = u64::MAX;
        for s in self.sources.iter().flatten() {
            if let Kind::Time { clock, next } = s.kind
                && Self::online(s)
                && !s.pending
            {
                let now = sys::clock_usec(clock);
                timeout = timeout.min(next.saturating_sub(now));
            }
        }
        timeout
    }

    /// `process_signal()`.
    fn process_signal(&mut self, i: usize) -> Result<(), i32> {
        if self.signals[i].current.is_some() {
            return Ok(());
        }
        loop {
            let Some(si) = sys::read_signalfd(self.signals[i].fd)? else { return Ok(()) };
            let found = self.sources.iter().enumerate().find_map(|(idx, s)| match s {
                Some(s) if matches!(s.kind, Kind::Signal { sig, .. } if sig as u32 == si.signo) => {
                    Some((Id { index: idx as u32, generation: s.generation }, s.pending))
                }
                _ => None,
            });
            let Some((id, pending)) = found else { continue };
            if pending {
                continue;
            }
            if let Some(s) = self.get_mut(id)
                && let Kind::Signal { info, .. } = &mut s.kind
            {
                *info = si;
            }
            self.set_pending(id, true);
            self.signals[i].current = Some(id);
            return Ok(());
        }
    }

    /// `process_pidfd()`.
    fn process_pidfd(&mut self, id: Id) -> Result<(), i32> {
        let Some(s) = self.get(id) else { return Ok(()) };
        if s.pending || !Self::online(s) {
            return Ok(());
        }
        let Kind::Child { pidfd, options, exited: false, .. } = s.kind else { return Ok(()) };
        let ci = sys::waitid_pidfd(pidfd, libc::WNOHANG | libc::WNOWAIT | options)?;
        if ci.pid == 0 {
            return Ok(());
        }
        let dead = matches!(ci.code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED);
        if let Some(s) = self.get_mut(id)
            && let Kind::Child { info, exited, .. } = &mut s.kind
        {
            *info = ci;
            *exited = dead;
        }
        if dead {
            // No more POLLIN interest once exited.
            let epoll_fd = self.epoll_fd;
            if let Some(s) = self.get_mut(id)
                && let Kind::Child { pidfd, registered, .. } = &mut s.kind
                && *registered
            {
                let _ = sys::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, *pidfd, 0, 0);
                *registered = false;
            }
        }
        self.set_pending(id, true);
        Ok(())
    }

    /// `sd_event_prepare()` + `sd_event_wait()`: true if something is pending.
    fn wait(&mut self, state: &mut T, timeout: u64) -> Result<bool, i32> {
        if self.exit_requested {
            return Ok(true);
        }
        self.iteration += 1;
        self.run_prepare(state);
        if self.exit_requested {
            return Ok(true);
        }
        let timeout = if self.next_pending().is_some() { 0 } else { timeout.min(self.timer_timeout()) };
        let n = self.sources.len() + self.signals.len();
        let events = match sys::epoll_wait(self.epoll_fd, n.max(1), timeout) {
            Err(r) if r == -libc::EINTR => return Ok(true),
            Err(r) => return Err(r),
            Ok(e) => e,
        };
        self.timestamp = Some((
            sys::clock_usec(libc::CLOCK_REALTIME),
            sys::clock_usec(libc::CLOCK_BOOTTIME),
            sys::clock_usec(libc::CLOCK_MONOTONIC),
        ));
        for (ev, data) in events {
            match data & TAG_MASK {
                TAG_SIGNAL => self.process_signal((data & !TAG_MASK) as usize)?,
                _ => {
                    let index = (data & !TAG_MASK) as usize;
                    let Some(Some(s)) = self.sources.get(index) else { continue };
                    let id = Id { index: index as u32, generation: s.generation };
                    match s.kind {
                        Kind::Io { .. } => {
                            let pending = s.pending;
                            if let Some(s) = self.get_mut(id)
                                && let Kind::Io { revents, .. } = &mut s.kind
                            {
                                *revents = if pending { *revents | ev } else { ev };
                            }
                            self.set_pending(id, true);
                        }
                        Kind::Child { .. } => self.process_pidfd(id)?,
                        _ => {}
                    }
                }
            }
        }
        // process_timer(), for each clock.
        let (rt, bt, mt) = self.timestamp.unwrap_or_default();
        let mut due: Vec<(u64, Id)> = Vec::new();
        for (i, s) in self.sources.iter().enumerate() {
            let Some(s) = s else { continue };
            if let Kind::Time { clock, next } = s.kind {
                let now = match clock {
                    libc::CLOCK_REALTIME => rt,
                    libc::CLOCK_BOOTTIME => bt,
                    _ => mt,
                };
                if next <= now && Self::online(s) && !s.pending {
                    due.push((next, Id { index: i as u32, generation: s.generation }));
                }
            }
        }
        due.sort_by_key(|(t, _)| *t);
        for (_, id) in due {
            self.set_pending(id, true);
        }
        Ok(self.next_pending().is_some())
    }

    fn mark_post_sources_pending(&mut self) {
        let ids: Vec<Id> = self
            .sources
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                Some(s) if s.kind == Kind::Post && Self::online(s) => {
                    Some(Id { index: i as u32, generation: s.generation })
                }
                _ => None,
            })
            .collect();
        for id in ids {
            self.set_pending(id, true);
        }
    }

    /// `source_dispatch()`.
    fn dispatch(&mut self, state: &mut T, id: Id) -> Result<(), i32> {
        let iteration = self.iteration;
        self.seq += 1;
        let seq = self.seq;
        let Some(s) = self.get_mut(id) else { return Ok(()) };
        let kind = s.kind;
        if matches!(kind, Kind::Defer | Kind::Exit) {
            s.pending_iteration = iteration;
            s.pending_seq = seq;
        } else {
            self.set_pending(id, false);
        }
        if kind != Kind::Post {
            self.mark_post_sources_pending();
        }
        let s = self.get_mut(id).expect("source exists");
        if s.enabled == Enabled::Oneshot {
            s.enabled = Enabled::Off;
            if matches!(kind, Kind::Io { .. } | Kind::Child { .. }) {
                self.sync_epoll(id)?;
            }
        }
        let s = self.get_mut(id).expect("source exists");
        let fired = match s.kind {
            Kind::Io { fd, revents, .. } => Fired::Io { fd, revents },
            Kind::Time { next, .. } => Fired::Time(next),
            Kind::Signal { info, .. } => Fired::Signal(info),
            Kind::Child { info, .. } => Fired::Child(info),
            Kind::Defer => Fired::Defer,
            Kind::Post => Fired::Post,
            Kind::Exit => Fired::Exit,
        };
        let handler = s.handler.take();
        let r = match handler {
            Some(mut h) => {
                let r = h(state, self, id, fired);
                if let Some(s) = self.get_mut(id)
                    && s.handler.is_none()
                {
                    s.handler = Some(h);
                }
                r
            }
            // signal_exit_callback()
            None => {
                self.exit(0);
                0
            }
        };
        // Reap the child for good, so the callback still saw the zombie.
        if let Fired::Child(ci) = fired
            && matches!(ci.code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
            && let Some(Kind::Child { pidfd, options, .. }) = self.get(id).map(|s| s.kind)
        {
            let _ = sys::waitid_pidfd(pidfd, libc::WNOHANG | libc::WEXITED | (options & libc::WNOWAIT));
        }
        if r < 0 {
            let (desc, exit_on_failure) = match self.get(id) {
                Some(s) => (s.description.clone(), s.exit_on_failure),
                None => (None, false),
            };
            crate::log_debug_errno!(
                r,
                "Event source ",
                desc.as_deref().unwrap_or(b"n/a"),
                " (type ",
                kind.type_name(),
                ") returned error, ",
                if exit_on_failure { "exiting" } else { "disabling" },
                ": ",
                strerror(r)
            );
            if exit_on_failure {
                self.exit(r);
            }
            if self.exists(id) {
                let _ = self.set_enabled(id, Enabled::Off);
            }
        }
        if kind != Kind::Post {
            self.mark_post_sources_pending();
        }
        Ok(())
    }

    /// `dispatch_exit()`.
    fn dispatch_exit(&mut self, state: &mut T) -> Result<(), i32> {
        let mut best: Option<(i64, u64, Id)> = None;
        for (i, s) in self.sources.iter().enumerate() {
            let Some(s) = s else { continue };
            if s.kind == Kind::Exit && Self::online(s) {
                let key = (s.priority, s.pending_seq);
                if best.is_none_or(|b| key < (b.0, b.1)) {
                    best = Some((key.0, key.1, Id { index: i as u32, generation: s.generation }));
                }
            }
        }
        let Some((_, _, id)) = best else {
            self.state = State::Finished;
            return Ok(());
        };
        self.iteration += 1;
        self.dispatch(state, id)
    }

    /// `sd_event_run(e, timeout)`.
    pub fn run(&mut self, state: &mut T, timeout: u64) -> Result<bool, i32> {
        if self.state == State::Finished {
            return Err(-libc::ESTALE);
        }
        if !self.wait(state, timeout)? {
            return Ok(false);
        }
        if self.exit_requested {
            self.dispatch_exit(state)?;
            return Ok(true);
        }
        if let Some(id) = self.next_pending() {
            self.dispatch(state, id)?;
        }
        Ok(true)
    }

    /// `sd_event_loop(e)`: the exit code.
    pub fn run_loop(&mut self, state: &mut T) -> Result<i32, i32> {
        while self.state != State::Finished {
            self.run(state, u64::MAX)?;
        }
        Ok(self.exit_code)
    }
}

impl<T> std::fmt::Debug for Event<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event").field("iteration", &self.iteration).finish_non_exhaustive()
    }
}
