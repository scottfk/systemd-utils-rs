// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-worker.c`: a forked worker processing events, and the worker
//! half of `udev-watch.c`.

use shared::blockdev::{block_device_get_whole_disk, device_sysname_startswith, sd_device_open};
use shared::device_monitor::Monitor;
use shared::errno::strerror;
use shared::event::{Event, Fired};
use shared::sd_device::{Action, Dev, Device};
use shared::sys;
use shared::{
    log_debug_errno, log_device_debug, log_device_debug_errno, log_device_info, log_device_warning_errno,
    log_error_errno,
};

use super::config::UdevConfig;
use crate::udev::def::EventMode;
use crate::udev::event::{Event as UdevEvent, udev_event_execute_rules};
use crate::udev::rules::Rules;
use crate::udev::spawn::udev_event_execute_run;
use crate::udev::util::{device_for_action, log_device_uevent};

/// `UdevWorker`.
pub struct UdevWorker {
    pub monitor: Monitor,
    pub properties: Vec<(Vec<u8>, Vec<u8>)>,
    pub rules: Option<Rules>,
    pub config: UdevConfig,
    pub manager_pid: i32,
}

/// `ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY()`.
fn absent_or_empty(r: i32) -> bool {
    shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM
}

/// `udev_get_whole_disk(dev, &ret_dev, &ret_devname)`: None if irrelevant.
pub fn udev_get_whole_disk(dev: &Dev) -> Result<Option<(Dev, Vec<u8>)>, i32> {
    if device_for_action(dev, Action::Remove) {
        return Ok(None);
    }
    match device_sysname_startswith(dev, &[b"dm-", b"md", b"drbd"]) {
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to check sysname: ", strerror(r))),
        Ok(true) => return Ok(None),
        Ok(false) => {}
    }
    let whole = match block_device_get_whole_disk(dev) {
        Err(r) if r == -libc::ENOTBLK || r == -libc::ENODEV => return Ok(None),
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get whole disk device: ", strerror(r))),
        Ok(w) => w,
    };
    match whole.get_devname() {
        Err(r) => Err(log_device_debug_errno!(whole, r, "Failed to get devname: ", strerror(r))),
        Ok(n) => {
            let n = n.bytes().to_vec();
            Ok(Some((whole, n)))
        }
    }
}

/// `worker_lock_whole_disk()`: Ok(Some(fd)) when locked, Err(-EAGAIN)
/// when the event was requeued.
fn worker_lock_whole_disk(ev: &mut Event<UdevWorker>, dev: &Dev) -> Result<Option<sys::OwnedFd>, i32> {
    if device_for_action(dev, Action::Remove) {
        return Ok(None);
    }
    let Some((whole, whole_disk)) = udev_get_whole_disk(dev)? else { return Ok(None) };
    let fd = match sd_device_open(&whole, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) {
        Ok(fd) => fd,
        Err(r) => {
            let ignore = absent_or_empty(r);
            log_device_debug_errno!(
                dev,
                r,
                "Failed to open '",
                &whole_disk[..],
                "'",
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { Ok(None) } else { Err(r) };
        }
    };
    if let Err(e) = sys::flock(fd.raw(), libc::LOCK_SH | libc::LOCK_NB) {
        if e != -libc::EAGAIN {
            return Err(log_device_debug_errno!(dev, e, "Failed to flock(", &whole_disk[..], "): ", strerror(e)));
        }
        log_device_debug_errno!(dev, e, "Block device ", &whole_disk[..], " is currently locked, requeuing the event.");
        let r = shared::notify::sd_notify(&shared::bcat!("TRY_AGAIN=1\nWHOLE_DISK=", &whole_disk[..]));
        if r < 0 {
            log_device_warning_errno!(dev, r, "Failed to send notification message to manager process: ", strerror(r));
            ev.exit(r);
        }
        return Err(-libc::EAGAIN);
    }
    log_device_debug!(
        dev,
        "Successfully took flock(LOCK_SH) for ",
        &whole_disk[..],
        ", it will be released after the event has been processed."
    );
    Ok(Some(fd))
}

/// `worker_mark_block_device_read_only()`.
fn worker_mark_block_device_read_only(dev: &Dev) -> Result<(), i32> {
    if !device_for_action(dev, Action::Add) || !dev.in_subsystem(&[b"block"])? {
        return Ok(());
    }
    match device_sysname_startswith(dev, &[b"dm-", b"md", b"drbd", b"loop", b"nbd", b"zram"]) {
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to check sysname: ", strerror(r))),
        Ok(true) => return Ok(()),
        Ok(false) => {}
    }
    let node = match dev.get_devname() {
        Ok(n) => n,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r))),
    };
    let fd = match sd_device_open(dev, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) {
        Ok(fd) => fd,
        Err(r) => {
            let ignore = absent_or_empty(r);
            shared::sd_device::log_device_full(
                Some(dev),
                if ignore { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                r,
                shared::bcat!(
                    "Failed to open device node '",
                    node.bytes(),
                    "'",
                    if ignore { ", ignoring" } else { "" },
                    ": ",
                    strerror(r)
                ),
            );
            return if ignore { Ok(()) } else { Err(r) };
        }
    };
    // BLKROSET = _IO(0x12, 93)
    let mut state: libc::c_int = 1;
    if let Err(r) = sys::ioctl_ptr(fd.raw(), 0x125d, &mut state) {
        return Err(log_device_warning_errno!(
            dev,
            r,
            "Failed to mark block device '",
            node.bytes(),
            "' read-only: ",
            strerror(r)
        ));
    }
    log_device_info!(dev, "Successfully marked block device '", node.bytes(), "' read-only.");
    Ok(())
}

/// `notify_and_wait_signal()`: tells the manager, then waits for its
/// SIGUSR1; the signal's value is the manager's result.
fn notify_and_wait_signal(manager_pid: i32, dev: &Device, msg: &[u8]) -> i32 {
    if dev.get_devname().is_err() {
        return 0;
    }
    let mut e: Event<i32> = match Event::new() {
        Ok(e) => e,
        Err(r) => return r,
    };
    let r = e.add_signal(
        libc::SIGUSR1,
        Some(Box::new(move |_s: &mut i32, ev, _id, f| {
            let Fired::Signal(si) = f else { return 0 };
            if !matches!(si.code, libc::SI_USER | libc::SI_QUEUE | libc::SI_TKILL) {
                shared::log_debug!("Received SIGUSR1 with unexpected .si_code ", si.code.to_string(), ", ignoring.");
                return 0;
            }
            if si.pid as i32 != manager_pid {
                shared::log_debug!("Received SIGUSR1 from unexpected process [", si.pid.to_string(), "], ignoring.");
                return 0;
            }
            ev.exit(0);
            0
        })),
    );
    if let Err(r) = r {
        return r;
    }
    let r = shared::notify::sd_notify(msg);
    if r <= 0 {
        return r;
    }
    let mut s = 0;
    e.run_loop(&mut s).unwrap_or_else(|r| r)
}

/// `udev_watch_begin()`.
fn udev_watch_begin(w: &UdevWorker, dev: &Device) -> i32 {
    if device_for_action(dev, Action::Remove) {
        return 0;
    }
    notify_and_wait_signal(w.manager_pid, dev, b"INOTIFY_WATCH_ADD=1")
}

/// `udev_watch_end()`.
fn udev_watch_end(w: &UdevWorker, dev: &Device) -> i32 {
    notify_and_wait_signal(w.manager_pid, dev, b"INOTIFY_WATCH_REMOVE=1")
}

/// `worker_process_device()`.
fn worker_process_device(w: &mut UdevWorker, ev: &mut Event<UdevWorker>, dev: &Dev) -> Result<(), i32> {
    log_device_uevent(dev, b"Processing device");
    let _lock = match worker_lock_whole_disk(ev, dev) {
        Err(r) if r == -libc::EAGAIN => return Ok(()),
        Err(r) => return Err(r),
        Ok(l) => l,
    };
    if w.config.blockdev_read_only {
        let _ = worker_mark_block_device_read_only(dev);
    }
    let r = udev_watch_end(w, dev);
    if r < 0 {
        log_device_warning_errno!(dev, r, "Failed to remove inotify watch, ignoring: ", strerror(r));
    }
    let mut event = UdevEvent::new(dev, EventMode::UdevWorker);
    event.trace = w.config.trace;
    event.worker_properties = Some(w.properties.clone());
    event.worker_timeouts = Some((w.config.timeout_usec, w.config.timeout_signal, w.config.exec_delay_usec));
    let rules = w.rules.as_ref().expect("rules are loaded");
    udev_event_execute_rules(&mut event, rules)?;
    udev_event_execute_run(&mut event);
    if event.inotify_watch {
        let r = udev_watch_begin(w, dev);
        if r < 0 {
            log_device_warning_errno!(dev, r, "Failed to add inotify watch, ignoring: ", strerror(r));
        }
    }
    if !device_for_action(dev, Action::Remove) {
        if let Err(r) = dev.add_property(b"ID_PROCESSING", None) {
            return Err(log_device_warning_errno!(dev, r, "Failed to remove 'ID_PROCESSING' property: ", strerror(r)));
        }
        if let Err(r) = dev.update_db() {
            return Err(log_device_warning_errno!(
                dev,
                r,
                "Failed to update database under /run/udev/data/: ",
                strerror(r)
            ));
        }
    }
    log_device_uevent(dev, b"Device processed");
    if let Err(r) = w.monitor.send(None, dev) {
        log_device_warning_errno!(dev, r, "Failed to broadcast event to libudev listeners: ", strerror(r));
        ev.exit(r);
        return Ok(());
    }
    let r = shared::notify::sd_notify(b"PROCESSED=1");
    if r < 0 {
        log_device_warning_errno!(dev, r, "Failed to send notification message to manager process: ", strerror(r));
        ev.exit(r);
    }
    Ok(())
}

/// `worker_device_monitor_handler()`.
fn worker_device_monitor_handler(w: &mut UdevWorker, ev: &mut Event<UdevWorker>, dev: &Dev) -> i32 {
    if let Err(r) = worker_process_device(w, ev, dev) {
        log_device_warning_errno!(dev, r, "Failed to process device, ignoring: ", strerror(r));
        let _ = super::manager::device_add_errno(dev, r);
        if let Err(k) = w.monitor.send(None, dev) {
            log_device_warning_errno!(dev, k, "Failed to broadcast event to libudev listeners: ", strerror(k));
            ev.exit(k);
            return 0;
        }
        let msg = match sys::errno_name(-r) {
            Some(n) => shared::bcat!("ERRNO=", (-r).to_string(), "\nERRNO_NAME=", n),
            None => shared::bcat!("ERRNO=", (-r).to_string()),
        };
        let r = shared::notify::sd_notify(&msg);
        if r < 0 {
            log_device_warning_errno!(
                dev,
                r,
                "Failed to send notification message to manager process, ignoring: ",
                strerror(r)
            );
            ev.exit(r);
            return 0;
        }
    }
    shared::log::log_set_max_level(w.config.log_level);
    1
}

/// `udev_worker_main()`.
pub fn udev_worker_main(mut w: UdevWorker, dev: &Dev) -> i32 {
    if let Err(r) = shared::blockdev::set_oom_score_adjust(0) {
        log_debug_errno!(r, "Failed to reset OOM score, ignoring: ", strerror(r));
    }
    let mut ev: Event<UdevWorker> = match Event::new() {
        Ok(e) => e,
        Err(r) => return log_error_errno!(r, "Failed to allocate event loop: ", strerror(r)),
    };
    if let Err(r) = ev.add_signal(libc::SIGTERM, None) {
        return log_error_errno!(r, "Failed to set SIGTERM event: ", strerror(r));
    }
    if let Err(r) = w.monitor.filter_update() {
        return log_error_errno!(r, "Failed to start device monitor: ", strerror(r));
    }
    let r = ev.add_io(
        w.monitor.get_fd(),
        libc::EPOLLIN as u32,
        Box::new(|w: &mut UdevWorker, ev, _id, _f| match w.monitor.receive() {
            Ok(Some(dev)) => worker_device_monitor_handler(w, ev, &dev),
            _ => 0,
        }),
    );
    match r {
        Err(r) => return log_error_errno!(r, "Failed to start device monitor: ", strerror(r)),
        Ok(id) => ev.set_description(id, b"worker"),
    }
    worker_device_monitor_handler(&mut w, &mut ev, dev);
    match ev.run_loop(&mut w) {
        Err(r) | Ok(r) if r < 0 => log_error_errno!(r, "Event loop failed: ", strerror(r)),
        _ => 0,
    }
}
