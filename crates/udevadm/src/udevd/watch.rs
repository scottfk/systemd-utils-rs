// SPDX-License-Identifier: GPL-2.0-or-later
//! The manager half of `udev-watch.c`: inotify watches on device nodes,
//! recorded as symlink pairs in /run/udev/watch/ (ID → wd, wd → ID).

use shared::blockdev::{
    REREADPT_BSD_LOCK, REREADPT_FORCE_UEVENT, block_device_is_whole_disk, device_sysname_startswith,
    reread_partition_table, sd_device_trigger_with_uuid,
};
use shared::errno::{strerror, synthetic};
use shared::event::Fired;
use shared::sd_device::{Action, Dev, Device, errno_is_neg_device_absent};
use shared::sys::{self, OwnedFd};
use shared::{
    log_debug, log_debug_errno, log_device_debug, log_device_debug_errno, log_error_errno, log_full_errno, log_warning,
    log_warning_errno,
};

use super::{EVENT_PRIORITY_INOTIFY_WATCH, Ev, Manager, event_reset_time_relative};
use crate::udev::util::device_for_action;

const WATCH_DIR: &[u8] = b"/run/udev/watch";

fn readlinkat(dirfd: i32, p: &[u8]) -> Result<Vec<u8>, i32> {
    sys::readlinkat(dirfd, p)
}

/// `device_new_from_watch_handle_at(&dev, -EBADF, wd)`.
fn device_new_from_watch_handle(wd: i32) -> Result<Dev, i32> {
    if wd < 0 {
        return Err(-libc::EBADF);
    }
    let id = sys::readlink(format!("/run/udev/watch/{wd}").as_bytes())?;
    Device::new_from_device_id(&id)
}

/// `udev_watch_dump()`.
pub fn udev_watch_dump() {
    let mut dir = match shared::sys_net::opendir(b"/run/udev/watch/") {
        Ok(d) => d,
        Err(r) => {
            log_full_errno!(
                if r == -libc::ENOENT { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                r,
                "Failed to open old watches directory '/run/udev/watch/': ",
                strerror(r)
            );
            return;
        }
    };
    let dfd = dir.fd();
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut verified: Vec<Vec<u8>> = Vec::new();
    while let Ok(Some((name, _))) = shared::conf_files::foreach_dirent(&mut dir) {
        if shared::parse::safe_atoi(&name).is_ok() {
            if !verified.contains(&name) && !pending.contains(&name) {
                pending.push(name);
            }
            continue;
        }
        let wd = match readlinkat(dfd, &name) {
            Ok(w) => w,
            Err(r) => {
                log_warning_errno!(
                    r,
                    "Found broken inotify watch, failed to read symlink ",
                    &name[..],
                    ", ignoring: ",
                    strerror(r)
                );
                continue;
            }
        };
        let devnode =
            Device::new_from_device_id(&name).ok().and_then(|d| d.get_devname().ok().map(|n| n.bytes().to_vec()));
        let dn: &[u8] = devnode.as_deref().unwrap_or(b"n/a");
        let id = match readlinkat(dfd, &wd) {
            Ok(i) => i,
            Err(r) => {
                log_warning_errno!(
                    r,
                    "Found broken inotify watch ",
                    &wd[..],
                    " on ",
                    dn,
                    " (",
                    &name[..],
                    "), failed to read symlink ",
                    &wd[..],
                    ", ignoring: ",
                    strerror(r)
                );
                continue;
            }
        };
        if name != id {
            log_warning!(
                "Found broken inotify watch ",
                &wd[..],
                " on ",
                dn,
                " (",
                &name[..],
                "), broken symlink chain: ",
                &name[..],
                " → ",
                &wd[..],
                " → ",
                &id[..]
            );
            continue;
        }
        log_debug!("Found inotify watch ", &wd[..], " on ", dn, " (", &name[..], ").");
        pending.retain(|p| *p != wd);
        if !verified.contains(&wd) {
            verified.push(wd);
        }
    }
    for w in &pending {
        let id = match readlinkat(dfd, w) {
            Ok(i) => i,
            Err(r) => {
                log_warning_errno!(
                    r,
                    "Found broken inotify watch ",
                    &w[..],
                    ", failed to read symlink ",
                    &w[..],
                    ", ignoring: ",
                    strerror(r)
                );
                continue;
            }
        };
        let devnode =
            Device::new_from_device_id(&id).ok().and_then(|d| d.get_devname().ok().map(|n| n.bytes().to_vec()));
        let wd = readlinkat(dfd, &id).ok();
        log_warning!(
            "Found broken inotify watch ",
            wd.as_deref().unwrap_or(b"(null)"),
            " on ",
            devnode.as_deref().unwrap_or(b"n/a"),
            " (",
            &id[..],
            "), broken symlink chain: ",
            &w[..],
            " → ",
            &id[..],
            " → ",
            wd.as_deref().unwrap_or(b"(null)")
        );
    }
}

/// `synthesize_change_one()`.
fn synthesize_change_one(m: &mut Manager, ev: &mut Ev, dev: &Dev) -> i32 {
    if shared::log::debug_logging() {
        log_device_debug!(dev, "device is closed, synthesising 'change' on ", dev.get_syspath().bytes());
    }
    let uuid = match sd_device_trigger_with_uuid(dev, Action::Change) {
        Ok(u) => u,
        Err(r) => return log_device_debug_errno!(dev, r, "Failed to trigger 'change' uevent: ", strerror(r)),
    };
    while m.synthesized_events.len() >= 1024 {
        let id = m.synthesized_events.remove(0);
        log_debug!(
            "Too many synthesized events are waiting, forgetting synthesized event with UUID ",
            shared::id128::to_string(&id),
            "."
        );
    }
    if !m.synthesized_events.contains(&uuid) {
        m.synthesized_events.push(uuid);
    }
    let mut slot = m.synthesized_events_clear_source;
    let r = event_reset_time_relative(
        ev,
        &mut slot,
        60 * 1_000_000,
        || {
            Box::new(|m: &mut Manager, _ev: &mut Ev, _id, _f| {
                for u in std::mem::take(&mut m.synthesized_events) {
                    log_warning!(
                        "Could not receive synthesized event with UUID ",
                        shared::id128::to_string(&u),
                        ", ignoring."
                    );
                }
                0
            })
        },
        shared::event::SD_EVENT_PRIORITY_NORMAL,
        b"synthesized-events-clear",
        true,
    );
    m.synthesized_events_clear_source = slot;
    if let Err(r) = r {
        log_debug_errno!(r, "Failed to reset timer event source for clearing synthesized event UUIDs: ", strerror(r));
    }
    0
}

/// `synthesize_change()`.
fn synthesize_change(m: &mut Manager, ev: &mut Ev, dev: &Dev) -> i32 {
    match device_sysname_startswith(dev, &[b"dm-"]) {
        Err(r) => return r,
        Ok(true) => return synthesize_change_one(m, ev, dev),
        Ok(false) => {}
    }
    match block_device_is_whole_disk(dev) {
        Err(r) => return r,
        Ok(false) => return synthesize_change_one(m, ev, dev),
        Ok(true) => {}
    }
    let flags = shared::process::FORK_RESET_SIGNALS
        | shared::process::FORK_CLOSE_ALL_FDS
        | shared::process::FORK_DEATHSIG_SIGTERM
        | shared::process::FORK_LOG
        | shared::process::FORK_REOPEN_LOG;
    let pid = match shared::process::safe_fork("(udev-synth)", flags) {
        Err(r) => return r,
        Ok(p) => p,
    };
    if pid == 0 {
        let _ = reread_partition_table(dev, REREADPT_FORCE_UEVENT | REREADPT_BSD_LOCK);
        sys::exit_now(libc::EXIT_SUCCESS);
    }
    let r = ev.add_child(
        pid,
        libc::WEXITED,
        Box::new(|m: &mut Manager, ev: &mut Ev, id, _f| {
            m.synthesize_change_children.retain(|x| *x != id);
            ev.remove(id);
            0
        }),
    );
    match r {
        Err(r) => {
            log_debug_errno!(r, "Failed to add child event source for ", pid.to_string(), ", ignoring: ", strerror(r));
        }
        Ok(id) => m.synthesize_change_children.push(id),
    }
    0
}

/// `udev_watch_clear_by_wd(dev, dirfd, wd)`.
fn udev_watch_clear_by_wd(dev: Option<&Device>, dirfd: Option<i32>, wd: i32) -> Result<(), i32> {
    let _owned;
    let dirfd = match dirfd {
        Some(d) => d,
        None => {
            match sys::open(WATCH_DIR, libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY, 0) {
                Ok(d) => {
                    _owned = OwnedFd::new(d);
                    d
                }
                Err(r) => {
                    return Err(shared::sd_device::log_device_full(
                        dev,
                        shared::log::LOG_DEBUG,
                        r,
                        shared::bcat!("Failed to open /run/udev/watch/: ", strerror(r)),
                    ));
                }
            }
        }
    };
    let log = |r: i32, msg: Vec<u8>| shared::sd_device::log_device_full(dev, shared::log::LOG_DEBUG, r, msg);
    let wd_str = wd.to_string().into_bytes();
    let mut r = (|| -> Result<(), i32> {
        let id = match readlinkat(dirfd, &wd_str) {
            Err(r) if r == -libc::ENOENT => return Err(0),
            Err(r) => {
                return Err(log(r, shared::bcat!("Failed to read '/run/udev/watch/", &wd_str[..], "': ", strerror(r))));
            }
            Ok(i) => i,
        };
        let wd_alloc = match readlinkat(dirfd, &id) {
            Err(r) => {
                return Err(log(r, shared::bcat!("Failed to read '/run/udev/watch/", &id[..], "': ", strerror(r))));
            }
            Ok(w) => w,
        };
        if wd_str != wd_alloc {
            return Err(log(
                synthetic(libc::ESTALE),
                shared::bcat!("Unmatching watch handle found: ", &wd_str[..], " -> ", &id[..], " -> ", &wd_alloc[..]),
            ));
        }
        match sys::unlinkat(dirfd, &id, 0) {
            Err(r) if r != -libc::ENOENT => {
                Err(log(r, shared::bcat!("Failed to remove '/run/udev/watch/", &id[..], "': ", strerror(r))))
            }
            _ => Ok(()),
        }
    })();
    if r == Err(0) {
        return Ok(());
    }
    match sys::unlinkat(dirfd, &wd_str, 0) {
        Err(e) if e != -libc::ENOENT => {
            let e = log(e, shared::bcat!("Failed to remove '/run/udev/watch/", &wd_str[..], "': ", strerror(e)));
            if r.is_ok() {
                r = Err(e);
            }
        }
        _ => {}
    }
    r
}

/// `udev_watch_clear(dev, dirfd, &wd)`: Ok(Some(wd)) if a watch was found.
fn udev_watch_clear(dev: &Device, dirfd: i32) -> Result<Option<i32>, i32> {
    let id = match dev.get_device_id() {
        Ok(i) => i.bytes().to_vec(),
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device ID: ", strerror(r))),
    };
    let r = (|| -> Result<Option<i32>, i32> {
        let wd_str = match readlinkat(dirfd, &id) {
            Err(r) if r == -libc::ENOENT => return Ok(None),
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to read symlink '/run/udev/watch/",
                    &id[..],
                    "': ",
                    strerror(r)
                ));
            }
            Ok(w) => w,
        };
        let wd = match shared::parse::safe_atoi(&wd_str) {
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to parse watch handle from symlink '/run/udev/watch/",
                    &id[..],
                    "': ",
                    strerror(r)
                ));
            }
            Ok(w) => w,
        };
        if wd < 0 {
            return Err(log_device_debug_errno!(
                dev,
                synthetic(libc::EBADF),
                "Invalid watch handle ",
                wd.to_string(),
                "."
            ));
        }
        let buf = match readlinkat(dirfd, &wd_str) {
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to read symlink '/run/udev/watch/",
                    &wd_str[..],
                    "': ",
                    strerror(r)
                ));
            }
            Ok(b) => b,
        };
        if buf != id {
            return Err(log_device_debug_errno!(
                dev,
                synthetic(libc::ENOENT),
                "Symlink '/run/udev/watch/",
                &wd_str[..],
                "' is owned by another device '",
                &buf[..],
                "'."
            ));
        }
        if let Err(r) = sys::unlinkat(dirfd, &wd_str, 0)
            && r != -libc::ENOENT
        {
            log_device_debug_errno!(
                dev,
                r,
                "Failed to remove '/run/udev/watch/",
                &wd_str[..],
                "', ignoring: ",
                strerror(r)
            );
        }
        Ok(Some(wd))
    })();
    if !matches!(r, Ok(None))
        && let Err(e) = sys::unlinkat(dirfd, &id, 0)
        && e != -libc::ENOENT
    {
        log_device_debug_errno!(dev, e, "Failed to remove '/run/udev/watch/", &id[..], "', ignoring: ", strerror(e));
    }
    r
}

/// `manager_add_watch()`.
pub fn manager_add_watch(m: &mut Manager, dev: &Device) -> Result<(), i32> {
    if device_for_action(dev, Action::Remove) {
        return Ok(());
    }
    let devnode = match dev.get_devname() {
        Ok(d) => d.bytes().to_vec(),
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r))),
    };
    let id = match dev.get_device_id() {
        Ok(i) => i.bytes().to_vec(),
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device ID: ", strerror(r))),
    };
    let dirfd = match shared::fs::open_mkdir(WATCH_DIR, libc::O_CLOEXEC | libc::O_RDONLY, 0o755) {
        Ok(d) => d,
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Failed to create and open '/run/udev/watch/': ", strerror(r)));
        }
    };
    let _ = udev_watch_clear(dev, dirfd.raw());
    log_device_debug!(dev, "Adding watch on '", &devnode[..], "'");
    let wd = match shared::sys_net::inotify_add_watch(m.inotify_fd, &devnode, libc::IN_CLOSE_WRITE) {
        Ok(w) => w,
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to watch device node '",
                &devnode[..],
                "': ",
                strerror(r)
            ));
        }
    };
    let _ = udev_watch_clear_by_wd(Some(dev), Some(dirfd.raw()), wd);
    let wd_str = wd.to_string().into_bytes();
    let r = sys::symlinkat(&wd_str, dirfd.raw(), &id)
        .map_err(|r| {
            log_device_debug_errno!(
                dev,
                r,
                "Failed to create symlink '/run/udev/watch/",
                &id[..],
                "' to '",
                &wd_str[..],
                "': ",
                strerror(r)
            )
        })
        .and_then(|_| {
            sys::symlinkat(&id, dirfd.raw(), &wd_str).map_err(|r| {
                log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to create symlink '/run/udev/watch/",
                    &wd_str[..],
                    "' to '",
                    &id[..],
                    "': ",
                    strerror(r)
                )
            })
        });
    if let Err(r) = r {
        let _ = sys::unlinkat(dirfd.raw(), &id, 0);
        let _ = sys::inotify_rm_watch(m.inotify_fd, wd);
        return Err(r);
    }
    Ok(())
}

/// `manager_remove_watch()`.
pub fn manager_remove_watch(m: &mut Manager, dev: &Device) -> Result<(), i32> {
    let dirfd = match sys::open(WATCH_DIR, libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY, 0) {
        Err(r) if r == -libc::ENOENT => return Ok(()),
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to open /run/udev/watch/: ", strerror(r))),
        Ok(d) => OwnedFd::new(d),
    };
    let Some(wd) = udev_watch_clear(dev, dirfd.raw())? else { return Ok(()) };
    log_device_debug!(dev, "Removing watch handle ", wd.to_string(), ".");
    let _ = sys::inotify_rm_watch(m.inotify_fd, wd);
    Ok(())
}

/// `manager_process_inotify()`.
fn process_inotify(m: &mut Manager, ev: &mut Ev, wd: i32, mask: u32) {
    if mask & libc::IN_IGNORED != 0 {
        log_debug!("Received inotify event about removal of watch handle ", wd.to_string(), ".");
        if let Err(r) = udev_watch_clear_by_wd(None, None, wd) {
            log_warning_errno!(
                r,
                "Failed to remove saved symlink(s) for watch handle ",
                wd.to_string(),
                ", ignoring: ",
                strerror(r)
            );
        }
        return;
    }
    if mask & libc::IN_CLOSE_WRITE == 0 {
        return;
    }
    let dev = match device_new_from_watch_handle(wd) {
        Ok(d) => d,
        Err(r) => {
            log_debug_errno!(r, "Failed to create sd_device object from watch handle, ignoring: ", strerror(r));
            return;
        }
    };
    log_device_debug!(dev, "Received inotify event of watch handle ", wd.to_string(), ".");
    m.create_queue_file();
    m.requeue_locked_events_by_device(&dev);
    let _ = synthesize_change(m, ev, &dev);
}

/// `udev_watch_restore()`.
fn udev_watch_restore(m: &mut Manager) {
    let old = b"/run/udev/watch.old/";
    let _ = shared::rm_rf::rm_rf_child(libc::AT_FDCWD, old, shared::rm_rf::REMOVE_PHYSICAL);
    match sys::renameat(libc::AT_FDCWD, b"/run/udev/watch/", libc::AT_FDCWD, old) {
        Err(r) if r == -libc::ENOENT => return,
        Err(r) => {
            log_warning_errno!(r, "Failed to move watches directory '/run/udev/watch/': ", strerror(r));
            return;
        }
        Ok(()) => {}
    }
    match shared::sys_net::opendir(old) {
        Err(r) => {
            log_warning_errno!(r, "Failed to open old watches directory '/run/udev/watch.old/': ", strerror(r));
        }
        Ok(mut dir) => {
            let dfd = dir.fd();
            while let Ok(Some((name, _))) = shared::conf_files::foreach_dirent(&mut dir) {
                if name.iter().all(u8::is_ascii_digit) {
                    continue;
                }
                match Device::new_from_device_id(&name) {
                    Err(r) => {
                        let absent = errno_is_neg_device_absent(r);
                        let wd =
                            if absent || shared::log::debug_logging() { readlinkat(dfd, &name).ok() } else { None };
                        log_full_errno!(
                            if absent { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                            r,
                            "Failed to create sd_device object from device ID '",
                            &name[..],
                            "' for watch handle '",
                            wd.as_deref().unwrap_or(b"n/a"),
                            "', ignoring: ",
                            strerror(r)
                        );
                    }
                    Ok(dev) => {
                        let _ = manager_add_watch(m, &dev);
                    }
                }
            }
        }
    }
    let _ = shared::rm_rf::rm_rf_child(libc::AT_FDCWD, old, shared::rm_rf::REMOVE_PHYSICAL);
}

/// `manager_init_inotify()`: takes `fd`.
pub fn init_inotify(m: &mut Manager, fd: Option<i32>) -> Result<(), i32> {
    if let Some(fd) = fd {
        if m.inotify_fd >= 0 {
            return Err(log_warning_errno!(
                synthetic(libc::EALREADY),
                "Received multiple inotify fd (",
                fd.to_string(),
                "), ignoring."
            ));
        }
        log_debug!("Received inotify fd (", fd.to_string(), ") from service manager.");
        m.inotify_fd = fd;
        return Ok(());
    }
    if m.inotify_fd >= 0 {
        return Ok(());
    }
    let fd = match shared::sys_net::inotify_init1(libc::IN_CLOEXEC) {
        Ok(fd) => fd,
        Err(r) => return Err(log_error_errno!(r, "Failed to create inotify descriptor: ", strerror(r))),
    };
    log_debug!("Initialized new inotify instance, restoring inotify watches of previous invocation.");
    m.inotify_fd = fd;
    udev_watch_restore(m);
    if sys::getenv("NOTIFY_SOCKET").is_some() {
        super::notify_remove_fd_warn(b"inotify");
        log_warning_errno!(
            -libc::EOPNOTSUPP,
            "Failed to push inotify fd to service manager, ignoring: ",
            strerror(-libc::EOPNOTSUPP)
        );
    } else {
        log_debug!("Pushed inotify fd to service manager.");
    }
    Ok(())
}

/// `manager_start_inotify()`.
pub fn start_inotify(m: &mut Manager, ev: &mut Ev) -> Result<(), i32> {
    init_inotify(m, None)?;
    udev_watch_dump();
    let id = ev
        .add_io(
            m.inotify_fd,
            libc::EPOLLIN as u32,
            Box::new(|m: &mut Manager, ev: &mut Ev, _id, f| {
                let Fired::Io { fd, .. } = f else { return 0 };
                let mut buf = vec![0u8; 64 * 1024];
                let n = match sys::read(fd, &mut buf) {
                    Ok(n) => n,
                    Err(r) if r == -libc::EAGAIN || r == -libc::EINTR => return 0,
                    Err(r) => return log_error_errno!(r, "Failed to read inotify fd: ", strerror(r)),
                };
                let mut p = 0;
                while p + 16 <= n {
                    let wd = i32::from_ne_bytes(buf[p..p + 4].try_into().expect("4 bytes"));
                    let mask = u32::from_ne_bytes(buf[p + 4..p + 8].try_into().expect("4 bytes"));
                    let len = u32::from_ne_bytes(buf[p + 12..p + 16].try_into().expect("4 bytes")) as usize;
                    p += 16 + len;
                    process_inotify(m, ev, wd, mask);
                }
                0
            }),
        )
        .map_err(|r| log_error_errno!(r, "Failed to create inotify event source: ", strerror(r)))?;
    ev.set_priority(id, EVENT_PRIORITY_INOTIFY_WATCH)
        .map_err(|r| log_error_errno!(r, "Failed to set priority to inotify event source: ", strerror(r)))?;
    ev.set_description(id, b"manager-inotify");
    m.inotify_source = Some(id);
    Ok(())
}
