// SPDX-License-Identifier: LGPL-2.1-or-later
//! `test-udev-rule-runner`: a port of upstream's
//! `src/udev/test-udev-rule-runner.c`, which runs the rules on one
//! synthetic event in the destructive mode udevd uses, inside a mount
//! namespace with `./tmpfs/sys`, `./tmpfs/dev` and `./run` bound over the
//! real ones.  Only the tests use it.

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_ERR, LOG_INFO, LOG_NOTICE};
use shared::sd_device::{Device, device_action_from_string};
use shared::sys;
use shared::{log_debug, log_debug_errno, log_error_errno, log_full_errno};

use udevadm::udev::def::{EventMode, ResolveNameTiming};
use udevadm::udev::event::{Event, udev_event_execute_rules};
use udevadm::udev::spawn::udev_event_execute_run;

/// `detach_mount_namespace()`.
fn detach_mount_namespace() -> Result<(), i32> {
    if let Err(r) = sys::unshare(libc::CLONE_NEWNS) {
        return Err(log_debug_errno!(r, "Failed to acquire mount namespace: ", strerror(r)));
    }
    if let Err(r) = sys::mount(None, b"/", None, libc::MS_SLAVE | libc::MS_REC) {
        return Err(log_debug_errno!(r, "Failed to set mount propagation to MS_SLAVE for all mounts: ", strerror(r)));
    }
    if let Err(r) = sys::mount(None, b"/", None, libc::MS_SHARED | libc::MS_REC) {
        return Err(log_debug_errno!(
            r,
            "Failed to set mount propagation back to MS_SHARED for all mounts: ",
            strerror(r)
        ));
    }
    Ok(())
}

/// `mount_nofollow_verbose(level, what, where, NULL, MS_BIND, NULL)`.
fn bind_verbose(level: i32, what: &[u8], target: &[u8]) -> Result<(), i32> {
    log_debug!("Bind-mounting ", what, " on ", target, " (MS_BIND \"\")...");
    let r = sys::open(target, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0).and_then(|fd| {
        let fd = sys::OwnedFd::new(fd);
        sys::mount(Some(what), &shared::fd::proc_fd_path(fd.raw()), None, libc::MS_BIND)
    });
    if let Err(r) = r {
        return Err(log_full_errno!(
            level,
            r,
            "Failed to mount ",
            what,
            " (type n/a) on ",
            target,
            " (MS_BIND \"\"): ",
            strerror(r)
        ));
    }
    Ok(())
}

/// `fake_filesystems()`.
fn fake_filesystems() -> Result<(), i32> {
    const FAKEFSS: &[(&[u8], &[u8], bool)] = &[
        (b"tmpfs/sys", b"/sys", false),
        (b"tmpfs/dev", b"/dev", false),
        (b"run", b"/run", false),
        (b"run", b"/etc/udev/rules.d", true),
        (b"run", b"/usr/lib/udev/rules.d", true),
    ];
    if let Err(r) = detach_mount_namespace() {
        return Err(log_error_errno!(r, "Failed to detach mount namespace: ", strerror(r)));
    }
    for &(src, target, ignore) in FAKEFSS {
        let r = bind_verbose(if ignore { LOG_NOTICE } else { LOG_ERR }, src, target);
        if let Err(r) = r
            && !ignore
        {
            return Err(r);
        }
    }
    Ok(())
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    // test_setup_logging(LOG_INFO)
    shared::log::log_set_max_level(LOG_INFO);
    shared::log::log_setup();
    let argc = argv.len();
    if !(2..=4).contains(&argc) {
        return log_error_errno!(
            synthetic(libc::EINVAL),
            "This program needs between one and three arguments, ",
            (argc as i32 - 1).to_string(),
            " given"
        );
    }
    if let Err(r) = fake_filesystems() {
        return r;
    }
    if argc == 2 {
        if argv[1] != b"check" {
            return log_error_errno!(synthetic(libc::EINVAL), "Unknown argument: ", &argv[1]);
        }
        return 0;
    }
    log_debug!("version ", shared::build::GIT_VERSION);
    let action = &argv[1];
    let devpath = &argv[2];
    if let Some(d) = argv.get(3) {
        match shared::parse::safe_atou(d) {
            Ok(us) => std::thread::sleep(std::time::Duration::from_micros(us as u64)),
            Err(r) => return log_error_errno!(r, "Invalid delay '", d, "': ", strerror(r)),
        }
    }
    let rules = udevadm::udev::rules::udev_rules_load(ResolveNameTiming::Early, &[]).expect("rules load");
    let syspath = shared::bcat!("/sys", devpath);
    // device_new_from_synthetic_event()
    let a = match device_action_from_string(action) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let dev = match Device::new_from_syspath(&syspath).and_then(|d| {
        d.read_uevent_file()?;
        d.set_action(a)?;
        Ok(d)
    }) {
        Ok(d) => d,
        Err(r) => return log_debug_errno!(r, "Failed to open device '", devpath, "'"),
    };
    let mut event = Event::new(&dev, EventMode::TestRuleRunner);
    let _ = sys::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP]);
    // Do what devtmpfs usually provides us.
    if let Ok(devname) = dev.get_devname() {
        let block = match dev.in_subsystem(&[b"block"]) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let mode = 0o600 | if block { libc::S_IFBLK } else { libc::S_IFCHR };
        if action != b"remove" {
            let _ = shared::fs::mkdirat_parents(shared::fd::AT_FDCWD, devname.bytes(), 0o755);
            let devnum = dev.get_devnum().unwrap_or(0);
            if let Err(r) = sys::mknodat(shared::fd::AT_FDCWD, devname.bytes(), mode, devnum) {
                return log_error_errno!(r, "mknod() failed for '", devname.bytes(), "': ", strerror(r));
            }
        } else {
            if let Err(r) = sys::unlinkat(shared::fd::AT_FDCWD, devname.bytes(), 0) {
                return log_error_errno!(r, "unlink('", devname.bytes(), "') failed: ", strerror(r));
            }
            let _ = udevadm::udev::node::rmdir_parents(devname.bytes(), b"/dev");
        }
    }
    let _ = udev_event_execute_rules(&mut event, &rules);
    udev_event_execute_run(&mut event);
    0
}

fn main() {
    shared::main_func::main_with(run)
}
