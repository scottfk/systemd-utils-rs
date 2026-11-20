// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-btrfs.c`.

use shared::errno::{strerror, synthetic};
use shared::sys::{self, OwnedFd};
use shared::{log_device_debug, log_device_debug_errno, log_device_error_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::def::EventMode;
use super::super::event::Event;

/// `BTRFS_IOC_DEVICES_READY`: `_IOR(0x94, 39, struct btrfs_ioctl_vol_args)`.
const BTRFS_IOC_DEVICES_READY: u64 = 0x9000_9427;

/// `builtin_btrfs()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if !matches!(argv.len(), 2 | 3) || argv[1] != b"ready" {
        return Err(log_device_error_errno!(dev, synthetic(libc::EINVAL), "Invalid arguments."));
    }
    let node = match dev.get_devname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get device node: ", strerror(r))),
    };
    if argv.len() == 3 && argv[2] != node {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Device node '",
            &argv[2][..],
            "' is not owned by the device, it must be '",
            &node[..],
            "'."
        ));
    }
    if node.len() >= 4088 {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Device name too long for BTRFS_IOC_DEVICES_READY call: ",
            &node[..]
        ));
    }
    if event.event_mode != EventMode::UdevWorker {
        log_device_debug!(dev, "Running in test mode, skipping execution of 'btrfs' builtin command.");
        return Ok(());
    }
    let fd = match sys::open(b"/dev/btrfs-control", libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) if shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM => {
            let _ = udev_builtin_add_property(event, b"ID_BTRFS_READY", Some(b"0"));
            return Ok(());
        }
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Failed to open /dev/btrfs-control: ", strerror(r)));
        }
    };
    // struct btrfs_ioctl_vol_args { __s64 fd; char name[4088]; }
    let mut args = [0u8; 4096];
    args[8..8 + node.len()].copy_from_slice(&node);
    let r = match sys::ioctl_ptr(fd.raw(), BTRFS_IOC_DEVICES_READY, &mut args) {
        Ok(r) => r,
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Failed to call BTRFS_IOC_DEVICES_READY: ", strerror(r)));
        }
    };
    let _ = udev_builtin_add_property(event, b"ID_BTRFS_READY", Some(if r == 0 { b"1" } else { b"0" }));
    Ok(())
}
