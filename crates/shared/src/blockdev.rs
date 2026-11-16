// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `blockdev-util.c`, `reread-partition-table.c` and
//! `sd-device.c` that udevd uses on block devices.
//!
//! Known difference: there is no libblkid, so `reread_partition_table()`
//! always takes C's no-libblkid path (BLKRRPART), also for GPT disks
//! where C would add, resize and remove partitions one by one.

use crate::device_enumerator::Enumerator;
use crate::errno::strerror;
use crate::sd_device::{Action, Dev, Device, device_action_to_string};
use crate::sys::{self, OwnedFd};
use crate::{log_debug_errno, log_device_debug, log_device_debug_errno};

/// `block_device_is_whole_disk(dev)`.
pub fn block_device_is_whole_disk(dev: &Device) -> Result<bool, i32> {
    if !dev.in_subsystem(&[b"block"])? {
        return Err(-libc::ENOTBLK);
    }
    dev.is_devtype(Some(b"disk"))
}

/// `block_device_get_whole_disk(dev, &ret)`.
pub fn block_device_get_whole_disk(dev: &Dev) -> Result<Dev, i32> {
    if block_device_is_whole_disk(dev)? {
        return Ok(dev.clone());
    }
    let parent = match dev.get_parent() {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENODEV),
        Err(r) => return Err(r),
        Ok(p) => p,
    };
    if !block_device_is_whole_disk(&parent)? {
        return Err(-libc::ENXIO);
    }
    Ok(parent)
}

/// `device_sysname_startswith(dev, prefixes...)`.
pub fn device_sysname_startswith(dev: &Device, prefixes: &[&[u8]]) -> Result<bool, i32> {
    let s = dev.get_sysname()?;
    Ok(prefixes.iter().any(|p| s.bytes().starts_with(p)))
}

/// `fd_get_diskseq(fd, &ret)`.
pub fn fd_get_diskseq(fd: i32) -> Result<u64, i32> {
    // BLKGETDISKSEQ = _IOR(0x12, 128, __u64)
    const BLKGETDISKSEQ: u64 = 0x8008_1280;
    let mut v: u64 = 0;
    match sys::ioctl_ptr(fd, BLKGETDISKSEQ, &mut v) {
        Err(r) if r == -libc::ENOTTY || r == -libc::EINVAL => Err(-libc::EOPNOTSUPP),
        Err(r) => Err(r),
        Ok(_) => Ok(v),
    }
}

/// `sd_device_open(device, flags)`.
pub fn sd_device_open(dev: &Device, flags: i32) -> Result<OwnedFd, i32> {
    let devname = match dev.get_devname() {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENOEXEC),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    let devnum = match dev.get_devnum() {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENOEXEC),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    let opath = flags & libc::O_PATH != 0;
    let fd = OwnedFd::new(sys::open(
        devname.bytes(),
        if opath { flags } else { libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH },
        0,
    )?);
    let st = sys::fstat(fd.raw())?;
    if st.st_rdev != devnum {
        return Err(-libc::ENXIO);
    }
    let fmt = st.st_mode & libc::S_IFMT;
    if if dev.in_subsystem(&[b"block"])? { fmt != libc::S_IFBLK } else { fmt != libc::S_IFCHR } {
        return Err(-libc::ENXIO);
    }
    if opath {
        return Ok(fd);
    }
    let mut diskseq = 0;
    if dev.get_is_initialized()? {
        let ignore = match dev.get_property_bool(b"ID_IGNORE_DISKSEQ") {
            Err(r) if r == -libc::ENOENT => false,
            Err(r) => return Err(r),
            Ok(b) => b,
        };
        if !ignore {
            match dev.get_diskseq() {
                Err(r) if r == -libc::ENOENT => {}
                Err(r) => return Err(r),
                Ok(d) => diskseq = d,
            }
        }
    }
    let fd2 = OwnedFd::new(crate::fd::fd_reopen(fd.raw(), flags)?);
    if diskseq == 0 {
        return Ok(fd2);
    }
    if fd_get_diskseq(fd2.raw())? != diskseq {
        return Err(-libc::ENXIO);
    }
    Ok(fd2)
}

/// `sd_device_trigger_with_uuid(device, action, &uuid)`.
pub fn sd_device_trigger_with_uuid(dev: &Device, action: Action) -> Result<crate::id128::Id128, i32> {
    let u = crate::id128::randomize()?;
    let j = crate::bcat!(device_action_to_string(action), " ", crate::id128::to_uuid_string(&u));
    dev.set_sysattr_value(b"uevent", Some(&j))?;
    Ok(u)
}

/// `sd_device_trigger(device, action)`.
pub fn sd_device_trigger(dev: &Device, action: Action) -> Result<(), i32> {
    sd_device_trigger_with_uuid(dev, action).map(|_| ())
}

/// `device_get_sysattr_bool()`.
fn sysattr_bool(dev: &Device, a: &[u8]) -> Result<bool, i32> {
    dev.get_sysattr_bool(a)
}

/// `blockdev_partscan_enabled(dev)`.
pub fn blockdev_partscan_enabled(dev: &Device) -> Result<bool, i32> {
    if !dev.in_subsystem(&[b"block"])? {
        return Err(-libc::ENOTBLK);
    }
    match sysattr_bool(dev, b"partscan") {
        Err(r) if r == -libc::ENOENT => {}
        x => return x,
    }
    if dev.is_devtype(Some(b"partition"))? {
        return Ok(false);
    }
    if sysattr_bool(dev, b"loop/partscan") == Ok(false) {
        return Ok(false);
    }
    let ext_range = match dev.get_sysattr_int(b"ext_range") {
        Err(r) if r == -libc::ENOENT => return Ok(false),
        Err(r) => return Err(r),
        Ok(v) => v,
    };
    if ext_range <= 1 {
        return Ok(false);
    }
    let capability = match dev.get_sysattr_unsigned_full(b"capability", 16) {
        Err(r) if r == -libc::ENOENT => return Ok(false),
        Err(r) => return Err(r),
        Ok(v) => v,
    };
    Ok(capability & (0x0200 | 0x0004) == 0)
}

/// `partition_enumerator_new(dev, &e)`.
pub fn partition_enumerator_new(dev: &Dev) -> Result<Enumerator, i32> {
    if !block_device_is_whole_disk(dev)? {
        return Err(-libc::ENXIO);
    }
    let mut e = Enumerator::new();
    e.allow_uninitialized();
    e.add_match_parent(dev);
    let s = crate::bcat!(dev.get_sysname()?.bytes(), "*");
    e.add_match_sysname(&s, true);
    e.add_match_subsystem(b"block", true);
    e.add_match_property(b"DEVTYPE", Some(b"partition"));
    Ok(e)
}

pub const REREADPT_FORCE_UEVENT: u32 = 1 << 0;
pub const REREADPT_BSD_LOCK: u32 = 1 << 1;

/// `trigger_partitions()`.
fn trigger_partitions(dev: &Dev, blkrrpart_success: bool) -> i32 {
    let mut ret = 0;
    let mut e = match partition_enumerator_new(dev) {
        Ok(e) => e,
        Err(r) => return log_device_debug_errno!(dev, r, "Failed to initialize partition enumerator: ", strerror(r)),
    };
    let r = e.scan_devices();
    let devices: Vec<Dev> = if r < 0 { Vec::new() } else { e.get_devices().unwrap_or_default() };
    if blkrrpart_success && !devices.is_empty() {
        return 0;
    }
    if let Err(r) = sd_device_trigger(dev, Action::Change) {
        crate::errno::ret_gather(
            &mut ret,
            log_device_debug_errno!(dev, r, "Failed to trigger 'change' uevent, proceeding: ", strerror(r)),
        );
    }
    for d in &devices {
        if let Err(r) = sd_device_trigger(d, Action::Change) {
            crate::errno::ret_gather(
                &mut ret,
                log_device_debug_errno!(d, r, "Failed to trigger 'change' uevent, proceeding: ", strerror(r)),
            );
        }
    }
    ret
}

/// `fallback_ioctl()`.
fn fallback_ioctl(dev: &Dev, fd: i32, flags: u32) -> i32 {
    // BLKRRPART = _IO(0x12, 95)
    let mut r = match sys::ioctl_none(fd, 0x125f) {
        Err(r) => log_device_debug_errno!(dev, r, "Failed to reread partition table via BLKRRPART: ", strerror(r)),
        Ok(_) => {
            log_device_debug!(dev, "Successfully reread partition table via BLKRRPART.");
            0
        }
    };
    if flags & REREADPT_FORCE_UEVENT != 0 {
        let t = trigger_partitions(dev, r >= 0);
        crate::errno::ret_gather(&mut r, t);
    }
    r
}

/// `reread_partition_table_full()`.
fn reread_partition_table_full(dev: &Dev, fd: i32, flags: u32) -> i32 {
    let p = match dev.get_devname() {
        Ok(p) => p,
        Err(r) => return log_device_debug_errno!(dev, r, "Failed to get block device name: ", strerror(r)),
    };
    let _lock = if flags & REREADPT_BSD_LOCK != 0 {
        let lock = match crate::fd::fd_reopen(fd, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) {
            Ok(l) => OwnedFd::new(l),
            Err(r) => {
                return log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to open lock fd for block device '",
                    p.bytes(),
                    "': ",
                    strerror(r)
                );
            }
        };
        if let Err(e) = sys::flock(lock.raw(), libc::LOCK_EX | libc::LOCK_NB) {
            let r = log_device_debug_errno!(
                dev,
                e,
                "Failed to take BSD lock on block device '",
                p.bytes(),
                "': ",
                strerror(e)
            );
            if r == -libc::EAGAIN && flags & REREADPT_FORCE_UEVENT != 0 {
                log_device_debug!(
                    dev,
                    "Giving up rereading partition table of '",
                    p.bytes(),
                    "'. Triggering change events for the device and its partitions."
                );
                let _ = trigger_partitions(dev, false);
            }
            return r;
        }
        Some(lock)
    } else {
        None
    };
    match blockdev_partscan_enabled(dev) {
        Err(r) => {
            return log_device_debug_errno!(
                dev,
                r,
                "Failed to test if block device '",
                p.bytes(),
                "' knows partition scanning: ",
                strerror(r)
            );
        }
        Ok(false) => {
            if flags & REREADPT_FORCE_UEVENT != 0 {
                if let Err(r) = sd_device_trigger(dev, Action::Change) {
                    return log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to trigger 'change' uevent, proceeding: ",
                        strerror(r)
                    );
                }
                return 0;
            }
            return log_device_debug_errno!(
                dev,
                crate::errno::synthetic(libc::ENOTTY),
                "Block device '",
                p.bytes(),
                "' does not support partition scanning."
            );
        }
        Ok(true) => {}
    }
    log_device_debug!(dev, "We don't have libblkid, falling back to BLKRRPART on '", p.bytes(), "'.");
    fallback_ioctl(dev, fd, flags)
}

/// `reread_partition_table(dev, flags)`.
pub fn reread_partition_table(dev: &Dev, flags: u32) -> i32 {
    let fd = match sd_device_open(dev, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) {
        Ok(fd) => fd,
        Err(r) => return log_debug_errno!(r, "Failed to open block device: ", strerror(r)),
    };
    reread_partition_table_full(dev, fd.raw(), flags)
}

/// `set_oom_score_adjust(value)` (WRITE_STRING_FILE_VERIFY_ON_FAILURE).
pub fn set_oom_score_adjust(value: i32) -> Result<(), i32> {
    let t = value.to_string();
    match crate::fileio::write_string_file(b"/proc/self/oom_score_adj", t.as_bytes(), 0) {
        Ok(()) => Ok(()),
        Err(r) => match crate::fileio::read_one_line_file(b"/proc/self/oom_score_adj") {
            Ok(old) if old == t.as_bytes() => Ok(()),
            _ => Err(r),
        },
    }
}
