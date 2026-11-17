// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `blockdev-util.c`, `reread-partition-table.c` and
//! `sd-device.c` that udevd uses on block devices.

use crate::device_enumerator::Enumerator;
use crate::errno::strerror;
use crate::sd_device::{Action, Dev, Device, device_action_to_string};
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_debug_errno, log_device_debug, log_device_debug_errno};

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
    let p = p.bytes().to_vec();
    match crate::sys_blkid::dlopen_libblkid(crate::log::LOG_DEBUG) {
        Err(r) if crate::errno::errno_is_neg_not_supported(r) => {
            log_device_debug!(dev, "We don't have libblkid, falling back to BLKRRPART on '", &p[..], "'.");
            return fallback_ioctl(dev, fd, flags);
        }
        Err(r) => return log_device_debug_errno!(dev, r, "Failed to load libblkid: ", strerror(r)),
        Ok(()) => {}
    }
    let neg = |e: i32, fallback: i32| if e > 0 { -e } else { -fallback };
    let b = match crate::sys_blkid::Probe::new() {
        Ok(b) => b,
        Err(_) => return log_debug_errno!(-libc::ENOMEM, "Out of memory."),
    };
    if let Err(e) = b.set_device_range(fd, 0, 0) {
        let r = neg(e, libc::ENOMEM);
        return log_device_debug_errno!(dev, r, "Failed to open block device '", &p[..], "': ", strerror(r));
    }
    b.enable_partitions(true);
    b.set_partitions_flags(crate::sys_blkid::BLKID_PARTS_ENTRY_DETAILS);
    let (rc, e) = b.do_safeprobe();
    match rc {
        -1 => {
            let r = neg(e, libc::EIO);
            return log_device_debug_errno!(
                dev,
                r,
                "Unable to probe for partition table of '",
                &p[..],
                "': ",
                strerror(r)
            );
        }
        -2 | 1 => {
            log_device_debug!(
                dev,
                "Didn't find partition table on block device '",
                &p[..],
                "', falling back to BLKRRPART."
            );
            return fallback_ioctl(dev, fd, flags);
        }
        _ => {}
    }
    if b.lookup_value(b"PTTYPE").as_deref() != Some(b"gpt") {
        log_device_debug!(dev, "Didn't find a GPT partition table on '", &p[..], "', falling back to BLKRRPART.");
        return fallback_ioctl(dev, fd, flags);
    }
    let pl = match b.partitions() {
        Ok(pl) => pl,
        Err(e) => {
            let r = neg(e, libc::EIO);
            return log_device_debug_errno!(dev, r, "Unable to read partition table of '", &p[..], "': ", strerror(r));
        }
    };
    sys::set_errno(0);
    let n_partitions = pl.len();
    if n_partitions < 0 {
        let r = crate::errno::errno_or_else(libc::EIO);
        return log_device_debug_errno!(
            dev,
            r,
            "Unable to acquire number of entries in partition table of '",
            &p[..],
            "': ",
            strerror(r)
        );
    }
    let mut e = match partition_enumerator_new(dev) {
        Ok(e) => e,
        Err(r) => {
            return log_device_debug_errno!(dev, r, "Failed to enumerate kernel partition devices: ", strerror(r));
        }
    };
    log_device_debug!(dev, "Updating/adding kernel partition devices...");
    let mut found = Vec::new();
    let mut changed = false;
    let mut ret = 0;
    for i in 0..n_partitions {
        sys::set_errno(0);
        let Some(pp) = pl.get(i) else {
            let r = crate::errno::errno_or_else(libc::EIO);
            return log_device_debug_errno!(
                dev,
                r,
                format!("Unable to get partition data of partition {i} of partition table of '"),
                &p[..],
                "': ",
                strerror(r)
            );
        };
        let r = process_partition(dev, fd, pp, &mut found, flags, &mut changed);
        crate::errno::ret_gather(&mut ret, r);
    }
    if ret < 0 {
        return ret;
    }
    log_device_debug!(dev, "Removing old kernel partition devices...");
    let r = remove_partitions(dev, fd, &mut e, &found, &mut changed);
    if r < 0 {
        return r;
    }
    if changed {
        return 1;
    }
    if flags & REREADPT_FORCE_UEVENT != 0
        && let Err(r) = sd_device_trigger(dev, Action::Change)
    {
        return log_device_debug_errno!(
            dev,
            r,
            "Failed to issue 'change' uevent on device '",
            &p[..],
            "': ",
            strerror(r)
        );
    }
    0
}

/// `process_partition()`.
fn process_partition(
    d: &Dev,
    fd: i32,
    pp: crate::sys_blkid::Partition,
    partnos: &mut Vec<i32>,
    flags: u32,
    changed: &mut bool,
) -> i32 {
    let node = match d.get_devname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => return log_device_debug_errno!(d, r, "Failed to acquire device node path: ", strerror(r)),
    };
    let or_eio = |e: i32| if e > 0 { -e } else { -libc::EIO };
    let (nr, e) = pp.partno();
    if nr < 0 {
        let r = or_eio(e);
        return log_debug_errno!(r, "Failed to read partition number of partition: ", strerror(r));
    }
    log_device_debug!(d, format!("Processing partition {nr}..."));
    let (start, e) = pp.start();
    if start < 0 {
        let r = or_eio(e);
        return log_debug_errno!(r, format!("Failed to read partition start offset of partition {nr}: "), strerror(r));
    }
    let (size, e) = pp.size();
    if size < 0 {
        let r = or_eio(e);
        return log_debug_errno!(r, format!("Failed to read partition size of partition {nr}: "), strerror(r));
    }
    let (start, size) = (start as u64, size as u64);
    if !partnos.contains(&nr) {
        partnos.push(nr);
    }
    let subnode = crate::dissect::partition_node_of(&node, nr);
    match Device::new_from_devname(&subnode) {
        Err(r) if r != -libc::ENODEV => {
            return log_device_debug_errno!(d, r, "Failed to acquire device '", &subnode[..], "': ", strerror(r));
        }
        Err(_) => {}
        Ok(partition) => {
            let start_kernel = match partition.get_sysattr_u64(b"start") {
                Ok(v) => v,
                Err(r) => {
                    return log_device_debug_errno!(
                        &partition,
                        r,
                        "Failed to get start of kernel partition device '",
                        &subnode[..],
                        "': ",
                        strerror(r)
                    );
                }
            };
            let size_kernel = match partition.get_sysattr_u64(b"size") {
                Ok(v) => v,
                Err(r) => {
                    return log_device_debug_errno!(
                        &partition,
                        r,
                        "Failed to get size of kernel partition device '",
                        &subnode[..],
                        "': ",
                        strerror(r)
                    );
                }
            };
            if start_kernel == start && size_kernel == size {
                log_device_debug!(
                    &partition,
                    "Kernel partition device '",
                    &subnode[..],
                    "' already matches partition table, not modifying."
                );
                if flags & REREADPT_FORCE_UEVENT != 0 {
                    if !*changed {
                        if let Err(r) = sd_device_trigger(d, Action::Change) {
                            return log_device_debug_errno!(
                                d,
                                r,
                                "Failed to issue 'change' uevent on device '",
                                &node[..],
                                "': ",
                                strerror(r)
                            );
                        }
                        log_device_debug!(d, "Successfully issued 'change' uevent on device '", &node[..], "'.");
                        *changed = true;
                    }
                    if let Err(r) = sd_device_trigger(&partition, Action::Change) {
                        return log_device_debug_errno!(
                            &partition,
                            r,
                            "Failed to issue 'change' uevent on partition '",
                            &subnode[..],
                            "': ",
                            strerror(r)
                        );
                    }
                    log_device_debug!(
                        &partition,
                        "Successfully issued 'change' uevent on partition '",
                        &subnode[..],
                        "'."
                    );
                }
                return 0;
            }
            if start_kernel == start {
                log_device_debug!(&partition, format!("Resizing partition {nr}..."));
                if let Err(r) = sys::blkpg(fd, sys::BLKPG_RESIZE_PARTITION, nr, start * 512, size * 512) {
                    return log_device_debug_errno!(
                        &partition,
                        r,
                        "Failed to resize kernel partition device '",
                        &subnode[..],
                        "' to partition table values: ",
                        strerror(r)
                    );
                }
                log_device_debug!(
                    &partition,
                    "Successfully resized kernel partition device '",
                    &subnode[..],
                    "' to match partition table."
                );
                *changed = true;
                return 1;
            }
            log_device_debug!(&partition, format!("Removing and recreating partition {nr}..."));
            drop(partition);
            if let Err(r) = sys::blkpg(fd, sys::BLKPG_DEL_PARTITION, nr, 0, 0) {
                return log_device_debug_errno!(
                    d,
                    r,
                    "Failed to remove kernel partition device '",
                    &subnode[..],
                    "' in order to recreate it: ",
                    strerror(r)
                );
            }
            log_device_debug!(
                d,
                "Successfully removed kernel partition device '",
                &subnode[..],
                "' in order to recreate it."
            );
        }
    }
    log_device_debug!(d, format!("Adding partition {nr}..."));
    if let Err(r) = sys::blkpg(fd, sys::BLKPG_ADD_PARTITION, nr, start * 512, size * 512) {
        return log_device_debug_errno!(
            d,
            r,
            format!("Failed to add kernel partition device {nr} to partition table values: "),
            strerror(r)
        );
    }
    log_device_debug!(d, format!("Successfully added kernel partition device {nr} to match partition table."));
    *changed = true;
    1
}

/// `remove_partitions()`: removes the kernel's partitions of `d` that
/// aren't in `partnos`.
fn remove_partitions(d: &Dev, fd: i32, e: &mut Enumerator, partnos: &[i32], changed: &mut bool) -> i32 {
    let mut ret = 0;
    let devices = if e.scan_devices() < 0 { Vec::new() } else { e.get_devices().unwrap_or_default() };
    for partition in &devices {
        let devname = match partition.get_devname() {
            Ok(n) => n.bytes().to_vec(),
            Err(r) => {
                return log_device_debug_errno!(partition, r, "Failed to get name of partition: ", strerror(r));
            }
        };
        let nr = match partition.get_property_uint(b"PARTN") {
            Ok(n) => n,
            Err(r) => {
                return log_device_debug_errno!(
                    partition,
                    r,
                    "Failed to read partition number property: ",
                    strerror(r)
                );
            }
        };
        if partnos.contains(&(nr as i32)) {
            log_device_debug!(
                partition,
                format!("Found kernel partition device {nr} in partition table, leaving around.")
            );
            continue;
        }
        log_device_debug!(partition, format!("Kernel knows partition {nr} which we didn't find, removing."));
        match sys::blkpg(fd, sys::BLKPG_DEL_PARTITION, nr as i32, 0, 0) {
            Err(r) => crate::errno::ret_gather(
                &mut ret,
                log_device_debug_errno!(
                    d,
                    r,
                    "Failed to remove kernel partition device '",
                    &devname[..],
                    "' that vanished from partition table: ",
                    strerror(r)
                ),
            ),
            Ok(()) => {
                log_device_debug!(d, format!("Removed partition {nr} from kernel."));
                *changed = true;
            }
        }
    }
    ret
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

fn sys_block_path(d: u64, suffix: &str) -> Vec<u8> {
    use crate::sd_device::{major, minor};
    format!("/sys/dev/block/{}:{}{suffix}", major(d), minor(d)).into_bytes()
}

/// `block_get_whole_disk(d, &ret)`: (whole disk, whether `d` was a partition).
pub fn block_get_whole_disk(d: u64) -> Result<(u64, bool), i32> {
    if crate::sd_device::major(d) == 0 {
        return Err(-libc::ENODEV);
    }
    match crate::sys_net::access(&sys_block_path(d, "/queue"), libc::F_OK) {
        Ok(()) => return Ok((d, false)),
        Err(r) if r != -libc::ENOENT => return Err(r),
        Err(_) => {}
    }
    crate::sys_net::access(&sys_block_path(d, "/partition"), libc::F_OK)?;
    let s = crate::fileio::read_one_line_file(&sys_block_path(d, "/../dev"))?;
    let devt = crate::parse::parse_devnum(&s)?;
    crate::sys_net::access(&sys_block_path(devt, "/queue"), libc::F_OK)?;
    Ok((devt, true))
}

/// `blockdev_get_sector_size(fd, &ret)`.
pub fn blockdev_get_sector_size(fd: i32) -> Result<u32, i32> {
    const BLKSSZGET: u64 = 0x1268;
    let mut ssz: libc::c_int = 0;
    sys::ioctl_ptr(fd, BLKSSZGET, &mut ssz)?;
    if ssz <= 0 {
        return Err(crate::log_debug_errno!(
            crate::errno::synthetic(libc::EIO),
            "Block device reported invalid sector size ",
            ssz.to_string(),
            "."
        ));
    }
    Ok(ssz as u32)
}

/// `block_device_get_originating_one()`.
fn block_device_get_originating_one(dev: &Dev) -> Result<Dev, i32> {
    let mut first: Option<(Dev, u64)> = None;
    let mut child = dev.get_child_first();
    while let Some((c, suffix)) = child {
        child = dev.get_child_next();
        if crate::path::path_startswith(&suffix, b"slaves").is_none() {
            continue;
        }
        let Ok(whole) = block_device_get_whole_disk(&c) else { continue };
        let Ok(n) = whole.get_devnum() else { continue };
        match &first {
            None => first = Some((c, n)),
            Some((_, devnum)) => {
                if n != *devnum {
                    return Err(-libc::ENOTUNIQ);
                }
            }
        }
    }
    first.map(|(d, _)| d).ok_or(-libc::ENOENT)
}

/// `block_device_get_originating(dev, &ret, recursive)`.
pub fn block_device_get_originating(dev: &Dev, recursive: bool) -> Result<Dev, i32> {
    if !recursive {
        return block_device_get_originating_one(dev);
    }
    let mut current = dev.clone();
    let mut moved = false;
    loop {
        match block_device_get_originating_one(&current) {
            Err(r) if r == -libc::ENOENT => break,
            Err(r) => return Err(r),
            Ok(o) => {
                current = o;
                moved = true;
            }
        }
    }
    if !moved {
        return Err(-libc::ENOENT);
    }
    Ok(current)
}

/// `block_get_originating(dt, &ret, recursive)`.
pub fn block_get_originating(dt: u64, recursive: bool) -> Result<u64, i32> {
    let dev = Device::new_from_devnum(b'b', dt)?;
    block_device_get_originating(&dev, recursive)?.get_devnum()
}

/// `btrfs_get_block_device_fd(fd, &ret)`: Ok(0) for btrfs RAID.
fn btrfs_get_block_device_fd(fd: i32) -> Result<u64, i32> {
    const BTRFS_IOC_FS_INFO: u64 = 0x8400_941f;
    const BTRFS_IOC_DEV_INFO: u64 = 0xd000_941e;
    if !crate::stat_util::is_fs_type_at(fd, None, crate::stat_util::BTRFS_SUPER_MAGIC)? {
        return Err(-libc::ENOTTY);
    }
    let mut fsi = [0u8; 1024];
    sys::ioctl_ptr(fd, BTRFS_IOC_FS_INFO, &mut fsi)?;
    let max_id = u64::from_ne_bytes(fsi[0..8].try_into().expect("8 bytes"));
    let num_devices = u64::from_ne_bytes(fsi[8..16].try_into().expect("8 bytes"));
    if num_devices != 1 {
        return Ok(0);
    }
    for id in 1..=max_id {
        let mut di = [0u8; 4096];
        di[0..8].copy_from_slice(&id.to_ne_bytes());
        match sys::ioctl_ptr(fd, BTRFS_IOC_DEV_INFO, &mut di) {
            Err(r) if r == -libc::ENODEV => continue,
            Err(r) => return Err(r),
            Ok(_) => {}
        }
        let raw = &di[3072..];
        let path = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        if crate::path::path_equal(path, b"/dev/root") {
            return Err(-libc::EUCLEAN);
        }
        let st = sys::stat(path)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFBLK {
            return Err(if st.st_mode & libc::S_IFMT == libc::S_IFDIR { -libc::EISDIR } else { -libc::ENOTBLK });
        }
        if crate::sd_device::major(st.st_rdev) == 0 {
            return Err(-libc::ENODEV);
        }
        return Ok(st.st_rdev);
    }
    Err(-libc::ENODEV)
}

/// `get_block_device_harder(path, &ret)`: 0 if not backed by a single
/// block device.
pub fn get_block_device_harder(path: &[u8]) -> Result<u64, i32> {
    let fd = OwnedFd::new(sys::open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?);
    // get_block_device_fd()
    let st = sys::fstat(fd.raw())?;
    let d = if crate::sd_device::major(st.st_dev) != 0 {
        st.st_dev
    } else {
        match btrfs_get_block_device_fd(fd.raw()) {
            Err(r) if r == -libc::ENOTTY => 0,
            r => r?,
        }
    };
    if d == 0 {
        return Ok(0);
    }
    match block_get_originating(d, true) {
        Ok(o) => Ok(o),
        Err(r) => {
            log_debug_errno!(r, "Failed to chase block device, ignoring: ", strerror(r));
            Ok(d)
        }
    }
}

/// `extension_overlay_block(p, IMAGE_SYSEXT, &ret)`.
fn extension_overlay_block(p: &[u8]) -> Result<u64, i32> {
    let j = crate::path::path_join(&[p, b".systemd-sysext"]);
    let fd = match sys::open(&j, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => return Err(log_debug_errno!(r, "Failed to open '", &j[..], "': ", strerror(r))),
    };
    match crate::stat_util::is_fs_type_at(fd.raw(), None, crate::stat_util::OVERLAYFS_SUPER_MAGIC) {
        Err(r) => {
            return Err(log_debug_errno!(
                r,
                "Failed to determine backing file system of '",
                &j[..],
                "': ",
                strerror(r)
            ));
        }
        Ok(false) => {
            return Err(log_debug_errno!(
                crate::errno::synthetic(libc::ENOTTY),
                "Backing file system of '",
                &j[..],
                "' is not an overlayfs."
            ));
        }
        Ok(true) => {}
    }
    let buf = crate::fileio::read_one_line_file(&crate::bcat!(crate::fd::proc_fd_path(fd.raw()), "/backing"))
        .map_err(|r| log_debug_errno!(r, "Failed to read contents of '", &j[..], "/backing': ", strerror(r)))?;
    let d = crate::parse::parse_devnum(&buf)
        .map_err(|r| log_debug_errno!(r, "Failed to parse contents of '", &j[..], "/backing': ", strerror(r)))?;
    if crate::sd_device::major(d) == 0 {
        return Ok(0);
    }
    Ok(block_get_originating(d, false).unwrap_or(d))
}

fn btrfs_log_dev_root(level: i32, r: i32, p: &str) -> i32 {
    crate::log_full_errno!(
        level,
        r,
        "File system behind ",
        p,
        " is reported by btrfs to be backed by pseudo-device /dev/root, which is not a valid userspace \
         accessible device node. Cannot determine correct backing block device."
    )
}

/// `blockdev_get_root(level, &ret)`: 0 if there is no single root block
/// device.
pub fn blockdev_get_root(level: i32) -> Result<u64, i32> {
    match sys::readlinkat(libc::AT_FDCWD, b"/run/systemd/volatile-root") {
        Err(r) if r == -libc::ENOENT => {}
        Err(r) => {
            return Err(crate::log_full_errno!(
                level,
                r,
                "Failed to read symlink /run/systemd/volatile-root: ",
                strerror(r)
            ));
        }
        Ok(p) => {
            let (m, devno) = crate::sd_device::device_path_parse_major_minor(&p).map_err(|r| {
                crate::log_full_errno!(level, r, "Failed to parse major/minor device node: ", strerror(r))
            })?;
            if m & libc::S_IFMT != libc::S_IFBLK {
                return Err(crate::log_full_errno!(
                    level,
                    crate::errno::synthetic(libc::ENOTBLK),
                    "Volatile root device is of wrong type."
                ));
            }
            return Ok(devno);
        }
    }
    let d = match get_block_device_harder(b"/") {
        Err(r) if r == -libc::EUCLEAN => return Err(btrfs_log_dev_root(level, r, "root file system")),
        Err(r) => {
            return Err(crate::log_full_errno!(
                level,
                r,
                "Failed to determine block device of root file system: ",
                strerror(r)
            ));
        }
        Ok(d) => d,
    };
    if d != 0 {
        return Ok(d);
    }
    let mut d = match get_block_device_harder(b"/usr") {
        Err(r) if r == -libc::EUCLEAN => return Err(btrfs_log_dev_root(level, r, "/usr")),
        Err(r) => {
            return Err(crate::log_full_errno!(
                level,
                r,
                "Failed to determine block device of /usr/ file system: ",
                strerror(r)
            ));
        }
        Ok(d) => d,
    };
    if d == 0 {
        d = match extension_overlay_block(b"/usr") {
            Err(r) if r == -libc::ENOENT || r == -libc::ENOTTY => 0,
            Err(r) => {
                return Err(crate::log_full_errno!(
                    level,
                    r,
                    "Failed to determine backing device of /usr/ extension overlay: ",
                    strerror(r)
                ));
            }
            Ok(d) => d,
        };
    }
    if d == 0 {
        log_debug!("Neither root nor /usr/ file system are on a (single) block device.");
    }
    Ok(d)
}

/// `gpt_probe(fd, NULL, &entries, &n, &size)`: the sector size (0 if
/// there is no GPT), the entries, and the size of each.
pub fn gpt_probe(fd: i32) -> Result<(u32, Vec<u8>, u32), i32> {
    let mut sectors = vec![0u8; 2 * 4096];
    let n = sys::pread(fd, &mut sectors, 0)?;
    if n < sectors.len() {
        return Ok((0, Vec::new(), 0));
    }
    let le32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"));
    let le64 = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    let has_signature = |p: &[u8]| {
        &p[..8] == b"EFI PART"
            && le32(p, 8) == 0x0001_0000
            && le32(p, 12) >= 92
            && le32(p, 12) <= 4096
            && le64(p, 24) == 1
    };
    let mut found = 0u32;
    let mut sz = 512u32;
    while sz <= 4096 {
        if has_signature(&sectors[sz as usize..]) {
            if found != 0 {
                return Err(-libc::ENOTUNIQ);
            }
            found = sz;
        }
        sz <<= 1;
    }
    if found == 0 {
        return Ok((0, Vec::new(), 0));
    }
    let h = &sectors[found as usize..];
    let entry_sz = le32(h, 84);
    let entry_count = le32(h, 80);
    let entry_lba = le64(h, 72);
    if entry_lba > i64::MAX as u64 / found as u64 {
        return Err(-libc::EBADMSG);
    }
    if entry_sz < 128 || entry_count == 0 || entry_count > 1024 {
        return Err(-libc::EBADMSG);
    }
    let size = entry_sz as usize * entry_count as usize;
    let mut entries = vec![0u8; size];
    let n = sys::pread(fd, &mut entries, entry_lba * found as u64)?;
    if n < size {
        return Err(-libc::EBADMSG);
    }
    Ok((found, entries, entry_sz))
}
