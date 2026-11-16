// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-blkid.c`: probe disks for file systems and partitions.

use shared::errno::{strerror, synthetic};
use shared::options::{Opt, OptionParser};
use shared::sd_device::Device;
use shared::sys::{self, OwnedFd};
use shared::sys_blkid::{self as blkid, Probe};
use shared::{log_debug_errno, log_device_debug, log_device_debug_errno, log_device_error_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

/// `SD_GPT_ROOT_NATIVE`.
#[cfg(target_arch = "x86_64")]
const GPT_ROOT_NATIVE: &[u8] = b"4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
#[cfg(target_arch = "x86")]
const GPT_ROOT_NATIVE: &[u8] = b"44479540-f297-41b2-9af7-d131d5f0458a";
#[cfg(target_arch = "aarch64")]
const GPT_ROOT_NATIVE: &[u8] = b"b921b045-1df0-41c3-af44-4c6f280d3fae";
const GPT_ESP: &[u8] = b"c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const GPT_XBOOTLDR: &[u8] = b"bc13c2ff-59e6-4262-a352-b275fd6f7172";
const GPT_FLAG_NO_AUTO: u64 = 1 << 63;

fn id(s: &[u8]) -> shared::id128::Id128 {
    shared::id128::from_string(s).expect("valid constant")
}

/// `print_property()`.
fn print_property(event: &Event, name: &[u8], value: &[u8]) {
    let add = |k: &[u8], v: &[u8]| {
        let _ = udev_builtin_add_property(event, k, Some(v));
    };
    let safe = |v: &[u8]| blkid::safe_string(v, 256);
    let enc = |v: &[u8]| blkid::encode_string(v, 256);
    match name {
        b"TYPE" => add(b"ID_FS_TYPE", value),
        b"USAGE" => add(b"ID_FS_USAGE", value),
        b"VERSION" => add(b"ID_FS_VERSION", value),
        b"UUID" => {
            add(b"ID_FS_UUID", &safe(value));
            add(b"ID_FS_UUID_ENC", &enc(value));
        }
        b"UUID_SUB" => {
            add(b"ID_FS_UUID_SUB", &safe(value));
            add(b"ID_FS_UUID_SUB_ENC", &enc(value));
        }
        b"LABEL" => {
            add(b"ID_FS_LABEL", &safe(value));
            add(b"ID_FS_LABEL_ENC", &enc(value));
        }
        b"FSSIZE" | b"FSLASTBLOCK" | b"FSBLOCKSIZE" => add(&shared::bcat!("ID_FS_", &name[2..]), value),
        b"PTTYPE" => add(b"ID_PART_TABLE_TYPE", value),
        b"PTUUID" => add(b"ID_PART_TABLE_UUID", value),
        b"PART_ENTRY_NAME" => add(b"ID_PART_ENTRY_NAME", &enc(value)),
        b"PART_ENTRY_TYPE" => add(b"ID_PART_ENTRY_TYPE", &enc(value)),
        _ if name.starts_with(b"PART_ENTRY_") => {
            let mut k = shared::bcat!("ID_", name);
            k.truncate(255);
            add(&k, value);
        }
        b"SYSTEM_ID" => add(b"ID_FS_SYSTEM_ID", &enc(value)),
        b"PUBLISHER_ID" => add(b"ID_FS_PUBLISHER_ID", &enc(value)),
        b"APPLICATION_ID" => add(b"ID_FS_APPLICATION_ID", &enc(value)),
        b"BOOT_SYSTEM_ID" => add(b"ID_FS_BOOT_SYSTEM_ID", &enc(value)),
        b"VOLUME_ID" => add(b"ID_FS_VOLUME_ID", &enc(value)),
        b"LOGICAL_VOLUME_ID" => add(b"ID_FS_LOGICAL_VOLUME_ID", &enc(value)),
        b"VOLUME_SET_ID" => add(b"ID_FS_VOLUME_SET_ID", &enc(value)),
        b"DATA_PREPARER_ID" => add(b"ID_FS_DATA_PREPARER_ID", &enc(value)),
        _ => {}
    }
}

fn not_supported(r: i32) -> bool {
    shared::errno::is_neg_not_supported(r)
}

/// `blkid_partition_get_uuid_id128()` / `..._type_id128()`.
fn part_id(s: Option<Vec<u8>>) -> Result<shared::id128::Id128, i32> {
    match s {
        Some(s) if !s.is_empty() => shared::id128::from_string(&s),
        _ => Err(-libc::ENXIO),
    }
}

/// `find_gpt_root()`.
fn find_gpt_root(event: &Event, pr: &Probe, loop_backing_fname: Option<&[u8]>) -> Result<(), i32> {
    let dev = event.dev.clone();
    let devnode = dev
        .get_devname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r)))?
        .bytes()
        .to_vec();
    match shared::blockdev::block_device_is_whole_disk(&dev) {
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Unable to determine if device '",
                &devnode[..],
                "' is a whole-block device: ",
                strerror(r)
            ));
        }
        Ok(false) => {
            log_device_debug!(
                dev,
                "Invoked on device '",
                &devnode[..],
                "' which is not a whole-disk block device, ignoring."
            );
            return Ok(());
        }
        Ok(true) => {}
    }
    match shared::blockdev::blockdev_partscan_enabled(&dev) {
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to determine if block device '",
                &devnode[..],
                "' supports partitions: ",
                strerror(r)
            ));
        }
        Ok(false) => {
            log_device_debug!(
                dev,
                "Invoked on block device '",
                &devnode[..],
                "' that lacks partition scanning, ignoring."
            );
            return Ok(());
        }
        Ok(true) => {}
    }
    let mut esp_or_xbootldr = [0u8; 16];
    let need_esp_or_xbootldr;
    let mut root_devno = 0u64;
    if shared::proc_cmdline::in_initrd() {
        match shared::efivars::efi_loader_get_device_part_uuid() {
            Err(r) => {
                if r != -libc::ENOENT && !not_supported(r) {
                    return Err(log_debug_errno!(r, "Unable to determine loader partition UUID: ", strerror(r)));
                }
                log_device_debug!(
                    dev,
                    "No loader partition UUID EFI variable set, not using partition data to search for default root block device."
                );
                if !matches!(loop_backing_fname, Some(b"rootdisk" | b"rootdisk.raw")) {
                    log_device_debug!(
                        dev,
                        "Device is not a loopback block device with reference string 'root', not considering block device as default root block device."
                    );
                    return Ok(());
                }
                need_esp_or_xbootldr = false;
            }
            Ok(u) => {
                esp_or_xbootldr = u;
                need_esp_or_xbootldr = true;
            }
        }
    } else {
        match shared::blockdev::blockdev_get_root(shared::log::LOG_DEBUG) {
            Err(r) => {
                log_device_debug_errno!(
                    dev,
                    r,
                    "Unable to determine current root block device, skipping gpt-auto probing: ",
                    strerror(r)
                );
                return Ok(());
            }
            Ok(0) => {
                log_device_debug!(
                    dev,
                    "Root block device not backed by a (single) whole block device, skipping gpt-auto probing."
                );
                return Ok(());
            }
            Ok(d) => root_devno = d,
        }
        let (whole, _) = shared::blockdev::block_get_whole_disk(root_devno).map_err(|r| {
            log_device_debug_errno!(dev, r, "Failed to find whole block device for root block device: ", strerror(r))
        })?;
        let this = dev.get_devnum().map_err(|r| {
            log_device_debug_errno!(dev, r, "Failed to get device major/minor of device: ", strerror(r))
        })?;
        if whole != this {
            log_device_debug!(dev, "This device is not the current root block device.");
            return Ok(());
        }
        need_esp_or_xbootldr = false;
    }
    let pl = match pr.partitions() {
        Ok(pl) => pl,
        Err(e) => {
            let r = if e > 0 { -e } else { -libc::ENOMEM };
            return Err(log_device_debug_errno!(dev, r, "Failed to probe partitions: ", strerror(r)));
        }
    };
    let mut root_id: Option<shared::id128::Id128> = None;
    let mut found = false;
    if root_devno != 0 {
        if let Some(p) = pl.devno_to_partition(root_devno) {
            match part_id(p.type_string()) {
                Err(r) => {
                    log_device_debug_errno!(dev, r, "Failed to get root partition type UUID, ignoring: ", strerror(r));
                }
                Ok(t) if t == id(GPT_ROOT_NATIVE) => match part_id(p.uuid()) {
                    Err(r) => {
                        log_device_debug_errno!(dev, r, "Failed to get partition UUID, ignoring: ", strerror(r));
                    }
                    Ok(u) => root_id = Some(u).filter(|u| *u != [0u8; 16]),
                },
                Ok(_) => {}
            }
        }
    } else {
        let mut root_label: Option<Vec<u8>> = None;
        for i in 0..pl.len() {
            let Some(pp) = pl.get(i) else { continue };
            let uid = match part_id(pp.uuid()) {
                Ok(u) => u,
                Err(r) => {
                    log_device_debug_errno!(dev, r, "Failed to get partition UUID, ignoring: ", strerror(r));
                    continue;
                }
            };
            let ty = match part_id(pp.type_string()) {
                Ok(t) => t,
                Err(r) => {
                    log_device_debug_errno!(dev, r, "Failed to get partition type UUID, ignoring: ", strerror(r));
                    continue;
                }
            };
            let label = pp.name();
            if need_esp_or_xbootldr && (ty == id(GPT_ESP) || ty == id(GPT_XBOOTLDR)) {
                if uid == esp_or_xbootldr {
                    found = true;
                }
            } else if ty == id(GPT_ROOT_NATIVE) {
                if pp.flags() & GPT_FLAG_NO_AUTO != 0 {
                    continue;
                }
                if label.as_deref() == Some(b"_empty") {
                    continue;
                }
                if root_id.is_none()
                    || shared::string::strverscmp_improved(label.as_deref(), root_label.as_deref()).is_gt()
                {
                    root_id = Some(uid).filter(|u| *u != [0u8; 16]);
                    root_label = label;
                }
            }
        }
    }
    if !need_esp_or_xbootldr || found {
        let _ = udev_builtin_add_property(event, b"ID_PART_GPT_AUTO_ROOT_DISK", Some(b"1"));
        if let Some(r) = root_id {
            let _ = udev_builtin_add_property(
                event,
                b"ID_PART_GPT_AUTO_ROOT_UUID",
                Some(&shared::id128::to_uuid_string(&r)),
            );
        }
    }
    Ok(())
}

/// `probe_superblocks()`: 0 found, 1 nothing found.
fn probe_superblocks(pr: &Probe) -> Result<i32, i32> {
    let st = sys::fstat(pr.fd())?;
    pr.enable_partitions(true);
    if st.st_mode & libc::S_IFMT != libc::S_IFCHR && pr.size() <= 1024 * 1440 && pr.is_wholedisk() {
        pr.enable_superblocks(false);
        let (rc, e) = pr.do_fullprobe();
        if rc < 0 {
            return Err(if e > 0 { -e } else { -libc::EIO });
        }
        if pr.lookup_value(b"PTTYPE").is_some() {
            return Ok(0);
        }
    }
    pr.set_partitions_flags(blkid::BLKID_PARTS_ENTRY_DETAILS);
    pr.enable_superblocks(true);
    let (rc, e) = pr.do_safeprobe();
    if rc < 0 {
        return Err(if e > 0 { -e } else { -libc::EIO });
    }
    Ok(rc)
}

/// `read_loopback_backing_inode()`: (device, inode, file name), None if
/// not a loop device.
fn read_loopback_backing_inode(dev: &Device, fd: i32) -> Result<Option<(u64, u64, Option<Vec<u8>>)>, i32> {
    const LOOP_GET_STATUS64: u64 = 0x4c05;
    if !shared::blockdev::device_sysname_startswith(dev, &[b"loop"])? {
        return Ok(None);
    }
    let mut info = [0u8; 232];
    if let Err(r) = sys::ioctl_ptr(fd, LOOP_GET_STATUS64, &mut info) {
        if shared::errno::is_neg_not_supported(r) {
            return Ok(None);
        }
        return Err(r);
    }
    let name = &info[56..120];
    let n = name.iter().position(|&b| b == 0).unwrap_or(64);
    let fname = if n == 0 || n.min(63) == 63 { None } else { Some(name[..n].to_vec()) };
    let devno = u64::from_ne_bytes(info[0..8].try_into().expect("8 bytes"));
    let inode = u64::from_ne_bytes(info[8..16].try_into().expect("8 bytes"));
    Ok(Some((devno, inode, fname)))
}

/// `gpt_boot_disk_needs_loop()`: (needs a loop device, GPT sector size).
fn gpt_boot_disk_needs_loop(dev: &Device, fd: i32) -> (Result<bool, i32>, u32) {
    let (gpt_ssz, entries, entry_size) = match shared::blockdev::gpt_probe(fd) {
        Err(r) => return (Err(log_device_debug_errno!(dev, r, "Failed to probe GPT: ", strerror(r))), 0),
        Ok(x) => x,
    };
    if gpt_ssz == 0 {
        return (Ok(false), 0);
    }
    let device_ssz = match shared::blockdev::blockdev_get_sector_size(fd) {
        Ok(s) => s,
        Err(r) => {
            return (Err(log_device_debug_errno!(dev, r, "Failed to get device sector size: ", strerror(r))), 0);
        }
    };
    let mismatch = gpt_ssz != device_ssz;
    if !mismatch {
        match shared::blockdev::blockdev_partscan_enabled(dev) {
            Err(r) => {
                return (
                    Err(log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to check if partition scanning is enabled: ",
                        strerror(r)
                    )),
                    0,
                );
            }
            Ok(true) => return (Ok(false), gpt_ssz),
            Ok(false) => {}
        }
    }
    if mismatch {
        log_device_debug!(dev, format!("GPT sector size {gpt_ssz} does not match device sector size {device_ssz}."));
    } else {
        log_device_debug!(dev, "Device does not support partition scanning.");
    }
    let loader = match shared::efivars::efi_loader_get_device_part_uuid() {
        Ok(u) => u,
        Err(r) => {
            if r != -libc::ENOENT && !not_supported(r) {
                return (Err(log_device_debug_errno!(dev, r, "Failed to get loader partition UUID: ", strerror(r))), 0);
            }
            return (Ok(false), gpt_ssz);
        }
    };
    for e in entries.chunks_exact(entry_size as usize) {
        let ty = shared::efivars::efi_guid_to_id128(&e[0..16]);
        if ty != id(GPT_ESP) && ty != id(GPT_XBOOTLDR) {
            continue;
        }
        if shared::efivars::efi_guid_to_id128(&e[16..32]) != loader {
            continue;
        }
        log_device_debug!(dev, "Found boot partition (ESP/XBOOTLDR) on disk where kernel cannot scan partitions.");
        return (Ok(true), gpt_ssz);
    }
    (Ok(false), gpt_ssz)
}

const HINT: i32 = 1;
const OFFSET: i32 = 2;
const NORAID: i32 = 3;
const OPTIONS: &[Opt] = &[
    Opt::new(HINT, b'H', Some("hint"), Some("HINT"), None),
    Opt::new(OFFSET, b'o', Some("offset"), Some("OFFSET"), None),
    Opt::new(NORAID, b'R', Some("noraid"), None, None),
];

/// `builtin_blkid()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    blkid::dlopen_libblkid(shared::log::LOG_DEBUG)
        .map_err(|r| log_device_debug_errno!(dev, r, "blkid not available: ", strerror(r)))?;
    let pr = Probe::new().map_err(|e| {
        let r = if e > 0 { -e } else { -libc::ENOMEM };
        log_device_debug_errno!(dev, r, "Failed to create blkid prober: ", strerror(r))
    })?;
    let mut noraid = false;
    let mut offset: i64 = 0;
    let mut opts = OptionParser::new(argv.to_vec(), OPTIONS);
    while let Some(c) = opts.next()? {
        let a = opts.arg.clone().unwrap_or_default();
        match c {
            HINT => {
                if let Err(e) = pr.set_hint(&a) {
                    let r = if e > 0 { -e } else { -libc::ENOMEM };
                    return Err(log_device_error_errno!(
                        dev,
                        r,
                        "Failed to use '",
                        &a[..],
                        "' probing hint: ",
                        strerror(r)
                    ));
                }
            }
            OFFSET => {
                offset = shared::parse::safe_atoi64(&a).map_err(|r| {
                    log_device_error_errno!(dev, r, "Failed to parse '", &a[..], "' as an integer: ", strerror(r))
                })?;
                if offset < 0 {
                    return Err(log_device_error_errno!(
                        dev,
                        synthetic(libc::EINVAL),
                        format!("Invalid offset {offset}.")
                    ));
                }
            }
            NORAID => noraid = true,
            _ => {}
        }
    }
    let devnode = dev
        .get_devname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get device name: ", strerror(r)))?
        .bytes()
        .to_vec();
    let fd: OwnedFd = match shared::blockdev::sd_device_open(
        &dev,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
    ) {
        Ok(f) => f,
        Err(r) => {
            let ignore = shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM;
            log_device_debug_errno!(
                dev,
                r,
                "Failed to open block device ",
                &devnode[..],
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { Ok(()) } else { Err(r) };
        }
    };
    if offset == 0 {
        let (r, gpt_ssz) = gpt_boot_disk_needs_loop(&dev, fd.raw());
        if gpt_ssz > 0 {
            let _ = udev_builtin_add_property(event, b"ID_PART_GPT_SECTOR_SIZE", Some(gpt_ssz.to_string().as_bytes()));
        }
        if r == Ok(true) {
            let _ = udev_builtin_add_property(event, b"ID_PART_GPT_AUTO_ROOT_DISK_NEEDS_LOOP", Some(b"1"));
        }
    }
    pr.set_superblocks_flags(
        blkid::BLKID_SUBLKS_LABEL
            | blkid::BLKID_SUBLKS_UUID
            | blkid::BLKID_SUBLKS_TYPE
            | blkid::BLKID_SUBLKS_SECTYPE
            | blkid::BLKID_SUBLKS_FSINFO
            | blkid::BLKID_SUBLKS_USAGE
            | blkid::BLKID_SUBLKS_VERSION,
    );
    if noraid {
        pr.filter_superblocks_usage(blkid::BLKID_FLTR_NOTIN, blkid::BLKID_USAGE_RAID);
    }
    if let Err(e) = pr.set_device(fd.raw(), offset) {
        let r = if e > 0 { -e } else { -libc::ENOMEM };
        return Err(log_device_debug_errno!(dev, r, "Failed to set device to blkid prober: ", strerror(r)));
    }
    log_device_debug!(
        dev,
        "Probe ",
        &devnode[..],
        " with ",
        if noraid { "no" } else { "" },
        format!("raid and offset={offset}")
    );
    probe_superblocks(&pr)
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to probe superblocks: ", strerror(r)))?;
    let root_partition = dev.get_property_value(b"ID_PART_GPT_AUTO_ROOT_UUID").ok().map(|v| v.bytes().to_vec());
    let nvals = pr.numof_values().map_err(|e| {
        let r = if e > 0 { -e } else { -libc::ENOMEM };
        log_device_debug_errno!(dev, r, "Failed to get number of probed values: ", strerror(r))
    })?;
    let mut is_gpt = false;
    for i in 0..nvals {
        let Some((name, data)) = pr.value(i) else { continue };
        print_property(event, &name, &data);
        if name == b"PTTYPE" && data == b"gpt" {
            is_gpt = true;
        }
        if name == b"PART_ENTRY_UUID" && root_partition.as_deref() == Some(&data[..]) {
            let _ = udev_builtin_add_property(event, b"ID_PART_GPT_AUTO_ROOT", Some(b"1"));
        }
    }
    let mut backing_fname = None;
    match read_loopback_backing_inode(&dev, fd.raw()) {
        Err(r) => {
            log_device_debug_errno!(dev, r, "Failed to read loopback backing inode, ignoring: ", strerror(r));
        }
        Ok(None) => {}
        Ok(Some((devno, inode, fname))) => {
            let _ = udev_builtin_add_property(
                event,
                b"ID_LOOP_BACKING_DEVICE",
                Some(shared::sd_device::devnum_format(devno).as_bytes()),
            );
            let _ = udev_builtin_add_property(event, b"ID_LOOP_BACKING_INODE", Some(inode.to_string().as_bytes()));
            if let Some(f) = &fname {
                let encoded = blkid::encode_string(f, 64 * 4 + 1);
                let _ = udev_builtin_add_property(event, b"ID_LOOP_BACKING_FILENAME", Some(f));
                let _ = udev_builtin_add_property(event, b"ID_LOOP_BACKING_FILENAME_ENC", Some(&encoded));
            }
            backing_fname = fname;
        }
    }
    if is_gpt {
        let _ = find_gpt_root(event, &pr, backing_fname.as_deref());
    }
    Ok(())
}
