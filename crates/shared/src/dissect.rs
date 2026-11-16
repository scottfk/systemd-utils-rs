// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `dissect-image.c` and `loop-util.c` that udev's
//! dissect_image builtin uses: `loop_device_open()` on a block device and
//! `dissect_loop_device()` with DISSECT_IMAGE_READ_ONLY,
//! DISSECT_IMAGE_GPT_ONLY, DISSECT_IMAGE_USR_NO_ROOT and
//! DISSECT_IMAGE_ALLOW_EMPTY, which rule out everything but a GPT
//! partition table probed as-is (no partition devices are added or
//! pinned, no unpartitioned images, no by-diskseq names).

use crate::errno::{strerror, synthetic};
use crate::gpt::{self, Designator, N_DESIGNATORS};
use crate::image_policy::{self as ip, ImagePolicy};
use crate::sd_device::Device;
use crate::sys::{self, OwnedFd};
use crate::sys_blkid::{self as blkid, Probe};
use crate::{log_debug, log_debug_errno, log_error_errno};

/// `VeritySettings` (no data path: udev never sets one).
#[derive(Debug, Clone, Default)]
pub struct VeritySettings {
    pub root_hash: Vec<u8>,
    pub root_hash_sig: Vec<u8>,
    pub designator: Option<Designator>,
}

/// An `ImageFilter`: a glob per designator.
#[derive(Debug, Clone, Default)]
pub struct ImageFilter {
    pub pattern: [Option<Vec<u8>>; N_DESIGNATORS],
}

/// `image_filter_parse(s, &ret)`.
pub fn image_filter_parse(s: &[u8]) -> Result<Option<ImageFilter>, i32> {
    use crate::extract::{EXTRACT_DONT_COALESCE_SEPARATORS, EXTRACT_UNQUOTE, extract_first_word};
    if s.is_empty() {
        return Ok(None);
    }
    let mut f: Option<ImageFilter> = None;
    let mut p = Some(s);
    loop {
        let word = match extract_first_word(&mut p, Some(b":"), EXTRACT_UNQUOTE | EXTRACT_DONT_COALESCE_SEPARATORS) {
            Err(r) => return Err(log_debug_errno!(r, "Failed to extract word: ", strerror(r))),
            Ok(None) => break,
            Ok(Some(w)) => w,
        };
        // extract_many_words(&x, "=", ..., &designator, &pattern)
        let mut x = Some(&word[..]);
        let flags = EXTRACT_UNQUOTE | EXTRACT_DONT_COALESCE_SEPARATORS;
        let d = extract_first_word(&mut x, Some(b"="), flags)
            .map_err(|r| log_debug_errno!(r, "Failed to extract designator: ", strerror(r)))?;
        let pat = if d.is_some() {
            extract_first_word(&mut x, Some(b"="), flags)
                .map_err(|r| log_debug_errno!(r, "Failed to extract designator: ", strerror(r)))?
        } else {
            None
        };
        let (Some(d), Some(pat)) = (d, pat) else {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Unable to split: ", &word[..]));
        };
        if !x.unwrap_or(b"").is_empty() {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Unable to split: ", &word[..]));
        }
        let Some(des) = Designator::from_bytes(&d) else {
            return Err(log_debug_errno!(-libc::EINVAL, "Failed to parse partition designator: ", &d[..]));
        };
        let filter = f.get_or_insert_with(ImageFilter::default);
        if filter.pattern[des.index()].is_some() {
            return Err(log_debug_errno!(
                synthetic(libc::EINVAL),
                "Duplicate pattern for '",
                des.as_str(),
                "', refusing."
            ));
        }
        filter.pattern[des.index()] = Some(pat);
    }
    Ok(f)
}

/// `image_filter_test()`.
fn image_filter_test(filter: Option<&ImageFilter>, d: Option<Designator>, label: Option<&[u8]>) -> bool {
    let Some(d) = d else { return true };
    let Some(p) = filter.and_then(|f| f.pattern[d.index()].as_ref()) else { return true };
    sys::fnmatch(p, label.unwrap_or(b""), libc::FNM_NOESCAPE) == 0
}

/// A `LoopDevice`, as `loop_device_open()` makes it: relinquished, so
/// freeing it only syncs and closes.
#[derive(Debug)]
pub struct LoopDevice {
    pub fd: OwnedFd,
    _lock_fd: Option<OwnedFd>,
    pub node: Vec<u8>,
    pub backing_file: Option<Vec<u8>>,
    pub devno: u64,
    pub diskseq: u64,
    pub sector_size: u32,
    pub device_size: u64,
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        // loop_device_free()
        if let Err(r) = sys::fsync(self.fd.raw()) {
            log_debug_errno!(r, "Failed to sync loop block device, ignoring: ", strerror(r));
        }
    }
}

/// `loop_device_open(dev, open_flags, lock_op, &ret)`.
pub fn loop_device_open(dev: &Device, open_flags: i32, lock_op: i32) -> Result<LoopDevice, i32> {
    const LOOP_GET_STATUS64: u64 = 0x4c05;
    const BLKGETSIZE64: u64 = 0x8008_1272;
    let fd = crate::blockdev::sd_device_open(dev, libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY | open_flags)?;
    let lock_fd = if lock_op & !libc::LOCK_NB != libc::LOCK_UN {
        // open_lock_fd(): fd_reopen() and flock().
        let l = OwnedFd::new(sys::open(
            &crate::fd::proc_fd_path(fd.raw()),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        )?);
        sys::flock(l.raw(), lock_op)?;
        Some(l)
    } else {
        None
    };
    let mut backing_file = None;
    let mut info = [0u8; 232];
    if sys::ioctl_ptr(fd.raw(), LOOP_GET_STATUS64, &mut info).is_ok() {
        backing_file = dev.get_sysattr_safe_string(b"loop/backing_file").ok().map(|s| s.bytes().to_vec());
    }
    let diskseq = match crate::blockdev::fd_get_diskseq(fd.raw()) {
        Ok(d) => d,
        Err(r) if r == -libc::EOPNOTSUPP => 0,
        Err(r) => return Err(r),
    };
    let sector_size = crate::blockdev::blockdev_get_sector_size(fd.raw())?;
    let mut device_size: u64 = 0;
    sys::ioctl_ptr(fd.raw(), BLKGETSIZE64, &mut device_size)?;
    let devno = dev.get_devnum()?;
    let node = dev.get_devname()?.bytes().to_vec();
    Ok(LoopDevice { fd, _lock_fd: lock_fd, node, backing_file, devno, diskseq, sector_size, device_size })
}

/// A `DissectedPartition`, with what udev's use of it needs.
#[derive(Debug, Clone, Default)]
pub struct DissectedPartition {
    pub found: bool,
    pub ignored: bool,
    pub partno: i32,
    pub rw: bool,
    pub growfs: bool,
    pub architecture: Option<&'static str>,
    pub node: Vec<u8>,
    pub fstype: Option<Vec<u8>>,
    pub label: Option<Vec<u8>>,
    pub uuid: [u8; 16],
    pub offset: u64,
    pub size: u64,
    pub gpt_flags: u64,
}

/// A `DissectedImage`.
#[derive(Debug, Default)]
pub struct DissectedImage {
    pub partitions: [DissectedPartition; N_DESIGNATORS],
    pub encrypted: bool,
    pub has_verity: bool,
    pub has_verity_sig: bool,
    pub verity_ready: bool,
    pub verity_sig_ready: bool,
    pub image_uuid: [u8; 16],
}

impl DissectedImage {
    /// `dissected_image_architecture()`.
    pub fn architecture(&self) -> Option<&'static str> {
        for d in [Designator::Root, Designator::Usr] {
            let p = &self.partitions[d.index()];
            if p.found && p.architecture.is_some() {
                return p.architecture;
            }
        }
        None
    }
}

/// `allowed_fstypes()`.
fn allowed_fstypes() -> Vec<Vec<u8>> {
    match sys::secure_getenv("SYSTEMD_DISSECT_FILE_SYSTEMS") {
        Some(e) => crate::string::strv_split(&e, b":"),
        None => ["btrfs", "erofs", "ext4", "f2fs", "squashfs", "vfat", "xfs"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
    }
}

/// `probe_blkid_filter()`.
fn probe_blkid_filter(p: &Probe) -> Result<(), i32> {
    let mut l = allowed_fstypes();
    l.push(b"crypto_LUKS".to_vec());
    l.push(b"swap".to_vec());
    p.filter_superblocks_type(blkid::BLKID_FLTR_ONLYIN, &l).map_err(|e| if e > 0 { -e } else { -libc::EINVAL })
}

/// `getenv_fstype()`.
fn getenv_fstype(d: Option<Designator>) -> Option<Vec<u8>> {
    let d = d?;
    if d.is_verity() || d == Designator::Swap {
        return None;
    }
    sys::secure_getenv(&format!("SYSTEMD_DISSECT_FSTYPE_{}", d.as_str().to_ascii_uppercase()))
}

/// `probe_filesystem_full(fd, path, offset, size, restrict_fstypes=true, &ret)`.
fn probe_filesystem(fd: i32, path: &[u8], offset: u64, size: u64) -> Result<Option<Vec<u8>>, i32> {
    const BLKFLSBUF: u64 = 0x1261;
    const NOT_FOUND: i32 = 1;
    const AMBIGUOUS: i32 = -2;
    blkid::dlopen_libblkid(libc::LOG_DEBUG)?;
    let found = 'probe: {
        if size == 0 {
            break 'probe None;
        }
        let b = Probe::new().map_err(|_| -libc::ENOMEM)?;
        probe_blkid_filter(&b)?;
        if offset != 0
            && let Err(r) = sys::ioctl_int(fd, BLKFLSBUF, 0)
        {
            log_debug_errno!(r, "Failed to flush block device cache, ignoring: ", strerror(r));
        }
        b.set_device_range(fd, offset as i64, if size == u64::MAX { 0 } else { size as i64 })
            .map_err(|e| if e > 0 { -e } else { -libc::ENOMEM })?;
        b.enable_superblocks(true);
        b.set_superblocks_flags(blkid::BLKID_SUBLKS_TYPE);
        let (r, e) = b.do_safeprobe();
        if r == NOT_FOUND {
            break 'probe None;
        }
        if r == AMBIGUOUS {
            return Err(log_debug_errno!(synthetic(libc::EUCLEAN), "Results ambiguous for partition ", path));
        }
        if r < 0 {
            let e = if e > 0 { -e } else { -libc::EIO };
            return Err(log_debug_errno!(e, "Failed to probe partition ", path, ": ", strerror(e)));
        }
        b.lookup_value(b"TYPE")
    };
    match found {
        Some(t) => {
            log_debug!("Probed fstype '", &t[..], "' on partition ", path, ".");
            Ok(Some(t))
        }
        None => {
            log_debug!("No type detected on partition ", path);
            Ok(None)
        }
    }
}

/// `partition_is_luks2_integrity()`.
fn partition_is_luks2_integrity(fd: i32, offset: u64, size: u64) -> Result<bool, i32> {
    const FIXED_HDR_SIZE: u64 = 0x1000;
    if size < FIXED_HDR_SIZE {
        log_debug_errno!(synthetic(libc::EINVAL), "Partition is too small to contain a LUKS header.");
        return Ok(false);
    }
    let mut h = [0u8; 16];
    let n = sys::pread(fd, &mut h, offset).map_err(|r| log_error_errno!(r, "Failed to read LUKS header."))?;
    if n != h.len() {
        return Err(log_error_errno!(synthetic(libc::EIO), "Failed to read LUKS header."));
    }
    if &h[..6] != b"LUKS\xba\xbe" {
        log_debug!("Partition does not have a LUKS magic header, assuming no integrity.");
        return Ok(false);
    }
    let version = u16::from_be_bytes([h[6], h[7]]);
    if version != 2 {
        log_debug!(format!("Partition is LUKS v{version}, not LUKS2, assuming no integrity."));
        return Ok(false);
    }
    let hdr_len = u64::from_be_bytes(h[8..16].try_into().expect("8 bytes"));
    if hdr_len > size {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "LUKS header length exceeds partition size."));
    }
    if hdr_len <= FIXED_HDR_SIZE || offset > u64::MAX - hdr_len {
        return Err(log_error_errno!(synthetic(libc::EINVAL), format!("Invalid LUKS header length: {hdr_len}.")));
    }
    if hdr_len - FIXED_HDR_SIZE > 16 * 1024 * 1024 {
        return Err(log_error_errno!(synthetic(libc::EINVAL), format!("LUKS header JSON area too large: {hdr_len}.")));
    }
    let mut json = vec![0u8; (hdr_len - FIXED_HDR_SIZE) as usize];
    let n = sys::pread(fd, &mut json, offset + FIXED_HDR_SIZE)
        .map_err(|r| log_error_errno!(r, "Failed to read LUKS JSON header."))?;
    if n != json.len() {
        return Err(log_error_errno!(synthetic(libc::EIO), "Failed to read LUKS JSON header."));
    }
    // The C string ends at the first NUL.
    let end = json.iter().position(|&b| b == 0).unwrap_or(json.len());
    let v = crate::json::parse(&json[..end]).map_err(|r| log_error_errno!(r, "Failed to parse LUKS JSON header."))?;
    let Some(crate::json::Json::Object(segments)) = v.get("segments") else {
        log_debug!("LUKS JSON header lacks 'segments' information, assuming no integrity.");
        return Ok(false);
    };
    for (key, w) in segments {
        let t = match w.get("integrity") {
            Some(i @ crate::json::Json::Object(_)) => i.get("type").and_then(|t| t.as_str()),
            _ => None,
        };
        let Some(t) = t else {
            log_debug!(
                "Failed to get integrity information from LUKS JSON for segment ",
                &key[..],
                ", assuming no integrity."
            );
            return Ok(false);
        };
        if t == b"none" {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `check_partition_flags()`.
fn check_partition_flags(node: &[u8], pflags: u64, supported: u64) {
    let pflags = pflags
        & !(supported
            | gpt::SD_GPT_FLAG_REQUIRED_PARTITION
            | gpt::SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL
            | gpt::SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE);
    for i in 0..64 {
        let bit = 1u64 << i;
        if pflags & bit != 0 {
            log_debug!(format!("Unexpected partition flag {bit} set on "), node, "!");
        }
    }
}

/// `compare_arch()`.
fn compare_arch(a: Option<&str>, b: Option<&str>) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    if a == b {
        return Equal;
    }
    if a == Some(gpt::NATIVE_ARCHITECTURE) {
        return Greater;
    }
    if b == Some(gpt::NATIVE_ARCHITECTURE) {
        return Less;
    }
    if let Some(s) = gpt::SECONDARY_ARCHITECTURE {
        if a == Some(s) {
            return Greater;
        }
        if b == Some(s) {
            return Less;
        }
    }
    Equal
}

/// `partition_node_of(node, nr, &ret)`.
fn partition_node_of(node: &[u8], nr: i32) -> Vec<u8> {
    let (dir, file) = match node.iter().rposition(|&c| c == b'/') {
        Some(i) => (Some(&node[..i + 1]), &node[i + 1..]),
        None => (None, node),
    };
    let need_p = file.last().is_some_and(u8::is_ascii_digit);
    let sub = crate::bcat!(file, if need_p { "p" } else { "" }, nr.to_string());
    match dir {
        Some(d) => crate::path::path_join(&[d, &sub]),
        None => sub,
    }
}

fn uuid_string(id: &[u8; 16]) -> Vec<u8> {
    crate::id128::to_uuid_string(id)
}

/// `acquire_sig_for_roothash()`: (root hash, signature).
fn acquire_sig_for_roothash(fd: i32, offset: u64, size: u64) -> Result<(Vec<u8>, Vec<u8>), i32> {
    if offset == u64::MAX || size == u64::MAX {
        return Err(-libc::EINVAL);
    }
    if size > 4 * 1024 * 1024 {
        return Err(log_debug_errno!(
            synthetic(libc::EFBIG),
            "Verity signature partition is larger than 4M, refusing."
        ));
    }
    let mut buf = vec![0u8; size as usize];
    let n = sys::pread(fd, &mut buf, offset)?;
    if n as u64 != size {
        return Err(-libc::EIO);
    }
    if let Some(e) = buf.iter().position(|&b| b == 0) {
        if buf[e..].iter().any(|&b| b != 0) {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Signature data contains embedded NUL byte."));
        }
        buf.truncate(e);
    }
    let v = crate::json::parse(&buf)
        .map_err(|r| log_debug_errno!(r, "Failed to parse signature JSON data: ", strerror(r)))?;
    let Some(rh) = v.get("rootHash") else {
        return Err(log_debug_errno!(synthetic(libc::EINVAL), "Signature JSON object lacks 'rootHash' field."));
    };
    let root_hash = rh
        .as_str()
        .ok_or(-libc::EINVAL)
        .and_then(crate::hexdecoct::unhexmem)
        .map_err(|r| log_debug_errno!(r, "Failed to parse root hash field: ", strerror(r)))?;
    let Some(sig) = v.get("signature") else {
        return Err(log_debug_errno!(synthetic(libc::EINVAL), "Signature JSON object lacks 'signature' field."));
    };
    let root_hash_sig = sig
        .as_str()
        .ok_or(-libc::EINVAL)
        .and_then(crate::hexdecoct::unbase64mem)
        .map_err(|r| log_debug_errno!(r, "Failed to parse signature field: ", strerror(r)))?;
    Ok((root_hash, root_hash_sig))
}

/// `image_policy_may_use()`: Ok(false) to ignore the partition.
fn image_policy_may_use(policy: &ImagePolicy, d: Designator) -> Result<bool, i32> {
    let f = policy.get_exhaustively(d);
    if f & ip::USE_MASK == ip::ABSENT {
        return Err(log_debug_errno!(
            synthetic(libc::ERFKILL),
            "Partition of designator '",
            d.as_str(),
            "' exists, but not allowed by policy, refusing."
        ));
    }
    if f & ip::USE_MASK & !ip::ABSENT == ip::UNUSED {
        log_debug!("Partition of designator '", d.as_str(), "' exists, and policy dictates to ignore it, doing so.");
        return Ok(false);
    }
    Ok(true)
}

/// `image_policy_check_protection()`.
fn image_policy_check_protection(policy: &ImagePolicy, d: Designator, found: i32) -> Result<(), i32> {
    let pf = policy.get_exhaustively(d);
    if found & pf == 0 {
        let (a, _) = ip::flags_to_string(found, true);
        let (b, _) = ip::flags_to_string(pf, true);
        return Err(log_debug_errno!(
            synthetic(libc::ERFKILL),
            "Partition ",
            d.as_str(),
            " discovered with policy '",
            &a[..],
            "' but '",
            &b[..],
            "' was required, refusing."
        ));
    }
    Ok(())
}

/// `image_policy_check_partition_flags()`.
fn image_policy_check_partition_flags(policy: &ImagePolicy, d: Designator, gpt_flags: u64) -> Result<(), i32> {
    let pf = policy.get_exhaustively(d);
    let one_zero = |b: bool| if b { "1" } else { "0" };
    let b = gpt_flags & gpt::SD_GPT_FLAG_READ_ONLY != 0;
    if pf & ip::READ_ONLY_MASK == if b { ip::READ_ONLY_OFF } else { ip::READ_ONLY_ON } {
        return Err(log_debug_errno!(
            synthetic(libc::ERFKILL),
            "Partition ",
            d.as_str(),
            " has 'read-only' flag incorrectly set (must be ",
            one_zero(!b),
            ", is ",
            one_zero(b),
            "), refusing."
        ));
    }
    let b = gpt_flags & gpt::SD_GPT_FLAG_GROWFS != 0;
    if pf & ip::GROWFS_MASK == if b { ip::GROWFS_OFF } else { ip::GROWFS_ON } {
        return Err(log_debug_errno!(
            synthetic(libc::ERFKILL),
            "Partition ",
            d.as_str(),
            " has 'growfs' flag incorrectly set (must be ",
            one_zero(!b),
            ", is ",
            one_zero(b),
            "), refusing."
        ));
    }
    Ok(())
}

/// `fstype_is_ro()`.
fn fstype_is_ro(t: &[u8]) -> bool {
    matches!(t, b"DM_verity_hash" | b"cramfs" | b"erofs" | b"iso9660" | b"squashfs")
}

/// `dissected_image_probe_filesystems()`.
fn probe_filesystems(m: &mut DissectedImage, fd: i32, policy: &ImagePolicy) -> Result<(), i32> {
    for d in gpt::ALL {
        let p = &mut m.partitions[d.index()];
        if !p.found {
            continue;
        }
        if p.fstype.is_none() {
            p.fstype = probe_filesystem(fd, &p.node, p.offset, p.size)?;
        }
        let found = if p.fstype.as_deref() == Some(b"crypto_LUKS") {
            m.encrypted = true;
            let integrity = partition_is_luks2_integrity(fd, p.offset, p.size)?;
            ip::UNUSED | if integrity { ip::ENCRYPTEDWITHINTEGRITY } else { ip::ENCRYPTED }
        } else {
            ip::UNUSED | ip::UNPROTECTED | ip::VERITY | ip::SIGNED
        };
        if p.fstype.as_deref().is_some_and(fstype_is_ro) {
            p.rw = false;
        }
        if !p.rw {
            p.growfs = false;
        }
        image_policy_check_protection(policy, d, found)?;
    }
    Ok(())
}

/// `dissect_loop_device(loop, verity, NULL, policy, filter, flags, &ret)`.
pub fn dissect_loop_device(
    lp: &LoopDevice,
    verity: &VeritySettings,
    policy: &ImagePolicy,
    filter: Option<&ImageFilter>,
) -> Result<DissectedImage, i32> {
    // dissected_image_new(): the name only matters when it's invalid.
    let path = lp.backing_file.as_deref().unwrap_or(&lp.node);
    if let Ok(f) = crate::path::path_extract_filename(path) {
        let name = raw_strip_suffixes(&f);
        if !image_name_is_valid(&name) {
            log_debug!("Image name ", &name[..], " is not valid, ignoring.");
        }
    }
    let mut m = DissectedImage::default();
    dissect_image(&mut m, lp.fd.raw(), &lp.node, lp.sector_size, verity, policy, filter)?;
    Ok(m)
}

/// `raw_strip_suffixes()`.
fn raw_strip_suffixes(name: &[u8]) -> Vec<u8> {
    const SUFFIXES: &[&[u8]] =
        &[b".xz", b".gz", b".bz2", b".zst", b".sysext.raw", b".confext.raw", b".raw", b".qcow2", b".img", b".bin"];
    let mut q = name.to_vec();
    loop {
        let mut changed = false;
        for s in SUFFIXES {
            if q.ends_with(s) {
                q.truncate(q.len() - s.len());
                changed = true;
            }
        }
        if !changed {
            return q;
        }
    }
}

/// `image_name_is_valid()`.
fn image_name_is_valid(s: &[u8]) -> bool {
    crate::path::filename_is_valid(s)
        && !s.iter().any(|&c| c < b' ' || c == 127)
        && crate::utf8::is_valid(s)
        && !s.starts_with(b".#")
}

/// `dissect_image()` for udev's flags.
#[allow(clippy::too_many_lines)]
fn dissect_image(
    m: &mut DissectedImage,
    fd: i32,
    devname: &[u8],
    sector_size: u32,
    verity: &VeritySettings,
    policy: &ImagePolicy,
    filter: Option<&ImageFilter>,
) -> Result<(), i32> {
    const FOUND: i32 = 0;
    const NOT_FOUND: i32 = 1;
    const AMBIGUOUS: i32 = -2;
    let (mut root_uuid, mut root_verity_uuid, mut usr_uuid, mut usr_verity_uuid) =
        ([0u8; 16], [0u8; 16], [0u8; 16], [0u8; 16]);
    if !verity.root_hash.is_empty() {
        if verity.root_hash.len() < 16 {
            return Err(-libc::EINVAL);
        }
        let mut fsuuid = [0u8; 16];
        let mut vuuid = [0u8; 16];
        fsuuid.copy_from_slice(&verity.root_hash[..16]);
        vuuid.copy_from_slice(&verity.root_hash[verity.root_hash.len() - 16..]);
        if fsuuid == [0; 16] || vuuid == [0; 16] {
            return Err(-libc::EINVAL);
        }
        if verity.designator == Some(Designator::Usr) {
            usr_uuid = fsuuid;
            usr_verity_uuid = vuuid;
        } else {
            root_uuid = fsuuid;
            root_verity_uuid = vuuid;
        }
    }
    blkid::dlopen_libblkid(libc::LOG_DEBUG)?;
    let b = Probe::new().map_err(|_| -libc::ENOMEM)?;
    probe_blkid_filter(&b)?;
    b.set_device_range(fd, 0, 0).map_err(|e| if e > 0 { -e } else { -libc::ENOMEM })?;
    b.set_sectorsize(sector_size).map_err(|e| if e > 0 { -e } else { -libc::EIO })?;
    b.enable_partitions(true);
    b.set_partitions_flags(blkid::BLKID_PARTS_ENTRY_DETAILS);
    let (r, e) = b.do_safeprobe();
    if r == -1 {
        return Err(if e > 0 { -e } else { -libc::EIO });
    }
    if r == AMBIGUOUS || r == NOT_FOUND {
        return Err(log_debug_errno!(synthetic(libc::ENOPKG), "Failed to identify any partition table."));
    }
    debug_assert_eq!(r, FOUND);
    let pttype = b.lookup_value(b"PTTYPE").ok_or(-libc::ENOPKG)?;
    if pttype != b"gpt" {
        return Err(-libc::ENOPKG);
    }
    if let Some(u) = b.lookup_value(b"PTUUID")
        && let Ok(id) = crate::id128::from_string(&u)
    {
        m.image_uuid = id;
    }
    let pl = b.partitions().map_err(|e| if e > 0 { -e } else { -libc::ENOMEM })?;
    crate::sys::set_errno(0);
    let n_partitions = pl.len();
    if n_partitions < 0 {
        let e = crate::sys::errno();
        return Err(if e > 0 { -e } else { -libc::EIO });
    }
    let oops = |e: i32, d: i32| if e > 0 { -e } else { -d };
    for i in 0..n_partitions {
        let Some(pp) = pl.get(i) else { return Err(oops(crate::sys::errno(), libc::EIO)) };
        let pflags = pp.flags();
        let (nr, e) = pp.partno();
        if nr < 0 {
            return Err(oops(e, libc::EIO));
        }
        let (start, e) = pp.start();
        if start < 0 {
            return Err(oops(e, libc::EIO));
        }
        if start as u64 > i64::MAX as u64 / 512 {
            return Err(log_debug_errno!(
                synthetic(libc::EOVERFLOW),
                "Partition start LBA too large to convert to a byte offset, refusing."
            ));
        }
        let (size, e) = pp.size();
        if size < 0 {
            return Err(oops(e, libc::EIO));
        }
        if size as u64 > i64::MAX as u64 / 512 {
            return Err(log_debug_errno!(
                synthetic(libc::EOVERFLOW),
                "Partition size in LBA too large to convert to a byte offset, refusing."
            ));
        }
        if start as u64 + size as u64 > i64::MAX as u64 / 512 {
            return Err(log_debug_errno!(
                synthetic(libc::EOVERFLOW),
                "Partition end LBA too large to convert to a byte offset, refusing."
            ));
        }
        let node = partition_node_of(devname, nr);
        let id = match pp.uuid().filter(|s| !s.is_empty()).map(|s| crate::id128::from_string(&s)) {
            Some(Ok(id)) => id,
            r => {
                let r = match r {
                    Some(Err(r)) => r,
                    _ => -libc::ENXIO,
                };
                log_debug_errno!(r, "Failed to read partition UUID, ignoring: ", strerror(r));
                continue;
            }
        };
        let type_id = match pp.type_string().filter(|s| !s.is_empty()).map(|s| crate::id128::from_string(&s)) {
            Some(Ok(id)) => id,
            r => {
                let r = match r {
                    Some(Err(r)) => r,
                    _ => -libc::ENXIO,
                };
                log_debug_errno!(r, "Failed to read partition type UUID, ignoring: ", strerror(r));
                continue;
            }
        };
        let ty = gpt::gpt_partition_type_from_uuid(&type_id);
        let label = pp.name();
        if label.as_deref() == Some(b"_empty") {
            continue;
        }
        if !image_filter_test(filter, ty.designator, label.as_deref()) {
            continue;
        }
        log_debug!(
            "Dissecting ",
            ty.designator.map_or("n/a", |d| d.as_str()),
            " partition with label ",
            label.as_deref().unwrap_or(b"n/a"),
            " and UUID ",
            uuid_string(&id),
            "."
        );
        if pflags & gpt::SD_GPT_FLAG_NO_AUTO != 0 && ty.designator != Some(Designator::Esp) {
            log_debug!("Partition has 'no auto' flag set, ignoring.");
            continue;
        }
        // verity is never NULL here: udev always passes its settings.
        if let (Some(vdes), Some(vd)) = (verity.designator, ty.designator.and_then(|d| d.verity_to_data()))
            && vd != vdes
        {
            log_debug!(
                "Partition is a ",
                ty.designator.map_or("", |d| d.as_str()),
                " partition but verity was only requested for the ",
                vdes.as_str(),
                " partition, ignoring."
            );
            continue;
        }
        let mut fstype = getenv_fstype(ty.designator);
        let (mut rw, mut growfs) = (true, false);
        let all3 = gpt::SD_GPT_FLAG_NO_AUTO | gpt::SD_GPT_FLAG_READ_ONLY | gpt::SD_GPT_FLAG_GROWFS;
        match ty.designator {
            Some(Designator::Home | Designator::Srv | Designator::Xbootldr | Designator::Tmp) => {
                check_partition_flags(&node, pflags, all3);
                rw = pflags & gpt::SD_GPT_FLAG_READ_ONLY == 0;
                growfs = pflags & gpt::SD_GPT_FLAG_GROWFS != 0;
                if ty.designator == Some(Designator::Xbootldr) && fstype.is_none() {
                    fstype = Some(b"vfat".to_vec());
                }
            }
            Some(Designator::Esp) => {
                if pflags & gpt::SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL != 0 {
                    log_debug!("ESP Partition has 'no block io' flag set, ignoring.");
                    continue;
                }
                if fstype.is_none() {
                    fstype = Some(b"vfat".to_vec());
                }
            }
            Some(d @ (Designator::Root | Designator::Usr)) => {
                let expected = if d == Designator::Root { root_uuid } else { usr_uuid };
                check_partition_flags(&node, pflags, all3);
                if expected != [0; 16] && expected != id {
                    log_debug!(
                        "Partition UUID '",
                        uuid_string(&id),
                        "' does not match expected UUID '",
                        uuid_string(&expected),
                        "' derived from ",
                        d.as_str(),
                        " verity hash, ignoring."
                    );
                    continue;
                }
                rw = pflags & gpt::SD_GPT_FLAG_READ_ONLY == 0;
                growfs = pflags & gpt::SD_GPT_FLAG_GROWFS != 0;
            }
            Some(d @ (Designator::RootVerity | Designator::UsrVerity)) => {
                let expected = if d == Designator::RootVerity { root_verity_uuid } else { usr_verity_uuid };
                check_partition_flags(&node, pflags, gpt::SD_GPT_FLAG_NO_AUTO | gpt::SD_GPT_FLAG_READ_ONLY);
                m.has_verity = true;
                if expected != [0; 16] && expected != id {
                    log_debug!(
                        "Partition UUID '",
                        uuid_string(&id),
                        "' does not match expected UUID '",
                        uuid_string(&expected),
                        "' derived from ",
                        d.verity_to_data().map_or("", |x| x.as_str()),
                        " verity hash, ignoring."
                    );
                    continue;
                }
                fstype = Some(b"DM_verity_hash".to_vec());
                rw = false;
            }
            Some(Designator::RootVeritySig | Designator::UsrVeritySig) => {
                if !verity.root_hash.is_empty() {
                    let (rh, _) = acquire_sig_for_roothash(fd, start as u64 * 512, size as u64 * 512)?;
                    if rh != verity.root_hash {
                        log_debug!(
                            "Verity root hash in signature JSON data (",
                            crate::hexdecoct::hexmem(&rh),
                            ") doesn't match configured hash (",
                            crate::hexdecoct::hexmem(&verity.root_hash),
                            ")."
                        );
                        continue;
                    }
                }
                check_partition_flags(&node, pflags, gpt::SD_GPT_FLAG_NO_AUTO | gpt::SD_GPT_FLAG_READ_ONLY);
                m.has_verity_sig = true;
                fstype = Some(b"verity_hash_signature".to_vec());
                rw = false;
            }
            Some(Designator::Swap) => check_partition_flags(&node, pflags, gpt::SD_GPT_FLAG_NO_AUTO),
            None if ty.uuid == gpt::SD_GPT_LINUX_GENERIC => {
                // Only used with DISSECT_IMAGE_GENERIC_ROOT, which udev doesn't set.
                if !image_filter_test(filter, Some(Designator::Root), label.as_deref()) {
                    continue;
                }
                check_partition_flags(&node, pflags, all3);
            }
            Some(Designator::Var) => {
                check_partition_flags(&node, pflags, all3);
                let machine = crate::id128::get_machine(None)?;
                let var_uuid = crate::sha256::id128_app_specific(&machine, &gpt::SD_GPT_VAR);
                if var_uuid != id {
                    log_debug!(
                        "Found a /var/ partition, but its UUID didn't match our expectations (found: ",
                        uuid_string(&id),
                        ", expected: ",
                        uuid_string(&var_uuid),
                        "), ignoring."
                    );
                    continue;
                }
                rw = pflags & gpt::SD_GPT_FLAG_READ_ONLY == 0;
                growfs = pflags & gpt::SD_GPT_FLAG_GROWFS != 0;
            }
            None => {}
        }
        let Some(d) = ty.designator else { continue };
        if !image_policy_may_use(policy, d)? {
            if !m.partitions[d.index()].found {
                m.partitions[d.index()].ignored = true;
            }
            continue;
        }
        if m.partitions[d.index()].found {
            let prev = &m.partitions[d.index()];
            let c = compare_arch(ty.arch, prev.architecture);
            if c.is_lt() {
                continue;
            }
            if c.is_eq()
                && (!d.is_versioned()
                    || crate::string::strverscmp_improved(label.as_deref(), prev.label.as_deref()).is_le())
            {
                continue;
            }
        }
        let t = match fstype {
            Some(f) => Some(f),
            None => ip::determine_fstype(policy, d),
        };
        m.partitions[d.index()] = DissectedPartition {
            found: true,
            ignored: false,
            partno: nr,
            rw,
            growfs,
            architecture: ty.arch,
            node: partition_node_of(devname, nr),
            fstype: t,
            label,
            uuid: id,
            offset: start as u64 * 512,
            size: size as u64 * 512,
            gpt_flags: pflags,
        };
    }
    let p = |d: Designator| &m.partitions[d.index()];
    for dd in [Designator::Root, Designator::Usr] {
        let dv = dd.verity_hash_of().expect("has verity");
        let ds = dd.verity_sig_of().expect("has a signature");
        if !p(dd).found && (p(dv).found || p(ds).found) {
            return Err(log_debug_errno!(
                synthetic(libc::EADDRNOTAVAIL),
                "Found ",
                dd.as_str(),
                " verity hash partition without matching ",
                dd.as_str(),
                " data partition."
            ));
        }
        if p(ds).found && !p(dv).found {
            return Err(log_debug_errno!(
                synthetic(libc::EADDRNOTAVAIL),
                "Found ",
                dd.as_str(),
                " verity signature partition without matching ",
                dd.as_str(),
                " verity hash partition."
            ));
        }
    }
    let (root, usr) = (p(Designator::Root), p(Designator::Usr));
    if root.found
        && usr.found
        && let (Some(a), Some(b)) = (root.architecture, usr.architecture)
        && a != b
    {
        return Err(log_debug_errno!(
            synthetic(libc::EREMOTE),
            "Found root and usr partitions with different architectures (",
            a,
            " vs ",
            b,
            ")."
        ));
    }
    if p(Designator::RootVerity).found {
        if p(Designator::UsrVerity).found {
            return Err(log_debug_errno!(
                synthetic(libc::ENOTUNIQ),
                "Found both root and usr verity enabled partitions which is not supported."
            ));
        }
        if p(Designator::Usr).found {
            return Err(log_debug_errno!(
                synthetic(libc::EADDRNOTAVAIL),
                "Found verity enabled root partition with split usr partition which is not supported."
            ));
        }
    }
    if let Some(vd) = verity.designator
        && !p(vd).found
    {
        return Err(log_debug_errno!(
            synthetic(libc::EADDRNOTAVAIL),
            "Explicit ",
            vd.as_str(),
            " verity designator was specified but did not find ",
            vd.as_str(),
            " partition."
        ));
    }
    if !verity.root_hash.is_empty() {
        let d =
            if verity.designator.is_none_or(|x| x == Designator::Root) { Designator::Root } else { Designator::Usr };
        let dv = d.verity_hash_of().expect("has verity");
        if !p(d).found {
            return Err(log_debug_errno!(
                synthetic(libc::EADDRNOTAVAIL),
                "Verity enabled ",
                d.as_str(),
                " partition was requested but did not find a ",
                d.as_str(),
                " data partition."
            ));
        }
        if !p(dv).found {
            return Err(log_debug_errno!(
                synthetic(libc::EADDRNOTAVAIL),
                "Verity enabled ",
                d.as_str(),
                " partition was requested but did not find a ",
                d.as_str(),
                " verity hash partition."
            ));
        }
        m.partitions[d.index()].rw = false;
        m.verity_ready = true;
        if !verity.root_hash_sig.is_empty() {
            m.verity_sig_ready = true;
        }
    }
    for d in gpt::ALL {
        let part = &m.partitions[d.index()];
        let found_flags = if part.found {
            let mut f = ip::ENCRYPTED | ip::ENCRYPTEDWITHINTEGRITY | ip::UNPROTECTED | ip::UNUSED;
            if let Some(vi) = d.verity_hash_of()
                && m.partitions[vi.index()].found
            {
                f |= ip::VERITY;
                if let Some(si) = d.verity_sig_of()
                    && m.partitions[si.index()].found
                {
                    f |= ip::SIGNED;
                }
            }
            f
        } else if part.ignored {
            ip::UNUSED
        } else {
            ip::ABSENT
        };
        if crate::log::debug_logging() {
            let (s, _) = ip::flags_to_string(found_flags, false);
            log_debug!("Found for designator ", d.as_str(), ": ", &s[..], ".");
        }
        image_policy_check_protection(policy, d, found_flags)?;
        if part.found {
            image_policy_check_partition_flags(policy, d, part.gpt_flags)?;
        }
    }
    // DISSECT_IMAGE_ALLOW_EMPTY: no partitions at all is fine.
    probe_filesystems(m, fd, policy)
}

/// `dissected_image_load_verity_sig_partition(m, fd, verity)`.
pub fn load_verity_sig_partition(m: &mut DissectedImage, fd: i32, verity: &mut VeritySettings) -> Result<(), i32> {
    if !verity.root_hash.is_empty() && !verity.root_hash_sig.is_empty() {
        return Ok(());
    }
    match crate::env::secure_getenv_bool("SYSTEMD_DISSECT_VERITY_EMBEDDED") {
        Ok(false) => return Ok(()),
        Err(r) if r != -libc::ENXIO => {
            log_debug_errno!(r, "Failed to parse $SYSTEMD_DISSECT_VERITY_EMBEDDED, ignoring: ", strerror(r));
        }
        _ => {}
    }
    let found = |d: Designator| m.partitions[d.index()].found;
    let dd = match verity.designator {
        Some(d) => d,
        None if found(Designator::RootVerity) => Designator::Root,
        None if found(Designator::UsrVerity) => Designator::Usr,
        None => return Ok(()),
    };
    if !found(dd) || !found(dd.verity_hash_of().expect("has verity")) {
        return Ok(());
    }
    let ds = dd.verity_sig_of().expect("has a signature");
    if !found(ds) {
        return Ok(());
    }
    let p = &m.partitions[ds.index()];
    let (rh, sig) = acquire_sig_for_roothash(fd, p.offset, p.size)?;
    if !verity.root_hash.is_empty() && verity.root_hash != rh {
        return Err(log_debug_errno!(
            synthetic(libc::EINVAL),
            "Root hash in signature JSON data (",
            crate::hexdecoct::hexmem(&rh),
            ") doesn't match configured hash (",
            crate::hexdecoct::hexmem(&verity.root_hash),
            ")."
        ));
    }
    verity.root_hash = rh;
    verity.root_hash_sig = sig;
    verity.designator = Some(dd);
    m.verity_ready = true;
    m.verity_sig_ready = true;
    m.partitions[dd.index()].rw = false;
    Ok(())
}

/// `dissected_image_guess_verity_roothash(m, verity)`.
pub fn guess_verity_roothash(m: &mut DissectedImage, verity: &mut VeritySettings) {
    if !verity.root_hash.is_empty() {
        return;
    }
    match crate::env::secure_getenv_bool("SYSTEMD_DISSECT_VERITY_GUESS") {
        Ok(false) => return,
        Err(r) if r != -libc::ENXIO => {
            log_debug_errno!(r, "Failed to parse $SYSTEMD_DISSECT_VERITY_GUESS, ignoring: ", strerror(r));
        }
        _ => {}
    }
    let found = |d: Designator| m.partitions[d.index()].found;
    let dd = match verity.designator {
        Some(d) => d,
        None if found(Designator::RootVerity) => Designator::Root,
        None if found(Designator::UsrVerity) => Designator::Usr,
        None => return,
    };
    let dv = dd.verity_hash_of().expect("has verity");
    if !found(dd) || !found(dv) {
        return;
    }
    verity.root_hash = crate::bcat!(&m.partitions[dd.index()].uuid[..], &m.partitions[dv.index()].uuid[..]);
    verity.designator = Some(dd);
    m.verity_ready = true;
    m.partitions[dd.index()].rw = false;
}
