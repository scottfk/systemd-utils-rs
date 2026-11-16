// SPDX-License-Identifier: LGPL-2.1-or-later
//! `blkid-util.c`: libblkid, loaded with `dlopen()` as upstream does.  Like
//! `sys.rs`, this module holds unsafe code: the libblkid calls go through
//! function pointers.

use std::ffi::{CStr, c_char, c_int, c_ulonglong, c_void};
use std::sync::OnceLock;

use crate::sys_dl::dlopen_many;

pub const BLKID_SUBLKS_LABEL: c_int = 1 << 1;
pub const BLKID_SUBLKS_UUID: c_int = 1 << 3;
pub const BLKID_SUBLKS_TYPE: c_int = 1 << 5;
pub const BLKID_SUBLKS_SECTYPE: c_int = 1 << 6;
pub const BLKID_SUBLKS_USAGE: c_int = 1 << 7;
pub const BLKID_SUBLKS_VERSION: c_int = 1 << 8;
pub const BLKID_SUBLKS_FSINFO: c_int = 1 << 11;
pub const BLKID_FLTR_NOTIN: c_int = 1;
pub const BLKID_USAGE_RAID: c_int = 1 << 2;
pub const BLKID_PARTS_ENTRY_DETAILS: c_int = 1 << 2;

type Pr = *mut c_void;
type PartList = *mut c_void;
type Part = *mut c_void;

const SYMBOLS: &[&str] = &[
    "blkid_do_fullprobe",
    "blkid_do_probe",
    "blkid_do_safeprobe",
    "blkid_do_wipe",
    "blkid_encode_string",
    "blkid_free_probe",
    "blkid_new_probe",
    "blkid_new_probe_from_filename",
    "blkid_partition_get_flags",
    "blkid_partition_get_name",
    "blkid_partition_get_partno",
    "blkid_partition_get_size",
    "blkid_partition_get_start",
    "blkid_partition_get_type",
    "blkid_partition_get_type_string",
    "blkid_partition_get_uuid",
    "blkid_partlist_devno_to_partition",
    "blkid_partlist_get_partition",
    "blkid_partlist_numof_partitions",
    "blkid_probe_enable_partitions",
    "blkid_probe_enable_superblocks",
    "blkid_probe_filter_superblocks_type",
    "blkid_probe_filter_superblocks_usage",
    "blkid_probe_get_fd",
    "blkid_probe_get_partitions",
    "blkid_probe_get_size",
    "blkid_probe_get_value",
    "blkid_probe_is_wholedisk",
    "blkid_probe_lookup_value",
    "blkid_probe_numof_values",
    "blkid_probe_set_device",
    "blkid_probe_set_hint",
    "blkid_probe_set_partitions_flags",
    "blkid_probe_set_sectorsize",
    "blkid_probe_set_superblocks_flags",
    "blkid_safe_string",
];

#[derive(Debug)]
struct Lib {
    do_fullprobe: unsafe extern "C" fn(Pr) -> c_int,
    do_safeprobe: unsafe extern "C" fn(Pr) -> c_int,
    encode_string: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> c_int,
    free_probe: unsafe extern "C" fn(Pr),
    new_probe: unsafe extern "C" fn() -> Pr,
    partition_get_flags: unsafe extern "C" fn(Part) -> c_ulonglong,
    partition_get_name: unsafe extern "C" fn(Part) -> *const c_char,
    partition_get_type_string: unsafe extern "C" fn(Part) -> *const c_char,
    partition_get_uuid: unsafe extern "C" fn(Part) -> *const c_char,
    partlist_devno_to_partition: unsafe extern "C" fn(PartList, libc::dev_t) -> Part,
    partlist_get_partition: unsafe extern "C" fn(PartList, c_int) -> Part,
    partlist_numof_partitions: unsafe extern "C" fn(PartList) -> c_int,
    probe_enable_partitions: unsafe extern "C" fn(Pr, c_int) -> c_int,
    probe_enable_superblocks: unsafe extern "C" fn(Pr, c_int) -> c_int,
    probe_filter_superblocks_usage: unsafe extern "C" fn(Pr, c_int, c_int) -> c_int,
    probe_get_fd: unsafe extern "C" fn(Pr) -> c_int,
    probe_get_partitions: unsafe extern "C" fn(Pr) -> PartList,
    probe_get_size: unsafe extern "C" fn(Pr) -> i64,
    probe_get_value: unsafe extern "C" fn(Pr, c_int, *mut *const c_char, *mut *const c_char, *mut usize) -> c_int,
    probe_is_wholedisk: unsafe extern "C" fn(Pr) -> c_int,
    probe_lookup_value: unsafe extern "C" fn(Pr, *const c_char, *mut *const c_char, *mut usize) -> c_int,
    probe_numof_values: unsafe extern "C" fn(Pr) -> c_int,
    probe_set_device: unsafe extern "C" fn(Pr, c_int, i64, i64) -> c_int,
    probe_set_hint: unsafe extern "C" fn(Pr, *const c_char, u64) -> c_int,
    probe_set_partitions_flags: unsafe extern "C" fn(Pr, c_int) -> c_int,
    probe_set_superblocks_flags: unsafe extern "C" fn(Pr, c_int) -> c_int,
    safe_string: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> c_int,
}

static LIB: OnceLock<Result<Lib, i32>> = OnceLock::new();

/// `dlopen_libblkid(log_level)`: only the first call logs, as in C.
pub fn dlopen_libblkid(log_level: i32) -> Result<(), i32> {
    lib_at(log_level).map(|_| ())
}

fn lib_at(log_level: i32) -> Result<&'static Lib, i32> {
    let r = LIB.get_or_init(|| {
        let s = dlopen_many("libblkid.so.1", SYMBOLS, log_level)?;
        let f = |n: &str| s[SYMBOLS.iter().position(|x| *x == n).expect("listed")].0;
        // SAFETY: each symbol is the libblkid function with the signature
        // declared in Lib.
        #[allow(clippy::missing_transmute_annotations)]
        Ok(unsafe {
            Lib {
                do_fullprobe: std::mem::transmute(f("blkid_do_fullprobe")),
                do_safeprobe: std::mem::transmute(f("blkid_do_safeprobe")),
                encode_string: std::mem::transmute(f("blkid_encode_string")),
                free_probe: std::mem::transmute(f("blkid_free_probe")),
                new_probe: std::mem::transmute(f("blkid_new_probe")),
                partition_get_flags: std::mem::transmute(f("blkid_partition_get_flags")),
                partition_get_name: std::mem::transmute(f("blkid_partition_get_name")),
                partition_get_type_string: std::mem::transmute(f("blkid_partition_get_type_string")),
                partition_get_uuid: std::mem::transmute(f("blkid_partition_get_uuid")),
                partlist_devno_to_partition: std::mem::transmute(f("blkid_partlist_devno_to_partition")),
                partlist_get_partition: std::mem::transmute(f("blkid_partlist_get_partition")),
                partlist_numof_partitions: std::mem::transmute(f("blkid_partlist_numof_partitions")),
                probe_enable_partitions: std::mem::transmute(f("blkid_probe_enable_partitions")),
                probe_enable_superblocks: std::mem::transmute(f("blkid_probe_enable_superblocks")),
                probe_filter_superblocks_usage: std::mem::transmute(f("blkid_probe_filter_superblocks_usage")),
                probe_get_fd: std::mem::transmute(f("blkid_probe_get_fd")),
                probe_get_partitions: std::mem::transmute(f("blkid_probe_get_partitions")),
                probe_get_size: std::mem::transmute(f("blkid_probe_get_size")),
                probe_get_value: std::mem::transmute(f("blkid_probe_get_value")),
                probe_is_wholedisk: std::mem::transmute(f("blkid_probe_is_wholedisk")),
                probe_lookup_value: std::mem::transmute(f("blkid_probe_lookup_value")),
                probe_numof_values: std::mem::transmute(f("blkid_probe_numof_values")),
                probe_set_device: std::mem::transmute(f("blkid_probe_set_device")),
                probe_set_hint: std::mem::transmute(f("blkid_probe_set_hint")),
                probe_set_partitions_flags: std::mem::transmute(f("blkid_probe_set_partitions_flags")),
                probe_set_superblocks_flags: std::mem::transmute(f("blkid_probe_set_superblocks_flags")),
                safe_string: std::mem::transmute(f("blkid_safe_string")),
            }
        })
    });
    r.as_ref().map_err(|e| *e)
}

fn lib() -> &'static Lib {
    lib_at(libc::LOG_DEBUG).expect("dlopen_libblkid() succeeded before")
}

fn opt_cstr(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: libblkid returns NUL-terminated strings.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

fn errno() -> i32 {
    crate::sys::errno()
}

/// Calls `f(src, buf, len)` into a buffer of `len` bytes: the string up to
/// the NUL.
fn into_buf(f: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> c_int, s: &[u8], len: usize) -> Vec<u8> {
    let c = crate::bytes::to_cstring(s);
    let mut buf = vec![0u8; len];
    // SAFETY: buf is valid for len bytes; c is NUL-terminated.
    unsafe { f(c.as_ptr(), buf.as_mut_ptr().cast(), len) };
    let n = buf.iter().position(|&b| b == 0).unwrap_or(len);
    buf.truncate(n);
    buf
}

/// `blkid_safe_string(s, buf, len)`.
pub fn safe_string(s: &[u8], len: usize) -> Vec<u8> {
    into_buf(lib().safe_string, s, len)
}

/// `blkid_encode_string(s, buf, len)`.
pub fn encode_string(s: &[u8], len: usize) -> Vec<u8> {
    into_buf(lib().encode_string, s, len)
}

/// A `blkid_probe`, freed on drop.
#[derive(Debug)]
pub struct Probe(Pr);

impl Drop for Probe {
    fn drop(&mut self) {
        // SAFETY: self.0 is a live probe.
        unsafe { (lib().free_probe)(self.0) };
    }
}

/// A partition of a probe's partition list.
#[derive(Debug, Clone, Copy)]
pub struct Partition(Part);

impl Partition {
    /// `blkid_partition_get_uuid()`.
    pub fn uuid(&self) -> Option<Vec<u8>> {
        // SAFETY: the partition lives as long as its probe.
        opt_cstr(unsafe { (lib().partition_get_uuid)(self.0) })
    }
    /// `blkid_partition_get_type_string()`.
    pub fn type_string(&self) -> Option<Vec<u8>> {
        // SAFETY: as above.
        opt_cstr(unsafe { (lib().partition_get_type_string)(self.0) })
    }
    /// `blkid_partition_get_name()`.
    pub fn name(&self) -> Option<Vec<u8>> {
        // SAFETY: as above.
        opt_cstr(unsafe { (lib().partition_get_name)(self.0) })
    }
    /// `blkid_partition_get_flags()`.
    pub fn flags(&self) -> u64 {
        // SAFETY: as above.
        unsafe { (lib().partition_get_flags)(self.0) }
    }
}

/// A probe's partition list.
#[derive(Debug, Clone, Copy)]
pub struct PartitionList(PartList);

impl PartitionList {
    /// `blkid_partlist_devno_to_partition()`.
    pub fn devno_to_partition(&self, devno: u64) -> Option<Partition> {
        // SAFETY: the list lives as long as its probe.
        let p = unsafe { (lib().partlist_devno_to_partition)(self.0, devno as libc::dev_t) };
        (!p.is_null()).then_some(Partition(p))
    }
    /// `blkid_partlist_numof_partitions()`.
    pub fn len(&self) -> i32 {
        // SAFETY: as above.
        unsafe { (lib().partlist_numof_partitions)(self.0) }
    }
    /// Whether there are no partitions.
    pub fn is_empty(&self) -> bool {
        self.len() <= 0
    }
    /// `blkid_partlist_get_partition()`.
    pub fn get(&self, i: i32) -> Option<Partition> {
        // SAFETY: as above.
        let p = unsafe { (lib().partlist_get_partition)(self.0, i) };
        (!p.is_null()).then_some(Partition(p))
    }
}

impl Probe {
    /// `blkid_new_probe()`: Err(errno) on failure (0 if unset).
    pub fn new() -> Result<Probe, i32> {
        crate::sys::set_errno(0);
        // SAFETY: plain constructor.
        let p = unsafe { (lib().new_probe)() };
        if p.is_null() { Err(errno()) } else { Ok(Probe(p)) }
    }
    /// `blkid_probe_set_hint(pr, name, 0)`: Err(errno) on failure.
    pub fn set_hint(&self, name: &[u8]) -> Result<(), i32> {
        let c = crate::bytes::to_cstring(name);
        crate::sys::set_errno(0);
        // SAFETY: live probe, NUL-terminated name.
        if unsafe { (lib().probe_set_hint)(self.0, c.as_ptr(), 0) } < 0 { Err(errno()) } else { Ok(()) }
    }
    /// `blkid_probe_set_superblocks_flags()`.
    pub fn set_superblocks_flags(&self, flags: c_int) {
        // SAFETY: live probe.
        unsafe { (lib().probe_set_superblocks_flags)(self.0, flags) };
    }
    /// `blkid_probe_filter_superblocks_usage()`.
    pub fn filter_superblocks_usage(&self, flag: c_int, usage: c_int) {
        // SAFETY: live probe.
        unsafe { (lib().probe_filter_superblocks_usage)(self.0, flag, usage) };
    }
    /// `blkid_probe_set_device(pr, fd, offset, 0)`: Err(errno) on failure.
    pub fn set_device(&self, fd: i32, offset: i64) -> Result<(), i32> {
        crate::sys::set_errno(0);
        // SAFETY: live probe; fd stays open while the probe is used.
        if unsafe { (lib().probe_set_device)(self.0, fd, offset, 0) } < 0 { Err(errno()) } else { Ok(()) }
    }
    /// `blkid_probe_get_fd()`.
    pub fn fd(&self) -> i32 {
        // SAFETY: live probe.
        unsafe { (lib().probe_get_fd)(self.0) }
    }
    /// `blkid_probe_enable_partitions()`.
    pub fn enable_partitions(&self, on: bool) {
        // SAFETY: live probe.
        unsafe { (lib().probe_enable_partitions)(self.0, on as c_int) };
    }
    /// `blkid_probe_enable_superblocks()`.
    pub fn enable_superblocks(&self, on: bool) {
        // SAFETY: live probe.
        unsafe { (lib().probe_enable_superblocks)(self.0, on as c_int) };
    }
    /// `blkid_probe_set_partitions_flags()`.
    pub fn set_partitions_flags(&self, flags: c_int) {
        // SAFETY: live probe.
        unsafe { (lib().probe_set_partitions_flags)(self.0, flags) };
    }
    /// `blkid_probe_get_size()`.
    pub fn size(&self) -> i64 {
        // SAFETY: live probe.
        unsafe { (lib().probe_get_size)(self.0) }
    }
    /// `blkid_probe_is_wholedisk()`.
    pub fn is_wholedisk(&self) -> bool {
        // SAFETY: live probe.
        unsafe { (lib().probe_is_wholedisk)(self.0) != 0 }
    }
    /// `blkid_do_fullprobe()`, with errno reset first: (rc, errno).
    pub fn do_fullprobe(&self) -> (i32, i32) {
        crate::sys::set_errno(0);
        // SAFETY: live probe.
        let rc = unsafe { (lib().do_fullprobe)(self.0) };
        (rc, errno())
    }
    /// `blkid_do_safeprobe()`, with errno reset first: (rc, errno).
    pub fn do_safeprobe(&self) -> (i32, i32) {
        crate::sys::set_errno(0);
        // SAFETY: live probe.
        let rc = unsafe { (lib().do_safeprobe)(self.0) };
        (rc, errno())
    }
    /// `blkid_probe_lookup_value(pr, name, &data, NULL)`.
    pub fn lookup_value(&self, name: &[u8]) -> Option<Vec<u8>> {
        let c = crate::bytes::to_cstring(name);
        let mut data: *const c_char = std::ptr::null();
        // SAFETY: live probe, NUL-terminated name, valid out-pointer.
        if unsafe { (lib().probe_lookup_value)(self.0, c.as_ptr(), &mut data, std::ptr::null_mut()) } != 0 {
            return None;
        }
        Some(opt_cstr(data).unwrap_or_default())
    }
    /// `blkid_probe_numof_values()`: Err(errno) when negative.
    pub fn numof_values(&self) -> Result<i32, i32> {
        crate::sys::set_errno(0);
        // SAFETY: live probe.
        let n = unsafe { (lib().probe_numof_values)(self.0) };
        if n < 0 { Err(errno()) } else { Ok(n) }
    }
    /// `blkid_probe_get_value(pr, i, &name, &data, NULL)`.
    pub fn value(&self, i: i32) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut name: *const c_char = std::ptr::null();
        let mut data: *const c_char = std::ptr::null();
        // SAFETY: live probe, valid out-pointers.
        if unsafe { (lib().probe_get_value)(self.0, i, &mut name, &mut data, std::ptr::null_mut()) } < 0 {
            return None;
        }
        Some((opt_cstr(name).unwrap_or_default(), opt_cstr(data).unwrap_or_default()))
    }
    /// `blkid_probe_get_partitions()`: Err(errno) on failure.
    pub fn partitions(&self) -> Result<PartitionList, i32> {
        crate::sys::set_errno(0);
        // SAFETY: live probe; the list is owned by it.
        let l = unsafe { (lib().probe_get_partitions)(self.0) };
        if l.is_null() { Err(errno()) } else { Ok(PartitionList(l)) }
    }
}
