// SPDX-License-Identifier: LGPL-2.1-or-later
//! `libudev.so.1`: a port of systemd's `src/libudev` (v262), the C ABI on
//! top of `shared::sd_device`, `shared::device_enumerator`,
//! `shared::device_monitor` and `shared::hwdb`.
//!
//! Every object is a heap allocation whose pointer the caller holds, with
//! C's reference counting.  Like C, the strings returned stay valid until
//! the object drops or replaces them, and failures set `errno`.  An
//! `assert_return()` that fails logs (at debug level) the same message as C,
//! C's source location included.
//!
//! This is the `extern "C"` surface, so it dereferences the caller's
//! pointers; that's the only `unsafe` here.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

mod device;
mod list;

use std::ffi::{CStr, c_char, c_int, c_uint, c_ulonglong, c_void};
use std::ptr;

use shared::device_enumerator::{Enumerator, MatchInitialized};
use shared::device_monitor::{Monitor, MonitorGroup};
use shared::hwdb::Hwdb;
use shared::log::{log_assert_failed, log_assert_failed_return, log_get_max_level, log_set_max_level};
use shared::sys::set_errno;

pub use device::udev_device;
use list::{UdevList, UdevListEntry};

/// `assert_return(expr, r)` with C's location: (text, file, line, function).
macro_rules! assert_return {
    ($cond:expr, $text:expr, $file:expr, $line:expr, $func:expr, $ret:expr) => {
        if !$cond {
            log_assert_failed_return($text, $file, $line, $func);
            return $ret;
        }
    };
}
pub(crate) use assert_return;

/// `assert_return_errno(expr, r, err)`.
macro_rules! assert_return_errno {
    ($cond:expr, $text:expr, $file:expr, $line:expr, $func:expr, $ret:expr, $err:expr) => {
        if !$cond {
            log_assert_failed_return($text, $file, $line, $func);
            shared::sys::set_errno($err);
            return $ret;
        }
    };
}
pub(crate) use assert_return_errno;

/// `return_with_errno(r, err)`.
pub(crate) fn with_errno<T>(r: T, err: i32) -> T {
    set_errno(shared::errno::errno_value(err));
    r
}

/// A C string argument, or None for NULL.
///
/// # Safety
/// `p` is NULL or a NUL-terminated string.
pub(crate) unsafe fn opt_str<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller passes a valid C string.
        Some(unsafe { CStr::from_ptr(p) }.to_bytes())
    }
}

/// The reference-count checks of `DEFINE_TRIVIAL_REF_FUNC()`.
pub(crate) fn ref_inc(n: &mut c_uint, file: &'static str, line: u32, func: &'static str) {
    if *n == 0 {
        log_assert_failed("*q > 0", file, line, func);
    }
    if *n == c_uint::MAX {
        log_assert_failed("*q < UINT_MAX", file, line, func);
    }
    *n += 1;
}

pub(crate) fn ref_dec(n: &mut c_uint, file: &'static str, line: u32, func: &'static str) -> bool {
    if *n == 0 {
        log_assert_failed("p->n_ref > 0", file, line, func);
    }
    *n -= 1;
    *n == 0
}

// libudev.c

/// `struct udev`.
#[derive(Debug)]
pub struct udev {
    n_ref: c_uint,
    userdata: *mut c_void,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_get_userdata(udev: *mut udev) -> *mut c_void {
    assert_return!(!udev.is_null(), "udev", "src/libudev/libudev.c", 36, "udev_get_userdata", ptr::null_mut());
    // SAFETY: a live udev.
    unsafe { (*udev).userdata }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_set_userdata(udev: *mut udev, userdata: *mut c_void) {
    if udev.is_null() {
        return;
    }
    // SAFETY: a live udev.
    unsafe { (*udev).userdata = userdata };
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_new() -> *mut udev {
    Box::into_raw(Box::new(udev { n_ref: 1, userdata: ptr::null_mut() }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_ref(udev: *mut udev) -> *mut udev {
    if udev.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live udev.
    ref_inc(unsafe { &mut (*udev).n_ref }, "src/libudev/libudev.c", 87, "udev_ref");
    udev
}

/// Unlike the other unrefs, returns the object while references remain.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_unref(udev: *mut udev) -> *mut udev {
    if udev.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live udev.
    unsafe {
        if (*udev).n_ref == 0 {
            log_assert_failed("udev->n_ref > 0", "src/libudev/libudev.c", 102, "udev_unref");
        }
        (*udev).n_ref -= 1;
        if (*udev).n_ref > 0 {
            return udev;
        }
        drop(Box::from_raw(udev));
    }
    ptr::null_mut()
}

/// A no-op, as in C (the callback's `va_list` is never used).
#[unsafe(no_mangle)]
pub extern "C" fn udev_set_log_fn(_udev: *mut udev, _log_fn: *const c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn udev_get_log_priority(_udev: *mut udev) -> c_int {
    log_get_max_level()
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_set_log_priority(_udev: *mut udev, priority: c_int) {
    if !(priority == -1 || (0..=7).contains(&priority)) {
        log_assert_failed(
            "level == LOG_NULL || log_level_is_valid(level)",
            "src/basic/log.c",
            379,
            "log_set_max_level",
        );
    }
    log_set_max_level(priority);
}

// libudev-list.c

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_list_entry_get_next(e: *mut UdevListEntry) -> *mut UdevListEntry {
    // SAFETY: the caller passes NULL or a live entry.
    unsafe { list::entry_get_next(e) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_list_entry_get_by_name(e: *mut UdevListEntry, name: *const c_char) -> *mut UdevListEntry {
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller passes a live entry and a C string.
    unsafe {
        let Some(name) = opt_str(name) else {
            return ptr::null_mut();
        };
        list::entry_get_by_name(e, name)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_list_entry_get_name(e: *mut UdevListEntry) -> *const c_char {
    // SAFETY: the caller passes NULL or a live entry.
    unsafe { list::entry_get_name(e) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_list_entry_get_value(e: *mut UdevListEntry) -> *const c_char {
    // SAFETY: the caller passes NULL or a live entry.
    unsafe { list::entry_get_value(e) }
}

// libudev-util.c

/// `allow_listed_char_for_devnode(c, NULL)`.
fn allow_listed_char_for_devnode(c: u8) -> bool {
    c.is_ascii_digit() || c.is_ascii_alphabetic() || b"#+-.:=@_".contains(&c)
}

/// `udev_util_encode_string()` (`encode_devnode_name()`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_util_encode_string(s: *const c_char, str_enc: *mut c_char, len: usize) -> c_int {
    if s.is_null() || str_enc.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: s is a C string; str_enc has room for len bytes, and only
    // indices below len are written.
    unsafe {
        let src = CStr::from_ptr(s).to_bytes_with_nul();
        let out = str_enc as *mut u8;
        let mut j = 0usize;
        let mut i = 0usize;
        while src[i] != 0 {
            let seqlen = shared::utf8::encoded_valid_unichar(&src[i..]).unwrap_or(0);
            if seqlen > 1 {
                if len - j < seqlen {
                    return -libc::EINVAL;
                }
                ptr::copy_nonoverlapping(src.as_ptr().add(i), out.add(j), seqlen);
                j += seqlen;
                i += seqlen - 1;
            } else if src[i] == b'\\' || !allow_listed_char_for_devnode(src[i]) {
                if len - j < 5 {
                    return -libc::EINVAL;
                }
                let hex = format!("\\x{:02x}\0", src[i]);
                ptr::copy_nonoverlapping(hex.as_ptr(), out.add(j), 5);
                j += 4;
            } else {
                if len - j < 1 {
                    return -libc::EINVAL;
                }
                *out.add(j) = src[i];
                j += 1;
            }
            i += 1;
        }
        if len - j < 1 {
            return -libc::EINVAL;
        }
        *out.add(j) = 0;
    }
    0
}

// libudev-enumerate.c

/// `struct udev_enumerate`.
#[derive(Debug)]
pub struct udev_enumerate {
    udev: *mut udev,
    n_ref: c_uint,
    devices_list: UdevList,
    devices_uptodate: bool,
    enumerator: Enumerator,
}

const ENUMERATE_C: &str = "src/libudev/libudev-enumerate.c";

#[unsafe(no_mangle)]
pub extern "C" fn udev_enumerate_new(udev: *mut udev) -> *mut udev_enumerate {
    let mut e = Enumerator::new();
    e.allow_uninitialized();
    Box::into_raw(Box::new(udev_enumerate {
        udev,
        n_ref: 1,
        devices_list: UdevList::new(false),
        devices_uptodate: false,
        enumerator: e,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_ref(e: *mut udev_enumerate) -> *mut udev_enumerate {
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object.
    ref_inc(unsafe { &mut (*e).n_ref }, ENUMERATE_C, 100, "udev_enumerate_ref");
    e
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_unref(e: *mut udev_enumerate) -> *mut udev_enumerate {
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object; freed when the last reference goes.
    unsafe {
        if ref_dec(&mut (*e).n_ref, ENUMERATE_C, 100, "udev_enumerate_unref") {
            drop(Box::from_raw(e));
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_get_udev(e: *mut udev_enumerate) -> *mut udev {
    assert_return_errno!(
        !e.is_null(),
        "udev_enumerate",
        "src/libudev/libudev-enumerate.c",
        111,
        "udev_enumerate_get_udev",
        ptr::null_mut(),
        libc::EINVAL
    );
    // SAFETY: a live object.
    unsafe { (*e).udev }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_get_list_entry(e: *mut udev_enumerate) -> *mut UdevListEntry {
    assert_return_errno!(
        !e.is_null(),
        "udev_enumerate",
        "src/libudev/libudev-enumerate.c",
        127,
        "udev_enumerate_get_list_entry",
        ptr::null_mut(),
        libc::EINVAL
    );
    // SAFETY: a live object.
    let e = unsafe { &mut *e };
    if !e.devices_uptodate {
        e.devices_list.cleanup();
        let mut d = e.enumerator.get_first();
        while let Some(dev) = d {
            e.devices_list.add(dev.get_syspath().bytes(), None);
            d = e.enumerator.get_next();
        }
        e.devices_uptodate = true;
    }
    let l = e.devices_list.get_entry();
    if l.is_null() {
        return with_errno(ptr::null_mut(), libc::ENODATA);
    }
    l
}

/// The body shared by the `udev_enumerate_add_*()` functions: the argument
/// check (NULL is a no-op), then the change.
macro_rules! enumerate_add {
    ($name:ident, $line:literal, |$en:ident $(, $arg:ident: $ty:ty)*| $body:block) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(e: *mut udev_enumerate, $($arg: $ty),*) -> c_int {
            assert_return!(!e.is_null(), "udev_enumerate", "src/libudev/libudev-enumerate.c", $line, stringify!($name), -libc::EINVAL);
            // SAFETY: a live object; string arguments are C strings or NULL.
            let e = unsafe { &mut *e };
            let $en = &mut e.enumerator;
            let r: c_int = $body;
            if r < 0 {
                return r;
            }
            e.devices_uptodate = false;
            0
        }
    };
}

enumerate_add!(udev_enumerate_add_match_subsystem, 168, |en, subsystem: *const c_char| {
    // SAFETY: NULL or a C string.
    let Some(s) = (unsafe { opt_str(subsystem) }) else { return 0 };
    en.add_match_subsystem(s, true);
    0
});

enumerate_add!(udev_enumerate_add_nomatch_subsystem, 193, |en, subsystem: *const c_char| {
    // SAFETY: NULL or a C string.
    let Some(s) = (unsafe { opt_str(subsystem) }) else { return 0 };
    en.add_match_subsystem(s, false);
    0
});

enumerate_add!(udev_enumerate_add_match_sysattr, 219, |en, sysattr: *const c_char, value: *const c_char| {
    // SAFETY: NULL or C strings.
    let Some(s) = (unsafe { opt_str(sysattr) }) else { return 0 };
    // SAFETY: NULL or a C string.
    en.add_match_sysattr(s, unsafe { opt_str(value) }, true);
    0
});

enumerate_add!(udev_enumerate_add_nomatch_sysattr, 245, |en, sysattr: *const c_char, value: *const c_char| {
    // SAFETY: NULL or C strings.
    let Some(s) = (unsafe { opt_str(sysattr) }) else { return 0 };
    // SAFETY: NULL or a C string.
    en.add_match_sysattr(s, unsafe { opt_str(value) }, false);
    0
});

enumerate_add!(udev_enumerate_add_match_property, 271, |en, property: *const c_char, value: *const c_char| {
    // SAFETY: NULL or C strings.
    let Some(p) = (unsafe { opt_str(property) }) else { return 0 };
    // SAFETY: NULL or a C string.
    en.add_match_property(p, unsafe { opt_str(value) });
    0
});

enumerate_add!(udev_enumerate_add_match_tag, 296, |en, tag: *const c_char| {
    // SAFETY: NULL or a C string.
    let Some(t) = (unsafe { opt_str(tag) }) else { return 0 };
    en.add_match_tag(t);
    0
});

enumerate_add!(udev_enumerate_add_match_parent, 322, |en, parent: *mut udev_device| {
    if parent.is_null() {
        return 0;
    }
    // SAFETY: a live udev_device.
    en.add_match_parent(unsafe { &(*parent).device });
    0
});

enumerate_add!(udev_enumerate_add_match_is_initialized, 356, |en| {
    en.add_match_is_initialized(MatchInitialized::Compat);
    0
});

enumerate_add!(udev_enumerate_add_match_sysname, 378, |en, sysname: *const c_char| {
    // SAFETY: NULL or a C string.
    let Some(s) = (unsafe { opt_str(sysname) }) else { return 0 };
    en.add_match_sysname(s, true);
    0
});

enumerate_add!(udev_enumerate_add_syspath, 404, |en, syspath: *const c_char| {
    // SAFETY: NULL or a C string.
    let Some(s) = (unsafe { opt_str(syspath) }) else { return 0 };
    match shared::sd_device::Device::new_from_syspath(s) {
        Err(r) => return r,
        Ok(d) => {
            en.add_device(&d);
        }
    }
    0
});

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_scan_devices(e: *mut udev_enumerate) -> c_int {
    assert_return!(
        !e.is_null(),
        "udev_enumerate",
        "src/libudev/libudev-enumerate.c",
        431,
        "udev_enumerate_scan_devices",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    unsafe { (*e).enumerator.scan_devices() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_enumerate_scan_subsystems(e: *mut udev_enumerate) -> c_int {
    assert_return!(
        !e.is_null(),
        "udev_enumerate",
        "src/libudev/libudev-enumerate.c",
        445,
        "udev_enumerate_scan_subsystems",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    unsafe { (*e).enumerator.scan_subsystems() }
}

// libudev-hwdb.c

/// `struct udev_hwdb`.
#[derive(Debug)]
pub struct udev_hwdb {
    n_ref: c_uint,
    hwdb: Hwdb,
    properties_list: UdevList,
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_hwdb_new(_udev: *mut udev) -> *mut udev_hwdb {
    match Hwdb::new() {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(h) => Box::into_raw(Box::new(udev_hwdb { n_ref: 1, hwdb: h, properties_list: UdevList::new(true) })),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_hwdb_ref(h: *mut udev_hwdb) -> *mut udev_hwdb {
    if h.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object.
    ref_inc(unsafe { &mut (*h).n_ref }, "src/libudev/libudev-hwdb.c", 88, "udev_hwdb_ref");
    h
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_hwdb_unref(h: *mut udev_hwdb) -> *mut udev_hwdb {
    if h.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object; freed when the last reference goes.
    unsafe {
        if ref_dec(&mut (*h).n_ref, "src/libudev/libudev-hwdb.c", 88, "udev_hwdb_unref") {
            drop(Box::from_raw(h));
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_hwdb_get_properties_list_entry(
    h: *mut udev_hwdb,
    modalias: *const c_char,
    _flags: c_uint,
) -> *mut UdevListEntry {
    assert_return_errno!(
        !h.is_null(),
        "hwdb",
        "src/libudev/libudev-hwdb.c",
        107,
        "udev_hwdb_get_properties_list_entry",
        ptr::null_mut(),
        libc::EINVAL
    );
    assert_return_errno!(
        !modalias.is_null(),
        "modalias",
        "src/libudev/libudev-hwdb.c",
        108,
        "udev_hwdb_get_properties_list_entry",
        ptr::null_mut(),
        libc::EINVAL
    );
    // SAFETY: a live object and a C string.
    let (h, modalias) = unsafe { (&mut *h, CStr::from_ptr(modalias).to_bytes()) };
    h.properties_list.cleanup();
    for (k, v) in h.hwdb.properties(modalias) {
        h.properties_list.add(&k, Some(&v));
    }
    let e = h.properties_list.get_entry();
    if e.is_null() {
        return with_errno(ptr::null_mut(), libc::ENODATA);
    }
    e
}

// libudev-monitor.c

/// `struct udev_monitor`.
#[derive(Debug)]
pub struct udev_monitor {
    udev: *mut udev,
    n_ref: c_uint,
    monitor: Monitor,
}

const MONITOR_C: &str = "src/libudev/libudev-monitor.c";

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_new_from_netlink(udev: *mut udev, name: *const c_char) -> *mut udev_monitor {
    // SAFETY: NULL or a C string.
    let g = match unsafe { opt_str(name) } {
        None => MonitorGroup::None,
        Some(b"udev") => MonitorGroup::Udev,
        Some(b"kernel") => MonitorGroup::Kernel,
        Some(_) => return with_errno(ptr::null_mut(), libc::EINVAL),
    };
    match Monitor::new_full(g) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(m) => Box::into_raw(Box::new(udev_monitor { udev, n_ref: 1, monitor: m })),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_filter_update(m: *mut udev_monitor) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        102,
        "udev_monitor_filter_update",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    match unsafe { (*m).monitor.filter_update() } {
        Ok(()) => 0,
        Err(r) => r,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_enable_receiving(m: *mut udev_monitor) -> c_int {
    // SAFETY: passed through.
    unsafe { udev_monitor_filter_update(m) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_set_receive_buffer_size(m: *mut udev_monitor, size: c_int) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        130,
        "udev_monitor_set_receive_buffer_size",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    match unsafe { (*m).monitor.set_receive_buffer_size(size as usize) } {
        Ok(b) => b as c_int,
        Err(r) => r,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_ref(m: *mut udev_monitor) -> *mut udev_monitor {
    if m.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object.
    ref_inc(unsafe { &mut (*m).n_ref }, MONITOR_C, 161, "udev_monitor_ref");
    m
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_unref(m: *mut udev_monitor) -> *mut udev_monitor {
    if m.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object; freed when the last reference goes.
    unsafe {
        if ref_dec(&mut (*m).n_ref, MONITOR_C, 161, "udev_monitor_unref") {
            drop(Box::from_raw(m));
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_get_udev(m: *mut udev_monitor) -> *mut udev {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        172,
        "udev_monitor_get_udev",
        ptr::null_mut()
    );
    // SAFETY: a live object.
    unsafe { (*m).udev }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_get_fd(m: *mut udev_monitor) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        186,
        "udev_monitor_get_fd",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    unsafe { (*m).monitor.get_fd() }
}

/// `udev_monitor_receive_sd_device()`.
fn receive_sd_device(m: &mut udev_monitor) -> Result<shared::sd_device::Dev, i32> {
    loop {
        match m.monitor.receive() {
            Err(r) => return Err(r),
            Ok(Some(d)) => return Ok(d),
            Ok(None) => {}
        }
        loop {
            match shared::sys_net::poll_one(m.monitor.get_fd(), libc::POLLIN, 0) {
                Err(r) if r == -libc::EINTR => continue,
                Err(r) => return Err(r),
                Ok(0) => return Err(-libc::EAGAIN),
                Ok(_) => break,
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_receive_device(m: *mut udev_monitor) -> *mut udev_device {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        242,
        "udev_monitor_receive_device",
        ptr::null_mut()
    );
    // SAFETY: a live object.
    let m = unsafe { &mut *m };
    match receive_sd_device(m) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => device::udev_device_new(m.udev, d),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_filter_add_match_subsystem_devtype(
    m: *mut udev_monitor,
    subsystem: *const c_char,
    devtype: *const c_char,
) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        267,
        "udev_monitor_filter_add_match_subsystem_devtype",
        -libc::EINVAL
    );
    // SAFETY: NULL or C strings.
    let Some(s) = (unsafe { opt_str(subsystem) }) else {
        log_assert_failed_return(
            "subsystem",
            "src/libsystemd/sd-device/device-monitor.c",
            891,
            "sd_device_monitor_filter_add_match_subsystem_devtype",
        );
        return -libc::EINVAL;
    };
    // SAFETY: a live object; devtype is NULL or a C string.
    unsafe { (*m).monitor.filter_add_match_subsystem_devtype(s, opt_str(devtype)) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_filter_add_match_tag(m: *mut udev_monitor, tag: *const c_char) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        288,
        "udev_monitor_filter_add_match_tag",
        -libc::EINVAL
    );
    // SAFETY: NULL or a C string.
    let Some(t) = (unsafe { opt_str(tag) }) else {
        log_assert_failed_return(
            "tag",
            "src/libsystemd/sd-device/device-monitor.c",
            907,
            "sd_device_monitor_filter_add_match_tag",
        );
        return -libc::EINVAL;
    };
    // SAFETY: a live object.
    unsafe { (*m).monitor.filter_add_match_tag(t) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_monitor_filter_remove(m: *mut udev_monitor) -> c_int {
    assert_return!(
        !m.is_null(),
        "udev_monitor",
        "src/libudev/libudev-monitor.c",
        303,
        "udev_monitor_filter_remove",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    match unsafe { (*m).monitor.filter_remove() } {
        Ok(()) => 0,
        Err(r) => r,
    }
}

// libudev-queue.c

/// `struct udev_queue`.
#[derive(Debug)]
pub struct udev_queue {
    udev: *mut udev,
    n_ref: c_uint,
    fd: c_int,
}

const QUEUE_C: &str = "src/libudev/libudev-queue.c";

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_new(udev: *mut udev) -> *mut udev_queue {
    Box::into_raw(Box::new(udev_queue { udev, n_ref: 1, fd: -libc::EBADF }))
}

/// `udev_queue_is_empty()`.
fn udev_queue_is_empty() -> c_int {
    match shared::sys_net::access(b"/run/udev/queue", libc::F_OK) {
        Ok(()) => 0,
        Err(e) if e == -libc::ENOENT => 1,
        Err(e) => e,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_queue_ref(q: *mut udev_queue) -> *mut udev_queue {
    if q.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object.
    ref_inc(unsafe { &mut (*q).n_ref }, QUEUE_C, 89, "udev_queue_ref");
    q
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_queue_unref(q: *mut udev_queue) -> *mut udev_queue {
    if q.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object; freed (and its fd closed) with the last reference.
    unsafe {
        if ref_dec(&mut (*q).n_ref, QUEUE_C, 89, "udev_queue_unref") {
            let b = Box::from_raw(q);
            if b.fd >= 0 {
                shared::sys::close(b.fd);
            }
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_queue_get_udev(q: *mut udev_queue) -> *mut udev {
    assert_return_errno!(
        !q.is_null(),
        "udev_queue",
        "src/libudev/libudev-queue.c",
        100,
        "udev_queue_get_udev",
        ptr::null_mut(),
        libc::EINVAL
    );
    // SAFETY: a live object.
    unsafe { (*q).udev }
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_kernel_seqnum(_q: *mut udev_queue) -> c_ulonglong {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_udev_seqnum(_q: *mut udev_queue) -> c_ulonglong {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_udev_is_active(_q: *mut udev_queue) -> c_int {
    shared::sys_net::access(b"/run/udev/control", libc::F_OK).is_ok() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_queue_is_empty(_q: *mut udev_queue) -> c_int {
    (udev_queue_is_empty() > 0) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_seqnum_sequence_is_finished(
    _q: *mut udev_queue,
    _start: c_ulonglong,
    _end: c_ulonglong,
) -> c_int {
    (udev_queue_is_empty() > 0) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_seqnum_is_finished(_q: *mut udev_queue, _seqnum: c_ulonglong) -> c_int {
    (udev_queue_is_empty() > 0) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_queue_get_queued_list_entry(_q: *mut udev_queue) -> *mut UdevListEntry {
    with_errno(ptr::null_mut(), libc::ENODATA)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_queue_get_fd(q: *mut udev_queue) -> c_int {
    assert_return!(!q.is_null(), "udev_queue", "src/libudev/libudev-queue.c", 205, "udev_queue_get_fd", -libc::EINVAL);
    // SAFETY: a live object.
    let q = unsafe { &mut *q };
    if q.fd >= 0 {
        return q.fd;
    }
    let fd = match shared::sys_net::inotify_init1(libc::IN_CLOEXEC) {
        Err(e) => return e,
        Ok(fd) => fd,
    };
    if let Err(e) = shared::sys_net::inotify_add_watch(fd, b"/run/udev", libc::IN_DELETE) {
        shared::sys::close(fd);
        return e;
    }
    q.fd = fd;
    fd
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_queue_flush(q: *mut udev_queue) -> c_int {
    assert_return!(!q.is_null(), "udev_queue", "src/libudev/libudev-queue.c", 229, "udev_queue_flush", -libc::EINVAL);
    // SAFETY: a live object.
    let fd = unsafe { (*q).fd };
    if fd < 0 {
        return -libc::EINVAL;
    }
    match shared::device_monitor::flush_fd(fd) {
        Err(r) => r,
        Ok(_) => 0,
    }
}
