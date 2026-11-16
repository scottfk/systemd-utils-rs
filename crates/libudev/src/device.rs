// SPDX-License-Identifier: LGPL-2.1-or-later
//! `libudev-device.c`: `struct udev_device`, a wrapper around a
//! `shared::sd_device::Device` with libudev's cached lists.

use std::ffi::{CStr, c_char, c_int, c_uint, c_ulonglong};
use std::ptr;
use std::rc::Rc;

use shared::log::log_assert_failed_return;
use shared::sd_device::{DStr, Dev, Device, device_action_to_string};
use shared::sys::{errno, set_errno};

use crate::list::{UdevList, UdevListEntry};
use crate::{assert_return, assert_return_errno, opt_str, ref_dec, ref_inc, udev, with_errno};

const DEVICE_C: &str = "src/libudev/libudev-device.c";
const SD_DEVICE_C: &str = "src/libsystemd/sd-device/sd-device.c";

/// `#expr` of `IN_SET(type, 'b', 'c')` as gcc expands it.
const IN_SET_TYPE_B_C: &str = "({ _Bool _found = 0; static const typeof(+type) __assert_in_set[] __attribute__((__unused__)) = { 'b', 'c' }; _Static_assert((__builtin_choose_expr( !__builtin_types_compatible_p(typeof(__assert_in_set), typeof(&*(__assert_in_set))), sizeof(__assert_in_set)/sizeof((__assert_in_set)[0]), ((void)0))) <= 22, \"ELEMENTSOF(__assert_in_set) <= 22\"); switch (type) { case 'b': case 'c': _found = 1; break; default: ; } _found; })";

/// `struct udev_device`.
#[derive(Debug)]
pub struct udev_device {
    udev: *mut udev,
    pub(crate) device: Dev,
    n_ref: c_uint,
    parent: *mut udev_device,
    parent_set: bool,
    parent_errno: i32,
    properties: UdevList,
    properties_generation: u64,
    all_tags: UdevList,
    current_tags: UdevList,
    all_tags_generation: u64,
    current_tags_generation: u64,
    devlinks: UdevList,
    devlinks_generation: u64,
    properties_read: bool,
    all_tags_read: bool,
    current_tags_read: bool,
    devlinks_read: bool,
    sysattrs: UdevList,
    sysattrs_read: bool,
}

/// `udev_device_new()`.
pub(crate) fn udev_device_new(udev: *mut udev, device: Dev) -> *mut udev_device {
    Box::into_raw(Box::new(udev_device {
        udev,
        device,
        n_ref: 1,
        parent: ptr::null_mut(),
        parent_set: false,
        parent_errno: 0,
        properties: UdevList::new(true),
        properties_generation: 0,
        all_tags: UdevList::new(true),
        current_tags: UdevList::new(true),
        all_tags_generation: 0,
        current_tags_generation: 0,
        devlinks: UdevList::new(true),
        devlinks_generation: 0,
        properties_read: false,
        all_tags_read: false,
        current_tags_read: false,
        devlinks_read: false,
        sysattrs: UdevList::new(true),
        sysattrs_read: false,
    }))
}

/// A string the device holds: its pointer stays valid while the device
/// keeps the value.
fn held(s: DStr) -> *const c_char {
    s.as_ptr()
}

/// The common shape of the string getters: NULL with errno on failure,
/// NULL without (C's `if (r == -ENOENT) return NULL;`) where `quiet_enoent`.
fn str_result(r: Result<DStr, i32>, quiet_enoent: bool) -> *const c_char {
    match r {
        Ok(s) => held(s),
        Err(e) if quiet_enoent && e == -libc::ENOENT => ptr::null(),
        Err(e) => with_errno(ptr::null(), e),
    }
}

macro_rules! dev_or {
    ($p:expr, $line:literal, $func:literal, $ret:expr) => {{
        assert_return_errno!(
            !$p.is_null(),
            "udev_device",
            "src/libudev/libudev-device.c",
            $line,
            $func,
            $ret,
            libc::EINVAL
        );
        // SAFETY: the caller passes a live udev_device.
        unsafe { &mut *$p }
    }};
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_seqnum(d: *mut udev_device) -> c_ulonglong {
    let d = dev_or!(d, 69, "udev_device_get_seqnum", 0);
    d.device.get_seqnum().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_devnum(d: *mut udev_device) -> libc::dev_t {
    let d = dev_or!(d, 89, "udev_device_get_devnum", 0);
    match d.device.get_devnum() {
        Ok(n) => n,
        Err(e) if e == -libc::ENOENT => 0,
        Err(e) => with_errno(0, e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_driver(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 112, "udev_device_get_driver", ptr::null());
    str_result(d.device.get_driver(), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_devtype(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 133, "udev_device_get_devtype", ptr::null());
    str_result(d.device.get_devtype(), true)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_subsystem(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 157, "udev_device_get_subsystem", ptr::null());
    str_result(d.device.get_subsystem(), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_property_value(d: *mut udev_device, key: *const c_char) -> *const c_char {
    assert_return_errno!(
        !d.is_null() && !key.is_null(),
        "udev_device && key",
        "src/libudev/libudev-device.c",
        179,
        "udev_device_get_property_value",
        ptr::null(),
        libc::EINVAL
    );
    // SAFETY: a live udev_device and a C string.
    let (d, key) = unsafe { (&mut *d, CStr::from_ptr(key).to_bytes()) };
    str_result(d.device.get_property_value(key), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_new_from_syspath(udev: *mut udev, syspath: *const c_char) -> *mut udev_device {
    // SAFETY: NULL or a C string.
    let Some(syspath) = (unsafe { opt_str(syspath) }) else {
        log_assert_failed_return("syspath", SD_DEVICE_C, 290, "device_new_from_syspath");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    };
    match Device::new_from_syspath(syspath) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => udev_device_new(udev, d),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_device_new_from_devnum(udev: *mut udev, ty: c_char, devnum: libc::dev_t) -> *mut udev_device {
    let ty = ty as u8;
    if ty != b'b' && ty != b'c' {
        // QUIRK: C's assert_return() stringifies its argument after macro
        // expansion, so the message shows IN_SET()'s expansion.
        log_assert_failed_return(IN_SET_TYPE_B_C, SD_DEVICE_C, 357, "sd_device_new_from_devnum");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    }
    match Device::new_from_devnum(ty, devnum) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => udev_device_new(udev, d),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_new_from_device_id(udev: *mut udev, id: *const c_char) -> *mut udev_device {
    // SAFETY: NULL or a C string.
    let Some(id) = (unsafe { opt_str(id) }) else {
        log_assert_failed_return("id", SD_DEVICE_C, 933, "sd_device_new_from_device_id");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    };
    match Device::new_from_device_id(id) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => udev_device_new(udev, d),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_new_from_subsystem_sysname(
    udev: *mut udev,
    subsystem: *const c_char,
    sysname: *const c_char,
) -> *mut udev_device {
    // SAFETY: NULL or C strings.
    let (subsystem, sysname) = unsafe { (opt_str(subsystem), opt_str(sysname)) };
    let Some(subsystem) = subsystem else {
        log_assert_failed_return("subsystem", SD_DEVICE_C, 506, "sd_device_new_from_subsystem_sysname");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    };
    let Some(sysname) = sysname else {
        log_assert_failed_return("sysname", SD_DEVICE_C, 507, "sd_device_new_from_subsystem_sysname");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    };
    match Device::new_from_subsystem_sysname(subsystem, sysname) {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => udev_device_new(udev, d),
    }
}

unsafe extern "C" {
    static environ: *const *const c_char;
}

#[unsafe(no_mangle)]
pub extern "C" fn udev_device_new_from_environment(udev: *mut udev) -> *mut udev_device {
    // Copies to parse, and the entries themselves to split (below).
    let mut copies: Vec<Vec<u8>> = Vec::new();
    let mut ptrs: Vec<*mut c_char> = Vec::new();
    // SAFETY: environ is NULL (after clearenv()) or a NULL-terminated
    // array of C strings.
    unsafe {
        let mut p = environ;
        if p.is_null() {
            shared::log::log_assert_failed(
                "strv",
                "src/libsystemd/sd-device/device-private.c",
                475,
                "device_new_from_strv",
            );
        }
        while !(*p).is_null() {
            copies.push(CStr::from_ptr(*p).to_bytes().to_vec());
            ptrs.push(*p as *mut c_char);
            p = p.add(1);
        }
    }
    let strv: Vec<&[u8]> = copies.iter().map(|c| &c[..]).collect();
    // QUIRK: as C does, each entry's '=' is overwritten with a NUL as it
    // is parsed, so those variables are gone from the environment after.
    let r = Device::new_from_strv_split(&strv, &mut |i, eq| {
        // SAFETY: entry i of environ is a writable C string longer than eq
        // (only the copies are read).
        unsafe { *ptrs[i].add(eq) = 0 };
    });
    match r {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(d) => udev_device_new(udev, d),
    }
}

/// `device_new_from_parent()`.
fn device_new_from_parent(child: &udev_device) -> *mut udev_device {
    match child.device.get_parent() {
        Err(r) => with_errno(ptr::null_mut(), r),
        Ok(p) => udev_device_new(child.udev, p),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_parent(d: *mut udev_device) -> *mut udev_device {
    let d = dev_or!(d, 392, "udev_device_get_parent", ptr::null_mut());
    if !d.parent_set {
        d.parent_set = true;
        d.parent = device_new_from_parent(d);
        d.parent_errno = if d.parent.is_null() { errno() } else { 0 };
    }
    if d.parent.is_null() {
        set_errno(d.parent_errno);
    }
    d.parent
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_parent_with_subsystem_devtype(
    d: *mut udev_device,
    subsystem: *const c_char,
    devtype: *const c_char,
) -> *mut udev_device {
    let mut dp = d;
    let d = dev_or!(d, 435, "udev_device_get_parent_with_subsystem_devtype", ptr::null_mut());
    // SAFETY: NULL or C strings.
    let (subsystem, devtype) = unsafe { (opt_str(subsystem), opt_str(devtype)) };
    let Some(subsystem) = subsystem else {
        log_assert_failed_return("subsystem", SD_DEVICE_C, 1337, "sd_device_get_parent_with_subsystem_devtype");
        return with_errno(ptr::null_mut(), libc::EINVAL);
    };
    let parent = match d.device.get_parent_with_subsystem_devtype(subsystem, devtype) {
        Err(r) => return with_errno(ptr::null_mut(), r),
        Ok(p) => p,
    };
    loop {
        // SAFETY: dp is a live udev_device; its parents live as long as it.
        dp = unsafe { udev_device_get_parent(dp) };
        if dp.is_null() {
            break;
        }
        // SAFETY: as above.
        if Rc::ptr_eq(unsafe { &(*dp).device }, &parent) {
            return dp;
        }
    }
    with_errno(ptr::null_mut(), libc::ENOENT)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_udev(d: *mut udev_device) -> *mut udev {
    let d = dev_or!(d, 463, "udev_device_get_udev", ptr::null_mut());
    d.udev
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_ref(d: *mut udev_device) -> *mut udev_device {
    if d.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object.
    ref_inc(unsafe { &mut (*d).n_ref }, DEVICE_C, 501, "udev_device_ref");
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_unref(d: *mut udev_device) -> *mut udev_device {
    if d.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a live object; freed (with its parent reference) when the
    // last reference goes.
    unsafe {
        if ref_dec(&mut (*d).n_ref, DEVICE_C, 501, "udev_device_unref") {
            let b = Box::from_raw(d);
            let parent = b.parent;
            drop(b);
            udev_device_unref(parent);
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_devpath(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 516, "udev_device_get_devpath", ptr::null());
    held(d.device.get_devpath())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_syspath(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 538, "udev_device_get_syspath", ptr::null());
    held(d.device.get_syspath())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_sysname(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 559, "udev_device_get_sysname", ptr::null());
    str_result(d.device.get_sysname(), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_sysnum(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 580, "udev_device_get_sysnum", ptr::null());
    str_result(d.device.get_sysnum(), true)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_devnode(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 604, "udev_device_get_devnode", ptr::null());
    str_result(d.device.get_devname(), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_devlinks_list_entry(d: *mut udev_device) -> *mut UdevListEntry {
    let d = dev_or!(d, 627, "udev_device_get_devlinks_list_entry", ptr::null_mut());
    if d.device.devlinks_generation() != d.devlinks_generation || !d.devlinks_read {
        d.devlinks.cleanup();
        for l in d.device.devlinks() {
            d.devlinks.add(l.bytes(), None);
        }
        d.devlinks_read = true;
        d.devlinks_generation = d.device.devlinks_generation();
    }
    d.devlinks.get_entry()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_properties_list_entry(d: *mut udev_device) -> *mut UdevListEntry {
    let d = dev_or!(d, 657, "udev_device_get_properties_list_entry", ptr::null_mut());
    if d.device.properties_generation() != d.properties_generation || !d.properties_read {
        d.properties.cleanup();
        for (k, v) in d.device.properties() {
            d.properties.add(k.bytes(), Some(v.bytes()));
        }
        d.properties_read = true;
        d.properties_generation = d.device.properties_generation();
    }
    d.properties.get_entry()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_action(d: *mut udev_device) -> *const c_char {
    let d = dev_or!(d, 687, "udev_device_get_action", ptr::null());
    match d.device.get_action() {
        Err(_) => ptr::null(),
        Ok(a) => action_cstr(device_action_to_string(a)),
    }
}

/// The action names as C strings, static like C's table.
fn action_cstr(s: &str) -> *const c_char {
    let c: &'static CStr = match s {
        "add" => c"add",
        "remove" => c"remove",
        "change" => c"change",
        "move" => c"move",
        "online" => c"online",
        "offline" => c"offline",
        "bind" => c"bind",
        _ => c"unbind",
    };
    c.as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_usec_since_initialized(d: *mut udev_device) -> c_ulonglong {
    assert_return!(
        !d.is_null(),
        "udev_device",
        "src/libudev/libudev-device.c",
        711,
        "udev_device_get_usec_since_initialized",
        (-libc::EINVAL) as c_ulonglong
    );
    // SAFETY: a live object.
    let d = unsafe { &mut *d };
    match d.device.get_usec_since_initialized() {
        Ok(t) => t,
        Err(r) => with_errno(0, r),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_sysattr_value(d: *mut udev_device, sysattr: *const c_char) -> *const c_char {
    let d = dev_or!(d, 734, "udev_device_get_sysattr_value", ptr::null());
    // SAFETY: NULL or a C string.
    let Some(sysattr) = (unsafe { opt_str(sysattr) }) else {
        log_assert_failed_return("sysattr", SD_DEVICE_C, 2536, "sd_device_get_sysattr_value_with_size");
        return with_errno(ptr::null(), libc::EINVAL);
    };
    str_result(d.device.get_sysattr_value(sysattr), false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_set_sysattr_value(
    d: *mut udev_device,
    sysattr: *const c_char,
    value: *const c_char,
) -> c_int {
    assert_return!(
        !d.is_null(),
        "udev_device",
        "src/libudev/libudev-device.c",
        756,
        "udev_device_set_sysattr_value",
        -libc::EINVAL
    );
    // SAFETY: a live object; NULL or C strings.
    let (d, sysattr, value) = unsafe { (&mut *d, opt_str(sysattr), opt_str(value)) };
    let Some(sysattr) = sysattr else {
        log_assert_failed_return("sysattr", SD_DEVICE_C, 2748, "sd_device_set_sysattr_value");
        return -libc::EINVAL;
    };
    match d.device.set_sysattr_value(sysattr, value) {
        Ok(()) => 0,
        Err(r) => r,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_sysattr_list_entry(d: *mut udev_device) -> *mut UdevListEntry {
    let d = dev_or!(d, 776, "udev_device_get_sysattr_list_entry", ptr::null_mut());
    if !d.sysattrs_read {
        d.sysattrs.cleanup();
        let mut a = d.device.get_sysattr_first();
        while let Some(s) = a {
            d.sysattrs.add(s.bytes(), None);
            a = d.device.get_sysattr_next();
        }
        d.sysattrs_read = true;
    }
    d.sysattrs.get_entry()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_is_initialized(d: *mut udev_device) -> c_int {
    assert_return!(
        !d.is_null(),
        "udev_device",
        "src/libudev/libudev-device.c",
        807,
        "udev_device_get_is_initialized",
        -libc::EINVAL
    );
    // SAFETY: a live object.
    let d = unsafe { &mut *d };
    match d.device.get_is_initialized() {
        Ok(b) => b as c_int,
        Err(r) => with_errno(0, r),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_tags_list_entry(d: *mut udev_device) -> *mut UdevListEntry {
    let d = dev_or!(d, 828, "udev_device_get_tags_list_entry", ptr::null_mut());
    if d.device.tags_generation() != d.all_tags_generation || !d.all_tags_read {
        d.all_tags.cleanup();
        for t in d.device.tags() {
            d.all_tags.add(t.bytes(), None);
        }
        d.all_tags_read = true;
        d.all_tags_generation = d.device.tags_generation();
    }
    d.all_tags.get_entry()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_get_current_tags_list_entry(d: *mut udev_device) -> *mut UdevListEntry {
    let d = dev_or!(d, 846, "udev_device_get_current_tags_list_entry", ptr::null_mut());
    if d.device.tags_generation() != d.current_tags_generation || !d.current_tags_read {
        d.current_tags.cleanup();
        for t in d.device.current_tags() {
            d.current_tags.add(t.bytes(), None);
        }
        d.current_tags_read = true;
        d.current_tags_generation = d.device.tags_generation();
    }
    d.current_tags.get_entry()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_has_tag(d: *mut udev_device, tag: *const c_char) -> c_int {
    assert_return!(!d.is_null(), "udev_device", "src/libudev/libudev-device.c", 873, "udev_device_has_tag", 0);
    // SAFETY: a live object; NULL or a C string.
    let (d, tag) = unsafe { (&mut *d, opt_str(tag)) };
    let Some(tag) = tag else {
        log_assert_failed_return("tag", SD_DEVICE_C, 2260, "sd_device_has_tag");
        return 0;
    };
    d.device.has_tag(tag) as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn udev_device_has_current_tag(d: *mut udev_device, tag: *const c_char) -> c_int {
    assert_return!(!d.is_null(), "udev_device", "src/libudev/libudev-device.c", 879, "udev_device_has_current_tag", 0);
    // SAFETY: a live object; NULL or a C string.
    let (d, tag) = unsafe { (&mut *d, opt_str(tag)) };
    let Some(tag) = tag else {
        log_assert_failed_return("tag", SD_DEVICE_C, 2269, "sd_device_has_current_tag");
        return 0;
    };
    d.device.has_current_tag(tag) as c_int
}
