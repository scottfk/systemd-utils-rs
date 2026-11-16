// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-device.c`, `device-private.c` and `device-util.c`: a device in
//! sysfs, read lazily from its directory, its `uevent` file and the udev
//! database in `/run/udev/data/`.
//!
//! A [`Device`] is shared (`Rc`), and its getters fill caches as C's do, so
//! the state sits in a `RefCell`; no borrow is held across calls.  Strings
//! are [`DStr`]s, which are NUL-terminated: libudev hands out pointers to
//! them, valid (as in C) until the device replaces or drops the value.
//!
//! Known difference: C keeps tags, devlinks, sysattr names and children in
//! hash sets, whose order (and so the order of `TAGS=`, `DEVLINKS=` and the
//! iterators) changes from run to run; here they are sorted, which is one of
//! the orders C produces.

use std::cell::{RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use libc::c_char;

use crate::chase::{CHASE_NO_AUTOFS, CHASE_NONEXISTENT, CHASE_PREFIX_ROOT, chase};
use crate::errno::{is_neg_privilege, strerror, synthetic};
use crate::escape::cescape;
use crate::extract::{EXTRACT_DONT_COALESCE_SEPARATORS, EXTRACT_RETAIN_ESCAPE, extract_first_word, strv_split_full};
use crate::fileio::{WRITE_STRING_FILE_AVOID_NEWLINE, WRITE_STRING_FILE_DISABLE_BUFFER, write_string_file_fd};
use crate::log_debug_errno;
use crate::parse::{
    SAFE_ATO_REFUSE_LEADING_WHITESPACE, SAFE_ATO_REFUSE_PLUS_MINUS, parse_boolean, parse_devnum, safe_atoi, safe_atou,
    safe_atou_full, safe_atou64,
};
use crate::path::{
    filename_is_valid, last_path_component, path_equal, path_extract_directory, path_find_last_component,
    path_is_absolute, path_is_normalized, path_is_safe, path_join, path_make_relative, path_simplify,
    path_split_prefix_filename, path_startswith,
};
use crate::string::{ALPHANUMERICAL, DIGITS, NEWLINE, STRING_ALLOW_BACKSLASHES, STRING_ALLOW_EMPTY};
use crate::string::{
    STRING_ALLOW_GLOBS, STRING_ALLOW_NEWLINES, STRING_ALLOW_QUOTES, delete_trailing_chars, in_charset, string_is_safe,
};
use crate::sys::{self, OwnedFd};

/// `SYSFS_MAGIC`.
const SYSFS_MAGIC: i64 = 0x6265_6572;
const MODE_INVALID: u32 = u32::MAX;
const UID_INVALID: u32 = u32::MAX;
const OLDEST_UDEV_DATABASE_VERSION: u32 = 1;
pub const LATEST_UDEV_DATABASE_VERSION: u32 = 1;

/// `log_device_full_errno(device, level, error, ...)`: like `log_full_errno!`,
/// with the device's sysname as the journal's `DEVICE=` field.
#[macro_export]
macro_rules! log_device_full_errno {
    ($dev:expr, $level:expr, $err:expr, $($e:expr),* $(,)?) => {{
        let level: i32 = $level;
        let err: i32 = $err;
        if $crate::log::enabled(level) {
            let sysname = $dev.get_sysname().ok();
            $crate::log::log_object_internal(
                level,
                err,
                $crate::log::Loc { file: file!(), line: line!(), func: "" },
                sysname.as_ref().map(|s| (&b"DEVICE="[..], s.bytes())),
                $crate::bcat!($($e),*),
            )
        } else {
            -$crate::errno::errno_value(err)
        }
    }};
}

#[macro_export]
macro_rules! log_device_debug {
    ($dev:expr, $($e:expr),* $(,)?) => { $crate::log_device_full_errno!($dev, $crate::log::LOG_DEBUG, 0, $($e),*) };
}

#[macro_export]
macro_rules! log_device_debug_errno {
    ($dev:expr, $err:expr, $($e:expr),* $(,)?) => {
        $crate::log_device_full_errno!($dev, $crate::log::LOG_DEBUG, $err, $($e),*)
    };
}

/// A NUL-terminated byte string shared with the device that holds it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DStr(Rc<[u8]>);

impl DStr {
    pub fn new(b: &[u8]) -> DStr {
        let mut v = Vec::with_capacity(b.len() + 1);
        v.extend_from_slice(b);
        v.push(0);
        DStr(v.into())
    }

    /// The string, without the terminating NUL.
    pub fn bytes(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr() as *const c_char
    }
}

impl fmt::Debug for DStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.bytes()))
    }
}

impl crate::bytes::AsBytes for DStr {
    fn as_bytes_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// `sd_device_action_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

const ACTIONS: [(Action, &str); 8] = [
    (Action::Add, "add"),
    (Action::Remove, "remove"),
    (Action::Change, "change"),
    (Action::Move, "move"),
    (Action::Online, "online"),
    (Action::Offline, "offline"),
    (Action::Bind, "bind"),
    (Action::Unbind, "unbind"),
];

/// The action names, in table order (`DUMP_STRING_TABLE(device_action, ...)`).
pub const DEVICE_ACTION_NAMES: &[&str] = &["add", "remove", "change", "move", "online", "offline", "bind", "unbind"];

/// `device_action_to_string()`.
pub fn device_action_to_string(a: Action) -> &'static str {
    ACTIONS.iter().find(|(x, _)| *x == a).map(|(_, s)| *s).expect("every action is in the table")
}

/// `device_action_from_string()`.
pub fn device_action_from_string(s: &[u8]) -> Result<Action, i32> {
    ACTIONS.iter().find(|(_, n)| n.as_bytes() == s).map(|(a, _)| *a).ok_or(-libc::EINVAL)
}

/// An `OrderedHashmap` of strings: insertion order, replacing in place.
#[derive(Debug, Default, Clone)]
struct OMap {
    v: Vec<(DStr, DStr)>,
}

impl OMap {
    fn get(&self, k: &[u8]) -> Option<&DStr> {
        self.v.iter().find(|(x, _)| x.bytes() == k).map(|(_, v)| v)
    }

    fn replace(&mut self, k: &[u8], val: &[u8]) {
        match self.v.iter_mut().find(|(x, _)| x.bytes() == k) {
            Some(e) => e.1 = DStr::new(val),
            None => self.v.push((DStr::new(k), DStr::new(val))),
        }
    }

    fn remove(&mut self, k: &[u8]) {
        self.v.retain(|(x, _)| x.bytes() != k);
    }
}

/// `SysAttrCacheEntry`.
#[derive(Debug)]
struct SysAttr {
    key: Vec<u8>,
    value: Option<DStr>,
    value_stripped: Option<DStr>,
    size: usize,
    error: i32,
}

#[derive(Debug)]
struct State {
    syspath: Option<DStr>,
    devpath: Option<DStr>,
    sysname: Option<DStr>,
    sysnum: Option<DStr>,

    action: Option<Action>,
    seqnum: u64,

    subsystem: Option<DStr>,
    driver_subsystem: Option<DStr>,
    driver: Option<DStr>,
    devtype: Option<DStr>,

    devname: Option<DStr>,
    devnum: u64,
    devmode: u32,
    devuid: u32,
    devgid: u32,
    diskseq: u64,
    ifindex: i32,
    device_id: Option<DStr>,

    sysattr_values: Vec<SysAttr>,
    sysattrs: BTreeSet<DStr>,
    sysattrs_iterator: usize,

    database_version: u32,
    usec_initialized: u64,

    properties: OMap,
    properties_iterator: usize,
    properties_generation: u64,
    properties_iterator_generation: u64,
    properties_db: OMap,
    properties_nulstr: Option<Rc<[u8]>>,
    properties_strv: Option<Rc<Vec<DStr>>>,

    all_tags: BTreeSet<DStr>,
    current_tags: BTreeSet<DStr>,
    all_tags_iterator: usize,
    current_tags_iterator: usize,
    all_tags_iterator_generation: u64,
    current_tags_iterator_generation: u64,
    tags_generation: u64,

    devlinks: BTreeSet<DStr>,
    devlinks_iterator: usize,
    devlinks_generation: u64,
    devlinks_iterator_generation: u64,
    devlink_priority: i32,

    parent: Option<Dev>,
    children: BTreeMap<Vec<u8>, Dev>,
    children_iterator: usize,
    children_enumerated: bool,

    parent_set: bool,
    sysattrs_read: bool,
    property_tags_outdated: bool,
    property_devlinks_outdated: bool,
    properties_buf_outdated: bool,
    subsystem_set: bool,
    driver_set: bool,
    uevent_loaded: bool,
    db_loaded: bool,
    is_initialized: bool,
    sealed: bool,
    db_persist: bool,
}

/// `sd_device`.
#[derive(Debug)]
pub struct Device {
    s: RefCell<State>,
}

/// A reference to a device (`sd_device*` with its reference count).
pub type Dev = Rc<Device>;

/// `ERRNO_IS_NEG_DEVICE_ABSENT()`.
pub fn errno_is_neg_device_absent(r: i32) -> bool {
    r == -libc::ENODEV || r == -libc::ENXIO || r == -libc::ENOENT
}

fn major(d: u64) -> u32 {
    libc::major(d)
}

fn minor(d: u64) -> u32 {
    libc::minor(d)
}

/// `DEVNUM_FORMAT_STR`.
pub fn devnum_format(d: u64) -> String {
    format!("{}:{}", major(d), minor(d))
}

/// `readlink_value()`: the last component of a symlink's target.
pub fn readlink_value(p: &[u8]) -> Result<Vec<u8>, i32> {
    let link = sys::readlinkat(libc::AT_FDCWD, p)?;
    let (_, name, is_dir) = path_split_prefix_filename(&link, false, true)?;
    if is_dir {
        return Err(-libc::EINVAL);
    }
    Ok(name.expect("requested"))
}

/// `device_path_parse_major_minor()`.
pub fn device_path_parse_major_minor(path: &[u8]) -> Result<(u32, u64), i32> {
    if path_equal(path, b"/run/systemd/inaccessible/chr") {
        return Ok((libc::S_IFCHR, 0));
    }
    if path_equal(path, b"/run/systemd/inaccessible/blk") {
        return Ok((libc::S_IFBLK, 0));
    }
    let (mode, w) = if let Some(w) = path_startswith(path, b"/dev/block/") {
        (libc::S_IFBLK, w)
    } else if let Some(w) = path_startswith(path, b"/dev/char/") {
        (libc::S_IFCHR, w)
    } else {
        return Err(-libc::ENODEV);
    };
    Ok((mode, parse_devnum(w)?))
}

/// `property_is_valid()`.
fn property_is_valid(key: &[u8], value: Option<&[u8]>) -> bool {
    if key.is_empty() || !in_charset(key, &[ALPHANUMERICAL, b"_."].concat()) {
        return false;
    }
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return true;
    };
    string_is_safe(value, STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS)
}

/// `mangle_devname()`.
fn mangle_devname(p: &[u8]) -> Result<Vec<u8>, i32> {
    if !path_is_safe(p) {
        return Err(-libc::EINVAL);
    }
    let q = if path_is_absolute(p) {
        if path_startswith(p, b"/dev/").is_none_or(|r| r.is_empty()) {
            return Err(-libc::EINVAL);
        }
        p.to_vec()
    } else {
        path_join(&[b"/dev/", p])
    };
    Ok(path_simplify(&q))
}

/// `is_valid_tag()`.
fn is_valid_tag(tag: &[u8]) -> bool {
    in_charset(tag, &[ALPHANUMERICAL, b"-_"].concat()) && filename_is_valid(tag)
}

/// `set_strjoin(s, separator, wrap_with_separator)`.
fn set_strjoin(s: &BTreeSet<DStr>, sep: &[u8], wrap: bool) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    let wrap = wrap && !sep.is_empty();
    let mut out = Vec::new();
    let mut first = !wrap;
    for v in s {
        if v.bytes().is_empty() {
            continue;
        }
        if !sep.is_empty() && !first {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(v.bytes());
        first = false;
    }
    if wrap {
        out.extend_from_slice(sep);
    }
    Some(out)
}

/// `strspn_from_end(str, DIGITS)`.
fn digits_from_end(s: &[u8]) -> usize {
    s.iter().rev().take_while(|b| DIGITS.contains(b)).count()
}

impl Device {
    /// `device_new_aux()`.
    pub fn new_aux() -> Dev {
        Rc::new(Device {
            s: RefCell::new(State {
                syspath: None,
                devpath: None,
                sysname: None,
                sysnum: None,
                action: None,
                seqnum: 0,
                subsystem: None,
                driver_subsystem: None,
                driver: None,
                devtype: None,
                devname: None,
                devnum: 0,
                devmode: MODE_INVALID,
                devuid: UID_INVALID,
                devgid: UID_INVALID,
                diskseq: 0,
                ifindex: 0,
                device_id: None,
                sysattr_values: Vec::new(),
                sysattrs: BTreeSet::new(),
                sysattrs_iterator: 0,
                database_version: OLDEST_UDEV_DATABASE_VERSION,
                usec_initialized: 0,
                properties: OMap::default(),
                properties_iterator: 0,
                properties_generation: 0,
                properties_iterator_generation: 0,
                properties_db: OMap::default(),
                properties_nulstr: None,
                properties_strv: None,
                all_tags: BTreeSet::new(),
                current_tags: BTreeSet::new(),
                all_tags_iterator: 0,
                current_tags_iterator: 0,
                all_tags_iterator_generation: 0,
                current_tags_iterator_generation: 0,
                tags_generation: 0,
                devlinks: BTreeSet::new(),
                devlinks_iterator: 0,
                devlinks_generation: 0,
                devlinks_iterator_generation: 0,
                devlink_priority: 0,
                parent: None,
                children: BTreeMap::new(),
                children_iterator: 0,
                children_enumerated: false,
                parent_set: false,
                sysattrs_read: false,
                property_tags_outdated: false,
                property_devlinks_outdated: false,
                properties_buf_outdated: false,
                subsystem_set: false,
                driver_set: false,
                uevent_loaded: false,
                db_loaded: false,
                is_initialized: false,
                sealed: false,
                db_persist: false,
            }),
        })
    }

    fn st(&self) -> RefMut<'_, State> {
        self.s.borrow_mut()
    }

    /// The syspath, which every constructed device has.
    fn syspath(&self) -> DStr {
        self.st().syspath.clone().expect("a device always has a syspath")
    }

    fn devpath_bytes(&self) -> DStr {
        self.st().devpath.clone().expect("a device always has a devpath")
    }

    /// `device_add_property_aux()`.
    pub fn add_property_aux(&self, key: &[u8], value: Option<&[u8]>, db: bool) -> Result<(), i32> {
        if !property_is_valid(key, value) {
            log_device_debug!(
                self,
                "sd-device: Refusing invalid property: ",
                cescape(key),
                "=",
                cescape(value.unwrap_or(b""))
            );
            return Err(-libc::EINVAL);
        }
        let mut s = self.st();
        let props = if db { &mut s.properties_db } else { &mut s.properties };
        match value.filter(|v| !v.is_empty()) {
            Some(v) => props.replace(key, v),
            None => props.remove(key),
        }
        if !db {
            s.properties_generation += 1;
            s.properties_buf_outdated = true;
        }
        Ok(())
    }

    /// `device_add_property_internal()`.
    pub fn add_property_internal(&self, key: &[u8], value: Option<&[u8]>) -> Result<(), i32> {
        self.add_property_aux(key, value, false)
    }

    /// `device_add_property()`: also to the database's properties, unless the
    /// key starts with a dot.
    pub fn add_property(&self, key: &[u8], value: Option<&[u8]>) -> Result<(), i32> {
        self.add_property_aux(key, value, false)?;
        if key.first() != Some(&b'.') {
            self.add_property_aux(key, value, true)?;
        }
        Ok(())
    }

    /// `device_set_syspath()`.
    pub fn set_syspath(&self, syspath_in: &[u8], verify: bool) -> Result<(), i32> {
        let syspath: Vec<u8> = if verify {
            let c = match chase(syspath_in, None, 0, true, true) {
                Err(e) if e == -libc::ENOENT => return Err(-libc::ENODEV), // log_trace_errno()
                Err(e) => {
                    return Err(log_debug_errno!(
                        e,
                        "sd-device: Failed to get target of '",
                        syspath_in,
                        "': ",
                        strerror(e)
                    ));
                }
                Ok(c) => c,
            };
            let fd = c.fd.expect("requested");
            let mut syspath = c.path.expect("requested");
            if path_startswith(&syspath, b"/sys").is_none() {
                let real_sys = match chase(b"/sys", None, 0, true, false) {
                    Ok(c) => c.path.expect("requested"),
                    Err(e) => {
                        return Err(log_debug_errno!(e, "sd-device: Failed to chase symlink /sys: ", strerror(e)));
                    }
                };
                let Some(p) = path_startswith(&syspath, &real_sys) else {
                    return Err(log_debug_errno!(
                        synthetic(libc::ENODEV),
                        "sd-device: Canonicalized path '",
                        syspath,
                        "' does not starts with sysfs mount point '",
                        real_sys,
                        "'"
                    ));
                };
                syspath = path_simplify(&path_join(&[b"/sys", p]));
            }
            if path_startswith(&syspath, b"/sys/devices/").is_some() {
                if let Err(e) = sys::faccessat(fd.raw(), b"uevent", libc::F_OK, 0) {
                    if e == -libc::ENOENT {
                        return Err(-libc::ENODEV); // log_trace_errno(), which logs nothing
                    }
                    if e == -libc::ENOTDIR {
                        return Err(log_debug_errno!(
                            synthetic(libc::ENODEV),
                            "sd-device: the syspath \"",
                            syspath,
                            "\" is not a directory."
                        ));
                    }
                    return Err(log_debug_errno!(
                        e,
                        "sd-device: cannot find uevent file for ",
                        syspath,
                        ": ",
                        strerror(e)
                    ));
                }
            } else {
                let st = match sys::fstat(fd.raw()) {
                    Ok(st) => st,
                    Err(e) => {
                        return Err(log_debug_errno!(
                            e,
                            "sd-device: failed to check if syspath \"",
                            syspath,
                            "\" is a directory: ",
                            strerror(e)
                        ));
                    }
                };
                if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    return Err(log_debug_errno!(
                        synthetic(libc::ENODEV),
                        "sd-device: the syspath \"",
                        syspath,
                        "\" is not a directory."
                    ));
                }
            }
            let r = crate::env::secure_getenv_bool("SYSTEMD_DEVICE_VERIFY_SYSFS");
            if let Err(e) = r
                && e != -libc::ENXIO
            {
                log_debug_errno!(e, "Failed to parse $SYSTEMD_DEVICE_VERIFY_SYSFS value: ", strerror(e));
            }
            if r != Ok(false) {
                match crate::stat_util::is_fs_type_at(fd.raw(), None, SYSFS_MAGIC) {
                    Err(e) => {
                        return Err(log_debug_errno!(
                            e,
                            "sd-device: failed to check if syspath \"",
                            syspath,
                            "\" is backed by sysfs."
                        ));
                    }
                    Ok(false) => {
                        return Err(log_debug_errno!(
                            synthetic(libc::ENODEV),
                            "sd-device: the syspath \"",
                            syspath,
                            "\" is outside of sysfs, refusing."
                        ));
                    }
                    Ok(true) => {}
                }
            }
            syspath
        } else {
            if path_startswith(syspath_in, b"/sys/").is_none() {
                return Err(log_debug_errno!(
                    synthetic(libc::EINVAL),
                    "sd-device: Syspath '",
                    syspath_in,
                    "' is not a subdirectory of /sys"
                ));
            }
            path_simplify(syspath_in)
        };

        let devpath = syspath.strip_prefix(b"/sys").expect("checked above").to_vec();
        if devpath.first() != Some(&b'/') {
            return Err(log_debug_errno!(
                synthetic(libc::ENODEV),
                "sd-device: \"/sys\" alone is not a valid device path."
            ));
        }
        if let Err(e) = self.add_property_internal(b"DEVPATH", Some(&devpath)) {
            return Err(log_debug_errno!(
                e,
                "sd-device: Failed to add \"DEVPATH\" property for device \"",
                syspath,
                "\": ",
                strerror(e)
            ));
        }
        let mut s = self.st();
        s.syspath = Some(DStr::new(&syspath));
        s.devpath = Some(DStr::new(&devpath));
        s.sysnum = None;
        s.sysname = None;
        Ok(())
    }

    /// `device_new_from_syspath(ret, syspath, strict)`.
    fn new_from_syspath_full(syspath: &[u8], strict: bool) -> Result<Dev, i32> {
        if strict && path_startswith(syspath, b"/sys/").is_none() {
            return Err(-libc::EINVAL);
        }
        let d = Device::new_aux();
        d.set_syspath(syspath, true)?;
        Ok(d)
    }

    /// `sd_device_new_from_syspath()`.
    pub fn new_from_syspath(syspath: &[u8]) -> Result<Dev, i32> {
        Device::new_from_syspath_full(syspath, true)
    }

    /// `device_new_from_mode_and_devnum()`.
    pub fn new_from_mode_and_devnum(mode: u32, devnum: u64) -> Result<Dev, i32> {
        let t = match mode & libc::S_IFMT {
            libc::S_IFCHR => "char",
            libc::S_IFBLK => "block",
            _ => return Err(-libc::ENOTTY),
        };
        if major(devnum) == 0 {
            return Err(-libc::ENODEV);
        }
        let syspath = format!("/sys/dev/{t}/{}", devnum_format(devnum));
        let dev = Device::new_from_syspath(syspath.as_bytes())?;
        let n = match dev.get_devnum() {
            Err(e) if e == -libc::ENOENT => return Err(-libc::ENXIO),
            r => r?,
        };
        if n != devnum {
            return Err(-libc::ENXIO);
        }
        let block = dev.in_subsystem(&[b"block"])?;
        let want = if block { libc::S_IFBLK } else { libc::S_IFCHR };
        if mode & libc::S_IFMT != want {
            return Err(-libc::ENXIO);
        }
        Ok(dev)
    }

    /// `sd_device_new_from_devnum()`.
    pub fn new_from_devnum(ty: u8, devnum: u64) -> Result<Dev, i32> {
        Device::new_from_mode_and_devnum(if ty == b'b' { libc::S_IFBLK } else { libc::S_IFCHR }, devnum)
    }

    /// `sd_device_new_from_ifindex()`.
    pub fn new_from_ifindex(ifindex: i32) -> Result<Dev, i32> {
        let ifname = crate::netlink::rtnl_get_ifname(ifindex)?;
        let dev = Device::new_from_syspath(&[b"/sys/class/net/", &ifname[..]].concat())?;
        let i = match dev.get_ifindex() {
            Err(e) if e == -libc::ENOENT => return Err(-libc::ENXIO),
            r => r?,
        };
        if i != ifindex {
            return Err(-libc::ENXIO);
        }
        Ok(dev)
    }

    /// `device_new_from_path_join()`: Ok(true) if `device` is (now) set.
    fn new_from_path_join(
        device: &mut Option<Dev>,
        subsystem: Option<&[u8]>,
        driver_subsystem: Option<&[u8]>,
        sysname: &[u8],
        parts: &[&[u8]],
    ) -> Result<bool, i32> {
        let p = path_join(parts);
        let new_device = match Device::new_from_syspath(&p) {
            Err(e) if e == -libc::ENODEV => return Ok(false),
            r => r?,
        };
        let subs: Vec<&[u8]> = subsystem.into_iter().collect();
        if !new_device.in_subsystem(&subs)? {
            return Ok(false);
        }
        let new_driver_subsystem = new_device.get_driver_subsystem().ok();
        if driver_subsystem != new_driver_subsystem.as_ref().map(|s| s.bytes()) {
            return Ok(false);
        }
        let new_sysname = new_device.get_sysname()?;
        if sysname != new_sysname.bytes() {
            return Ok(false);
        }
        let Some(d) = device else {
            *device = Some(new_device);
            return Ok(true);
        };
        let devpath = d.get_devpath();
        let new_devpath = new_device.get_devpath();
        if devpath != new_devpath {
            return Err(log_debug_errno!(
                synthetic(libc::ETOOMANYREFS),
                "sd-device: found multiple devices for subsystem=",
                subsystem.unwrap_or(b"(null)"),
                " and sysname=",
                sysname,
                ", refusing: ",
                devpath,
                ", ",
                new_devpath
            ));
        }
        Ok(true)
    }

    /// `sd_device_new_from_subsystem_sysname()`.
    pub fn new_from_subsystem_sysname(subsystem: &[u8], sysname: &[u8]) -> Result<Dev, i32> {
        if !path_is_normalized(subsystem) || !path_is_normalized(sysname) {
            return Err(-libc::EINVAL);
        }
        let name: Vec<u8> = sysname.iter().map(|&c| if c == b'/' { b'!' } else { c }).collect();
        let mut device = None;
        if subsystem == b"subsystem" {
            for s in [&b"/sys/bus/"[..], b"/sys/class/"] {
                Device::new_from_path_join(&mut device, Some(subsystem), None, sysname, &[s, &name])?;
            }
        } else if subsystem == b"module" {
            Device::new_from_path_join(&mut device, Some(subsystem), None, sysname, &[b"/sys/module/", &name])?;
        } else if subsystem == b"drivers"
            && let Some(sep) = name.iter().position(|&c| c == b':')
            && sep + 1 < name.len()
        {
            let subsys = &name[..sep];
            let rest = &name[sep + 1..];
            if rest == b"drivers" {
                Device::new_from_path_join(
                    &mut device,
                    Some(subsystem),
                    Some(subsys),
                    b"drivers",
                    &[b"/sys/bus/", subsys, b"/drivers"],
                )?;
            } else {
                Device::new_from_path_join(
                    &mut device,
                    Some(subsystem),
                    Some(subsys),
                    &sysname[sep + 1..],
                    &[b"/sys/bus/", subsys, b"/drivers/", rest],
                )?;
            }
        }
        Device::new_from_path_join(
            &mut device,
            Some(subsystem),
            None,
            sysname,
            &[b"/sys/bus/", subsystem, b"/devices/", &name],
        )?;
        Device::new_from_path_join(&mut device, Some(subsystem), None, sysname, &[b"/sys/class/", subsystem, &name])?;
        // Devices under /sys/firmware/ have no subsystem (issue #35861).
        Device::new_from_path_join(&mut device, None, None, sysname, &[b"/sys/firmware/", subsystem, &name])?;
        device.ok_or(-libc::ENODEV)
    }

    /// `sd_device_new_from_stat_rdev()`.
    pub fn new_from_stat_rdev(st: &sys::Stat) -> Result<Dev, i32> {
        Device::new_from_mode_and_devnum(st.st_mode, st.st_rdev)
    }

    /// `device_new_from_devname(ret, devname, strict)`.
    fn new_from_devname_full(devname: &[u8], strict: bool) -> Result<Dev, i32> {
        if strict && path_startswith(devname, b"/dev/").is_none_or(|r| r.is_empty()) {
            return Err(-libc::EINVAL);
        }
        if let Ok((mode, devnum)) = device_path_parse_major_minor(devname) {
            return Device::new_from_mode_and_devnum(mode, devnum);
        }
        let c = match chase(devname, None, 0, true, true) {
            Err(e) if errno_is_neg_device_absent(e) => return Err(-libc::ENODEV),
            r => r?,
        };
        let st = sys::fstat(c.fd.expect("requested").raw())?;
        let resolved = c.path.expect("requested");
        if path_startswith(&resolved, b"/dev/").is_none_or(|r| r.is_empty()) {
            return Err(-libc::EINVAL);
        }
        Device::new_from_stat_rdev(&st)
    }

    /// `sd_device_new_from_devname()`.
    pub fn new_from_devname(devname: &[u8]) -> Result<Dev, i32> {
        Device::new_from_devname_full(devname, true)
    }

    /// `sd_device_new_from_path()`.
    pub fn new_from_path(path: &[u8]) -> Result<Dev, i32> {
        if let Ok(d) = Device::new_from_devname_full(path, false) {
            return Ok(d);
        }
        Device::new_from_syspath_full(path, false)
    }

    /// `device_set_devtype()`.
    pub fn set_devtype(&self, devtype: &[u8]) -> Result<(), i32> {
        self.add_property_internal(b"DEVTYPE", Some(devtype))?;
        self.st().devtype = Some(DStr::new(devtype));
        Ok(())
    }

    /// `device_set_ifindex()`.
    pub fn set_ifindex(&self, name: &[u8]) -> Result<(), i32> {
        let ifindex = crate::parse::parse_ifindex(name)?;
        self.add_property_internal(b"IFINDEX", Some(name))?;
        self.st().ifindex = ifindex;
        Ok(())
    }

    /// `device_set_devname()`.
    pub fn set_devname(&self, devname: &[u8]) -> Result<(), i32> {
        let t = mangle_devname(devname)?;
        self.add_property_internal(b"DEVNAME", Some(&t))?;
        self.st().devname = Some(DStr::new(&t));
        Ok(())
    }

    /// `device_set_devmode()`.
    pub fn set_devmode(&self, devmode: &[u8]) -> Result<(), i32> {
        let m = safe_atou(devmode)?;
        if m > 0o7777 {
            return Err(-libc::EINVAL);
        }
        self.add_property_internal(b"DEVMODE", Some(devmode))?;
        self.st().devmode = m;
        Ok(())
    }

    /// `device_set_devnum()`.
    pub fn set_devnum(&self, maj: &[u8], min: Option<&[u8]>) -> Result<(), i32> {
        let ma = safe_atou(maj)?;
        if ma == 0 {
            return Ok(());
        }
        if ma >= 1 << 12 {
            return Err(-libc::EINVAL);
        }
        let mut mi = 0;
        if let Some(m) = min {
            mi = safe_atou(m)?;
            if mi >= 1 << 20 {
                return Err(-libc::EINVAL);
            }
        }
        self.add_property_internal(b"MAJOR", Some(maj))?;
        if let Some(m) = min {
            self.add_property_internal(b"MINOR", Some(m))?;
        }
        self.st().devnum = libc::makedev(ma, mi);
        Ok(())
    }

    /// `device_set_diskseq()`.
    pub fn set_diskseq(&self, str: &[u8]) -> Result<(), i32> {
        let d = safe_atou64(str)?;
        if d == 0 {
            return Err(-libc::EINVAL);
        }
        self.add_property_internal(b"DISKSEQ", Some(str))?;
        self.st().diskseq = d;
        Ok(())
    }

    /// `device_set_devuid()`.
    pub fn set_devuid(&self, uid: &[u8]) -> Result<(), i32> {
        let u = crate::user::parse_uid(uid)?;
        self.add_property_internal(b"DEVUID", Some(uid))?;
        self.st().devuid = u;
        Ok(())
    }

    /// `device_set_devgid()`.
    pub fn set_devgid(&self, gid: &[u8]) -> Result<(), i32> {
        let g = crate::user::parse_uid(gid)?;
        self.add_property_internal(b"DEVGID", Some(gid))?;
        self.st().devgid = g;
        Ok(())
    }

    /// `handle_uevent_line()`: Some(...) for MAJOR=/MINOR=, which the caller
    /// keeps for later.
    fn handle_uevent_line(&self, key: &[u8], value: &[u8]) -> Result<(), i32> {
        match key {
            b"SUBSYSTEM" => self.set_subsystem(Some(value)),
            b"DEVTYPE" => self.set_devtype(value),
            b"IFINDEX" => self.set_ifindex(value),
            b"DEVNAME" => self.set_devname(value),
            b"DEVUID" => self.set_devuid(value),
            b"DEVGID" => self.set_devgid(value),
            b"DEVMODE" => self.set_devmode(value),
            b"DISKSEQ" => self.set_diskseq(value),
            b"DRIVER" => self.set_driver(Some(value)),
            _ => self.add_property_internal(key, Some(value)),
        }
    }

    /// `device_read_uevent_file()`.
    pub fn read_uevent_file(&self) -> Result<(), i32> {
        {
            let mut s = self.st();
            if s.uevent_loaded || s.sealed {
                return Ok(());
            }
            s.uevent_loaded = true;
        }
        let uevent = match self.get_sysattr_value(b"uevent") {
            Err(e) if is_neg_privilege(e) || errno_is_neg_device_absent(e) => return Ok(()),
            Err(e) => {
                return Err(log_device_debug_errno!(self, e, "sd-device: Failed to read uevent file: ", strerror(e)));
            }
            Ok(v) => v,
        };
        let mut v = match strv_split_full(uevent.bytes(), Some(NEWLINE), EXTRACT_RETAIN_ESCAPE) {
            Ok(v) => v,
            Err(e) => {
                return Err(log_device_debug_errno!(self, e, "sd-device: Failed to parse uevent file: ", strerror(e)));
            }
        };
        if v.last().is_some_and(|l| l.is_empty()) {
            v.pop();
        }
        let mut major: Option<Vec<u8>> = None;
        let mut minor: Option<Vec<u8>> = None;
        for line in &v {
            let line = crate::bytes::c_str_prefix(line);
            let Some(eq) = line.iter().position(|&c| c == b'=') else {
                log_device_debug!(self, "sd-device: Invalid uevent line, ignoring: ", cescape(line));
                continue;
            };
            let (key, value) = (&line[..eq], &line[eq + 1..]);
            let r = match key {
                b"MAJOR" => {
                    major = Some(value.to_vec());
                    Ok(())
                }
                b"MINOR" => {
                    minor = Some(value.to_vec());
                    Ok(())
                }
                _ => self.handle_uevent_line(key, value),
            };
            if let Err(e) = r {
                log_device_debug_errno!(
                    self,
                    e,
                    "sd-device: Failed to handle uevent entry '",
                    cescape(key),
                    "=",
                    cescape(value),
                    "', ignoring: ",
                    strerror(e)
                );
            }
        }
        if let Some(ma) = &major
            && let Err(e) = self.set_devnum(ma, minor.as_deref())
        {
            let mi: Vec<u8> = match &minor {
                Some(m) => cescape(m),
                None => b"n/a".to_vec(),
            };
            log_device_debug_errno!(
                self,
                e,
                "sd-device: Failed to set 'MAJOR=",
                cescape(ma),
                "' and/or 'MINOR=",
                mi,
                "' from uevent, ignoring: ",
                strerror(e)
            );
        }
        match self.in_subsystem(&[b"drivers"]) {
            Err(e) => {
                log_device_debug_errno!(self, e, "Failed to check if the device is a driver, ignoring: ", strerror(e));
            }
            Ok(true) => {
                if let Err(e) = self.set_drivers_subsystem() {
                    log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to set driver subsystem, ignoring: ",
                        strerror(e)
                    );
                }
            }
            Ok(false) => {}
        }
        Ok(())
    }

    /// `sd_device_get_ifindex()`.
    pub fn get_ifindex(&self) -> Result<i32, i32> {
        self.read_uevent_file()?;
        let i = self.st().ifindex;
        if i <= 0 { Err(-libc::ENOENT) } else { Ok(i) }
    }

    /// `device_get_ifname()`.
    pub fn get_ifname(&self) -> Result<DStr, i32> {
        self.get_ifindex()?;
        self.get_property_value(b"INTERFACE")
    }

    /// `sd_device_new_from_device_id()`.
    pub fn new_from_device_id(id: &[u8]) -> Result<Dev, i32> {
        match id.first() {
            Some(&t @ (b'b' | b'c')) => {
                let devt = parse_devnum(&id[1..])?;
                Device::new_from_devnum(t, devt)
            }
            Some(b'n') => {
                let ifindex = crate::parse::parse_ifindex(&id[1..])?;
                Device::new_from_ifindex(ifindex)
            }
            Some(b'+') => {
                let rest = &id[1..];
                let Some(sep) = rest.iter().position(|&c| c == b':') else {
                    return Err(-libc::EINVAL);
                };
                if sep + 1 >= rest.len() {
                    return Err(-libc::EINVAL);
                }
                let subsystem = &rest[..sep];
                let sysname: Vec<u8> = rest[sep + 1..].iter().map(|&c| if c == b'!' { b'/' } else { c }).collect();
                Device::new_from_subsystem_sysname(subsystem, &sysname)
            }
            _ => Err(-libc::EINVAL),
        }
    }

    /// `sd_device_get_syspath()`.
    pub fn get_syspath(&self) -> DStr {
        self.syspath()
    }

    /// `device_enumerate_children_internal()`.
    fn enumerate_children_internal(
        &self,
        subdir: Option<&[u8]>,
        stack: &mut BTreeSet<Vec<u8>>,
        children: &mut BTreeMap<Vec<u8>, Dev>,
    ) -> Result<(), i32> {
        let mut dir = self.opendir(subdir)?;
        while let Some((name, ty)) = dir.next_entry()? {
            if name == b"." || name == b".." {
                continue;
            }
            if ty != libc::DT_LNK && ty != libc::DT_DIR {
                continue;
            }
            let p = match subdir {
                Some(s) => path_join(&[s, &name]),
                None => name.clone(),
            };
            match self.new_child(&p) {
                Ok(child) => {
                    children.insert(p, child);
                }
                Err(e) if e == -libc::ENODEV => {
                    if ty == libc::DT_LNK {
                        continue;
                    }
                    stack.insert(p);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// `device_enumerate_children()`.
    fn enumerate_children(&self) -> Result<(), i32> {
        if self.st().children_enumerated {
            return Ok(());
        }
        let mut stack = BTreeSet::new();
        let mut children = BTreeMap::new();
        self.enumerate_children_internal(None, &mut stack, &mut children)?;
        while let Some(subdir) = stack.pop_first() {
            self.enumerate_children_internal(Some(&subdir), &mut stack, &mut children)?;
        }
        let mut s = self.st();
        s.children_enumerated = true;
        s.children = children;
        Ok(())
    }

    /// `sd_device_get_child_first()`: (child, suffix).
    pub fn get_child_first(&self) -> Option<(Dev, Vec<u8>)> {
        if let Err(e) = self.enumerate_children() {
            log_device_debug_errno!(self, e, "sd-device: failed to enumerate child devices: ", strerror(e));
            return None;
        }
        self.st().children_iterator = 0;
        self.get_child_next()
    }

    /// `sd_device_get_child_next()`.
    pub fn get_child_next(&self) -> Option<(Dev, Vec<u8>)> {
        let mut s = self.st();
        let i = s.children_iterator;
        let r = s.children.iter().nth(i).map(|(k, v)| (v.clone(), k.clone()));
        if r.is_some() {
            s.children_iterator += 1;
        }
        r
    }

    /// `sd_device_new_child()`.
    pub fn new_child(&self, suffix: &[u8]) -> Result<Dev, i32> {
        if !path_is_safe(suffix) {
            return Err(-libc::EINVAL);
        }
        if let Some(c) = self.st().children.get(suffix) {
            return Ok(c.clone());
        }
        Device::new_from_syspath(&path_join(&[self.syspath().bytes(), suffix]))
    }

    /// `device_new_from_child()`.
    fn new_from_child(&self) -> Result<Dev, i32> {
        let mut path = self.syspath().bytes().to_vec();
        loop {
            let p = path_extract_directory(&path)?;
            if path_equal(&p, b"/sys") {
                return Err(-libc::ENODEV);
            }
            match Device::new_from_syspath(&p) {
                Err(e) if e == -libc::ENODEV => path = p,
                r => return r,
            }
        }
    }

    /// `sd_device_get_parent()`.
    pub fn get_parent(&self) -> Result<Dev, i32> {
        if !self.st().parent_set {
            match self.new_from_child() {
                Ok(p) => self.st().parent = Some(p),
                Err(e) if e == -libc::ENODEV => {}
                Err(e) => return Err(e),
            }
            self.st().parent_set = true;
        }
        self.st().parent.clone().ok_or(-libc::ENOENT)
    }

    /// `device_set_subsystem()`.
    pub fn set_subsystem(&self, subsystem: Option<&[u8]>) -> Result<(), i32> {
        self.add_property_internal(b"SUBSYSTEM", subsystem)?;
        let mut s = self.st();
        s.subsystem_set = true;
        s.subsystem = subsystem.map(DStr::new);
        Ok(())
    }

    /// `device_set_drivers_subsystem()`.
    pub fn set_drivers_subsystem(&self) -> Result<(), i32> {
        let devpath = self.devpath_bytes();
        let d = devpath.bytes();
        let pos = match d.windows(9).position(|w| w == b"/drivers/") {
            Some(p) => p,
            None if d.ends_with(b"/drivers") => d.len() - 8,
            None => return Err(-libc::EINVAL),
        };
        let (len, begin, _) = path_find_last_component(&d[..=pos], false)?;
        if len == 0 {
            return Err(-libc::EINVAL);
        }
        let subsystem = d[begin..begin + len].to_vec();
        self.set_subsystem(Some(b"drivers"))?;
        self.st().driver_subsystem = Some(DStr::new(&subsystem));
        Ok(())
    }

    /// `sd_device_get_subsystem()`.
    pub fn get_subsystem(&self) -> Result<DStr, i32> {
        self.read_uevent_file()?;
        if !self.st().subsystem_set {
            let devpath = self.devpath_bytes();
            let r = match self.get_sysattr_safe_string(b"subsystem") {
                Err(e) if e != -libc::ENOENT => {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to read subsystem for ",
                        devpath,
                        ": ",
                        strerror(e)
                    ));
                }
                Ok(s) => self.set_subsystem(Some(s.bytes())),
                Err(_) => {
                    let d = devpath.bytes();
                    if path_startswith(d, b"/module/").is_some_and(|r| !r.is_empty()) {
                        self.set_subsystem(Some(b"module"))
                    } else if d.windows(9).any(|w| w == b"/drivers/") || d.ends_with(b"/drivers") {
                        self.set_drivers_subsystem()
                    } else if path_startswith(d, b"/class/")
                        .or_else(|| path_startswith(d, b"/bus/"))
                        .is_some_and(|r| !r.is_empty())
                    {
                        self.set_subsystem(Some(b"subsystem"))
                    } else {
                        self.set_subsystem(None)
                    }
                }
            };
            if let Err(e) = r {
                return Err(log_device_debug_errno!(
                    self,
                    e,
                    "sd-device: Failed to set subsystem for ",
                    devpath,
                    ": ",
                    strerror(e)
                ));
            }
        }
        self.st().subsystem.clone().ok_or(-libc::ENOENT)
    }

    /// `sd_device_get_driver_subsystem()`.
    pub fn get_driver_subsystem(&self) -> Result<DStr, i32> {
        if !self.in_subsystem(&[b"drivers"])? {
            return Err(-libc::ENOENT);
        }
        Ok(self.st().driver_subsystem.clone().expect("set with the drivers subsystem"))
    }

    /// `sd_device_get_devtype()`.
    pub fn get_devtype(&self) -> Result<DStr, i32> {
        self.read_uevent_file()?;
        self.st().devtype.clone().ok_or(-libc::ENOENT)
    }

    /// `sd_device_get_parent_with_subsystem_devtype()`.
    pub fn get_parent_with_subsystem_devtype(&self, subsystem: &[u8], devtype: Option<&[u8]>) -> Result<Dev, i32> {
        let mut d = self.get_parent()?;
        loop {
            if d.is_subsystem_devtype(Some(subsystem), devtype)? {
                return Ok(d);
            }
            d = d.get_parent()?;
        }
    }

    /// `sd_device_get_devnum()`.
    pub fn get_devnum(&self) -> Result<u64, i32> {
        self.read_uevent_file()?;
        let d = self.st().devnum;
        if major(d) == 0 { Err(-libc::ENOENT) } else { Ok(d) }
    }

    /// `device_set_driver()`.
    pub fn set_driver(&self, driver: Option<&[u8]>) -> Result<(), i32> {
        self.add_property_internal(b"DRIVER", driver)?;
        let mut s = self.st();
        s.driver_set = true;
        s.driver = driver.map(DStr::new);
        Ok(())
    }

    /// `sd_device_get_driver()`.
    pub fn get_driver(&self) -> Result<DStr, i32> {
        self.read_uevent_file()?;
        if !self.st().driver_set {
            let driver = match self.get_sysattr_safe_string(b"driver") {
                Ok(d) => Some(d),
                Err(e) if e == -libc::ENOENT => None,
                Err(e) => {
                    return Err(log_device_debug_errno!(self, e, "sd-device: Failed to read driver: ", strerror(e)));
                }
            };
            if let Err(e) = self.set_driver(driver.as_ref().map(|d| d.bytes())) {
                return Err(log_device_debug_errno!(
                    self,
                    e,
                    "sd-device: Failed to set driver \"",
                    driver.as_ref().map(|d| d.bytes()).unwrap_or(b"(null)"),
                    "\": ",
                    strerror(e)
                ));
            }
        }
        self.st().driver.clone().ok_or(-libc::ENOENT)
    }

    /// `sd_device_get_devpath()`.
    pub fn get_devpath(&self) -> DStr {
        self.devpath_bytes()
    }

    /// `sd_device_get_devname()`.
    pub fn get_devname(&self) -> Result<DStr, i32> {
        self.read_uevent_file()?;
        self.st().devname.clone().ok_or(-libc::ENOENT)
    }

    /// `device_set_sysname_and_sysnum()`.
    fn set_sysname_and_sysnum(&self) -> Result<(), i32> {
        // A device made from a strv or nulstr may have no devpath yet
        // (logging asks for the sysname): path_extract_filename(NULL).
        let Some(devpath) = self.st().devpath.clone() else {
            return Err(-libc::EINVAL);
        };
        let (_, name, is_dir) = path_split_prefix_filename(devpath.bytes(), false, true)?;
        if is_dir {
            return Err(-libc::EINVAL);
        }
        let sysname: Vec<u8> = name.expect("requested").iter().map(|&c| if c == b'!' { b'/' } else { c }).collect();
        let mut n = digits_from_end(&sysname);
        if n == sysname.len() {
            n = 0;
        }
        let mut s = self.st();
        s.sysnum = if n > 0 { Some(DStr::new(&sysname[sysname.len() - n..])) } else { None };
        s.sysname = Some(DStr::new(&sysname));
        Ok(())
    }

    /// `sd_device_get_sysname()`.
    pub fn get_sysname(&self) -> Result<DStr, i32> {
        if self.st().sysname.is_none() {
            self.set_sysname_and_sysnum()?;
        }
        Ok(self.st().sysname.clone().expect("just set"))
    }

    /// `sd_device_get_sysnum()`.
    pub fn get_sysnum(&self) -> Result<DStr, i32> {
        if self.st().sysname.is_none() {
            self.set_sysname_and_sysnum()?;
        }
        self.st().sysnum.clone().ok_or(-libc::ENOENT)
    }

    /// `device_get_sysnum_unsigned()`.
    pub fn get_sysnum_unsigned(&self) -> Result<u32, i32> {
        let s = self.get_sysnum()?;
        safe_atou_full(s.bytes(), SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_WHITESPACE | 10)
    }

    /// `sd_device_get_action()`.
    pub fn get_action(&self) -> Result<Action, i32> {
        self.st().action.ok_or(-libc::ENOENT)
    }

    /// `sd_device_get_seqnum()`.
    pub fn get_seqnum(&self) -> Result<u64, i32> {
        let n = self.st().seqnum;
        if n == 0 { Err(-libc::ENOENT) } else { Ok(n) }
    }

    /// `sd_device_get_diskseq()`.
    pub fn get_diskseq(&self) -> Result<u64, i32> {
        self.read_uevent_file()?;
        let n = self.st().diskseq;
        if n == 0 { Err(-libc::ENOENT) } else { Ok(n) }
    }

    /// `device_add_tag()`.
    pub fn add_tag(&self, tag: &[u8], both: bool) -> Result<(), i32> {
        if !is_valid_tag(tag) {
            return Err(-libc::EINVAL);
        }
        let mut s = self.st();
        s.all_tags.insert(DStr::new(tag));
        if both {
            s.current_tags.insert(DStr::new(tag));
        }
        s.tags_generation += 1;
        s.property_tags_outdated = true;
        Ok(())
    }

    /// `device_add_devlink()`: Ok(true) if newly added.
    pub fn add_devlink(&self, devlink: &[u8]) -> Result<bool, i32> {
        let p = mangle_devname(devlink)?;
        let mut s = self.st();
        let added = if s.devlinks.iter().any(|d| path_equal(d.bytes(), &p)) {
            false
        } else {
            s.devlinks.insert(DStr::new(&p));
            true
        };
        s.devlinks_generation += 1;
        s.property_devlinks_outdated = true;
        Ok(added)
    }

    /// `device_remove_devlink()`: Ok(true) if removed.
    pub fn remove_devlink(&self, devlink: &[u8]) -> Result<bool, i32> {
        let p = mangle_devname(devlink)?;
        let mut s = self.st();
        let Some(k) = s.devlinks.iter().find(|d| path_equal(d.bytes(), &p)).cloned() else {
            return Ok(false);
        };
        s.devlinks.remove(&k);
        s.devlinks_generation += 1;
        s.property_devlinks_outdated = true;
        Ok(true)
    }

    /// `device_has_devlink()`.
    pub fn has_devlink(&self, devlink: &[u8]) -> bool {
        self.st().devlinks.iter().any(|d| path_equal(d.bytes(), devlink))
    }

    /// `device_add_property_internal_from_string()`.
    fn add_property_internal_from_string(&self, str: &[u8]) -> Result<(), i32> {
        let Some(eq) = str.iter().position(|&c| c == b'=') else {
            return Err(-libc::EINVAL);
        };
        let value = &str[eq + 1..];
        self.add_property(&str[..eq], if value.is_empty() { None } else { Some(value) })
    }

    /// `device_set_usec_initialized()`.
    pub fn set_usec_initialized(&self, when: u64) -> Result<(), i32> {
        self.add_property_internal(b"USEC_INITIALIZED", Some(when.to_string().as_bytes()))?;
        self.st().usec_initialized = when;
        Ok(())
    }

    /// `handle_db_line()`.
    fn handle_db_line(&self, key: u8, value: &[u8]) -> Result<(), i32> {
        match key {
            b'G' | b'Q' => self.add_tag(value, key == b'Q'),
            b'S' => self.add_devlink(&[b"/dev/", value].concat()).map(|_| ()),
            b'E' => self.add_property_internal_from_string(value),
            b'I' => {
                let t = safe_atou64(value)?;
                self.set_usec_initialized(t)
            }
            b'L' => {
                let p = safe_atoi(value)?;
                self.st().devlink_priority = p;
                Ok(())
            }
            b'W' => Ok(()),
            b'V' => {
                let v = safe_atou(value)?;
                self.st().database_version = v;
                Ok(())
            }
            _ => {
                log_device_debug!(self, "sd-device: Unknown key '", [key], "' in device db, ignoring");
                Ok(())
            }
        }
    }

    /// `sd_device_get_device_id()`.
    pub fn get_device_id(&self) -> Result<DStr, i32> {
        if let Some(id) = self.st().device_id.clone() {
            return Ok(id);
        }
        let id: Vec<u8> = if let Ok(devnum) = self.get_devnum() {
            let t = if self.in_subsystem(&[b"block"])? { 'b' } else { 'c' };
            format!("{t}{}", devnum_format(devnum)).into_bytes()
        } else if let Ok(ifindex) = self.get_ifindex() {
            format!("n{}", ifindex as u32).into_bytes()
        } else {
            let devpath = self.devpath_bytes();
            let (_, name, is_dir) = path_split_prefix_filename(devpath.bytes(), false, true)?;
            if is_dir {
                return Err(-libc::EINVAL);
            }
            let sysname = name.expect("requested");
            if self.in_subsystem(&[b"drivers"])? {
                let ds = self.st().driver_subsystem.clone().expect("set with the drivers subsystem");
                [b"+drivers:", ds.bytes(), b":", &sysname[..]].concat()
            } else {
                let subsystem = self.get_subsystem()?;
                [b"+", subsystem.bytes(), b":", &sysname[..]].concat()
            }
        };
        if !filename_is_valid(&id) {
            return Err(-libc::EINVAL);
        }
        let id = DStr::new(&id);
        self.st().device_id = Some(id.clone());
        Ok(id)
    }

    /// `device_read_db_internal_filename()`.
    pub fn read_db_internal_filename(&self, filename: &[u8]) -> Result<(), i32> {
        let db = match crate::fileio::read_full_file_with_nuls(filename) {
            Err(e) if e == -libc::ENOENT => return Ok(()),
            Err(e) => {
                return Err(log_device_debug_errno!(
                    self,
                    e,
                    "sd-device: Failed to read db '",
                    filename,
                    "': ",
                    strerror(e)
                ));
            }
            Ok(d) => d,
        };
        {
            let mut s = self.st();
            s.is_initialized = true;
            s.db_loaded = true;
        }
        #[derive(PartialEq)]
        enum St {
            PreKey,
            Key,
            PreValue,
            Value,
            InvalidLine,
        }
        let mut state = St::PreKey;
        let mut key = 0u8;
        let mut value_start = 0usize;
        for (i, &c) in db.iter().enumerate() {
            match state {
                St::PreKey => {
                    // strchr(NEWLINE, c) also matches the NUL.
                    if c != 0 && !NEWLINE.contains(&c) {
                        key = c;
                        state = St::Key;
                    }
                }
                St::Key => {
                    if c != b':' {
                        log_device_debug!(self, "sd-device: Invalid db entry with key '", [key], "', ignoring");
                        state = St::InvalidLine;
                    } else {
                        state = St::PreValue;
                    }
                }
                St::PreValue => {
                    // QUIRK: this byte starts the value even if it's a
                    // newline, so an empty value ("E:\n") takes in the next
                    // line too.
                    value_start = i;
                    state = St::Value;
                }
                St::InvalidLine => {
                    if c == 0 || NEWLINE.contains(&c) {
                        state = St::PreKey;
                    }
                }
                St::Value => {
                    if c == 0 || NEWLINE.contains(&c) {
                        let value = crate::bytes::c_str_prefix(&db[value_start..i]);
                        if let Err(e) = self.handle_db_line(key, value) {
                            log_device_debug_errno!(
                                self,
                                e,
                                "sd-device: Failed to handle db entry '",
                                [key],
                                ":",
                                value,
                                "', ignoring: ",
                                strerror(e)
                            );
                        }
                        state = St::PreKey;
                    }
                }
            }
        }
        // QUIRK: a last line without a newline (state Value) is dropped.
        Ok(())
    }

    /// `sd_device_get_is_initialized()`.
    pub fn get_is_initialized(&self) -> Result<bool, i32> {
        match self.read_db() {
            Err(e) if e == -libc::ENOENT => return Ok(false),
            r => r?,
        }
        Ok(self.st().is_initialized)
    }

    /// `sd_device_get_usec_initialized()`.
    pub fn get_usec_initialized(&self) -> Result<u64, i32> {
        if !self.get_is_initialized()? {
            return Err(-libc::EBUSY);
        }
        let u = self.st().usec_initialized;
        if u == 0 { Err(-libc::ENODATA) } else { Ok(u) }
    }

    /// `sd_device_get_usec_since_initialized()`.
    pub fn get_usec_since_initialized(&self) -> Result<u64, i32> {
        let ts = self.get_usec_initialized()?;
        let now = sys::clock_usec(libc::CLOCK_MONOTONIC);
        if now < ts {
            return Err(-libc::EIO);
        }
        Ok(now - ts)
    }

    /// `sd_device_get_tag_first()`.
    pub fn get_tag_first(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        s.all_tags_iterator_generation = s.tags_generation;
        s.all_tags_iterator = 0;
        let r = s.all_tags.iter().next().cloned();
        if r.is_some() {
            s.all_tags_iterator = 1;
        }
        r
    }

    /// `sd_device_get_tag_next()`.
    pub fn get_tag_next(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        if s.all_tags_iterator_generation != s.tags_generation {
            return None;
        }
        let r = s.all_tags.iter().nth(s.all_tags_iterator).cloned();
        if r.is_some() {
            s.all_tags_iterator += 1;
        }
        r
    }

    /// `sd_device_get_current_tag_first()`.
    pub fn get_current_tag_first(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        s.current_tags_iterator_generation = s.tags_generation;
        s.current_tags_iterator = 0;
        let r = s.current_tags.iter().next().cloned();
        if r.is_some() {
            s.current_tags_iterator = 1;
        }
        r
    }

    /// `sd_device_get_current_tag_next()`.
    pub fn get_current_tag_next(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        if s.current_tags_iterator_generation != s.tags_generation {
            return None;
        }
        let r = s.current_tags.iter().nth(s.current_tags_iterator).cloned();
        if r.is_some() {
            s.current_tags_iterator += 1;
        }
        r
    }

    /// `sd_device_get_devlink_first()`.
    pub fn get_devlink_first(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        s.devlinks_iterator_generation = s.devlinks_generation;
        s.devlinks_iterator = 0;
        let r = s.devlinks.iter().next().cloned();
        if r.is_some() {
            s.devlinks_iterator = 1;
        }
        r
    }

    /// `sd_device_get_devlink_next()`.
    pub fn get_devlink_next(&self) -> Option<DStr> {
        let _ = self.read_db();
        let mut s = self.st();
        if s.devlinks_iterator_generation != s.devlinks_generation {
            return None;
        }
        let r = s.devlinks.iter().nth(s.devlinks_iterator).cloned();
        if r.is_some() {
            s.devlinks_iterator += 1;
        }
        r
    }

    /// All tags (`FOREACH_DEVICE_TAG`).
    pub fn tags(&self) -> Vec<DStr> {
        let _ = self.read_db();
        self.st().all_tags.iter().cloned().collect()
    }

    /// All current tags (`FOREACH_DEVICE_CURRENT_TAG`).
    pub fn current_tags(&self) -> Vec<DStr> {
        let _ = self.read_db();
        self.st().current_tags.iter().cloned().collect()
    }

    /// All devlinks (`FOREACH_DEVICE_DEVLINK`).
    pub fn devlinks(&self) -> Vec<DStr> {
        let _ = self.read_db();
        self.st().devlinks.iter().cloned().collect()
    }

    /// `device_properties_prepare()`.
    pub fn properties_prepare(&self) -> Result<(), i32> {
        self.read_uevent_file()?;
        self.read_db()?;
        if self.st().property_devlinks_outdated {
            let devlinks = set_strjoin(&self.st().devlinks, b" ", false);
            if let Some(d) = devlinks.filter(|d| !d.is_empty()) {
                self.add_property_internal(b"DEVLINKS", Some(&d))?;
            }
            self.st().property_devlinks_outdated = false;
        }
        if self.st().property_tags_outdated {
            let tags = set_strjoin(&self.st().all_tags, b":", true);
            if let Some(t) = tags.filter(|t| !t.is_empty()) {
                self.add_property_internal(b"TAGS", Some(&t))?;
            }
            let tags = set_strjoin(&self.st().current_tags, b":", true);
            if let Some(t) = tags.filter(|t| !t.is_empty()) {
                self.add_property_internal(b"CURRENT_TAGS", Some(&t))?;
            }
            self.st().property_tags_outdated = false;
        }
        Ok(())
    }

    /// `sd_device_get_property_first()`.
    pub fn get_property_first(&self) -> Option<(DStr, DStr)> {
        self.properties_prepare().ok()?;
        let mut s = self.st();
        s.properties_iterator_generation = s.properties_generation;
        s.properties_iterator = 0;
        let r = s.properties.v.first().cloned();
        if r.is_some() {
            s.properties_iterator = 1;
        }
        r
    }

    /// `sd_device_get_property_next()`.
    pub fn get_property_next(&self) -> Option<(DStr, DStr)> {
        self.properties_prepare().ok()?;
        let mut s = self.st();
        if s.properties_iterator_generation != s.properties_generation {
            return None;
        }
        let r = s.properties.v.get(s.properties_iterator).cloned();
        if r.is_some() {
            s.properties_iterator += 1;
        }
        r
    }

    /// All properties (`FOREACH_DEVICE_PROPERTY`), or none if they can't
    /// be prepared.
    pub fn properties(&self) -> Vec<(DStr, DStr)> {
        if self.properties_prepare().is_err() {
            return Vec::new();
        }
        self.st().properties.v.clone()
    }

    /// `device_sysattrs_read_all_internal()`.
    fn sysattrs_read_all_internal(&self, subdir: Option<&[u8]>, stack: &mut BTreeSet<Vec<u8>>) -> Result<(), i32> {
        let mut dir = match self.opendir(subdir) {
            Err(e) if e == -libc::ENOENT && subdir.is_some() => return Ok(()),
            r => r?,
        };
        if let Some(sub) = subdir {
            match sys::faccessat(dir.fd(), b"uevent", libc::F_OK, 0) {
                Ok(()) => return Ok(()),
                Err(e) if e == -libc::ENOENT => {}
                Err(e) => {
                    log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to access ",
                        sub,
                        "/uevent, ignoring sub-directory ",
                        sub,
                        ": ",
                        strerror(e)
                    );
                    return Ok(());
                }
            }
        }
        while let Some((name, ty)) = dir.next_entry()? {
            if name == b"." || name == b".." {
                continue;
            }
            if ty != libc::DT_LNK && ty != libc::DT_REG && ty != libc::DT_DIR {
                continue;
            }
            let p = match subdir {
                Some(s) => path_join(&[s, &name]),
                None => name.clone(),
            };
            if ty == libc::DT_DIR {
                stack.insert(p);
                continue;
            }
            let Ok(st) = sys::fstatat(dir.fd(), &name, libc::AT_SYMLINK_NOFOLLOW) else {
                continue;
            };
            if st.st_mode & (libc::S_IRUSR | libc::S_IWUSR) == 0 {
                continue;
            }
            let mut s = self.st();
            if !s.sysattrs.iter().any(|a| path_equal(a.bytes(), &p)) {
                s.sysattrs.insert(DStr::new(&p));
            }
        }
        Ok(())
    }

    /// `device_sysattrs_read_all()`.
    fn sysattrs_read_all(&self) -> Result<(), i32> {
        if self.st().sysattrs_read {
            return Ok(());
        }
        let mut stack = BTreeSet::new();
        self.sysattrs_read_all_internal(None, &mut stack)?;
        while let Some(subdir) = stack.pop_first() {
            self.sysattrs_read_all_internal(Some(&subdir), &mut stack)?;
        }
        self.st().sysattrs_read = true;
        Ok(())
    }

    /// `sd_device_get_sysattr_first()`.
    pub fn get_sysattr_first(&self) -> Option<DStr> {
        if !self.st().sysattrs_read && self.sysattrs_read_all().is_err() {
            return None;
        }
        let mut s = self.st();
        s.sysattrs_iterator = 0;
        let r = s.sysattrs.iter().next().cloned();
        if r.is_some() {
            s.sysattrs_iterator = 1;
        }
        r
    }

    /// `sd_device_get_sysattr_next()`.
    pub fn get_sysattr_next(&self) -> Option<DStr> {
        let mut s = self.st();
        if !s.sysattrs_read {
            return None;
        }
        let r = s.sysattrs.iter().nth(s.sysattrs_iterator).cloned();
        if r.is_some() {
            s.sysattrs_iterator += 1;
        }
        r
    }

    /// `sd_device_has_tag()`.
    pub fn has_tag(&self, tag: &[u8]) -> bool {
        let _ = self.read_db();
        self.st().all_tags.iter().any(|t| t.bytes() == tag)
    }

    /// `sd_device_has_current_tag()`.
    pub fn has_current_tag(&self, tag: &[u8]) -> bool {
        let _ = self.read_db();
        self.st().current_tags.iter().any(|t| t.bytes() == tag)
    }

    /// `sd_device_get_property_value()`.
    pub fn get_property_value(&self, key: &[u8]) -> Result<DStr, i32> {
        self.properties_prepare()?;
        self.st().properties.get(key).cloned().ok_or(-libc::ENOENT)
    }

    /// `device_get_property_bool()`.
    pub fn get_property_bool(&self, key: &[u8]) -> Result<bool, i32> {
        parse_boolean(self.get_property_value(key)?.bytes())
    }

    /// `device_get_property_int()`.
    pub fn get_property_int(&self, key: &[u8]) -> Result<i32, i32> {
        safe_atoi(self.get_property_value(key)?.bytes())
    }

    /// `device_get_property_uint()`.
    pub fn get_property_uint(&self, key: &[u8]) -> Result<u32, i32> {
        safe_atou(self.get_property_value(key)?.bytes())
    }

    /// `device_clear_sysattr_cache()`.
    pub fn clear_sysattr_cache(&self) {
        self.st().sysattr_values.clear();
    }

    /// `device_cache_sysattr_value_full()`: Ok(true) if cached.
    fn cache_sysattr_value_full(
        &self,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        mut error: i32,
        ignore_uevent: bool,
    ) -> bool {
        if ignore_uevent && last_path_component(&key) == b"uevent" {
            return false;
        }
        let mut s = self.st();
        s.sysattr_values.retain(|e| !path_equal(&e.key, &key));
        if error == libc::ENOANO {
            error = libc::ESTALE;
        }
        let size = value.as_ref().map_or(0, |v| v.len());
        // memdup_suffix0() then delete_trailing_chars(), which stops at a NUL.
        let value_stripped =
            value.as_ref().map(|v| DStr::new(delete_trailing_chars(crate::bytes::c_str_prefix(v), Some(NEWLINE))));
        s.sysattr_values.push(SysAttr { key, value: value.as_deref().map(DStr::new), value_stripped, size, error });
        true
    }

    /// `device_cache_sysattr_value()`.
    pub fn cache_sysattr_value(&self, key: &[u8], value: &[u8], error: i32) -> bool {
        self.cache_sysattr_value_full(key.to_vec(), Some(crate::bytes::c_str_prefix(value).to_vec()), error, true)
    }

    /// `device_get_cached_sysattr_value()`: Ok(None) is C's -ENOANO.
    fn get_cached_sysattr_value(&self, key: &[u8], with_size: bool) -> Result<Option<(DStr, usize)>, i32> {
        let s = self.st();
        let Some(e) = s.sysattr_values.iter().find(|e| path_equal(&e.key, key)) else {
            return Ok(None);
        };
        match &e.value {
            None => Err(-e.error),
            Some(v) => Ok(Some(if with_size {
                (v.clone(), e.size)
            } else {
                (e.value_stripped.clone().expect("set with the value"), 0)
            })),
        }
    }

    /// `device_chase()`: the path relative to the syspath (if asked for)
    /// and an O_PATH fd (if asked for).
    pub fn chase(&self, path: &[u8], mut flags: u32, want_fd: bool) -> Result<(Vec<u8>, Option<OwnedFd>), i32> {
        let syspath = self.syspath();
        let prefixed;
        let path = if flags & CHASE_PREFIX_ROOT != 0 || !path_is_absolute(path) {
            prefixed = path_join(&[syspath.bytes(), path]);
            flags &= !CHASE_PREFIX_ROOT;
            &prefixed[..]
        } else {
            path
        };
        let c = chase(path, None, CHASE_NO_AUTOFS | flags, true, want_fd)?;
        let resolved = c.path.expect("requested");
        if path_startswith(&resolved, b"/sys/").is_none() {
            return Err(-libc::EINVAL);
        }
        let rel = path_make_relative(syspath.bytes(), &resolved)?;
        Ok((rel, c.fd))
    }

    /// `sd_device_get_sysattr_value_with_size()`: the raw value (which may
    /// hold NULs) and its size.
    pub fn get_sysattr_value_with_size(&self, sysattr: &[u8]) -> Result<(DStr, usize), i32> {
        self.sysattr_value(sysattr, true)
    }

    /// `sd_device_get_sysattr_value()`: the value up to a NUL, without
    /// trailing newlines.
    pub fn get_sysattr_value(&self, sysattr: &[u8]) -> Result<DStr, i32> {
        self.sysattr_value(sysattr, false).map(|(v, _)| v)
    }

    fn sysattr_value(&self, sysattr: &[u8], with_size: bool) -> Result<(DStr, usize), i32> {
        if let Some(v) = self.get_cached_sysattr_value(sysattr, with_size)? {
            return Ok(v);
        }
        let mut resolved: Option<Vec<u8>> = None;
        let mut value: Option<Vec<u8>> = None;
        let r: i32 = 'cache: {
            if matches!(sysattr, b"driver" | b"subsystem" | b"module") {
                let prefixed = path_join(&[self.syspath().bytes(), sysattr]);
                let r = match readlink_value(&prefixed) {
                    Ok(v) => {
                        value = Some(v);
                        0
                    }
                    Err(e) => e,
                };
                if r != -libc::EINVAL {
                    break 'cache r;
                }
            }
            let fd = match self.chase(sysattr, CHASE_PREFIX_ROOT, true) {
                Err(e) => break 'cache e,
                Ok((res, fd)) => {
                    resolved = Some(res);
                    fd.expect("requested")
                }
            };
            if let Some(v) = self.get_cached_sysattr_value(resolved.as_deref().expect("set"), with_size)? {
                return Ok(v);
            }
            match crate::fileio::read_virtual_file_fd_with_size(fd.raw(), usize::MAX) {
                Ok((v, _)) => {
                    value = Some(v);
                    0
                }
                Err(e) => e,
            }
        };
        if r == -libc::ENOMEM {
            return Err(r);
        }
        let resolved = resolved.unwrap_or_else(|| sysattr.to_vec());
        self.cache_sysattr_value_full(resolved.clone(), if r < 0 { None } else { value }, -r, false);
        if r < 0 {
            return Err(r);
        }
        Ok(self.get_cached_sysattr_value(&resolved, with_size)?.expect("just cached"))
    }

    /// `device_get_sysattr_streq()`.
    pub fn get_sysattr_streq(&self, sysattr: &[u8], expected: &[u8]) -> Result<bool, i32> {
        Ok(self.get_sysattr_value(sysattr)?.bytes() == expected)
    }

    /// `device_get_sysattr_safe_string()`.
    pub fn get_sysattr_safe_string(&self, sysattr: &[u8]) -> Result<DStr, i32> {
        let value = self.get_sysattr_value(sysattr)?;
        if !string_is_safe(
            value.bytes(),
            STRING_ALLOW_EMPTY
                | STRING_ALLOW_NEWLINES
                | STRING_ALLOW_BACKSLASHES
                | STRING_ALLOW_QUOTES
                | STRING_ALLOW_GLOBS,
        ) {
            log_device_debug!(
                self,
                "sd-device: '",
                sysattr,
                "' sysattr contains invalid characters, refusing: ",
                cescape(value.bytes())
            );
            return Err(-libc::ENXIO);
        }
        Ok(value)
    }

    /// `device_get_sysattr_int()`: (value, value > 0).
    pub fn get_sysattr_int(&self, sysattr: &[u8]) -> Result<i32, i32> {
        let value = self.get_sysattr_value(sysattr)?;
        safe_atoi(value.bytes())
            .map_err(|e| log_device_debug_errno!(self, e, "Failed to parse '", sysattr, "' attribute: ", strerror(e)))
    }

    /// `device_get_sysattr_unsigned_full()`.
    pub fn get_sysattr_unsigned_full(&self, sysattr: &[u8], base: u32) -> Result<u32, i32> {
        let value = self.get_sysattr_value(sysattr)?;
        safe_atou_full(value.bytes(), base)
            .map_err(|e| log_device_debug_errno!(self, e, "Failed to parse '", sysattr, "' attribute: ", strerror(e)))
    }

    /// `device_get_sysattr_u64()`.
    pub fn get_sysattr_u64(&self, sysattr: &[u8]) -> Result<u64, i32> {
        let value = self.get_sysattr_value(sysattr)?;
        safe_atou64(value.bytes())
            .map_err(|e| log_device_debug_errno!(self, e, "Failed to parse '", sysattr, "' attribute: ", strerror(e)))
    }

    /// `device_get_sysattr_bool()`.
    pub fn get_sysattr_bool(&self, sysattr: &[u8]) -> Result<bool, i32> {
        parse_boolean(self.get_sysattr_value(sysattr)?.bytes())
    }

    /// `device_remove_cached_sysattr_value()`.
    fn remove_cached_sysattr_value(&self, sysattr: &[u8]) -> Result<(), i32> {
        let (resolved, _) = self.chase(sysattr, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, false)?;
        self.st().sysattr_values.retain(|e| !path_equal(&e.key, &resolved));
        Ok(())
    }

    /// `sd_device_set_sysattr_value()`; `None` drops the cached value.
    pub fn set_sysattr_value(&self, sysattr: &[u8], value: Option<&[u8]>) -> Result<(), i32> {
        let Some(value) = value else {
            return self.remove_cached_sysattr_value(sysattr);
        };
        let (resolved, fd) = match self.chase(sysattr, CHASE_PREFIX_ROOT, true) {
            Err(e) => {
                self.st().sysattr_values.retain(|e| !path_equal(&e.key, sysattr));
                return Err(e);
            }
            Ok(x) => x,
        };
        let fd = fd.expect("requested");
        let value = crate::bytes::c_str_prefix(value);
        let copied = delete_trailing_chars(&value[..value.len().min(4096)], Some(NEWLINE)).to_vec();
        if let Err(e) =
            write_string_file_fd(fd.raw(), &copied, WRITE_STRING_FILE_DISABLE_BUFFER | WRITE_STRING_FILE_AVOID_NEWLINE)
        {
            self.st().sysattr_values.retain(|e| !path_equal(&e.key, &resolved));
            return Err(e);
        }
        self.cache_sysattr_value_full(resolved, Some(copied), 0, true);
        Ok(())
    }

    /// `device_opendir()`.
    pub fn opendir(&self, subdir: Option<&[u8]>) -> Result<sys::Dir, i32> {
        let syspath = self.syspath();
        let path = match subdir {
            Some(s) => {
                if !path_is_safe(s) {
                    return Err(-libc::EINVAL);
                }
                path_join(&[syspath.bytes(), s])
            }
            None => syspath.bytes().to_vec(),
        };
        crate::sys_net::opendir(&path)
    }

    // device-private.c

    /// `device_set_devlink_priority()`.
    pub fn set_devlink_priority(&self, priority: i32) {
        self.st().devlink_priority = priority;
    }

    /// `device_set_is_initialized()`.
    pub fn set_is_initialized(&self) {
        self.st().is_initialized = true;
    }

    /// `device_get_properties_generation()`.
    pub fn properties_generation(&self) -> u64 {
        self.st().properties_generation
    }

    /// `device_get_tags_generation()`.
    pub fn tags_generation(&self) -> u64 {
        self.st().tags_generation
    }

    /// `device_get_devlinks_generation()`.
    pub fn devlinks_generation(&self) -> u64 {
        self.st().devlinks_generation
    }

    /// `device_get_devnode_mode()`.
    pub fn get_devnode_mode(&self) -> Result<u32, i32> {
        self.read_uevent_file()?;
        self.read_db()?;
        let m = self.st().devmode;
        if m == MODE_INVALID { Err(-libc::ENOENT) } else { Ok(m) }
    }

    /// `device_get_devnode_uid()`.
    pub fn get_devnode_uid(&self) -> Result<u32, i32> {
        self.read_uevent_file()?;
        self.read_db()?;
        let u = self.st().devuid;
        if u == UID_INVALID { Err(-libc::ENOENT) } else { Ok(u) }
    }

    /// `device_get_devnode_gid()`.
    pub fn get_devnode_gid(&self) -> Result<u32, i32> {
        self.read_uevent_file()?;
        self.read_db()?;
        let g = self.st().devgid;
        if g == UID_INVALID { Err(-libc::ENOENT) } else { Ok(g) }
    }

    /// `device_set_action()`.
    pub fn set_action(&self, a: Action) -> Result<(), i32> {
        self.add_property_internal(b"ACTION", Some(device_action_to_string(a).as_bytes()))?;
        self.st().action = Some(a);
        Ok(())
    }

    /// `device_set_seqnum()`.
    fn set_seqnum(&self, str: &[u8]) -> Result<(), i32> {
        let n = safe_atou64(str)?;
        if n == 0 {
            return Err(-libc::EINVAL);
        }
        self.add_property_internal(b"SEQNUM", Some(str))?;
        self.st().seqnum = n;
        Ok(())
    }

    /// `device_amend()`.
    fn amend(&self, key: &[u8], value: &[u8]) -> Result<(), i32> {
        macro_rules! fail {
            ($r:expr, $what:expr) => {
                if let Err(e) = $r {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to set ",
                        $what,
                        " to '",
                        value,
                        "': ",
                        strerror(e)
                    ));
                }
            };
        }
        match key {
            b"DEVPATH" => {
                let path = [b"/sys", value].concat();
                if let Err(e) = self.set_syspath(&path, false) {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to set syspath to '",
                        path,
                        "': ",
                        strerror(e)
                    ));
                }
            }
            b"SUBSYSTEM" => fail!(self.set_subsystem(Some(value)), "subsystem"),
            b"DEVTYPE" => fail!(self.set_devtype(value), "devtype"),
            b"DEVNAME" => fail!(self.set_devname(value), "devname"),
            b"USEC_INITIALIZED" => {
                let t = match safe_atou64(value) {
                    Ok(t) => t,
                    Err(e) => {
                        return Err(log_device_debug_errno!(
                            self,
                            e,
                            "sd-device: Failed to parse timestamp '",
                            value,
                            "': ",
                            strerror(e)
                        ));
                    }
                };
                fail!(self.set_usec_initialized(t), "usec-initialized");
            }
            b"DRIVER" => fail!(self.set_driver(Some(value)), "driver"),
            b"IFINDEX" => fail!(self.set_ifindex(value), "ifindex"),
            b"DEVMODE" => fail!(self.set_devmode(value), "devmode"),
            b"DEVUID" => fail!(self.set_devuid(value), "devuid"),
            b"DEVGID" => fail!(self.set_devgid(value), "devgid"),
            b"ACTION" => fail!(device_action_from_string(value).and_then(|a| self.set_action(a)), "action"),
            b"SEQNUM" => fail!(self.set_seqnum(value), "SEQNUM"),
            b"DISKSEQ" => fail!(self.set_diskseq(value), "DISKSEQ"),
            b"DEVLINKS" => {
                let mut p = Some(value);
                while let Some(word) = extract_first_word(&mut p, None, EXTRACT_RETAIN_ESCAPE)? {
                    if let Err(e) = self.add_devlink(&word) {
                        return Err(log_device_debug_errno!(
                            self,
                            e,
                            "sd-device: Failed to add devlink '",
                            word,
                            "': ",
                            strerror(e)
                        ));
                    }
                }
            }
            b"TAGS" | b"CURRENT_TAGS" => {
                let mut p = Some(value);
                while let Some(word) = extract_first_word(&mut p, Some(b":"), EXTRACT_DONT_COALESCE_SEPARATORS)? {
                    if word.is_empty() {
                        continue;
                    }
                    if let Err(e) = self.add_tag(&word, key == b"CURRENT_TAGS") {
                        return Err(log_device_debug_errno!(
                            self,
                            e,
                            "sd-device: Failed to add tag '",
                            word,
                            "': ",
                            strerror(e)
                        ));
                    }
                }
            }
            b"UDEV_DATABASE_VERSION" => match safe_atou(value) {
                Ok(v) => self.st().database_version = v,
                Err(e) => {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to parse udev database version '",
                        value,
                        "': ",
                        strerror(e)
                    ));
                }
            },
            _ => match self.add_property_internal(key, Some(value)) {
                Err(e) if e == -libc::EINVAL => {
                    log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to add property '",
                        cescape(key),
                        "=",
                        cescape(value),
                        "', ignoring: ",
                        strerror(e)
                    );
                }
                Err(e) => {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to add property '",
                        key,
                        "=",
                        value,
                        "': ",
                        strerror(e)
                    ));
                }
                Ok(()) => {}
            },
        }
        Ok(())
    }

    /// `device_append()`.
    fn append(&self, kv: &[u8], major: &mut Option<Vec<u8>>, minor: &mut Option<Vec<u8>>) -> Result<(), i32> {
        let Some(eq) = kv.iter().position(|&c| c == b'=') else {
            return Err(log_device_debug_errno!(
                self,
                synthetic(libc::EINVAL),
                "sd-device: Not a key-value pair: '",
                kv,
                "'"
            ));
        };
        let (key, value) = (&kv[..eq], &kv[eq + 1..]);
        match key {
            b"MAJOR" => *major = Some(value.to_vec()),
            b"MINOR" => *minor = Some(value.to_vec()),
            _ => self.amend(key, value)?,
        }
        Ok(())
    }

    /// `device_seal()`.
    pub fn seal(&self) {
        self.st().sealed = true;
    }

    /// `device_verify()`.
    fn verify(&self) -> Result<(), i32> {
        let ok = {
            let s = self.st();
            s.devpath.is_some() && s.subsystem.is_some() && s.action.is_some() && s.seqnum != 0
        };
        if !ok {
            return Err(log_device_debug_errno!(
                self,
                synthetic(libc::EINVAL),
                "sd-device: Device created from strv or nulstr lacks devpath, subsystem, action or seqnum."
            ));
        }
        match self.in_subsystem(&[b"drivers"]) {
            Err(e) => {
                return Err(log_device_debug_errno!(
                    self,
                    e,
                    "sd-device: Failed to check if the device is a driver: ",
                    strerror(e)
                ));
            }
            Ok(true) => {
                if let Err(e) = self.set_drivers_subsystem() {
                    return Err(log_device_debug_errno!(
                        self,
                        e,
                        "sd-device: Failed to set driver subsystem: ",
                        strerror(e)
                    ));
                }
            }
            Ok(false) => {}
        }
        self.st().sealed = true;
        Ok(())
    }

    fn finish_new(&self, major: Option<Vec<u8>>, minor: Option<Vec<u8>>) -> Result<(), i32> {
        if let Some(ma) = &major
            && let Err(e) = self.set_devnum(ma, minor.as_deref())
        {
            return Err(log_device_debug_errno!(
                self,
                e,
                "sd-device: Failed to set devnum ",
                ma,
                ":",
                minor.as_deref().unwrap_or(b"(null)"),
                ": ",
                strerror(e)
            ));
        }
        self.verify()
    }

    /// `device_new_from_strv()`: each entry is a C string.
    pub fn new_from_strv(strv: &[&[u8]]) -> Result<Dev, i32> {
        Device::new_from_strv_split(strv, &mut |_, _| {})
    }

    /// `device_new_from_strv()`, telling `split(i, n)` where C's
    /// `device_append()` writes a NUL over the '=' of entry i, at offset n.
    /// QUIRK: C splits the caller's strings in place and leaves them so; for
    /// `udev_device_new_from_environment()` that's the process environment.
    pub fn new_from_strv_split(strv: &[&[u8]], split: &mut dyn FnMut(usize, usize)) -> Result<Dev, i32> {
        let d = Device::new_aux();
        let (mut major, mut minor) = (None, None);
        for (i, kv) in strv.iter().enumerate() {
            let kv = crate::bytes::c_str_prefix(kv);
            if let Some(eq) = kv.iter().position(|&c| c == b'=') {
                split(i, eq);
            }
            d.append(kv, &mut major, &mut minor)?;
        }
        d.finish_new(major, minor)?;
        Ok(d)
    }

    /// `device_new_from_nulstr()`.
    pub fn new_from_nulstr(nulstr: &[u8]) -> Result<Dev, i32> {
        let d = Device::new_aux();
        let (mut major, mut minor) = (None, None);
        let mut i = 0;
        while i < nulstr.len() {
            let rest = &nulstr[i..];
            let Some(end) = rest.iter().position(|&c| c == 0) else {
                return Err(log_device_debug_errno!(d, synthetic(libc::EINVAL), "sd-device: Failed to parse nulstr"));
            };
            i += end + 1;
            let mut key = &rest[..end];
            // truncate_nl(): drop a newline and everything after it.
            if let Some(nl) = key.iter().position(|c| NEWLINE.contains(c)) {
                key = &key[..nl];
            }
            d.append(key, &mut major, &mut minor)?;
        }
        d.finish_new(major, minor)?;
        Ok(d)
    }

    /// `device_update_properties_bufs()`.
    fn update_properties_bufs(&self) -> Result<(), i32> {
        if !self.st().properties_buf_outdated {
            return Ok(());
        }
        let mut nulstr = format!("UDEV_DATABASE_VERSION={LATEST_UDEV_DATABASE_VERSION}\0").into_bytes();
        for (k, v) in self.properties() {
            nulstr.extend_from_slice(k.bytes());
            nulstr.push(b'=');
            nulstr.extend_from_slice(v.bytes());
            nulstr.push(0);
        }
        let strv: Vec<DStr> = nulstr.split(|&c| c == 0).filter(|p| !p.is_empty()).map(DStr::new).collect();
        let mut s = self.st();
        s.properties_nulstr = Some(nulstr.into());
        s.properties_strv = Some(Rc::new(strv));
        s.properties_buf_outdated = false;
        Ok(())
    }

    /// `device_get_properties_nulstr()`: the nulstr (without the final
    /// extra NUL).
    pub fn get_properties_nulstr(&self) -> Result<Rc<[u8]>, i32> {
        self.update_properties_bufs()?;
        Ok(self.st().properties_nulstr.clone().unwrap_or_else(|| Rc::from(&b""[..])))
    }

    /// `device_get_properties_strv()`.
    pub fn get_properties_strv(&self) -> Result<Rc<Vec<DStr>>, i32> {
        self.update_properties_bufs()?;
        Ok(self.st().properties_strv.clone().unwrap_or_default())
    }

    /// `device_get_devlink_priority()`.
    pub fn get_devlink_priority(&self) -> Result<i32, i32> {
        self.read_db()?;
        Ok(self.st().devlink_priority)
    }

    /// `device_read_db_internal()`.
    pub fn read_db_internal(&self, force: bool) -> Result<(), i32> {
        {
            let s = self.st();
            if s.db_loaded || (!force && s.sealed) {
                return Ok(());
            }
        }
        let path = self.get_db_path()?;
        self.read_db_internal_filename(&path)
    }

    /// `device_read_db()`.
    pub fn read_db(&self) -> Result<(), i32> {
        self.read_db_internal(false)
    }

    /// `device_get_db_path()`.
    pub fn get_db_path(&self) -> Result<Vec<u8>, i32> {
        let id = self.get_device_id()?;
        Ok(path_join(&[b"/run/udev/data/", id.bytes()]))
    }

    /// `device_has_db()`.
    pub fn has_db(&self) -> Result<bool, i32> {
        let path = self.get_db_path()?;
        Ok(crate::sys_net::access(&path, libc::F_OK).is_ok())
    }

    /// `device_set_db_persist()`.
    pub fn set_db_persist(&self) {
        self.st().db_persist = true;
    }

    // device-util.c

    /// `device_in_subsystem_strv()`.
    pub fn in_subsystem(&self, subsystems: &[&[u8]]) -> Result<bool, i32> {
        match self.get_subsystem() {
            Err(e) if e == -libc::ENOENT => Ok(subsystems.is_empty()),
            Err(e) => Err(e),
            Ok(s) => Ok(subsystems.contains(&s.bytes())),
        }
    }

    /// `device_is_devtype()`.
    pub fn is_devtype(&self, devtype: Option<&[u8]>) -> Result<bool, i32> {
        match self.get_devtype() {
            Err(e) if e == -libc::ENOENT => Ok(devtype.is_none()),
            Err(e) => Err(e),
            Ok(s) => Ok(Some(s.bytes()) == devtype),
        }
    }

    /// `device_is_subsystem_devtype()`.
    pub fn is_subsystem_devtype(&self, subsystem: Option<&[u8]>, devtype: Option<&[u8]>) -> Result<bool, i32> {
        let subs: Vec<&[u8]> = subsystem.into_iter().collect();
        if !self.in_subsystem(&subs)? {
            return Ok(false);
        }
        if devtype.is_none() {
            return Ok(true);
        }
        self.is_devtype(devtype)
    }
}

/// `log_device_full_errno_zerook(device, level, error, ...)` for a device
/// that may be NULL.
pub fn log_device_full(dev: Option<&Device>, level: i32, error: i32, msg: Vec<u8>) -> i32 {
    if !crate::log::enabled(level) {
        return -crate::errno::errno_value(error);
    }
    let sysname = dev.and_then(|d| d.get_sysname().ok());
    crate::log::log_object_internal(
        level,
        error,
        crate::log::Loc { file: file!(), line: line!(), func: "" },
        sysname.as_ref().map(|s| (&b"DEVICE="[..], s.bytes())),
        msg,
    )
}

// device-private.c: the parts udevd and the rule runner write with.
impl Device {
    /// `sd_device_get_trigger_uuid()`: `SYNTH_UUID`, as a UUID string.
    pub fn get_trigger_uuid(&self) -> Result<Vec<u8>, i32> {
        let v = self.get_property_value(b"SYNTH_UUID")?;
        let hex: Vec<u8> = v.bytes().iter().copied().filter(|&c| c != b'-').collect();
        if hex.len() != 32 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return Err(-libc::EINVAL);
        }
        let h = hex.to_ascii_lowercase();
        if h.iter().all(|&c| c == b'0') {
            return Err(-libc::ENOENT);
        }
        Ok(crate::bcat!(&h[0..8], "-", &h[8..12], "-", &h[12..16], "-", &h[16..20], "-", &h[20..32]))
    }

    /// `device_clone_with_db()`.
    pub fn clone_with_db(&self) -> Result<Dev, i32> {
        let dest = Device::new_aux();
        dest.st().sealed = true;
        let syspath = self.st().syspath.clone().ok_or(-libc::EINVAL)?;
        dest.set_syspath(syspath.bytes(), false)?;
        let props: Vec<(DStr, DStr)> = self.st().properties.v.clone();
        for (key, val) in &props {
            if key.bytes() == b"MINOR" {
                continue;
            }
            if key.bytes() == b"MAJOR" {
                let minor = props.iter().find(|(k, _)| k.bytes() == b"MINOR").map(|(_, v)| v.bytes().to_vec());
                dest.set_devnum(val.bytes(), minor.as_deref())?;
            } else {
                dest.amend(key.bytes(), val.bytes())?;
            }
            if key.bytes() == b"SUBSYSTEM" && val.bytes() == b"drivers" {
                let ds = self.st().driver_subsystem.clone();
                dest.st().driver_subsystem = ds;
            }
        }
        dest.read_db_internal(true)?;
        Ok(dest)
    }

    /// `device_copy_all_tags(dest, src)`.
    pub fn copy_all_tags(&self, src: Option<&Device>) -> Result<(), i32> {
        let Some(src) = src else { return Ok(()) };
        for tag in src.tags() {
            self.add_tag(tag.bytes(), false)?;
        }
        Ok(())
    }

    /// `device_cleanup_tags(device, original)`.
    pub fn cleanup_tags(&self, original: Option<&Device>) -> Result<(), i32> {
        let saved = {
            let mut s = self.st();
            let saved = std::mem::take(&mut s.all_tags);
            s.current_tags.clear();
            s.property_tags_outdated = true;
            s.tags_generation += 1;
            saved
        };
        if let Err(r) = self.copy_all_tags(original) {
            self.st().all_tags = saved;
            return Err(r);
        }
        Ok(())
    }

    /// `device_cleanup_devlinks()`.
    pub fn cleanup_devlinks(&self) {
        let mut s = self.st();
        s.devlinks.clear();
        s.property_devlinks_outdated = true;
        s.devlinks_generation += 1;
    }

    /// `device_remove_tag()`.
    pub fn remove_tag(&self, tag: &[u8]) {
        let mut s = self.st();
        s.current_tags.remove(&DStr::new(tag));
        s.property_tags_outdated = true;
        s.tags_generation += 1;
    }

    /// `device_tag(device, tag, add)`.
    fn tag(&self, tag: &[u8], add: bool) -> Result<(), i32> {
        let id = self.get_device_id()?;
        let path = crate::bcat!("/run/udev/tags/", tag, "/", id.bytes());
        if add {
            return crate::fs::touch_file(&path, true, u64::MAX, u32::MAX, u32::MAX, 0o444);
        }
        match sys::unlinkat(crate::fd::AT_FDCWD, &path, 0) {
            Err(r) if r != -libc::ENOENT => Err(r),
            _ => Ok(()),
        }
    }

    /// `device_tag_index(device, add)`.
    pub fn tag_index(&self, add: bool) -> Result<(), i32> {
        let mut r = 0;
        for tag in self.tags() {
            if let Err(e) = self.tag(tag.bytes(), add) {
                crate::errno::ret_gather(&mut r, e);
            }
        }
        if r < 0 { Err(r) } else { Ok(()) }
    }

    /// `device_has_info()`.
    fn has_info(&self) -> bool {
        let s = self.st();
        !s.devlinks.is_empty()
            || s.devlink_priority != 0
            || !s.properties_db.v.is_empty()
            || !s.all_tags.is_empty()
            || !s.current_tags.is_empty()
    }

    /// `device_should_have_db()`.
    pub fn should_have_db(&self) -> bool {
        if self.has_info() {
            return true;
        }
        let s = self.st();
        libc::major(s.devnum) != 0 || s.ifindex != 0
    }

    /// `device_ensure_usec_initialized(device, device_old)`.
    pub fn ensure_usec_initialized(&self, old: Option<&Device>) -> Result<(), i32> {
        let when = match old.map(|o| o.st().usec_initialized) {
            Some(u) if u > 0 => u,
            _ => crate::time::now_monotonic(),
        };
        self.set_usec_initialized(when)
    }

    /// `device_delete_db()`.
    pub fn delete_db(&self) -> Result<(), i32> {
        let path = self.get_db_path()?;
        match sys::unlinkat(crate::fd::AT_FDCWD, &path, 0) {
            Err(r) if r != -libc::ENOENT => Err(r),
            _ => Ok(()),
        }
    }

    /// `device_update_db()`.
    pub fn update_db(&self) -> Result<(), i32> {
        if !self.should_have_db() {
            return self.delete_db();
        }
        let path = self.get_db_path()?;
        // C's cleanup unlinks the database file too when this fails.
        let unlink_db = || {
            let _ = sys::unlinkat(crate::fd::AT_FDCWD, &path, 0);
        };
        if let Err(r) = crate::fs::mkdirat_parents(crate::fd::AT_FDCWD, &path, 0o755) {
            unlink_db();
            return Err(log_device_debug_errno!(
                self,
                r,
                "sd-device: Failed to create parent directories of '",
                &path,
                "': ",
                strerror(r)
            ));
        }
        let (fd, tmp) = match crate::fs::fopen_temporary(&path) {
            Ok(x) => x,
            Err(r) => {
                unlink_db();
                return Err(log_device_debug_errno!(
                    self,
                    r,
                    "sd-device: Failed to create temporary file for database file '",
                    &path,
                    "': ",
                    strerror(r)
                ));
            }
        };
        let fail = |r: i32, msg: Vec<u8>| -> i32 {
            let _ = sys::unlinkat(crate::fd::AT_FDCWD, &tmp, 0);
            unlink_db();
            log_device_debug_errno!(self, r, msg)
        };
        let persist = self.st().db_persist;
        if let Err(r) = sys::fchmod(fd.raw(), if persist { 0o1644 } else { 0o644 }) {
            return Err(fail(
                r,
                crate::bcat!("sd-device: Failed to chmod temporary database file '", &tmp, "': ", strerror(r)),
            ));
        }
        let mut f: Vec<u8> = Vec::new();
        if self.has_info() {
            let (devnum, prio, usec, props_db, current) = {
                let s = self.st();
                (s.devnum, s.devlink_priority, s.usec_initialized, s.properties_db.v.clone(), s.current_tags.clone())
            };
            if libc::major(devnum) > 0 {
                for l in self.devlinks() {
                    f.extend(crate::bcat!("S:", &l.bytes()[5..], "\n"));
                }
                if prio != 0 {
                    f.extend(format!("L:{prio}\n").into_bytes());
                }
            }
            if usec > 0 {
                f.extend(format!("I:{usec}\n").into_bytes());
            }
            for (k, v) in &props_db {
                f.extend(crate::bcat!("E:", k.bytes(), "=", v.bytes(), "\n"));
            }
            for t in self.tags() {
                f.extend(crate::bcat!("G:", t.bytes(), "\n"));
            }
            for t in &current {
                f.extend(crate::bcat!("Q:", t.bytes(), "\n"));
            }
            f.extend_from_slice(b"V:1\n");
        }
        if let Err(r) = sys::write_all(fd.raw(), &f) {
            return Err(fail(
                r,
                crate::bcat!("sd-device: Failed to flush temporary database file '", &tmp, "': ", strerror(r)),
            ));
        }
        if let Err(r) = sys::renameat(crate::fd::AT_FDCWD, &tmp, crate::fd::AT_FDCWD, &path) {
            return Err(fail(
                r,
                crate::bcat!(
                    "sd-device: Failed to rename temporary database file '",
                    &tmp,
                    "' to '",
                    &path,
                    "': ",
                    strerror(r)
                ),
            ));
        }
        let devpath = self.get_devpath();
        log_device_debug!(self, "sd-device: Created database file '", &path, "' for '", devpath.bytes(), "'.");
        Ok(())
    }
}

#[macro_export]
macro_rules! log_device_info {
    ($dev:expr, $($e:expr),* $(,)?) => { $crate::log_device_full_errno!($dev, $crate::log::LOG_INFO, 0, $($e),*) };
}

#[macro_export]
macro_rules! log_device_notice {
    ($dev:expr, $($e:expr),* $(,)?) => { $crate::log_device_full_errno!($dev, $crate::log::LOG_NOTICE, 0, $($e),*) };
}

#[macro_export]
macro_rules! log_device_warning {
    ($dev:expr, $($e:expr),* $(,)?) => { $crate::log_device_full_errno!($dev, $crate::log::LOG_WARNING, 0, $($e),*) };
}

#[macro_export]
macro_rules! log_device_warning_errno {
    ($dev:expr, $err:expr, $($e:expr),* $(,)?) => {
        $crate::log_device_full_errno!($dev, $crate::log::LOG_WARNING, $err, $($e),*)
    };
}

#[macro_export]
macro_rules! log_device_error {
    ($dev:expr, $($e:expr),* $(,)?) => { $crate::log_device_full_errno!($dev, $crate::log::LOG_ERR, 0, $($e),*) };
}

#[macro_export]
macro_rules! log_device_error_errno {
    ($dev:expr, $err:expr, $($e:expr),* $(,)?) => {
        $crate::log_device_full_errno!($dev, $crate::log::LOG_ERR, $err, $($e),*)
    };
}
