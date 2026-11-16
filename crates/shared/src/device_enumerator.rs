// SPDX-License-Identifier: LGPL-2.1-or-later
//! `device-enumerator.c`: find the devices in sysfs (or in the udev tag
//! index) that pass a set of matches, sorted as udev wants them.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::device_filter::{MatchStrv, device_match_parent, device_match_sysattr, set_fnmatch, strv_fnmatch};
use crate::errno::strerror;
use crate::log_debug_errno;
use crate::path::{path_compare, path_extract_directory};
use crate::sd_device::{Dev, Device, errno_is_neg_device_absent};
use crate::sys::fnmatch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnumerationType {
    Devices,
    Subsystems,
    All,
}

/// `MatchInitializedType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchInitialized {
    /// Only devices without a db entry.
    No,
    /// Only devices with a db entry.
    Yes,
    /// All devices.
    All,
    /// Devices that have a db entry, or no devnode and no ifindex.
    Compat,
}

pub const MATCH_BASIC: u32 = 1 << 0;
pub const MATCH_SYSNAME: u32 = 1 << 1;
pub const MATCH_SUBSYSTEM: u32 = 1 << 2;
pub const MATCH_PARENT: u32 = 1 << 3;
pub const MATCH_TAG: u32 = 1 << 4;
pub const MATCH_ALL: u32 = (1 << 5) - 1;

/// `sd_device_enumerator`.
#[derive(Debug)]
pub struct Enumerator {
    ty: Option<EnumerationType>,
    devices_by_syspath: BTreeMap<Vec<u8>, Dev>,
    devices: Vec<Dev>,
    current_device_index: usize,
    scan_uptodate: bool,
    sorted: bool,

    prioritized_subsystems: Vec<Vec<u8>>,
    match_subsystem: BTreeSet<Vec<u8>>,
    nomatch_subsystem: BTreeSet<Vec<u8>>,
    match_sysattr: MatchStrv,
    nomatch_sysattr: MatchStrv,
    match_property: MatchStrv,
    match_property_required: MatchStrv,
    match_sysname: BTreeSet<Vec<u8>>,
    nomatch_sysname: BTreeSet<Vec<u8>>,
    match_tag: BTreeSet<Vec<u8>>,
    match_parent: Option<BTreeSet<Vec<u8>>>,
    match_initialized: MatchInitialized,
    parent_match_flags: u32,
}

impl Default for Enumerator {
    fn default() -> Self {
        Enumerator::new()
    }
}

/// `sound_device_compare()`.
fn sound_device_compare(a: &[u8], b: &[u8]) -> Ordering {
    if !a.windows(11).any(|w| w == b"/sound/card") {
        return Ordering::Equal;
    }
    // QUIRK: C looks for the '/' from the start of the devpath, not after
    // "/sound/card", so the prefix is always empty and the controlC test
    // runs on the whole devpaths, which never start with it: sound devices
    // aren't reordered.
    let Some(pos) = a.iter().position(|&c| c == b'/') else {
        return Ordering::Equal;
    };
    let n = pos;
    let strneq = (0..n).all(|i| a.get(i) == b.get(i));
    if !strneq {
        return Ordering::Equal;
    }
    let sound_a = &a[pos..];
    let sound_b = &b[n.min(b.len())..];
    sound_a.starts_with(b"/controlC").cmp(&sound_b.starts_with(b"/controlC"))
}

/// `devpath_is_late_block()`.
fn devpath_is_late_block(d: &[u8]) -> bool {
    d.windows(9).any(|w| w == b"/block/md") || d.windows(10).any(|w| w == b"/block/dm-")
}

/// `device_compare()`.
fn device_compare(a: &Dev, b: &Dev) -> Ordering {
    let da = a.get_devpath();
    let db = b.get_devpath();
    let (da, db) = (da.bytes(), db.bytes());
    let r = sound_device_compare(da, db);
    if r != Ordering::Equal {
        return r;
    }
    let r = devpath_is_late_block(da).cmp(&devpath_is_late_block(db));
    if r != Ordering::Equal {
        return r;
    }
    path_compare(da, db)
}

/// `relevant_sysfs_subdir()`.
fn relevant_sysfs_subdir(name: &[u8], ty: u8) -> bool {
    if name.first() == Some(&b'.') {
        return false;
    }
    ty == libc::DT_DIR || ty == libc::DT_LNK
}

impl Enumerator {
    /// `sd_device_enumerator_new()`.
    pub fn new() -> Enumerator {
        Enumerator {
            ty: None,
            devices_by_syspath: BTreeMap::new(),
            devices: Vec::new(),
            current_device_index: 0,
            scan_uptodate: false,
            sorted: false,
            prioritized_subsystems: Vec::new(),
            match_subsystem: BTreeSet::new(),
            nomatch_subsystem: BTreeSet::new(),
            match_sysattr: Vec::new(),
            nomatch_sysattr: Vec::new(),
            match_property: Vec::new(),
            match_property_required: Vec::new(),
            match_sysname: BTreeSet::new(),
            nomatch_sysname: BTreeSet::new(),
            match_tag: BTreeSet::new(),
            match_parent: None,
            match_initialized: MatchInitialized::Compat,
            parent_match_flags: MATCH_ALL,
        }
    }

    /// `device_enumerator_unref_devices()`.
    fn unref_devices(&mut self) {
        self.devices_by_syspath.clear();
        self.devices.clear();
    }

    /// `device_enumerator_add_prioritized_subsystem()`.
    pub fn add_prioritized_subsystem(&mut self, subsystem: &[u8]) -> bool {
        if self.prioritized_subsystems.iter().any(|s| s == subsystem) {
            return false;
        }
        self.prioritized_subsystems.push(subsystem.to_vec());
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_subsystem()`.
    pub fn add_match_subsystem(&mut self, subsystem: &[u8], m: bool) -> bool {
        let set = if m { &mut self.match_subsystem } else { &mut self.nomatch_subsystem };
        if !set.insert(subsystem.to_vec()) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_sysattr()`.
    pub fn add_match_sysattr(&mut self, sysattr: &[u8], value: Option<&[u8]>, m: bool) -> bool {
        let h = if m { &mut self.match_sysattr } else { &mut self.nomatch_sysattr };
        if !crate::device_filter::update_match_strv(h, sysattr, value, true) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_property()`.
    pub fn add_match_property(&mut self, property: &[u8], value: Option<&[u8]>) -> bool {
        if !crate::device_filter::update_match_strv(&mut self.match_property, property, value, false) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_property_required()`.
    pub fn add_match_property_required(&mut self, property: &[u8], value: Option<&[u8]>) -> bool {
        if !crate::device_filter::update_match_strv(&mut self.match_property_required, property, value, false) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_sysname()` / `..._add_nomatch_sysname()`.
    pub fn add_match_sysname(&mut self, sysname: &[u8], m: bool) -> bool {
        let set = if m { &mut self.match_sysname } else { &mut self.nomatch_sysname };
        if !set.insert(sysname.to_vec()) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_tag()`.
    pub fn add_match_tag(&mut self, tag: &[u8]) -> bool {
        if !self.match_tag.insert(tag.to_vec()) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `device_enumerator_add_match_parent_incremental()`.
    pub fn add_match_parent_incremental(&mut self, parent: &Device) -> bool {
        let path = parent.get_syspath();
        if !self.match_parent.get_or_insert_with(BTreeSet::new).insert(path.bytes().to_vec()) {
            return false;
        }
        self.scan_uptodate = false;
        true
    }

    /// `sd_device_enumerator_add_match_parent()`.
    pub fn add_match_parent(&mut self, parent: &Device) -> bool {
        if let Some(s) = &mut self.match_parent {
            s.clear();
        }
        self.add_match_parent_incremental(parent)
    }

    /// `sd_device_enumerator_allow_uninitialized()`.
    pub fn allow_uninitialized(&mut self) {
        self.match_initialized = MatchInitialized::All;
        self.scan_uptodate = false;
    }

    /// `sd_device_enumerator_add_all_parents()`.
    pub fn add_all_parents(&mut self) {
        self.parent_match_flags = 0;
        self.scan_uptodate = false;
    }

    /// `device_enumerator_add_match_is_initialized()`.
    pub fn add_match_is_initialized(&mut self, t: MatchInitialized) {
        self.match_initialized = t;
        self.scan_uptodate = false;
    }

    /// `enumerator_sort_devices()`.
    fn sort_devices(&mut self) -> Result<(), i32> {
        if self.sorted {
            return Ok(());
        }
        let mut devices: Vec<Dev> = Vec::new();
        let mut n_sorted = 0;
        for ps in self.prioritized_subsystems.clone() {
            loop {
                let m = devices.len();
                let mut found = None;
                for (syspath, d) in &self.devices_by_syspath {
                    if d.in_subsystem(&[&ps])? {
                        found = Some((syspath.clone(), d.clone()));
                        break;
                    }
                }
                if let Some((syspath, d)) = found {
                    devices.push(d);
                    let mut p = syspath;
                    loop {
                        let q = match path_extract_directory(&p) {
                            Err(e) if e == -libc::EADDRNOTAVAIL => break,
                            r => r?,
                        };
                        if let Some(d) = self.devices_by_syspath.get(&q) {
                            devices.push(d.clone());
                        }
                        p = q;
                    }
                }
                for d in &devices[m..] {
                    self.devices_by_syspath.remove(d.get_syspath().bytes());
                }
                if m == devices.len() {
                    break;
                }
            }
            devices[n_sorted..].sort_by(device_compare);
            n_sorted = devices.len();
        }
        devices.extend(self.devices_by_syspath.values().cloned());
        // Move the devices back, or devices added by
        // udev_enumerate_add_syspath() may not be listed.
        for d in &devices[..n_sorted] {
            self.devices_by_syspath.insert(d.get_syspath().bytes().to_vec(), d.clone());
        }
        devices[n_sorted..].sort_by(device_compare);
        self.devices = devices;
        self.sorted = true;
        Ok(())
    }

    /// `device_enumerator_add_device()`: Ok(true) if newly added.
    pub fn add_device(&mut self, device: &Dev) -> bool {
        let syspath = device.get_syspath().bytes().to_vec();
        if self.devices_by_syspath.contains_key(&syspath) {
            return false;
        }
        self.devices_by_syspath.insert(syspath, device.clone());
        self.sorted = false;
        true
    }

    /// `match_property()`.
    fn match_property(properties: &MatchStrv, device: &Device, match_all: bool) -> bool {
        if properties.is_empty() {
            return true;
        }
        let props = device.properties();
        for (property_pattern, value_patterns) in properties {
            let mut m = false;
            for (property, value) in &props {
                if fnmatch(property_pattern, property.bytes(), 0) != 0 {
                    continue;
                }
                m = strv_fnmatch(value_patterns, value.bytes());
                if m {
                    if !match_all {
                        return true;
                    }
                    break;
                }
            }
            if !m && match_all {
                return false;
            }
        }
        match_all
    }

    /// `match_tag()`.
    fn match_tag(&self, device: &Device) -> bool {
        self.match_tag.iter().all(|t| device.has_tag(t))
    }

    /// `match_sysname()`.
    fn match_sysname(&self, sysname: &[u8]) -> bool {
        set_fnmatch(&self.match_sysname, &self.nomatch_sysname, sysname)
    }

    /// `match_initialized()`.
    fn match_initialized(&self, device: &Device) -> Result<bool, i32> {
        if self.match_initialized == MatchInitialized::All {
            return Ok(true);
        }
        let r = match device.get_is_initialized() {
            Err(e) if e == -libc::ENOENT => return Ok(false),
            r => r?,
        };
        if self.match_initialized == MatchInitialized::Compat {
            if r {
                return Ok(true);
            }
            if device.get_devnum().is_ok() {
                return Ok(false);
            }
            if device.get_ifindex().is_ok() {
                return Ok(false);
            }
            return Ok(true);
        }
        Ok((self.match_initialized == MatchInitialized::No) == !r)
    }

    /// `match_subsystem()`.
    fn match_subsystem(&self, subsystem: Option<&[u8]>) -> bool {
        match subsystem {
            None => false,
            Some(s) => set_fnmatch(&self.match_subsystem, &self.nomatch_subsystem, s),
        }
    }

    /// `test_matches()`.
    fn test_matches(&self, device: &Device, flags: u32) -> Result<bool, i32> {
        if flags & MATCH_SYSNAME != 0 {
            let sysname = device.get_sysname()?;
            if !self.match_sysname(sysname.bytes()) {
                return Ok(false);
            }
        }
        if flags & MATCH_SUBSYSTEM != 0 {
            let subsystem = match device.get_subsystem() {
                Err(e) if e == -libc::ENOENT => return Ok(false),
                r => r?,
            };
            if !self.match_subsystem(Some(subsystem.bytes())) {
                return Ok(false);
            }
        }
        if flags & MATCH_PARENT != 0 && !device_match_parent(device, self.match_parent.as_ref(), None) {
            return Ok(false);
        }
        if flags & MATCH_TAG != 0 && !self.match_tag(device) {
            return Ok(false);
        }
        if flags & MATCH_BASIC != 0 {
            if !self.match_initialized(device)? {
                return Ok(false);
            }
            if !Enumerator::match_property(&self.match_property, device, false) {
                return Ok(false);
            }
            if !Enumerator::match_property(&self.match_property_required, device, true) {
                return Ok(false);
            }
            if !device_match_sysattr(device, &self.match_sysattr, &self.nomatch_sysattr) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `enumerator_add_parent_devices()`.
    fn add_parent_devices_flags(&mut self, device: &Dev, flags: u32) -> Result<(), i32> {
        let mut device = device.clone();
        loop {
            device = match device.get_parent() {
                Err(e) if e == -libc::ENOENT => return Ok(()),
                r => r?,
            };
            if !self.test_matches(&device, flags)? {
                continue;
            }
            if !self.add_device(&device) {
                return Ok(());
            }
        }
    }

    /// `device_enumerator_add_parent_devices()`.
    pub fn add_parent_devices(&mut self, device: &Dev) -> Result<(), i32> {
        self.add_parent_devices_flags(device, MATCH_ALL & !MATCH_PARENT)
    }

    /// `enumerator_scan_dir_and_add_devices()`.
    fn scan_dir_and_add_devices(&mut self, basedir: &[u8], subdir1: Option<&[u8]>, subdir2: Option<&[u8]>) -> i32 {
        let mut path = [b"/sys/", basedir, b"/"].concat();
        if let Some(s) = subdir1 {
            path.extend_from_slice(s);
            path.push(b'/');
        }
        if let Some(s) = subdir2 {
            path.extend_from_slice(s);
            path.push(b'/');
        }
        let mut dir = match crate::sys_net::opendir(&path) {
            Err(e) if e == -libc::ENOENT => return 0,
            Err(e) => {
                return log_debug_errno!(
                    e,
                    "sd-device-enumerator: Failed to open directory '",
                    path,
                    "': ",
                    strerror(e)
                );
            }
            Ok(d) => d,
        };
        let mut r = 0;
        loop {
            let (name, ty) = match dir.next_entry() {
                Err(e) => return e,
                Ok(None) => break,
                Ok(Some(x)) => x,
            };
            if !relevant_sysfs_subdir(&name, ty) {
                continue;
            }
            if !self.match_sysname(&name) {
                continue;
            }
            let syspath = [&path[..], &name[..]].concat();
            let device = match Device::new_from_syspath(&syspath) {
                Err(k) => {
                    if !errno_is_neg_device_absent(k) {
                        r = k;
                    }
                    continue;
                }
                Ok(d) => d,
            };
            match self.test_matches(&device, MATCH_ALL & !MATCH_SYSNAME) {
                Err(k) => {
                    r = k;
                    continue;
                }
                Ok(false) => continue,
                Ok(true) => {}
            }
            self.add_device(&device);
            // Also the matching parents, e.g. root buses like
            // /sys/devices/pci0000:00/, which no class or bus links to.
            if let Err(k) = self.add_parent_devices_flags(&device, self.parent_match_flags) {
                r = k;
            }
        }
        r
    }

    /// `enumerator_scan_dir()`.
    fn scan_dir(&mut self, basedir: &[u8], subdir: Option<&[u8]>, subsystem: Option<&[u8]>) -> i32 {
        let path = [b"/sys/", basedir].concat();
        let mut dir = match crate::sys_net::opendir(&path) {
            Err(e) if e == -libc::ENOENT => return 0,
            Err(e) => {
                return log_debug_errno!(
                    e,
                    "sd-device-enumerator: Failed to open directory '",
                    path,
                    "': ",
                    strerror(e)
                );
            }
            Ok(d) => d,
        };
        let mut r = 0;
        loop {
            let (name, ty) = match dir.next_entry() {
                Err(e) => return e,
                Ok(None) => break,
                Ok(Some(x)) => x,
            };
            if !relevant_sysfs_subdir(&name, ty) {
                continue;
            }
            if !self.match_subsystem(Some(subsystem.unwrap_or(&name))) {
                continue;
            }
            let k = self.scan_dir_and_add_devices(basedir, Some(&name), subdir);
            if k < 0 {
                r = k;
            }
        }
        r
    }

    /// `enumerator_scan_devices_tag()`.
    fn scan_devices_tag(&mut self, tag: &[u8]) -> i32 {
        let path = [b"/run/udev/tags/", tag].concat();
        let mut dir = match crate::sys_net::opendir(&path) {
            Err(e) if e == -libc::ENOENT => return 0,
            Err(e) => {
                return log_debug_errno!(
                    e,
                    "sd-device-enumerator: Failed to open directory '",
                    path,
                    "': ",
                    strerror(e)
                );
            }
            Ok(d) => d,
        };
        let mut r = 0;
        loop {
            let (name, _) = match dir.next_entry() {
                Err(e) => return e,
                Ok(None) => break,
                Ok(Some(x)) => x,
            };
            if name.first() == Some(&b'.') {
                continue;
            }
            let device = match Device::new_from_device_id(&name) {
                Err(k) => {
                    if !errno_is_neg_device_absent(k) {
                        r = k;
                    }
                    continue;
                }
                Ok(d) => d,
            };
            match self.test_matches(&device, MATCH_ALL & !MATCH_TAG) {
                Err(k) => {
                    r = k;
                    continue;
                }
                Ok(false) => continue,
                Ok(true) => {}
            }
            self.add_device(&device);
        }
        r
    }

    /// `enumerator_scan_devices_tags()`.
    fn scan_devices_tags(&mut self) -> i32 {
        let mut r = 0;
        for tag in self.match_tag.clone() {
            let k = self.scan_devices_tag(&tag);
            if k < 0 {
                r = k;
            }
        }
        r
    }

    /// `parent_add_child()`.
    fn parent_add_child(&mut self, path: &[u8], flags: u32) -> Result<(), i32> {
        let device = match Device::new_from_syspath(path) {
            Err(e) if errno_is_neg_device_absent(e) => return Ok(()),
            r => r?,
        };
        if !self.test_matches(&device, flags)? {
            return Ok(());
        }
        self.add_device(&device);
        Ok(())
    }

    /// `parent_crawl_children()`.
    fn parent_crawl_children(&mut self, path: &[u8], stack: &mut BTreeSet<Vec<u8>>) -> i32 {
        let mut dir = match crate::sys_net::opendir(path) {
            Err(e) if e == -libc::ENOENT => return 0,
            Err(e) => {
                return log_debug_errno!(
                    e,
                    "sd-device-enumerator: Failed to open directory '",
                    path,
                    "': ",
                    strerror(e)
                );
            }
            Ok(d) => d,
        };
        let mut r = 0;
        loop {
            let (name, ty) = match dir.next_entry() {
                Err(e) => return e,
                Ok(None) => break,
                Ok(Some(x)) => x,
            };
            if name.first() == Some(&b'.') || ty != libc::DT_DIR {
                continue;
            }
            let child = crate::path::path_join(&[path, &name]);
            if self.match_sysname(&name)
                && let Err(k) = self.parent_add_child(&child, MATCH_ALL & !(MATCH_SYSNAME | MATCH_PARENT))
            {
                r = k;
            }
            stack.insert(child);
        }
        r
    }

    /// `enumerator_scan_devices_children()`.
    fn scan_devices_children(&mut self) -> i32 {
        let mut stack = BTreeSet::new();
        let mut r = 0;
        for path in self.match_parent.clone().unwrap_or_default() {
            if let Err(k) = self.parent_add_child(&path, MATCH_ALL & !MATCH_PARENT) {
                r = k;
            }
            let k = self.parent_crawl_children(&path, &mut stack);
            if k < 0 {
                r = k;
            }
        }
        while let Some(p) = stack.pop_first() {
            let k = self.parent_crawl_children(&p, &mut stack);
            if k < 0 {
                r = k;
            }
        }
        r
    }

    /// `enumerator_scan_devices_all()`.
    fn scan_devices_all(&mut self) -> i32 {
        let mut r = 0;
        let k = self.scan_dir(b"bus", Some(b"devices"), None);
        if k < 0 {
            r = log_debug_errno!(k, "sd-device-enumerator: Failed to scan /sys/bus: ", strerror(k));
        }
        let k = self.scan_dir(b"class", None, None);
        if k < 0 {
            r = log_debug_errno!(k, "sd-device-enumerator: Failed to scan /sys/class: ", strerror(k));
        }
        r
    }

    /// `device_enumerator_scan_devices()`.
    pub fn scan_devices(&mut self) -> i32 {
        if self.scan_uptodate && self.ty == Some(EnumerationType::Devices) {
            return 0;
        }
        self.unref_devices();
        let mut r = 0;
        let k = if !self.match_tag.is_empty() {
            self.scan_devices_tags()
        } else if self.match_parent.is_some() {
            self.scan_devices_children()
        } else {
            self.scan_devices_all()
        };
        if k < 0 {
            r = k;
        }
        self.scan_uptodate = true;
        self.ty = Some(EnumerationType::Devices);
        r
    }

    /// `sd_device_enumerator_get_device_first()`.
    pub fn get_device_first(&mut self) -> Option<Dev> {
        if self.scan_devices() < 0 {
            return None;
        }
        if self.sort_devices().is_err() {
            return None;
        }
        self.current_device_index = 0;
        self.devices.first().cloned()
    }

    /// `sd_device_enumerator_get_device_next()`.
    pub fn get_device_next(&mut self) -> Option<Dev> {
        if !self.scan_uptodate
            || !self.sorted
            || self.ty != Some(EnumerationType::Devices)
            || self.current_device_index + 1 >= self.devices.len()
        {
            return None;
        }
        self.current_device_index += 1;
        Some(self.devices[self.current_device_index].clone())
    }

    fn scan_subsystems_parts(&mut self, r: &mut i32) {
        if self.match_subsystem(Some(b"module")) {
            let k = self.scan_dir_and_add_devices(b"module", None, None);
            if k < 0 {
                *r = log_debug_errno!(k, "sd-device-enumerator: Failed to scan modules: ", strerror(k));
            }
        }
        if self.match_subsystem(Some(b"subsystem")) {
            let k = self.scan_dir_and_add_devices(b"bus", None, None);
            if k < 0 {
                *r = log_debug_errno!(k, "sd-device-enumerator: Failed to scan subsystems: ", strerror(k));
            }
        }
        if self.match_subsystem(Some(b"drivers")) {
            let k = self.scan_dir(b"bus", Some(b"drivers"), Some(b"drivers"));
            if k < 0 {
                *r = log_debug_errno!(k, "sd-device-enumerator: Failed to scan drivers: ", strerror(k));
            }
        }
    }

    /// `device_enumerator_scan_subsystems()`.
    pub fn scan_subsystems(&mut self) -> i32 {
        if self.scan_uptodate && self.ty == Some(EnumerationType::Subsystems) {
            return 0;
        }
        self.unref_devices();
        let mut r = 0;
        self.scan_subsystems_parts(&mut r);
        self.scan_uptodate = true;
        self.ty = Some(EnumerationType::Subsystems);
        r
    }

    /// `sd_device_enumerator_get_subsystem_first()`.
    pub fn get_subsystem_first(&mut self) -> Option<Dev> {
        if self.scan_subsystems() < 0 {
            return None;
        }
        if self.sort_devices().is_err() {
            return None;
        }
        self.current_device_index = 0;
        self.devices.first().cloned()
    }

    /// `sd_device_enumerator_get_subsystem_next()`.
    pub fn get_subsystem_next(&mut self) -> Option<Dev> {
        if !self.scan_uptodate
            || !self.sorted
            || self.ty != Some(EnumerationType::Subsystems)
            || self.current_device_index + 1 >= self.devices.len()
        {
            return None;
        }
        self.current_device_index += 1;
        Some(self.devices[self.current_device_index].clone())
    }

    /// `device_enumerator_scan_devices_and_subsystems()`.
    pub fn scan_devices_and_subsystems(&mut self) -> i32 {
        if self.scan_uptodate && self.ty == Some(EnumerationType::All) {
            return 0;
        }
        self.unref_devices();
        let mut r;
        if !self.match_tag.is_empty() {
            r = self.scan_devices_tags();
        } else if self.match_parent.is_some() {
            r = self.scan_devices_children();
        } else {
            r = self.scan_devices_all();
            self.scan_subsystems_parts(&mut r);
        }
        self.scan_uptodate = true;
        self.ty = Some(EnumerationType::All);
        r
    }

    /// `device_enumerator_get_first()`.
    pub fn get_first(&mut self) -> Option<Dev> {
        if !self.scan_uptodate {
            return None;
        }
        if self.sort_devices().is_err() {
            return None;
        }
        self.current_device_index = 0;
        self.devices.first().cloned()
    }

    /// `device_enumerator_get_next()`.
    pub fn get_next(&mut self) -> Option<Dev> {
        if !self.scan_uptodate || !self.sorted || self.current_device_index + 1 >= self.devices.len() {
            return None;
        }
        self.current_device_index += 1;
        Some(self.devices[self.current_device_index].clone())
    }

    /// `device_enumerator_get_devices()`.
    pub fn get_devices(&mut self) -> Option<Vec<Dev>> {
        if !self.scan_uptodate {
            return None;
        }
        if self.sort_devices().is_err() {
            return None;
        }
        Some(self.devices.clone())
    }
}
