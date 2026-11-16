// SPDX-License-Identifier: LGPL-2.1-or-later
//! `libudev-list.c`: the lists libudev hands out.  A "unique" list keeps
//! one entry per name and is walked in name order (`strcmp()`); the other
//! kind keeps entries in the order added.  Entries are heap objects whose
//! addresses the caller holds, so they never move.

use std::collections::BTreeMap;
use std::ffi::c_char;
use std::ptr;

/// `struct udev_list_entry`.
#[derive(Debug)]
pub struct UdevListEntry {
    list: *const UdevList,
    /// NUL-terminated.
    name: Vec<u8>,
    /// NUL-terminated.
    value: Option<Vec<u8>>,
    next: *mut UdevListEntry,
}

/// `struct udev_list`.
#[derive(Debug)]
pub struct UdevList {
    unique: bool,
    uptodate: bool,
    /// For unique lists, by name.
    unique_entries: BTreeMap<Vec<u8>, Box<UdevListEntry>>,
    /// For the others, in order.  Boxed: callers hold the entries'
    /// addresses, which must survive the Vec growing.
    #[allow(clippy::vec_box)]
    entries: Vec<Box<UdevListEntry>>,
    head: *mut UdevListEntry,
}

fn with_nul(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b.len() + 1);
    v.extend_from_slice(b);
    v.push(0);
    v
}

impl UdevList {
    /// `udev_list_new()`.
    pub fn new(unique: bool) -> UdevList {
        UdevList {
            unique,
            uptodate: false,
            unique_entries: BTreeMap::new(),
            entries: Vec::new(),
            head: ptr::null_mut(),
        }
    }

    /// `udev_list_entry_add()`.  The list must not move afterwards (it's
    /// always inside a boxed object).
    pub fn add(&mut self, name: &[u8], value: Option<&[u8]>) -> *mut UdevListEntry {
        let mut e = Box::new(UdevListEntry {
            list: self as *const UdevList,
            name: with_nul(name),
            value: value.map(with_nul),
            next: ptr::null_mut(),
        });
        let p: *mut UdevListEntry = &mut *e;
        if self.unique {
            self.unique_entries.insert(name.to_vec(), e);
            self.uptodate = false;
        } else {
            if let Some(last) = self.entries.last_mut() {
                last.next = p;
            } else {
                self.head = p;
            }
            self.entries.push(e);
        }
        p
    }

    /// `udev_list_cleanup()`.
    pub fn cleanup(&mut self) {
        if self.unique {
            self.uptodate = false;
            self.unique_entries.clear();
        } else {
            self.entries.clear();
            self.head = ptr::null_mut();
        }
    }

    /// `udev_list_get_entry()`.
    pub fn get_entry(&mut self) -> *mut UdevListEntry {
        if self.unique && !self.uptodate {
            self.head = ptr::null_mut();
            let mut next: *mut UdevListEntry = ptr::null_mut();
            for e in self.unique_entries.values_mut().rev() {
                e.next = next;
                next = &mut **e;
            }
            self.head = next;
            self.uptodate = true;
        }
        self.head
    }
}

/// `udev_list_entry_get_next()`.
///
/// # Safety
/// `e` is NULL or an entry of a live list.
pub unsafe fn entry_get_next(e: *mut UdevListEntry) -> *mut UdevListEntry {
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller passes a live entry, whose list outlives it.
    unsafe {
        let list = &*(*e).list;
        if list.unique && !list.uptodate {
            return ptr::null_mut();
        }
        (*e).next
    }
}

/// `udev_list_entry_get_by_name()`.
///
/// # Safety
/// `e` is NULL or an entry of a live list.
pub unsafe fn entry_get_by_name(e: *mut UdevListEntry, name: &[u8]) -> *mut UdevListEntry {
    if e.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: as in entry_get_next(); the list is only read.
    unsafe {
        let list = (*e).list as *mut UdevList;
        if !(*list).unique || !(*list).uptodate {
            return ptr::null_mut();
        }
        match (*list).unique_entries.get_mut(name) {
            Some(b) => &mut **b,
            None => ptr::null_mut(),
        }
    }
}

/// `udev_list_entry_get_name()`.
///
/// # Safety
/// `e` is NULL or a live entry.
pub unsafe fn entry_get_name(e: *mut UdevListEntry) -> *const c_char {
    if e.is_null() {
        return ptr::null();
    }
    // SAFETY: a live entry.
    unsafe { (*e).name.as_ptr() as *const c_char }
}

/// `udev_list_entry_get_value()`.
///
/// # Safety
/// `e` is NULL or a live entry.
pub unsafe fn entry_get_value(e: *mut UdevListEntry) -> *const c_char {
    if e.is_null() {
        return ptr::null();
    }
    // SAFETY: a live entry.
    unsafe {
        match &(*e).value {
            Some(v) => v.as_ptr() as *const c_char,
            None => ptr::null(),
        }
    }
}
