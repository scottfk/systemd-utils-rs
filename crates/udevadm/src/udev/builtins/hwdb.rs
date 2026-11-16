// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-hwdb.c`.

use std::cell::RefCell;

use shared::errno::{strerror, synthetic};
use shared::hwdb::{HWDB_BIN_PATHS, Hwdb};
use shared::options::{Opt, OptionParser};
use shared::sd_device::{Dev, Device};
use shared::{log_debug, log_device_debug, log_device_debug_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

thread_local! {
    static HWDB: RefCell<Option<Hwdb>> = const { RefCell::new(None) };
}

/// `udev_builtin_hwdb_lookup(event, prefix, modalias, filter)`: the number
/// of properties added.
pub fn lookup(event: &Event, prefix: Option<&[u8]>, modalias: &[u8], filter: Option<&[u8]>) -> Result<usize, i32> {
    let key = match prefix {
        Some(p) => shared::bcat!(p, modalias),
        None => modalias.to_vec(),
    };
    let props = HWDB.with(|h| h.borrow_mut().as_mut().map(|h| h.properties(&key))).ok_or(-libc::ENOENT)?;
    let mut n = 0;
    for (k, v) in props {
        if let Some(f) = filter
            && shared::sys::fnmatch(f, &k, libc::FNM_NOESCAPE) != 0
        {
            continue;
        }
        if udev_builtin_add_property(event, &k, Some(&v)).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

/// `modalias_usb()`.
fn modalias_usb(dev: &Device) -> Option<Vec<u8>> {
    let v = dev.get_sysattr_u16_full(b"idVendor", 16).ok()?;
    let p = dev.get_sysattr_u16_full(b"idProduct", 16).ok()?;
    let n = dev.get_sysattr_safe_string(b"product").ok();
    let mut s = format!("usb:v{v:04X}p{p:04X}:").into_bytes();
    if let Some(n) = n {
        s.extend_from_slice(n.bytes());
    }
    // snprintf() into a LINE_MAX buffer.
    s.truncate(2047);
    Some(s)
}

/// `udev_builtin_hwdb_search()`.
fn search(
    event: &Event,
    srcdev: Option<Dev>,
    subsystem: Option<&[u8]>,
    prefix: Option<&[u8]>,
    filter: Option<&[u8]>,
) -> Result<usize, i32> {
    let dev = event.dev.clone();
    let mut d = srcdev.unwrap_or_else(|| dev.clone());
    let mut r = 0;
    loop {
        let wanted = match subsystem {
            Some(s) => d.in_subsystem(&[s])?,
            None => true,
        };
        if wanted {
            let mut modalias = d.get_property_value(b"MODALIAS").ok().map(|m| m.bytes().to_vec());
            let mut last = false;
            if d.is_subsystem_devtype(Some(b"usb"), Some(b"usb_device"))? {
                if modalias.is_none() {
                    modalias = modalias_usb(&d);
                }
                last = true;
            }
            if let Some(m) = modalias {
                log_device_debug!(dev, "hwdb modalias key: \"", &m[..], "\"");
                r = lookup(event, prefix, &m, filter)?;
                if r > 0 || last {
                    break;
                }
            }
        }
        match d.get_parent() {
            Ok(p) => d = p,
            Err(_) => break,
        }
    }
    Ok(r)
}

const FILTER: i32 = 1;
const DEVICE: i32 = 2;
const SUBSYSTEM: i32 = 3;
const PREFIX: i32 = 4;
const OPTIONS: &[Opt] = &[
    Opt::new(FILTER, b'f', Some("filter"), Some("FILTER"), None),
    Opt::new(DEVICE, b'd', Some("device"), Some("DEVICE"), None),
    Opt::new(SUBSYSTEM, b's', Some("subsystem"), Some("SUBSYSTEM"), None),
    Opt::new(PREFIX, b'p', Some("lookup-prefix"), Some("PREFIX"), None),
];

/// `builtin_hwdb()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if HWDB.with(|h| h.borrow().is_none()) {
        return Err(-libc::EINVAL);
    }
    let (mut filter, mut device, mut subsystem, mut prefix) = (None, None, None, None);
    let mut opts = OptionParser::new(argv.to_vec(), OPTIONS);
    while let Some(c) = opts.next()? {
        let a = opts.arg.clone();
        match c {
            FILTER => filter = a,
            DEVICE => device = a,
            SUBSYSTEM => subsystem = a,
            PREFIX => prefix = a,
            _ => {}
        }
    }
    let done = |r: Result<usize, i32>| -> Result<(), i32> {
        match r {
            Err(r) => Err(log_device_debug_errno!(dev, r, "Failed to look up hwdb: ", strerror(r))),
            Ok(0) => Err(log_device_debug_errno!(dev, synthetic(libc::ENODATA), "No entry found from hwdb.")),
            Ok(_) => Ok(()),
        }
    };
    if let Some(modalias) = opts.args().first().cloned() {
        return done(lookup(event, prefix.as_deref(), &modalias, filter.as_deref()));
    }
    let srcdev = match &device {
        Some(id) => match Device::new_from_device_id(id) {
            Ok(d) => Some(d),
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to create sd_device object '",
                    &id[..],
                    "': ",
                    strerror(r)
                ));
            }
        },
        None => None,
    };
    done(search(event, srcdev, subsystem.as_deref(), prefix.as_deref(), filter.as_deref()))
}

/// `builtin_hwdb_init()`.
pub fn init() {
    if HWDB.with(|h| h.borrow().is_some()) {
        return;
    }
    if let Ok(h) = Hwdb::new() {
        HWDB.with(|x| *x.borrow_mut() = Some(h));
        log_debug!("Loaded hardware database.");
    }
}

/// `builtin_hwdb_exit()`.
pub fn exit() {
    HWDB.with(|h| *h.borrow_mut() = None);
    log_debug!("Unloaded hardware database.");
}

/// `builtin_hwdb_should_reload()`.
pub fn should_reload() -> bool {
    let Some(mtime) = HWDB.with(|h| h.borrow().as_ref().map(|h| h.mtime)) else { return false };
    let reload = match HWDB_BIN_PATHS.iter().find_map(|p| shared::sys::stat(p).ok()) {
        None => true,
        Some(st) => shared::sys::stat_mtime(&st) != mtime,
    };
    if reload {
        log_debug!("hwdb needs reloading.");
    }
    reload
}
