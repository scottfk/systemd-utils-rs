// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-usb_id.c`: USB device properties and identification.

use shared::errno::{strerror, synthetic};
use shared::sd_device::Device;
use shared::{log_device_debug, log_device_debug_errno, log_device_warning_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::def::UDEV_NAME_SIZE;
use super::super::event::Event;
use super::super::util::{encode_devnode_name, udev_replace_chars, udev_replace_whitespace};

fn set_usb_iftype(c: u32) -> &'static str {
    match c {
        0x01 => "audio",
        0x03 => "hid",
        0x06 => "media",
        0x07 => "printer",
        0x08 => "storage",
        0x09 => "hub",
        0x0e => "video",
        _ => "generic",
    }
}

fn set_usb_mass_storage_ifsubtype(t: u32) -> &'static str {
    match t as u8 {
        0x01 => "rbc",
        0x02 => "atapi",
        0x03 => "tape",
        0x04 => "floppy",
        0x06 => "scsi",
        _ => "generic",
    }
}

fn set_scsi_type(t: u32) -> &'static str {
    match t {
        0x00 | 0x0e => "disk",
        0x01 => "tape",
        0x04 | 0x07 | 0x0f => "optical",
        0x05 => "cd",
        _ => "generic",
    }
}

/// `dev_if_packed_info()`: ":ccsspp:...:" of all interfaces.
fn dev_if_packed_info(dev: &Device, len: usize) -> Vec<u8> {
    let syspath = dev.get_syspath().bytes().to_vec();
    let filename = shared::bcat!(&syspath[..], "/descriptors");
    let fd = match shared::sys::open(&filename, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
        Ok(fd) => shared::sys::OwnedFd::new(fd),
        Err(r) => {
            log_device_debug_errno!(dev, r, "Failed to open \"", &filename[..], "\": ", strerror(r));
            return Vec::new();
        }
    };
    let mut buf = vec![0u8; 18 + 65535];
    let size = shared::sys::read(fd.raw(), &mut buf).unwrap_or(0);
    if size < 18 {
        log_device_warning_errno!(dev, synthetic(libc::EIO), "Short read from \"", &filename[..], "\"");
        return Vec::new();
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0;
    while pos + 9 < size && out.len() + 7 < len - 2 {
        let blength = buf[pos] as usize;
        if blength < 3 {
            break;
        }
        if blength > size - pos {
            log_device_debug_errno!(dev, synthetic(libc::EIO), "Corrupt data read from \"", &filename[..], "\"");
            return Vec::new();
        }
        let d = &buf[pos..];
        pos += blength;
        if d[1] != 0x04 {
            continue;
        }
        let if_str = format!(":{:02x}{:02x}{:02x}", d[5], d[6], d[7]).into_bytes();
        if out.windows(7).any(|w| w == &if_str[..]) {
            continue;
        }
        out.extend_from_slice(&if_str);
    }
    if !out.is_empty() {
        out.push(b':');
    }
    out
}

/// `udev_replace_whitespace()` into a buffer of `size` bytes, then
/// `udev_replace_chars(str, NULL)`.
fn clean(s: &[u8], size: usize) -> Vec<u8> {
    let mut v = udev_replace_whitespace(s, size - 1);
    udev_replace_chars(&mut v, None);
    v
}

/// `sscanf(s, "%d:%d:%d:%d", ...)`: the target and lun.
fn scan_hctl(s: &[u8]) -> Option<(i64, i64)> {
    let mut nums = Vec::new();
    let mut rest = s;
    for i in 0..4 {
        if i > 0 {
            rest = rest.strip_prefix(b":")?;
        }
        let t = shared::string::skip_leading_chars(rest, Some(shared::string::WHITESPACE));
        let (v, consumed, e) = shared::sys::strtol(t, 10);
        if consumed == 0 || e != 0 {
            return None;
        }
        nums.push(v as i32 as i64);
        rest = &t[consumed..];
    }
    Some((nums[2], nums[3]))
}

/// `strpcpyl()` into a 256-byte buffer.
fn cap256(mut v: Vec<u8>) -> Vec<u8> {
    v.truncate(255);
    v
}

/// `builtin_usb_id()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    dev.get_sysname()?;
    let mut ifnum: Option<Vec<u8>> = None;
    let mut driver: Option<Vec<u8>> = None;
    let mut type_str: Option<&str> = None;
    let mut vendor_str = Vec::new();
    let mut vendor_str_enc = Vec::new();
    let mut model_str = Vec::new();
    let mut model_str_enc = Vec::new();
    let mut revision_str = Vec::new();
    let mut instance_str = Vec::new();
    let packed_if_str;
    let dev_usb;
    if dev.is_devtype(Some(b"usb_device")) != Ok(false) {
        packed_if_str = dev_if_packed_info(&dev, UDEV_NAME_SIZE);
        dev_usb = dev.clone();
    } else {
        let iface = dev
            .get_parent_with_subsystem_devtype(b"usb", Some(b"usb_interface"))
            .map_err(|r| log_device_debug_errno!(dev, r, "Failed to access usb_interface: ", strerror(r)))?;
        ifnum = iface.get_sysattr_safe_string(b"bInterfaceNumber").ok().map(|v| v.bytes().to_vec());
        driver = iface.get_sysattr_safe_string(b"driver").ok().map(|v| v.bytes().to_vec());
        let if_class_num = iface.get_sysattr_unsigned_full(b"bInterfaceClass", 16).map_err(|r| {
            log_device_debug_errno!(iface, r, "Failed to read bInterfaceClass attribute: ", strerror(r))
        })?;
        let mut protocol = 0;
        if if_class_num == 8 {
            if let Ok(p) = iface.get_sysattr_unsigned_full(b"bInterfaceSubClass", 16) {
                protocol = p;
                type_str = Some(set_usb_mass_storage_ifsubtype(p));
            }
        } else {
            type_str = Some(set_usb_iftype(if_class_num));
        }
        log_device_debug!(iface, "if_class:", if_class_num.to_string(), " protocol:", protocol.to_string());
        dev_usb = iface
            .get_parent_with_subsystem_devtype(b"usb", Some(b"usb_device"))
            .map_err(|r| log_device_debug_errno!(iface, r, "Failed to find parent 'usb' device"))?;
        packed_if_str = dev_if_packed_info(&dev_usb, UDEV_NAME_SIZE);
        if protocol == 6 || protocol == 2 {
            // mass storage: SCSI or ATAPI; any failure falls back to the USB data.
            let _ = (|| -> Option<()> {
                let dev_scsi = match dev.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_device")) {
                    Ok(d) => d,
                    Err(r) => {
                        log_device_debug_errno!(dev, r, "Unable to find parent SCSI device");
                        return None;
                    }
                };
                let scsi_sysname = dev_scsi.get_sysname().ok()?.bytes().to_vec();
                let Some((target, lun)) = scan_hctl(&scsi_sysname) else {
                    log_device_debug!(dev_scsi, "Invalid SCSI device");
                    return None;
                };
                let vendor = match dev_scsi.get_sysattr_value(b"vendor") {
                    Ok(v) => v.bytes().to_vec(),
                    Err(r) => {
                        log_device_debug_errno!(dev_scsi, r, "Failed to get SCSI vendor attribute: ", strerror(r));
                        return None;
                    }
                };
                vendor_str_enc = encode_devnode_name(&vendor, 256);
                vendor_str = clean(&vendor, 64);
                let model = match dev_scsi.get_sysattr_value(b"model") {
                    Ok(v) => v.bytes().to_vec(),
                    Err(r) => {
                        log_device_debug_errno!(dev_scsi, r, "Failed to get SCSI model attribute: ", strerror(r));
                        return None;
                    }
                };
                model_str_enc = encode_devnode_name(&model, 256);
                model_str = clean(&model, 64);
                let scsi_type = match dev_scsi.get_sysattr_value(b"type").and_then(|v| {
                    shared::parse::safe_atou(v.bytes()).map_err(|e| {
                        log_device_debug_errno!(dev_scsi, e, "Failed to parse 'type' attribute: ", strerror(e))
                    })
                }) {
                    Ok(t) => t,
                    Err(r) => {
                        log_device_debug_errno!(dev_scsi, r, "Failed to get SCSI type attribute: ", strerror(r));
                        return None;
                    }
                };
                type_str = Some(set_scsi_type(scsi_type));
                let rev = match dev_scsi.get_sysattr_value(b"rev") {
                    Ok(v) => v.bytes().to_vec(),
                    Err(r) => {
                        log_device_debug_errno!(dev_scsi, r, "Failed to get SCSI revision attribute: ", strerror(r));
                        return None;
                    }
                };
                revision_str = clean(&rev, 64);
                instance_str = format!("{target}:{lun}").into_bytes();
                Some(())
            })();
        }
    }
    // fallback:
    let vendor_id = dev_usb
        .get_sysattr_value(b"idVendor")
        .map_err(|r| log_device_debug_errno!(dev_usb, r, "Failed to get idVendor attribute: ", strerror(r)))?
        .bytes()
        .to_vec();
    let product_id = dev_usb
        .get_sysattr_value(b"idProduct")
        .map_err(|r| log_device_debug_errno!(dev_usb, r, "Failed to get idProduct attribute: ", strerror(r)))?
        .bytes()
        .to_vec();
    if vendor_str.is_empty() {
        let v = dev_usb.get_sysattr_value(b"manufacturer").map(|v| v.bytes().to_vec()).unwrap_or(vendor_id.clone());
        vendor_str_enc = encode_devnode_name(&v, 256);
        vendor_str = clean(&v, 64);
    }
    if model_str.is_empty() {
        let m = dev_usb.get_sysattr_value(b"product").map(|v| v.bytes().to_vec()).unwrap_or(product_id.clone());
        model_str_enc = encode_devnode_name(&m, 256);
        model_str = clean(&m, 64);
    }
    if revision_str.is_empty()
        && let Ok(rev) = dev_usb.get_sysattr_value(b"bcdDevice")
    {
        revision_str = clean(rev.bytes(), 64);
    }
    let mut serial_str = Vec::new();
    if let Ok(s) = dev_usb.get_sysattr_value(b"serial")
        && !s.bytes().iter().any(|&c| !(0x20..=0x7f).contains(&c) || c == b',')
    {
        serial_str = clean(s.bytes(), UDEV_NAME_SIZE);
    }
    let mut serial = cap256(shared::bcat!(&vendor_str[..], "_", &model_str[..]));
    if !serial_str.is_empty() {
        serial = cap256(shared::bcat!(&serial[..], "_", &serial_str[..]));
    }
    if !instance_str.is_empty() {
        serial = cap256(shared::bcat!(&serial[..], "-", &instance_str[..]));
    }
    let add = |k: &str, v: &[u8]| {
        let _ = udev_builtin_add_property(event, k.as_bytes(), Some(v));
    };
    if dev.get_property_value(b"ID_BUS").is_ok() {
        log_device_debug!(dev, "ID_BUS property is already set, setting only properties prefixed with \"ID_USB_\".");
    } else {
        add("ID_BUS", b"usb");
        add("ID_MODEL", &model_str);
        add("ID_MODEL_ENC", &model_str_enc);
        add("ID_MODEL_ID", &product_id);
        add("ID_SERIAL", &serial);
        if !serial_str.is_empty() {
            add("ID_SERIAL_SHORT", &serial_str);
        }
        add("ID_VENDOR", &vendor_str);
        add("ID_VENDOR_ENC", &vendor_str_enc);
        add("ID_VENDOR_ID", &vendor_id);
        add("ID_REVISION", &revision_str);
        if let Some(t) = type_str {
            add("ID_TYPE", t.as_bytes());
        }
        if !instance_str.is_empty() {
            add("ID_INSTANCE", &instance_str);
        }
    }
    add("ID_USB_MODEL", &model_str);
    add("ID_USB_MODEL_ENC", &model_str_enc);
    add("ID_USB_MODEL_ID", &product_id);
    add("ID_USB_SERIAL", &serial);
    if !serial_str.is_empty() {
        add("ID_USB_SERIAL_SHORT", &serial_str);
    }
    add("ID_USB_VENDOR", &vendor_str);
    add("ID_USB_VENDOR_ENC", &vendor_str_enc);
    add("ID_USB_VENDOR_ID", &vendor_id);
    add("ID_USB_REVISION", &revision_str);
    if let Some(t) = type_str {
        add("ID_USB_TYPE", t.as_bytes());
    }
    if !instance_str.is_empty() {
        add("ID_USB_INSTANCE", &instance_str);
    }
    if !packed_if_str.is_empty() {
        add("ID_USB_INTERFACES", &packed_if_str);
    }
    if let Some(i) = &ifnum {
        add("ID_USB_INTERFACE_NUM", i);
    }
    if let Some(d) = &driver {
        add("ID_USB_DRIVER", d);
    }
    Ok(())
}
