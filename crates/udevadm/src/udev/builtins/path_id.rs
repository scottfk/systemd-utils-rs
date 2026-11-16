// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-path_id.c`: compose the persistent device path.

use shared::log_device_debug_errno;
use shared::sd_device::{Dev, Device};
use shared::string::WHITESPACE;

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

/// `path_prepend(&path, ...)`.
fn prepend(path: &mut Option<Vec<u8>>, pre: Vec<u8>) {
    *path = Some(match path.take() {
        Some(p) => shared::bcat!(&pre[..], "-", &p[..]),
        None => pre,
    });
}

/// sscanf's `%u`/`%d`: whitespace, an optional sign, digits; the value
/// (wrapped to 32 bits) and the rest.
fn scan_num(s: &[u8]) -> Option<(i64, &[u8])> {
    let s = shared::string::skip_leading_chars(s, Some(WHITESPACE));
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in &digits[..n] {
        v = v.wrapping_mul(10).wrapping_add((c - b'0') as u64);
    }
    let v = if neg { (v as i64).wrapping_neg() } else { v as i64 };
    Some((v as u32 as i64, &digits[n..]))
}

/// `sscanf(name, "%u:%u:%u:%u", ...)` (or `%d`).
fn scan4(s: &[u8], signed: bool) -> Option<[i64; 4]> {
    let mut out = [0i64; 4];
    let mut rest = s;
    for (i, o) in out.iter_mut().enumerate() {
        if i > 0 {
            rest = rest.strip_prefix(b":")?;
        }
        let (v, r) = scan_num(rest)?;
        *o = if signed { v as u32 as i32 as i64 } else { v };
        rest = r;
    }
    Some(out)
}

/// `format_lun_number(dev, &lun)`: "(null)" if the number can't be read,
/// as C's `%s` of the NULL string prints.
fn format_lun_number(dev: &Device) -> Vec<u8> {
    match dev.get_sysnum_unsigned() {
        Err(_) => b"(null)".to_vec(),
        Ok(lun) if lun < 256 => format!("lun-{lun}").into_bytes(),
        Ok(lun) => format!("lun-0x{:04x}{:04x}00000000", lun & 0xffff, (lun >> 16) & 0xffff).into_bytes(),
    }
}

/// `skip_subsystem()`: drops the parents in `subsys`, except the last one.
fn skip_subsystem(dev: Dev, subsys: &[u8]) -> Dev {
    let mut dev = dev;
    let mut parent = dev.clone();
    loop {
        if parent.in_subsystem(&[subsys]).unwrap_or(false) {
            dev = parent.clone();
            match dev.get_parent() {
                Ok(p) => parent = p,
                Err(_) => break,
            }
        } else {
            break;
        }
    }
    dev
}

fn safe_string(d: &Device, attr: &[u8]) -> Option<Vec<u8>> {
    d.get_sysattr_safe_string(attr).ok().map(|v| v.bytes().to_vec())
}

fn sysname(d: &Device) -> Option<Vec<u8>> {
    d.get_sysname().ok().map(|s| s.bytes().to_vec())
}

fn from_subsystem_sysname(subsystem: &[u8], name: &[u8]) -> Option<Dev> {
    Device::new_from_subsystem_sysname(subsystem, name).ok()
}

/// `handle_scsi_fibre_channel()`.
fn handle_scsi_fibre_channel(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let target = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_target")).ok()?;
    let fc = from_subsystem_sysname(b"fc_transport", &sysname(&target)?)?;
    let port = safe_string(&fc, b"port_name")?;
    let lun = format_lun_number(parent);
    prepend(path, shared::bcat!("fc-", &port[..], "-", &lun[..]));
    Some(parent.clone())
}

/// `handle_scsi_sas_wide_port()`.
fn handle_scsi_sas_wide_port(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let target = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_target")).ok()?;
    let target_parent = target.get_parent().ok()?;
    let sas = from_subsystem_sysname(b"sas_device", &sysname(&target_parent)?)?;
    let addr = safe_string(&sas, b"sas_address")?;
    let lun = format_lun_number(parent);
    prepend(path, shared::bcat!("sas-", &addr[..], "-", &lun[..]));
    Some(parent.clone())
}

/// `handle_scsi_sas()`.
fn handle_scsi_sas(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let target = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_target")).ok()?;
    let target_parent = target.get_parent().ok()?;
    let target_sas = from_subsystem_sysname(b"sas_device", &sysname(&target_parent)?)?;
    let port = target_parent.get_parent().ok()?;
    let port_sas = from_subsystem_sysname(b"sas_port", &sysname(&port)?)?;
    let num_phys =
        port_sas.get_sysattr_value(b"num_phys").ok().and_then(|v| match shared::parse::safe_atou(v.bytes()) {
            Ok(n) => Some(n),
            Err(e) => {
                log_device_debug_errno!(
                    port_sas,
                    e,
                    "Failed to parse 'num_phys' attribute: ",
                    shared::errno::strerror(e)
                );
                None
            }
        })?;
    if num_phys > 1 {
        return handle_scsi_sas_wide_port(parent, path);
    }
    let phy_id = safe_string(&target_sas, b"phy_identifier")?;
    let expander = port.get_parent().ok()?;
    let mut sas_address = None;
    if let Some(e) = from_subsystem_sysname(b"sas_device", &sysname(&expander)?) {
        sas_address = Some(safe_string(&e, b"sas_address")?);
    }
    let lun = format_lun_number(parent);
    match sas_address {
        Some(a) => prepend(path, shared::bcat!("sas-exp", &a[..], "-phy", &phy_id[..], "-", &lun[..])),
        None => prepend(path, shared::bcat!("sas-phy", &phy_id[..], "-", &lun[..])),
    }
    Some(parent.clone())
}

/// `handle_scsi_iscsi()`.
fn handle_scsi_iscsi(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let mut transport = parent.clone();
    let name = loop {
        transport = transport.get_parent().ok()?;
        let n = sysname(&transport)?;
        if n.starts_with(b"session") {
            break n;
        }
    };
    let session = from_subsystem_sysname(b"iscsi_session", &name)?;
    let target = safe_string(&session, b"targetname")?;
    let sysnum = transport.get_sysnum().ok()?.bytes().to_vec();
    let conn = from_subsystem_sysname(b"iscsi_connection", &shared::bcat!("connection", &sysnum[..], ":0"))?;
    let addr = safe_string(&conn, b"persistent_address")?;
    let port = safe_string(&conn, b"persistent_port")?;
    let lun = format_lun_number(parent);
    prepend(path, shared::bcat!("ip-", &addr[..], ":", &port[..], "-iscsi-", &target[..], "-", &lun[..]));
    Some(parent.clone())
}

/// `handle_scsi_ata()`.
fn handle_scsi_ata(parent: &Dev, path: &mut Option<Vec<u8>>, compat_path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let name = sysname(parent)?;
    let [_host, bus, target, _lun] = scan4(&name, false)?;
    let host = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_host")).ok()?;
    let host_parent = host.get_parent().ok()?;
    let ata = from_subsystem_sysname(b"ata_port", &sysname(&host_parent)?)?;
    let port_no = safe_string(&ata, b"port_no")?;
    if bus != 0 {
        prepend(path, shared::bcat!("ata-", &port_no[..], ".", bus.to_string(), ".0"));
    } else {
        prepend(path, shared::bcat!("ata-", &port_no[..], ".", target.to_string()));
    }
    prepend(compat_path, shared::bcat!("ata-", &port_no[..]));
    Some(parent.clone())
}

/// `handle_scsi_default()`.
fn handle_scsi_default(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let hostdev = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_host")).ok()?;
    let name = sysname(parent)?;
    let [host, bus, target, lun] = scan4(&name, true)?;
    let base = hostdev.get_syspath().bytes().to_vec();
    let pos = base.iter().rposition(|&c| c == b'/')?;
    let mut dir = shared::sys_net::opendir(&base[..pos]).ok()?;
    let mut basenum: i64 = -1;
    while let Ok(Some((n, t))) = shared::conf_files::foreach_dirent_all(&mut dir) {
        if n.first() == Some(&b'.') || !(t == libc::DT_DIR || t == libc::DT_LNK) {
            continue;
        }
        let Some(num) = n.strip_prefix(b"host") else { continue };
        let Ok(i) = shared::parse::safe_atou_full(num, 10) else { continue };
        if basenum == -1 || (i as i32 as i64) < basenum {
            basenum = i as i64;
        }
    }
    if basenum == -1 {
        return Some(hostdev);
    }
    let host = (host - basenum) as i32;
    prepend(path, format!("scsi-{host}:{bus}:{target}:{lun}").into_bytes());
    Some(hostdev)
}

/// `handle_scsi_hyperv()`.
fn handle_scsi_hyperv(parent: &Dev, path: &mut Option<Vec<u8>>, guid_str_len: usize) -> Option<Dev> {
    let hostdev = parent.get_parent_with_subsystem_devtype(b"scsi", Some(b"scsi_host")).ok()?;
    let vmbus = hostdev.get_parent().ok()?;
    let g = safe_string(&vmbus, b"device_id")?;
    if g.len() < guid_str_len || g[0] != b'{' || g[guid_str_len - 1] != b'}' {
        return None;
    }
    let guid: Vec<u8> = g[1..guid_str_len - 1].iter().copied().filter(|&c| c != b'-').collect();
    let lun = format_lun_number(parent);
    prepend(path, shared::bcat!("vmbus-", &guid[..], "-", &lun[..]));
    Some(parent.clone())
}

/// `handle_scsi()`.
fn handle_scsi(
    parent: &Dev,
    path: &mut Option<Vec<u8>>,
    compat_path: &mut Option<Vec<u8>>,
    supported_parent: &mut bool,
) -> Option<Dev> {
    if parent.is_devtype(Some(b"scsi_device")) != Ok(true) {
        return Some(parent.clone());
    }
    if let Some(id) = safe_string(parent, b"ieee1394_id") {
        prepend(path, shared::bcat!("ieee1394-0x", &id[..]));
        *supported_parent = true;
        return Some(skip_subsystem(parent.clone(), b"scsi"));
    }
    let name = parent.get_syspath().bytes().to_vec();
    let has = |s: &[u8]| name.windows(s.len()).any(|w| w == s);
    if has(b"/rport-") {
        *supported_parent = true;
        return handle_scsi_fibre_channel(parent, path);
    }
    if has(b"/end_device-") {
        *supported_parent = true;
        return handle_scsi_sas(parent, path);
    }
    if has(b"/session") {
        *supported_parent = true;
        return handle_scsi_iscsi(parent, path);
    }
    if has(b"/ata") {
        return handle_scsi_ata(parent, path, compat_path);
    }
    if has(b"/vmbus_") {
        return handle_scsi_hyperv(parent, path, 37);
    } else if has(b"/VMBUS") {
        return handle_scsi_hyperv(parent, path, 38);
    }
    handle_scsi_default(parent, path)
}

/// `handle_cciss()`: `sscanf(str, "c%ud%u%*s")`.
fn handle_cciss(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let s = sysname(parent)?;
    let (_, rest) = scan_num(s.strip_prefix(b"c")?)?;
    let (disk, _) = scan_num(rest.strip_prefix(b"d")?)?;
    prepend(path, format!("cciss-disk{disk}").into_bytes());
    Some(skip_subsystem(parent.clone(), b"cciss"))
}

/// `handle_scsi_tape()`.
fn handle_scsi_tape(dev: &Device, path: &mut Option<Vec<u8>>) {
    if path.is_some() {
        return;
    }
    let Some(name) = sysname(dev) else { return };
    // strchr("lma", c) also matches the terminating NUL.
    let in_lma = |c: Option<&u8>| matches!(c, Some(b'l' | b'm' | b'a') | None);
    if name.starts_with(b"nst") && in_lma(name.get(3)) {
        prepend(path, shared::bcat!("nst", name.get(3).map(|c| vec![*c]).unwrap_or_default()));
    } else if name.starts_with(b"st") && in_lma(name.get(2)) {
        prepend(path, shared::bcat!("st", name.get(2).map(|c| vec![*c]).unwrap_or_default()));
    }
}

/// `get_usb_revision()`.
fn get_usb_revision(dev: &Device) -> Result<i32, i32> {
    let protocol = dev.get_sysattr_value(b"bDeviceProtocol").and_then(|v| {
        shared::parse::safe_atou_full(v.bytes(), 16).and_then(|p| u8::try_from(p).map_err(|_| -libc::ERANGE)).map_err(
            |e| {
                log_device_debug_errno!(
                    dev,
                    e,
                    "Failed to parse 'bDeviceProtocol' attribute: ",
                    shared::errno::strerror(e)
                )
            },
        )
    })?;
    match protocol {
        0 => Ok(if dev.get_sysattr_streq(b"speed", b"480")? { 2 } else { 1 }),
        1 | 2 => Ok(2),
        3 => Ok(3),
        _ => Err(-libc::EPROTONOSUPPORT),
    }
}

/// `handle_usb()`.
fn handle_usb(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    if parent.is_devtype(Some(b"usb_interface")) != Ok(true) && parent.is_devtype(Some(b"usb_device")) != Ok(true) {
        return Some(parent.clone());
    }
    let Some(s) = sysname(parent) else { return Some(parent.clone()) };
    let Some(i) = s.iter().position(|&c| c == b'-') else { return Some(parent.clone()) };
    let port = &s[i + 1..];
    let parent = skip_subsystem(parent.clone(), b"usb");
    match get_usb_revision(&parent) {
        Err(r) => {
            log_device_debug_errno!(
                parent,
                r,
                "Failed to get the USB revision number, ignoring: ",
                shared::errno::strerror(r)
            );
            prepend(path, shared::bcat!("usb-0:", port));
        }
        Ok(r) => prepend(path, shared::bcat!(format!("usbv{r}-0:"), port)),
    }
    Some(parent)
}

/// `handle_bcma()`: `sscanf(sysname, "bcma%*u:%u")`.
fn handle_bcma(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    let s = sysname(parent)?;
    let (_, rest) = scan_num(s.strip_prefix(b"bcma")?)?;
    let (core, _) = scan_num(rest.strip_prefix(b":")?)?;
    prepend(path, format!("bcma-{core}").into_bytes());
    Some(parent.clone())
}

/// `handle_ap()`.
fn handle_ap(parent: &Dev, path: &mut Option<Vec<u8>>) -> Option<Dev> {
    match (safe_string(parent, b"type"), safe_string(parent, b"ap_functions")) {
        (Some(t), Some(f)) => prepend(path, shared::bcat!("ap-", &t[..], "-", &f[..])),
        _ => {
            if let Some(s) = sysname(parent) {
                prepend(path, shared::bcat!("ap-", &s[..]));
            }
        }
    }
    Some(skip_subsystem(parent.clone(), b"ap"))
}

/// `find_real_nvme_parent()`.
fn find_real_nvme_parent(dev: &Device) -> Result<Dev, i32> {
    let s = dev.get_sysname()?.bytes().to_vec();
    let end = s.strip_prefix(b"nvme").ok_or(-libc::ENXIO)?;
    let n = 4 + end.iter().take_while(|c| c.is_ascii_digit()).count();
    let nvme = Device::new_from_subsystem_sysname(b"nvme", &s[..n])?;
    if shared::path::path_startswith(nvme.get_devpath().bytes(), b"/devices/virtual/").is_some() {
        return Err(-libc::ENXIO);
    }
    Ok(nvme)
}

/// `add_id_with_usb_revision()`.
fn add_id_with_usb_revision(event: &Event, path: &mut Vec<u8>) {
    let Some(i) = path.windows(5).position(|w| w == b"-usbv") else { return };
    let p = i + 5;
    if !path.get(p).is_some_and(u8::is_ascii_digit) || path.get(p + 1) != Some(&b'-') {
        return;
    }
    let _ = udev_builtin_add_property(event, b"ID_PATH_WITH_USB_REVISION", Some(path));
    // Drop the "v<digit>": "-usbv3-" becomes "-usb-".
    path.drain(p - 1..p + 1);
}

/// `add_id_tag()`.
fn add_id_tag(event: &Event, path: &[u8]) {
    let mut tag: Vec<u8> = Vec::new();
    for &c in path {
        if tag.len() >= 511 {
            break;
        }
        if c.is_ascii_alphanumeric() || c == b'-' {
            tag.push(c);
            continue;
        }
        if tag.is_empty() || tag.last() == Some(&b'_') {
            continue;
        }
        tag.push(b'_');
    }
    while tag.last() == Some(&b'_') {
        tag.pop();
    }
    let _ = udev_builtin_add_property(event, b"ID_PATH_TAG", Some(&tag));
}

/// `handle_pnp()`.
fn handle_pnp(parent: &Dev, path: &mut Option<Vec<u8>>) -> Result<(), i32> {
    let fw = parent.new_child(b"firmware_node")?;
    if !fw.in_subsystem(&[b"acpi"]).unwrap_or(false) {
        return Err(-libc::ENODEV);
    }
    let s = fw.get_sysname()?.bytes().to_vec();
    prepend(path, shared::bcat!("acpi-", &s[..]));
    Ok(())
}

/// `builtin_path_id()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    let mut path: Option<Vec<u8>> = None;
    let mut compat_path: Option<Vec<u8>> = None;
    let (mut supported_transport, mut supported_parent) = (false, false);
    let mut parent = Some(dev.clone());
    while let Some(p) = parent.take() {
        let in_sub = |s: &[u8]| p.in_subsystem(&[s]).unwrap_or(false);
        let mut next = Some(p.clone());
        // `prepend` to both paths, the compat one only once it exists.
        let both = |path: &mut Option<Vec<u8>>, compat: &mut Option<Vec<u8>>, s: Vec<u8>| {
            prepend(path, s.clone());
            if compat.is_some() {
                prepend(compat, s);
            }
        };
        if let Some(name) = sysname(&p) {
            if in_sub(b"scsi_tape") {
                handle_scsi_tape(&p, &mut path);
            } else if in_sub(b"scsi") {
                next = handle_scsi(&p, &mut path, &mut compat_path, &mut supported_parent);
                supported_transport = true;
            } else if in_sub(b"cciss") {
                next = handle_cciss(&p, &mut path);
                supported_transport = true;
            } else if in_sub(b"usb") {
                next = handle_usb(&p, &mut path);
                supported_transport = true;
            } else if in_sub(b"bcma") {
                next = handle_bcma(&p, &mut path);
                supported_transport = true;
            } else if in_sub(b"serio") {
                if let Ok(n) = p.get_sysnum() {
                    prepend(&mut path, shared::bcat!("serio-", n.bytes()));
                    next = Some(skip_subsystem(p.clone(), b"serio"));
                }
            } else if in_sub(b"auxiliary") {
                if let Ok(sf) = p.get_sysattr_unsigned_full(b"sfnum", 0) {
                    both(&mut path, &mut compat_path, format!("sf-{sf}").into_bytes());
                }
            } else if in_sub(b"pci") {
                both(&mut path, &mut compat_path, shared::bcat!("pci-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"pci"));
                supported_parent = true;
            } else if in_sub(b"platform") {
                both(&mut path, &mut compat_path, shared::bcat!("platform-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"platform"));
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"amba") {
                both(&mut path, &mut compat_path, shared::bcat!("amba-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"amba"));
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"acpi") {
                both(&mut path, &mut compat_path, shared::bcat!("acpi-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"acpi"));
                supported_parent = true;
            } else if in_sub(b"pnp") {
                if handle_pnp(&p, &mut path).is_ok() {
                    supported_parent = true;
                }
                next = Some(skip_subsystem(p.clone(), b"pnp"));
            } else if in_sub(b"xen") {
                both(&mut path, &mut compat_path, shared::bcat!("xen-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"xen"));
                supported_parent = true;
            } else if in_sub(b"virtio") {
                next = Some(skip_subsystem(p.clone(), b"virtio"));
                supported_transport = true;
            } else if in_sub(b"scm") {
                both(&mut path, &mut compat_path, shared::bcat!("scm-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"scm"));
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"ccw") {
                both(&mut path, &mut compat_path, shared::bcat!("ccw-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"ccw"));
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"ccwgroup") {
                both(&mut path, &mut compat_path, shared::bcat!("ccwgroup-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"ccwgroup"));
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"ap") {
                next = handle_ap(&p, &mut path);
                supported_transport = true;
                supported_parent = true;
            } else if in_sub(b"iucv") {
                both(&mut path, &mut compat_path, shared::bcat!("iucv-", &name[..]));
                next = Some(skip_subsystem(p.clone(), b"iucv"));
                supported_transport = true;
                supported_parent = true;
            } else if p.in_subsystem(&[b"nvme", b"nvme-subsystem"]).unwrap_or(false) {
                if let Some(nsid) = safe_string(&dev, b"nsid") {
                    both(&mut path, &mut compat_path, shared::bcat!("nvme-", &nsid[..]));
                    let mut q = p.clone();
                    if in_sub(b"nvme-subsystem") {
                        q = find_real_nvme_parent(&dev)?;
                    }
                    next = Some(skip_subsystem(q, b"nvme"));
                    supported_parent = true;
                    supported_transport = true;
                }
            } else if in_sub(b"spi")
                && let Ok(n) = p.get_sysnum()
            {
                prepend(&mut path, shared::bcat!("cs-", n.bytes()));
                next = Some(skip_subsystem(p.clone(), b"spi"));
            }
        }
        let Some(n) = next else { break };
        parent = n.get_parent().ok();
    }
    let Some(mut path) = path else { return Err(-libc::ENOENT) };
    if !supported_parent {
        return Err(-libc::ENOENT);
    }
    if dev.in_subsystem(&[b"block"]).unwrap_or(false) && !supported_transport {
        return Err(-libc::ENOENT);
    }
    add_id_with_usb_revision(event, &mut path);
    let _ = udev_builtin_add_property(event, b"ID_PATH", Some(&path));
    add_id_tag(event, &path);
    if let Some(c) = compat_path {
        let _ = udev_builtin_add_property(event, b"ID_PATH_ATA_COMPAT", Some(&c));
    }
    Ok(())
}
