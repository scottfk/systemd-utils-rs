// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-net_id.c`: predictable network interface names from
//! firmware indexes, slots, bus paths and MAC addresses.

use shared::errno::{strerror, synthetic};
use shared::locale::{Glyph, glyph};
use shared::netif_naming_scheme::{self as ns, naming_scheme, naming_scheme_has};
use shared::sd_device::{Dev, Device};
use shared::{log_debug_errno, log_device_debug, log_device_debug_errno, log_device_warning_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

const ALTIFNAMSIZ: usize = 128;
const ONBOARD_14BIT_INDEX_MAX: u32 = (1 << 14) - 1;
const ONBOARD_16BIT_INDEX_MAX: u32 = (1 << 16) - 1;
const ARPHRD_ETHER: u32 = 1;
const ARPHRD_SLIP: u32 = 256;
const ARPHRD_INFINIBAND: u32 = 32;
const ARPHRD_MCTP: u32 = 290;
const NET_ADDR_PERM: u32 = 0;
const PCI_HEADER_TYPE: usize = 0x0e;

fn arrow() -> &'static [u8] {
    glyph(Glyph::ArrowRight)
}

/// `snprintf_ok(str, ALTIFNAMSIZ, ...)`: (whether it fit, what the buffer
/// holds, truncated if not).
fn fit(s: Vec<u8>) -> (bool, Vec<u8>) {
    if s.len() < ALTIFNAMSIZ {
        (true, s)
    } else {
        let mut t = s;
        t.truncate(ALTIFNAMSIZ - 1);
        (false, t)
    }
}

/// Adds the property if the name fits; returns the buffer for logging.
fn add_name(event: &Event, key: &[u8], s: Vec<u8>) -> Vec<u8> {
    let (ok, buf) = fit(s);
    if ok {
        let _ = udev_builtin_add_property(event, key, Some(&buf));
    }
    buf
}

/// `strna()`.
fn na(s: &Option<Vec<u8>>) -> &[u8] {
    s.as_deref().unwrap_or(b"n/a")
}

/// `empty_to_na()`.
fn empty_na(s: &[u8]) -> &[u8] {
    if s.is_empty() { b"n/a" } else { s }
}

fn opt(s: &Option<Vec<u8>>) -> &[u8] {
    s.as_deref().unwrap_or(b"")
}

/// scanf's numeric conversions: whitespace, a sign, then digits of `base`
/// (`%x` also takes a 0x prefix).  The value as strtoul() wraps it, and the
/// rest.
fn scan_num(s: &[u8], base: u32) -> Option<(u64, &[u8])> {
    let s = shared::string::skip_leading_chars(s, Some(shared::string::WHITESPACE));
    let (neg, mut t) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if base == 16 && t.len() > 2 && t[0] == b'0' && (t[1] | 0x20) == b'x' && t[2].is_ascii_hexdigit() {
        t = &t[2..];
    }
    let n = t.iter().take_while(|c| (**c as char).is_digit(base)).count();
    if n == 0 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in &t[..n] {
        v = v.wrapping_mul(base as u64).wrapping_add((c as char).to_digit(base).unwrap_or(0) as u64);
    }
    Some((if neg { v.wrapping_neg() } else { v }, &t[n..]))
}

/// `device_get_parent_skip_virtio()`.
fn parent_skip_virtio(dev: &Device) -> Result<Dev, i32> {
    let mut d = dev.get_parent()?;
    loop {
        if !d.in_subsystem(&[b"virtio"])? {
            return Ok(d);
        }
        d = d.get_parent()?;
    }
}

/// `get_matching_parent()`.
fn get_matching_parent(dev: &Device, subsystems: &[&[u8]], skip_virtio: bool) -> Result<Dev, i32> {
    let parent = if skip_virtio { parent_skip_virtio(dev)? } else { dev.get_parent()? };
    if !parent.in_subsystem(subsystems)? {
        return Err(-libc::ENODEV);
    }
    Ok(parent)
}

/// `get_first_syspath_component()`.
fn get_first_syspath_component(dev: &Device, prefix: &[u8]) -> Result<Vec<u8>, i32> {
    let syspath = dev.get_syspath().bytes().to_vec();
    let mut p = shared::path::path_startswith(&syspath, prefix).ok_or(-libc::EINVAL)?;
    let (n, q) = shared::path::path_find_first_component(&mut p, false)?;
    Ok(q[..n].to_vec())
}

/// `get_virtfn_info()`: the PF's PCI device and the "v<N>" suffix.
fn get_virtfn_info(pcidev: &Dev) -> Result<(Dev, Vec<u8>), i32> {
    let syspath = pcidev.get_syspath().bytes().to_vec();
    let physfn = pcidev.new_child(b"physfn")?;
    let mut child = physfn.get_child_first();
    while let Some((c, name)) = child {
        child = physfn.get_child_next();
        let Some(n) = name.strip_prefix(b"virtfn") else { continue };
        if n.is_empty() || !n.iter().all(u8::is_ascii_digit) {
            continue;
        }
        if c.get_syspath().bytes() == &syspath[..] {
            return Ok((physfn.clone(), shared::bcat!("v", n)));
        }
    }
    Err(-libc::ENOENT)
}

/// `get_subfunc_info()`: the PCI parent and the "S<sfnum>" suffix.
fn get_subfunc_info(aux: &Dev) -> Result<(Dev, Vec<u8>), i32> {
    let sfnum = ns::get_sysattr_unsigned_filtered(aux, b"sfnum")?;
    let parent = aux.get_parent()?;
    if !parent.in_subsystem(&[b"pci"])? {
        return Err(-libc::ENODEV);
    }
    Ok((parent, format!("S{sfnum}").into_bytes()))
}

/// `get_port_specifier()`.
fn get_port_specifier(dev: &Device) -> Result<Option<Vec<u8>>, i32> {
    if let Ok(name) = ns::get_sysattr_safe_string_filtered(dev, b"phys_port_name")
        && !name.is_empty()
    {
        if naming_scheme_has(ns::NAMING_SR_IOV_R) {
            // sscanf(name, "pf%*uvf%d", &vf_id)
            let vf_id = name
                .strip_prefix(b"pf")
                .and_then(|r| scan_num(r, 10))
                .and_then(|(_, r)| r.strip_prefix(b"vf"))
                .and_then(|r| scan_num(r, 10))
                .map(|(v, _)| v as u32 as i32)
                .unwrap_or(-1);
            if vf_id >= 0 {
                return Ok(Some(format!("r{vf_id}").into_bytes()));
            }
        }
        return Ok(Some(shared::bcat!("n", &name[..])));
    }
    match ns::get_sysattr_unsigned_filtered(dev, b"dev_port") {
        Err(r) => Err(log_device_debug_errno!(dev, r, "Failed to get device port index: ", strerror(r))),
        Ok(p) if p > 0 => Ok(Some(format!("d{p}").into_bytes())),
        Ok(_) => Ok(None),
    }
}

fn is_valid_onboard_index(idx: u32) -> bool {
    idx <= if naming_scheme_has(ns::NAMING_16BIT_INDEX) { ONBOARD_16BIT_INDEX_MAX } else { ONBOARD_14BIT_INDEX_MAX }
}

/// `pci_get_onboard_index()`.
fn pci_get_onboard_index(dev: &Device) -> Result<u32, i32> {
    let idx = ns::get_sysattr_unsigned_filtered(dev, b"acpi_index")
        .or_else(|_| ns::get_sysattr_unsigned_filtered(dev, b"index"))
        .map_err(|r| log_device_debug_errno!(dev, r, "Could not obtain onboard index: ", strerror(r)))?;
    if idx == 0 && !naming_scheme_has(ns::NAMING_ZERO_ACPI_INDEX) {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Naming scheme does not allow onboard index==0."
        ));
    }
    if !is_valid_onboard_index(idx) {
        return Err(log_device_debug_errno!(dev, synthetic(libc::EINVAL), format!("Not a valid onboard index: {idx}")));
    }
    Ok(idx)
}

/// `names_pci_onboard()`.
fn names_pci_onboard(event: &Event, pci_dev: &Device, prefix: &str, suffix: Option<&[u8]>) -> Result<(), i32> {
    let dev = event.dev.clone();
    let idx = pci_get_onboard_index(pci_dev)?;
    let port = get_port_specifier(&dev)?;
    let s = add_name(
        event,
        b"ID_NET_NAME_ONBOARD",
        shared::bcat!(prefix, format!("o{idx}"), opt(&port), suffix.unwrap_or(b"")),
    );
    log_device_debug!(
        dev,
        format!("PCI onboard index identifier: index={idx} port="),
        na(&port),
        " ",
        arrow(),
        " ",
        empty_na(&s)
    );
    Ok(())
}

/// `names_pci_onboard_label()`.
fn names_pci_onboard_label(event: &Event, pci_dev: &Device, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let label = ns::get_sysattr_safe_string_filtered(pci_dev, b"label")
        .map_err(|r| log_device_debug_errno!(pci_dev, r, "Failed to get PCI onboard label: ", strerror(r)))?;
    let p = if naming_scheme_has(ns::NAMING_LABEL_NOPREFIX) { "" } else { prefix };
    add_name(event, b"ID_NET_LABEL_ONBOARD", shared::bcat!(p, &label[..]));
    log_device_debug!(dev, "Onboard label from PCI device: ", &label[..]);
    Ok(())
}

/// `is_pci_multifunction()`.
fn is_pci_multifunction(dev: &Device) -> Result<bool, i32> {
    let filename = shared::bcat!(dev.get_syspath().bytes(), "/config");
    let (config, _) = shared::fileio::read_virtual_file(&filename, PCI_HEADER_TYPE + 1)?;
    if config.len() < PCI_HEADER_TYPE + 1 {
        return Err(-libc::EINVAL);
    }
    Ok(config[PCI_HEADER_TYPE] & 0x80 != 0)
}

/// `is_pci_ari_enabled()`.
fn is_pci_ari_enabled(dev: &Device) -> bool {
    ns::get_sysattr_bool_filtered(dev, b"ari_enabled") == Ok(true)
}

/// `is_pci_bridge()`.
fn is_pci_bridge(dev: &Device) -> bool {
    let Ok(v) = ns::get_sysattr_safe_string_filtered(dev, b"modalias") else { return false };
    if !v.starts_with(b"pci:") {
        return false;
    }
    let Some(i) = v.iter().rposition(|&c| c == b's') else { return false };
    if v.get(i + 1) != Some(&b'c') {
        return false;
    }
    let b = v.get(i + 2..i + 4) == Some(b"04");
    if b {
        log_device_debug!(dev, "Device is a PCI bridge.");
    }
    b
}

/// `parse_hotplug_slot_from_function_id()`: Some(slot) if found.
fn parse_hotplug_slot_from_function_id(dev: &Device, slots_dirfd: i32) -> Result<Option<u32>, i32> {
    if !naming_scheme_has(ns::NAMING_SLOT_FUNCTION_ID) {
        return Ok(None);
    }
    let Ok(attr) = ns::get_sysattr_safe_string_filtered(dev, b"function_id") else { return Ok(None) };
    let function_id = shared::parse::safe_atou64(&attr)
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to parse function_id, ignoring: '", &attr[..], "'"))?;
    if function_id == 0 || function_id > u32::MAX as u64 {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            format!("Invalid function id (0x{function_id:x}), ignoring.")
        ));
    }
    let filename = format!("{function_id:08x}");
    if let Err(r) = shared::sys::faccessat(slots_dirfd, filename.as_bytes(), libc::F_OK, 0) {
        return Err(log_device_debug_errno!(
            dev,
            r,
            "Cannot access '",
            &filename[..],
            "' under pci slots, ignoring: ",
            strerror(r)
        ));
    }
    Ok(Some(function_id as u32))
}

/// `pci_get_hotplug_slot_from_address()`.
fn pci_get_hotplug_slot_from_address(
    dev: &Device,
    pci: &Device,
    dir: &mut shared::sys::Dir,
) -> Result<Option<u32>, i32> {
    let sysname = dev
        .get_sysname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get sysname: ", strerror(r)))?
        .bytes()
        .to_vec();
    dir.rewind();
    while let Ok(Some((name, ty))) = dir.next_entry() {
        if name == b"." || name == b".." || ty != libc::DT_DIR {
            continue;
        }
        let Ok(slot) = shared::parse::safe_atou(&name) else { continue };
        if slot == 0 {
            continue;
        }
        let path = shared::path::path_join(&[b"slots", &name, b"address"]);
        let Ok(address) = ns::get_sysattr_safe_string_filtered(pci, &path) else { continue };
        if !sysname.starts_with(&address) {
            continue;
        }
        return Ok(Some(slot));
    }
    Ok(None)
}

/// `pci_get_hotplug_slot()`: (slot, whether the domain is to be dropped).
fn pci_get_hotplug_slot(dev: &Dev) -> Result<(u32, bool), i32> {
    let pci = Device::new_from_subsystem_sysname(b"subsystem", b"pci")
        .map_err(|r| log_debug_errno!(r, "Failed to create sd_device object for pci subsystem: ", strerror(r)))?;
    let mut dir = pci
        .opendir(Some(b"slots"))
        .map_err(|r| log_device_debug_errno!(dev, r, "Cannot open 'slots' subdirectory: ", strerror(r)))?;
    let mut slot_dev = Some(dev.clone());
    while let Some(sd) = slot_dev {
        if let Some(slot) = parse_hotplug_slot_from_function_id(&sd, dir.fd())? {
            return Ok((slot, true));
        }
        if let Some(slot) = pci_get_hotplug_slot_from_address(&sd, &pci, &mut dir)? {
            if naming_scheme_has(ns::NAMING_BRIDGE_NO_SLOT) && is_pci_bridge(&sd) {
                if naming_scheme_has(ns::NAMING_BRIDGE_MULTIFUNCTION_SLOT) && is_pci_multifunction(dev) != Ok(true) {
                    return Err(log_device_debug_errno!(
                        dev,
                        synthetic(libc::ESTALE),
                        "Not using slot information because the PCI device associated with the hotplug slot is a bridge and the PCI device has a single function."
                    ));
                }
                if !naming_scheme_has(ns::NAMING_BRIDGE_MULTIFUNCTION_SLOT) {
                    return Err(log_device_debug_errno!(
                        dev,
                        synthetic(libc::ESTALE),
                        "Not using slot information because the PCI device is a bridge."
                    ));
                }
            }
            return Ok((slot, false));
        }
        slot_dev = sd.get_parent_with_subsystem_devtype(b"pci", None).ok();
    }
    Err(-libc::ENOENT)
}

/// `get_device_firmware_node_sun()`.
fn get_device_firmware_node_sun(dev: &Device) -> Result<u32, i32> {
    let attr = ns::get_sysattr_safe_string_filtered(dev, b"firmware_node/sun")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to read firmware_node/sun, ignoring: ", strerror(r)))?;
    let sun = shared::parse::safe_atou(&attr).map_err(|r| {
        log_device_debug_errno!(dev, r, "Failed to parse firmware_node/sun '", &attr[..], "', ignoring: ", strerror(r))
    })?;
    if sun == 0 {
        return Err(log_device_debug_errno!(dev, synthetic(libc::EINVAL), "firmware_node/sun == 0, ignoring."));
    }
    Ok(sun)
}

/// `pci_get_slot_from_firmware_node_sun()`.
fn pci_get_slot_from_firmware_node_sun(dev: &Device) -> Result<u32, i32> {
    if !naming_scheme_has(ns::NAMING_FIRMWARE_NODE_SUN) {
        return Err(-libc::EOPNOTSUPP);
    }
    if let Ok(s) = get_device_firmware_node_sun(dev) {
        return Ok(s);
    }
    let slot_dev = dev
        .get_parent_with_subsystem_devtype(b"pci", None)
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to find parent PCI device, ignoring: ", strerror(r)))?;
    if is_pci_bridge(&slot_dev) && is_pci_multifunction(dev) != Ok(true) {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::ESTALE),
            "Not using slot information because the parent PCI slot is a bridge and the PCI device is not multifunction."
        ));
    }
    get_device_firmware_node_sun(&slot_dev).map_err(|_| -libc::ENOENT)
}

/// `get_pci_slot_specifiers()`: (domain, bus and slot, function).
fn get_pci_slot_specifiers(dev: &Device) -> Result<(Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>), i32> {
    let sysname = dev
        .get_sysname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get sysname: ", strerror(r)))?
        .bytes()
        .to_vec();
    // sscanf(sysname, "%x:%x:%x.%u", &domain, &bus, &slot, &func)
    let parsed = (|| {
        let (domain, r) = scan_num(&sysname, 16)?;
        let (bus, r) = scan_num(r.strip_prefix(b":")?, 16)?;
        let (slot, r) = scan_num(r.strip_prefix(b":")?, 16)?;
        let (func, _) = scan_num(r.strip_prefix(b".")?, 10)?;
        Some((domain as u32, bus as u32, slot as u32, func as u32))
    })();
    let Some((domain, bus, slot, mut func)) = parsed else {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Failed to parse slot information from PCI device sysname."
        ));
    };
    if naming_scheme_has(ns::NAMING_NPAR_ARI) && is_pci_ari_enabled(dev) {
        func = func.wrapping_add(slot.wrapping_mul(8));
    }
    let include_domain = match dev.get_property_bool(b"ID_NET_NAME_INCLUDE_DOMAIN") {
        Ok(b) => b,
        Err(r) => {
            if r != -libc::ENOENT {
                log_device_warning_errno!(
                    dev,
                    r,
                    "Failed to read property \"ID_NET_NAME_INCLUDE_DOMAIN\", ignoring: ",
                    strerror(r)
                );
            }
            domain > 0
        }
    };
    let domain_spec = include_domain.then(|| format!("P{domain}").into_bytes());
    let bus_and_slot = format!("p{bus}s{slot}").into_bytes();
    let func_spec = (func > 0 || is_pci_multifunction(dev) == Ok(true)).then(|| format!("f{func}").into_bytes());
    Ok((domain_spec, bus_and_slot, func_spec))
}

/// `names_pci_slot()`.
fn names_pci_slot(event: &Event, pci_dev: &Dev, prefix: &str, suffix: Option<&[u8]>) -> Result<(), i32> {
    let dev = event.dev.clone();
    let (mut domain, bus_and_slot, func) = get_pci_slot_specifiers(pci_dev)?;
    let port = get_port_specifier(&dev)?;
    let sfx = suffix.unwrap_or(b"");
    let s = add_name(
        event,
        b"ID_NET_NAME_PATH",
        shared::bcat!(prefix, opt(&domain), &bus_and_slot[..], opt(&func), opt(&port), sfx),
    );
    log_device_debug!(
        dev,
        "PCI path identifier: domain=",
        na(&domain),
        " bus_and_slot=",
        &bus_and_slot[..],
        " func=",
        na(&func),
        " port=",
        na(&port),
        " ",
        arrow(),
        " ",
        empty_na(&s)
    );
    let slot = match pci_get_slot_from_firmware_node_sun(pci_dev) {
        Ok(s) => s,
        Err(_) => {
            let (slot, drop_domain) = pci_get_hotplug_slot(pci_dev)?;
            if drop_domain {
                domain = None;
            }
            slot
        }
    };
    let s = add_name(
        event,
        b"ID_NET_NAME_SLOT",
        shared::bcat!(prefix, opt(&domain), format!("s{slot}"), opt(&func), opt(&port), sfx),
    );
    log_device_debug!(
        dev,
        "PCI slot identifier: domain=",
        na(&domain),
        format!(" slot={slot}"),
        " func=",
        na(&func),
        " port=",
        na(&port),
        " ",
        arrow(),
        " ",
        empty_na(&s)
    );
    Ok(())
}

/// `str + strlen(prefix)` of a (possibly truncated) name buffer.
fn after_prefix<'a>(s: &'a [u8], prefix: &str) -> &'a [u8] {
    s.get(prefix.len()..).unwrap_or(b"")
}

/// `names_vio()`.
fn names_vio(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    if get_matching_parent(&dev, &[b"vio"], false).is_err() {
        return Ok(());
    }
    log_device_debug!(dev, "Parent device is in the vio subsystem.");
    let s = get_first_syspath_component(&dev, b"/sys/devices/vio/")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get VIO bus ID and slot ID: ", strerror(r)))?;
    if s.len() != 8 {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "VIO bus ID and slot ID have invalid length: '",
            &s[..],
            "'"
        ));
    }
    if !s.iter().all(u8::is_ascii_hexdigit) {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "VIO bus ID and slot ID contain invalid characters: '",
            &s[..],
            "'"
        ));
    }
    let slotid = shared::parse::safe_atou_full(&s[4..], 16)
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to parse VIO slot from '", &s[..], "': ", strerror(r)))?;
    let n = add_name(event, b"ID_NET_NAME_SLOT", shared::bcat!(prefix, format!("v{slotid}")));
    log_device_debug!(dev, format!("Vio slot identifier: slotid={slotid} "), arrow(), " ", after_prefix(&n, prefix));
    Ok(())
}

/// `names_platform()`.
fn names_platform(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    if get_matching_parent(&dev, &[b"platform"], false).is_err() {
        return Ok(());
    }
    log_device_debug!(dev, "Parent device is in the platform subsystem.");
    let p = get_first_syspath_component(&dev, b"/sys/devices/platform/")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get platform ID: ", strerror(r)))?;
    let (mut vendor, model_str, instance_str, digits_ok) = if p.len() == 10 && p[7] == b':' {
        (p[..3].to_vec(), &p[3..7], &p[8..10], false)
    } else if p.len() == 11 && p[8] == b':' {
        (p[..4].to_vec(), &p[4..8], &p[9..11], true)
    } else {
        return Err(-libc::EOPNOTSUPP);
    };
    if !vendor.iter().all(|c| c.is_ascii_uppercase() || (digits_ok && c.is_ascii_digit())) {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Platform vendor contains invalid characters: '",
            &vendor[..],
            "'"
        ));
    }
    vendor.make_ascii_lowercase();
    let model = shared::parse::safe_atou_full(model_str, 16).map_err(|r| {
        log_device_debug_errno!(dev, r, "Failed to parse model number \"", model_str, "\": ", strerror(r))
    })?;
    let instance = shared::parse::safe_atou_full(instance_str, 16).map_err(|r| {
        log_device_debug_errno!(dev, r, "Failed to parse instance id \"", instance_str, "\": ", strerror(r))
    })?;
    let n =
        add_name(event, b"ID_NET_NAME_PATH", shared::bcat!(prefix, "a", &vendor[..], format!("{model:x}i{instance}")));
    log_device_debug!(
        dev,
        "Platform identifier: vendor=",
        &vendor[..],
        format!(" model={model:x} instance={instance} "),
        arrow(),
        " ",
        after_prefix(&n, prefix)
    );
    Ok(())
}

/// `names_devicetree_alias_prefix()`: whether an alias was found.
fn names_devicetree_alias_prefix(event: &Event, prefix: &str, alias_prefix: &str) -> Result<bool, i32> {
    let dev = event.dev.clone();
    let alias_prefix_0 = format!("{alias_prefix}0");
    let mut ofnode: Option<Dev> = None;
    if naming_scheme_has(ns::NAMING_DEVICETREE_PORT_ALIASES) {
        match dev.new_child(b"of_node") {
            Ok(d) => ofnode = Some(d),
            Err(r) => {
                log_device_debug_errno!(dev, r, "Failed to get device of_node, ignoring: ", strerror(r));
            }
        }
    }
    let ofnode = match ofnode {
        Some(d) => d,
        None => {
            let parent = dev
                .get_parent()
                .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get parent device: ", strerror(r)))?;
            parent
                .new_child(b"of_node")
                .map_err(|r| log_device_debug_errno!(parent, r, "Failed to get device of_node: ", strerror(r)))?
        }
    };
    let ofnode_syspath = ofnode.get_syspath().bytes().to_vec();
    let dt = Device::new_from_path(b"/proc/device-tree").map_err(|r| {
        log_debug_errno!(r, "Failed to create sd-device object from '/proc/device-tree': ", strerror(r))
    })?;
    let dt_syspath = dt.get_syspath().bytes().to_vec();
    let Some(rel) = shared::path::path_startswith(&ofnode_syspath, &dt_syspath) else {
        return Err(log_device_debug_errno!(
            ofnode,
            synthetic(libc::EINVAL),
            "The device '",
            &ofnode_syspath[..],
            "' is not a child device of '",
            &dt_syspath[..],
            "'."
        ));
    };
    // Get back the leading slash, to match the aliases.
    let ofnode_path = &ofnode_syspath[ofnode_syspath.len() - rel.len() - 1..];
    let aliases = dt
        .new_child(b"aliases")
        .map_err(|r| log_device_debug_errno!(dt, r, "Failed to get 'aliases' child device: ", strerror(r)))?;
    let mut attr = aliases.get_sysattr_first();
    while let Some(a) = attr {
        attr = aliases.get_sysattr_next();
        let alias = a.bytes().to_vec();
        let Some(alias_index) = alias.strip_prefix(alias_prefix.as_bytes()) else { continue };
        let Ok(alias_path) = ns::get_sysattr_safe_string_filtered(&aliases, &alias) else { continue };
        if !shared::path::path_equal(ofnode_path, &alias_path) {
            continue;
        }
        let (i, conflict) = if alias_index.is_empty() {
            (0, alias_prefix_0.as_bytes())
        } else {
            let i = shared::parse::safe_atou(alias_index).map_err(|r| {
                log_device_debug_errno!(dev, r, "Could not get index of alias '", &alias[..], "': ", strerror(r))
            })?;
            (i, alias_prefix.as_bytes())
        };
        if i == 0 && ns::get_sysattr_safe_string_filtered(&aliases, conflict).is_ok() {
            return Err(log_device_debug_errno!(
                dev,
                synthetic(libc::EEXIST),
                "DeviceTree alias conflict: '",
                alias_prefix,
                "' and '",
                &alias_prefix_0[..],
                "' both exist."
            ));
        }
        let n = add_name(event, b"ID_NET_NAME_ONBOARD", shared::bcat!(prefix, format!("d{i}")));
        log_device_debug!(
            dev,
            format!("DeviceTree identifier: alias_index={i} "),
            arrow(),
            " \"",
            after_prefix(&n, prefix),
            "\""
        );
        return Ok(true);
    }
    Ok(false)
}

/// `names_devicetree()`.
fn names_devicetree(event: &Event, prefix: &str) -> Result<(), i32> {
    if !naming_scheme_has(ns::NAMING_DEVICETREE_ALIASES) {
        return Ok(());
    }
    let found = if prefix == "en" {
        names_devicetree_alias_prefix(event, prefix, "ethernet")?
    } else if naming_scheme_has(ns::NAMING_DEVICETREE_ALIASES_WLAN) && prefix == "wl" {
        names_devicetree_alias_prefix(event, prefix, "wifi")?
            || names_devicetree_alias_prefix(event, prefix, "ethernet")?
    } else {
        return Err(-libc::EOPNOTSUPP);
    };
    if found { Ok(()) } else { Err(-libc::ENOENT) }
}

/// `names_pci()`.
fn names_pci(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let mut sub: Option<(Dev, Vec<u8>)> = None;
    if naming_scheme_has(ns::NAMING_SUBFUNC)
        && let Ok(aux) = get_matching_parent(&dev, &[b"auxiliary"], false)
    {
        sub = get_subfunc_info(&aux).ok();
    }
    let mut parent = match &sub {
        Some((p, _)) => p.clone(),
        None => match get_matching_parent(&dev, &[b"pci"], true) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        },
    };
    let mut is_child_function = sub.is_some();
    let mut virtfn_suffix = None;
    if naming_scheme_has(ns::NAMING_SR_IOV_V)
        && let Ok((pf, s)) = get_virtfn_info(&parent)
    {
        parent = pf;
        virtfn_suffix = Some(s);
        is_child_function = true;
    }
    if !is_child_function {
        let _ = names_pci_onboard_label(event, &parent, prefix);
    }
    let subfunc_suffix = sub.map(|(_, s)| s);
    let suffix = match (&virtfn_suffix, &subfunc_suffix) {
        (Some(v), Some(s)) => Some(shared::bcat!(&v[..], &s[..])),
        (Some(v), None) => Some(v.clone()),
        (None, s) => s.clone(),
    };
    let _ = names_pci_onboard(event, &parent, prefix, suffix.as_deref());
    let _ = names_pci_slot(event, &parent, prefix, suffix.as_deref());
    Ok(())
}

/// `get_usb_specifier()`.
fn get_usb_specifier(dev: &Device) -> Result<Vec<u8>, i32> {
    let sysname = dev
        .get_sysname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get sysname: ", strerror(r)))?
        .bytes()
        .to_vec();
    let bad = |c: &str| {
        log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            "sysname \"",
            &sysname[..],
            "\" does not have '",
            c,
            "' in the expected place."
        )
    };
    let i = sysname.iter().position(|&c| c == b'-').ok_or_else(|| bad("-"))?;
    let rest = &sysname[i + 1..];
    let t = rest.iter().position(|&c| c == b':').ok_or_else(|| bad(":"))?;
    let mut ports = rest[..t].to_vec();
    let after = &rest[t + 1..];
    let t = after.iter().position(|&c| c == b'.').ok_or_else(|| bad("."))?;
    let config = Some(after[..t].to_vec()).filter(|c| c != b"1");
    let interf = Some(after[t + 1..].to_vec()).filter(|c| c != b"0");
    for c in ports.iter_mut() {
        if *c == b'.' {
            *c = b'u';
        }
    }
    let buf = shared::bcat!(
        "u",
        &ports[..],
        if config.is_some() { "c" } else { "" },
        opt(&config),
        if interf.is_some() { "i" } else { "" },
        opt(&interf)
    );
    log_device_debug!(
        dev,
        "USB name identifier: ports=",
        &ports[..],
        " config=",
        na(&config),
        " interface=",
        na(&interf),
        " ",
        arrow(),
        " ",
        &buf[..]
    );
    Ok(buf)
}

/// `names_usb()`.
fn names_usb(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let usbdev = dev
        .get_parent_with_subsystem_devtype(b"usb", Some(b"usb_interface"))
        .map_err(|r| log_device_debug_errno!(dev, r, "Could not find USB parent device: ", strerror(r)))?;
    let suffix = get_usb_specifier(&usbdev)?;
    match usbdev.get_parent_with_subsystem_devtype(b"pci", None) {
        Ok(pcidev) => return names_pci_slot(event, &pcidev, prefix, Some(&suffix)),
        Err(r) => {
            if r != -libc::ENOENT || !naming_scheme_has(ns::NAMING_USB_HOST) {
                return Err(log_device_debug_errno!(usbdev, r, "Failed to get parent PCI bus: ", strerror(r)));
            }
        }
    }
    add_name(event, b"ID_NET_NAME_PATH", shared::bcat!(prefix, &suffix[..]));
    Ok(())
}

/// `get_bcma_specifier()`.
fn get_bcma_specifier(dev: &Device) -> Result<Option<Vec<u8>>, i32> {
    let sysname = dev
        .get_sysname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get sysname: ", strerror(r)))?
        .bytes()
        .to_vec();
    // sscanf(sysname, "bcma%*u:%u", &core)
    let core = sysname
        .strip_prefix(b"bcma")
        .and_then(|r| scan_num(r, 10))
        .and_then(|(_, r)| r.strip_prefix(b":"))
        .and_then(|r| scan_num(r, 10))
        .map(|(v, _)| v as u32);
    let Some(core) = core else {
        return Err(log_device_debug_errno!(dev, synthetic(libc::EINVAL), "Failed to parse BCMA device information."));
    };
    let buf = (core > 0).then(|| format!("b{core}").into_bytes());
    log_device_debug!(dev, format!("BCMA core identifier: core={core} "), arrow(), " \"", na(&buf), "\"");
    Ok(buf)
}

/// `names_bcma()`.
fn names_bcma(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let bcmadev = dev
        .get_parent_with_subsystem_devtype(b"bcma", None)
        .map_err(|r| log_device_debug_errno!(dev, r, "Could not get BCMA parent device: ", strerror(r)))?;
    let pcidev = bcmadev
        .get_parent_with_subsystem_devtype(b"pci", None)
        .map_err(|r| log_device_debug_errno!(dev, r, "Could not get PCI parent device: ", strerror(r)))?;
    let suffix = get_bcma_specifier(&bcmadev)?;
    names_pci_slot(event, &pcidev, prefix, suffix.as_deref())
}

/// `names_ccw()`.
fn names_ccw(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let Ok(cdev) = get_matching_parent(&dev, &[b"ccwgroup", b"ccw"], true) else { return Ok(()) };
    log_device_debug!(dev, "Device is CCW.");
    let bus_id = cdev
        .get_sysname()
        .map_err(|r| log_device_debug_errno!(cdev, r, "Failed to get sysname: ", strerror(r)))?
        .bytes()
        .to_vec();
    let len = bus_id.len();
    if len != 8 && len != 9 {
        return Err(log_device_debug_errno!(cdev, synthetic(libc::EINVAL), "Invalid bus_id: '", &bus_id[..], "'"));
    }
    let start = bus_id.iter().take_while(|c| matches!(c, b'.' | b'0')).count();
    let b = &bus_id[if start < len { start } else { len - 1 }..];
    let n = add_name(event, b"ID_NET_NAME_PATH", shared::bcat!(prefix, "c", b));
    log_device_debug!(dev, "CCW identifier: ccw_busid=", b, " ", arrow(), " \"", after_prefix(&n, prefix), "\"");
    Ok(())
}

/// `ieee_oui()`.
fn ieee_oui(event: &Event, a: &[u8]) -> Result<usize, i32> {
    if a.len() != 6 {
        return Err(-libc::EOPNOTSUPP);
    }
    if a[0] == 0 && a[1] == 0 && a[2] == 0 {
        return Err(-libc::EINVAL);
    }
    let s = format!("OUI:{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", a[0], a[1], a[2], a[3], a[4], a[5]);
    super::hwdb::lookup(event, None, s.as_bytes(), None)
}

/// `names_mac()`.
fn names_mac(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    let iftype = ns::get_sysattr_unsigned_filtered(&dev, b"type")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to read 'type' attribute: ", strerror(r)))?;
    if iftype == ARPHRD_INFINIBAND {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EOPNOTSUPP),
            "Not generating MAC name for infiniband device."
        ));
    }
    let assign_type = ns::get_sysattr_unsigned_filtered(&dev, b"addr_assign_type")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to read/parse addr_assign_type: ", strerror(r)))?;
    if assign_type != NET_ADDR_PERM {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EINVAL),
            format!("addr_assign_type={assign_type}, MAC address is not permanent.")
        ));
    }
    let s = ns::get_sysattr_safe_string_filtered(&dev, b"address")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to read 'address' attribute: ", strerror(r)))?;
    let a = shared::ether_addr::parse_hw_addr(&s)
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to parse 'address' attribute: ", strerror(r)))?;
    if a.len() != 6 {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EOPNOTSUPP),
            format!("Not generating MAC name for device with MAC address of length {}.", a.len())
        ));
    }
    let n = shared::bcat!(prefix, "x", shared::ether_addr::hw_addr_to_string_full(&a, true));
    let _ = udev_builtin_add_property(event, b"ID_NET_NAME_MAC", Some(&n));
    log_device_debug!(
        dev,
        "MAC address identifier: hw_addr=",
        shared::ether_addr::hw_addr_to_string(&a),
        " ",
        arrow(),
        " ",
        after_prefix(&n, prefix)
    );
    let _ = ieee_oui(event, &a);
    Ok(())
}

/// `names_netdevsim()`.
fn names_netdevsim(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    if !naming_scheme_has(ns::NAMING_NETDEVSIM) {
        return Ok(());
    }
    let nd = dev.get_parent_with_subsystem_devtype(b"netdevsim", None)?;
    let addr = nd
        .get_sysnum_unsigned()
        .map_err(|r| log_device_debug_errno!(nd, r, "Failed to get device sysnum: ", strerror(r)))?;
    let ppn = ns::get_sysattr_safe_string_filtered(&dev, b"phys_port_name")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get 'phys_port_name' attribute: ", strerror(r)))?;
    if ppn.is_empty() {
        return Err(log_device_debug_errno!(
            dev,
            synthetic(libc::EOPNOTSUPP),
            "The 'phys_port_name' attribute is empty."
        ));
    }
    let n = add_name(event, b"ID_NET_NAME_PATH", shared::bcat!(prefix, format!("i{addr}n"), &ppn[..]));
    log_device_debug!(
        dev,
        format!("Netdevsim identifier: address={addr}, port_name="),
        &ppn[..],
        " ",
        arrow(),
        " ",
        after_prefix(&n, prefix)
    );
    Ok(())
}

/// `names_xen()`.
fn names_xen(event: &Event, prefix: &str) -> Result<(), i32> {
    let dev = event.dev.clone();
    if !naming_scheme_has(ns::NAMING_XEN_VIF) {
        return Ok(());
    }
    if get_matching_parent(&dev, &[b"xen"], false).is_err() {
        return Ok(());
    }
    let vif = get_first_syspath_component(&dev, b"/sys/devices/")
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get Xen VIF name: ", strerror(r)))?;
    let Some(p) = vif.strip_prefix(b"vif-") else {
        return Err(log_device_debug_errno!(dev, synthetic(libc::EINVAL), "Invalid vif name: '", &vif[..], "'."));
    };
    let id = shared::parse::safe_atou_full(
        p,
        shared::parse::SAFE_ATO_REFUSE_PLUS_MINUS
            | shared::parse::SAFE_ATO_REFUSE_LEADING_ZERO
            | shared::parse::SAFE_ATO_REFUSE_LEADING_WHITESPACE
            | 10,
    )
    .map_err(|r| log_device_debug_errno!(dev, r, "Failed to parse vif index from '", p, "': ", strerror(r)))?;
    let n = add_name(event, b"ID_NET_NAME_SLOT", shared::bcat!(prefix, format!("X{id}")));
    log_device_debug!(dev, format!("Xen identifier: id={id} "), arrow(), " ", after_prefix(&n, prefix));
    Ok(())
}

/// `get_ifname_prefix()`.
fn get_ifname_prefix(dev: &Device) -> Result<&'static str, i32> {
    let iftype = ns::get_sysattr_unsigned_filtered(dev, b"type")?;
    match iftype {
        ARPHRD_ETHER => Ok(if dev.is_devtype(Some(b"wlan")) == Ok(true) {
            "wl"
        } else if dev.is_devtype(Some(b"wwan")) == Ok(true) {
            "ww"
        } else {
            "en"
        }),
        ARPHRD_INFINIBAND if naming_scheme_has(ns::NAMING_INFINIBAND) => Ok("ib"),
        ARPHRD_SLIP => Ok("sl"),
        ARPHRD_MCTP if naming_scheme_has(ns::NAMING_MCTP) => Ok("mc"),
        _ => Err(-libc::EOPNOTSUPP),
    }
}

/// `device_is_stacked()`.
fn device_is_stacked(dev: &Device) -> Result<bool, i32> {
    let ifindex = dev.get_ifindex()?;
    let iflink = ns::get_sysattr_int_filtered(dev, b"iflink")?;
    Ok(ifindex != iflink)
}

/// `builtin_net_id()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    match device_is_stacked(&dev) {
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Failed to check if the device is stacked: ", strerror(r)));
        }
        Ok(true) => return Ok(()),
        Ok(false) => {}
    }
    let prefix = match get_ifname_prefix(&dev) {
        Ok(p) => p,
        Err(r) => {
            log_device_debug_errno!(
                dev,
                r,
                "Failed to determine prefix for network interface naming, ignoring: ",
                strerror(r)
            );
            return Ok(());
        }
    };
    let _ = udev_builtin_add_property(event, b"ID_NET_NAMING_SCHEME", Some(naming_scheme().name.as_bytes()));
    let _ = names_mac(event, prefix);
    let _ = names_devicetree(event, prefix);
    let _ = names_ccw(event, prefix);
    let _ = names_vio(event, prefix);
    let _ = names_platform(event, prefix);
    let _ = names_netdevsim(event, prefix);
    let _ = names_xen(event, prefix);
    let _ = names_pci(event, prefix);
    let _ = names_usb(event, prefix);
    let _ = names_bcma(event, prefix);
    Ok(())
}

/// `builtin_net_id_init()`: picks the naming scheme here, so that workers
/// don't log it.
pub fn init() {
    let _ = naming_scheme();
}
