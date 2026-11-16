// SPDX-License-Identifier: LGPL-2.1-or-later
//! `netif-util.c` and `arphrd-util.c`: interface types, persistent names,
//! and checking generated hardware addresses.

use crate::sd_device::Device;
use crate::{log_device_debug, log_device_debug_errno, log_interface};

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_INFINIBAND: u16 = 32;
const ARPHRD_TUNNEL: u16 = 768;
const ARPHRD_TUNNEL6: u16 = 769;
const ARPHRD_SIT: u16 = 776;
const ARPHRD_IPGRE: u16 = 778;
const ARPHRD_IP6GRE: u16 = 823;
pub const INFINIBAND_ALEN: usize = 20;

/// `arphrd_to_name()`.
pub fn arphrd_to_name(id: u16) -> Option<&'static str> {
    crate::arphrd_names::ARPHRD_NAMES.iter().find(|(i, _)| *i == id).map(|(_, n)| *n)
}

/// `arphrd_to_hw_addr_len()`.
pub fn arphrd_to_hw_addr_len(t: u16) -> usize {
    match t {
        ARPHRD_ETHER => 6,
        ARPHRD_INFINIBAND => INFINIBAND_ALEN,
        ARPHRD_TUNNEL | ARPHRD_SIT | ARPHRD_IPGRE => 4,
        ARPHRD_TUNNEL6 | ARPHRD_IP6GRE => 16,
        _ => 0,
    }
}

/// `net_get_type_string(device, iftype, &ret)`.
pub fn net_get_type_string(device: Option<&Device>, iftype: u16) -> Option<Vec<u8>> {
    if let Some(d) = device
        && let Ok(t) = d.get_devtype()
        && !t.bytes().is_empty()
    {
        return Some(t.bytes().to_vec());
    }
    arphrd_to_name(iftype).map(|n| n.to_ascii_lowercase().into_bytes())
}

/// `net_get_persistent_name(device)`.
pub fn net_get_persistent_name(device: &Device) -> Option<Vec<u8>> {
    ["ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC"]
        .iter()
        .find_map(|f| device.get_property_value(f.as_bytes()).ok().map(|v| v.bytes().to_vec()))
}

/// The `HASH_KEY` of `net_get_unique_predictable_data()`.
const HASH_KEY: [u8; 16] =
    [0xd3, 0x1e, 0x48, 0xfa, 0x90, 0xfe, 0x4b, 0x4c, 0x9d, 0xaf, 0xd5, 0xd7, 0xa1, 0xb1, 0x2e, 0x8a];

/// `net_get_unique_predictable_data(device, use_sysname, &ret)`: the
/// little-endian bytes of the hash.
pub fn net_get_unique_predictable_data(device: &Device, use_sysname: bool) -> Result<[u8; 8], i32> {
    let mut name = net_get_persistent_name(device);
    if name.is_none() && use_sysname {
        name = device.get_sysname().ok().map(|s| s.bytes().to_vec());
    }
    let Some(name) = name else {
        return Err(log_device_debug_errno!(
            device,
            crate::errno::synthetic(libc::ENODATA),
            "No stable identifying information found"
        ));
    };
    log_device_debug!(device, "Using \"", &name[..], "\" as stable identifying information");
    let machine = crate::id128::get_machine(None)?;
    let v = crate::bcat!(&machine[..], &name[..]);
    Ok(crate::siphash::siphash24(&v, &HASH_KEY).to_le_bytes())
}

/// `net_verify_hardware_address(ifname, is_static, iftype, ib_hw_addr,
/// new_hw_addr)`.
pub fn net_verify_hardware_address(
    ifname: &[u8],
    is_static: bool,
    iftype: u16,
    ib_hw_addr: &[u8],
    new: &mut [u8],
) -> Result<(), i32> {
    use libc::LOG_WARNING;
    let warn = |m: &[u8]| {
        if is_static {
            log_interface!(Some(ifname), LOG_WARNING, 0, m);
        }
    };
    if new.is_empty() {
        return Ok(());
    }
    let want = arphrd_to_hw_addr_len(iftype);
    if new.len() != want {
        warn(
            format!("Specified MAC address with invalid length ({}, expected {}), refusing.", new.len(), want)
                .as_bytes(),
        );
        return Err(-libc::EINVAL);
    }
    match iftype {
        ARPHRD_ETHER => {
            if new.iter().all(|&b| b == 0) {
                warn(b"Specified MAC address is null, refusing.");
                return Err(-libc::EINVAL);
            }
            if new.iter().all(|&b| b == 0xff) {
                warn(b"Specified MAC address is broadcast, refusing.");
                return Err(-libc::EINVAL);
            }
            if new[0] & 0x01 != 0 {
                warn(b"Specified MAC address has the multicast bit set, clearing the bit.");
                new[0] &= 0xfe;
            }
            if !is_static && new[0] & 0x02 == 0 {
                new[0] |= 0x02;
            }
        }
        ARPHRD_INFINIBAND => {
            let n = INFINIBAND_ALEN - 8;
            if is_static && (new[..n].iter().any(|&b| b != 0) || new[..n] != ib_hw_addr[..n]) {
                warn(
                    b"Only the last 8 bytes of the InifniBand MAC address can be changed, ignoring the first 12 bytes.",
                );
            }
            if new[n..].iter().all(|&b| b == 0) {
                warn(b"The last 8 bytes of the InfiniBand MAC address cannot be null, refusing.");
                return Err(-libc::EINVAL);
            }
            new[..n].copy_from_slice(&ib_hw_addr[..n]);
        }
        _ => {
            warn(
                format!(
                    "Unsupported interface type {}{iftype} to set MAC address, refusing.",
                    arphrd_to_name(iftype).unwrap_or("n/a")
                )
                .as_bytes(),
            );
            return Err(-libc::EINVAL);
        }
    }
    Ok(())
}
