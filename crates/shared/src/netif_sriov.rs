// SPDX-License-Identifier: LGPL-2.1-or-later
//! `netif-sriov.c`: `[SR-IOV]` sections and setting them up.

use crate::errno::{strerror, synthetic};
use crate::sd_device::Device;
use crate::{log_device_debug, log_device_debug_errno, log_syntax, log_warning};

const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_VF_INFO: u16 = 1;
const IFLA_VF_MAC: u16 = 1;
const IFLA_VF_SPOOFCHK: u16 = 4;
const IFLA_VF_LINK_STATE: u16 = 5;
const IFLA_VF_RSS_QUERY_EN: u16 = 7;
const IFLA_VF_TRUST: u16 = 9;
const IFLA_VF_VLAN_LIST: u16 = 12;
const IFLA_VF_VLAN_INFO: u16 = 1;

/// `SRIOVLinkState`: auto, enable, disable (-1 unset).
pub const SR_IOV_LINK_STATE_AUTO: i32 = 0;
pub const SR_IOV_LINK_STATE_ENABLE: i32 = 1;
pub const SR_IOV_LINK_STATE_DISABLE: i32 = 2;

/// The `SRIOVAttribute`s, in order, with `sr_iov_attribute_table`'s names.
pub const ATTRIBUTES: &[&str] = &["MAC address", "spoof check", "RSS query", "trust", "link state", "vlan list"];

/// An `SRIOV`, keyed by its section (file, line).
#[derive(Debug, Clone)]
pub struct SrIov {
    pub filename: Vec<u8>,
    pub line: u32,
    pub invalid: bool,
    pub vf: u32,
    pub vlan: u32,
    pub qos: u32,
    pub vlan_proto: u16,
    pub vf_spoof_check_setting: i32,
    pub query_rss: i32,
    pub trust: i32,
    pub link_state: i32,
    pub mac: [u8; 6],
}

/// `sr_iov_by_section`, in insertion order.
pub type SrIovBySection = Vec<SrIov>;

/// `sr_iov_new_static()`: the section's entry, made if needed.
fn new_static<'a>(list: &'a mut SrIovBySection, filename: &[u8], line: u32) -> &'a mut SrIov {
    if let Some(i) = list.iter().position(|s| s.filename == filename && s.line == line) {
        return &mut list[i];
    }
    list.push(SrIov {
        filename: filename.to_vec(),
        line,
        invalid: false,
        vf: u32::MAX,
        vlan: 0,
        qos: 0,
        vlan_proto: ETH_P_8021Q,
        vf_spoof_check_setting: -1,
        query_rss: -1,
        trust: -1,
        link_state: -1,
        mac: [0; 6],
    });
    list.last_mut().expect("just pushed")
}

/// The `config_parse_sr_iov_*()` parsers.  A value that fails to parse
/// marks the section invalid (`sr_iov_unref_or_set_invalidp`).
pub fn config_parse_sr_iov(
    list: &mut SrIovBySection,
    filename: &[u8],
    line: u32,
    section_line: u32,
    lvalue: &[u8],
    rvalue: &[u8],
) -> i32 {
    let s = new_static(list, filename, section_line);
    let warn = |e: i32, m: Vec<u8>| {
        log_syntax!(libc::LOG_WARNING, Some(filename), line, e, m);
    };
    let ok = match lvalue {
        b"VirtualFunction" | b"VLANId" | b"QualityOfService" => {
            if rvalue.is_empty() {
                match lvalue {
                    b"VirtualFunction" => s.vf = u32::MAX,
                    b"VLANId" => s.vlan = 0,
                    _ => s.qos = 0,
                }
                true
            } else {
                match crate::parse::safe_atou(rvalue) {
                    Err(r) => {
                        warn(r, crate::bcat!("Failed to parse SR-IOV '", lvalue, "=', ignoring assignment: ", rvalue));
                        false
                    }
                    Ok(k) => match lvalue {
                        b"VLANId" if k == 0 || k > 4095 => {
                            warn(0, format!("Invalid SR-IOV VLANId: {k}").into_bytes());
                            false
                        }
                        b"VLANId" => {
                            s.vlan = k;
                            true
                        }
                        b"VirtualFunction" if k >= i32::MAX as u32 => {
                            warn(0, format!("Invalid SR-IOV virtual function: {k}").into_bytes());
                            false
                        }
                        b"VirtualFunction" => {
                            s.vf = k;
                            true
                        }
                        _ => {
                            s.qos = k;
                            true
                        }
                    },
                }
            }
        }
        b"VLANProtocol" => {
            if rvalue.is_empty() || rvalue == b"802.1Q" {
                s.vlan_proto = ETH_P_8021Q;
                true
            } else if rvalue == b"802.1ad" {
                s.vlan_proto = ETH_P_8021AD;
                true
            } else {
                warn(0, crate::bcat!("Invalid SR-IOV '", lvalue, "=', ignoring assignment: ", rvalue));
                false
            }
        }
        b"LinkState" => {
            if rvalue.is_empty() {
                s.link_state = -1;
                true
            } else if rvalue == b"auto" {
                s.link_state = SR_IOV_LINK_STATE_AUTO;
                true
            } else {
                match crate::parse::parse_boolean(rvalue) {
                    Err(r) => {
                        warn(r, crate::bcat!("Failed to parse SR-IOV '", lvalue, "=', ignoring assignment: ", rvalue));
                        false
                    }
                    Ok(b) => {
                        s.link_state = if b { SR_IOV_LINK_STATE_ENABLE } else { SR_IOV_LINK_STATE_DISABLE };
                        true
                    }
                }
            }
        }
        b"MACSpoofCheck" | b"QueryReceiveSideScaling" | b"Trust" => {
            let v = if rvalue.is_empty() {
                Some(-1)
            } else {
                match crate::parse::parse_boolean(rvalue) {
                    Err(r) => {
                        warn(r, crate::bcat!("Failed to parse '", lvalue, "=', ignoring: ", rvalue));
                        None
                    }
                    Ok(b) => Some(b as i32),
                }
            };
            match v {
                None => false,
                Some(v) => {
                    match lvalue {
                        b"MACSpoofCheck" => s.vf_spoof_check_setting = v,
                        b"QueryReceiveSideScaling" => s.query_rss = v,
                        _ => s.trust = v,
                    }
                    true
                }
            }
        }
        _ => {
            // MACAddress=
            if rvalue.is_empty() {
                s.mac = [0; 6];
                true
            } else {
                match crate::ether_addr::parse_hw_addr_full(rvalue, Some(6)) {
                    Err(r) => {
                        warn(r, crate::bcat!("Failed to parse SR-IOV '", lvalue, "=', ignoring assignment: ", rvalue));
                        false
                    }
                    Ok(a) => {
                        s.mac.copy_from_slice(&a);
                        true
                    }
                }
            }
        }
    };
    if !ok {
        s.invalid = true;
    }
    0
}

/// `config_parse_sr_iov_num_vfs()`.
pub fn config_parse_sr_iov_num_vfs(filename: &[u8], line: u32, lvalue: &[u8], rvalue: &[u8], num_vfs: &mut u32) -> i32 {
    if rvalue.is_empty() {
        *num_vfs = u32::MAX;
        return 0;
    }
    match crate::parse::safe_atou(rvalue) {
        Err(r) => {
            log_syntax!(
                libc::LOG_WARNING,
                Some(filename),
                line,
                r,
                "Failed to parse ",
                lvalue,
                "=, ignoring assignment: ",
                rvalue
            );
        }
        Ok(n) if n > i32::MAX as u32 => {
            log_syntax!(
                libc::LOG_WARNING,
                Some(filename),
                line,
                0,
                format!(
                    "The number of SR-IOV virtual functions is too large. It must be equal to or smaller than 2147483647. Ignoring assignment: {n}"
                )
            );
        }
        Ok(n) => *num_vfs = n,
    }
    0
}

/// `sr_iov_drop_invalid_sections(num_vfs, sr_iov_by_section)`.
pub fn sr_iov_drop_invalid_sections(num_vfs: u32, list: &mut SrIovBySection) {
    let mut kept: SrIovBySection = Vec::new();
    for s in std::mem::take(list) {
        // sr_iov_section_verify()
        if s.invalid {
            continue;
        }
        if s.vf == u32::MAX {
            log_warning!(
                &s.filename[..],
                format!(
                    ": [SR-IOV] section without VirtualFunction= field configured. Ignoring [SR-IOV] section from line {}.",
                    s.line
                )
            );
            continue;
        }
        if s.vf >= num_vfs {
            log_warning!(
                &s.filename[..],
                format!(
                    ": VirtualFunction= must be smaller than the value specified in SR-IOVVirtualFunctions=. Ignoring [SR-IOV] section from line {}.",
                    s.line
                )
            );
            continue;
        }
        if let Some(i) = kept.iter().position(|d| d.vf == s.vf) {
            let dup = kept.remove(i);
            log_warning!(
                &dup.filename[..],
                format!(
                    ": Conflicting [SR-IOV] section is specified at line {} and {}, dropping the [SR-IOV] section specified at line {}.",
                    s.line, dup.line, dup.line
                )
            );
        }
        kept.push(s);
    }
    // Detached sections leave the ordered map; the rest keep their order.
    *list = kept;
}

/// `sr_iov_has_config(sr_iov, attr)`.
pub fn sr_iov_has_config(s: &SrIov, attr: usize) -> bool {
    match attr {
        0 => s.mac != [0; 6],
        1 => s.vf_spoof_check_setting >= 0,
        2 => s.query_rss >= 0,
        3 => s.trust >= 0,
        4 => s.link_state >= 0,
        _ => s.vlan > 0,
    }
}

/// `sr_iov_set_netlink_message()` and `sd_netlink_call()`.
pub fn sr_iov_configure(ifindex: i32, s: &SrIov, attr: usize) -> Result<(), i32> {
    use crate::netlink::append_attr;
    if !sr_iov_has_config(s, attr) {
        return Ok(());
    }
    let vf = s.vf.to_ne_bytes();
    let pair = |v: u32| [&vf[..], &v.to_ne_bytes()[..]].concat();
    let mut info = Vec::new();
    match attr {
        0 => {
            // struct ifla_vf_mac: vf, mac[32]
            let mut ivm = vec![0u8; 36];
            ivm[..4].copy_from_slice(&vf);
            ivm[4..10].copy_from_slice(&s.mac);
            append_attr(&mut info, IFLA_VF_MAC, &ivm, false);
        }
        1 => append_attr(&mut info, IFLA_VF_SPOOFCHK, &pair(s.vf_spoof_check_setting as u32), false),
        2 => append_attr(&mut info, IFLA_VF_RSS_QUERY_EN, &pair(s.query_rss as u32), false),
        3 => append_attr(&mut info, IFLA_VF_TRUST, &pair(s.trust as u32), false),
        4 => append_attr(&mut info, IFLA_VF_LINK_STATE, &pair(s.link_state as u32), false),
        _ => {
            // struct ifla_vf_vlan_info: vf, vlan, qos, vlan_proto (be16) + padding
            let mut ivvi = vec![0u8; 16];
            ivvi[..4].copy_from_slice(&vf);
            ivvi[4..8].copy_from_slice(&s.vlan.to_ne_bytes());
            ivvi[8..12].copy_from_slice(&s.qos.to_ne_bytes());
            ivvi[12..14].copy_from_slice(&s.vlan_proto.to_be_bytes());
            let mut list = Vec::new();
            append_attr(&mut list, IFLA_VF_VLAN_INFO, &ivvi, false);
            append_attr(&mut info, IFLA_VF_VLAN_LIST, &list, true);
        }
    }
    let mut vfinfo = Vec::new();
    append_attr(&mut vfinfo, IFLA_VF_INFO, &info, true);
    let mut body = Vec::new();
    append_attr(&mut body, IFLA_VFINFO_LIST, &vfinfo, true);
    crate::netlink::rtnl_setlink_body(ifindex, &body)
}

/// `sr_iov_get_num_vfs(device, &ret)`.
pub fn sr_iov_get_num_vfs(device: &Device) -> Result<u32, i32> {
    device.get_sysattr_unsigned_full(b"device/sriov_numvfs", 0)
}

/// `sr_iov_set_num_vfs(device, num_vfs, sr_iov_by_section)`.
pub fn sr_iov_set_num_vfs(device: &Device, mut num_vfs: u32, list: &SrIovBySection) -> Result<(), i32> {
    if num_vfs == u32::MAX {
        num_vfs = list.iter().map(|s| s.vf + 1).max().unwrap_or(0);
        if num_vfs == 0 {
            return Ok(());
        }
        let current = sr_iov_get_num_vfs(device).map_err(|r| {
            log_device_debug_errno!(
                device,
                r,
                "Failed to get the current number of SR-IOV virtual functions: ",
                strerror(r)
            )
        })?;
        if num_vfs <= current {
            return Ok(());
        }
    } else if num_vfs == 0 {
        let r = device.set_sysattr_value(b"device/sriov_numvfs", Some(b"0"));
        if let Err(e) = r {
            log_device_debug_errno!(
                device,
                e,
                "Failed to write device/sriov_numvfs sysfs attribute, ignoring: ",
                strerror(e)
            );
            return if e == -libc::ENOENT { Ok(()) } else { Err(e) };
        }
        return Ok(());
    }
    match device.get_sysattr_unsigned_full(b"device/sriov_totalvfs", 0) {
        Ok(max) => {
            if num_vfs > max {
                return Err(log_device_debug_errno!(
                    device,
                    synthetic(libc::ERANGE),
                    format!(
                        "Specified number of virtual functions is out of range. The maximum allowed value is {max}."
                    )
                ));
            }
        }
        Err(r) if r == -libc::ENOENT => {}
        Err(r) => {
            return Err(log_device_debug_errno!(
                device,
                r,
                "Failed to read device/sriov_totalvfs sysfs attribute: ",
                strerror(r)
            ));
        }
    }
    let val = num_vfs.to_string();
    let mut r = device.set_sysattr_value(b"device/sriov_numvfs", Some(val.as_bytes()));
    if r == Err(-libc::EBUSY) {
        r = device.set_sysattr_value(b"device/sriov_numvfs", Some(b"0"));
        if r.is_ok() {
            r = device.set_sysattr_value(b"device/sriov_numvfs", Some(val.as_bytes()));
        }
    }
    if let Err(e) = r {
        return Err(log_device_debug_errno!(
            device,
            e,
            "Failed to write device/sriov_numvfs sysfs attribute: ",
            strerror(e)
        ));
    }
    log_device_debug!(device, "device/sriov_numvfs sysfs attribute set to '", val.as_bytes(), "'.");
    Ok(())
}
