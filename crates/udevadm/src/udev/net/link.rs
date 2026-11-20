// SPDX-License-Identifier: LGPL-2.1-or-later
//! `link-config.c` (the applying half): a network interface's `Link`,
//! matching it against the `.link` files, and applying the settings.

use shared::cpu_set::CpuSet;
use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_WARNING};
use shared::netif_naming_scheme::{self as ns, naming_scheme_has};
use shared::netif_util::{ARPHRD_ETHER, ARPHRD_INFINIBAND, INFINIBAND_ALEN};
use shared::sd_device::{Action, Device, device_action_to_string};
use shared::{log_interface, log_warning_errno};

use super::super::builtin::{udev_builtin_add_property, udev_builtin_import_property};
use super::super::def::EventMode;
use super::super::event::Event;
use super::link_config::{
    IRQ_AFFINITY_NUMA_LOCAL, IRQ_AFFINITY_NUMA_UNSET, IRQ_AFFINITY_POLICY_SINGLE, IRQ_AFFINITY_POLICY_SPREAD,
    LinkConfig, LinkConfigContext, MAC_ADDRESS_POLICIES, MAC_ADDRESS_POLICY_NONE, MAC_ADDRESS_POLICY_RANDOM,
    NamePolicy,
};

const IFF_LOOPBACK: u32 = 0x8;
const NET_NAME_ENUM: u32 = 1;
const NET_NAME_PREDICTABLE: u32 = 2;
const NET_NAME_USER: u32 = 3;
const NET_NAME_RENAMED: u32 = 4;
const NET_ADDR_PERM: u32 = 0;
const NET_ADDR_RANDOM: u32 = 1;
const NET_ADDR_STOLEN: u32 = 2;
const NET_ADDR_SET: u32 = 3;

/// `log_link_full_errno(link, level, error, ...)`.
macro_rules! log_link {
    ($link:expr, $level:expr, $err:expr, $($e:expr),* $(,)?) => {
        log_interface!(Some(&$link.ifname[..]), $level, $err, $($e),*)
    };
}

/// A `Link`.  `config` is the index of the matching configuration.
#[derive(Debug)]
pub struct Link {
    pub config: Option<usize>,
    pub ifname: Vec<u8>,
    pub ifindex: i32,
    pub action: Action,
    pub kind: Option<Vec<u8>>,
    pub driver: Option<Vec<u8>>,
    pub iftype: u16,
    pub flags: u32,
    pub hw_addr: Vec<u8>,
    pub permanent_hw_addr: Vec<u8>,
    pub name_assign_type: u32,
    pub addr_assign_type: u32,
    pub new_name: Option<Vec<u8>>,
}

/// `link_new(ctx, event, &link)`.
pub fn link_new(ctx: &mut LinkConfigContext, event: &Event) -> Result<Link, i32> {
    let dev = event.dev.clone();
    let ifname = dev.get_ifname()?.bytes().to_vec();
    let ifindex = dev.get_ifindex()?;
    let action = dev.get_action()?;
    let mut link = Link {
        config: None,
        ifname,
        ifindex,
        action,
        kind: None,
        driver: None,
        iftype: 0,
        flags: 0,
        hw_addr: Vec::new(),
        permanent_hw_addr: Vec::new(),
        name_assign_type: 0,
        addr_assign_type: 0,
        new_name: None,
    };
    match dev.get_sysattr_unsigned_full(b"name_assign_type", 0) {
        Err(r) => {
            log_link!(link, LOG_DEBUG, r, "Failed to get \"name_assign_type\" attribute, ignoring: ", strerror(r));
        }
        Ok(v) => {
            link.name_assign_type = v;
            log_link!(link, LOG_DEBUG, 0, format!("Device has name_assign_type attribute: {v}"));
        }
    }
    match dev.get_sysattr_unsigned_full(b"addr_assign_type", 0) {
        Err(r) => {
            log_link!(link, LOG_DEBUG, r, "Failed to get \"addr_assign_type\" attribute, ignoring: ", strerror(r));
        }
        Ok(v) => {
            link.addr_assign_type = v;
            log_link!(link, LOG_DEBUG, 0, format!("Device has addr_assign_type attribute: {v}"));
        }
    }
    let info = shared::netlink::rtnl_get_link_info(ifindex)?;
    link.iftype = info.iftype;
    link.flags = info.flags;
    link.kind = info.kind;
    link.hw_addr = info.hw_addr;
    link.permanent_hw_addr = info.permanent_hw_addr;
    if !link.hw_addr.is_empty() && link.permanent_hw_addr.is_empty() {
        match ctx.ethtool.get_permanent_hw_addr(&link.ifname) {
            Ok(a) => link.permanent_hw_addr = a,
            Err(r) => {
                log_link!(link, LOG_DEBUG, r, "Failed to get permanent hardware address, ignoring: ", strerror(r));
            }
        }
    }
    match dev.get_property_value(b"ID_NET_DRIVER") {
        Ok(d) => link.driver = Some(d.bytes().to_vec()),
        Err(r) if r == -libc::ENOENT => {}
        Err(r) => {
            log_link!(link, LOG_DEBUG, r, "Failed to get driver, ignoring: ", strerror(r));
        }
    }
    Ok(link)
}

/// `net_condition_test_strv()`.
fn test_strv(patterns: &[Vec<u8>], s: Option<&[u8]>) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let mut matched = false;
    let mut has_positive = false;
    for p in patterns {
        let (invert, q) = match p.strip_prefix(b"!") {
            Some(q) => (true, q),
            None => (false, &p[..]),
        };
        if !invert {
            has_positive = true;
        }
        if let Some(s) = s
            && shared::sys::fnmatch(q, s, 0) == 0
        {
            if invert {
                return false;
            }
            matched = true;
        }
    }
    if has_positive { matched } else { true }
}

/// `net_condition_test_property()`.
fn test_property(props: &[Vec<u8>], dev: &Device) -> Result<bool, i32> {
    for p in props {
        let invert = p.first() == Some(&b'!');
        let body = &p[invert as usize..];
        let eq = body.iter().position(|&c| c == b'=').ok_or(-libc::EINVAL)?;
        let (key, val) = (&body[..eq], &body[eq + 1..]);
        let v = dev.get_property_value(key).is_ok_and(|d| shared::sys::fnmatch(val, d.bytes(), 0) == 0);
        if if invert { v } else { !v } {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `net_match_config()` with the arguments `link_get_config()` passes.
fn net_match_config(c: &LinkConfig, link: &Link, dev: &Device) -> Result<bool, i32> {
    let m = &c.matches;
    let iftype_str = shared::netif_util::net_get_type_string(Some(dev), link.iftype);
    let path = dev.get_property_value(b"ID_PATH").ok().map(|p| p.bytes().to_vec());
    if !m.hw_addr.is_empty() && !m.hw_addr.contains(&link.hw_addr) {
        return Ok(false);
    }
    if !m.permanent_hw_addr.is_empty() && !m.permanent_hw_addr.contains(&link.permanent_hw_addr) {
        return Ok(false);
    }
    Ok(test_strv(&m.path, path.as_deref())
        && test_strv(&m.driver, link.driver.as_deref())
        && test_strv(&m.iftype, iftype_str.as_deref())
        && test_strv(&m.kind, link.kind.as_deref())
        && test_strv(&m.ifname, Some(&link.ifname))
        && test_property(&m.property, dev)?)
}

/// `link_get_config(ctx, link)`.
pub fn link_get_config(ctx: &LinkConfigContext, link: &mut Link, event: &Event) -> Result<(), i32> {
    if link.flags & IFF_LOOPBACK != 0 {
        return Err(-libc::ENOENT);
    }
    for (i, c) in ctx.configs.iter().enumerate() {
        if !net_match_config(c, link, &event.dev)? {
            continue;
        }
        if !c.matches.ifname.is_empty()
            && !c.matches.ifname.iter().any(|n| n == b"*")
            && link.name_assign_type == NET_NAME_ENUM
        {
            log_link!(
                link,
                LOG_WARNING,
                0,
                "Config file ",
                &c.filename[..],
                " is applied to device based on potentially unpredictable interface name."
            );
        } else {
            log_link!(link, LOG_DEBUG, 0, "Config file ", &c.filename[..], " is applied");
        }
        link.config = Some(i);
        return Ok(());
    }
    Err(-libc::ENOENT)
}

fn duplex_to_string(d: i32) -> &'static str {
    shared::ethtool::DUPLEX_TABLE
        .iter()
        .find(|(_, v)| *v == d)
        .map(|(n, _)| std::str::from_utf8(n).unwrap_or(""))
        .unwrap_or("")
}

fn port_to_string(p: i32) -> &'static str {
    shared::ethtool::PORT_TABLE
        .iter()
        .find(|(_, v)| *v == p)
        .map(|(n, _)| std::str::from_utf8(n).unwrap_or(""))
        .unwrap_or("")
}

fn mdi_to_string(m: u8) -> &'static str {
    ["unknown", "mdi", "mdi-x", "auto"].get(m as usize).copied().unwrap_or("")
}

/// `link_apply_ethtool_settings()`.
fn apply_ethtool_settings(ctx: &mut LinkConfigContext, link: &Link, event: &Event) {
    if event.event_mode != EventMode::UdevWorker {
        log_link!(link, LOG_DEBUG, 0, "Running in test mode, skipping application of ethtool settings.");
        return;
    }
    let c = &ctx.configs[link.config.expect("matched")];
    let et = &mut ctx.ethtool;
    let name = &link.ifname[..];
    if let Err(r) = et.set_link_settings(name, c.autonegotiation, &c.advertise, c.speed, c.duplex, c.port, c.mdi) {
        if c.autonegotiation >= 0 {
            log_link!(
                link,
                LOG_WARNING,
                r,
                "Could not ",
                if c.autonegotiation != 0 { "enable" } else { "disable" },
                " auto negotiation, ignoring: ",
                strerror(r)
            );
        }
        if c.advertise.iter().any(|&a| a != 0) {
            log_link!(link, LOG_WARNING, r, "Could not set advertise mode, ignoring: ", strerror(r));
        }
        if c.speed > 0 {
            log_link!(
                link,
                LOG_WARNING,
                r,
                format!("Could not set speed to {}Mbps, ignoring: ", c.speed.div_ceil(1_000_000)),
                strerror(r)
            );
        }
        if c.duplex >= 0 {
            log_link!(
                link,
                LOG_WARNING,
                r,
                "Could not set duplex to ",
                duplex_to_string(c.duplex),
                ", ignoring: ",
                strerror(r)
            );
        }
        if c.port >= 0 {
            log_link!(
                link,
                LOG_WARNING,
                r,
                "Could not set port to '",
                port_to_string(c.port),
                "', ignoring: ",
                strerror(r)
            );
        }
        if c.mdi != shared::ethtool::ETH_TP_MDI_INVALID {
            log_link!(
                link,
                LOG_WARNING,
                r,
                "Could not set MDI-X to '",
                mdi_to_string(c.mdi),
                "', ignoring: ",
                strerror(r)
            );
        }
    }
    if let Err(r) = et.set_wol(name, c.wol, c.wol_password.as_ref()) {
        let s = shared::ethtool::wol_options_to_string(c.wol).unwrap_or_default();
        log_link!(
            link,
            LOG_WARNING,
            r,
            "Could not set WakeOnLan",
            if s.is_empty() { "" } else { " to " },
            &s[..],
            ", ignoring: ",
            strerror(r)
        );
    }
    if let Err(r) = et.set_features(name, &c.features) {
        log_link!(link, LOG_WARNING, r, "Could not set offload features, ignoring: ", strerror(r));
    }
    if let Err(r) = et.set_channels(name, &c.channels) {
        log_link!(link, LOG_WARNING, r, "Could not set channels, ignoring: ", strerror(r));
    }
    if let Err(r) = et.set_nic_buffer_size(name, &c.ring) {
        log_link!(link, LOG_WARNING, r, "Could not set ring buffer, ignoring: ", strerror(r));
    }
    if let Err(r) = et.set_flow_control(name, c.rx_flow_control, c.tx_flow_control, c.autoneg_flow_control) {
        log_link!(link, LOG_WARNING, r, "Could not set flow control, ignoring: ", strerror(r));
    }
    if let Err(r) = et.set_nic_coalesce_settings(name, &c.coalesce) {
        log_link!(link, LOG_WARNING, r, "Could not set coalesce settings, ignoring: ", strerror(r));
    }
    if let Err(r) =
        et.set_eee_settings(name, c.eee_enabled, c.eee_tx_lpi_enabled, c.eee_tx_lpi_timer_usec, c.eee_advertise[0])
    {
        log_link!(link, LOG_WARNING, r, "Could not set energy efficient ethernet settings, ignoring: ", strerror(r));
    }
}

/// `hw_addr_is_valid()`.
fn hw_addr_is_valid(a: &[u8], iftype: u16) -> bool {
    match iftype {
        ARPHRD_ETHER => a.len() == 6 && a.iter().any(|&b| b != 0) && a.iter().any(|&b| b != 0xff),
        ARPHRD_INFINIBAND => a.len() == INFINIBAND_ALEN && a[INFINIBAND_ALEN - 8..].iter().any(|&b| b != 0),
        _ => false,
    }
}

/// `link_generate_new_hw_addr()`: empty for no change.
fn generate_new_hw_addr(c: &LinkConfig, link: &Link, event: &Event) -> Result<Vec<u8>, i32> {
    let mut hw: Vec<u8> = Vec::new();
    let mut is_static = false;
    'finalize: {
        if link.hw_addr.is_empty() {
            break 'finalize;
        }
        if c.mac_address_policy == MAC_ADDRESS_POLICY_NONE {
            log_link!(link, LOG_DEBUG, 0, "Using static MAC address.");
            hw = c.hw_addr.clone();
            is_static = true;
            break 'finalize;
        }
        if link.iftype != ARPHRD_ETHER && link.iftype != ARPHRD_INFINIBAND {
            break 'finalize;
        }
        match link.addr_assign_type {
            NET_ADDR_SET => {
                log_link!(link, LOG_DEBUG, 0, "MAC address on the device already set by userspace.");
                break 'finalize;
            }
            NET_ADDR_STOLEN => {
                log_link!(link, LOG_DEBUG, 0, "MAC address on the device already set based on another device.");
                break 'finalize;
            }
            NET_ADDR_RANDOM | NET_ADDR_PERM => {}
            t => {
                log_link!(link, LOG_WARNING, 0, format!("Unknown addr_assign_type {t}, ignoring"));
                break 'finalize;
            }
        }
        if (c.mac_address_policy == MAC_ADDRESS_POLICY_RANDOM) == (link.addr_assign_type == NET_ADDR_RANDOM) {
            log_link!(
                link,
                LOG_DEBUG,
                0,
                "MAC address on the device already matches policy \"",
                MAC_ADDRESS_POLICIES[c.mac_address_policy as usize],
                "\"."
            );
            break 'finalize;
        }
        hw = vec![0u8; shared::netif_util::arphrd_to_hw_addr_len(link.iftype)];
        let (off, len) = if link.iftype == ARPHRD_ETHER { (0, hw.len()) } else { (INFINIBAND_ALEN - 8, 8) };
        if c.mac_address_policy == MAC_ADDRESS_POLICY_RANDOM {
            loop {
                let _ = shared::sys::getrandom(&mut hw[off..off + len]);
                if hw_addr_is_valid(&hw, link.iftype) {
                    break;
                }
            }
        } else {
            let result = match shared::netif_util::net_get_unique_predictable_data(
                &event.dev,
                naming_scheme_has(ns::NAMING_STABLE_VIRTUAL_MACS),
            ) {
                Ok(v) => v,
                Err(r) => {
                    return Err(log_link!(
                        link,
                        LOG_WARNING,
                        r,
                        "Could not generate persistent MAC address: ",
                        strerror(r)
                    ));
                }
            };
            hw[off..off + len].copy_from_slice(&result[..len]);
            if !hw_addr_is_valid(&hw, link.iftype) {
                return Err(log_link!(
                    link,
                    LOG_WARNING,
                    synthetic(libc::EINVAL),
                    "Could not generate valid persistent MAC address."
                ));
            }
        }
    }
    // finalize:
    shared::netif_util::net_verify_hardware_address(&link.ifname, is_static, link.iftype, &link.hw_addr, &mut hw)?;
    if hw == link.hw_addr {
        return Ok(Vec::new());
    }
    if !hw.is_empty() {
        log_link!(
            link,
            LOG_DEBUG,
            0,
            "Applying ",
            if c.mac_address_policy == MAC_ADDRESS_POLICY_NONE {
                "static"
            } else {
                MAC_ADDRESS_POLICIES[c.mac_address_policy as usize]
            },
            " MAC address: ",
            shared::ether_addr::hw_addr_to_string(&hw)
        );
    }
    Ok(hw)
}

/// `link_apply_rtnl_settings()`.
fn apply_rtnl_settings(c: &LinkConfig, link: &Link, event: &Event) {
    if event.event_mode != EventMode::UdevWorker {
        log_link!(link, LOG_DEBUG, 0, "Running in test mode, skipping application of rtnl settings.");
        return;
    }
    let hw = generate_new_hw_addr(c, link, event).unwrap_or_default();
    // C passes gso_max_size (a size_t) as the u32 parameter.
    if let Err(r) = shared::netlink::rtnl_set_link_properties(
        link.ifindex,
        c.alias.as_deref(),
        &hw,
        c.txqueues,
        c.rxqueues,
        c.txqueuelen,
        c.mtu,
        c.gso_max_size as u32,
        c.gso_max_segments,
    ) {
        log_link!(
            link,
            LOG_WARNING,
            r,
            "Could not set Alias=, MACAddress=/MACAddressPolicy=, TransmitQueues=, ReceiveQueues=, TransmitQueueLength=, MTUBytes=, GenericSegmentOffloadMaxBytes= or GenericSegmentOffloadMaxSegments=, ignoring: ",
            strerror(r)
        );
    }
}

thread_local! {
    static ENABLE_NAME_POLICY: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// `enable_name_policy()`.
fn enable_name_policy() -> bool {
    if let Some(b) = ENABLE_NAME_POLICY.with(|c| c.get()) {
        return b;
    }
    // proc_cmdline_get_bool("net.ifnames", 0, &b)
    let r = match shared::proc_cmdline::proc_cmdline_get_key(b"net.ifnames", true) {
        Err(r) => Err(r),
        Ok(None) => Ok(None),
        Ok(Some(None)) => Ok(Some(true)),
        Ok(Some(Some(v))) => shared::parse::parse_boolean(&v).map(Some),
    };
    let b = match r {
        Err(r) => {
            log_warning_errno!(r, "Failed to parse net.ifnames= kernel command line option, ignoring: ", strerror(r));
            true
        }
        Ok(None) => true,
        Ok(Some(b)) => {
            if !b {
                shared::log_info!("Network interface NamePolicy= disabled on kernel command line.");
            }
            b
        }
    };
    ENABLE_NAME_POLICY.with(|c| c.set(Some(b)));
    b
}

/// The property a name policy reads.
fn policy_property(p: NamePolicy) -> &'static [u8] {
    match p {
        NamePolicy::Database => b"ID_NET_NAME_FROM_DATABASE",
        NamePolicy::Onboard => b"ID_NET_NAME_ONBOARD",
        NamePolicy::Slot => b"ID_NET_NAME_SLOT",
        NamePolicy::Path => b"ID_NET_NAME_PATH",
        _ => b"ID_NET_NAME_MAC",
    }
}

/// `link_generate_new_name()`.
fn generate_new_name(c: &LinkConfig, link: &mut Link, event: &Event) -> Result<(), i32> {
    let dev = event.dev.clone();
    'rename: {
        if link.action != Action::Add {
            log_link!(
                link,
                LOG_DEBUG,
                0,
                "Not applying Name= and NamePolicy= on '",
                device_action_to_string(link.action),
                "' uevent."
            );
            break 'rename;
        }
        if (link.name_assign_type == NET_NAME_USER || link.name_assign_type == NET_NAME_RENAMED)
            && !naming_scheme_has(ns::NAMING_ALLOW_RERENAMES)
        {
            log_link!(link, LOG_DEBUG, 0, "Device already has a name given by userspace, not renaming.");
            break 'rename;
        }
        if enable_name_policy()
            && let Some(policies) = &c.name_policy
        {
            for &p in policies {
                let new_name = match p {
                    NamePolicy::Kernel => {
                        if link.name_assign_type != NET_NAME_PREDICTABLE {
                            continue;
                        }
                        log_link!(link, LOG_DEBUG, 0, "Policy *", p.as_str(), "*: keeping predictable kernel name");
                        break 'rename;
                    }
                    NamePolicy::Keep => {
                        if link.name_assign_type != NET_NAME_USER && link.name_assign_type != NET_NAME_RENAMED {
                            continue;
                        }
                        log_link!(link, LOG_DEBUG, 0, "Policy *", p.as_str(), "*: keeping existing userspace name");
                        break 'rename;
                    }
                    _ => dev.get_property_value(policy_property(p)).ok().map(|v| v.bytes().to_vec()),
                };
                if let Some(n) = new_name
                    && shared::netlink::ifname_valid(&n)
                {
                    log_link!(link, LOG_DEBUG, 0, "Policy *", p.as_str(), "* yields \"", &n[..], "\".");
                    link.new_name = Some(n);
                    return Ok(());
                }
            }
        }
        if let Some(n) = &c.name {
            log_link!(link, LOG_DEBUG, 0, "Policies didn't yield a name, using specified Name=", &n[..], ".");
            link.new_name = Some(n.clone());
            return Ok(());
        }
        log_link!(link, LOG_DEBUG, 0, "Policies didn't yield a name and Name= is not given, not renaming.");
    }
    // no_rename:
    if !naming_scheme_has(ns::NAMING_USE_INTERFACE_PROPERTY) {
        link.new_name = Some(dev.get_sysname()?.bytes().to_vec());
        return Ok(());
    }
    link.new_name = Some(link.ifname.clone());
    Ok(())
}

/// `link_generate_alternative_names()`.
fn generate_alternative_names(c: &LinkConfig, link: &Link, event: &mut Event) {
    if link.action != Action::Add {
        log_link!(
            link,
            LOG_DEBUG,
            0,
            "Not applying AlternativeNames= and AlternativeNamesPolicy= on '",
            device_action_to_string(link.action),
            "' uevent."
        );
        return;
    }
    let mut altnames = c.alternative_names.clone();
    if let Some(policies) = &c.alternative_names_policy {
        for &p in policies {
            if let Ok(n) = event.dev.get_property_value(policy_property(p))
                && shared::netlink::ifname_valid_full(n.bytes(), true)
            {
                altnames.push(n.bytes().to_vec());
            }
        }
    }
    event.altnames = altnames;
}

/// `link_apply_sr_iov_config()`.
fn apply_sr_iov_config(c: &LinkConfig, link: &Link, event: &Event) {
    use shared::netif_sriov as s;
    if event.event_mode != EventMode::UdevWorker {
        log_link!(link, LOG_DEBUG, 0, "Running in test mode, skipping application of SR-IOV settings.");
        return;
    }
    if let Err(r) = s::sr_iov_set_num_vfs(&event.dev, c.sr_iov_num_vfs, &c.sr_iov_by_section) {
        log_link!(
            link,
            LOG_WARNING,
            r,
            "Failed to set the number of SR-IOV virtual functions, ignoring: ",
            strerror(r)
        );
    }
    if c.sr_iov_by_section.is_empty() {
        return;
    }
    let n = match s::sr_iov_get_num_vfs(&event.dev) {
        Err(r) => {
            log_link!(
                link,
                LOG_WARNING,
                r,
                "Failed to get the number of SR-IOV virtual functions, ignoring all [SR-IOV] sections: ",
                strerror(r)
            );
            return;
        }
        Ok(n) => n,
    };
    if n == 0 {
        log_link!(link, LOG_WARNING, 0, "No SR-IOV virtual functions exist, ignoring all [SR-IOV] sections.");
        return;
    }
    for sec in &c.sr_iov_by_section {
        if sec.vf >= n {
            log_link!(
                link,
                LOG_WARNING,
                0,
                format!(
                    "SR-IOV virtual function {} does not exist, ignoring [SR-IOV] section for the virtual function.",
                    sec.vf
                )
            );
            continue;
        }
        for (attr, aname) in s::ATTRIBUTES.iter().enumerate() {
            if let Err(r) = s::sr_iov_configure(link.ifindex, sec, attr) {
                log_link!(
                    link,
                    LOG_WARNING,
                    r,
                    "Failed to set up ",
                    *aname,
                    format!(" for SR-IOV virtual function {}, ignoring: ", sec.vf),
                    strerror(r)
                );
            }
        }
    }
}

/// `link_apply_rps_cpu_mask()`.
fn apply_rps_cpu_mask(c: &LinkConfig, link: &Link, event: &Event) {
    if event.event_mode != EventMode::UdevWorker {
        log_link!(link, LOG_DEBUG, 0, "Running in test mode, skipping application of RPS setting.");
        return;
    }
    if !c.rps_cpu_mask.is_set() {
        return;
    }
    let mask = c.rps_cpu_mask.to_mask_string();
    log_link!(link, LOG_DEBUG, 0, "Applying RPS CPU mask: ", &mask[..]);
    let dev = &event.dev;
    let mut attr = dev.get_sysattr_first();
    while let Some(a) = attr {
        attr = dev.get_sysattr_next();
        let a = a.bytes().to_vec();
        let Some(rest) = shared::path::path_startswith(&a, b"queues/") else { continue };
        let Some(rest) = rest.strip_prefix(b"rx-") else { continue };
        let tail = &rest[rest.iter().position(|&c| c == b'/').unwrap_or(rest.len())..];
        if !shared::path::path_equal(tail, b"/rps_cpus") {
            continue;
        }
        if let Err(r) = dev.set_sysattr_value(&a, Some(&mask)) {
            log_link!(link, LOG_WARNING, r, "Failed to write ", &a[..], " sysfs attribute, ignoring: ", strerror(r));
        }
    }
}

/// `link_apply_irq_affinity()`.
fn apply_irq_affinity(c: &LinkConfig, link: &Link, event: &Event) -> Result<(), i32> {
    if event.event_mode != EventMode::UdevWorker {
        log_link!(link, LOG_DEBUG, 0, "Running in test mode, skipping application of IRQ affinity settings.");
        return Ok(());
    }
    if c.irq_affinity_policy < 0 {
        return Ok(());
    }
    let mut effective = CpuSet::default();
    if c.irq_affinity_numa != IRQ_AFFINITY_NUMA_UNSET {
        let numa_node = if c.irq_affinity_numa == IRQ_AFFINITY_NUMA_LOCAL {
            // link_get_device_numa_node()
            let n = match event.dev.get_sysattr_int(b"device/numa_node") {
                Ok(n) if n < 0 => Err(-libc::ENOENT),
                r => r,
            };
            match n {
                Err(r) => {
                    log_link!(
                        link,
                        LOG_WARNING,
                        r,
                        "Failed to determine local NUMA node for device, skipping IRQ affinity configuration: ",
                        strerror(r)
                    );
                    return Ok(());
                }
                Ok(n) => {
                    log_link!(link, LOG_DEBUG, 0, format!("Device is on NUMA node {n}."));
                    n as u32
                }
            }
        } else {
            c.irq_affinity_numa
        };
        let numa_cpus = match shared::cpu_set::numa_node_get_cpus(numa_node) {
            Err(r) => {
                log_link!(
                    link,
                    LOG_WARNING,
                    r,
                    format!("Failed to get CPUs for NUMA node {numa_node}, skipping IRQ affinity configuration: "),
                    strerror(r)
                );
                return Ok(());
            }
            Ok(s) => s,
        };
        if c.irq_affinity_cpus.is_set() {
            let max = numa_cpus.allocated().max(c.irq_affinity_cpus.allocated());
            effective.realloc(max * 8)?;
            for i in 0..max * 8 {
                if numa_cpus.contains(i) && c.irq_affinity_cpus.contains(i) {
                    effective.add(i)?;
                }
            }
            if !effective.is_set() || effective.count() == 0 {
                log_link!(
                    link,
                    LOG_WARNING,
                    0,
                    "IRQAffinity= and IRQAffinityNUMA= intersection is empty, skipping IRQ affinity configuration."
                );
                return Ok(());
            }
            log_link!(
                link,
                LOG_DEBUG,
                0,
                format!("Using intersection of IRQAffinity= and NUMA node {numa_node} CPUs.")
            );
        } else {
            effective = numa_cpus;
            log_link!(link, LOG_DEBUG, 0, format!("Using CPUs from NUMA node {numa_node}."));
        }
    } else if c.irq_affinity_cpus.is_set() {
        effective.add_set(&c.irq_affinity_cpus)?;
    }
    let allowed = if effective.is_set() { Some(&effective) } else { None };
    match c.irq_affinity_policy {
        IRQ_AFFINITY_POLICY_SINGLE => super::irq::apply_single(link, &event.dev, allowed),
        IRQ_AFFINITY_POLICY_SPREAD => super::irq::apply_spread(link, &event.dev, allowed),
        _ => unreachable!("validated policy"),
    }
}

/// `link_apply_udev_properties()`.
fn apply_udev_properties(c: &LinkConfig, link: &Link, event: &Event) {
    for p in &c.import_properties {
        let _ = udev_builtin_import_property(event, p);
    }
    for p in &c.properties {
        let Some(eq) = p.iter().position(|&b| b == b'=') else { continue };
        let _ = udev_builtin_add_property(event, &p[..eq], Some(&p[eq + 1..]));
    }
    for p in &c.unset_properties {
        let _ = udev_builtin_add_property(event, p, None);
    }
    let _ = udev_builtin_add_property(event, b"ID_NET_LINK_FILE", Some(&c.filename));
    let joined: Vec<u8> = c.dropins.iter().map(|d| crate::udev::node::xescape(d, b":")).collect::<Vec<_>>().join(&b':');
    let _ = udev_builtin_add_property(event, b"ID_NET_LINK_FILE_DROPINS", Some(&joined));
    if let Some(n) = &link.new_name {
        let _ = udev_builtin_add_property(event, b"ID_NET_NAME", Some(n));
    }
}

/// `link_apply_config(ctx, link)`.
pub fn link_apply_config(ctx: &mut LinkConfigContext, link: &mut Link, event: &mut Event) -> Result<(), i32> {
    apply_ethtool_settings(ctx, link, event);
    let c = &ctx.configs[link.config.expect("matched")];
    apply_rtnl_settings(c, link, event);
    generate_new_name(c, link, event)?;
    generate_alternative_names(c, link, event);
    apply_sr_iov_config(c, link, event);
    apply_rps_cpu_mask(c, link, event);
    apply_irq_affinity(c, link, event)?;
    apply_udev_properties(c, link, event);
    Ok(())
}
