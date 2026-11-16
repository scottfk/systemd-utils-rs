// SPDX-License-Identifier: LGPL-2.1-or-later
//! `link-config.c` (the loading half), `link-config-gperf.gperf` and the
//! `[Match]` half of `net-condition.c`: `.link` files.

use shared::condition::{ConditionType, Conditions, condition_test_list_net, config_parse_net_condition};
use shared::conf_parser::{
    Assign, CONFIG_PARSE_WARN, StatsByPath, config_get_stats_by_path, config_parse_many_full, log_syntax_parse_error,
};
use shared::cpu_set::{CpuSet, config_parse_cpu_set};
use shared::errno::strerror;
use shared::ethtool::{self as et, Channels, Coalesce, N_ADVERTISE, NET_DEV_FEAT_MAX, Ring, SOPASS_MAX, U32Opt};
use shared::extract::{EXTRACT_CUNESCAPE, EXTRACT_RETAIN_ESCAPE, EXTRACT_UNQUOTE, extract_first_word};
use shared::netif_sriov::{self as sriov, SrIovBySection};
use shared::{log_debug, log_error_errno, log_syntax, log_warning, log_warning_errno};

/// `NETWORK_DIRS`.
pub const NETWORK_DIRS: &[&[u8]] =
    &[b"/etc/systemd/network", b"/run/systemd/network", b"/usr/local/lib/systemd/network", b"/usr/lib/systemd/network"];

/// `MACAddressPolicy`.
pub const MAC_ADDRESS_POLICY_PERSISTENT: i32 = 0;
pub const MAC_ADDRESS_POLICY_RANDOM: i32 = 1;
pub const MAC_ADDRESS_POLICY_NONE: i32 = 2;
pub const MAC_ADDRESS_POLICIES: &[&str] = &["persistent", "random", "none"];

/// `NamePolicy`, by `name_policy_table` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamePolicy {
    Kernel,
    Keep,
    Database,
    Onboard,
    Slot,
    Path,
    Mac,
}

impl NamePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            NamePolicy::Kernel => "kernel",
            NamePolicy::Keep => "keep",
            NamePolicy::Database => "database",
            NamePolicy::Onboard => "onboard",
            NamePolicy::Slot => "slot",
            NamePolicy::Path => "path",
            NamePolicy::Mac => "mac",
        }
    }

    /// `name_policy_from_string()` (or the alternative names table, which
    /// lacks "kernel" and "keep").
    fn from_bytes(s: &[u8], alternative: bool) -> Option<NamePolicy> {
        let all = [
            NamePolicy::Kernel,
            NamePolicy::Keep,
            NamePolicy::Database,
            NamePolicy::Onboard,
            NamePolicy::Slot,
            NamePolicy::Path,
            NamePolicy::Mac,
        ];
        all.into_iter()
            .filter(|p| !alternative || !matches!(p, NamePolicy::Kernel | NamePolicy::Keep))
            .find(|p| p.as_str().as_bytes() == s)
    }
}

pub const IRQ_AFFINITY_POLICY_SINGLE: i32 = 0;
pub const IRQ_AFFINITY_POLICY_SPREAD: i32 = 1;
pub const IRQ_AFFINITY_NUMA_UNSET: u32 = u32::MAX;
pub const IRQ_AFFINITY_NUMA_LOCAL: u32 = u32::MAX - 1;

/// `NetMatch`: empty lists are C's NULL.
#[derive(Debug, Default)]
pub struct NetMatch {
    pub hw_addr: Vec<Vec<u8>>,
    pub permanent_hw_addr: Vec<Vec<u8>>,
    pub path: Vec<Vec<u8>>,
    pub driver: Vec<Vec<u8>>,
    pub iftype: Vec<Vec<u8>>,
    pub kind: Vec<Vec<u8>>,
    pub ifname: Vec<Vec<u8>>,
    pub property: Vec<Vec<u8>>,
}

impl NetMatch {
    /// `net_match_is_empty()`.
    pub fn is_empty(&self) -> bool {
        self.hw_addr.is_empty()
            && self.permanent_hw_addr.is_empty()
            && self.path.is_empty()
            && self.driver.is_empty()
            && self.iftype.is_empty()
            && self.kind.is_empty()
            && self.ifname.is_empty()
            && self.property.is_empty()
    }
}

/// A `LinkConfig`.
#[derive(Debug)]
pub struct LinkConfig {
    pub filename: Vec<u8>,
    pub dropins: Vec<Vec<u8>>,
    pub matches: NetMatch,
    pub conditions: Conditions,
    pub description: Option<Vec<u8>>,
    pub properties: Vec<Vec<u8>>,
    pub import_properties: Vec<Vec<u8>>,
    pub unset_properties: Vec<Vec<u8>>,
    pub hw_addr: Vec<u8>,
    pub mac_address_policy: i32,
    pub name_policy: Option<Vec<NamePolicy>>,
    pub alternative_names_policy: Option<Vec<NamePolicy>>,
    pub name: Option<Vec<u8>>,
    pub alternative_names: Vec<Vec<u8>>,
    pub alias: Option<Vec<u8>>,
    pub txqueues: u32,
    pub rxqueues: u32,
    pub txqueuelen: u32,
    pub mtu: u32,
    pub gso_max_segments: u32,
    pub gso_max_size: u64,
    pub speed: u64,
    pub duplex: i32,
    pub autonegotiation: i32,
    pub advertise: [u32; N_ADVERTISE],
    pub port: i32,
    pub mdi: u8,
    pub wol: u32,
    pub wol_password_file: Option<Vec<u8>>,
    pub wol_password: Option<[u8; SOPASS_MAX]>,
    pub features: [i32; NET_DEV_FEAT_MAX],
    pub channels: Channels,
    pub ring: Ring,
    pub rx_flow_control: i32,
    pub tx_flow_control: i32,
    pub autoneg_flow_control: i32,
    pub coalesce: Coalesce,
    pub eee_enabled: i32,
    pub eee_tx_lpi_enabled: i32,
    pub eee_tx_lpi_timer_usec: u64,
    pub eee_advertise: [u32; N_ADVERTISE],
    pub rps_cpu_mask: CpuSet,
    pub irq_affinity_policy: i32,
    pub irq_affinity_cpus: CpuSet,
    pub irq_affinity_numa: u32,
    pub sr_iov_num_vfs: u32,
    pub sr_iov_by_section: SrIovBySection,
}

impl LinkConfig {
    fn new(filename: &[u8]) -> LinkConfig {
        LinkConfig {
            filename: filename.to_vec(),
            dropins: Vec::new(),
            matches: NetMatch::default(),
            conditions: Vec::new(),
            description: None,
            properties: Vec::new(),
            import_properties: Vec::new(),
            unset_properties: Vec::new(),
            hw_addr: Vec::new(),
            mac_address_policy: MAC_ADDRESS_POLICY_NONE,
            name_policy: None,
            alternative_names_policy: None,
            name: None,
            alternative_names: Vec::new(),
            alias: None,
            txqueues: 0,
            rxqueues: 0,
            txqueuelen: u32::MAX,
            mtu: 0,
            gso_max_segments: 0,
            gso_max_size: 0,
            speed: 0,
            duplex: -1,
            autonegotiation: -1,
            advertise: [0; N_ADVERTISE],
            port: -1,
            mdi: et::ETH_TP_MDI_INVALID,
            wol: u32::MAX,
            wol_password_file: None,
            wol_password: None,
            features: [-1; NET_DEV_FEAT_MAX],
            channels: Channels::default(),
            ring: Ring::default(),
            rx_flow_control: -1,
            tx_flow_control: -1,
            autoneg_flow_control: -1,
            coalesce: Coalesce::default(),
            eee_enabled: -1,
            eee_tx_lpi_enabled: -1,
            eee_tx_lpi_timer_usec: u64::MAX,
            eee_advertise: [0; N_ADVERTISE],
            rps_cpu_mask: CpuSet::default(),
            irq_affinity_policy: -1,
            irq_affinity_cpus: CpuSet::default(),
            irq_affinity_numa: IRQ_AFFINITY_NUMA_UNSET,
            sr_iov_num_vfs: u32::MAX,
            sr_iov_by_section: Vec::new(),
        }
    }
}

/// `LinkConfigContext`.
#[derive(Debug, Default)]
pub struct LinkConfigContext {
    pub configs: Vec<LinkConfig>,
    pub ethtool: et::Ethtool,
    pub stats_by_path: Option<StatsByPath>,
}

fn warn(a: &Assign, e: i32, m: Vec<u8>) -> i32 {
    log_syntax!(libc::LOG_WARNING, Some(a.filename), a.line, e, m);
    0
}

/// The words of `rvalue`: Err(r) when extract_first_word() fails.
fn words(rvalue: &[u8], flags: u32) -> impl Iterator<Item = Result<Vec<u8>, i32>> + '_ {
    let mut p = Some(rvalue);
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        match extract_first_word(&mut p, None, flags) {
            Ok(Some(w)) => Some(Ok(w)),
            Ok(None) => None,
            Err(r) => {
                done = true;
                Some(Err(r))
            }
        }
    })
}

/// `config_parse_match_strv()`.
fn parse_match_strv(a: &Assign, sv: &mut Vec<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        sv.clear();
        return 0;
    }
    let (invert, p) = match a.rvalue.strip_prefix(b"!") {
        Some(p) => (true, p),
        None => (false, a.rvalue),
    };
    for w in words(p, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE) {
        match w {
            Err(r) => return warn(a, r, shared::bcat!("Invalid syntax, ignoring: ", a.rvalue)),
            Ok(w) => sv.push(if invert { shared::bcat!("!", &w[..]) } else { w }),
        }
    }
    0
}

/// `config_parse_match_ifnames()` (ltype 0).
fn parse_match_ifnames(a: &Assign, sv: &mut Vec<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        sv.clear();
        return 0;
    }
    let (invert, p) = match a.rvalue.strip_prefix(b"!") {
        Some(p) => (true, p),
        None => (false, a.rvalue),
    };
    for w in words(p, 0) {
        match w {
            Err(_) => return warn(a, 0, shared::bcat!("Failed to parse interface name list, ignoring: ", a.rvalue)),
            Ok(w) => {
                if !shared::netlink::ifname_valid_full(&w, false) {
                    warn(a, 0, shared::bcat!("Interface name is not valid or too long, ignoring assignment: ", &w[..]));
                    continue;
                }
                sv.push(if invert { shared::bcat!("!", &w[..]) } else { w });
            }
        }
    }
    0
}

/// `config_parse_match_property()`.
fn parse_match_property(a: &Assign, sv: &mut Vec<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        sv.clear();
        return 0;
    }
    let (invert, p) = match a.rvalue.strip_prefix(b"!") {
        Some(p) => (true, p),
        None => (false, a.rvalue),
    };
    for w in words(p, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE) {
        match w {
            Err(_) => return warn(a, 0, shared::bcat!("Invalid syntax, ignoring: ", a.rvalue)),
            Ok(w) => {
                if !shared::env::env_assignment_is_valid(&w) {
                    warn(a, 0, shared::bcat!("Invalid property or value, ignoring assignment: ", &w[..]));
                    continue;
                }
                sv.push(if invert { shared::bcat!("!", &w[..]) } else { w });
            }
        }
    }
    0
}

/// `config_parse_hw_addrs()` (ltype 0): a set, so no duplicates.
fn parse_hw_addrs(a: &Assign, set: &mut Vec<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        set.clear();
        return 1;
    }
    for w in words(a.rvalue, 0) {
        match w {
            Err(r) => return log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(w) => match shared::ether_addr::parse_hw_addr_full(&w, Some(0)) {
                Err(r) => {
                    warn(a, r, shared::bcat!("Not a valid hardware address, ignoring: ", &w[..]));
                }
                Ok(h) => {
                    if !set.contains(&h) {
                        set.push(h);
                    }
                }
            },
        }
    }
    1
}

/// `config_parse_string()` (ltype 0).
fn parse_string(a: &Assign, s: &mut Option<Vec<u8>>) -> i32 {
    *s = if a.rvalue.is_empty() { None } else { Some(a.rvalue.to_vec()) };
    1
}

/// `config_parse_tristate()`.
fn parse_tristate(a: &Assign, t: &mut i32) -> i32 {
    match shared::parse::parse_tristate(a.rvalue) {
        Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
        Ok(v) => {
            *t = v;
            1
        }
    }
}

/// `config_parse_uint32()`.
fn parse_uint32(a: &Assign, v: &mut u32) -> i32 {
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
        Ok(x) => {
            *v = x;
            1
        }
    }
}

/// The `udev_property_*` checks and specifiers of
/// `config_parse_udev_property()` / `config_parse_udev_property_name()`.
fn parse_udev_property(a: &Assign, props: &mut Vec<Vec<u8>>, name_only: bool) -> i32 {
    if a.rvalue.is_empty() {
        props.clear();
        return 0;
    }
    let mut table = shared::specifier::common_system_specifiers();
    table.extend(shared::specifier::common_tmp_specifiers());
    for w in words(a.rvalue, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE) {
        let w = match w {
            Err(r) => return warn(a, r, shared::bcat!("Invalid syntax, ignoring assignment: ", a.rvalue)),
            Ok(w) => w,
        };
        let resolved = match shared::specifier::specifier_printf(&w, usize::MAX, &table, None) {
            Ok(r) => r,
            Err(r) => {
                warn(
                    a,
                    r,
                    shared::bcat!("Failed to resolve specifiers in ", &w[..], ", ignoring assignment: ", strerror(r)),
                );
                continue;
            }
        };
        if name_only {
            if !shared::env::env_name_is_valid(&resolved) || !crate::udev::rules::device_property_can_set(&resolved) {
                warn(a, 0, shared::bcat!("Invalid udev property name, ignoring assignment: ", &resolved[..]));
                continue;
            }
            props.push(resolved);
        } else {
            if !shared::env::env_assignment_is_valid(&resolved) {
                warn(a, 0, shared::bcat!("Invalid udev property, ignoring assignment: ", &w[..]));
                continue;
            }
            let eq = resolved.iter().position(|&c| c == b'=').expect("valid assignment");
            let key = &resolved[..eq];
            if !crate::udev::rules::device_property_can_set(key) {
                warn(
                    a,
                    0,
                    shared::bcat!("Invalid udev property name '", key, "', ignoring assignment: ", &resolved[..]),
                );
                continue;
            }
            // strv_env_replace_consume()
            let name = key.to_vec();
            let has = |e: &Vec<u8>| e.len() > name.len() && e.starts_with(&name) && e[name.len()] == b'=';
            if let Some(i) = props.iter().position(has) {
                props[i] = resolved;
                let mut j = i + 1;
                while j < props.len() {
                    if has(&props[j]) {
                        props.remove(j);
                    } else {
                        j += 1;
                    }
                }
            } else {
                props.push(resolved);
            }
        }
    }
    0
}

/// `DEFINE_CONFIG_PARSE_ENUMV()` for the name policies.
fn parse_name_policy(a: &Assign, out: &mut Option<Vec<NamePolicy>>, alternative: bool) -> i32 {
    let mut xs: Vec<NamePolicy> = Vec::new();
    for w in words(a.rvalue, 0) {
        let w = match w {
            Err(r) => return log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(w) => w,
        };
        let Some(x) = NamePolicy::from_bytes(&w, alternative) else {
            warn(a, -libc::EINVAL, shared::bcat!("Failed to parse ", &w[..], " in ", a.lvalue, "=, ignoring."));
            continue;
        };
        if xs.contains(&x) {
            log_syntax!(
                libc::LOG_NOTICE,
                Some(a.filename),
                a.line,
                0,
                "Duplicate entry ",
                &w[..],
                " in ",
                a.lvalue,
                "=, ignoring."
            );
            continue;
        }
        xs.push(x);
    }
    *out = if xs.is_empty() { None } else { Some(xs) };
    1
}

/// `DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT()` / `_ENUM()` on a string
/// table; `default` is used for the empty string (None: no default).
fn parse_enum(a: &Assign, v: &mut i32, table: &[(&[u8], i32)], default: Option<i32>) -> i32 {
    if let Some(d) = default
        && a.rvalue.is_empty()
    {
        *v = d;
        return 1;
    }
    match table.iter().find(|(n, _)| *n == a.rvalue) {
        None => log_syntax_parse_error(a.filename, a.line, -libc::EINVAL, a.lvalue, a.rvalue),
        Some((_, x)) => {
            *v = *x;
            1
        }
    }
}

/// `config_parse_advertise()`.
fn parse_advertise(a: &Assign, adv: &mut [u32; N_ADVERTISE]) -> i32 {
    if a.rvalue.is_empty() {
        *adv = [0; N_ADVERTISE];
        return 0;
    }
    for w in words(a.rvalue, 0) {
        let w = match w {
            Err(r) => {
                return warn(
                    a,
                    r,
                    shared::bcat!(
                        "Failed to split advertise modes '",
                        a.rvalue,
                        "', ignoring assignment: ",
                        strerror(r)
                    ),
                );
            }
            Ok(w) => w,
        };
        match shared::ethtool_link_modes::LINK_MODES.iter().find(|(n, _)| *n == &w[..]) {
            None => {
                warn(a, -libc::EINVAL, shared::bcat!("Failed to parse advertise mode, ignoring: ", &w[..]));
            }
            Some((_, m)) => adv[(*m / 32) as usize] |= 1 << (m % 32),
        }
    }
    0
}

/// `config_parse_mdi()`.
fn parse_mdi(a: &Assign, mdi: &mut u8) -> i32 {
    *mdi = match a.rvalue {
        b"" => et::ETH_TP_MDI_INVALID,
        b"mdi" | b"straight" => et::ETH_TP_MDI,
        b"mdi-x" | b"mdix" | b"crossover" => et::ETH_TP_MDI_X,
        b"auto" => et::ETH_TP_MDI_AUTO,
        _ => {
            return warn(
                a,
                0,
                shared::bcat!("Failed to parse ", a.lvalue, "= setting, ignoring assignment: ", a.rvalue),
            );
        }
    };
    0
}

/// `config_parse_ring_buffer_or_channel()`.
fn parse_ring_buffer_or_channel(a: &Assign, dst: &mut U32Opt) -> i32 {
    if a.rvalue.is_empty() {
        *dst = U32Opt { value: 0, set: false };
        return 0;
    }
    if a.rvalue == b"max" {
        *dst = U32Opt { value: 0, set: true };
        return 0;
    }
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse ", a.lvalue, "=, ignoring: ", a.rvalue)),
        Ok(0) => warn(a, 0, shared::bcat!("Invalid ", a.lvalue, "= value, ignoring: ", a.rvalue)),
        Ok(k) => {
            *dst = U32Opt { value: k, set: true };
            0
        }
    }
}

/// `config_parse_wol()`.
fn parse_wol(a: &Assign, opts: &mut u32) -> i32 {
    if a.rvalue.is_empty() {
        *opts = u32::MAX;
        return 0;
    }
    if a.rvalue == b"off" {
        *opts = 0;
        return 0;
    }
    let mut new = 0u32;
    for w in words(a.rvalue, 0) {
        let w = match w {
            Err(r) => {
                return warn(
                    a,
                    r,
                    shared::bcat!(
                        "Failed to split wake-on-lan modes '",
                        a.rvalue,
                        "', ignoring assignment: ",
                        strerror(r)
                    ),
                );
            }
            Ok(w) => w,
        };
        match et::WOL_OPTIONS.iter().find(|(_, n)| n.as_bytes() == &w[..]) {
            Some((o, _)) => new |= o,
            None => {
                warn(a, 0, shared::bcat!("Unknown wake-on-lan mode '", &w[..], "', ignoring."));
            }
        }
    }
    if *opts == u32::MAX {
        *opts = new;
    } else {
        *opts |= new;
    }
    0
}

/// `config_parse_coalesce_u32()`.
fn parse_coalesce_u32(a: &Assign, dst: &mut U32Opt) -> i32 {
    if a.rvalue.is_empty() {
        *dst = U32Opt::default();
        return 0;
    }
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse ", a.lvalue, "=, ignoring: ", a.rvalue)),
        Ok(k) => {
            *dst = U32Opt { value: k, set: true };
            0
        }
    }
}

/// `config_parse_coalesce_sec()`.
fn parse_coalesce_sec(a: &Assign, dst: &mut U32Opt) -> i32 {
    if a.rvalue.is_empty() {
        *dst = U32Opt::default();
        return 0;
    }
    match shared::time::parse_sec(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse coalesce setting value, ignoring: ", a.rvalue)),
        Ok(u) if u > u32::MAX as u64 => {
            warn(a, 0, shared::bcat!("Too large ", a.lvalue, "= value, ignoring: ", a.rvalue))
        }
        Ok(u) => {
            if matches!(a.lvalue, b"StatisticsBlockCoalesceSec" | b"CoalescePacketRateSampleIntervalSec") && u < 1 {
                return warn(a, 0, shared::bcat!("Invalid ", a.lvalue, "= value, ignoring: ", a.rvalue));
            }
            *dst = U32Opt { value: u as u32, set: true };
            0
        }
    }
}

/// `config_parse_rx_tx_queues()`.
fn parse_rx_tx_queues(a: &Assign, v: &mut u32) -> i32 {
    if a.rvalue.is_empty() {
        *v = 0;
        return 0;
    }
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse ", a.lvalue, "=, ignoring assignment: ", a.rvalue, ".")),
        Ok(k) if k == 0 || k > 16384 => {
            warn(a, 0, shared::bcat!("Invalid ", a.lvalue, "=, ignoring assignment: ", a.rvalue, "."))
        }
        Ok(k) => {
            *v = k;
            0
        }
    }
}

/// `config_parse_txqueuelen()`.
fn parse_txqueuelen(a: &Assign, v: &mut u32) -> i32 {
    if a.rvalue.is_empty() {
        *v = u32::MAX;
        return 0;
    }
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse ", a.lvalue, "=, ignoring assignment: ", a.rvalue, ".")),
        Ok(u32::MAX) => warn(a, 0, shared::bcat!("Invalid ", a.lvalue, "=, ignoring assignment: ", a.rvalue, ".")),
        Ok(k) => {
            *v = k;
            0
        }
    }
}

/// `link_parse_wol_password()`: `parse_ether_addr()`.
fn parse_wol_password_value(s: &[u8]) -> Result<[u8; SOPASS_MAX], i32> {
    let a = shared::ether_addr::parse_hw_addr_full(s, Some(6))?;
    let mut p = [0u8; SOPASS_MAX];
    p.copy_from_slice(&a);
    Ok(p)
}

/// `warn_file_is_world_accessible(filename, st, unit, line)`.
fn warn_file_is_world_accessible(filename: &[u8], st: Option<&shared::sys::Stat>, line: Option<u32>) {
    let owned;
    let st = match st {
        Some(s) => s,
        None => match shared::sys::stat(filename) {
            Ok(s) => {
                owned = s;
                &owned
            }
            Err(_) => return,
        },
    };
    if st.st_mode & 0o007 == 0 {
        return;
    }
    let msg = shared::bcat!(
        filename,
        format!(
            " has {:04o} mode that is too permissive, please adjust the ownership and access mode.",
            st.st_mode & 0o7777
        )
    );
    match line {
        Some(l) => {
            log_syntax!(libc::LOG_WARNING, Some(filename), l, 0, msg);
        }
        None => {
            log_warning!(msg);
        }
    }
}

/// `config_parse_wol_password()`.
fn parse_wol_password(a: &Assign, c: &mut LinkConfig) -> i32 {
    if a.rvalue.is_empty() {
        c.wol_password = None;
        c.wol_password_file = None;
        return 0;
    }
    if shared::path::path_is_absolute(a.rvalue) && shared::path::path_is_safe(a.rvalue) {
        c.wol_password = None;
        c.wol_password_file = Some(a.rvalue.to_vec());
        return 0;
    }
    // warn_file_is_world_accessible(filename, NULL, unit=NULL, line): no unit, so log_warning().
    warn_file_is_world_accessible(a.filename, None, None);
    match parse_wol_password_value(a.rvalue) {
        Err(r) => warn(a, r, shared::bcat!("Failed to parse ", a.lvalue, "=, ignoring assignment: ", a.rvalue, ".")),
        Ok(p) => {
            c.wol_password = Some(p);
            c.wol_password_file = None;
            0
        }
    }
}

/// `config_parse_rps_cpu_mask()`.
fn parse_rps_cpu_mask(a: &Assign, mask: &mut CpuSet) -> i32 {
    if a.rvalue == b"disable" {
        let mut c = CpuSet::default();
        let _ = c.realloc(1);
        *mask = c;
        return 0;
    }
    if a.rvalue == b"all" {
        let mut c = CpuSet::default();
        if let Err(r) = c.add_all() {
            return warn(
                a,
                r,
                shared::bcat!("Failed to create CPU affinity mask representing \"all\" cpus, ignoring: ", strerror(r)),
            );
        }
        *mask = c;
        return 0;
    }
    config_parse_cpu_set(a.filename, a.line, a.lvalue, a.rvalue, mask)
}

/// `config_parse_irq_affinity_numa()`.
fn parse_irq_affinity_numa(a: &Assign, numa: &mut u32) -> i32 {
    if a.rvalue.is_empty() {
        *numa = IRQ_AFFINITY_NUMA_UNSET;
        return 0;
    }
    if a.rvalue == b"local" {
        *numa = IRQ_AFFINITY_NUMA_LOCAL;
        return 0;
    }
    match shared::parse::safe_atou(a.rvalue) {
        Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
        Ok(t) if t >= IRQ_AFFINITY_NUMA_LOCAL => {
            warn(a, 0, shared::bcat!(format!("Invalid NUMA node number {t}, ignoring assignment: "), a.rvalue))
        }
        Ok(t) => {
            *numa = t;
            0
        }
    }
}

/// `config_parse_ifalias()`.
fn parse_ifalias(a: &Assign, s: &mut Option<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        *s = None;
        return 0;
    }
    if !a.rvalue.is_ascii() {
        return warn(a, 0, shared::bcat!("Interface alias is not ASCII clean, ignoring assignment: ", a.rvalue));
    }
    if a.rvalue.len() >= 256 {
        return warn(a, 0, shared::bcat!("Interface alias is too long, ignoring assignment: ", a.rvalue));
    }
    *s = Some(a.rvalue.to_vec());
    0
}

/// `config_parse_ifname()`.
fn parse_ifname(a: &Assign, s: &mut Option<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        *s = None;
        return 1;
    }
    if !shared::netlink::ifname_valid(a.rvalue) {
        return warn(a, 0, shared::bcat!("Interface name is not valid or too long, ignoring assignment: ", a.rvalue));
    }
    *s = Some(a.rvalue.to_vec());
    1
}

/// `config_parse_ifnames()` with IFNAME_VALID_ALTERNATIVE.
fn parse_ifnames_alternative(a: &Assign, s: &mut Vec<Vec<u8>>) -> i32 {
    if a.rvalue.is_empty() {
        s.clear();
        return 1;
    }
    let mut names: Vec<Vec<u8>> = Vec::new();
    for w in words(a.rvalue, 0) {
        match w {
            Err(r) => return log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(w) => {
                if !shared::netlink::ifname_valid_full(&w, true) {
                    warn(a, 0, shared::bcat!("Interface name is not valid or too long, ignoring assignment: ", &w[..]));
                    continue;
                }
                names.push(w);
            }
        }
    }
    // strv_extend_strv(s, names, filter_duplicates=true)
    for n in names {
        if !s.contains(&n) {
            s.push(n);
        }
    }
    1
}

/// `config_parse_mtu()` with AF_UNSPEC.
fn parse_mtu(a: &Assign, mtu: &mut u32) -> i32 {
    match shared::parse::parse_mtu(a.rvalue) {
        Err(r) if r == -libc::ERANGE => warn(
            a,
            r,
            shared::bcat!(
                format!(
                    "Maximum transfer unit (MTU) value out of range. Permitted range is 0…{}, ignoring: ",
                    u32::MAX
                ),
                a.rvalue
            ),
        ),
        Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
        Ok(v) => {
            *mtu = v;
            1
        }
    }
}

/// The `link_config_gperf_lookup()` table: None for an unknown key.
fn lookup(c: &mut LinkConfig, a: &Assign) -> Option<i32> {
    use et::coalesce as co;
    let section = a.section?;
    let key = shared::bcat!(section, ".", a.lvalue);
    let cond = |c: &mut LinkConfig, t: ConditionType| config_parse_net_condition(&mut c.conditions, t, a.rvalue);
    let feat = |c: &mut LinkConfig, i: usize| parse_tristate(a, &mut c.features[i]);
    let cf = |c: &mut LinkConfig, i: usize, sec: bool| {
        if sec {
            parse_coalesce_sec(a, &mut c.coalesce.fields[i])
        } else {
            parse_coalesce_u32(a, &mut c.coalesce.fields[i])
        }
    };
    Some(match &key[..] {
        b"Match.MACAddress" => parse_hw_addrs(a, &mut c.matches.hw_addr),
        b"Match.PermanentMACAddress" => parse_hw_addrs(a, &mut c.matches.permanent_hw_addr),
        b"Match.OriginalName" => parse_match_ifnames(a, &mut c.matches.ifname),
        b"Match.Path" => parse_match_strv(a, &mut c.matches.path),
        b"Match.Driver" => parse_match_strv(a, &mut c.matches.driver),
        b"Match.Type" => parse_match_strv(a, &mut c.matches.iftype),
        b"Match.Kind" => parse_match_strv(a, &mut c.matches.kind),
        b"Match.Property" => parse_match_property(a, &mut c.matches.property),
        b"Match.Host" => cond(c, ConditionType::Host),
        b"Match.Virtualization" => cond(c, ConditionType::Virtualization),
        b"Match.KernelCommandLine" => cond(c, ConditionType::KernelCommandLine),
        b"Match.KernelVersion" | b"Match.Version" => cond(c, ConditionType::Version),
        b"Match.Credential" => cond(c, ConditionType::Credential),
        b"Match.Architecture" => cond(c, ConditionType::Architecture),
        b"Match.Firmware" => cond(c, ConditionType::Firmware),
        b"Match.MachineTag" => cond(c, ConditionType::MachineTag),
        b"Link.Description" => parse_string(a, &mut c.description),
        b"Link.Property" => parse_udev_property(a, &mut c.properties, false),
        b"Link.ImportProperty" => parse_udev_property(a, &mut c.import_properties, true),
        b"Link.UnsetProperty" => parse_udev_property(a, &mut c.unset_properties, true),
        b"Link.MACAddressPolicy" => {
            let t: Vec<(&[u8], i32)> =
                MAC_ADDRESS_POLICIES.iter().enumerate().map(|(i, n)| (n.as_bytes(), i as i32)).collect();
            parse_enum(a, &mut c.mac_address_policy, &t, Some(MAC_ADDRESS_POLICY_NONE))
        }
        b"Link.MACAddress" => {
            if a.rvalue.is_empty() {
                c.hw_addr.clear();
                1
            } else {
                match shared::ether_addr::parse_hw_addr_full(a.rvalue, Some(0)) {
                    Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
                    Ok(h) => {
                        c.hw_addr = h;
                        1
                    }
                }
            }
        }
        b"Link.NamePolicy" => parse_name_policy(a, &mut c.name_policy, false),
        b"Link.Name" => parse_ifname(a, &mut c.name),
        b"Link.AlternativeName" => parse_ifnames_alternative(a, &mut c.alternative_names),
        b"Link.AlternativeNamesPolicy" => parse_name_policy(a, &mut c.alternative_names_policy, true),
        b"Link.Alias" => parse_ifalias(a, &mut c.alias),
        b"Link.TransmitQueues" => parse_rx_tx_queues(a, &mut c.txqueues),
        b"Link.ReceiveQueues" => parse_rx_tx_queues(a, &mut c.rxqueues),
        b"Link.TransmitQueueLength" => parse_txqueuelen(a, &mut c.txqueuelen),
        b"Link.MTUBytes" => parse_mtu(a, &mut c.mtu),
        b"Link.GenericSegmentOffloadMaxBytes" => match shared::parse::parse_size(a.rvalue, 1024) {
            Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(v) if v > usize::MAX as u64 => {
                log_syntax_parse_error(a.filename, a.line, -libc::ERANGE, a.lvalue, a.rvalue)
            }
            Ok(v) => {
                c.gso_max_size = v;
                1
            }
        },
        b"Link.GenericSegmentOffloadMaxSegments" => parse_uint32(a, &mut c.gso_max_segments),
        b"Link.BitsPerSecond" => match shared::parse::parse_size(a.rvalue, 1000) {
            Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(v) => {
                c.speed = v;
                1
            }
        },
        b"Link.Duplex" => parse_enum(a, &mut c.duplex, et::DUPLEX_TABLE, None),
        b"Link.AutoNegotiation" => parse_tristate(a, &mut c.autonegotiation),
        b"Link.Advertise" => parse_advertise(a, &mut c.advertise),
        b"Link.Port" => parse_enum(a, &mut c.port, et::PORT_TABLE, None),
        b"Link.MDI" => parse_mdi(a, &mut c.mdi),
        b"Link.WakeOnLan" => parse_wol(a, &mut c.wol),
        b"Link.WakeOnLanPassword" => parse_wol_password(a, c),
        b"Link.ReceiveChecksumOffload" => feat(c, et::NET_DEV_FEAT_RXCSUM),
        b"Link.TransmitChecksumOffload" => feat(c, et::NET_DEV_FEAT_TXCSUM),
        b"Link.ScatterGather" => feat(c, et::NET_DEV_FEAT_SG),
        b"Link.ScatterGatherFragmentList" => feat(c, et::NET_DEV_FEAT_FRAGLIST),
        b"Link.GenericSegmentationOffload" => feat(c, et::NET_DEV_FEAT_GSO),
        b"Link.TCPSegmentationOffload" => feat(c, et::NET_DEV_FEAT_TSO),
        b"Link.TCPECNSegmentationOffload" => feat(c, et::NET_DEV_FEAT_TSO_ECN),
        b"Link.TCPMangleIdSegmentationOffload" => feat(c, et::NET_DEV_FEAT_TSO_MANGLEID),
        b"Link.TCP6SegmentationOffload" => feat(c, et::NET_DEV_FEAT_TSO6),
        b"Link.PartialGenericSegmentationOffload" => feat(c, et::NET_DEV_FEAT_GSO_PARTIAL),
        b"Link.UDPSegmentationOffload" => {
            // config_parse_warn_compat(DISABLED_LEGACY)
            log_syntax!(
                libc::LOG_INFO,
                Some(a.filename),
                a.line,
                0,
                "Support for option ",
                a.lvalue,
                "= has been removed and it is ignored"
            );
            0
        }
        b"Link.GenericReceiveOffload" => feat(c, et::NET_DEV_FEAT_GRO),
        b"Link.GenericReceiveOffloadHardware" => feat(c, et::NET_DEV_FEAT_GRO_HW),
        b"Link.GenericReceiveOffloadList" => feat(c, et::NET_DEV_FEAT_GRO_FRAGLIST),
        b"Link.GenericReceiveOffloadUDPForwarding" => feat(c, et::NET_DEV_FEAT_GRO_UDP_FWD),
        b"Link.LargeReceiveOffload" => feat(c, et::NET_DEV_FEAT_LRO),
        b"Link.ReceiveVLANCTAGHardwareAcceleration" => feat(c, et::NET_DEV_FEAT_HW_VLAN_CTAG_RX),
        b"Link.TransmitVLANCTAGHardwareAcceleration" => feat(c, et::NET_DEV_FEAT_HW_VLAN_CTAG_TX),
        b"Link.ReceiveVLANCTAGFilter" => feat(c, et::NET_DEV_FEAT_HW_VLAN_CTAG_FILTER),
        b"Link.TransmitVLANSTAGHardwareAcceleration" => feat(c, et::NET_DEV_FEAT_HW_VLAN_STAG_TX),
        b"Link.NTupleFilter" => feat(c, et::NET_DEV_FEAT_NTUPLE),
        b"Link.ReceiveFCS" => feat(c, et::NET_DEV_FEAT_RXFCS),
        b"Link.ReceiveAll" => feat(c, et::NET_DEV_FEAT_RXALL),
        b"Link.RxChannels" => parse_ring_buffer_or_channel(a, &mut c.channels.rx),
        b"Link.TxChannels" => parse_ring_buffer_or_channel(a, &mut c.channels.tx),
        b"Link.OtherChannels" => parse_ring_buffer_or_channel(a, &mut c.channels.other),
        b"Link.CombinedChannels" => parse_ring_buffer_or_channel(a, &mut c.channels.combined),
        b"Link.RxBufferSize" => parse_ring_buffer_or_channel(a, &mut c.ring.rx),
        b"Link.RxMiniBufferSize" => parse_ring_buffer_or_channel(a, &mut c.ring.rx_mini),
        b"Link.RxJumboBufferSize" => parse_ring_buffer_or_channel(a, &mut c.ring.rx_jumbo),
        b"Link.TxBufferSize" => parse_ring_buffer_or_channel(a, &mut c.ring.tx),
        b"Link.RxFlowControl" => parse_tristate(a, &mut c.rx_flow_control),
        b"Link.TxFlowControl" => parse_tristate(a, &mut c.tx_flow_control),
        b"Link.AutoNegotiationFlowControl" => parse_tristate(a, &mut c.autoneg_flow_control),
        b"Link.RxCoalesceSec" => cf(c, co::RX_USECS, true),
        b"Link.RxMaxCoalescedFrames" => cf(c, co::RX_MAX_FRAMES, false),
        b"Link.RxCoalesceIrqSec" => cf(c, co::RX_USECS_IRQ, true),
        b"Link.RxMaxCoalescedIrqFrames" => cf(c, co::RX_MAX_FRAMES_IRQ, false),
        b"Link.TxCoalesceSec" => cf(c, co::TX_USECS, true),
        b"Link.TxMaxCoalescedFrames" => cf(c, co::TX_MAX_FRAMES, false),
        b"Link.TxCoalesceIrqSec" => cf(c, co::TX_USECS_IRQ, true),
        b"Link.TxMaxCoalescedIrqFrames" => cf(c, co::TX_MAX_FRAMES_IRQ, false),
        b"Link.StatisticsBlockCoalesceSec" => cf(c, co::STATS_BLOCK_USECS, true),
        b"Link.UseAdaptiveRxCoalesce" => parse_tristate(a, &mut c.coalesce.use_adaptive_rx),
        b"Link.UseAdaptiveTxCoalesce" => parse_tristate(a, &mut c.coalesce.use_adaptive_tx),
        b"Link.CoalescePacketRateLow" => cf(c, co::PKT_RATE_LOW, false),
        b"Link.RxCoalesceLowSec" => cf(c, co::RX_USECS_LOW, true),
        b"Link.RxMaxCoalescedLowFrames" => cf(c, co::RX_MAX_FRAMES_LOW, false),
        b"Link.TxCoalesceLowSec" => cf(c, co::TX_USECS_LOW, true),
        b"Link.TxMaxCoalescedLowFrames" => cf(c, co::TX_MAX_FRAMES_LOW, false),
        b"Link.CoalescePacketRateHigh" => cf(c, co::PKT_RATE_HIGH, false),
        b"Link.RxCoalesceHighSec" => cf(c, co::RX_USECS_HIGH, true),
        b"Link.RxMaxCoalescedHighFrames" => cf(c, co::RX_MAX_FRAMES_HIGH, false),
        b"Link.TxCoalesceHighSec" => cf(c, co::TX_USECS_HIGH, true),
        b"Link.TxMaxCoalescedHighFrames" => cf(c, co::TX_MAX_FRAMES_HIGH, false),
        b"Link.CoalescePacketRateSampleIntervalSec" => cf(c, co::RATE_SAMPLE_INTERVAL, true),
        b"Link.ReceivePacketSteeringCPUMask" => parse_rps_cpu_mask(a, &mut c.rps_cpu_mask),
        b"Link.IRQAffinityPolicy" => {
            let t: &[(&[u8], i32)] =
                &[(b"single", IRQ_AFFINITY_POLICY_SINGLE), (b"spread", IRQ_AFFINITY_POLICY_SPREAD)];
            parse_enum(a, &mut c.irq_affinity_policy, t, Some(-1))
        }
        b"Link.IRQAffinity" => config_parse_cpu_set(a.filename, a.line, a.lvalue, a.rvalue, &mut c.irq_affinity_cpus),
        b"Link.IRQAffinityNUMA" => parse_irq_affinity_numa(a, &mut c.irq_affinity_numa),
        b"Link.SR-IOVVirtualFunctions" => {
            sriov::config_parse_sr_iov_num_vfs(a.filename, a.line, a.lvalue, a.rvalue, &mut c.sr_iov_num_vfs)
        }
        b"SR-IOV.VirtualFunction"
        | b"SR-IOV.VLANId"
        | b"SR-IOV.QualityOfService"
        | b"SR-IOV.VLANProtocol"
        | b"SR-IOV.MACSpoofCheck"
        | b"SR-IOV.QueryReceiveSideScaling"
        | b"SR-IOV.Trust"
        | b"SR-IOV.LinkState"
        | b"SR-IOV.MACAddress" => {
            sriov::config_parse_sr_iov(&mut c.sr_iov_by_section, a.filename, a.line, a.section_line, a.lvalue, a.rvalue)
        }
        b"EnergyEfficientEthernet.Enable" => parse_tristate(a, &mut c.eee_enabled),
        b"EnergyEfficientEthernet.TxLowPowerIdle" => parse_tristate(a, &mut c.eee_tx_lpi_enabled),
        b"EnergyEfficientEthernet.TxLowPowerIdleSec" => match shared::time::parse_sec(a.rvalue) {
            Err(r) => log_syntax_parse_error(a.filename, a.line, r, a.lvalue, a.rvalue),
            Ok(v) => {
                c.eee_tx_lpi_timer_usec = v;
                1
            }
        },
        b"EnergyEfficientEthernet.LinkMode" => parse_advertise(a, &mut c.eee_advertise),
        _ => return None,
    })
}

/// `link_read_wol_password_from_file()`.
fn read_wol_password_from_file(c: &mut LinkConfig) -> Result<(), i32> {
    let Some(f) = c.wol_password_file.clone() else { return Ok(()) };
    let st = shared::sys::stat(&f)?;
    // READ_FULL_FILE_WARN_WORLD_READABLE
    if st.st_mode & libc::S_IFMT == libc::S_IFREG {
        warn_file_is_world_accessible(&f, Some(&st), None);
    }
    let data = shared::fileio::read_full_file(&f)?;
    c.wol_password = Some(parse_wol_password_value(&data)?);
    Ok(())
}

/// `link_read_wol_password_from_cred()`.
fn read_wol_password_from_cred(c: &mut LinkConfig) -> Result<(), i32> {
    if c.wol == u32::MAX
        || c.wol & et::WAKE_MAGICSECURE == 0
        || c.wol_password.is_some()
        || c.wol_password_file.is_some()
    {
        return Ok(());
    }
    let base = shared::path::path_extract_filename(&c.filename)?;
    let name = shared::bcat!(&base[..], ".wol.password");
    let pw = match shared::creds::read_credential(&name) {
        Err(r) if r == -libc::ENOENT => shared::creds::read_credential(b"wol.password")?,
        r => r?,
    };
    c.wol_password = Some(parse_wol_password_value(&pw)?);
    Ok(())
}

/// `link_adjust_wol_options()`.
fn adjust_wol_options(c: &mut LinkConfig) {
    if let Err(r) = read_wol_password_from_file(c) {
        log_warning_errno!(
            r,
            "Failed to read WakeOnLan password from ",
            c.wol_password_file.as_deref().unwrap_or(b"(null)"),
            ", ignoring: ",
            strerror(r)
        );
    }
    if let Err(r) = read_wol_password_from_cred(c) {
        log_warning_errno!(r, "Failed to read WakeOnLan password from credential, ignoring: ", strerror(r));
    }
    if c.wol != u32::MAX && c.wol_password.is_some() {
        c.wol |= et::WAKE_MAGICSECURE;
    }
}

impl LinkConfigContext {
    /// `link_load_one(ctx, filename)`.
    pub fn load_one(&mut self, filename: &[u8]) {
        match shared::sys::stat(filename) {
            Err(r) => {
                log_warning_errno!(r, "Failed to check if \"", filename, "\" is empty: ", strerror(r));
                return;
            }
            Ok(st) if shared::stat_util::null_or_empty(&st) => {
                log_debug!("Skipping empty file: ", filename);
                return;
            }
            Ok(_) => {}
        }
        let mut config = LinkConfig::new(filename);
        let base = match shared::path::path_extract_filename(filename) {
            Ok(b) => b,
            Err(r) => {
                log_error_errno!(r, "Failed to extract file name of '", filename, "': ", strerror(r));
                return;
            }
        };
        let dropin_dirname = shared::bcat!(&base[..], ".d");
        let sections = ["Match", "Link", "SR-IOV", "EnergyEfficientEthernet"];
        let (stats, dropins) = {
            let mut l = |a: &Assign| lookup(&mut config, a);
            match config_parse_many_full(
                &[filename],
                NETWORK_DIRS,
                &dropin_dirname,
                Some(&sections),
                CONFIG_PARSE_WARN,
                &mut l,
                true,
            ) {
                Ok(x) => x,
                Err(_) => return,
            }
        };
        config.dropins = dropins;
        match &mut self.stats_by_path {
            Some(s) => {
                // hashmap_move(): entries already there stay.
                for (k, v) in stats {
                    s.entry(k).or_insert(v);
                }
            }
            None => self.stats_by_path = Some(stats),
        }
        if config.matches.is_empty() && config.conditions.is_empty() {
            log_warning!(
                filename,
                ": No valid settings found in the [Match] section, ignoring file. To match all interfaces, add OriginalName=* in the [Match] section."
            );
            return;
        }
        if !condition_test_list_net(&config.conditions) {
            log_debug!(filename, ": Conditions do not match the system environment, skipping.");
            return;
        }
        if (config.mac_address_policy == MAC_ADDRESS_POLICY_PERSISTENT
            || config.mac_address_policy == MAC_ADDRESS_POLICY_RANDOM)
            && !config.hw_addr.is_empty()
        {
            log_warning!(
                filename,
                ": MACAddress= in [Link] section will be ignored when MACAddressPolicy= is set to \"persistent\" or \"random\"."
            );
        }
        adjust_wol_options(&mut config);
        sriov::sr_iov_drop_invalid_sections(config.sr_iov_num_vfs, &mut config.sr_iov_by_section);
        log_debug!("Parsed configuration file \"", filename, "\"");
        self.configs.insert(0, config);
    }

    /// `link_config_load(ctx)`.
    pub fn load(&mut self) -> i32 {
        // link_configs_free()
        self.stats_by_path = None;
        self.configs.clear();
        let dirs: Vec<Vec<u8>> = NETWORK_DIRS.iter().map(|d| d.to_vec()).collect();
        let files = match shared::conf_files::conf_files_list_strv(
            Some(b".link"),
            None,
            shared::conf_files::CONF_FILES_WARN,
            &dirs,
        ) {
            Ok(f) => f,
            Err(r) => return log_error_errno!(r, "failed to enumerate link files: ", strerror(r)),
        };
        for f in files.iter().rev() {
            self.load_one(f);
        }
        0
    }

    /// `link_config_should_reload(ctx)`.
    pub fn should_reload(&self) -> bool {
        match config_get_stats_by_path(b".link", 0, NETWORK_DIRS, true) {
            Err(r) => {
                log_warning_errno!(r, "Failed to get stats of .link files, ignoring: ", strerror(r));
                true
            }
            Ok(s) => !shared::conf_parser::stats_by_path_equal(
                self.stats_by_path.as_ref().unwrap_or(&StatsByPath::new()),
                &s,
            ),
        }
    }
}
