// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `ethtool-util.c` that udev uses.

use crate::errno::strerror;
use crate::sys::{self, OwnedFd};

/// `socket_ioctl_fd()`.
fn socket_ioctl_fd() -> Result<OwnedFd, i32> {
    match sys::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
        Ok(fd) => Ok(OwnedFd::new(fd)),
        Err(_) => {
            sys::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_GENERIC).map(OwnedFd::new)
        }
    }
}

/// A lazily connected ethtool socket (`int ethtool_fd`).
#[derive(Debug, Default)]
pub struct Ethtool {
    fd: Option<OwnedFd>,
}

impl Ethtool {
    /// `ethtool_connect()`.
    fn connect(&mut self) -> Result<i32, i32> {
        if self.fd.is_none() {
            let fd = socket_ioctl_fd()
                .map_err(|r| crate::log_debug_errno!(r, "ethtool: could not create control socket: ", strerror(r)))?;
            self.fd = Some(fd);
        }
        Ok(self.fd.as_ref().expect("connected").raw())
    }

    /// `ethtool_get_driver(&fd, ifname, &ret)`.
    pub fn get_driver(&mut self, ifname: &[u8]) -> Result<Vec<u8>, i32> {
        let fd = self.connect()?;
        // struct ethtool_drvinfo: cmd, then driver[32], ...
        let mut buf = vec![0u8; 196];
        buf[..4].copy_from_slice(&3u32.to_ne_bytes()); // ETHTOOL_GDRVINFO
        sys::siocethtool(fd, ifname, &mut buf)?;
        let driver = crate::bytes::c_str_prefix(&buf[4..36]).to_vec();
        if driver.is_empty() {
            return Err(-libc::ENODATA);
        }
        Ok(driver)
    }
}

pub const N_ADVERTISE: usize = 4;
pub const WAKE_MAGICSECURE: u32 = 1 << 6;
pub const SOPASS_MAX: usize = 6;
pub const ETH_TP_MDI_INVALID: u8 = 0;
pub const ETH_TP_MDI: u8 = 1;
pub const ETH_TP_MDI_X: u8 = 2;
pub const ETH_TP_MDI_AUTO: u8 = 3;
const AUTONEG_DISABLE: i32 = 0;
const AUTONEG_ENABLE: i32 = 1;
const ETH_GSTRING_LEN: usize = 32;
const ETH_SS_FEATURES: u32 = 4;
const ETHTOOL_GSET: u32 = 1;
const ETHTOOL_GWOL: u32 = 5;
const ETHTOOL_SWOL: u32 = 6;
const ETHTOOL_GCOALESCE: u32 = 14;
const ETHTOOL_SCOALESCE: u32 = 15;
const ETHTOOL_GRINGPARAM: u32 = 16;
const ETHTOOL_SRINGPARAM: u32 = 17;
const ETHTOOL_GPAUSEPARAM: u32 = 18;
const ETHTOOL_SPAUSEPARAM: u32 = 19;
const ETHTOOL_GSTRINGS: u32 = 27;
const ETHTOOL_GPERMADDR: u32 = 32;
const ETHTOOL_GSSET_INFO: u32 = 55;
const ETHTOOL_GFEATURES: u32 = 58;
const ETHTOOL_SFEATURES: u32 = 59;
const ETHTOOL_GCHANNELS: u32 = 60;
const ETHTOOL_SCHANNELS: u32 = 61;
const ETHTOOL_GEEE: u32 = 68;
const ETHTOOL_SEEE: u32 = 69;
const ETHTOOL_GLINKSETTINGS: u32 = 76;
const ETHTOOL_SLINKSETTINGS: u32 = 77;

/// `Duplex`: `DUPLEX_HALF`, `DUPLEX_FULL`.
pub const DUPLEX_TABLE: &[(&[u8], i32)] = &[(b"half", 0), (b"full", 1)];
/// `NetDevPort`: the ones `port_table` names.
pub const PORT_TABLE: &[(&[u8], i32)] = &[(b"tp", 0), (b"aui", 1), (b"mii", 2), (b"fibre", 3), (b"bnc", 4)];

/// `wol_option_map`.
pub const WOL_OPTIONS: &[(u32, &str)] = &[
    (1 << 0, "phy"),
    (1 << 1, "unicast"),
    (1 << 2, "multicast"),
    (1 << 3, "broadcast"),
    (1 << 4, "arp"),
    (1 << 5, "magic"),
    (1 << 6, "secureon"),
];

/// `wol_options_to_string_alloc()`: None for UINT32_MAX.
pub fn wol_options_to_string(opts: u32) -> Option<Vec<u8>> {
    if opts == u32::MAX {
        return None;
    }
    let names: Vec<&str> = WOL_OPTIONS.iter().filter(|(o, _)| opts & o != 0).map(|(_, n)| *n).collect();
    Some(if names.is_empty() { b"off".to_vec() } else { names.join(",").into_bytes() })
}

/// `netdev_feature_table`, in `NetDevFeature` order; the last one is
/// `NET_DEV_FEAT_TXCSUM`, a prefix.
pub const NETDEV_FEATURES: &[&str] = &[
    "tx-scatter-gather",
    "tx-checksum-ipv4",
    "tx-checksum-ip-generic",
    "tx-checksum-ipv6",
    "highdma",
    "tx-scatter-gather-fraglist",
    "tx-vlan-hw-insert",
    "rx-vlan-hw-parse",
    "rx-vlan-filter",
    "tx-vlan-stag-hw-insert",
    "rx-vlan-stag-hw-parse",
    "rx-vlan-stag-filter",
    "vlan-challenged",
    "tx-generic-segmentation",
    "tx-lockless",
    "netns-local",
    "rx-gro",
    "rx-gro-hw",
    "rx-lro",
    "tx-tcp-segmentation",
    "tx-gso-robust",
    "tx-tcp-ecn-segmentation",
    "tx-tcp-mangleid-segmentation",
    "tx-tcp6-segmentation",
    "tx-fcoe-segmentation",
    "tx-gre-segmentation",
    "tx-gre-csum-segmentation",
    "tx-ipxip4-segmentation",
    "tx-ipxip6-segmentation",
    "tx-udp_tnl-segmentation",
    "tx-udp_tnl-csum-segmentation",
    "tx-gso-partial",
    "tx-tunnel-remcsum-segmentation",
    "tx-sctp-segmentation",
    "tx-esp-segmentation",
    "tx-udp-segmentation",
    "tx-gso-list",
    "tx-checksum-fcoe-crc",
    "tx-checksum-sctp",
    "fcoe-mtu",
    "rx-ntuple-filter",
    "rx-hashing",
    "rx-checksum",
    "tx-nocache-copy",
    "loopback",
    "rx-fcs",
    "rx-all",
    "l2-fwd-offload",
    "hw-tc-offload",
    "esp-hw-offload",
    "esp-tx-csum-hw-offload",
    "rx-udp_tunnel-port-offload",
    "tls-hw-record",
    "tls-hw-tx-offload",
    "tls-hw-rx-offload",
    "rx-gro-list",
    "macsec-hw-offload",
    "rx-udp-gro-forwarding",
    "hsr-tag-ins-offload",
    "hsr-tag-rm-offload",
    "hsr-fwd-offload",
    "hsr-dup-offload",
    "tx-checksum-",
];
/// `_NET_DEV_FEAT_SIMPLE_MAX`.
pub const NET_DEV_FEAT_SIMPLE_MAX: usize = 62;
/// `_NET_DEV_FEAT_MAX`.
pub const NET_DEV_FEAT_MAX: usize = 63;
pub const NET_DEV_FEAT_SG: usize = 0;
pub const NET_DEV_FEAT_FRAGLIST: usize = 5;
pub const NET_DEV_FEAT_HW_VLAN_CTAG_TX: usize = 6;
pub const NET_DEV_FEAT_HW_VLAN_CTAG_RX: usize = 7;
pub const NET_DEV_FEAT_HW_VLAN_CTAG_FILTER: usize = 8;
pub const NET_DEV_FEAT_HW_VLAN_STAG_TX: usize = 9;
pub const NET_DEV_FEAT_GSO: usize = 13;
pub const NET_DEV_FEAT_GRO: usize = 16;
pub const NET_DEV_FEAT_GRO_HW: usize = 17;
pub const NET_DEV_FEAT_LRO: usize = 18;
pub const NET_DEV_FEAT_TSO: usize = 19;
pub const NET_DEV_FEAT_TSO_ECN: usize = 21;
pub const NET_DEV_FEAT_TSO_MANGLEID: usize = 22;
pub const NET_DEV_FEAT_TSO6: usize = 23;
pub const NET_DEV_FEAT_GSO_PARTIAL: usize = 31;
pub const NET_DEV_FEAT_NTUPLE: usize = 40;
pub const NET_DEV_FEAT_RXCSUM: usize = 42;
pub const NET_DEV_FEAT_RXFCS: usize = 45;
pub const NET_DEV_FEAT_RXALL: usize = 46;
pub const NET_DEV_FEAT_GRO_FRAGLIST: usize = 55;
pub const NET_DEV_FEAT_GRO_UDP_FWD: usize = 57;
pub const NET_DEV_FEAT_TXCSUM: usize = 62;

/// A `u32_opt`: a value of 0 with `set` means the hardware maximum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U32Opt {
    pub value: u32,
    pub set: bool,
}

/// `netdev_channels`: rx, tx, other, combined.
#[derive(Debug, Clone, Copy, Default)]
pub struct Channels {
    pub rx: U32Opt,
    pub tx: U32Opt,
    pub other: U32Opt,
    pub combined: U32Opt,
}

/// `netdev_ring_param`: rx, rx_mini, rx_jumbo, tx.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ring {
    pub rx: U32Opt,
    pub rx_mini: U32Opt,
    pub rx_jumbo: U32Opt,
    pub tx: U32Opt,
}

/// `netdev_coalesce_param`: the 22 fields of `struct ethtool_coalesce`
/// after `cmd`, in order (index 9 and 10 are the adaptive tristates).
#[derive(Debug, Clone, Copy)]
pub struct Coalesce {
    pub fields: [U32Opt; 22],
    pub use_adaptive_rx: i32,
    pub use_adaptive_tx: i32,
}

impl Default for Coalesce {
    fn default() -> Coalesce {
        Coalesce { fields: [U32Opt::default(); 22], use_adaptive_rx: -1, use_adaptive_tx: -1 }
    }
}

/// Indexes into [`Coalesce::fields`].
pub mod coalesce {
    pub const RX_USECS: usize = 0;
    pub const RX_MAX_FRAMES: usize = 1;
    pub const RX_USECS_IRQ: usize = 2;
    pub const RX_MAX_FRAMES_IRQ: usize = 3;
    pub const TX_USECS: usize = 4;
    pub const TX_MAX_FRAMES: usize = 5;
    pub const TX_USECS_IRQ: usize = 6;
    pub const TX_MAX_FRAMES_IRQ: usize = 7;
    pub const STATS_BLOCK_USECS: usize = 8;
    pub const PKT_RATE_LOW: usize = 11;
    pub const RX_USECS_LOW: usize = 12;
    pub const RX_MAX_FRAMES_LOW: usize = 13;
    pub const TX_USECS_LOW: usize = 14;
    pub const TX_MAX_FRAMES_LOW: usize = 15;
    pub const PKT_RATE_HIGH: usize = 16;
    pub const RX_USECS_HIGH: usize = 17;
    pub const RX_MAX_FRAMES_HIGH: usize = 18;
    pub const TX_USECS_HIGH: usize = 19;
    pub const TX_MAX_FRAMES_HIGH: usize = 20;
    pub const RATE_SAMPLE_INTERVAL: usize = 21;
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}

fn wr32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}

/// A command buffer of `size` bytes with `cmd` set.
fn cmdbuf(cmd: u32, size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size];
    wr32(&mut b, 0, cmd);
    b
}

/// `UPDATE(dest, val, updated)` on the u32 at `o`.
fn update(b: &mut [u8], o: usize, v: u32, changed: &mut bool) {
    if rd32(b, o) != v {
        *changed = true;
    }
    wr32(b, o, v);
}

/// `UPDATE_WITH_MAX(dest, max, val, updated)`.
fn update_with_max(b: &mut [u8], o: usize, max_o: usize, v: u32, changed: &mut bool) {
    let max = rd32(b, max_o);
    let v = if v == 0 || v > max { max } else { v };
    update(b, o, v, changed);
}

/// Link information: autonegotiation, speed (bits/s, UINT64_MAX if
/// unknown), duplex and port.
#[derive(Debug, Clone, Copy)]
pub struct LinkInfo {
    pub autonegotiation: i32,
    pub speed: u64,
    pub duplex: i32,
    pub port: i32,
}

impl Ethtool {
    fn ioctl(&mut self, ifname: &[u8], buf: &mut [u8]) -> Result<(), i32> {
        let fd = self.connect()?;
        sys::siocethtool(fd, ifname, buf)
    }

    /// `ethtool_get_link_info()`.
    pub fn get_link_info(&mut self, ifname: &[u8]) -> Result<LinkInfo, i32> {
        let mut b = cmdbuf(ETHTOOL_GSET, 44);
        self.ioctl(ifname, &mut b)?;
        let speed = u16::from_ne_bytes([b[12], b[13]]) as u32 | ((u16::from_ne_bytes([b[28], b[29]]) as u32) << 16);
        Ok(LinkInfo {
            autonegotiation: b[18] as i32,
            speed: if speed == u32::MAX { u64::MAX } else { speed as u64 * 1000 * 1000 },
            duplex: b[14] as i32,
            port: b[15] as i32,
        })
    }

    /// `ethtool_get_permanent_hw_addr()`.
    pub fn get_permanent_hw_addr(&mut self, ifname: &[u8]) -> Result<Vec<u8>, i32> {
        let max = crate::ether_addr::HW_ADDR_MAX_SIZE;
        let mut b = cmdbuf(ETHTOOL_GPERMADDR, 8 + max);
        wr32(&mut b, 4, max as u32);
        self.ioctl(ifname, &mut b)?;
        let size = rd32(&b, 4) as usize;
        if size == 0 {
            return Err(-libc::ENODATA);
        }
        if size > max {
            return Err(-libc::EINVAL);
        }
        Ok(b[8..8 + size].to_vec())
    }

    /// `ethtool_set_wol()`.
    pub fn set_wol(&mut self, ifname: &[u8], mut wolopts: u32, password: Option<&[u8; SOPASS_MAX]>) -> Result<(), i32> {
        if wolopts == u32::MAX && password.is_none() {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GWOL, 20);
        self.ioctl(ifname, &mut b)?;
        let supported = rd32(&b, 4);
        if wolopts == u32::MAX {
            wolopts = rd32(&b, 8);
            if password.is_some() && supported & WAKE_MAGICSECURE != 0 {
                wolopts |= WAKE_MAGICSECURE;
            }
        }
        if wolopts & !supported != 0 {
            let s = wol_options_to_string(wolopts & !supported);
            crate::log_debug!(
                "Network interface ",
                ifname,
                " does not support requested Wake on LAN options \"",
                s.as_deref().unwrap_or(b"n/a"),
                "\", ignoring."
            );
            wolopts &= supported;
        }
        let password = if wolopts & WAKE_MAGICSECURE == 0 { None } else { password };
        let mut changed = false;
        update(&mut b, 8, wolopts, &mut changed);
        if let Some(p) = password
            && b[12..18] != p[..]
        {
            b[12..18].copy_from_slice(p);
            changed = true;
        }
        let r = if changed {
            wr32(&mut b, 0, ETHTOOL_SWOL);
            self.ioctl(ifname, &mut b)
        } else {
            Ok(())
        };
        // CLEANUP_ERASE(ecmd)
        b.iter_mut().for_each(|x| *x = 0);
        r
    }

    /// `ethtool_set_nic_buffer_size()`.
    pub fn set_nic_buffer_size(&mut self, ifname: &[u8], ring: &Ring) -> Result<(), i32> {
        if !ring.rx.set && !ring.rx_mini.set && !ring.rx_jumbo.set && !ring.tx.set {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GRINGPARAM, 36);
        self.ioctl(ifname, &mut b)?;
        let mut changed = false;
        // rx_max_pending, rx_mini_max_pending, rx_jumbo_max_pending, tx_max_pending, then the pendings.
        for (i, o) in [ring.rx, ring.rx_mini, ring.rx_jumbo, ring.tx].iter().enumerate() {
            if o.set {
                update_with_max(&mut b, 20 + 4 * i, 4 + 4 * i, o.value, &mut changed);
            }
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut b, 0, ETHTOOL_SRINGPARAM);
        self.ioctl(ifname, &mut b)
    }

    /// `get_stringset(fd, ifname, ETH_SS_FEATURES, &strings)`.
    fn get_stringset_features(&mut self, ifname: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        let mut info = cmdbuf(ETHTOOL_GSSET_INFO, 16 + 4);
        info[8..16].copy_from_slice(&(1u64 << ETH_SS_FEATURES).to_ne_bytes());
        self.ioctl(ifname, &mut info)?;
        if u64::from_ne_bytes(info[8..16].try_into().expect("8 bytes")) == 0 {
            return Err(-libc::EOPNOTSUPP);
        }
        let len = rd32(&info, 16) as usize;
        if len == 0 {
            return Err(-libc::EOPNOTSUPP);
        }
        let mut s = cmdbuf(ETHTOOL_GSTRINGS, 12 + len * ETH_GSTRING_LEN);
        wr32(&mut s, 4, ETH_SS_FEATURES);
        wr32(&mut s, 8, len as u32);
        self.ioctl(ifname, &mut s)?;
        Ok((0..len).map(|i| s[12 + i * ETH_GSTRING_LEN..12 + (i + 1) * ETH_GSTRING_LEN].to_vec()).collect())
    }

    /// `ethtool_set_features()`.  `features` is indexed by `NetDevFeature`
    /// (-1: leave alone).
    pub fn set_features(&mut self, ifname: &[u8], features: &[i32; NET_DEV_FEAT_MAX]) -> Result<(), i32> {
        if !features.iter().any(|&f| f >= 0) {
            return Ok(());
        }
        self.connect()?;
        let strings = self
            .get_stringset_features(ifname)
            .map_err(|r| crate::log_debug_errno!(r, "ethtool: could not get ethtool feature strings: ", strerror(r)))?;
        let n = strings.len();
        let blocks = n.div_ceil(32);
        let mut g = cmdbuf(ETHTOOL_GFEATURES, 8 + blocks * 16);
        wr32(&mut g, 4, blocks as u32);
        self.ioctl(ifname, &mut g).map_err(|r| {
            crate::log_debug_errno!(r, "ethtool: could not get ethtool features for ", ifname, ": ", strerror(r))
        })?;
        let available = |blk: usize| rd32(&g, 8 + blk * 16);
        let never_changed = |blk: usize| rd32(&g, 8 + blk * 16 + 12);
        let mut sf = cmdbuf(ETHTOOL_SFEATURES, 8 + blocks * 8);
        wr32(&mut sf, 4, blocks as u32);
        let set = |sf: &mut Vec<u8>, i: usize, flag: i32| {
            let (block, mask) = (i / 32, 1u32 << (i % 32));
            let valid = rd32(sf, 8 + block * 8) | mask;
            wr32(sf, 8 + block * 8, valid);
            let req = rd32(sf, 8 + block * 8 + 4);
            wr32(sf, 8 + block * 8 + 4, if flag != 0 { req | mask } else { req & !mask });
        };
        let c_str = |s: &[u8]| s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())].to_vec();
        for (fi, name) in NETDEV_FEATURES.iter().enumerate().take(NET_DEV_FEAT_SIMPLE_MAX) {
            let flag = features[fi];
            if flag < 0 {
                continue;
            }
            // set_features_bit(): strneq(string, feature, ETH_GSTRING_LEN)
            let mut r = Err(-libc::ENODATA);
            for (i, s) in strings.iter().enumerate() {
                if c_str(s) != name.as_bytes() {
                    continue;
                }
                let (block, mask) = (i / 32, 1u32 << (i % 32));
                r = if available(block) & mask == 0 || never_changed(block) & mask != 0 {
                    Err(-libc::EOPNOTSUPP)
                } else {
                    set(&mut sf, i, flag);
                    Ok(())
                };
                break;
            }
            if let Err(e) = r {
                crate::log_debug_errno!(
                    e,
                    "ethtool: could not set feature ",
                    *name,
                    " for ",
                    ifname,
                    ", ignoring: ",
                    strerror(e)
                );
            }
        }
        for (fi, name) in NETDEV_FEATURES.iter().enumerate().skip(NET_DEV_FEAT_SIMPLE_MAX) {
            let flag = features[fi];
            if flag < 0 {
                continue;
            }
            // set_features_multiple_bit()
            let (mut found, mut r) = (false, -libc::ENODATA);
            for (i, s) in strings.iter().enumerate() {
                if !c_str(s).starts_with(name.as_bytes()) {
                    continue;
                }
                let (block, mask) = (i / 32, 1u32 << (i % 32));
                if available(block) & mask == 0 || never_changed(block) & mask != 0 {
                    r = -libc::EOPNOTSUPP;
                    continue;
                }
                if rd32(&sf, 8 + block * 8) & mask != 0 {
                    continue;
                }
                set(&mut sf, i, flag);
                found = true;
            }
            if !found {
                crate::log_debug_errno!(
                    r,
                    "ethtool: could not set feature ",
                    *name,
                    " for ",
                    ifname,
                    ", ignoring: ",
                    strerror(r)
                );
            }
        }
        self.ioctl(ifname, &mut sf)
            .map_err(|r| crate::log_debug_errno!(r, "ethtool: could not set ethtool features for ", ifname))
    }

    /// `get_link_settings()`.
    fn get_link_settings(&mut self, ifname: &[u8]) -> Result<Vec<u8>, i32> {
        let mut e = cmdbuf(ETHTOOL_GLINKSETTINGS, 48);
        self.ioctl(ifname, &mut e)?;
        let nwords = e[15] as i8;
        if nwords >= 0 || rd32(&e, 0) != ETHTOOL_GLINKSETTINGS {
            return Err(-libc::EOPNOTSUPP);
        }
        let n = nwords.wrapping_neg();
        let mut s = cmdbuf(ETHTOOL_GLINKSETTINGS, 48 + 4 * n as u8 as usize * 3);
        s[15] = n as u8;
        self.ioctl(ifname, &mut s)?;
        if s[15] as i8 != n || rd32(&s, 0) != ETHTOOL_GLINKSETTINGS {
            return Err(-libc::EOPNOTSUPP);
        }
        Ok(s)
    }

    /// `ethtool_set_link_settings()`.  `duplex` and `port` are negative
    /// when unset.
    #[allow(clippy::too_many_arguments)]
    pub fn set_link_settings(
        &mut self,
        ifname: &[u8],
        mut autonegotiation: i32,
        advertise: &[u32; N_ADVERTISE],
        mut speed: u64,
        mut duplex: i32,
        mut port: i32,
        mdi: u8,
    ) -> Result<(), i32> {
        let adv_zero = advertise.iter().all(|&a| a == 0);
        if autonegotiation < 0 && adv_zero && speed == 0 && duplex < 0 && port < 0 && mdi == ETH_TP_MDI_INVALID {
            return Ok(());
        }
        if speed > 0 || duplex >= 0 || port >= 0 {
            if autonegotiation == AUTONEG_ENABLE || !adv_zero {
                crate::log_debug!("ethtool: autonegotiation is enabled, ignoring speed, duplex, or port settings.");
                speed = 0;
                duplex = -1;
                port = -1;
            } else {
                crate::log_debug!("ethtool: setting speed, duplex, or port, disabling autonegotiation.");
                autonegotiation = AUTONEG_DISABLE;
            }
        }
        self.connect()?;
        let mut s = self.get_link_settings(ifname).map_err(|r| {
            crate::log_debug_errno!(r, "ethtool: Cannot get link settings for ", ifname, ": ", strerror(r))
        })?;
        let mut changed = false;
        let upd8 = |s: &mut Vec<u8>, o: usize, v: u8, changed: &mut bool| {
            if s[o] != v {
                *changed = true;
            }
            s[o] = v;
        };
        if speed > 0 {
            // UPDATE() compares at the value's width, then stores the u32.
            let v = speed.div_ceil(1_000_000);
            if rd32(&s, 4) as u64 != v {
                changed = true;
            }
            wr32(&mut s, 4, v as u32);
        }
        if duplex >= 0 {
            upd8(&mut s, 8, duplex as u8, &mut changed);
        }
        if port >= 0 {
            upd8(&mut s, 9, port as u8, &mut changed);
        }
        if autonegotiation >= 0 {
            upd8(&mut s, 11, autonegotiation as u8, &mut changed);
        }
        if !adv_zero {
            upd8(&mut s, 11, AUTONEG_ENABLE as u8, &mut changed);
            let nwords = s[15] as usize;
            let base = 48 + 4 * nwords;
            let n = nwords.min(N_ADVERTISE);
            let differs = (0..n).any(|i| rd32(&s, base + 4 * i) != advertise[i])
                || (n..nwords).any(|i| rd32(&s, base + 4 * i) != 0);
            changed = changed || differs;
            for (i, a) in advertise.iter().enumerate().take(n) {
                wr32(&mut s, base + 4 * i, *a);
            }
            for i in n..nwords {
                wr32(&mut s, base + 4 * i, 0);
            }
        }
        if mdi != ETH_TP_MDI_INVALID {
            if s[14] == ETH_TP_MDI_INVALID {
                crate::log_debug!("ethtool: setting MDI not supported for ", ifname, ", ignoring.");
            } else {
                upd8(&mut s, 14, mdi, &mut changed);
            }
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut s, 0, ETHTOOL_SLINKSETTINGS);
        self.ioctl(ifname, &mut s).map_err(|r| {
            crate::log_debug_errno!(r, "ethtool: Cannot set link settings for ", ifname, ": ", strerror(r))
        })
    }

    /// `ethtool_set_channels()`.
    pub fn set_channels(&mut self, ifname: &[u8], ch: &Channels) -> Result<(), i32> {
        if !ch.rx.set && !ch.tx.set && !ch.other.set && !ch.combined.set {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GCHANNELS, 36);
        self.ioctl(ifname, &mut b)?;
        let mut changed = false;
        for (i, o) in [ch.rx, ch.tx, ch.other, ch.combined].iter().enumerate() {
            if o.set {
                update_with_max(&mut b, 20 + 4 * i, 4 + 4 * i, o.value, &mut changed);
            }
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut b, 0, ETHTOOL_SCHANNELS);
        self.ioctl(ifname, &mut b)
    }

    /// `ethtool_set_flow_control()`.
    pub fn set_flow_control(&mut self, ifname: &[u8], rx: i32, tx: i32, autoneg: i32) -> Result<(), i32> {
        if rx < 0 && tx < 0 && autoneg < 0 {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GPAUSEPARAM, 16);
        self.ioctl(ifname, &mut b)?;
        let mut changed = false;
        if rx >= 0 {
            update(&mut b, 8, rx as u32, &mut changed);
        }
        if tx >= 0 {
            update(&mut b, 12, tx as u32, &mut changed);
        }
        if autoneg >= 0 {
            update(&mut b, 4, autoneg as u32, &mut changed);
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut b, 0, ETHTOOL_SPAUSEPARAM);
        self.ioctl(ifname, &mut b)
    }

    /// `ethtool_set_nic_coalesce_settings()`.
    pub fn set_nic_coalesce_settings(&mut self, ifname: &[u8], c: &Coalesce) -> Result<(), i32> {
        if c.use_adaptive_rx < 0 && c.use_adaptive_tx < 0 && !c.fields.iter().any(|f| f.set) {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GCOALESCE, 92);
        self.ioctl(ifname, &mut b)?;
        let mut changed = false;
        let off = |i: usize| 4 + 4 * i;
        if c.use_adaptive_rx >= 0 {
            update(&mut b, off(9), c.use_adaptive_rx as u32, &mut changed);
        }
        if c.use_adaptive_tx >= 0 {
            update(&mut b, off(10), c.use_adaptive_tx as u32, &mut changed);
        }
        for (i, f) in c.fields.iter().enumerate() {
            if i == 9 || i == 10 || !f.set {
                continue;
            }
            let v = if i == coalesce::RATE_SAMPLE_INTERVAL { f.value.div_ceil(1_000_000) } else { f.value };
            update(&mut b, off(i), v, &mut changed);
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut b, 0, ETHTOOL_SCOALESCE);
        self.ioctl(ifname, &mut b)
    }

    /// `ethtool_set_eee_settings()`.
    pub fn set_eee_settings(
        &mut self,
        ifname: &[u8],
        enabled: i32,
        tx_lpi_enabled: i32,
        tx_lpi_timer_usec: u64,
        advertise: u32,
    ) -> Result<(), i32> {
        if enabled < 0 && tx_lpi_enabled < 0 && tx_lpi_timer_usec == u64::MAX && advertise == 0 {
            return Ok(());
        }
        let mut b = cmdbuf(ETHTOOL_GEEE, 40);
        self.ioctl(ifname, &mut b)?;
        let supported = rd32(&b, 4);
        if supported == 0 {
            return Ok(());
        }
        let mut changed = false;
        if enabled >= 0 {
            update(&mut b, 20, enabled as u32, &mut changed);
        }
        if tx_lpi_enabled >= 0 {
            update(&mut b, 24, tx_lpi_enabled as u32, &mut changed);
        }
        if tx_lpi_timer_usec != u64::MAX {
            update(&mut b, 28, tx_lpi_timer_usec.div_ceil(1000).min(u32::MAX as u64) as u32, &mut changed);
        }
        if advertise != 0 {
            update(&mut b, 8, advertise & supported, &mut changed);
        }
        if !changed {
            return Ok(());
        }
        wr32(&mut b, 0, ETHTOOL_SEEE);
        self.ioctl(ifname, &mut b)
    }
}
