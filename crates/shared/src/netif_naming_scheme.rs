// SPDX-License-Identifier: LGPL-2.1-or-later
//! `netif-naming-scheme.c`: the network interface naming schemes, and the
//! sysattr reads that `ID_NET_NAME_ALLOW*` properties can turn off.

use std::sync::OnceLock;

use crate::sd_device::Device;
use crate::{log_info, log_warning};

pub const NAMING_SR_IOV_V: u32 = 1 << 0;
pub const NAMING_NPAR_ARI: u32 = 1 << 1;
pub const NAMING_INFINIBAND: u32 = 1 << 2;
pub const NAMING_ZERO_ACPI_INDEX: u32 = 1 << 3;
pub const NAMING_ALLOW_RERENAMES: u32 = 1 << 4;
pub const NAMING_STABLE_VIRTUAL_MACS: u32 = 1 << 5;
pub const NAMING_NETDEVSIM: u32 = 1 << 6;
pub const NAMING_LABEL_NOPREFIX: u32 = 1 << 7;
pub const NAMING_NSPAWN_LONG_HASH: u32 = 1 << 8;
pub const NAMING_BRIDGE_NO_SLOT: u32 = 1 << 9;
pub const NAMING_SLOT_FUNCTION_ID: u32 = 1 << 10;
pub const NAMING_16BIT_INDEX: u32 = 1 << 11;
pub const NAMING_REPLACE_STRICTLY: u32 = 1 << 12;
pub const NAMING_XEN_VIF: u32 = 1 << 13;
pub const NAMING_BRIDGE_MULTIFUNCTION_SLOT: u32 = 1 << 14;
pub const NAMING_DEVICETREE_ALIASES: u32 = 1 << 15;
pub const NAMING_USB_HOST: u32 = 1 << 16;
pub const NAMING_SR_IOV_R: u32 = 1 << 17;
pub const NAMING_FIRMWARE_NODE_SUN: u32 = 1 << 18;
pub const NAMING_DEVICETREE_PORT_ALIASES: u32 = 1 << 19;
pub const NAMING_USE_INTERFACE_PROPERTY: u32 = 1 << 20;
pub const NAMING_DEVICETREE_ALIASES_WLAN: u32 = 1 << 21;
pub const NAMING_MCTP: u32 = 1 << 22;
pub const NAMING_SUBFUNC: u32 = 1 << 23;

const V238: u32 = 0;
const V239: u32 = V238 | NAMING_SR_IOV_V | NAMING_NPAR_ARI;
const V240: u32 = V239 | NAMING_INFINIBAND | NAMING_ZERO_ACPI_INDEX | NAMING_ALLOW_RERENAMES;
const V241: u32 = V240 | NAMING_STABLE_VIRTUAL_MACS;
const V243: u32 = V241 | NAMING_NETDEVSIM | NAMING_LABEL_NOPREFIX;
const V245: u32 = V243 | NAMING_NSPAWN_LONG_HASH;
const V247: u32 = V245 | NAMING_BRIDGE_NO_SLOT;
const V249: u32 = V247 | NAMING_SLOT_FUNCTION_ID | NAMING_16BIT_INDEX | NAMING_REPLACE_STRICTLY;
const V250: u32 = V249 | NAMING_XEN_VIF;
const V251: u32 = V250 | NAMING_BRIDGE_MULTIFUNCTION_SLOT;
const V252: u32 = V251 | NAMING_DEVICETREE_ALIASES;
const V253: u32 = V252 | NAMING_USB_HOST;
const V254: u32 = V253 | NAMING_SR_IOV_R;
const V255: u32 = V254 & !NAMING_BRIDGE_MULTIFUNCTION_SLOT;
const V257: u32 = V255 | NAMING_FIRMWARE_NODE_SUN | NAMING_DEVICETREE_PORT_ALIASES;
const V258: u32 = V257 | NAMING_USE_INTERFACE_PROPERTY;
const V259: u32 = V258 | NAMING_DEVICETREE_ALIASES_WLAN;
const V260: u32 = V259 | NAMING_MCTP;
const V261: u32 = V260 | NAMING_SUBFUNC;

/// A `NamingScheme`.
#[derive(Debug, PartialEq, Eq)]
pub struct NamingScheme {
    pub name: &'static str,
    pub flags: u32,
}

static SCHEMES: &[NamingScheme] = &[
    NamingScheme { name: "v238", flags: V238 },
    NamingScheme { name: "v239", flags: V239 },
    NamingScheme { name: "v240", flags: V240 },
    NamingScheme { name: "v241", flags: V241 },
    NamingScheme { name: "v243", flags: V243 },
    NamingScheme { name: "v245", flags: V245 },
    NamingScheme { name: "v247", flags: V247 },
    NamingScheme { name: "v249", flags: V249 },
    NamingScheme { name: "v250", flags: V250 },
    NamingScheme { name: "v251", flags: V251 },
    NamingScheme { name: "v252", flags: V252 },
    NamingScheme { name: "v253", flags: V253 },
    NamingScheme { name: "v254", flags: V254 },
    NamingScheme { name: "v255", flags: V255 },
    NamingScheme { name: "v257", flags: V257 },
    NamingScheme { name: "v258", flags: V258 },
    NamingScheme { name: "v259", flags: V259 },
    NamingScheme { name: "v260", flags: V260 },
    NamingScheme { name: "v261", flags: V261 },
];

/// `DEFAULT_NET_NAMING_SCHEME`.
const DEFAULT_NET_NAMING_SCHEME: &[u8] = b"latest";

/// `naming_scheme_from_name()`.
pub fn naming_scheme_from_name(name: &[u8]) -> Option<&'static NamingScheme> {
    if let Some(s) = SCHEMES.iter().find(|s| s.name.as_bytes() == name) {
        return Some(s);
    }
    (name == b"latest").then(|| SCHEMES.last().expect("not empty"))
}

static CACHE: OnceLock<&'static NamingScheme> = OnceLock::new();

/// `naming_scheme()`: chosen, and logged, on first use.
pub fn naming_scheme() -> &'static NamingScheme {
    CACHE.get_or_init(|| {
        let buffer = crate::proc_cmdline::proc_cmdline_get_key(b"net.naming_scheme", false).ok().flatten().flatten();
        let k = match crate::sys::getenv("NET_NAMING_SCHEME") {
            Some(e) => match e.strip_prefix(b":") {
                Some(rest) => Some(buffer.unwrap_or_else(|| rest.to_vec())),
                None => Some(e),
            },
            None => buffer,
        };
        if let Some(k) = k {
            if let Some(s) = naming_scheme_from_name(&k) {
                log_info!("Using interface naming scheme '", s.name, "'.");
                return s;
            }
            log_warning!("Unknown interface naming scheme '", &k[..], "' requested, ignoring.");
        }
        let s = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME).expect("default scheme exists");
        log_info!("Using default interface naming scheme '", s.name, "'.");
        s
    })
}

/// `naming_scheme_has(flags)`.
pub fn naming_scheme_has(flags: u32) -> bool {
    naming_scheme().flags & flags == flags
}

/// `naming_sysattr_allowed()`.
fn naming_sysattr_allowed(dev: &Device, sysattr: &[u8]) -> Result<bool, i32> {
    let prop = crate::bcat!("ID_NET_NAME_ALLOW_", sysattr).to_ascii_uppercase();
    match dev.get_property_bool(&prop) {
        Err(r) if r == -libc::ENOENT => match dev.get_property_bool(b"ID_NET_NAME_ALLOW") {
            Err(r) if r == -libc::ENOENT => Ok(true),
            r => r,
        },
        r => r,
    }
}

fn allowed(dev: &Device, sysattr: &[u8]) -> Result<(), i32> {
    if naming_sysattr_allowed(dev, sysattr)? { Ok(()) } else { Err(-libc::ENOENT) }
}

/// `device_get_sysattr_int_filtered()`.
pub fn get_sysattr_int_filtered(dev: &Device, sysattr: &[u8]) -> Result<i32, i32> {
    allowed(dev, sysattr)?;
    dev.get_sysattr_int(sysattr)
}

/// `device_get_sysattr_unsigned_filtered()`.
pub fn get_sysattr_unsigned_filtered(dev: &Device, sysattr: &[u8]) -> Result<u32, i32> {
    allowed(dev, sysattr)?;
    dev.get_sysattr_unsigned_full(sysattr, 0)
}

/// `device_get_sysattr_bool_filtered()`.
pub fn get_sysattr_bool_filtered(dev: &Device, sysattr: &[u8]) -> Result<bool, i32> {
    allowed(dev, sysattr)?;
    dev.get_sysattr_bool(sysattr)
}

/// `device_get_sysattr_safe_string_filtered()`.
pub fn get_sysattr_safe_string_filtered(dev: &Device, sysattr: &[u8]) -> Result<Vec<u8>, i32> {
    allowed(dev, sysattr)?;
    dev.get_sysattr_safe_string(sysattr).map(|v| v.bytes().to_vec())
}
