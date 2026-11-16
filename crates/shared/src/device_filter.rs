// SPDX-License-Identifier: LGPL-2.1-or-later
//! `device-filter.c`: the sysattr and parent matches shared by the
//! enumerator and the monitor.

use std::collections::BTreeSet;

use crate::path::path_startswith;
use crate::sd_device::Device;
use crate::sys::fnmatch;

/// A `Hashmap` of key → patterns, in insertion order (the order doesn't
/// change any result).
pub type MatchStrv = Vec<(Vec<u8>, Vec<Vec<u8>>)>;

/// `update_match_strv()`: Ok(true) if something changed.
pub fn update_match_strv(m: &mut MatchStrv, key: &[u8], value: Option<&[u8]>, clear_on_null: bool) -> bool {
    if let Some((_, strv)) = m.iter_mut().find(|(k, _)| k == key) {
        match value {
            None => {
                if strv.is_empty() || !clear_on_null {
                    return false;
                }
                // Accept any value: clear what was there.
                strv.clear();
            }
            Some(v) => {
                if strv.iter().any(|s| s == v) {
                    return false;
                }
                strv.push(v.to_vec());
            }
        }
    } else {
        m.push((key.to_vec(), value.map(|v| vec![v.to_vec()]).unwrap_or_default()));
    }
    true
}

/// `strv_fnmatch(patterns, s)`.
pub fn strv_fnmatch(patterns: &[Vec<u8>], s: &[u8]) -> bool {
    patterns.iter().any(|p| fnmatch(p, s, 0) == 0)
}

/// `strv_fnmatch_or_empty(patterns, s, 0)`.
pub fn strv_fnmatch_or_empty(patterns: &[Vec<u8>], s: &[u8]) -> bool {
    patterns.is_empty() || strv_fnmatch(patterns, s)
}

/// `set_fnmatch(include, exclude, needle)`.
pub fn set_fnmatch(include: &BTreeSet<Vec<u8>>, exclude: &BTreeSet<Vec<u8>>, needle: &[u8]) -> bool {
    if exclude.iter().any(|p| fnmatch(p, needle, 0) == 0) {
        return false;
    }
    if include.is_empty() {
        return true;
    }
    include.iter().any(|p| fnmatch(p, needle, 0) == 0)
}

/// `device_match_sysattr_value()`.
fn device_match_sysattr_value(device: &Device, sysattr: &[u8], patterns: &[Vec<u8>]) -> bool {
    match device.get_sysattr_value(sysattr) {
        Err(_) => false,
        Ok(v) => strv_fnmatch_or_empty(patterns, v.bytes()),
    }
}

/// `device_match_sysattr()`.
pub fn device_match_sysattr(device: &Device, match_sysattr: &MatchStrv, nomatch_sysattr: &MatchStrv) -> bool {
    for (sysattr, patterns) in match_sysattr {
        if !device_match_sysattr_value(device, sysattr, patterns) {
            return false;
        }
    }
    for (sysattr, patterns) in nomatch_sysattr {
        if device_match_sysattr_value(device, sysattr, patterns) {
            return false;
        }
    }
    true
}

/// `device_match_parent()`.
pub fn device_match_parent(
    device: &Device,
    match_parent: Option<&BTreeSet<Vec<u8>>>,
    nomatch_parent: Option<&BTreeSet<Vec<u8>>>,
) -> bool {
    let syspath = device.get_syspath();
    if let Some(n) = nomatch_parent
        && n.iter().any(|p| path_startswith(syspath.bytes(), p).is_some())
    {
        return false;
    }
    match match_parent {
        None => true,
        Some(m) if m.is_empty() => true,
        Some(m) => m.iter().any(|p| path_startswith(syspath.bytes(), p).is_some()),
    }
}
