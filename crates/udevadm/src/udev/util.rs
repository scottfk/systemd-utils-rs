// SPDX-License-Identifier: GPL-2.0-or-later
//! The parts of `udev-util.c` the engine uses.

use shared::conf_parser::{CONFIG_PARSE_WARN, config_parse_log_level, config_parse_standard_file_with_dropins};
use shared::log_device_debug;
use shared::sd_device::{Action, DStr, Device, device_action_to_string};
use shared::string::WHITESPACE;

/// `udev_parse_config()`: `udev_log=` of `udev.conf` sets the log level.
pub fn udev_parse_config() -> i32 {
    let mut log_val = -1;
    let mut lookup = |file: &[u8], line: u32, section: Option<&[u8]>, lvalue: &[u8], rvalue: &[u8]| -> Option<i32> {
        if section.is_some() {
            return None;
        }
        match lvalue {
            b"udev_log" => Some(config_parse_log_level(file, line, lvalue, rvalue, &mut log_val)),
            b"children_max" | b"exec_delay" | b"event_timeout" | b"resolve_names" | b"timeout_signal" => Some(0),
            _ => None,
        }
    };
    let r = config_parse_standard_file_with_dropins("udev/udev.conf", CONFIG_PARSE_WARN, &mut lookup);
    if r == -libc::ENOENT {
        return 0;
    }
    if r < 0 {
        return r;
    }
    if log_val >= 0 {
        shared::log::log_set_max_level(log_val);
    }
    0
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `udev_replace_whitespace(str, to, len)`: what it leaves in `to`.
pub fn udev_replace_whitespace(s: &[u8], len: usize) -> Vec<u8> {
    let s = &s[..s.len().min(len)];
    let mut i = s.iter().take_while(|c| WHITESPACE.contains(c)).count();
    let mut to = Vec::new();
    let mut is_space = false;
    while to.len() < len && i < len && i < s.len() && s[i] != 0 {
        if isspace(s[i]) {
            is_space = true;
            i += 1;
            continue;
        }
        if is_space {
            if to.len() + 1 >= len {
                break;
            }
            to.push(b'_');
            is_space = false;
        }
        to.push(s[i]);
        i += 1;
    }
    to
}

/// `allow_listed_char_for_devnode(c, additional)`.
fn allow_listed_char_for_devnode(c: u8, additional: Option<&[u8]>) -> bool {
    c.is_ascii_digit()
        || c.is_ascii_alphabetic()
        || b"#+-.:=@_".contains(&c)
        || additional.is_some_and(|a| a.contains(&c))
}

/// `udev_replace_chars(str, allow)`: the number of characters replaced.
pub fn udev_replace_chars(s: &mut [u8], allow: Option<&[u8]>) -> usize {
    let mut i = 0;
    let mut replaced = 0;
    while i < s.len() && s[i] != 0 {
        if allow_listed_char_for_devnode(s[i], allow) {
            i += 1;
            continue;
        }
        if s[i] == b'\\' && s.get(i + 1) == Some(&b'x') {
            i += 2;
            continue;
        }
        if let Some(len) = shared::utf8::encoded_valid_unichar(&s[i..])
            && len > 1
        {
            i += len;
            continue;
        }
        if isspace(s[i]) && allow.is_some_and(|a| a.contains(&b' ')) {
            s[i] = b' ';
            i += 1;
            replaced += 1;
            continue;
        }
        s[i] = b'_';
        i += 1;
        replaced += 1;
    }
    replaced
}

/// `device_for_action(dev, a)`.
pub fn device_for_action(dev: &Device, a: Action) -> bool {
    dev.get_action().is_ok_and(|b| a == b)
}

/// `log_device_uevent(device, str)`.
pub fn log_device_uevent(dev: &Device, s: &[u8]) {
    if !shared::log::debug_logging() {
        return;
    }
    let seqnum = dev.get_seqnum().unwrap_or(0);
    let action = dev.get_action().ok().map(device_action_to_string);
    let uuid = dev.get_trigger_uuid().ok();
    log_device_debug!(
        dev,
        s,
        if s.is_empty() { "" } else { " " },
        "(SEQNUM=",
        seqnum.to_string(),
        ", ACTION=",
        action.unwrap_or("n/a"),
        if uuid.is_some() { ", UUID=" } else { "" },
        uuid.unwrap_or_default(),
        ")"
    );
}

/// `device_get_property_value_with_fallback(device, prop, extra_props)`.
pub fn device_get_property_value_with_fallback(
    dev: &Device,
    prop: &[u8],
    extra: Option<&[(Vec<u8>, Vec<u8>)]>,
) -> Result<Vec<u8>, i32> {
    match dev.get_property_value(prop) {
        Ok(v) => Ok(v.bytes().to_vec()),
        Err(r) if r != -libc::ENOENT => Err(r),
        Err(_) => extra.and_then(|e| e.iter().find(|(k, _)| k == prop)).map(|(_, v)| v.clone()).ok_or(-libc::ENOENT),
    }
}

/// The `DStr` of a successful device getter, as bytes.
pub fn bytes(d: &DStr) -> Vec<u8> {
    d.bytes().to_vec()
}
