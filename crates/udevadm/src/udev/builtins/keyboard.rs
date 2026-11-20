// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-keyboard.c`: scan code remapping, EV_ABS overrides and
//! pointing stick sensitivity, from the hwdb's properties.

use shared::errno::{strerror, synthetic};
use shared::sd_device::Device;
use shared::sys::{self, OwnedFd};
use shared::{log_device_debug, log_device_error_errno, log_device_warning, log_device_warning_errno};

use super::super::def::EventMode;
use super::super::event::Event;
use super::keyboard_keys::KEYS;

/// `EVIOCSKEYCODE`: `_IOW('E', 0x04, unsigned int[2])`.
const EVIOCSKEYCODE: u64 = 0x4008_4504;
/// `EVIOCGABS(0)`.
const EVIOCGABS: u64 = 0x8018_4540;
/// `EVIOCSABS(0)`.
const EVIOCSABS: u64 = 0x4018_45c0;
const EV_ABS: usize = 3;

/// `install_force_release()`.
fn install_force_release(dev: &Device, release: &[u32]) -> Result<(), i32> {
    let atkbd = dev
        .get_parent_with_subsystem_devtype(b"serio", None)
        .map_err(|r| log_device_error_errno!(dev, r, "Failed to get serio parent: ", strerror(r)))?;
    let cur = atkbd
        .get_sysattr_safe_string(b"force_release")
        .map_err(|r| log_device_error_errno!(atkbd, r, "Failed to get force-release attribute: ", strerror(r)))?;
    let mut codes = cur.bytes().to_vec();
    for r in release {
        codes.extend_from_slice(format!(",{r}").as_bytes());
    }
    // strpcpy() into a 4096-byte buffer.
    codes.truncate(4095);
    log_device_debug!(atkbd, "keyboard: updating force-release list with '", &codes[..], "'");
    atkbd
        .set_sysattr_value(b"force_release", Some(&codes))
        .map_err(|r| log_device_error_errno!(atkbd, r, "Failed to set force-release attribute: ", strerror(r)))
}

/// `map_keycode()`.
fn map_keycode(dev: &Device, fd: i32, scancode: u32, keycode: &[u8]) -> Result<(), i32> {
    let key = match KEYS.iter().find(|(n, _)| *n == keycode) {
        Some((_, id)) => *id as u32,
        None => shared::parse::safe_atou(keycode).map_err(|r| {
            log_device_error_errno!(dev, r, "Failed to parse key identifier '", keycode, "': ", strerror(r))
        })?,
    };
    log_device_debug!(
        dev,
        "keyboard: mapping scan code ",
        format!("{scancode} (0x{scancode:x}) to key code {key} (0x{key:x})")
    );
    let mut map = [scancode, key];
    sys::ioctl_ptr(fd, EVIOCSKEYCODE, &mut map).map_err(|r| {
        log_device_error_errno!(
            dev,
            r,
            format!("Failed to call EVIOCSKEYCODE with scan code 0x{scancode:x}, and key code {key}: "),
            strerror(r)
        )
    })?;
    Ok(())
}

/// `parse_token()`: the rest after the token, None if it is malformed.
fn parse_token<'a>(current: Option<&'a [u8]>, val: &mut i32) -> Option<&'a [u8]> {
    let current = current?;
    let (v, consumed, _) = sys::strtol(current, 0);
    let next = &current[consumed..];
    if !next.is_empty() && next[0] != b':' {
        return None;
    }
    if consumed != 0 {
        *val = v as i32;
    }
    Some(if next.is_empty() { next } else { &next[1..] })
}

/// `override_abs()`.
fn override_abs(dev: &Device, fd: i32, evcode: u32, value: &[u8]) -> Result<(), i32> {
    // struct input_absinfo: value, minimum, maximum, fuzz, flat, resolution.
    let mut a = [0i32; 6];
    sys::ioctl_ptr(fd, EVIOCGABS + evcode as u64, &mut a)
        .map_err(|r| log_device_error_errno!(dev, r, "Failed to call EVIOCGABS"))?;
    let (mut min, mut max, mut fuzz, mut flat, mut res) = (a[1], a[2], a[3], a[4], a[5]);
    let next = parse_token(Some(value), &mut min);
    let next = parse_token(next, &mut max);
    let next = parse_token(next, &mut res);
    let next = parse_token(next, &mut fuzz);
    let next = parse_token(next, &mut flat);
    if next.is_none() {
        return Err(log_device_error_errno!(
            dev,
            synthetic(libc::EINVAL),
            "Failed to parse EV_ABS override '",
            value,
            "'"
        ));
    }
    (a[1], a[2], a[3], a[4], a[5]) = (min, max, fuzz, flat, res);
    log_device_debug!(dev, format!("keyboard: {evcode:x} overridden with {min}/{max}/{res}/{fuzz}/{flat}"));
    sys::ioctl_ptr(fd, EVIOCSABS + evcode as u64, &mut a)
        .map_err(|r| log_device_error_errno!(dev, r, "Failed to call EVIOCSABS"))?;
    Ok(())
}

/// `set_trackpoint_sensitivity()`.
fn set_trackpoint_sensitivity(dev: &Device, value: &[u8]) -> Result<(), i32> {
    let pdev = dev
        .get_parent_with_subsystem_devtype(b"serio", None)
        .map_err(|r| log_device_error_errno!(dev, r, "Failed to get serio parent: ", strerror(r)))?;
    let v = shared::parse::safe_atoi(value).map_err(|r| {
        log_device_error_errno!(dev, r, "Failed to parse POINTINGSTICK_SENSITIVITY '", value, "': ", strerror(r))
    })?;
    if !(0..=255).contains(&v) {
        return Err(log_device_error_errno!(
            dev,
            synthetic(libc::ERANGE),
            "POINTINGSTICK_SENSITIVITY ",
            v.to_string(),
            " outside range [0..255]"
        ));
    }
    pdev.set_sysattr_value(b"sensitivity", Some(v.to_string().as_bytes()))
        .map_err(|r| log_device_error_errno!(dev, r, "Failed to write 'sensitivity' attribute: ", strerror(r)))
}

/// Opens the device for the first change; Err(r) to return r (0 to
/// return success).
fn open_once(dev: &Device, node: &[u8], fd: &mut Option<OwnedFd>) -> Result<i32, i32> {
    if let Some(f) = fd {
        return Ok(f.raw());
    }
    match shared::blockdev::sd_device_open(dev, libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) {
        Ok(f) => {
            let raw = f.raw();
            *fd = Some(f);
            Ok(raw)
        }
        Err(r) => {
            let ignore = shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM;
            shared::sd_device::log_device_full(
                Some(dev),
                if ignore { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                r,
                shared::bcat!(
                    "Failed to open device '",
                    node,
                    "'",
                    if ignore { ", ignoring" } else { "" },
                    ": ",
                    strerror(r)
                ),
            );
            Err(if ignore { 0 } else { r })
        }
    }
}

/// `builtin_keyboard()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if event.event_mode != EventMode::UdevWorker {
        log_device_debug!(dev, "Running in test mode, skipping execution of 'keyboard' builtin command.");
        return Ok(());
    }
    let node = match dev.get_devname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get device name: ", strerror(r))),
    };
    let mut release: Vec<u32> = Vec::new();
    let mut fd: Option<OwnedFd> = None;
    let mut has_abs: Option<bool> = None;
    let bail = |r: i32| if r == 0 { Ok(()) } else { Err(r) };
    for (k, v) in dev.properties() {
        let (key, value) = (k.bytes(), v.bytes());
        if let Some(code) = key.strip_prefix(b"KEYBOARD_KEY_") {
            let scancode = match shared::parse::safe_atou_full(code, 16) {
                Ok(s) => s,
                Err(r) => {
                    log_device_warning_errno!(
                        dev,
                        r,
                        "Failed to parse scan code from \"",
                        key,
                        "\", ignoring: ",
                        strerror(r)
                    );
                    continue;
                }
            };
            let mut keycode = value;
            if let Some(rest) = keycode.strip_prefix(b"!") {
                keycode = rest;
                // C's array of 1024 holds at most 1023; later ones go to
                // the unused last slot.
                if release.len() < 1023 {
                    release.push(scancode);
                }
                if keycode.is_empty() {
                    continue;
                }
            }
            let f = match open_once(&dev, &node, &mut fd) {
                Ok(f) => f,
                Err(r) => return bail(r),
            };
            let _ = map_keycode(&dev, f, scancode, keycode);
        } else if let Some(code) = key.strip_prefix(b"EVDEV_ABS_") {
            let evcode = match shared::parse::safe_atou_full(code, 16) {
                Ok(e) => e,
                Err(r) => {
                    log_device_warning_errno!(
                        dev,
                        r,
                        "Failed to parse EV_ABS code from \"",
                        key,
                        "\", ignoring: ",
                        strerror(r)
                    );
                    continue;
                }
            };
            let f = match open_once(&dev, &node, &mut fd) {
                Ok(f) => f,
                Err(r) => return bail(r),
            };
            if has_abs.is_none() {
                let mut bits: usize = 0;
                // EVIOCGBIT(0, sizeof(unsigned long))
                let req = 0x8000_4520 | ((std::mem::size_of::<usize>() as u64) << 16);
                if let Err(r) = sys::ioctl_ptr(f, req, &mut bits) {
                    return Err(log_device_error_errno!(dev, r, "Failed to set EVIOCGBIT"));
                }
                let b = bits & (1 << EV_ABS) != 0;
                if !b {
                    log_device_warning!(dev, "EVDEV_ABS override set but no EV_ABS present on device");
                }
                has_abs = Some(b);
            }
            if has_abs != Some(true) {
                continue;
            }
            let _ = override_abs(&dev, f, evcode, value);
        } else if key == b"POINTINGSTICK_SENSITIVITY" {
            let _ = set_trackpoint_sensitivity(&dev, value);
        }
    }
    if !release.is_empty() {
        let _ = install_force_release(&dev, &release);
    }
    Ok(())
}
