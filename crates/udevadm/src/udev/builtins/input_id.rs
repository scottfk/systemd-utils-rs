// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-input_id.c`: classify input devices from their
//! capability bitmaps.

use shared::errno::strerror;
use shared::sd_device::Device;
use shared::{log_device_debug, log_device_debug_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::def::EventMode;
use super::super::event::Event;

const BITS_PER_LONG: usize = usize::BITS as usize;

const fn nbits(x: usize) -> usize {
    (x - 1) / BITS_PER_LONG + 1
}

const EV_KEY: usize = 0x01;
const EV_REL: usize = 0x02;
const EV_SW: usize = 0x05;
const EV_MAX: usize = 0x1f;
const ABS_X: usize = 0x00;
const ABS_Y: usize = 0x01;
const ABS_Z: usize = 0x02;
const ABS_RX: usize = 0x03;
const ABS_PRESSURE: usize = 0x18;
const ABS_MT_SLOT: usize = 0x2f;
const ABS_MT_POSITION_X: usize = 0x35;
const ABS_MT_POSITION_Y: usize = 0x36;
const ABS_MAX: usize = 0x3f;
const REL_X: usize = 0x00;
const REL_Y: usize = 0x01;
const REL_HWHEEL: usize = 0x06;
const REL_WHEEL: usize = 0x08;
const REL_MAX: usize = 0x0f;
const INPUT_PROP_DIRECT: usize = 0x01;
const INPUT_PROP_POINTING_STICK: usize = 0x05;
const INPUT_PROP_ACCELEROMETER: usize = 0x06;
const INPUT_PROP_MAX: usize = 0x1f;
const KEY_MAX: usize = 0x2ff;
const BTN_MISC: usize = 0x100;
const BTN_0: usize = 0x100;
const BTN_1: usize = 0x101;
const BTN_MOUSE: usize = 0x110;
const BTN_JOYSTICK: usize = 0x120;
const BTN_DIGI: usize = 0x140;
const BTN_TOOL_PEN: usize = 0x140;
const BTN_TOOL_FINGER: usize = 0x145;
const BTN_TOUCH: usize = 0x14a;
const BTN_STYLUS: usize = 0x14b;
const BTN_DPAD_UP: usize = 0x220;
const BTN_DPAD_RIGHT: usize = 0x223;
const BTN_TRIGGER_HAPPY: usize = 0x2c0;
const BTN_TRIGGER_HAPPY1: usize = 0x2c0;
const BTN_TRIGGER_HAPPY40: usize = 0x2e7;
const KEY_OK: usize = 0x160;
const KEY_ALS_TOGGLE: usize = 0x230;
const BUS_I2C: u16 = 0x18;

/// Key code ranges above BTN_MISC (start inclusive, end exclusive).
const HIGH_KEY_BLOCKS: [(usize, usize); 2] = [(KEY_OK, BTN_DPAD_UP), (KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY)];

fn test_bit(bit: usize, array: &[usize]) -> bool {
    (array[bit / BITS_PER_LONG] >> (bit % BITS_PER_LONG)) & 1 != 0
}

/// `safe_atolu_full(s, 16, &v)`.
fn atolu16(s: &[u8]) -> Result<usize, i32> {
    let v = shared::parse::safe_atou64_full(s, 16)?;
    usize::try_from(v).map_err(|_| -libc::ERANGE)
}

/// `extract_info()`: the size of an absolute device, in mm.
fn extract_info(event: &Event) {
    let Ok(fd) = shared::blockdev::sd_device_open(
        &event.dev,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
    ) else {
        return;
    };
    // struct input_absinfo: value, minimum, maximum, fuzz, flat, resolution.
    let absinfo = |abs: u64| -> Option<[i32; 6]> {
        let mut info = [0i32; 6];
        // EVIOCGABS(abs) = _IOR('E', 0x40 + abs, struct input_absinfo)
        shared::sys::ioctl_ptr(fd.raw(), 0x8018_4540 + abs, &mut info).ok()?;
        Some(info)
    };
    let (Some(x), Some(y)) = (absinfo(ABS_X as u64), absinfo(ABS_Y as u64)) else { return };
    if x[5] <= 0 || y[5] <= 0 {
        return;
    }
    let width = ((x[2] - x[1]) / x[5]).to_string();
    let height = ((y[2] - y[1]) / y[5]).to_string();
    let _ = udev_builtin_add_property(event, b"ID_INPUT_WIDTH_MM", Some(width.as_bytes()));
    let _ = udev_builtin_add_property(event, b"ID_INPUT_HEIGHT_MM", Some(height.as_bytes()));
}

/// `get_cap_mask()`.
fn get_cap_mask(pdev: &Device, attr: &[u8], words: usize, mode: EventMode) -> Vec<usize> {
    let v = pdev.get_sysattr_safe_string(attr).map(|v| v.bytes().to_vec()).unwrap_or_default();
    log_device_debug!(pdev, attr, " raw kernel attribute: ", &v[..]);
    let mut bitmask = vec![0usize; words];
    let mut text = &v[..];
    let mut i = 0;
    let mut store = |i: usize, word: &[u8]| match atolu16(word) {
        Err(r) => {
            log_device_debug_errno!(pdev, r, "Ignoring ", attr, " block which failed to parse: ", strerror(r));
        }
        Ok(val) if i < words => bitmask[i] = val,
        Ok(val) => {
            log_device_debug!(
                pdev,
                "Ignoring ",
                attr,
                " block ",
                format!("{val:X}"),
                " which is larger than maximum size"
            );
        }
    };
    while let Some(p) = text.iter().rposition(|&c| c == b' ') {
        store(i, &text[p + 1..]);
        text = &text[..p];
        i += 1;
    }
    store(i, text);
    if mode == EventMode::UdevadmTestBuiltin && shared::log::debug_logging() {
        log_device_debug!(pdev, attr, " decoded bit map:");
        let mut n = words;
        while n > 0 && bitmask[n - 1] == 0 {
            n -= 1;
        }
        for (j, w) in bitmask.iter().take(n).enumerate() {
            let line = if BITS_PER_LONG == 32 {
                format!("  bit {:4}: {:08X}\n", j * BITS_PER_LONG, w)
            } else {
                format!("  bit {:4}: {:016X}\n", j * BITS_PER_LONG, w)
            };
            log_device_debug!(pdev, line);
        }
    }
    bitmask
}

/// `get_input_id()`: the bus type.
fn get_bustype(dev: &Device) -> u16 {
    let bustype = dev.get_sysattr_u16_full(b"id/bustype", 16).unwrap_or(0);
    let _ = dev.get_sysattr_u16_full(b"id/vendor", 16);
    let _ = dev.get_sysattr_u16_full(b"id/product", 16);
    let _ = dev.get_sysattr_u16_full(b"id/version", 16);
    bustype
}

/// `test_pointers()`.
#[allow(clippy::too_many_arguments)]
fn test_pointers(
    event: &Event,
    bustype: u16,
    ev: &[usize],
    abs: &[usize],
    key: &[usize],
    rel: &[usize],
    props: &[usize],
) -> bool {
    let dev = &event.dev;
    let add = |k: &[u8]| {
        let _ = udev_builtin_add_property(event, k, Some(b"1"));
    };
    let has_keys = test_bit(EV_KEY, ev);
    let has_abs_coordinates = test_bit(ABS_X, abs) && test_bit(ABS_Y, abs);
    let has_3d_coordinates = has_abs_coordinates && test_bit(ABS_Z, abs);
    let mut is_accelerometer = test_bit(INPUT_PROP_ACCELEROMETER, props);
    if !has_keys && has_3d_coordinates {
        is_accelerometer = true;
    }
    if is_accelerometer {
        add(b"ID_INPUT_ACCELEROMETER");
        return true;
    }
    let mut is_pointing_stick = test_bit(INPUT_PROP_POINTING_STICK, props);
    let has_stylus = test_bit(BTN_STYLUS, key);
    let has_pen = test_bit(BTN_TOOL_PEN, key);
    let finger_but_no_pen = test_bit(BTN_TOOL_FINGER, key) && !test_bit(BTN_TOOL_PEN, key);
    let has_mouse_button = (BTN_MOUSE..BTN_JOYSTICK).any(|b| test_bit(b, key));
    let has_rel_coordinates = test_bit(EV_REL, ev) && test_bit(REL_X, rel) && test_bit(REL_Y, rel);
    let mut has_mt_coordinates = test_bit(ABS_MT_POSITION_X, abs) && test_bit(ABS_MT_POSITION_Y, abs);
    if has_mt_coordinates && test_bit(ABS_MT_SLOT, abs) && test_bit(ABS_MT_SLOT - 1, abs) {
        has_mt_coordinates = false;
    }
    let is_direct = test_bit(INPUT_PROP_DIRECT, props);
    let has_touch = test_bit(BTN_TOUCH, key);
    let has_pad_buttons = test_bit(BTN_0, key) && test_bit(BTN_1, key) && !has_pen;
    let has_wheel = test_bit(EV_REL, ev) && (test_bit(REL_WHEEL, rel) || test_bit(REL_HWHEEL, rel));
    let mut num_joystick_buttons = 0usize;
    if !test_bit(BTN_JOYSTICK - 1, key) {
        num_joystick_buttons += (BTN_JOYSTICK..BTN_DIGI).filter(|&b| test_bit(b, key)).count();
        num_joystick_buttons += (BTN_TRIGGER_HAPPY1..=BTN_TRIGGER_HAPPY40).filter(|&b| test_bit(b, key)).count();
        num_joystick_buttons += (BTN_DPAD_UP..=BTN_DPAD_RIGHT).filter(|&b| test_bit(b, key)).count();
    }
    let num_joystick_axes = (ABS_RX..ABS_PRESSURE).filter(|&a| test_bit(a, abs)).count();
    let (mut is_tablet, mut is_touchpad, mut is_abs_mouse, mut is_touchscreen, mut is_joystick) =
        (false, false, false, false, false);
    if has_abs_coordinates {
        if has_stylus || has_pen {
            is_tablet = true;
        } else if finger_but_no_pen && !is_direct {
            is_touchpad = true;
        } else if has_mouse_button {
            is_abs_mouse = true;
        } else if has_touch || is_direct {
            is_touchscreen = true;
        } else if num_joystick_buttons > 0 || num_joystick_axes > 0 {
            is_joystick = true;
        }
    } else if num_joystick_buttons > 0 || num_joystick_axes > 0 {
        is_joystick = true;
    }
    if has_mt_coordinates {
        if has_stylus || has_pen {
            is_tablet = true;
        } else if finger_but_no_pen && !is_direct {
            is_touchpad = true;
        } else if has_touch || is_direct {
            is_touchscreen = true;
        }
    }
    let mut is_tablet_pad = is_tablet && has_pad_buttons;
    if has_pad_buttons && has_wheel && !has_rel_coordinates {
        is_tablet = true;
        is_tablet_pad = true;
    }
    let is_mouse =
        !is_tablet && !is_touchpad && !is_joystick && has_mouse_button && (has_rel_coordinates || !has_abs_coordinates);
    if is_mouse && bustype == BUS_I2C {
        is_pointing_stick = true;
    }
    if is_joystick {
        const WELL_KNOWN_KEYBOARD_KEYS: [usize; 10] = [29, 58, 69, 110, 113, 140, 144, 155, 164, 224];
        let num_well_known_keys =
            if has_keys { WELL_KNOWN_KEYBOARD_KEYS.iter().filter(|&&k| test_bit(k, key)).count() } else { 0 };
        if num_well_known_keys >= 4 || num_joystick_buttons + num_joystick_axes < 2 {
            log_device_debug!(
                dev,
                "Input device has ",
                num_joystick_buttons.to_string(),
                " joystick buttons and ",
                num_joystick_axes.to_string(),
                " axes but also ",
                num_well_known_keys.to_string(),
                " keyboard key sets, assuming this is a keyboard, not a joystick."
            );
            is_joystick = false;
        }
        if has_wheel && has_pad_buttons {
            log_device_debug!(
                dev,
                "Input device has ",
                num_joystick_buttons.to_string(),
                " joystick buttons as well as tablet pad buttons, assuming this is a tablet pad, not a joystick."
            );
            is_joystick = false;
        }
    }
    if is_pointing_stick {
        add(b"ID_INPUT_POINTINGSTICK");
    }
    if is_mouse || is_abs_mouse {
        add(b"ID_INPUT_MOUSE");
    }
    if is_touchpad {
        add(b"ID_INPUT_TOUCHPAD");
    }
    if is_touchscreen {
        add(b"ID_INPUT_TOUCHSCREEN");
    }
    if is_joystick {
        add(b"ID_INPUT_JOYSTICK");
    }
    if is_tablet {
        add(b"ID_INPUT_TABLET");
    }
    if is_tablet_pad {
        add(b"ID_INPUT_TABLET_PAD");
    }
    is_tablet || is_mouse || is_abs_mouse || is_touchpad || is_touchscreen || is_joystick || is_pointing_stick
}

/// `test_key()`.
fn test_key(event: &Event, ev: &[usize], key: &[usize]) -> bool {
    let dev = &event.dev;
    if !test_bit(EV_KEY, ev) {
        log_device_debug!(dev, "test_key: no EV_KEY capability");
        return false;
    }
    let mut found = false;
    let mut i = 0;
    while i < BTN_MISC / BITS_PER_LONG && !found {
        if key[i] != 0 {
            found = true;
        }
        log_device_debug!(
            dev,
            "test_key: checking bit block ",
            (i * BITS_PER_LONG).to_string(),
            " for any keys; found=",
            if found { "yes" } else { "no" }
        );
        i += 1;
    }
    'outer: for (start, end) in HIGH_KEY_BLOCKS {
        for i in start..end {
            if found {
                break 'outer;
            }
            if test_bit(i, key) {
                log_device_debug!(dev, "test_key: Found key ", format!("{i:x}"), " in high block");
                found = true;
            }
        }
    }
    if found {
        let _ = udev_builtin_add_property(event, b"ID_INPUT_KEY", Some(b"1"));
    }
    if key[0] & 0xFFFF_FFFE == 0xFFFF_FFFE {
        let _ = udev_builtin_add_property(event, b"ID_INPUT_KEYBOARD", Some(b"1"));
        return true;
    }
    found
}

/// `builtin_input_id()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    let mut pdev = Some(dev.clone());
    while let Some(p) = pdev.clone() {
        if p.get_sysattr_value(b"capabilities/ev").is_ok() {
            break;
        }
        pdev = p.get_parent_with_subsystem_devtype(b"input", None).ok();
    }
    if let Some(p) = pdev {
        let bustype = get_bustype(&p);
        let _ = udev_builtin_add_property(event, b"ID_INPUT", Some(b"1"));
        let mode = event.event_mode;
        let ev = get_cap_mask(&p, b"capabilities/ev", nbits(EV_MAX), mode);
        let abs = get_cap_mask(&p, b"capabilities/abs", nbits(ABS_MAX), mode);
        let rel = get_cap_mask(&p, b"capabilities/rel", nbits(REL_MAX), mode);
        let key = get_cap_mask(&p, b"capabilities/key", nbits(KEY_MAX), mode);
        let props = get_cap_mask(&p, b"properties", nbits(INPUT_PROP_MAX), mode);
        let is_pointer = test_pointers(event, bustype, &ev, &abs, &key, &rel, &props);
        let is_key = test_key(event, &ev, &key);
        if !is_pointer && !is_key && test_bit(EV_REL, &ev) && (test_bit(REL_WHEEL, &rel) || test_bit(REL_HWHEEL, &rel))
        {
            let _ = udev_builtin_add_property(event, b"ID_INPUT_KEY", Some(b"1"));
        }
        if test_bit(EV_SW, &ev) {
            let _ = udev_builtin_add_property(event, b"ID_INPUT_SWITCH", Some(b"1"));
        }
    }
    if shared::blockdev::device_sysname_startswith(&dev, &[b"event"])? {
        extract_info(event);
    }
    Ok(())
}
