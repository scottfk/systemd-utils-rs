// SPDX-License-Identifier: GPL-2.0-or-later
//! The builtins, one module each (`udev-builtin-*.c`).

pub mod blkid;
pub mod btrfs;
pub mod dissect_image;
pub mod factory_reset;
pub mod hwdb;
pub mod input_id;
pub mod keyboard;
mod keyboard_keys;
pub mod kmod;
pub mod net_driver;
pub mod net_id;
pub mod net_setup_link;
pub mod path_id;
pub mod uaccess;
pub mod usb_id;
