// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-factory_reset.c`.

use shared::errno::{strerror, synthetic};
use shared::{log_device_debug_errno, log_device_warning_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

/// `builtin_factory_reset()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if argv.len() != 2 || argv[1] != b"status" {
        return Err(log_device_warning_errno!(dev, synthetic(libc::EINVAL), &argv[0][..], ": expected: status"));
    }
    match shared::factory_reset::factory_reset_mode() {
        Err(r) => {
            log_device_debug_errno!(dev, r, "Unable to detect factory reset mode, ignoring: ", strerror(r));
            Ok(())
        }
        Ok(f) => udev_builtin_add_property(event, b"ID_FACTORY_RESET", Some(f.as_str().as_bytes())),
    }
}
