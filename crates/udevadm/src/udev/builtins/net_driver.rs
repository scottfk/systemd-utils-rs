// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-builtin-net_driver.c`.

use shared::errno::strerror;
use shared::{log_device_debug_errno, log_device_warning_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

/// `builtin_net_driver_set_driver()`.
pub fn run(event: &mut Event, _argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    let ifname = match dev.get_ifname() {
        Ok(n) => n.bytes().to_vec(),
        Err(r) => return Err(log_device_warning_errno!(dev, r, "Failed to get network interface name: ", strerror(r))),
    };
    let mut ethtool = shared::ethtool::Ethtool::default();
    match ethtool.get_driver(&ifname) {
        Err(r) if shared::errno::is_neg_not_supported(r) => {
            log_device_debug_errno!(
                dev,
                r,
                "Querying driver name via ethtool API is not supported by device '",
                &ifname[..],
                "', ignoring: ",
                strerror(r)
            );
            Ok(())
        }
        Err(r) if r == -libc::ENODEV => {
            log_device_debug_errno!(dev, r, "Device already vanished, ignoring.");
            Ok(())
        }
        Err(r) => Err(log_device_warning_errno!(dev, r, "Failed to get driver for '", &ifname[..], "': ", strerror(r))),
        Ok(d) => udev_builtin_add_property(event, b"ID_NET_DRIVER", Some(&d)),
    }
}
