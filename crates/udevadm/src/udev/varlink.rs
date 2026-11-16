// SPDX-License-Identifier: LGPL-2.1-or-later
//! The client half of `udev-varlink.c`.

use shared::varlink::Client;

/// `UDEV_VARLINK_ADDRESS`.
pub const UDEV_VARLINK_ADDRESS: &[u8] = b"/run/udev/io.systemd.Udev";

/// `udev_varlink_connect(&link, timeout)`.
pub fn udev_varlink_connect(timeout: u64) -> Result<Client, i32> {
    let mut link = Client::connect_address(UDEV_VARLINK_ADDRESS)?;
    link.set_description(b"udev");
    link.set_relative_timeout(timeout);
    Ok(link)
}
