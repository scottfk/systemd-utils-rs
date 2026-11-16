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
