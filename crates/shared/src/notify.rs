// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-daemon.c`'s `sd_notify()`: one datagram to $NOTIFY_SOCKET.
//!
//! Known difference: AF_VSOCK addresses ("vsock:...") are not supported.

use crate::sys::{self, OwnedFd};

/// `sd_notify(0, state)`: 0 if there is no socket, 1 if sent.
pub fn sd_notify(state: &[u8]) -> i32 {
    let Some(e) = sys::getenv("NOTIFY_SOCKET") else { return 0 };
    if e.is_empty() || (e[0] != b'/' && e[0] != b'@') {
        return -libc::EAFNOSUPPORT;
    }
    let fd = match sys::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => return r,
    };
    match sys::sendto_unix(fd.raw(), state, &e) {
        Ok(_) => 1,
        Err(r) => r,
    }
}
