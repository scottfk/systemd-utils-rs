// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-daemon.c`'s `sd_notify()`: one datagram to $NOTIFY_SOCKET, and the
//! receiving side of `notify-recv.c`.
//!
//! Known difference: AF_VSOCK addresses ("vsock:...") are not supported,
//! and fds are never sent.

use crate::errno::strerror;
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_debug_errno};

/// `sd_notify(0, state)`: 0 if there is no socket, 1 if sent.
pub fn sd_notify(state: &[u8]) -> i32 {
    let Some(e) = sys::getenv("NOTIFY_SOCKET") else { return 0 };
    if e.is_empty() || (e[0] != b'/' && e[0] != b'@') {
        let r = -libc::EPROTO;
        return log_debug_errno!(
            r,
            "Address NOTIFY_SOCKET='",
            &e[..],
            "' is neither UNIX nor VSOCK, refusing: ",
            strerror(r)
        );
    }
    let fd = match sys::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => {
            return log_debug_errno!(r, "Failed to open datagram notify socket to '", &e[..], "': ", strerror(r));
        }
    };
    if let Err(r) = sys::sendto_unix(fd.raw(), state, &e) {
        return log_debug_errno!(r, "Failed to send notify message to '", &e[..], "': ", strerror(r));
    }
    if crate::log::debug_logging() {
        log_debug!("Notify message sent to '", &e[..], "': \"", crate::escape::shell_escape(state, b"\""), "\"");
    }
    1
}

/// `notify_socket_prepare()`'s socket: an autobound abstract datagram
/// socket with SO_PASSCRED: (fd, "@<random>").
pub fn notify_socket_new() -> Result<(OwnedFd, Vec<u8>), i32> {
    let fd = match sys::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => return Err(log_debug_errno!(r, "Failed to create notification socket: ", strerror(r))),
    };
    let mut b = [0u8; 8];
    sys::getrandom(&mut b)?;
    let name = format!("@{}", u64::from_ne_bytes(b)).into_bytes();
    if let Err(r) = sys::bind_unix(fd.raw(), &name) {
        return Err(log_debug_errno!(r, "Failed to bind notification socket: ", strerror(r)));
    }
    if let Err(r) = sys::setsockopt_int(fd.raw(), libc::SOL_SOCKET, libc::SO_PASSCRED, 1) {
        return Err(log_debug_errno!(r, "Failed to enable SO_PASSCRED on notification socket: ", strerror(r)));
    }
    Ok((fd, name))
}

/// `notify_recv_strv(fd, &list, NULL, &pidref)`: the lines and the
/// sender's pid; Err(-EAGAIN) for messages to ignore.
pub fn notify_recv_strv(fd: i32) -> Result<(Vec<Vec<u8>>, i32), i32> {
    let (buf, pid) = match sys::recv_with_creds(fd, 4096) {
        Err(r) if r == -libc::EAGAIN || r == -libc::EINTR => return Err(-libc::EAGAIN),
        Err(r) => return Err(crate::log_error_errno!(r, "Failed to receive notification message: ", strerror(r))),
        Ok(x) => x,
    };
    let Some(pid) = pid.filter(|&p| p > 0) else {
        return Err(crate::log_warning_errno!(
            crate::errno::synthetic(libc::EAGAIN),
            "Got notification datagram lacking valid credential information, ignoring."
        ));
    };
    if buf.len() > 1 && buf[..buf.len() - 1].contains(&0) {
        return Err(crate::log_warning_errno!(
            crate::errno::synthetic(libc::EAGAIN),
            "Got notification message with embedded NUL, ignoring."
        ));
    }
    let text = match buf.iter().position(|&c| c == 0) {
        Some(i) => &buf[..i],
        None => &buf[..],
    };
    Ok((crate::extract::strv_split_newlines_full(text, 0).unwrap_or_default(), pid))
}
