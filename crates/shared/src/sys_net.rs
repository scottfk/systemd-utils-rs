// SPDX-License-Identifier: LGPL-2.1-or-later
//! The libc calls for sd-device: netlink sockets, socket filters, poll and
//! inotify.  Like `sys.rs`, this is where the `unsafe` is; a failing call
//! returns `Err(-errno)`.

use libc::{c_int, c_void};

use crate::bytes::to_cstring;
use crate::sys::{Fd, neg_errno};

/// A received netlink datagram: its length and the sender's address and
/// credentials.
#[derive(Debug, Clone, Copy, Default)]
pub struct NlRecv {
    pub len: usize,
    pub nl_pid: u32,
    pub nl_groups: u32,
    /// `SCM_CREDENTIALS`: (pid, uid, gid).
    pub cred: Option<(i32, u32, u32)>,
}

fn sockaddr_nl(pid: u32, groups: u32) -> libc::sockaddr_nl {
    // SAFETY: sockaddr_nl is plain old data.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    sa.nl_pid = pid;
    sa.nl_groups = groups;
    sa
}

/// `bind(fd, &sockaddr_nl{pid, groups})`.
pub fn bind_netlink(fd: Fd, pid: u32, groups: u32) -> Result<(), i32> {
    let sa = sockaddr_nl(pid, groups);
    // SAFETY: sa is a valid sockaddr_nl.
    let r = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `getsockname()` of a netlink socket: (nl_pid, nl_groups).
pub fn getsockname_netlink(fd: Fd) -> Result<(u32, u32), i32> {
    let mut sa = sockaddr_nl(0, 0);
    let mut l = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: sa and l are valid out-pointers of the given size.
    let r = unsafe { libc::getsockname(fd, &mut sa as *mut libc::sockaddr_nl as *mut libc::sockaddr, &mut l) };
    if r < 0 { Err(neg_errno()) } else { Ok((sa.nl_pid, sa.nl_groups)) }
}

/// `recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC)`.
pub fn recv_peek_trunc(fd: Fd) -> Result<isize, i32> {
    // SAFETY: a zero-length receive into NULL is allowed.
    let r = unsafe { libc::recv(fd, std::ptr::null_mut(), 0, libc::MSG_PEEK | libc::MSG_TRUNC) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `ioctl(fd, FIONREAD, &k)`.
pub fn fionread(fd: Fd) -> Result<c_int, i32> {
    let mut k: c_int = 0;
    // SAFETY: FIONREAD writes an int.
    let r = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut k as *mut c_int) };
    if r < 0 { Err(neg_errno()) } else { Ok(k) }
}

/// `recvmsg_safe()` on a netlink socket, with room for `SCM_CREDENTIALS`:
/// `-ECHRNG` for truncated control data, `-EXFULL` for a truncated payload.
pub fn recvmsg_netlink(fd: Fd, buf: &mut [u8]) -> Result<NlRecv, i32> {
    let mut sa = sockaddr_nl(0, 0);
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: buf.len() };
    // CMSG_SPACE(sizeof(struct ucred)), 8-aligned.
    let mut control = [0u64; 8];
    // SAFETY: CMSG_SPACE only computes a size.
    let clen = unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) } as usize;
    // SAFETY: msghdr is plain old data.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut sa as *mut libc::sockaddr_nl as *mut c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = clen as _;
    // SAFETY: every pointer in msg is valid for the sizes given.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(neg_errno());
    }
    let mut cred = None;
    // SAFETY: msg was filled by recvmsg(); the CMSG macros walk its control buffer.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                // cmsg_close_all(): close any fds passed along.
                let data = libc::CMSG_DATA(c) as *const c_int;
                let nfds = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / size_of::<c_int>();
                for i in 0..nfds {
                    libc::close(std::ptr::read_unaligned(data.add(i)));
                }
            }
            if (*c).cmsg_level == libc::SOL_SOCKET
                && (*c).cmsg_type == libc::SCM_CREDENTIALS
                && (*c).cmsg_len as usize == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
            {
                let u: libc::ucred = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::ucred);
                cred = Some((u.pid, u.uid, u.gid));
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(-libc::ECHRNG);
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(-libc::EXFULL);
    }
    Ok(NlRecv { len: n as usize, nl_pid: sa.nl_pid, nl_groups: sa.nl_groups, cred })
}

/// `sendmsg(fd, {parts}, to sockaddr_nl{pid, groups})`.
pub fn sendmsg_netlink(fd: Fd, parts: &[&[u8]], pid: u32, groups: u32) -> Result<usize, i32> {
    let mut sa = sockaddr_nl(pid, groups);
    let mut iov: Vec<libc::iovec> =
        parts.iter().map(|p| libc::iovec { iov_base: p.as_ptr() as *mut c_void, iov_len: p.len() }).collect();
    // SAFETY: msghdr is plain old data.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut sa as *mut libc::sockaddr_nl as *mut c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;
    // SAFETY: the iovecs point into parts, which outlive the call.
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// One BPF instruction: (code, jt, jf, k).
pub type SockFilter = (u16, u8, u8, u32);

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sock_fprog)`.
pub fn attach_filter(fd: Fd, ins: &[SockFilter]) -> Result<(), i32> {
    let mut f: Vec<libc::sock_filter> =
        ins.iter().map(|&(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k }).collect();
    let prog = libc::sock_fprog { len: f.len() as u16, filter: f.as_mut_ptr() };
    // SAFETY: prog points to f, which lives for the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const libc::sock_fprog as *const c_void,
            size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &(struct sock_fprog){0, NULL})`.
pub fn detach_filter(fd: Fd) -> Result<(), i32> {
    let prog = libc::sock_fprog { len: 0, filter: std::ptr::null_mut() };
    // SAFETY: prog is a valid (empty) sock_fprog.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DETACH_FILTER,
            &prog as *const libc::sock_fprog as *const c_void,
            size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `ppoll_usec()` on one fd: the revents, 0 on timeout, `-EBADF` for
/// POLLNVAL.  `timeout` is in µs, `u64::MAX` for none.
pub fn poll_one(fd: Fd, events: i16, timeout: u64) -> Result<i16, i32> {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    let ts;
    let tsp = if timeout == u64::MAX {
        std::ptr::null()
    } else {
        ts = libc::timespec {
            tv_sec: (timeout / 1_000_000) as libc::time_t,
            tv_nsec: ((timeout % 1_000_000) * 1000) as libc::c_long,
        };
        &ts as *const libc::timespec
    };
    // SAFETY: p is one valid pollfd; tsp is NULL or points to ts.
    let r = unsafe { libc::ppoll(&mut p, 1, tsp, std::ptr::null()) };
    if r < 0 {
        return Err(neg_errno());
    }
    if r == 0 {
        return Ok(0);
    }
    if p.revents & libc::POLLNVAL != 0 {
        return Err(-libc::EBADF);
    }
    Ok(p.revents)
}

/// `inotify_init1(flags)`.
pub fn inotify_init1(flags: c_int) -> Result<Fd, i32> {
    // SAFETY: plain syscall.
    let fd = unsafe { libc::inotify_init1(flags) };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd) }
}

/// `inotify_add_watch(fd, path, mask)`.
pub fn inotify_add_watch(fd: Fd, path: &[u8], mask: u32) -> Result<c_int, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let r = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `access(path, mode)`.
pub fn access(path: &[u8], mode: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::access(c.as_ptr(), mode) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `opendir(path)`.
pub fn opendir(path: &[u8]) -> Result<crate::sys::Dir, i32> {
    let fd = crate::sys::open(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?;
    crate::sys::Dir::from_fd(fd)
}
