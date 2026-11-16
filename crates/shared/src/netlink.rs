// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bit of sd-netlink and `netlink-util.c` that sd-device uses:
//! `rtnl_get_ifname()`, one RTM_GETLINK request for an interface's name.

use crate::sys::{self, OwnedFd};
use crate::sys_net;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const IFLA_IFNAME: u16 = 3;
const IFLA_EXT_MASK: u16 = 29;
const RTEXT_FILTER_SKIP_STATS: u32 = 1 << 3;
const NETLINK_EXT_ACK: i32 = 11;
const NETLINK_GET_STRICT_CHK: i32 = 12;
/// `NETLINK_DEFAULT_TIMEOUT_USEC`.
const TIMEOUT_USEC: u64 = 25_000_000;

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_ne_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The RTM_NEWLINK reply's ifindex and IFLA_IFNAME.
fn parse_newlink(msg: &[u8]) -> Result<(i32, Option<Vec<u8>>), i32> {
    // nlmsghdr (16) + ifinfomsg (16), then attributes.
    if msg.len() < 32 {
        return Err(-libc::EPROTO);
    }
    let ifindex = u32_at(msg, 20) as i32;
    let mut i = 32;
    let mut name = None;
    while i + 4 <= msg.len() {
        let len = u16_at(msg, i) as usize;
        let ty = u16_at(msg, i + 2) & 0x3fff;
        if len < 4 || i + len > msg.len() {
            break;
        }
        if ty == IFLA_IFNAME {
            name = Some(crate::bytes::c_str_prefix(&msg[i + 4..i + len]).to_vec());
        }
        i += align4(len);
    }
    Ok((ifindex, name))
}

/// `sd_netlink_open()` and `sd_netlink_call()` for one RTM_GETLINK.
fn getlink(ifindex: i32) -> Result<Vec<u8>, i32> {
    let fd = OwnedFd::new(sys::socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        libc::NETLINK_ROUTE,
    )?);
    let _ = sys::setsockopt_int(fd.raw(), libc::SOL_NETLINK, NETLINK_EXT_ACK, 1);
    let _ = sys::setsockopt_int(fd.raw(), libc::SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1);
    sys_net::bind_netlink(fd.raw(), 0, 0)?;

    let seq: u32 = 1;
    let mut req = Vec::with_capacity(40);
    let total: u32 = 16 + 16 + 8;
    req.extend_from_slice(&total.to_ne_bytes());
    req.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    req.extend_from_slice(&seq.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    // ifinfomsg: family AF_UNSPEC, type 0, index, flags 0, change 0.
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&ifindex.to_ne_bytes());
    req.extend_from_slice(&[0; 8]);
    // IFLA_EXT_MASK = RTEXT_FILTER_SKIP_STATS
    req.extend_from_slice(&8u16.to_ne_bytes());
    req.extend_from_slice(&IFLA_EXT_MASK.to_ne_bytes());
    req.extend_from_slice(&RTEXT_FILTER_SKIP_STATS.to_ne_bytes());
    sys_net::sendmsg_netlink(fd.raw(), &[&req], 0, 0)?;

    let deadline = sys::clock_usec(libc::CLOCK_MONOTONIC).saturating_add(TIMEOUT_USEC);
    let mut reply: Option<Vec<u8>> = None;
    loop {
        let now = sys::clock_usec(libc::CLOCK_MONOTONIC);
        if now >= deadline {
            return Err(-libc::ETIMEDOUT);
        }
        match sys_net::poll_one(fd.raw(), libc::POLLIN, deadline - now) {
            Err(e) if e == -libc::EINTR => continue,
            Err(e) => return Err(e),
            Ok(0) => return Err(-libc::ETIMEDOUT),
            Ok(_) => {}
        }
        let size = match sys_net::recv_peek_trunc(fd.raw()) {
            Ok(n) if n > 0 => n as usize,
            Ok(_) => 65536,
            Err(e) if e == -libc::EAGAIN || e == -libc::EINTR => continue,
            Err(e) => return Err(e),
        };
        let mut buf = vec![0u8; size];
        let got = match sys_net::recvmsg_netlink(fd.raw(), &mut buf) {
            Ok(r) => r,
            Err(e) if e == -libc::EAGAIN || e == -libc::EINTR => continue,
            Err(e) => return Err(e),
        };
        if got.nl_pid != 0 {
            // Not from the kernel.
            continue;
        }
        let mut i = 0;
        let data = &buf[..got.len];
        while i + 16 <= data.len() {
            let len = u32_at(data, i) as usize;
            if len < 16 || i + len > data.len() {
                break;
            }
            let ty = u16_at(data, i + 4);
            let mseq = u32_at(data, i + 8);
            let m = &data[i..i + len];
            i += align4(len);
            if mseq != seq {
                continue;
            }
            match ty {
                NLMSG_ERROR => {
                    if m.len() < 20 {
                        return Err(-libc::EPROTO);
                    }
                    let err = u32_at(m, 16) as i32;
                    if err < 0 {
                        return Err(err);
                    }
                    if let Some(r) = reply.take() {
                        return Ok(r);
                    }
                }
                NLMSG_DONE => {
                    if let Some(r) = reply.take() {
                        return Ok(r);
                    }
                }
                _ => {
                    if ty != RTM_NEWLINK {
                        return Err(-libc::EPROTO);
                    }
                    reply = Some(m.to_vec());
                }
            }
        }
    }
}

/// `rtnl_get_ifname(NULL, ifindex, &ret)`.
pub fn rtnl_get_ifname(ifindex: i32) -> Result<Vec<u8>, i32> {
    let reply = match getlink(ifindex) {
        Err(e) if e == -libc::EINVAL => return Err(-libc::ENODEV),
        r => r?,
    };
    let (idx, name) = parse_newlink(&reply)?;
    if idx <= 0 {
        return Err(-libc::EPROTO);
    }
    let name = name.ok_or(-libc::ENODATA)?;
    if idx != ifindex {
        return Err(-libc::EIO);
    }
    Ok(name)
}
