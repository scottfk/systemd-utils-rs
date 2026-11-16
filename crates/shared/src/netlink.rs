// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bits of sd-netlink and `netlink-util.c` that sd-device and udevd
//! use: getting an interface's name and alternative names, renaming it,
//! and adding or removing alternative names, one request at a time.

use crate::sys::{self, OwnedFd};
use crate::sys_net;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWLINKPROP: u16 = 108;
const RTM_DELLINKPROP: u16 = 109;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_ALT_IFNAME: u16 = 53;
const NLA_F_NESTED: u16 = 1 << 15;
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
    parse_newlink_full(msg).map(|(i, n, _)| (i, n))
}

/// The RTM_NEWLINK reply's ifindex, IFLA_IFNAME and alternative names.
fn parse_newlink_full(msg: &[u8]) -> Result<(i32, Option<Vec<u8>>, Vec<Vec<u8>>), i32> {
    // nlmsghdr (16) + ifinfomsg (16), then attributes.
    if msg.len() < 32 {
        return Err(-libc::EPROTO);
    }
    let ifindex = u32_at(msg, 20) as i32;
    let mut i = 32;
    let mut name = None;
    let mut altnames = Vec::new();
    while i + 4 <= msg.len() {
        let len = u16_at(msg, i) as usize;
        let ty = u16_at(msg, i + 2) & 0x3fff;
        if len < 4 || i + len > msg.len() {
            break;
        }
        if ty == IFLA_IFNAME {
            name = Some(crate::bytes::c_str_prefix(&msg[i + 4..i + len]).to_vec());
        } else if ty == IFLA_PROP_LIST {
            let mut j = i + 4;
            while j + 4 <= i + len {
                let l2 = u16_at(msg, j) as usize;
                let t2 = u16_at(msg, j + 2) & 0x3fff;
                if l2 < 4 || j + l2 > i + len {
                    break;
                }
                if t2 == IFLA_ALT_IFNAME {
                    altnames.push(crate::bytes::c_str_prefix(&msg[j + 4..j + l2]).to_vec());
                }
                j += align4(l2);
            }
        }
        i += align4(len);
    }
    Ok((ifindex, name, altnames))
}

/// An rtnetlink attribute: (type, payload).
type Attr<'a> = (u16, &'a [u8]);

fn push_attr(req: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    req.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    req.extend_from_slice(&ty.to_ne_bytes());
    req.extend_from_slice(payload);
    while req.len() % 4 != 0 {
        req.push(0);
    }
}

/// A NUL-terminated string attribute's payload.
fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}

/// `sd_netlink_open()` and `sd_netlink_call()` for one RTM_GETLINK.
fn getlink(ifindex: i32) -> Result<Vec<u8>, i32> {
    let mask = RTEXT_FILTER_SKIP_STATS.to_ne_bytes();
    call(RTM_GETLINK, ifindex, &[(IFLA_EXT_MASK, &mask)], None)?.ok_or(-libc::EPROTO)
}

/// `sd_rtnl_message_new_link(type, ifindex)` with `attrs` (and a nested
/// `(container, [(type, payload)])`), then `sd_netlink_call()`: the
/// RTM_NEWLINK reply, if any.
fn call(msg_type: u16, ifindex: i32, attrs: &[Attr], nested: Option<(u16, &[Attr])>) -> Result<Option<Vec<u8>>, i32> {
    let fd = OwnedFd::new(sys::socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        libc::NETLINK_ROUTE,
    )?);
    let _ = sys::setsockopt_int(fd.raw(), libc::SOL_NETLINK, NETLINK_EXT_ACK, 1);
    let _ = sys::setsockopt_int(fd.raw(), libc::SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1);
    sys_net::bind_netlink(fd.raw(), 0, 0)?;

    let seq: u32 = 1;
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&msg_type.to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    req.extend_from_slice(&seq.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    // ifinfomsg: family AF_UNSPEC, type 0, index, flags 0, change 0.
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&ifindex.to_ne_bytes());
    req.extend_from_slice(&[0; 8]);
    for (ty, payload) in attrs {
        push_attr(&mut req, *ty, payload);
    }
    if let Some((container, inner)) = nested {
        let mut body = Vec::new();
        for (ty, payload) in inner {
            push_attr(&mut body, *ty, payload);
        }
        push_attr(&mut req, container | NLA_F_NESTED, &body);
    }
    let total = req.len() as u32;
    req[..4].copy_from_slice(&total.to_ne_bytes());
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
                    return Ok(reply.take());
                }
                NLMSG_DONE => return Ok(reply.take()),
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

/// `ifname_valid_char()`.
pub fn ifname_valid_char(a: u8) -> bool {
    if a >= 127 {
        return false;
    }
    if a <= 32 {
        return false;
    }
    !matches!(a, b':' | b'/' | b'%')
}

/// `ifname_valid_full(p, flags)` without IFNAME_VALID_NUMERIC/SPECIAL.
pub fn ifname_valid_full(p: &[u8], alternative: bool) -> bool {
    if p.is_empty() {
        return false;
    }
    if crate::parse::safe_atoi(p).is_ok_and(|i| i > 0) {
        return false;
    }
    if p.len() >= if alternative { 128 } else { 16 } {
        return false;
    }
    if p == b"." || p == b".." || p == b"all" || p == b"default" {
        return false;
    }
    p.iter().all(|&c| ifname_valid_char(c)) && !p.iter().all(u8::is_ascii_digit)
}

/// `ifname_valid()`.
pub fn ifname_valid(p: &[u8]) -> bool {
    ifname_valid_full(p, false)
}

/// `rtnl_get_link_alternative_names(ifindex)`.
pub fn rtnl_get_link_alternative_names(ifindex: i32) -> Result<Vec<Vec<u8>>, i32> {
    let reply = getlink(ifindex)?;
    Ok(parse_newlink_full(&reply)?.2)
}

/// `rtnl_update_link_alternative_names(type, ifindex, names)`.
fn update_link_alternative_names(msg_type: u16, ifindex: i32, names: &[Vec<u8>]) -> Result<(), i32> {
    if names.is_empty() {
        return Ok(());
    }
    let payloads: Vec<Vec<u8>> = names.iter().map(|n| cstr(n)).collect();
    let inner: Vec<Attr> = payloads.iter().map(|p| (IFLA_ALT_IFNAME, &p[..])).collect();
    call(msg_type, ifindex, &[], Some((IFLA_PROP_LIST, &inner))).map(|_| ())
}

/// `rtnl_set_link_alternative_names(ifindex, names)`.
pub fn rtnl_set_link_alternative_names(ifindex: i32, names: &[Vec<u8>]) -> Result<(), i32> {
    update_link_alternative_names(RTM_NEWLINKPROP, ifindex, names)
}

/// `rtnl_delete_link_alternative_names(ifindex, names)`.
pub fn rtnl_delete_link_alternative_names(ifindex: i32, names: &[Vec<u8>]) -> Result<(), i32> {
    update_link_alternative_names(RTM_DELLINKPROP, ifindex, names)
}

/// `set_link_name()`.
fn set_link_name(ifindex: i32, name: &[u8]) -> Result<(), i32> {
    let n = cstr(name);
    call(RTM_SETLINK, ifindex, &[(IFLA_IFNAME, &n)], None).map(|_| ())
}

/// `rtnl_set_link_name(rtnl, ifindex, name, alternative_names)`.
pub fn rtnl_set_link_name(ifindex: i32, name: Option<&[u8]>, alternative_names: &[Vec<u8>]) -> Result<(), i32> {
    use crate::errno::strerror;
    if name.is_none_or(<[u8]>::is_empty) && alternative_names.is_empty() {
        return Ok(());
    }
    if let Some(n) = name
        && !ifname_valid(n)
    {
        return Err(-libc::EINVAL);
    }
    let original = rtnl_get_link_alternative_names(ifindex).unwrap_or_else(|r| {
        crate::log_debug_errno!(
            r,
            "Failed to get alternative names on network interface ",
            ifindex.to_string(),
            ", ignoring: ",
            strerror(r)
        );
        Vec::new()
    });
    let mut altname_deleted = false;
    if let Some(name) = name {
        if original.iter().any(|a| a == name) {
            if let Err(r) = rtnl_delete_link_alternative_names(ifindex, &[name.to_vec()]) {
                return Err(crate::log_debug_errno!(
                    r,
                    "Failed to remove '",
                    name,
                    "' from alternative names on network interface ",
                    ifindex.to_string(),
                    ": ",
                    strerror(r)
                ));
            }
            altname_deleted = true;
        }
        if let Err(r) = set_link_name(ifindex, name) {
            if altname_deleted && let Err(q) = rtnl_set_link_alternative_names(ifindex, &[name.to_vec()]) {
                crate::log_debug_errno!(
                    q,
                    "Failed to restore '",
                    name,
                    "' as an alternative name on network interface ",
                    ifindex.to_string(),
                    ", ignoring: ",
                    strerror(q)
                );
            }
            return Err(r);
        }
    }
    let mut new: Vec<Vec<u8>> = Vec::new();
    for a in alternative_names {
        if name == Some(&a[..]) || original.contains(a) || new.contains(a) || !ifname_valid_full(a, true) {
            continue;
        }
        new.push(a.clone());
    }
    new.sort();
    match rtnl_set_link_alternative_names(ifindex, &new) {
        Err(r) if r == -libc::EEXIST => {
            for a in &new {
                if let Err(r) = rtnl_set_link_alternative_names(ifindex, std::slice::from_ref(a)) {
                    crate::log_debug_errno!(
                        r,
                        "Failed to assign '",
                        &a[..],
                        "' as an alternative name on network interface ",
                        ifindex.to_string(),
                        ", ignoring: ",
                        strerror(r)
                    );
                }
            }
        }
        Err(r) => {
            crate::log_debug_errno!(
                r,
                "Failed to assign alternative names on network interface ",
                ifindex.to_string(),
                ", ignoring: ",
                strerror(r)
            );
        }
        Ok(()) => {}
    }
    Ok(())
}
