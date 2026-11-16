// SPDX-License-Identifier: LGPL-2.1-or-later
//! `device-monitor.c`: receive devices from the kernel's uevent netlink
//! socket or from udevd's broadcasts, filtered in the kernel by a BPF
//! program and again in userspace.  (The sd-event glue isn't here yet.)

use std::collections::BTreeSet;

use crate::device_filter::{MatchStrv, device_match_parent, device_match_sysattr, update_match_strv};
use crate::errno::{strerror, synthetic};
use crate::sd_device::{Dev, Device};
use crate::sys::{self, OwnedFd};
use crate::sys_net::{self, SockFilter};
use crate::{log_debug, log_debug_errno, log_device_debug, log_device_debug_errno};

/// `MonitorNetlinkGroup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorGroup {
    None = 0,
    Kernel = 1,
    Udev = 2,
}

/// `UDEV_MONITOR_MAGIC`.
pub const UDEV_MONITOR_MAGIC: u32 = 0xfeed_cafe;

/// `sizeof(monitor_netlink_header)`.
pub const HEADER_SIZE: usize = 40;
const OFF_MAGIC: u32 = 8;
const OFF_PROPERTIES_OFF: usize = 16;
const OFF_SUBSYSTEM_HASH: u32 = 24;
const OFF_DEVTYPE_HASH: u32 = 28;
const OFF_BLOOM_HI: u32 = 32;
const OFF_BLOOM_LO: u32 = 36;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

/// `MurmurHash2(key, len, seed)`.
pub fn murmur_hash2(key: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let mut h = seed ^ key.len() as u32;
    let mut data = key;
    while data.len() >= 4 {
        let mut k = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M);
        h ^= k;
        data = &data[4..];
    }
    if data.len() == 3 {
        h ^= (data[2] as u32) << 16;
    }
    if data.len() >= 2 {
        h ^= (data[1] as u32) << 8;
    }
    if !data.is_empty() {
        h ^= data[0] as u32;
        h = h.wrapping_mul(M);
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

/// `string_hash32()`.
pub fn string_hash32(s: &[u8]) -> u32 {
    murmur_hash2(s, 0)
}

/// `string_bloom64()`.
pub fn string_bloom64(s: &[u8]) -> u64 {
    let hash = string_hash32(s);
    let mut bits = 0u64;
    bits |= 1u64 << (hash & 63);
    bits |= 1u64 << ((hash >> 6) & 63);
    bits |= 1u64 << ((hash >> 12) & 63);
    bits |= 1u64 << ((hash >> 18) & 63);
    bits
}

/// `uid_range_load_userns(NULL, UID_RANGE_USERNS_INSIDE)`: (start, nr) pairs.
fn uid_range_load_userns() -> Result<Vec<(u32, u32)>, i32> {
    let data = match crate::fileio::read_full_file_with_nuls(b"/proc/self/uid_map") {
        Err(e) if e == -libc::ENOENT => {
            return Err(if crate::fs::proc_mounted_full() == Ok(true) { -libc::EOPNOTSUPP } else { -libc::ENOSYS });
        }
        r => r?,
    };
    let mut out = Vec::new();
    for line in data.split(|&c| c == b'\n') {
        let f: Vec<&[u8]> = line.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
        if f.is_empty() {
            continue;
        }
        if f.len() != 3 {
            return Err(-libc::EBADMSG);
        }
        let n = |w: &[u8]| crate::parse::safe_atou(w).map_err(|_| -libc::EBADMSG);
        let (base, _shift, nr) = (n(f[0])?, n(f[1])?, n(f[2])?);
        if nr > 0 {
            out.push((base, nr));
        }
    }
    Ok(out)
}

/// `uid_range_contains()`.
fn uid_range_contains(range: Option<&[(u32, u32)]>, uid: u32) -> bool {
    if uid == u32::MAX {
        return false;
    }
    range.is_some_and(|r| r.iter().any(|&(s, n)| uid >= s && (uid as u64) < s as u64 + n as u64))
}

/// `sd_device_monitor`.
#[derive(Debug)]
pub struct Monitor {
    sock: OwnedFd,
    nl_pid: u32,
    nl_groups: u32,
    trusted_sender_pid: u32,
    mapped_userns_uid_range: Option<Vec<(u32, u32)>>,
    subsystem_filter: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    tag_filter: BTreeSet<Vec<u8>>,
    match_sysattr_filter: MatchStrv,
    nomatch_sysattr_filter: MatchStrv,
    match_parent_filter: Option<BTreeSet<Vec<u8>>>,
    nomatch_parent_filter: Option<BTreeSet<Vec<u8>>>,
    filter_uptodate: bool,
    description: Option<Vec<u8>>,
}

impl Monitor {
    fn desc(&self) -> Vec<u8> {
        self.description.clone().unwrap_or_else(|| b"n/a".to_vec())
    }

    /// `device_monitor_new_full(ret, group, -EBADF)`.
    pub fn new_full(group: MonitorGroup) -> Result<Monitor, i32> {
        Monitor::new_full_fd(group, None)
    }

    /// `device_monitor_new_full(ret, group, fd)`: takes `fd` on success.
    pub fn new_full_fd(mut group: MonitorGroup, fd: Option<i32>) -> Result<Monitor, i32> {
        if group == MonitorGroup::Udev
            && sys_net::access(b"/run/udev/control", libc::F_OK).is_err()
            && dev_is_devtmpfs().is_none_or(|b| !b)
        {
            // No udevd: don't let host uevents reach containers.
            log_debug!("sd-device-monitor(n/a): The udev service seems not to be active, disabling the monitor.");
            group = MonitorGroup::None;
        }
        let sock = match fd {
            Some(fd) => OwnedFd::new(fd),
            None => match sys::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_KOBJECT_UEVENT,
            ) {
                Ok(s) => OwnedFd::new(s),
                Err(e) => {
                    return Err(log_debug_errno!(e, "sd-device-monitor(n/a): Failed to create socket: ", strerror(e)));
                }
            },
        };
        let mut m = Monitor {
            sock,
            nl_pid: 0,
            nl_groups: group as u32,
            trusted_sender_pid: 0,
            mapped_userns_uid_range: None,
            subsystem_filter: Vec::new(),
            tag_filter: BTreeSet::new(),
            match_sysattr_filter: Vec::new(),
            nomatch_sysattr_filter: Vec::new(),
            match_parent_filter: None,
            nomatch_parent_filter: None,
            filter_uptodate: false,
            description: None,
        };
        if fd.is_none()
            && let Err(e) = sys::setsockopt_int(m.sock.raw(), libc::SOL_SOCKET, libc::SO_PASSCRED, 1)
        {
            return Err(log_debug_errno!(
                e,
                "sd-device-monitor(n/a): Failed to set socket option SO_PASSCRED: ",
                strerror(e)
            ));
        }
        if fd.is_none()
            && let Err(e) = sys_net::bind_netlink(m.sock.raw(), 0, m.nl_groups)
        {
            return Err(log_debug_errno!(e, "sd-device-monitor(n/a): Failed to bind monitoring socket: ", strerror(e)));
        }
        match sys_net::getsockname_netlink(m.sock.raw()) {
            Ok((pid, _)) => m.nl_pid = pid,
            Err(e) => {
                if fd.is_some() {
                    let _ = m.sock.into_raw();
                }
                return Err(log_debug_errno!(
                    e,
                    "sd-device-monitor(n/a): Failed to set netlink address: ",
                    strerror(e)
                ));
            }
        }
        if crate::log::debug_logging() {
            match network_namespace_is_init(m.sock.raw()) {
                Err(e) => {
                    log_debug_errno!(
                        e,
                        "sd-device-monitor(n/a): Failed to check if we are in the main network namespace, ignoring: ",
                        strerror(e)
                    );
                }
                Ok(false) => {
                    log_debug!(
                        "sd-device-monitor(n/a): Netlink socket we listen on is not from the main network namespace, we won't see device events."
                    );
                }
                Ok(true) => {}
            }
        }
        if fd.is_none()
            && let Err(e) = m.set_receive_buffer_size(128 * 1024 * 1024)
        {
            log_debug_errno!(
                e,
                "sd-device-monitor(n/a): Failed to increase receive buffer size, ignoring: ",
                strerror(e)
            );
        }
        Ok(m)
    }

    /// `sd_device_monitor_new()`.
    pub fn new() -> Result<Monitor, i32> {
        Monitor::new_full(MonitorGroup::Udev)
    }

    /// `device_monitor_get_address()`: (nl_pid, nl_groups).
    pub fn get_address(&self) -> (u32, u32) {
        (self.nl_pid, self.nl_groups)
    }

    /// The netlink port id of a monitor (for `allow_unicast_sender_pid()`).
    pub fn address_of(m: &Monitor) -> u32 {
        m.nl_pid
    }

    /// `device_monitor_allow_unicast_sender()` by port id.
    pub fn allow_unicast_sender_pid(&mut self, pid: u32) {
        self.trusted_sender_pid = pid;
    }

    /// `device_monitor_allow_unicast_sender()`.
    pub fn allow_unicast_sender(&mut self, sender: &Monitor) {
        self.trusted_sender_pid = sender.nl_pid;
    }

    /// `sd_device_monitor_set_receive_buffer_size()`.
    pub fn set_receive_buffer_size(&self, size: usize) -> Result<bool, i32> {
        fd_set_rcvbuf(self.sock.raw(), size, false)
    }

    /// `sd_device_monitor_get_fd()`.
    pub fn get_fd(&self) -> i32 {
        self.sock.raw()
    }

    /// `sd_device_monitor_set_description()`: Ok(true) if changed.
    pub fn set_description(&mut self, d: Option<&[u8]>) -> bool {
        if self.description.as_deref() == d {
            return false;
        }
        self.description = d.map(|d| d.to_vec());
        true
    }

    /// `sd_device_monitor_get_description()`.
    pub fn get_description(&self) -> Option<&[u8]> {
        self.description.as_deref()
    }

    /// `check_subsystem_filter()`.
    fn check_subsystem_filter(&self, device: &Device) -> Result<bool, i32> {
        if self.subsystem_filter.is_empty() {
            return Ok(true);
        }
        for (s, d) in &self.subsystem_filter {
            if device.is_subsystem_devtype(Some(s), d.as_deref())? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `check_tag_filter()`.
    fn check_tag_filter(&self, device: &Device) -> bool {
        if self.tag_filter.is_empty() {
            return true;
        }
        self.tag_filter.iter().any(|t| device.has_tag(t))
    }

    /// `passes_filter()`.
    fn passes_filter(&self, device: &Device) -> Result<bool, i32> {
        if !self.check_subsystem_filter(device)? {
            return Ok(false);
        }
        if !self.check_tag_filter(device) {
            return Ok(false);
        }
        if !device_match_sysattr(device, &self.match_sysattr_filter, &self.nomatch_sysattr_filter) {
            return Ok(false);
        }
        Ok(device_match_parent(device, self.match_parent_filter.as_ref(), self.nomatch_parent_filter.as_ref()))
    }

    /// `check_sender_uid()`.
    fn check_sender_uid(&mut self, uid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        if uid == sys::getuid() || uid == sys::geteuid() {
            return true;
        }
        if self.mapped_userns_uid_range.is_none() {
            match uid_range_load_userns() {
                Ok(r) => self.mapped_userns_uid_range = Some(r),
                Err(e) => {
                    log_debug_errno!(
                        e,
                        "sd-device-monitor(",
                        self.desc(),
                        "): Failed to load UID ranges mapped to the current user namespace, ignoring: ",
                        strerror(e)
                    );
                }
            }
        }
        !uid_range_contains(self.mapped_userns_uid_range.as_deref(), uid)
    }

    /// `sd_device_monitor_receive()`: Ok(None) is a device that doesn't pass
    /// the filter (C's 0).
    pub fn receive(&mut self) -> Result<Option<Dev>, i32> {
        let desc = self.desc();
        let n = match next_datagram_size_fd(self.sock.raw()) {
            Err(e) => {
                if e != -libc::EAGAIN && e != -libc::EINTR {
                    log_debug_errno!(
                        e,
                        "sd-device-monitor(",
                        desc,
                        "): Failed to get the received message size: ",
                        strerror(e)
                    );
                }
                return Err(e);
            }
            Ok(n) => n,
        };
        let mut buf = vec![0u8; n];
        let got = match sys_net::recvmsg_netlink(self.sock.raw(), &mut buf) {
            Err(e) => {
                if e != -libc::EAGAIN && e != -libc::EINTR {
                    let what: Vec<u8> = if e == -libc::ECHRNG {
                        b"got truncated control data".to_vec()
                    } else if e == -libc::EXFULL {
                        b"got truncated payload data".to_vec()
                    } else {
                        strerror(e)
                    };
                    log_debug_errno!(e, "sd-device-monitor(", desc, "): Failed to receive message: ", what);
                }
                return Err(e);
            }
            Ok(g) => g,
        };
        let n = got.len;
        if n < 32 {
            return Err(log_debug_errno!(
                synthetic(libc::EINVAL),
                "sd-device-monitor(",
                desc,
                "): Invalid message length (",
                n.to_string(),
                "), ignoring message."
            ));
        }
        let msg = &buf[..n];
        if got.nl_groups == MonitorGroup::None as u32 {
            if self.trusted_sender_pid == 0 || got.nl_pid != self.trusted_sender_pid {
                return Err(log_debug_errno!(
                    synthetic(libc::EAGAIN),
                    "sd-device-monitor(",
                    desc,
                    "): Unicast netlink message ignored."
                ));
            }
        } else if got.nl_groups == MonitorGroup::Kernel as u32 && got.nl_pid > 0 {
            return Err(log_debug_errno!(
                synthetic(libc::EAGAIN),
                "sd-device-monitor(",
                desc,
                "): Multicast kernel netlink message from PID ",
                got.nl_pid.to_string(),
                " ignored."
            ));
        }
        let Some((_, uid, _)) = got.cred else {
            return Err(log_debug_errno!(
                synthetic(libc::EAGAIN),
                "sd-device-monitor(",
                desc,
                "): No sender credentials received, ignoring message."
            ));
        };
        if !self.check_sender_uid(uid) {
            return Err(log_debug_errno!(
                synthetic(libc::EAGAIN),
                "sd-device-monitor(",
                desc,
                "): Sender uid=",
                uid.to_string(),
                ", message ignored."
            ));
        }
        let Some(nul) = msg.iter().position(|&c| c == 0) else {
            return Err(log_debug_errno!(
                synthetic(libc::EAGAIN),
                "sd-device-monitor(",
                desc,
                "): Received message without NUL, ignoring message."
            ));
        };
        let first = &msg[..nul];
        let mut is_initialized = false;
        let offset;
        if first == b"libudev" {
            let magic = u32::from_ne_bytes(msg[8..12].try_into().expect("4 bytes"));
            if magic != UDEV_MONITOR_MAGIC.to_be() {
                return Err(log_debug_errno!(
                    synthetic(libc::EAGAIN),
                    "sd-device-monitor(",
                    desc,
                    "): Invalid message signature (",
                    format!("{magic:x} != {:x}", UDEV_MONITOR_MAGIC.to_be()),
                    ")."
                ));
            }
            let properties_off =
                u32::from_ne_bytes(msg[OFF_PROPERTIES_OFF..OFF_PROPERTIES_OFF + 4].try_into().expect("4 bytes"));
            if properties_off as usize > n.saturating_sub(32) {
                return Err(log_debug_errno!(
                    synthetic(libc::EAGAIN),
                    "sd-device-monitor(",
                    desc,
                    "): Invalid properties offset (",
                    properties_off.to_string(),
                    ") for message of length ",
                    n.to_string(),
                    "."
                ));
            }
            offset = properties_off as usize;
            is_initialized = true;
        } else {
            if !first.windows(2).any(|w| w == b"@/") {
                return Err(log_debug_errno!(
                    synthetic(libc::EAGAIN),
                    "sd-device-monitor(",
                    desc,
                    "): Invalid message header."
                ));
            }
            offset = first.len() + 1;
            if offset >= n {
                return Err(log_debug_errno!(
                    synthetic(libc::EAGAIN),
                    "sd-device-monitor(",
                    desc,
                    "): Invalid message length."
                ));
            }
        }
        let device = match Device::new_from_nulstr(&msg[offset..]) {
            Err(e) => {
                return Err(log_debug_errno!(
                    e,
                    "sd-device-monitor(",
                    desc,
                    "): Failed to create device from received message: ",
                    strerror(e)
                ));
            }
            Ok(d) => d,
        };
        if is_initialized {
            device.set_is_initialized();
        }
        match self.passes_filter(&device) {
            Err(e) => Err(log_device_debug_errno!(
                device,
                e,
                "sd-device-monitor(",
                desc,
                "): Failed to check received device passing filter: ",
                strerror(e)
            )),
            Ok(false) => {
                log_device_debug!(
                    device,
                    "sd-device-monitor(",
                    desc,
                    "): Received device does not pass filter, ignoring."
                );
                Ok(None)
            }
            Ok(true) => Ok(Some(device)),
        }
    }

    /// `device_monitor_send()`: the bytes sent (0 for a multicast without
    /// listeners).  `destination` is (nl_pid, nl_groups), or the udev group.
    pub fn send(&self, destination: Option<(u32, u32)>, device: &Device) -> Result<usize, i32> {
        let desc = self.desc();
        let buf = match device.get_properties_nulstr() {
            Err(e) => {
                return Err(log_device_debug_errno!(
                    device,
                    e,
                    "sd-device-monitor(",
                    desc,
                    "): Failed to get device properties: ",
                    strerror(e)
                ));
            }
            Ok(b) => b,
        };
        if buf.len() < 32 {
            return Err(log_device_debug_errno!(
                device,
                synthetic(libc::EINVAL),
                "sd-device-monitor(",
                desc,
                "): Length of device property nulstr is too small to contain valid device information."
            ));
        }
        let subsystem = match device.get_subsystem() {
            Err(e) => {
                return Err(log_device_debug_errno!(
                    device,
                    e,
                    "sd-device-monitor(",
                    desc,
                    "): Failed to get device subsystem: ",
                    strerror(e)
                ));
            }
            Ok(s) => s,
        };
        let mut h = [0u8; HEADER_SIZE];
        h[..7].copy_from_slice(b"libudev");
        h[8..12].copy_from_slice(&UDEV_MONITOR_MAGIC.to_be().to_ne_bytes());
        h[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_ne_bytes());
        h[16..20].copy_from_slice(&(HEADER_SIZE as u32).to_ne_bytes());
        h[20..24].copy_from_slice(&(buf.len() as u32).to_ne_bytes());
        h[24..28].copy_from_slice(&string_hash32(subsystem.bytes()).to_be().to_ne_bytes());
        if let Ok(dt) = device.get_devtype() {
            h[28..32].copy_from_slice(&string_hash32(dt.bytes()).to_be().to_ne_bytes());
        }
        let mut bloom = 0u64;
        for tag in device.tags() {
            bloom |= string_bloom64(tag.bytes());
        }
        if bloom > 0 {
            h[32..36].copy_from_slice(&((bloom >> 32) as u32).to_be().to_ne_bytes());
            h[36..40].copy_from_slice(&((bloom & 0xffff_ffff) as u32).to_be().to_ne_bytes());
        }
        let (pid, groups) = destination.unwrap_or((0, MonitorGroup::Udev as u32));
        match sys_net::sendmsg_netlink(self.sock.raw(), &[&h, &buf], pid, groups) {
            Err(e) if destination.is_none() && e == -libc::ECONNREFUSED => {
                log_device_debug!(device, "sd-device-monitor(", desc, "): Passed to netlink monitor.");
                Ok(0)
            }
            Err(e) => Err(log_device_debug_errno!(
                device,
                e,
                "sd-device-monitor(",
                desc,
                "): Failed to send device to netlink monitor: ",
                strerror(e)
            )),
            Ok(count) => {
                log_device_debug!(
                    device,
                    "sd-device-monitor(",
                    desc,
                    "): Passed ",
                    count.to_string(),
                    " byte to netlink monitor."
                );
                Ok(count)
            }
        }
    }

    /// `sd_device_monitor_filter_update()`.
    pub fn filter_update(&mut self) -> Result<(), i32> {
        if self.filter_uptodate {
            return Ok(());
        }
        if self.nl_groups == MonitorGroup::Kernel as u32
            || (self.subsystem_filter.is_empty() && self.tag_filter.is_empty())
        {
            self.filter_uptodate = true;
            return Ok(());
        }
        let mut ins: Vec<SockFilter> = Vec::new();
        let mut r = 0;
        let mut stmt = |ins: &mut Vec<SockFilter>, code: u16, k: u32| {
            if ins.len() >= 512 {
                crate::errno::ret_gather(&mut r, -libc::E2BIG);
                return;
            }
            ins.push((code, 0, 0, k));
        };
        let mut jmps: Vec<(usize, u32, u32)> = Vec::new();
        // (index, jt, jf) for jumps, checked for the u8 range at the end.
        let jmp =
            |ins: &mut Vec<SockFilter>, jmps: &mut Vec<(usize, u32, u32)>, code: u16, k: u32, jt: u32, jf: u32| {
                if ins.len() >= 512 {
                    jmps.push((usize::MAX, 0, 0));
                    return;
                }
                jmps.push((ins.len(), jt, jf));
                ins.push((code, jt as u8, jf as u8, k));
            };
        // load magic in A; jump if it matches; wrong magic: pass the packet
        stmt(&mut ins, BPF_LD | BPF_W | BPF_ABS, OFF_MAGIC);
        jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
        stmt(&mut ins, BPF_RET | BPF_K, 0xffff_ffff);
        if !self.tag_filter.is_empty() {
            let mut tag_matches = self.tag_filter.len() as u32;
            for tag in &self.tag_filter {
                let bloom = string_bloom64(tag);
                let hi = (bloom >> 32) as u32;
                let lo = (bloom & 0xffff_ffff) as u32;
                stmt(&mut ins, BPF_LD | BPF_W | BPF_ABS, OFF_BLOOM_HI);
                stmt(&mut ins, BPF_ALU | BPF_AND | BPF_K, hi);
                jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, hi, 0, 3);
                stmt(&mut ins, BPF_LD | BPF_W | BPF_ABS, OFF_BLOOM_LO);
                stmt(&mut ins, BPF_ALU | BPF_AND | BPF_K, lo);
                tag_matches -= 1;
                jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, lo, 1 + tag_matches * 6, 0);
            }
            stmt(&mut ins, BPF_RET | BPF_K, 0);
        }
        if !self.subsystem_filter.is_empty() {
            for (subsystem, devtype) in &self.subsystem_filter {
                let hash = string_hash32(subsystem);
                stmt(&mut ins, BPF_LD | BPF_W | BPF_ABS, OFF_SUBSYSTEM_HASH);
                match devtype {
                    None => jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, hash, 0, 1),
                    Some(dt) => {
                        jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, hash, 0, 3);
                        stmt(&mut ins, BPF_LD | BPF_W | BPF_ABS, OFF_DEVTYPE_HASH);
                        jmp(&mut ins, &mut jmps, BPF_JMP | BPF_JEQ | BPF_K, string_hash32(dt), 0, 1);
                    }
                }
                stmt(&mut ins, BPF_RET | BPF_K, 0xffff_ffff);
            }
            stmt(&mut ins, BPF_RET | BPF_K, 0);
        }
        stmt(&mut ins, BPF_RET | BPF_K, 0xffff_ffff);
        for &(i, jt, jf) in &jmps {
            if i == usize::MAX || jt > 255 || jf > 255 {
                crate::errno::ret_gather(&mut r, -libc::E2BIG);
            }
        }
        if r < 0 {
            return Err(r);
        }
        sys_net::attach_filter(self.sock.raw(), &ins)?;
        self.filter_uptodate = true;
        Ok(())
    }

    /// `sd_device_monitor_filter_add_match_subsystem_devtype()`.
    /// QUIRK: always adds, duplicates too (C keys the hashmap by pointer).
    pub fn filter_add_match_subsystem_devtype(&mut self, subsystem: &[u8], devtype: Option<&[u8]>) -> bool {
        self.subsystem_filter.push((subsystem.to_vec(), devtype.map(|d| d.to_vec())));
        self.filter_uptodate = false;
        true
    }

    /// `sd_device_monitor_filter_add_match_tag()`.
    pub fn filter_add_match_tag(&mut self, tag: &[u8]) -> bool {
        if !self.tag_filter.insert(tag.to_vec()) {
            return false;
        }
        self.filter_uptodate = false;
        true
    }

    /// `sd_device_monitor_filter_add_match_sysattr()`.
    pub fn filter_add_match_sysattr(&mut self, sysattr: &[u8], value: Option<&[u8]>, m: bool) -> bool {
        let h = if m { &mut self.match_sysattr_filter } else { &mut self.nomatch_sysattr_filter };
        update_match_strv(h, sysattr, value, true)
    }

    /// `sd_device_monitor_filter_add_match_parent()`.
    pub fn filter_add_match_parent(&mut self, device: &Device, m: bool) -> bool {
        let syspath = device.get_syspath().bytes().to_vec();
        let set = if m { &mut self.match_parent_filter } else { &mut self.nomatch_parent_filter };
        set.get_or_insert_with(BTreeSet::new).insert(syspath)
    }

    /// `sd_device_monitor_filter_remove()`.
    pub fn filter_remove(&mut self) -> Result<(), i32> {
        self.subsystem_filter.clear();
        self.tag_filter.clear();
        self.match_sysattr_filter.clear();
        self.nomatch_sysattr_filter.clear();
        self.match_parent_filter = None;
        self.nomatch_parent_filter = None;
        sys_net::detach_filter(self.sock.raw())?;
        self.filter_uptodate = true;
        Ok(())
    }
}

/// `fd_set_rcvbuf(fd, n, increase)`: Ok(false) if already so.
pub fn fd_set_rcvbuf(fd: i32, n: usize, increase: bool) -> Result<bool, i32> {
    if n > i32::MAX as usize {
        return Err(-libc::ERANGE);
    }
    let ok = |v: Result<i32, i32>| match v {
        Ok(v) => {
            if increase {
                v as usize >= n * 2
            } else {
                v as usize == n * 2
            }
        }
        // C's precedence makes a failed getsockopt() fall to the test as well,
        // with an indeterminate value; treat it as not done.
        Err(_) => false,
    };
    if ok(sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)) {
        return Ok(false);
    }
    sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, n as i32)?;
    if ok(sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)) {
        return Ok(true);
    }
    sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, n as i32)?;
    Ok(true)
}

/// `next_datagram_size_fd()`.
pub fn next_datagram_size_fd(fd: i32) -> Result<usize, i32> {
    match sys_net::recv_peek_trunc(fd) {
        Ok(l) if l > 0 => return Ok(l as usize),
        Ok(_) => {}
        Err(e) if e == -libc::EOPNOTSUPP || e == -libc::EFAULT => {}
        Err(e) => return Err(e),
    }
    Ok(sys_net::fionread(fd)? as usize)
}

/// `flush_fd()`: read and drop everything queued; the bytes dropped.
pub fn flush_fd(fd: i32) -> Result<i32, i32> {
    let mut count: i32 = 0;
    let mut buf = [0u8; crate::log::LINE_MAX];
    loop {
        match sys_net::poll_one(fd, libc::POLLIN, 0) {
            Err(e) if e == -libc::EINTR => continue,
            Err(e) => return Err(e),
            Ok(0) => return Ok(count),
            Ok(_) => {}
        }
        match sys::read(fd, &mut buf) {
            Err(e) if e == -libc::EINTR => continue,
            Err(e) if e == -libc::EAGAIN => return Ok(count),
            Err(e) => return Err(e),
            Ok(0) => return Ok(count),
            Ok(l) => {
                if l as i64 > (i32::MAX - count) as i64 {
                    return Ok(i32::MAX);
                }
                count += l as i32;
            }
        }
    }
}

/// `dev_is_devtmpfs()`: None for an error.
fn dev_is_devtmpfs() -> Option<bool> {
    let st = crate::stat_util::xstatx_full(
        libc::AT_FDCWD,
        Some(b"/dev"),
        libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC,
        libc::STATX_MNT_ID,
        0,
        0,
    )
    .ok()?;
    let mount_id = st.stx_mnt_id;
    let data = crate::fileio::read_full_file_with_nuls(b"/proc/self/mountinfo").ok()?;
    for line in data.split(|&c| c == b'\n') {
        let n = line.iter().take_while(|c| c.is_ascii_digit()).count();
        let Ok(mid) = crate::parse::safe_atou64(&line[..n]) else {
            continue;
        };
        if mid != mount_id {
            continue;
        }
        let Some(i) = line.windows(3).position(|w| w == b" - ") else {
            continue;
        };
        if line[i + 3..].starts_with(b"devtmpfs") {
            return Some(true);
        }
    }
    Some(false)
}

/// `network_namespace_is_init(fd)`.
fn network_namespace_is_init(fd: i32) -> Result<bool, i32> {
    let a = match sys::stat(b"/proc/1/ns/net") {
        Err(e) if e == -libc::ENOENT => {
            return match crate::fs::proc_mounted_full() {
                Err(_) => Err(-libc::ENOENT),
                Ok(true) => Ok(true),
                Ok(false) => Err(-libc::ENOSYS),
            };
        }
        r => r?,
    };
    const SIOCGSKNS: u64 = 0x894C;
    let netns = OwnedFd::new(sys::ioctl_none(fd, SIOCGSKNS)?);
    let b = sys::fstat(netns.raw())?;
    Ok(a.st_dev == b.st_dev && a.st_ino == b.st_ino)
}
