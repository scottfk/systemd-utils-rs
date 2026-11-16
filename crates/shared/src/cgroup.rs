// SPDX-License-Identifier: LGPL-2.1-or-later
//! The parts of `cgroup-util.c` and `unit-name.c` the ported code uses
//! (cgroup v2 only).

pub const UNIT_NAME_PLAIN: u32 = 1 << 0;
pub const UNIT_NAME_INSTANCE: u32 = 1 << 2;

const UNIT_TYPES: &[&[u8]] = &[
    b"service",
    b"socket",
    b"target",
    b"device",
    b"mount",
    b"automount",
    b"swap",
    b"timer",
    b"path",
    b"slice",
    b"scope",
];

/// `unit_name_is_valid(n, flags)` for PLAIN and INSTANCE.
pub fn unit_name_is_valid(n: &[u8], flags: u32) -> bool {
    if flags == 0 || n.is_empty() || n.len() >= 256 {
        return false;
    }
    let Some(e) = n.iter().rposition(|&c| c == b'.') else { return false };
    if e == 0 || !UNIT_TYPES.contains(&&n[e + 1..]) {
        return false;
    }
    let mut at = None;
    for (i, &c) in n[..e].iter().enumerate() {
        if c == b'@' && at.is_none() {
            at = Some(i);
        }
        if !(c.is_ascii_alphanumeric() || b":-_.\\@".contains(&c)) {
            return false;
        }
    }
    if at == Some(0) {
        return false;
    }
    if flags & UNIT_NAME_PLAIN != 0 && at.is_none() {
        return true;
    }
    if flags & UNIT_NAME_INSTANCE != 0
        && let Some(a) = at
        && e > a + 1
    {
        return true;
    }
    false
}

/// `cg_unescape()`.
fn cg_unescape(p: &[u8]) -> &[u8] {
    p.strip_prefix(b"_").unwrap_or(p)
}

/// `cg_pid_get_path(pid, &path)`: the unified hierarchy's path.
pub fn cg_pid_get_path(pid: i32) -> Result<Vec<u8>, i32> {
    let f = if pid == 0 { b"/proc/self/cgroup".to_vec() } else { format!("/proc/{pid}/cgroup").into_bytes() };
    let data = match crate::fileio::read_full_file(&f) {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ESRCH),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    for line in data.split(|&c| c == b'\n') {
        let Some(e) = line.strip_prefix(b"0:") else { continue };
        let Some(i) = e.iter().position(|&c| c == b':') else { continue };
        let mut path = e[i + 1..].to_vec();
        if path.starts_with(b"/../") {
            return Err(-libc::EUNATCH);
        }
        if path.ends_with(b" (deleted)") {
            path.truncate(path.len() - 10);
        }
        return Ok(path);
    }
    Err(-libc::ENODATA)
}

/// `valid_slice_name()`.
fn valid_slice_name(p: &[u8]) -> bool {
    p.len() >= 7 && p.ends_with(b".slice") && unit_name_is_valid(cg_unescape(p), UNIT_NAME_PLAIN)
}

/// `skip_slices()`.
fn skip_slices(mut p: &[u8]) -> &[u8] {
    loop {
        p = &p[p.iter().take_while(|&&c| c == b'/').count()..];
        let n = p.iter().position(|&c| c == b'/').unwrap_or(p.len());
        if !valid_slice_name(&p[..n]) {
            return p;
        }
        p = &p[n..];
    }
}

/// `cg_path_get_unit(path, &unit)`.
pub fn cg_path_get_unit(path: &[u8]) -> Result<Vec<u8>, i32> {
    let e = skip_slices(path);
    let n = e.iter().position(|&c| c == b'/').unwrap_or(e.len());
    if n < 3 {
        return Err(-libc::ENXIO);
    }
    let c = cg_unescape(&e[..n]);
    if !unit_name_is_valid(c, UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE) || c.ends_with(b".slice") {
        return Err(-libc::ENXIO);
    }
    Ok(c.to_vec())
}

/// `cg_pid_get_unit(pid, &unit)`, with the path shifted by PID 1's root.
pub fn cg_pid_get_unit(pid: i32) -> Result<Vec<u8>, i32> {
    let raw = cg_pid_get_path(pid)?;
    let mut root = cg_pid_get_path(1)?;
    if root.ends_with(b"/init.scope") {
        root.truncate(root.len() - 11);
    }
    let shifted = match crate::path::path_startswith(&raw, &root) {
        Some(rest) if !root.is_empty() && root != b"/" => {
            let mut s = b"/".to_vec();
            s.extend_from_slice(rest);
            s
        }
        _ => raw,
    };
    cg_path_get_unit(&shifted)
}

/// `sd_pid_get_unit(pid, &unit)`.
pub fn sd_pid_get_unit(pid: i32) -> Result<Vec<u8>, i32> {
    cg_pid_get_unit(pid).map_err(|r| if r == -libc::ENXIO || r == -libc::ENOMEDIUM { -libc::ENODATA } else { r })
}

/// `cg_get_root_path()`.
pub fn cg_get_root_path() -> Result<Vec<u8>, i32> {
    let mut p = cg_pid_get_path(1)?;
    if p.ends_with(b"/init.scope") {
        p.truncate(p.len() - 11);
    }
    Ok(p)
}

/// `physical_memory()`.
pub fn physical_memory() -> u64 {
    let ps = crate::sys::page_size() as u64;
    let mem = crate::sys::phys_pages() * ps;
    let root = match cg_get_root_path() {
        Ok(r) => r,
        Err(r) => {
            crate::log_debug_errno!(
                r,
                "Failed to determine root cgroup, ignoring cgroup memory limit: ",
                crate::errno::strerror(r)
            );
            return mem;
        }
    };
    let p = crate::path::path_join(&[b"/sys/fs/cgroup", &root, b"memory.max"]);
    let value = match crate::fileio::read_one_line_file(&p) {
        Err(r) if r == -libc::ENOENT => return mem,
        Err(r) => {
            crate::log_debug_errno!(
                r,
                "Failed to read memory.max cgroup attribute, ignoring cgroup memory limit: ",
                crate::errno::strerror(r)
            );
            return mem;
        }
        Ok(v) => v,
    };
    if value == b"max" {
        return mem;
    }
    let lim = match crate::parse::safe_atou64(&value) {
        Err(r) => {
            crate::log_debug_errno!(
                r,
                "Failed to parse cgroup memory limit '",
                &value[..],
                "', ignoring: ",
                crate::errno::strerror(r)
            );
            return mem;
        }
        Ok(v) => v,
    };
    if lim == u64::MAX {
        return mem;
    }
    mem.min(lim / ps * ps)
}
