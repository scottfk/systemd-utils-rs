// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-format.c`: `%k`, `$attr{...}` and friends.
//!
//! C formats into fixed-size buffers and reports truncation; the sizes
//! (`UDEV_NAME_SIZE` and so on) are kept, and so is what ends up in the
//! buffer when it overflows.

use shared::sd_device::Device;
use shared::{log_debug, log_device_debug, log_device_warning_errno};

use super::def::{UDEV_NAME_SIZE, UDEV_PATH_SIZE};
use super::event::Event;
use super::util::{device_get_property_value_with_fallback, udev_replace_chars, udev_replace_whitespace};

/// `UDEV_ALLOWED_CHARS_INPUT`.
pub const UDEV_ALLOWED_CHARS_INPUT: &[u8] = b"/ $%?,";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subst {
    Devnode,
    Attr,
    Env,
    Kernel,
    KernelNumber,
    Driver,
    Devpath,
    Id,
    Major,
    Minor,
    Result,
    Parent,
    Name,
    Links,
    Root,
    Sys,
}

const MAP: &[(&[u8], u8, Subst)] = &[
    (b"devnode", b'N', Subst::Devnode),
    (b"tempnode", b'N', Subst::Devnode),
    (b"attr", b's', Subst::Attr),
    (b"sysfs", b's', Subst::Attr),
    (b"env", b'E', Subst::Env),
    (b"kernel", b'k', Subst::Kernel),
    (b"number", b'n', Subst::KernelNumber),
    (b"driver", b'd', Subst::Driver),
    (b"devpath", b'p', Subst::Devpath),
    (b"id", b'b', Subst::Id),
    (b"major", b'M', Subst::Major),
    (b"minor", b'm', Subst::Minor),
    (b"result", b'c', Subst::Result),
    (b"parent", b'P', Subst::Parent),
    (b"name", b'D', Subst::Name),
    (b"links", b'L', Subst::Links),
    (b"root", b'r', Subst::Root),
    (b"sys", b'S', Subst::Sys),
];

fn type_to_string(t: Subst) -> &'static [u8] {
    MAP.iter().find(|e| e.2 == t).map(|e| e.0).expect("in the map")
}

fn type_to_char(t: Subst) -> u8 {
    MAP.iter().find(|e| e.2 == t).map(|e| e.1).expect("in the map")
}

/// `get_subst_type(&str, strict, &type, attr)`: `Ok(None)` for a plain
/// character (`*pos` then points at it, past a doubled `$$`/`%%`), or
/// the substitution and its `{attr}`.
fn get_subst_type(s: &[u8], pos: &mut usize, strict: bool) -> Result<Option<(Subst, Vec<u8>)>, i32> {
    let p = *pos;
    let mut found: Option<(usize, Subst)> = None;
    match s[p] {
        b'$' => {
            if s.get(p + 1) == Some(&b'$') {
                *pos = p + 1;
                return Ok(None);
            }
            for e in MAP {
                if s[p + 1..].starts_with(e.0) {
                    found = Some((p + 1 + e.0.len(), e.2));
                    break;
                }
            }
        }
        b'%' => {
            if s.get(p + 1) == Some(&b'%') {
                *pos = p + 1;
                return Ok(None);
            }
            for e in MAP {
                if s.get(p + 1) == Some(&e.1) {
                    found = Some((p + 2, e.2));
                    break;
                }
            }
        }
        _ => return Ok(None),
    }
    let Some((mut q, t)) = found else {
        return if strict { Err(-libc::EINVAL) } else { Ok(None) };
    };
    let attr = if s.get(q) == Some(&b'{') {
        let start = q + 1;
        let Some(len) = s[start..].iter().position(|&b| b == b'}') else {
            return Err(-libc::EINVAL);
        };
        if len == 0 || len >= UDEV_PATH_SIZE {
            return Err(-libc::EINVAL);
        }
        q = start + len + 1;
        s[start..start + len].to_vec()
    } else {
        Vec::new()
    };
    *pos = q;
    Ok(Some((t, attr)))
}

/// `safe_atou_optional_plus(s)`: (number, has plus).
fn safe_atou_optional_plus(s: &[u8]) -> Result<(u32, bool), i32> {
    let (s, plus) = match s.strip_suffix(b"+") {
        Some(t) => (t, true),
        None => (s, false),
    };
    Ok((shared::parse::safe_atou(s)?, plus))
}

/// A `char *dest` with `l` bytes left (the NUL included), as
/// `strpcpy_full()` and friends fill it.
struct Dest<'a> {
    out: &'a mut Vec<u8>,
    l: usize,
    truncated: bool,
}

impl Dest<'_> {
    /// `strnpcpy_full(&s, l, src, len, &t)`.
    fn cpy(&mut self, src: &[u8]) {
        let len = src.len();
        if self.l == 0 {
            self.truncated = len > 0;
            return;
        }
        if len >= self.l {
            if self.l > 1 {
                self.out.extend_from_slice(&src[..self.l - 1]);
            }
            self.l = 0;
            self.truncated = true;
        } else {
            self.out.extend_from_slice(src);
            self.l -= len;
            self.truncated = false;
        }
    }
    /// `strpcpyl_full(&s, l, &t, a, b, NULL)`.
    fn cpyl(&mut self, parts: &[&[u8]]) {
        let mut t = false;
        for p in parts {
            self.cpy(p);
            t = t || self.truncated;
        }
        self.truncated = t;
    }
}

fn is_ws(c: u8) -> bool {
    shared::string::WHITESPACE.contains(&c)
}

/// `udev_event_subst_format()`: appends to `out` with `l` bytes of room;
/// Ok(truncated).
fn subst_format(event: &Event, t: Subst, attr: &[u8], out: &mut Vec<u8>, l: usize) -> Result<bool, i32> {
    let dev = &event.dev;
    let mut d = Dest { out, l, truncated: false };
    match t {
        Subst::Devpath => d.cpy(dev.get_devpath().bytes()),
        Subst::Kernel => d.cpy(dev.get_sysname()?.bytes()),
        Subst::KernelNumber => match dev.get_sysnum() {
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(r),
            Ok(v) => d.cpy(v.bytes()),
        },
        Subst::Id => {
            if let Some(p) = &event.dev_parent {
                d.cpy(p.get_sysname()?.bytes());
            }
        }
        Subst::Driver => {
            if let Some(p) = &event.dev_parent {
                match p.get_driver() {
                    Err(r) if r == -libc::ENOENT => {}
                    Err(r) => return Err(r),
                    Ok(v) => d.cpy(v.bytes()),
                }
            }
        }
        Subst::Major | Subst::Minor => {
            let n = match dev.get_devnum() {
                Ok(devnum) => {
                    if t == Subst::Major {
                        libc::major(devnum)
                    } else {
                        libc::minor(devnum)
                    }
                }
                Err(r) if r == -libc::ENOENT => 0,
                Err(r) => return Err(r),
            };
            // strpcpyf_full(): on overflow nothing counts as written.
            let s = n.to_string();
            if s.len() < d.l {
                d.out.extend_from_slice(s.as_bytes());
                d.l -= s.len();
            } else {
                d.l = 0;
                d.truncated = true;
            }
        }
        Subst::Result => {
            let Some(result) = &event.program_result else {
                return Ok(d.truncated);
            };
            let (index, has_plus) = if attr.is_empty() { (0, false) } else { safe_atou_optional_plus(attr)? };
            if index == 0 {
                d.cpy(result);
            } else {
                let mut p = result.iter().take_while(|&&c| is_ws(c)).count();
                let mut i = 1;
                while i < index {
                    while p < result.len() && !is_ws(result[p]) {
                        p += 1;
                    }
                    while p < result.len() && is_ws(result[p]) {
                        p += 1;
                    }
                    if p >= result.len() {
                        break;
                    }
                    i += 1;
                }
                if i != index {
                    log_device_debug!(dev, "requested part of result string not found");
                    return Ok(d.truncated);
                }
                let start = p;
                if has_plus {
                    d.cpy(&result[start..]);
                } else {
                    while p < result.len() && !is_ws(result[p]) {
                        p += 1;
                    }
                    d.cpy(&result[start..p]);
                }
            }
        }
        Subst::Attr => {
            if attr.is_empty() {
                return Err(-libc::EINVAL);
            }
            let mut val: Option<Vec<u8>> = None;
            let mut from_vbuf = false;
            if let Ok(v) = udev_resolve_subsys_kernel(attr, UDEV_NAME_SIZE, true) {
                val = Some(v);
                from_vbuf = true;
            }
            if val.is_none() {
                val = dev.get_sysattr_value(attr).ok().map(|v| v.bytes().to_vec());
            }
            if val.is_none()
                && let Some(p) = &event.dev_parent
                && !std::rc::Rc::ptr_eq(p, dev)
            {
                val = p.get_sysattr_value(attr).ok().map(|v| v.bytes().to_vec());
            }
            let Some(val) = val else {
                return Ok(d.truncated);
            };
            let mut truncated = false;
            let mut vbuf = if from_vbuf {
                val
            } else if val.len() >= UDEV_NAME_SIZE {
                truncated = true;
                val[..UDEV_NAME_SIZE - 1].to_vec()
            } else {
                val
            };
            let n = shared::string::delete_trailing_chars(&vbuf, None).len();
            vbuf.truncate(n);
            let count = udev_replace_chars(&mut vbuf, Some(UDEV_ALLOWED_CHARS_INPUT));
            if count > 0 {
                log_device_debug!(dev, count.to_string(), " character(s) replaced");
            }
            d.cpy(&vbuf);
            d.truncated = truncated || d.truncated;
        }
        Subst::Parent => {
            let parent = match dev.get_parent() {
                Err(r) if r == -libc::ENOENT => return Ok(d.truncated),
                Err(r) => return Err(r),
                Ok(p) => p,
            };
            match parent.get_devname() {
                Err(r) if r == -libc::ENOENT => {}
                Err(r) => return Err(r),
                Ok(v) => d.cpy(&v.bytes()[5..]),
            }
        }
        Subst::Devnode => match dev.get_devname() {
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(r),
            Ok(v) => d.cpy(v.bytes()),
        },
        Subst::Name => {
            if let Some(n) = &event.name {
                d.cpy(n);
            } else if let Ok(v) = dev.get_devname() {
                d.cpy(&v.bytes()[5..]);
            } else {
                d.cpy(dev.get_sysname()?.bytes());
            }
        }
        Subst::Links => {
            let start = d.out.len();
            for link in dev.devlinks() {
                let lk = &link.bytes()[5..];
                if d.out.len() == start {
                    d.cpy(lk);
                } else {
                    d.cpyl(&[b" ", lk]);
                }
                if d.truncated {
                    break;
                }
            }
        }
        Subst::Root => d.cpy(b"/dev"),
        Subst::Sys => d.cpy(b"/sys"),
        Subst::Env => {
            if attr.is_empty() {
                return Err(-libc::EINVAL);
            }
            match device_get_property_value_with_fallback(dev, attr, event.worker_properties.as_deref()) {
                Err(r) if r == -libc::ENOENT => {}
                Err(r) => return Err(r),
                Ok(v) => d.cpy(&v),
            }
        }
    }
    Ok(d.truncated)
}

/// `udev_event_apply_format(event, src, dest, size, replace_whitespace,
/// &truncated)`: (the result, truncated).
pub fn udev_event_apply_format(event: &Event, src: &[u8], size: usize, replace_whitespace: bool) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut size = size;
    let mut truncated = false;
    let mut s = 0;
    while s < src.len() {
        match get_subst_type(src, &mut s, false) {
            Err(r) => {
                log_device_warning_errno!(event.dev, r, "Invalid format string, ignoring: ", src);
                break;
            }
            Ok(None) => {
                if size < 2 {
                    truncated = true;
                    break;
                }
                out.push(src[s]);
                s += 1;
                size -= 1;
            }
            Ok(Some((t, attr))) => {
                let start = out.len();
                let t_ = match subst_format(event, t, &attr, &mut out, size) {
                    Ok(x) => x,
                    Err(r) => {
                        out.truncate(start);
                        log_device_warning_errno!(
                            event.dev,
                            r,
                            "Failed to substitute variable '$",
                            type_to_string(t),
                            "' or apply format '%",
                            [type_to_char(t)],
                            "', ignoring: ",
                            shared::errno::strerror(r)
                        );
                        break;
                    }
                };
                truncated = truncated || t_;
                let mut subst_len = out.len() - start;
                if replace_whitespace && t != Subst::Result {
                    let r = udev_replace_whitespace(&out[start..], subst_len);
                    out.truncate(start);
                    out.extend_from_slice(&r);
                    subst_len = r.len();
                }
                size -= subst_len;
            }
        }
    }
    (out, truncated)
}

/// `udev_check_format(value, &offset, &hint)`: Err((offset, hint)).
pub fn udev_check_format(value: &[u8]) -> Result<(), (usize, &'static str)> {
    let mut s = 0;
    while s < value.len() {
        match get_subst_type(value, &mut s, true) {
            Err(_) => return Err((s, "invalid substitution type")),
            Ok(None) => s += 1,
            Ok(Some((t, attr))) => {
                if matches!(t, Subst::Attr | Subst::Env) && attr.is_empty() {
                    return Err((s, "attribute value missing"));
                }
                if t == Subst::Result && !attr.is_empty() && safe_atou_optional_plus(&attr).is_err() {
                    return Err((s, "attribute value not a valid number"));
                }
            }
        }
    }
    Ok(())
}

/// `udev_resolve_subsys_kernel(string, result, maxsize, read_value)`.
pub fn udev_resolve_subsys_kernel(string: &[u8], maxsize: usize, read_value: bool) -> Result<Vec<u8>, i32> {
    if string.first() != Some(&b'[') {
        return Err(-libc::EINVAL);
    }
    let temp = &string[1..];
    let Some(slash) = temp.iter().position(|&b| b == b'/') else {
        return Err(-libc::EINVAL);
    };
    let subsys = &temp[..slash];
    let rest = &temp[slash + 1..];
    let Some(close) = rest.iter().position(|&b| b == b']') else {
        return Err(-libc::EINVAL);
    };
    let sysname = &rest[..close];
    let mut attr = &rest[close + 1..];
    if attr.first() == Some(&b'/') {
        attr = &attr[1..];
    }
    let attr: Option<&[u8]> = if attr.is_empty() { None } else { Some(attr) };
    if read_value && attr.is_none() {
        return Err(-libc::EINVAL);
    }
    let dev = Device::new_from_subsystem_sysname(subsys, sysname)?;
    if read_value {
        let attr = attr.expect("checked");
        let result = match dev.get_sysattr_value(attr) {
            Ok(v) => strscpy(v.bytes(), maxsize),
            Err(r) if shared::errno::is_neg_privilege(r) || r == -libc::ENOENT => Vec::new(),
            Err(r) => return Err(r),
        };
        log_debug!("value '[", subsys, "/", sysname, "]", attr, "' is '", &result, "'");
        Ok(result)
    } else {
        let sp = dev.get_syspath();
        let result = match attr {
            Some(a) => strscpy(&shared::bcat!(sp.bytes(), "/", a), maxsize),
            None => strscpy(sp.bytes(), maxsize),
        };
        log_debug!("path '[", subsys, "/", sysname, "]", attr.unwrap_or_default(), "' is '", &result, "'");
        Ok(result)
    }
}

/// `strscpy(dest, size, src)`: what fits in `size` bytes with the NUL.
pub fn strscpy(src: &[u8], size: usize) -> Vec<u8> {
    if src.len() >= size { src[..size.saturating_sub(1)].to_vec() } else { src.to_vec() }
}
