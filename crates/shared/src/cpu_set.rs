// SPDX-License-Identifier: LGPL-2.1-or-later
//! `cpu-set-util.c` and `numa-util.c`: CPU sets as `.link` files and the
//! IRQ affinity code use them.

use crate::errno::strerror;
use crate::{log_debug, log_debug_errno, log_syntax};

const CPU_SET_MAX_NCPU: usize = 8192;
/// `__NCPUBITS`: the bits of a `__cpu_mask` (an unsigned long).
const NCPUBITS: usize = usize::BITS as usize;

/// A `CPUSet`: `allocated` bytes of bits (`CPU_ALLOC_SIZE()` rounding).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuSet {
    bits: Vec<u8>,
}

impl CpuSet {
    /// Whether C's `set` pointer is non-NULL.
    pub fn is_set(&self) -> bool {
        !self.bits.is_empty()
    }

    /// `allocated`, in bytes.
    pub fn allocated(&self) -> usize {
        self.bits.len()
    }

    /// `CPU_ISSET_S(i, allocated, set)`.
    pub fn contains(&self, i: usize) -> bool {
        self.bits.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0)
    }

    /// `CPU_COUNT_S()`.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// `cpu_set_realloc(c, n)`.
    pub fn realloc(&mut self, n: usize) -> Result<(), i32> {
        if n > CPU_SET_MAX_NCPU {
            return Err(-libc::ERANGE);
        }
        // CPU_ALLOC_SIZE(n)
        let bytes = n.div_ceil(NCPUBITS) * (NCPUBITS / 8);
        if bytes > self.bits.len() {
            self.bits.resize(bytes, 0);
        }
        Ok(())
    }

    /// `cpu_set_add(c, i)`.
    pub fn add(&mut self, i: usize) -> Result<(), i32> {
        if i >= CPU_SET_MAX_NCPU {
            return Err(-libc::ERANGE);
        }
        self.realloc(i + 1)?;
        self.bits[i / 8] |= 1 << (i % 8);
        Ok(())
    }

    /// `cpu_set_add_range(c, start, end)`.
    pub fn add_range(&mut self, start: usize, end: usize) -> Result<(), i32> {
        if end >= CPU_SET_MAX_NCPU {
            return Err(-libc::ERANGE);
        }
        self.realloc(end + 1)?;
        for i in start..=end {
            self.bits[i / 8] |= 1 << (i % 8);
        }
        Ok(())
    }

    /// `cpu_set_add_set(c, src)`.
    pub fn add_set(&mut self, src: &CpuSet) -> Result<(), i32> {
        self.realloc(src.allocated() * 8)?;
        for (d, s) in self.bits.iter_mut().zip(src.bits.iter()) {
            *d |= *s;
        }
        Ok(())
    }

    /// `cpu_set_add_all(c)`.
    pub fn add_all(&mut self) -> Result<(), i32> {
        // SAFETY: plain libc call.
        let m = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if m < 0 {
            return Err(-crate::sys::errno());
        }
        if m == 0 {
            return Err(-libc::ENXIO);
        }
        self.add_range(0, m as usize - 1)
    }

    /// `cpu_set_to_mask_string(c)`.
    pub fn to_mask_string(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut found_nonzero = false;
        let mut i = self.allocated() * 8;
        while i > 0 {
            let mut m: u32 = 0;
            let n = if i.is_multiple_of(32) { 32 } else { i % 32 };
            for j in (0..n).rev() {
                i -= 1;
                if self.contains(i) {
                    m |= 1 << j;
                }
            }
            if !found_nonzero {
                if m == 0 {
                    continue;
                }
                out.extend_from_slice(format!("{m:x}").as_bytes());
            } else {
                out.extend_from_slice(format!(",{m:08x}").as_bytes());
            }
            found_nonzero = true;
        }
        if out.is_empty() { b"0".to_vec() } else { out }
    }
}

/// `config_parse_cpu_set()` with ltype 0 (a configuration file): adds to
/// `c`.
pub fn config_parse_cpu_set(filename: &[u8], line: u32, lvalue: &[u8], rvalue: &[u8], c: &mut CpuSet) -> i32 {
    parse_cpu_set_impl(Some((filename, line, lvalue)), rvalue, c).unwrap_or_else(|r| r)
}

/// `parse_cpu_set(s, &ret)`.
pub fn parse_cpu_set(s: &[u8]) -> Result<CpuSet, i32> {
    let mut c = CpuSet::default();
    parse_cpu_set_impl(None, s, &mut c)?;
    Ok(c)
}

/// The two faces of `config_parse_cpu_set()`: `conf` is None when
/// `critical` (ltype 1).
fn parse_cpu_set_impl(conf: Option<(&[u8], u32, &[u8])>, rvalue: &[u8], c: &mut CpuSet) -> Result<i32, i32> {
    use crate::extract::{EXTRACT_UNQUOTE, extract_first_word};
    if rvalue.is_empty() {
        *c = CpuSet::default();
        return Ok(1);
    }
    let seps = crate::bcat!(crate::string::WHITESPACE, ",");
    let mut cpuset = CpuSet::default();
    let mut p = Some(rvalue);
    loop {
        let word = match extract_first_word(&mut p, Some(&seps), EXTRACT_UNQUOTE) {
            Err(r) => match conf {
                None => return Err(log_debug_errno!(r, "Failed to parse CPU set: ", rvalue)),
                Some((f, l, lv)) => {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(f),
                        l,
                        r,
                        "Failed to parse ",
                        lv,
                        "= setting, ignoring assignment: ",
                        rvalue
                    );
                    return Ok(0);
                }
            },
            Ok(None) => break,
            Ok(Some(w)) => w,
        };
        let (lower, upper) = match crate::parse::parse_range(&word) {
            Ok(x) => x,
            Err(r) => match conf {
                None => return Err(log_debug_errno!(r, "Failed to parse CPU range: ", &word[..])),
                Some((f, l, _)) => {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(f),
                        l,
                        r,
                        "Failed to parse CPU range, ignoring assignment: ",
                        &word[..]
                    );
                    continue;
                }
            },
        };
        if lower > upper {
            match conf {
                None => {
                    return Err(log_debug_errno!(
                        crate::errno::synthetic(libc::EINVAL),
                        format!("Invalid CPU range ({lower} > {upper}): "),
                        &word[..]
                    ));
                }
                Some((f, l, _)) => {
                    // C passes the stale r (0, from parse_range()).
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(f),
                        l,
                        0,
                        format!("Invalid CPU range ({lower} > {upper}), ignoring assignment: "),
                        &word[..]
                    );
                    continue;
                }
            }
        }
        if let Err(r) = cpuset.add_range(lower as usize, upper as usize) {
            match conf {
                None => return Err(log_debug_errno!(r, "Failed to set CPU(s) '", &word[..], "': ", strerror(r))),
                Some((f, l, _)) => {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(f),
                        l,
                        r,
                        "Failed to set CPU(s), ignoring assignment: ",
                        &word[..]
                    );
                }
            }
        }
    }
    if !c.is_set() {
        *c = cpuset;
        return Ok(1);
    }
    c.add_set(&cpuset)?;
    Ok(1)
}

/// `numa_node_get_cpus(node, &ret)`.
pub fn numa_node_get_cpus(node: u32) -> Result<CpuSet, i32> {
    let p = format!("/sys/devices/system/node/node{node}/cpulist");
    let (s, _) = crate::fileio::read_virtual_file(p.as_bytes(), usize::MAX)?;
    parse_cpu_set(&s)
}

/// `numa_get_node_from_cpu(cpu, &ret)`.
pub fn numa_get_node_from_cpu(cpu: u32) -> Result<u32, i32> {
    let mut d = crate::sys_net::opendir(b"/sys/devices/system/node")?;
    while let Ok(Some((name, ty))) = crate::conf_files::foreach_dirent(&mut d) {
        if ty != libc::DT_DIR {
            continue;
        }
        let Some(n) = name.strip_prefix(b"node") else { continue };
        let node = match crate::parse::safe_atou(n) {
            Ok(x) => x,
            Err(r) => {
                log_debug_errno!(r, "Failed to parse node number ", n, " to unsigned, ignoring: ", strerror(r));
                continue;
            }
        };
        let p = format!("/sys/devices/system/node/node{node}/cpulist");
        let list = match crate::fileio::read_virtual_file(p.as_bytes(), usize::MAX) {
            Ok((v, _)) => v,
            Err(r) => {
                log_debug_errno!(r, "Failed to read ", &p[..], ", ignoring: ", strerror(r));
                continue;
            }
        };
        let cpus = match parse_cpu_set(&list) {
            Ok(c) => c,
            Err(r) => {
                log_debug_errno!(r, "Failed to parse cpu set ", &list[..], ", ignoring: ", strerror(r));
                continue;
            }
        };
        if cpus.contains(cpu as usize) {
            return Ok(node);
        }
    }
    log_debug!(format!("CPU {cpu} not found in any NUMA node, assuming node 0."));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_strings() {
        let s = |v: &[usize]| {
            let mut c = CpuSet::default();
            for &i in v {
                c.add(i).unwrap();
            }
            String::from_utf8(c.to_mask_string()).unwrap()
        };
        assert_eq!(s(&[0]), "1");
        assert_eq!(s(&[0, 1, 2, 3]), "f");
        assert_eq!(s(&[7]), "80");
        assert_eq!(s(&[]), "0");
        assert_eq!(s(&(0..48).collect::<Vec<_>>()), "ffff,ffffffff");
        assert_eq!(s(&(0..72).collect::<Vec<_>>()), "ff,ffffffff,ffffffff");
        assert_eq!(parse_cpu_set(b"0-2,5").unwrap().count(), 4);
    }
}
