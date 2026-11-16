// SPDX-License-Identifier: LGPL-2.1-or-later
//! `architecture.c`, `virt.c` (for x86) and `confidential-virt.c`: what
//! udev's `CONST{arch}`, `CONST{virt}` and `CONST{cvm}` compare against,
//! and whether we run in a container (which decides where the kernel
//! command line is read).

use std::sync::OnceLock;

use crate::errno::strerror;
use crate::fileio::{LONG_LINE_MAX, fopen_re, read_line, read_one_line_file};
use crate::sys;
use crate::{log_debug, log_debug_errno};

/// `Architecture`, for the machines this build runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
}

/// `uname_architecture()`.
pub fn uname_architecture() -> Architecture {
    match sys::uname_machine().as_slice() {
        b"x86_64" => Architecture::X86_64,
        b"i686" | b"i586" | b"i486" | b"i386" => Architecture::X86,
        m => panic!("unknown machine {}", String::from_utf8_lossy(m)),
    }
}

/// `architecture_to_string()`.
pub fn architecture_to_string(a: Architecture) -> Option<&'static str> {
    Some(match a {
        Architecture::X86 => "x86",
        Architecture::X86_64 => "x86-64",
    })
}

/// `Virtualization`, by its name in `virtualization_table`.
pub type Virtualization = &'static str;

pub const NONE: Virtualization = "none";
const VM_OTHER: Virtualization = "vm-other";
const CONTAINER_OTHER: Virtualization = "container-other";

/// `virtualization_to_string()`.
pub fn virtualization_to_string(v: Virtualization) -> Option<&'static str> {
    Some(v)
}

const CONTAINERS: &[&str] =
    &["lxc", "lxc-libvirt", "systemd-nspawn", "docker", "podman", "rkt", "wsl", "proot", "pouch"];

/// `detect_vm_cpuid()`.
fn detect_vm_cpuid() -> Virtualization {
    const TABLE: &[(&[u8], Virtualization)] = &[
        (b"XenVMMXenVMM", "xen"),
        (b"KVMKVMKVM", "kvm"),
        (b"Linux KVM Hv", "kvm"),
        (b"TCGTCGTCGTCG", "qemu"),
        (b"VMwareVMware", "vmware"),
        (b"Microsoft Hv", "microsoft"),
        (b"bhyve bhyve ", "bhyve"),
        (b"QNXQVMBSQG", "qnx"),
        (b"ACRNACRNACRN", "acrn"),
        (b"SRESRESRESRE", "sre"),
        (b"Apple VZ", "apple"),
    ];
    let (max, ..) = sys::cpuid_count(0, 0);
    if max < 1 {
        return NONE;
    }
    let (_, _, ecx, _) = sys::cpuid_count(1, 0);
    if ecx & 0x8000_0000 != 0 {
        let (_, ebx, ecx, edx) = sys::cpuid_count(0x4000_0000, 0);
        let mut sig = [0u8; 12];
        sig[0..4].copy_from_slice(&ebx.to_le_bytes());
        sig[4..8].copy_from_slice(&ecx.to_le_bytes());
        sig[8..12].copy_from_slice(&edx.to_le_bytes());
        let text = &sig[..sig.iter().position(|&b| b == 0).unwrap_or(12)];
        log_debug!("Virtualization found, CPUID=", text);
        for (s, id) in TABLE {
            let mut padded = [0u8; 12];
            padded[..s.len()].copy_from_slice(s);
            if padded == sig {
                return id;
            }
        }
        log_debug!("Unknown virtualization with CPUID=", text, ". Add to vm_table[]?");
        return VM_OTHER;
    }
    log_debug!("No virtualization found in CPUID");
    NONE
}

/// `detect_vm_dmi_vendor()`.
fn detect_vm_dmi_vendor() -> Result<Virtualization, i32> {
    const FILES: &[&[u8]] = &[
        b"/sys/class/dmi/id/product_name",
        b"/sys/class/dmi/id/sys_vendor",
        b"/sys/class/dmi/id/board_vendor",
        b"/sys/class/dmi/id/bios_vendor",
        b"/sys/class/dmi/id/product_version",
    ];
    const TABLE: &[(&[u8], Virtualization)] = &[
        (b"KVM", "kvm"),
        (b"OpenStack", "kvm"),
        (b"KubeVirt", "kvm"),
        (b"Alibaba Cloud ECS", "kvm"),
        (b"Amazon EC2", "amazon"),
        (b"QEMU", "qemu"),
        (b"VMware", "vmware"),
        (b"VMW", "vmware"),
        (b"innotek GmbH", "oracle"),
        (b"VirtualBox", "oracle"),
        (b"Oracle Corporation", "oracle"),
        (b"Xen", "xen"),
        (b"Bochs", "bochs"),
        (b"Parallels", "parallels"),
        (b"BHYVE", "bhyve"),
        (b"Hyper-V", "microsoft"),
        (b"Apple Virtualization", "apple"),
        (b"Google Compute Engine", "google"),
    ];
    for f in FILES {
        let s = match read_one_line_file(f) {
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => return Err(r),
            Ok(s) => s,
        };
        for (v, id) in TABLE {
            if s.starts_with(v) {
                log_debug!("Virtualization ", &s, " found in DMI (", f, ")");
                return Ok(id);
            }
        }
    }
    log_debug!("No virtualization found in DMI vendor table.");
    Ok(NONE)
}

#[derive(PartialEq)]
enum SmbiosBit {
    Set,
    Unset,
    Unknown,
}

/// `detect_vm_smbios()`.
fn detect_vm_smbios() -> SmbiosBit {
    let s = match crate::fileio::read_virtual_file(b"/sys/firmware/dmi/entries/0-0/raw", usize::MAX) {
        Err(r) => {
            log_debug_errno!(
                r,
                "Unable to read /sys/firmware/dmi/entries/0-0/raw, using the virtualization information found in DMI vendor table, ignoring: ",
                strerror(r)
            );
            return SmbiosBit::Unknown;
        }
        Ok((s, _)) => s,
    };
    if s.len() < 20 || (s[1] as i8) < 20 {
        log_debug!(
            "Only read ",
            s.len().to_string(),
            " bytes from /sys/firmware/dmi/entries/0-0/raw (expected 20). Using the virtualization information found in DMI vendor table."
        );
        return SmbiosBit::Unknown;
    }
    if s[19] & (1 << 4) != 0 {
        log_debug!("DMI BIOS Extension table indicates virtualization.");
        return SmbiosBit::Set;
    }
    log_debug!("DMI BIOS Extension table does not indicate virtualization.");
    SmbiosBit::Unset
}

/// `detect_vm_dmi()`.
fn detect_vm_dmi() -> Result<Virtualization, i32> {
    let r = detect_vm_dmi_vendor()?;
    if r == "amazon" {
        return Ok(match detect_vm_smbios() {
            SmbiosBit::Set => "amazon",
            SmbiosBit::Unset => NONE,
            SmbiosBit::Unknown => {
                match crate::fileio::read_virtual_file(b"/sys/class/dmi/id/product_name", usize::MAX) {
                    Err(e) => {
                        log_debug_errno!(
                            e,
                            "Can't read /sys/class/dmi/id/product_name, assuming virtualized: ",
                            strerror(e)
                        );
                        "amazon"
                    }
                    Ok((s, _)) => {
                        let s = crate::string::delete_trailing_chars(&s, Some(b"\n"));
                        let metal = s
                            .windows(6)
                            .position(|w| w == b".metal")
                            .is_some_and(|k| matches!(s.get(k + 6), None | Some(b'-')));
                        if metal {
                            log_debug!("DMI product name has '.metal', assuming no virtualization");
                            NONE
                        } else {
                            "amazon"
                        }
                    }
                }
            }
        });
    }
    if r == NONE && detect_vm_smbios() == SmbiosBit::Set {
        return Ok(VM_OTHER);
    }
    Ok(r)
}

/// `detect_vm_xen_dom0()`: Ok(true) for dom0.
fn detect_vm_xen_dom0() -> Result<bool, i32> {
    const FEATURES: &str = "/sys/hypervisor/properties/features";
    match read_one_line_file(FEATURES.as_bytes()) {
        Err(r) if r != -libc::ENOENT => return Err(r),
        Err(_) => {}
        Ok(domcap) => {
            let hex: Vec<u8> = domcap
                .iter()
                .copied()
                .skip_while(|c| c.is_ascii_whitespace())
                .take_while(u8::is_ascii_hexdigit)
                .collect();
            if let Ok(features) = u64::from_str_radix(std::str::from_utf8(&hex).unwrap_or(""), 16) {
                let dom0 = features & (1 << 11) != 0;
                log_debug!(
                    "Virtualization XEN, found ",
                    FEATURES,
                    format!(" with value {features:08x}"),
                    ", XENFEAT_dom0 (indicating the 'hardware domain') is",
                    if dom0 { "" } else { " not" },
                    " set."
                );
                return Ok(dom0);
            }
            log_debug!("Virtualization XEN, found ", FEATURES, ", unhandled content '", &domcap, "'");
        }
    }
    let domcap = match read_one_line_file(b"/proc/xen/capabilities") {
        Err(r) if r == -libc::ENOENT => {
            log_debug!("Virtualization XEN because /proc/xen/capabilities does not exist");
            return Ok(false);
        }
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    let mut p = Some(&domcap[..]);
    loop {
        match crate::extract::extract_first_word(&mut p, Some(b","), 0)? {
            None => {
                log_debug!("Virtualization XEN DomU found (/proc/xen/capabilities)");
                return Ok(false);
            }
            Some(cap) if cap == b"control_d" => {
                log_debug!("Virtualization XEN Dom0 ignored (/proc/xen/capabilities)");
                return Ok(true);
            }
            Some(_) => {}
        }
    }
}

/// `detect_vm_xen()`.
fn detect_vm_xen() -> Virtualization {
    if crate::sys_net::access(b"/proc/xen", libc::F_OK).is_err() {
        log_debug!("Virtualization XEN not found, /proc/xen does not exist");
        return NONE;
    }
    log_debug!("Virtualization XEN found (/proc/xen exists)");
    "xen"
}

/// `detect_vm_hypervisor()`.
fn detect_vm_hypervisor() -> Result<Virtualization, i32> {
    let t = match read_one_line_file(b"/sys/hypervisor/type") {
        Err(r) if r == -libc::ENOENT => return Ok(NONE),
        Err(r) => return Err(r),
        Ok(t) => t,
    };
    log_debug!("Virtualization ", &t, " found in /sys/hypervisor/type");
    Ok(if t == b"xen" { "xen" } else { VM_OTHER })
}

/// `detect_vm_uml()`.
fn detect_vm_uml() -> Result<Virtualization, i32> {
    let mut f = match fopen_re(b"/proc/cpuinfo") {
        Err(r) if r == -libc::ENOENT => {
            log_debug!("/proc/cpuinfo not found, assuming no UML virtualization.");
            return Ok(NONE);
        }
        Err(r) => return Err(r),
        Ok(f) => f,
    };
    loop {
        let line = match read_line(&mut f, LONG_LINE_MAX)? {
            (0, _) => break,
            (_, l) => l,
        };
        if let Some(t) = line.strip_prefix(b"vendor_id\t: ") {
            if t.starts_with(b"User Mode Linux") {
                log_debug!("UML virtualization found in /proc/cpuinfo");
                return Ok("uml");
            }
            break;
        }
    }
    log_debug!("UML virtualization not found in /proc/cpuinfo.");
    Ok(NONE)
}

/// `detect_vm()`.
pub fn detect_vm() -> Result<Virtualization, i32> {
    static CACHED: OnceLock<Virtualization> = OnceLock::new();
    if let Some(v) = CACHED.get() {
        return Ok(v);
    }
    let mut other = false;
    let mut hyperv = false;
    let mut xen_dom0 = false;
    let dmi = detect_vm_dmi();
    let v: Virtualization = 'finish: {
        if let Ok(d) = dmi
            && matches!(d, "oracle" | "xen" | "amazon" | "parallels")
        {
            break 'finish d;
        }
        let v = detect_vm_uml()?;
        if v != NONE {
            break 'finish v;
        }
        let v = detect_vm_xen();
        if v == "xen" {
            xen_dom0 = detect_vm_xen_dom0()?;
            if !xen_dom0 {
                break 'finish v;
            }
        }
        let v = detect_vm_cpuid();
        if v == "microsoft" {
            hyperv = true;
        } else if v == VM_OTHER {
            other = true;
        } else if v == "kvm" && dmi == Ok("google") {
            return Ok("google");
        } else if v != NONE {
            break 'finish v;
        }
        if xen_dom0 {
            break 'finish v;
        }
        let d = dmi?;
        if d == VM_OTHER {
            other = true;
        } else if d != NONE && d != "google" {
            break 'finish d;
        }
        let v = detect_vm_hypervisor()?;
        if v == VM_OTHER {
            other = true;
        } else if v != NONE {
            break 'finish v;
        }
        log_debug!("This platform does not support /proc/device-tree");
        log_debug!("This platform does not support /proc/sysinfo");
        NONE
    };
    let v = if v == NONE {
        if hyperv {
            "microsoft"
        } else if other {
            VM_OTHER
        } else {
            v
        }
    } else {
        v
    };
    let _ = CACHED.set(v);
    log_debug!("Found VM virtualization ", v);
    Ok(v)
}

/// `detect_container_files()`.
fn detect_container_files() -> Virtualization {
    for (path, id) in [(&b"/run/.containerenv"[..], "podman"), (b"/.dockerenv", "docker")] {
        match crate::sys_net::access(path, libc::F_OK) {
            Ok(()) => return id,
            Err(r) if r != -libc::ENOENT => {
                log_debug_errno!(r, "Checking if ", path, " exists failed, ignoring: ", strerror(r));
            }
            Err(_) => {}
        }
    }
    NONE
}

/// `getenv_for_pid(1, field)`.
fn getenv_for_pid1(field: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    if crate::log::getpid_cached() == 1 {
        return Ok(crate::env::getenv(std::str::from_utf8(field).unwrap_or("")));
    }
    let data = match crate::fileio::read_full_file_with_nuls(b"/proc/1/environ") {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ESRCH),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    for e in data.split(|&b| b == 0) {
        if let Some(v) = e.strip_prefix(field)
            && v.first() == Some(&b'=')
        {
            return Ok(Some(v[1..].to_vec()));
        }
    }
    Ok(None)
}

/// `get_proc_field("/proc/self/status", key)`.
fn get_proc_field(path: &[u8], key: &[u8]) -> Result<Vec<u8>, i32> {
    let mut f = fopen_re(path)?;
    loop {
        let line = match read_line(&mut f, LONG_LINE_MAX)? {
            (0, _) => return Err(-libc::ENODATA),
            (_, l) => l,
        };
        if let Some(l) = line.strip_prefix(key)
            && l.first() == Some(&b':')
        {
            let s = crate::string::skip_leading_chars(&l[1..], Some(b" \t"));
            let n = s.iter().position(|c| crate::string::WHITESPACE.contains(c)).unwrap_or(s.len());
            return Ok(s[..n].to_vec());
        }
    }
}

/// `translate_name:` of `detect_container()`.
fn translate_container(e: &[u8]) -> Virtualization {
    if e == b"oci" {
        let v = detect_container_files();
        return if v == NONE { CONTAINER_OTHER } else { v };
    }
    CONTAINERS.iter().find(|c| c.as_bytes() == e).copied().unwrap_or(CONTAINER_OTHER)
}

fn detect_container_uncached() -> Result<Virtualization, i32> {
    match crate::sys_net::access(b"/proc/vz", libc::F_OK) {
        Err(r) if r != -libc::ENOENT => {
            log_debug_errno!(r, "Failed to check if /proc/vz exists, ignoring: ", strerror(r));
        }
        Err(_) => {}
        Ok(()) => match crate::sys_net::access(b"/proc/bc", libc::F_OK) {
            Err(r) if r == -libc::ENOENT => return Ok("openvz"),
            Err(r) => {
                log_debug_errno!(r, "Failed to check if /proc/bc exists, ignoring: ", strerror(r));
            }
            Ok(()) => {}
        },
    }
    match read_one_line_file(b"/proc/sys/kernel/osrelease") {
        Err(r) => {
            log_debug_errno!(r, "Failed to read /proc/sys/kernel/osrelease, ignoring: ", strerror(r));
        }
        Ok(o) => {
            if o.windows(9).any(|w| w == b"Microsoft") || o.windows(3).any(|w| w == b"WSL") {
                return Ok("wsl");
            }
        }
    }
    match get_proc_field(b"/proc/self/status", b"TracerPid") {
        Err(r) => {
            log_debug_errno!(r, "Failed to read our own trace PID, ignoring: ", strerror(r));
        }
        Ok(p) if p != b"0" => match crate::parse::safe_atoi(&p) {
            Ok(pid) if pid > 0 => {
                let pf = format!("/proc/{pid}/comm");
                match read_one_line_file(pf.as_bytes()) {
                    Err(r) => {
                        log_debug_errno!(r, "Failed to read ", pf, ", ignoring: ", strerror(r));
                    }
                    Ok(c) if c.starts_with(b"proot") => return Ok("proot"),
                    Ok(_) => {}
                }
            }
            Ok(_) => {
                log_debug_errno!(
                    -libc::EINVAL,
                    "Failed to parse our own tracer PID, ignoring: ",
                    strerror(-libc::EINVAL)
                );
            }
            Err(r) => {
                log_debug_errno!(r, "Failed to parse our own tracer PID, ignoring: ", strerror(r));
            }
        },
        Ok(_) => {}
    }
    match read_one_line_file(b"/run/host/container-manager") {
        Ok(m) if !m.is_empty() => return Ok(translate_container(&m)),
        Ok(_) => {}
        Err(r) if r == -libc::ENOENT => {}
        Err(r) => return Err(log_debug_errno!(r, "Failed to read /run/host/container-manager: ", strerror(r))),
    }
    if crate::log::getpid_cached() == 1 {
        match crate::env::getenv("container") {
            None => {}
            Some(e) if e.is_empty() => return Ok(NONE),
            Some(e) => return Ok(translate_container(&e)),
        }
    } else {
        match read_one_line_file(b"/run/systemd/container") {
            Ok(m) if !m.is_empty() => return Ok(translate_container(&m)),
            Ok(_) => {}
            Err(r) if r == -libc::ENOENT => {}
            Err(r) => return Err(log_debug_errno!(r, "Failed to read /run/systemd/container: ", strerror(r))),
        }
        match getenv_for_pid1(b"container") {
            Ok(Some(m)) if !m.is_empty() => return Ok(translate_container(&m)),
            Ok(_) => {}
            Err(r) => {
                log_debug_errno!(r, "Failed to read $container of PID 1, ignoring: ", strerror(r));
            }
        }
    }
    let v = detect_container_files();
    if v != NONE {
        return Ok(v);
    }
    // The root pid namespace has inode 0xEFFFFFFC.
    match sys::stat(b"/proc/self/ns/pid") {
        Ok(st) if st.st_ino != 0xEFFF_FFFC => {
            log_debug!("Running in a pid namespace, assuming unknown container manager.");
            return Ok(CONTAINER_OTHER);
        }
        Ok(_) => {}
        Err(r) if r == -libc::ENOENT => {}
        Err(r) => {
            log_debug_errno!(r, "Failed to test if in root PID namespace, ignoring: ", strerror(r));
        }
    }
    Ok(NONE)
}

/// `detect_container()`.
pub fn detect_container() -> Result<Virtualization, i32> {
    static CACHED: OnceLock<Virtualization> = OnceLock::new();
    if let Some(v) = CACHED.get() {
        return Ok(v);
    }
    let v = detect_container_uncached()?;
    log_debug!("Found container virtualization ", v, ".");
    let _ = CACHED.set(v);
    Ok(v)
}

/// `detect_virtualization()`: a name, or an errno (`CONST{virt}` then
/// compares with NULL).
pub fn detect_virtualization() -> Result<Virtualization, i32> {
    let v = detect_container()?;
    if v != NONE {
        return Ok(v);
    }
    detect_vm()
}

// confidential-virt.c (x86_64; other architectures have none here).

fn cvm_cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    log_debug!(format!("CPUID func {eax:x} {ecx:x}"));
    let r = sys::cpuid_count(eax, ecx);
    log_debug!(format!("CPUID result {:x} {:x} {:x} {:x}", r.0, r.1, r.2, r.3));
    r
}

/// `cpuid_leaf(eax, sig, swapped)`: (eax, sig).
fn cpuid_leaf(eax: u32, swapped: bool) -> (u32, [u8; 12]) {
    let (a, b, c, d) = cvm_cpuid(eax, 0);
    let words = if swapped { [b, d, c] } else { [b, c, d] };
    let mut sig = [0u8; 12];
    for (i, w) in words.iter().enumerate() {
        sig[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let text = &sig[..sig.iter().position(|&x| x == 0).unwrap_or(12)];
    let shown: &[u8] = if crate::utf8::is_valid(text) { text } else { b"n/a" };
    log_debug!("CPUID sig '", shown, "'");
    (a, sig)
}

fn sig_is(sig: &[u8; 12], want: &[u8]) -> bool {
    let mut p = [0u8; 12];
    p[..want.len()].copy_from_slice(want);
    *sig == p
}

/// `msr(index)`.
fn msr(index: u64) -> Result<u64, i32> {
    const DEV: &str = "/dev/cpu/0/msr";
    let fd = match sys::open(DEV.as_bytes(), libc::O_RDONLY | libc::O_CLOEXEC, 0) {
        Ok(fd) => sys::OwnedFd::new(fd),
        Err(r) => {
            return Err(log_debug_errno!(
                r,
                "Cannot open MSR device ",
                DEV,
                " (index ",
                index.to_string(),
                "): ",
                strerror(r)
            ));
        }
    };
    let mut b = [0u8; 8];
    match sys::pread(fd.raw(), &mut b, index) {
        Err(r) => {
            Err(log_debug_errno!(r, "Cannot read MSR device ", DEV, " (index ", index.to_string(), "): ", strerror(r)))
        }
        Ok(8) => {
            let v = u64::from_ne_bytes(b);
            log_debug!("MSR ", index.to_string(), " result ", v.to_string());
            Ok(v)
        }
        Ok(n) => Err(log_debug_errno!(
            crate::errno::synthetic(libc::EIO),
            "Short read ",
            n.to_string(),
            " bytes from MSR device ",
            DEV,
            " (index ",
            index.to_string(),
            ")"
        )),
    }
}

fn detect_hyperv_cvm(isoltype: u32) -> bool {
    let (feat, sig) = cpuid_leaf(0x4000_0000, false);
    if !(0x4000_0005..=0x4000_ffff).contains(&feat) || !sig_is(&sig, b"Microsoft Hv") {
        return false;
    }
    log_debug!("CPUID is on hyperv");
    let (_, ebx, _, _) = cvm_cpuid(0x4000_0003, 0);
    if ebx & (1 << 22) != 0 && ebx & (1 << 12) == 0 {
        let (_, ebx, _, _) = cvm_cpuid(0x4000_000C, 0);
        if ebx & 0xf == isoltype {
            return true;
        }
    }
    false
}

fn detect_sev() -> &'static str {
    let (eax, ..) = cvm_cpuid(0x8000_0000, 0);
    if eax < 0x8000_001f {
        return "none";
    }
    let (eax, ..) = cvm_cpuid(0x8000_001f, 0);
    if eax & (1 << 1) == 0 {
        log_debug!("No sev in CPUID, trying hyperv CPUID");
        if detect_hyperv_cvm(2) {
            return "sev-snp";
        }
        log_debug!("No hyperv CPUID");
        return "none";
    }
    match msr(0xc001_0131) {
        Err(r) => {
            log_debug_errno!(r, "Failed to read SEV MSR, assuming SEV: ", strerror(r));
            "sev"
        }
        Ok(v) if v & (1 << 2) != 0 => "sev-snp",
        Ok(v) if v & (1 << 1) != 0 => "sev-es",
        Ok(v) if v & 1 != 0 => "sev",
        Ok(_) => "none",
    }
}

fn detect_tdx() -> &'static str {
    let (_, sig) = cpuid_leaf(0x21, true);
    if sig_is(&sig, b"IntelTDX    ") {
        return "tdx";
    }
    log_debug!("No tdx in CPUID, trying hyperv CPUID");
    if detect_hyperv_cvm(3) { "tdx" } else { "none" }
}

/// `ConfidentialVirtualization`, by name.
pub type ConfidentialVirtualization = &'static str;

/// `detect_confidential_virtualization()`.
pub fn detect_confidential_virtualization() -> ConfidentialVirtualization {
    static CACHED: OnceLock<&'static str> = OnceLock::new();
    CACHED.get_or_init(|| {
        if !cfg!(target_arch = "x86_64") {
            log_debug!("No confidential virtualization detection on this architecture");
            return "none";
        }
        let (_, _, ecx, _) = cvm_cpuid(1, 0);
        let is_hv = ecx & (1 << 31) != 0;
        log_debug!("CPUID is hypervisor: ", crate::string::yes_no(is_hv));
        if is_hv {
            let (_, sig) = cpuid_leaf(0, true);
            if sig_is(&sig, b"AuthenticAMD") {
                return detect_sev();
            } else if sig_is(&sig, b"GenuineIntel") {
                return detect_tdx();
            }
        }
        "none"
    })
}

/// `confidential_virtualization_to_string()`.
pub fn confidential_virtualization_to_string(v: ConfidentialVirtualization) -> Option<&'static str> {
    Some(v)
}

/// `running_in_chroot()` (`virt.c`).
pub fn running_in_chroot() -> i32 {
    match crate::env::getenv_bool("SYSTEMD_IN_CHROOT") {
        Ok(b) => return b as i32,
        Err(r) if r != -libc::ENXIO => {
            crate::log_debug_errno!(r, "Failed to parse $SYSTEMD_IN_CHROOT, ignoring: ", strerror(r));
        }
        Err(_) => {}
    }
    if crate::env::getenv_bool("SYSTEMD_IGNORE_CHROOT") == Ok(true) {
        return 0;
    }
    match crate::stat_util::inode_same_at(libc::AT_FDCWD, Some(b"/proc/1/root"), libc::AT_FDCWD, Some(b"/"), 0) {
        Err(r) if r == -libc::ENOENT => match crate::fs::proc_mounted_full() {
            Ok(false) => {
                if crate::sys::getpid() == 1 {
                    return 0;
                }
                crate::log_debug!("/proc/ is not mounted, assuming we're in a chroot.");
                1
            }
            Ok(true) => -libc::ENOSYS,
            Err(_) => {
                crate::log_debug_errno!(r, "Failed to check if /proc/1/root and / are the same inode: ", strerror(r))
            }
        },
        Err(r) => crate::log_debug_errno!(r, "Failed to check if /proc/1/root and / are the same inode: ", strerror(r)),
        Ok(same) => !same as i32,
    }
}
