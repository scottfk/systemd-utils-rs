// SPDX-License-Identifier: LGPL-2.1-or-later
//! `condition.c` and `compare-operator.c`: the conditions of a `.link`
//! file's `[Match]` section (`condition_test_list_net()`).

use crate::errno::{strerror, synthetic};
use crate::extract::{
    EXTRACT_DONT_COALESCE_SEPARATORS, EXTRACT_RETAIN_SEPARATORS, EXTRACT_UNQUOTE, extract_first_word,
};
use crate::string::WHITESPACE;
use crate::{log_debug, log_debug_errno, sys};

/// The `ConditionType`s that `[Match]` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    KernelCommandLine,
    Version,
    Credential,
    Virtualization,
    Host,
    Architecture,
    Firmware,
    MachineTag,
}

/// A `Condition`.
#[derive(Debug, Clone)]
pub struct Condition {
    pub ty: ConditionType,
    pub parameter: Vec<u8>,
    pub negate: bool,
}

/// A condition list: C prepends, so the newest comes first.
pub type Conditions = Vec<Condition>;

/// `config_parse_net_condition()`.
pub fn config_parse_net_condition(list: &mut Conditions, ty: ConditionType, rvalue: &[u8]) -> i32 {
    list.retain(|c| c.ty != ty);
    if rvalue.is_empty() {
        return 0;
    }
    let (negate, p) = match rvalue.strip_prefix(b"!") {
        Some(p) => (true, p),
        None => (false, rvalue),
    };
    list.insert(0, Condition { ty, parameter: p.to_vec(), negate });
    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    StringEqual,
    StringUnequal,
    FnmatchEqual,
    FnmatchUnequal,
    Lower,
    LowerOrEqual,
    Equal,
    Unequal,
    GreaterOrEqual,
    Greater,
}

const COMPARE_ALLOW_FNMATCH: u32 = 1 << 0;
const COMPARE_EQUAL_BY_STRING: u32 = 1 << 1;
const COMPARE_ALLOW_TEXTUAL: u32 = 1 << 2;
const COMPARE_OPERATOR_WITH_FNMATCH_CHARS: &[u8] = b"!<=>$";

/// `parse_compare_operator(&s, flags)`.
fn parse_compare_operator(s: &mut &[u8], flags: u32) -> Option<Op> {
    const TABLE: &[(Op, &[u8], u32, u32)] = &[
        (Op::FnmatchEqual, b"$=", COMPARE_ALLOW_FNMATCH, 0),
        (Op::FnmatchUnequal, b"!$=", COMPARE_ALLOW_FNMATCH, 0),
        (Op::Unequal, b"<>", 0, 0),
        (Op::LowerOrEqual, b"<=", 0, 0),
        (Op::GreaterOrEqual, b">=", 0, 0),
        (Op::Lower, b"<", 0, 0),
        (Op::Greater, b">", 0, 0),
        (Op::Equal, b"==", 0, 0),
        (Op::StringEqual, b"=", 0, COMPARE_EQUAL_BY_STRING),
        (Op::Equal, b"=", 0, 0),
        (Op::StringUnequal, b"!=", 0, COMPARE_EQUAL_BY_STRING),
        (Op::Unequal, b"!=", 0, 0),
        (Op::Lower, b"lt", COMPARE_ALLOW_TEXTUAL, 0),
        (Op::LowerOrEqual, b"le", COMPARE_ALLOW_TEXTUAL, 0),
        (Op::Equal, b"eq", COMPARE_ALLOW_TEXTUAL, 0),
        (Op::Unequal, b"ne", COMPARE_ALLOW_TEXTUAL, 0),
        (Op::GreaterOrEqual, b"ge", COMPARE_ALLOW_TEXTUAL, 0),
        (Op::Greater, b"gt", COMPARE_ALLOW_TEXTUAL, 0),
    ];
    for &(op, st, valid, need) in TABLE {
        if need != 0 && flags & need != need {
            continue;
        }
        if let Some(e) = s.strip_prefix(st) {
            if valid != 0 && flags & valid != valid {
                return None;
            }
            *s = e;
            return Some(op);
        }
    }
    None
}

/// `version_or_fnmatch_compare(op, a, b)`.
fn version_or_fnmatch_compare(op: Op, a: &[u8], b: &[u8]) -> Result<bool, i32> {
    use std::cmp::Ordering::*;
    let fnm = || match sys::fnmatch(b, a, 0) {
        0 => Ok(true),
        libc::FNM_NOMATCH => Ok(false),
        _ => Err(-libc::EINVAL),
    };
    let k = || crate::string::strverscmp_improved(Some(a), Some(b));
    Ok(match op {
        Op::StringEqual => a == b,
        Op::StringUnequal => a != b,
        Op::FnmatchEqual => fnm()?,
        Op::FnmatchUnequal => !fnm()?,
        Op::Lower => k() == Less,
        Op::LowerOrEqual => k() != Greater,
        Op::Equal => k() == Equal,
        Op::Unequal => k() != Equal,
        Op::GreaterOrEqual => k() != Less,
        Op::Greater => k() == Greater,
    })
}

/// `condition_test_kernel_command_line()`.
fn test_kernel_command_line(c: &Condition) -> Result<bool, i32> {
    let args = crate::proc_cmdline::proc_cmdline_strv()?;
    let equal = c.parameter.contains(&b'=');
    Ok(args.iter().any(|w| {
        if equal {
            *w == c.parameter
        } else {
            w.strip_prefix(&c.parameter[..]).is_some_and(|f| f.is_empty() || f[0] == b'=')
        }
    }))
}

/// `condition_test_credential()`.
fn test_credential(c: &Condition) -> Result<bool, i32> {
    if !crate::creds::credential_name_valid(&c.parameter) {
        return Ok(false);
    }
    for var in ["CREDENTIALS_DIRECTORY", "ENCRYPTED_CREDENTIALS_DIRECTORY"] {
        // get_credentials_dir_internal()
        let Some(cd) = sys::secure_getenv(var) else { continue };
        if !crate::path::path_is_absolute(&cd) || !crate::path::path_is_normalized(&cd) {
            return Err(-libc::EINVAL);
        }
        let j = crate::path::path_join(&[&cd, &c.parameter]);
        match sys::faccessat(libc::AT_FDCWD, &j, libc::F_OK, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(()) => return Ok(true),
            Err(r) if r != -libc::ENOENT => return Err(r),
            Err(_) => {}
        }
    }
    Ok(false)
}

/// `condition_test_version_cmp()`.
fn test_version_cmp(condition: &[u8], ver: &[u8]) -> Result<bool, i32> {
    let mut first = true;
    let mut p = Some(condition);
    loop {
        let word = match extract_first_word(&mut p, None, EXTRACT_UNQUOTE) {
            Err(r) => {
                return Err(log_debug_errno!(
                    r,
                    "Failed to parse condition string \"",
                    p.unwrap_or(b"(null)"),
                    "\": ",
                    strerror(r)
                ));
            }
            Ok(None) => break,
            Ok(Some(w)) => w,
        };
        let mut s: &[u8] = crate::string::strstrip(&word);
        let op =
            parse_compare_operator(&mut s, COMPARE_ALLOW_FNMATCH | COMPARE_EQUAL_BY_STRING).unwrap_or(Op::FnmatchEqual);
        s = crate::string::skip_leading_chars(s, Some(WHITESPACE));
        let second;
        if s.is_empty() {
            if !first {
                return Err(log_debug_errno!(
                    synthetic(libc::EINVAL),
                    "Unexpected end of expression: ",
                    p.unwrap_or(b"(null)")
                ));
            }
            match extract_first_word(&mut p, None, 0) {
                Err(r) => {
                    return Err(log_debug_errno!(
                        r,
                        "Failed to parse condition string \"",
                        p.unwrap_or(b"(null)"),
                        "\": ",
                        strerror(r)
                    ));
                }
                Ok(None) => {
                    return Err(log_debug_errno!(
                        synthetic(libc::EINVAL),
                        "Unexpected end of expression: ",
                        p.unwrap_or(b"(null)")
                    ));
                }
                Ok(Some(w)) => second = w,
            }
            s = &second;
        }
        if !version_or_fnmatch_compare(op, ver, s)? {
            return Ok(false);
        }
        first = false;
    }
    Ok(true)
}

/// `condition_test_version()`.
fn test_version(c: &Condition) -> Result<bool, i32> {
    if c.parameter.is_empty() {
        return Ok(true);
    }
    let mut p = Some(&c.parameter[..]);
    let seps = crate::bcat!(COMPARE_OPERATOR_WITH_FNMATCH_CHARS, WHITESPACE);
    let word =
        match extract_first_word(&mut p, Some(&seps), EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_RETAIN_SEPARATORS) {
            Err(r) => {
                return Err(log_debug_errno!(
                    r,
                    "Failed to parse compare predicate \"",
                    p.unwrap_or(b"(null)"),
                    "\": ",
                    strerror(r)
                ));
            }
            Ok(None) => {
                return Err(log_debug_errno!(
                    synthetic(libc::EINVAL),
                    "Missing right operand in condition: ",
                    &c.parameter[..]
                ));
            }
            Ok(Some(w)) => w,
        };
    let rest = p.unwrap_or(b"");
    match &word[..] {
        b"systemd" => test_version_cmp(rest, crate::build::PROJECT_VERSION.to_string().as_bytes()),
        b"glibc" => test_version_cmp(rest, &sys::gnu_get_libc_version()),
        w => {
            let cond = if w == b"kernel" { rest } else { &c.parameter[..] };
            let (_, release) = sys::uname_machine_release()?;
            test_version_cmp(cond, &release)
        }
    }
}

/// `machine_tag_is_valid()`.
fn machine_tag_is_valid(s: &[u8]) -> bool {
    let n = s.len();
    if n == 0 || n >= 256 || b"-.=".contains(&s[0]) {
        return false;
    }
    match s.iter().position(|&c| c == b'=') {
        Some(eq) => {
            if b"-.".contains(&s[eq - 1]) {
                return false;
            }
        }
        None => {
            if b"-.".contains(&s[n - 1]) {
                return false;
            }
        }
    }
    s.iter().all(|c| c.is_ascii_alphanumeric() || b"-.=".contains(c))
}

/// `machine_tags_from_string(s, graceful=true, &ret)`.
fn machine_tags_from_string(s: Option<&[u8]>) -> Result<Vec<Vec<u8>>, i32> {
    let Some(s) = s.filter(|s| !s.is_empty()) else { return Ok(Vec::new()) };
    let mut l = crate::string::strv_split(s, b":");
    l.sort();
    l.dedup();
    let mut cleaned: Vec<Vec<u8>> = Vec::new();
    for i in l {
        if !machine_tag_is_valid(&i) {
            continue;
        }
        if cleaned.len() + 1 > 1024 {
            return Err(-libc::E2BIG);
        }
        if let Some(eq) = i.iter().position(|&c| c == b'=')
            && cleaned.iter().any(|j| j.len() > eq && j[..eq + 1] == i[..eq + 1])
        {
            continue;
        }
        cleaned.push(i);
    }
    Ok(cleaned)
}

/// `condition_test_machine_tag()`.
fn test_machine_tag(c: &Condition) -> Result<bool, i32> {
    let path = sys::secure_getenv("SYSTEMD_ETC_MACHINE_INFO").unwrap_or_else(|| b"/etc/machine-info".to_vec());
    let tags = match crate::env_file::parse_env_file(&path, &["TAGS"]) {
        Ok(mut v) => v.remove(0),
        Err(r) if r == -libc::ENOENT => None,
        Err(r) => {
            log_debug_errno!(r, "Failed to read /etc/machine-info, ignoring: ", strerror(r));
            return Ok(false);
        }
    };
    let l = match machine_tags_from_string(tags.as_deref()) {
        Ok(l) => l,
        Err(r) => {
            log_debug_errno!(
                r,
                "Failed to parse machine tags '",
                tags.as_deref().unwrap_or(b"(null)"),
                "', ignoring: ",
                strerror(r)
            );
            return Ok(false);
        }
    };
    Ok(l.iter().any(|t| sys::fnmatch(&c.parameter, t, 0) == 0))
}

/// `running_in_userns()`.
fn running_in_userns() -> Result<bool, i32> {
    const PROC_USER_INIT_INO: u64 = 0xEFFF_FFFD;
    // namespace_is_init(NAMESPACE_USER)
    let r = match sys::stat(b"/proc/self/ns/user") {
        Ok(st) => Ok(st.st_ino == PROC_USER_INIT_INO),
        Err(r) if r == -libc::ENOENT => {
            match crate::stat_util::is_fs_type_at(libc::AT_FDCWD, Some(b"/proc/"), crate::stat_util::PROC_SUPER_MAGIC) {
                Ok(true) => Ok(true),
                Ok(false) => Err(-libc::ENOSYS),
                Err(e) if e == -libc::ENOENT => Err(-libc::ENOSYS),
                Err(_) => Err(-libc::ENOENT),
            }
        }
        Err(r) => Err(r),
    };
    match r {
        Ok(init) => Ok(!init),
        Err(r) => Err(log_debug_errno!(r, "Failed to test if in root user namespace, ignoring: ", strerror(r))),
    }
}

const VMS: &[&str] = &[
    "kvm",
    "amazon",
    "qemu",
    "bochs",
    "xen",
    "uml",
    "vmware",
    "oracle",
    "microsoft",
    "zvm",
    "parallels",
    "bhyve",
    "qnx",
    "acrn",
    "powervm",
    "apple",
    "sre",
    "google",
    "vm-other",
];

/// `condition_test_virtualization()`.
fn test_virtualization(c: &Condition) -> Result<bool, i32> {
    if c.parameter == b"private-users" {
        return running_in_userns();
    }
    let v = crate::virt::detect_virtualization()?;
    if let Ok(b) = crate::parse::parse_boolean(&c.parameter) {
        return Ok(b == (v != crate::virt::NONE));
    }
    let is_vm = VMS.contains(&v);
    match &c.parameter[..] {
        b"vm" => Ok(is_vm),
        b"container" => Ok(v != crate::virt::NONE && !is_vm),
        p => Ok(v != crate::virt::NONE && p == v.as_bytes()),
    }
}

const ARCHITECTURES: &[&str] = &[
    "arm64",
    "arm64-be",
    "arm",
    "arm-be",
    "alpha",
    "arc",
    "arc-be",
    "cris",
    "x86-64",
    "x86",
    "ia64",
    "loongarch64",
    "m68k",
    "mips64-le",
    "mips64",
    "mips-le",
    "mips",
    "nios2",
    "parisc64",
    "parisc",
    "ppc64-le",
    "ppc64",
    "ppc",
    "ppc-le",
    "riscv32",
    "riscv64",
    "s390x",
    "s390",
    "sh64",
    "sh",
    "sparc64",
    "sparc",
    "tilegx",
];

/// `condition_test_architecture()`.
fn test_architecture(c: &Condition) -> Result<bool, i32> {
    let a = crate::virt::architecture_to_string(crate::virt::uname_architecture()).unwrap_or("");
    let b: &[u8] = if c.parameter == b"native" {
        if cfg!(target_arch = "x86_64") { b"x86-64" } else { b"x86" }
    } else {
        if !ARCHITECTURES.iter().any(|x| x.as_bytes() == &c.parameter[..]) {
            return Ok(false);
        }
        &c.parameter
    };
    Ok(a.as_bytes() == b)
}

/// `condition_test_firmware_smbios_field()`.
fn test_firmware_smbios_field(expression: &[u8]) -> Result<bool, i32> {
    let mut p = Some(expression);
    let mut field = extract_first_word(&mut p, Some(COMPARE_OPERATOR_WITH_FNMATCH_CHARS), EXTRACT_RETAIN_SEPARATORS)?
        .ok_or(-libc::EINVAL)?;
    let mut e = p.unwrap_or(b"");
    if e.is_empty() {
        return Err(-libc::EINVAL);
    }
    while field.last().is_some_and(|c| WHITESPACE.contains(c)) {
        field.pop();
    }
    let op = parse_compare_operator(&mut e, COMPARE_ALLOW_FNMATCH | COMPARE_EQUAL_BY_STRING).ok_or(-libc::EINVAL)?;
    let mut p = Some(e);
    let expected = extract_first_word(&mut p, None, EXTRACT_UNQUOTE)?.ok_or(-libc::EINVAL)?;
    if !p.unwrap_or(b"").is_empty() {
        return Err(-libc::EINVAL);
    }
    if !crate::path::filename_is_valid(&field) {
        return Err(log_debug_errno!(synthetic(libc::EINVAL), "Invalid SMBIOS field name."));
    }
    let path = crate::bcat!("/sys/class/dmi/id/", &field[..]);
    let mut actual = match crate::fileio::read_virtual_file(&path, usize::MAX) {
        Ok((v, _)) => v,
        Err(r) => {
            log_debug_errno!(r, "Failed to read ", &path[..], ": ", strerror(r));
            return if r == -libc::ENOENT { Ok(false) } else { Err(r) };
        }
    };
    while actual.last().is_some_and(|c| WHITESPACE.contains(c)) {
        actual.pop();
    }
    version_or_fnmatch_compare(op, &actual, &expected)
}

/// `condition_test_firmware()`.
fn test_firmware(c: &Condition) -> Result<bool, i32> {
    let p = &c.parameter[..];
    if p == b"device-tree" {
        return match crate::sys_net::access(b"/sys/firmware/devicetree/", libc::F_OK) {
            Ok(()) => Ok(true),
            Err(r) => {
                if r != -libc::ENOENT {
                    log_debug_errno!(r, "Unexpected error when checking for /sys/firmware/devicetree/: ", strerror(r));
                }
                Ok(false)
            }
        };
    }
    if let Some(arg) = p.strip_prefix(b"device-tree-compatible(") {
        let end = arg.iter().rposition(|&c| c == b')');
        let Some(end) = end.filter(|&e| e + 1 == arg.len()) else {
            log_debug!("Malformed ConditionFirmware=", p);
            return Ok(false);
        };
        let want = &arg[..end];
        const DTCOMPAT_FILE: &str = "/proc/device-tree/compatible";
        let data = match crate::fileio::read_virtual_file(DTCOMPAT_FILE.as_bytes(), usize::MAX) {
            Ok((d, _)) => d,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_debug_errno!(
                        r,
                        "Failed to open '",
                        DTCOMPAT_FILE,
                        "', assuming machine is incompatible: ",
                        strerror(r)
                    );
                }
                return Ok(false);
            }
        };
        if data.is_empty() {
            log_debug!(DTCOMPAT_FILE, " has zero length, assuming machine is incompatible");
            return Ok(false);
        }
        if data.last() != Some(&0) {
            log_debug!(DTCOMPAT_FILE, " is in an unknown format, assuming machine is incompatible");
            return Ok(false);
        }
        return Ok(data[..data.len() - 1].split(|&b| b == 0).any(|s| s == want));
    }
    if p == b"uefi" {
        return Ok(crate::efivars::is_efi_boot());
    }
    if let Some(arg) = p.strip_prefix(b"smbios-field(") {
        let end = arg.iter().rposition(|&c| c == b')');
        let Some(end) = end.filter(|&e| e + 1 == arg.len()) else {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Malformed ConditionFirmware=", p, "."));
        };
        return test_firmware_smbios_field(&arg[..end])
            .map_err(|r| log_debug_errno!(r, "Malformed ConditionFirmware=", p, ": ", strerror(r)));
    }
    log_debug!("Unsupported Firmware condition \"", p, "\"");
    Ok(false)
}

/// `id128_get_product()`.
fn id128_get_product() -> Result<crate::id128::Id128, i32> {
    if crate::virt::detect_container()? != crate::virt::NONE {
        return Err(-libc::ENOENT);
    }
    let mut r = Err(-libc::ENOENT);
    for p in [&b"/sys/class/dmi/id/product_uuid"[..], b"/proc/device-tree/vm,uuid", b"/sys/hypervisor/uuid"] {
        r = crate::id128::read(p, crate::id128::ID128_FORMAT_UUID);
        if r != Err(-libc::ENOENT) {
            break;
        }
    }
    let u = r?;
    if u == [0u8; 16] || u == [0xffu8; 16] {
        return Err(-libc::EADDRNOTAVAIL);
    }
    Ok(u)
}

/// `condition_test_host()`.
fn test_host(c: &Condition) -> Result<bool, i32> {
    if let Ok(x) = crate::id128::from_string(&c.parameter) {
        let table: [(&str, fn() -> Result<crate::id128::Id128, i32>); 3] = [
            ("machine ID", || crate::id128::get_machine(None)),
            ("boot ID", crate::id128::get_boot),
            ("product UUID", id128_get_product),
        ];
        for (name, get) in table {
            match get() {
                Err(r) => {
                    log_debug_errno!(r, "Failed to get ", name, ", ignoring: ", strerror(r));
                }
                Ok(y) if y == x => return Ok(true),
                Ok(_) => {}
            }
        }
    }
    let h = crate::hostname::gethostname(false)?;
    match sys::fnmatch(&c.parameter, &h, libc::FNM_CASEFOLD) {
        0 => Ok(true),
        libc::FNM_NOMATCH => Ok(false),
        _ => Err(log_debug_errno!(synthetic(libc::EINVAL), "fnmatch() failed.")),
    }
}

/// `condition_test_net()` on one condition: Err on error, else whether it
/// holds (negation applied).
fn condition_test_net(c: &Condition) -> Result<bool, i32> {
    let r = match c.ty {
        ConditionType::KernelCommandLine => test_kernel_command_line(c),
        ConditionType::Version => test_version(c),
        ConditionType::Credential => test_credential(c),
        ConditionType::Virtualization => test_virtualization(c),
        ConditionType::Host => test_host(c),
        ConditionType::Architecture => test_architecture(c),
        ConditionType::Firmware => test_firmware(c),
        ConditionType::MachineTag => test_machine_tag(c),
    }?;
    Ok(r != c.negate)
}

/// `condition_test_list_net(first, environ, NULL, NULL, NULL)`: no trigger
/// conditions here, so all must hold, and errors make the list fail.
pub fn condition_test_list_net(list: &Conditions) -> bool {
    let mut error = false;
    for c in list {
        match condition_test_net(c) {
            Err(_) => error = true,
            Ok(false) => return false,
            Ok(true) => {}
        }
    }
    !error
}
