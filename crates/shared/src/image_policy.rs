// SPDX-License-Identifier: LGPL-2.1-or-later
//! `image-policy.c`: image policies, as udev's dissect_image builtin uses
//! them.

use crate::errno::synthetic;
use crate::extract::{EXTRACT_DONT_COALESCE_SEPARATORS, extract_first_word};
use crate::gpt::{ALL, Designator};
use crate::log_debug_errno;

pub const VERITY: i32 = 1 << 0;
pub const SIGNED: i32 = 1 << 1;
pub const ENCRYPTED: i32 = 1 << 2;
pub const ENCRYPTEDWITHINTEGRITY: i32 = 1 << 3;
pub const UNPROTECTED: i32 = 1 << 4;
pub const UNUSED: i32 = 1 << 5;
pub const ABSENT: i32 = 1 << 6;
pub const OPEN: i32 = VERITY | SIGNED | ENCRYPTED | ENCRYPTEDWITHINTEGRITY | UNPROTECTED | UNUSED | ABSENT;
pub const IGNORE: i32 = UNUSED | ABSENT;
pub const USE_MASK: i32 = OPEN;
pub const READ_ONLY_OFF: i32 = 1 << 7;
pub const READ_ONLY_ON: i32 = 1 << 8;
pub const READ_ONLY_MASK: i32 = READ_ONLY_OFF | READ_ONLY_ON;
pub const GROWFS_OFF: i32 = 1 << 9;
pub const GROWFS_ON: i32 = 1 << 10;
pub const GROWFS_MASK: i32 = GROWFS_OFF | GROWFS_ON;
pub const PFLAGS_MASK: i32 = READ_ONLY_MASK | GROWFS_MASK;
const FSTYPES: &[(&str, i32)] = &[
    ("btrfs", 1 << 11),
    ("erofs", 1 << 12),
    ("ext4", 1 << 13),
    ("f2fs", 1 << 14),
    ("squashfs", 1 << 15),
    ("vfat", 1 << 16),
    ("xfs", 1 << 17),
];
pub const FSTYPE_MASK: i32 = 0x3f800;

/// An `ImagePolicy`: the per-designator rules are sorted by designator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePolicy {
    pub default_flags: i32,
    pub policies: Vec<(Designator, i32)>,
}

/// `image_policy_host`.
pub fn image_policy_host() -> ImagePolicy {
    let data = VERITY | SIGNED | ENCRYPTED | ENCRYPTEDWITHINTEGRITY | UNPROTECTED | ABSENT;
    let enc = ENCRYPTED | ENCRYPTEDWITHINTEGRITY | UNPROTECTED | ABSENT;
    ImagePolicy {
        default_flags: IGNORE,
        policies: vec![
            (Designator::Root, data),
            (Designator::Usr, data),
            (Designator::Home, enc),
            (Designator::Srv, enc),
            (Designator::Esp, UNPROTECTED | ABSENT),
            (Designator::Xbootldr, UNPROTECTED | ABSENT),
            (Designator::Swap, enc),
            (Designator::Tmp, enc),
            (Designator::Var, enc),
        ],
    }
}

/// `partition_policy_flags_extend()`.
pub fn flags_extend(mut f: i32) -> i32 {
    if f & USE_MASK == 0 {
        f |= OPEN;
    }
    if f & READ_ONLY_MASK == 0 {
        f |= READ_ONLY_MASK;
    }
    if f & GROWFS_MASK == 0 {
        f |= GROWFS_MASK;
    }
    f
}

/// `partition_policy_normalized_flags()`.
fn normalized(d: Designator, f: i32) -> i32 {
    let mut f = flags_extend(f);
    if d.verity_hash_to_data().is_some() || d.verity_sig_to_data().is_some() {
        f &= !(VERITY | SIGNED | ENCRYPTED | ENCRYPTEDWITHINTEGRITY);
    }
    if d.verity_hash_of().is_none() {
        f &= !(VERITY | SIGNED);
    }
    if f & USE_MASK == ABSENT {
        f &= !(READ_ONLY_MASK | GROWFS_MASK);
    }
    f
}

impl ImagePolicy {
    fn find(&self, d: Designator) -> Option<i32> {
        self.policies.iter().find(|(x, _)| *x == d).map(|(_, f)| *f)
    }

    /// `image_policy_get()`: None for `_PARTITION_POLICY_FLAGS_INVALID`.
    pub fn get(&self, d: Designator) -> Option<i32> {
        if let Some(f) = self.find(d) {
            return Some(normalized(d, f));
        }
        if let Some(data) = d.verity_hash_to_data() {
            let df = self.get(data)?;
            if df & (SIGNED | VERITY) == 0 {
                return None;
            }
            return Some(normalized(d, UNPROTECTED | (df & (UNUSED | ABSENT)) | (df & PFLAGS_MASK)));
        }
        if let Some(data) = d.verity_sig_to_data() {
            let df = self.get(data)?;
            if df & SIGNED == 0 {
                return None;
            }
            return Some(normalized(d, UNPROTECTED | (df & (UNUSED | ABSENT)) | (df & PFLAGS_MASK)));
        }
        None
    }

    /// `image_policy_get_exhaustively()`.
    pub fn get_exhaustively(&self, d: Designator) -> i32 {
        self.get(d).unwrap_or_else(|| normalized(d, self.default_flags))
    }

    /// `image_policy_ignore_designators()`.
    pub fn ignore_designators(&self, table: &[Designator]) -> ImagePolicy {
        let mut p: Vec<(Designator, i32)> = Vec::new();
        for &t in table {
            if !p.iter().any(|(x, _)| *x == t) {
                p.push((t, IGNORE));
                p.sort_by_key(|(x, _)| *x);
            }
        }
        for &(d, f) in &self.policies {
            if !p.iter().any(|(x, _)| *x == d) {
                p.push((d, f));
                p.sort_by_key(|(x, _)| *x);
            }
        }
        ImagePolicy { default_flags: self.default_flags, policies: p }
    }

    fn flags_all_match(&self, expected: i32) -> bool {
        if flags_extend(self.default_flags) != flags_extend(expected) {
            return false;
        }
        ALL.iter().all(|&d| self.get_exhaustively(d) == normalized(d, expected))
    }

    /// `image_policy_to_string()`.
    pub fn to_string(&self, simplify: bool) -> Vec<u8> {
        if simplify {
            if self.flags_all_match(OPEN) {
                return b"*".to_vec();
            }
            if self.flags_all_match(IGNORE) {
                return b"-".to_vec();
            }
            if self.flags_all_match(ABSENT) {
                return b"~".to_vec();
            }
        }
        let mut s: Vec<u8> = Vec::new();
        for &(d, f) in &self.policies {
            if simplify && normalized(d, self.default_flags) == f {
                continue;
            }
            if !s.is_empty() {
                s.push(b':');
            }
            s.extend_from_slice(d.as_str().as_bytes());
            s.push(b'=');
            s.extend_from_slice(&flags_to_string(f, simplify).0);
        }
        if !simplify || flags_extend(self.default_flags) != flags_extend(IGNORE) {
            if !s.is_empty() {
                s.push(b':');
            }
            s.push(b'=');
            s.extend_from_slice(&flags_to_string(self.default_flags, simplify).0);
        }
        if s.is_empty() { b"-".to_vec() } else { s }
    }
}

/// `partition_policy_flags_to_string(flags, simplify, &ret)`: the string
/// and the number of words.
pub fn flags_to_string(f: i32, simplify: bool) -> (Vec<u8>, usize) {
    let mut l: Vec<&str> = Vec::new();
    if simplify && f & USE_MASK == OPEN {
        l.push("open");
    } else if simplify && f & USE_MASK == IGNORE {
        l.push("ignore");
    } else {
        for (b, n) in [
            (VERITY, "verity"),
            (SIGNED, "signed"),
            (ENCRYPTED, "encrypted"),
            (ENCRYPTEDWITHINTEGRITY, "encryptedwithintegrity"),
            (UNPROTECTED, "unprotected"),
            (UNUSED, "unused"),
            (ABSENT, "absent"),
        ] {
            if f & b != 0 {
                l.push(n);
            }
        }
    }
    if !simplify || ((f & READ_ONLY_ON == 0) != (f & READ_ONLY_OFF == 0)) {
        if f & READ_ONLY_ON != 0 {
            l.push("read-only-on");
        }
        if f & READ_ONLY_OFF != 0 {
            l.push("read-only-off");
        }
    }
    if !simplify || ((f & GROWFS_ON == 0) != (f & GROWFS_OFF == 0)) {
        if f & GROWFS_OFF != 0 {
            l.push("growfs-off");
        }
        if f & GROWFS_ON != 0 {
            l.push("growfs-on");
        }
    }
    for (n, b) in FSTYPES {
        if f & b != 0 {
            l.push(n);
        }
    }
    let n = l.len();
    (if n == 0 { b"-".to_vec() } else { l.join("+").into_bytes() }, n)
}

/// `partition_policy_determine_fstype(policy, designator, NULL, &ret)`.
pub fn determine_fstype(policy: &ImagePolicy, d: Designator) -> Option<Vec<u8>> {
    let f = policy.get_exhaustively(d);
    let (s, n) = flags_to_string(f & FSTYPE_MASK, true);
    (n == 1).then_some(s)
}

/// `policy_flag_from_string_one()`.
fn flag_from_string_one(s: &[u8]) -> Option<i32> {
    Some(match s {
        b"verity" => VERITY,
        b"signed" => SIGNED,
        b"encrypted" => ENCRYPTED,
        b"encryptedwithintegrity" => ENCRYPTEDWITHINTEGRITY,
        b"unprotected" => UNPROTECTED,
        b"unused" => UNUSED,
        b"absent" => ABSENT,
        b"open" => OPEN,
        b"ignore" => IGNORE,
        b"read-only-on" => READ_ONLY_ON,
        b"read-only-off" => READ_ONLY_OFF,
        b"growfs-on" => GROWFS_ON,
        b"growfs-off" => GROWFS_OFF,
        _ => return FSTYPES.iter().find(|(n, _)| n.as_bytes() == s).map(|(_, b)| *b),
    })
}

/// `partition_policy_flags_from_string(s, graceful=false)`.
pub fn flags_from_string(s: &[u8]) -> Result<i32, i32> {
    if s.is_empty() || s == b"-" {
        return Ok(0);
    }
    let mut flags = 0;
    let mut p = Some(s);
    while let Some(f) = extract_first_word(&mut p, Some(b"+"), EXTRACT_DONT_COALESCE_SEPARATORS)? {
        flags |= flag_from_string_one(crate::string::strstrip(&f)).ok_or(-libc::EBADRQC)?;
    }
    Ok(flags)
}

/// `image_policy_from_string(s, graceful=false, &ret)`.
pub fn image_policy_from_string(s: &[u8]) -> Result<ImagePolicy, i32> {
    let symbolic = match s {
        b"" | b"-" => Some(IGNORE),
        b"*" => Some(OPEN),
        b"~" => Some(ABSENT),
        _ => None,
    };
    if let Some(f) = symbolic {
        return Ok(ImagePolicy { default_flags: f, policies: Vec::new() });
    }
    let mut p = ImagePolicy { default_flags: 0, policies: Vec::new() };
    let mut default_specified = false;
    let mut q = Some(s);
    while let Some(e) = extract_first_word(&mut q, Some(b":"), EXTRACT_DONT_COALESCE_SEPARATORS)? {
        let mut f = Some(&e[..]);
        let Some(d) = extract_first_word(&mut f, Some(b"="), EXTRACT_DONT_COALESCE_SEPARATORS)? else {
            return Err(log_debug_errno!(
                synthetic(libc::EINVAL),
                "Expected designator name followed by '='; got instead: ",
                &e[..]
            ));
        };
        let Some(f) = f else {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Missing '=' in policy expression: ", &e[..]));
        };
        let ds = crate::string::strstrip(&d);
        let designator = if ds.is_empty() {
            if default_specified {
                return Err(log_debug_errno!(
                    synthetic(libc::ENOTUNIQ),
                    "Default partition policy flags specified more than once."
                ));
            }
            default_specified = true;
            None
        } else {
            let Some(x) = Designator::from_bytes(ds) else {
                return Err(log_debug_errno!(synthetic(libc::EBADSLT), "Unknown partition designator: ", ds));
            };
            if p.policies.iter().any(|(y, _)| *y == x) {
                return Err(log_debug_errno!(
                    synthetic(libc::ENOTUNIQ),
                    "Partition designator specified more than once: ",
                    ds
                ));
            }
            Some(x)
        };
        let fs = crate::string::strstrip(f);
        let flags = match flags_from_string(fs) {
            Err(r) if r == -libc::EBADRQC => {
                return Err(log_debug_errno!(r, "Unknown partition policy flag: ", fs));
            }
            Err(r) => {
                return Err(log_debug_errno!(
                    r,
                    "Failed to parse partition policy flags '",
                    fs,
                    "': ",
                    crate::errno::strerror(r)
                ));
            }
            Ok(f) => f,
        };
        match designator {
            None => p.default_flags = flags,
            Some(x) => p.policies.push((x, flags)),
        }
    }
    p.policies.sort_by_key(|(x, _)| *x);
    Ok(p)
}
