// SPDX-License-Identifier: LGPL-2.1-or-later
//! tmpfiles.c: file capabilities (`k` and `K` lines).

use shared::capability::{all_capabilities, capability_from_name};
use shared::errno::{strerror, synthetic};
use shared::extract::{EXTRACT_RELAX, EXTRACT_UNQUOTE, extract_first_word};
use shared::{log_debug, log_debug_errno, log_error_errno, sys};

use crate::item::{FCapsPatch, FCapsUpdate};
use crate::{args, log_action};

const VFS_CAP_REVISION_MASK: u32 = 0xff000000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x000001;
const VFS_CAP_REVISION_1: u32 = 0x01000000;
const VFS_CAP_REVISION_2: u32 = 0x02000000;
const VFS_CAP_REVISION_3: u32 = 0x03000000;
const VFS_CAP_U32: usize = 2;
const XATTR_CAPS_SZ_1: usize = 4 + 2 * 4;
const XATTR_CAPS_SZ_2: usize = 4 + 2 * 2 * 4;
const XATTR_CAPS_SZ_3: usize = XATTR_CAPS_SZ_2 + 4;
/// `sizeof(struct vfs_ns_cap_data)`: magic_etc, 2 × {permitted, inheritable}, rootid.
const VFS_NS_CAP_DATA_SIZE: usize = XATTR_CAPS_SZ_3;

/// `capability_vfs_from_string()`.
pub fn capability_vfs_from_string(s: &[u8]) -> Result<FCapsUpdate, i32> {
    let mut set = FCapsUpdate { rootuid: u32::MAX, ..Default::default() };
    let mut p = Some(s);
    loop {
        let before = p.unwrap_or_default().to_vec();
        let word = match extract_first_word(&mut p, None, EXTRACT_UNQUOTE | EXTRACT_RELAX) {
            Err(r) => return Err(log_debug_errno!(r, "Failed to split words from '", before, "': ", strerror(r))),
            Ok(None) => break,
            Ok(Some(w)) => w,
        };
        let Some(pos) = word.iter().position(|c| b"=+-".contains(c)) else {
            let r = synthetic(libc::EINVAL);
            return Err(log_debug_errno!(r, "Failed to parse key/value '", word, "': ", strerror(r)));
        };
        let keys = &word[..pos];
        let sep = word[pos];
        let value = &word[pos + 1..];
        if sep == b'=' && keys == b"rootuid" {
            match shared::user::parse_uid(value) {
                Ok(u) => set.rootuid = u,
                Err(r) => {
                    return Err(log_debug_errno!(r, "Failed to parse rootuid value '", value, "': ", strerror(r)));
                }
            }
            continue;
        }
        if !shared::string::in_charset(value, b"eip") {
            let r = synthetic(libc::EINVAL);
            return Err(log_debug_errno!(r, "Failed to parse value '", value, "': ", strerror(r)));
        }
        let mut caps: u64 = 0;
        if keys == b"all" || keys.is_empty() {
            caps = all_capabilities();
        } else {
            let mut rk = Some(keys);
            while rk.is_some_and(|k| !k.is_empty()) {
                let key = match extract_first_word(&mut rk, Some(b","), 0) {
                    Err(r) => {
                        return Err(log_debug_errno!(r, "Failed to parse capability list '", keys, "': ", strerror(r)));
                    }
                    Ok(None) => break,
                    Ok(Some(k)) => k,
                };
                if key == b"all" {
                    caps = all_capabilities();
                } else {
                    match capability_from_name(&key) {
                        Ok(c) => caps |= 1u64 << c,
                        Err(r) => {
                            return Err(log_debug_errno!(r, "Failed to parse capability '", key, "': ", strerror(r)));
                        }
                    }
                }
            }
        }
        let has = |c: u8| value.contains(&c);
        let patches: [(&mut FCapsPatch, u8); 3] =
            [(&mut set.permitted, b'p'), (&mut set.inheritable, b'i'), (&mut set.effective, b'e')];
        for (patch, ch) in patches {
            if sep == b'=' {
                patch.mask |= caps;
            }
            if sep == b'=' || sep == b'+' {
                if has(ch) {
                    patch.set |= caps;
                }
            } else if has(ch) {
                patch.mask |= caps;
                patch.set &= !caps;
            }
        }
    }
    Ok(set)
}

/// `cap_data_size()`.
fn cap_data_size(revision: u32) -> Option<usize> {
    match revision {
        VFS_CAP_REVISION_1 => Some(XATTR_CAPS_SZ_1),
        VFS_CAP_REVISION_2 => Some(XATTR_CAPS_SZ_2),
        VFS_CAP_REVISION_3 => Some(XATTR_CAPS_SZ_3),
        _ => None,
    }
}

/// `apply_fcaps(fd, path, append, set)`.
pub fn apply_fcaps(fd: i32, path: &[u8], append: bool, set: &FCapsUpdate) -> i32 {
    let st = match sys::fstat(fd) {
        Ok(st) => st,
        Err(e) => return log_error_errno!(e, "Failed to fstat(", path, "): ", strerror(e)),
    };
    if crate::ops::hardlink_vulnerable(&st) {
        return log_error_errno!(
            synthetic(libc::EPERM),
            "Refusing to set file capabilities on hardlinked file ",
            path,
            " while the fs.protected_hardlinks sysctl is turned off."
        );
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        log_debug!("Skipping file capabilities for '", path, "' (inode type does not support file capabilities).");
        return 0;
    }

    // struct vfs_ns_cap_data, in host order (the xattr is little-endian,
    // as is every target of this port).
    let mut magic_etc: u32 = 0x03000000; // VFS_CAP_REVISION
    let mut permitted = [0u32; VFS_CAP_U32];
    let mut inheritable = [0u32; VFS_CAP_U32];
    let mut rootid: u32 = 0;
    let mut effective = [0u32; VFS_CAP_U32];

    if append {
        match shared::xattr::fgetxattr_malloc(fd, b"security.capability") {
            Err(r) if r == -libc::ENODATA => {
                log_debug!("No capabilities found for '", path, "'");
            }
            Err(r) => return log_error_errno!(r, "Failed to read capabilities of '", path, "': ", strerror(r)),
            Ok(data) => {
                if data.len() < 4 {
                    return log_error_errno!(
                        synthetic(libc::EINVAL),
                        "Extended attributes for capabilities are too small"
                    );
                }
                let len = data.len();
                let mut original = data;
                original.resize(original.len().max(VFS_NS_CAP_DATA_SIZE), 0);
                let u32_at = |o: usize| u32::from_le_bytes(original[o..o + 4].try_into().expect("4 bytes"));
                let omagic = u32_at(0);
                let Some(expected) = cap_data_size(omagic & VFS_CAP_REVISION_MASK) else {
                    return log_error_errno!(synthetic(libc::EINVAL), "Unknown type of file capabilities");
                };
                if len != expected {
                    return log_error_errno!(
                        synthetic(libc::EINVAL),
                        "Size of file capabilities does not match its type"
                    );
                }
                for n in 0..VFS_CAP_U32 {
                    let (op, oi) = (u32_at(4 + n * 8), u32_at(8 + n * 8));
                    if omagic & VFS_CAP_FLAGS_EFFECTIVE != 0 {
                        effective[n] = op | oi;
                    }
                    permitted[n] = op;
                    inheritable[n] = oi;
                }
                rootid = u32_at(20);
            }
        }
    }

    for n in 0..VFS_CAP_U32 {
        let shift = 32 * n;
        let lo = |v: u64| ((v >> shift) & 0xffffffff) as u32;
        inheritable[n] &= !lo(set.inheritable.mask);
        inheritable[n] |= lo(set.inheritable.set);
        permitted[n] &= !lo(set.permitted.mask);
        permitted[n] |= lo(set.permitted.set);
        effective[n] &= !lo(set.effective.mask);
        effective[n] |= lo(set.effective.set);
        if effective[n] != 0 {
            magic_etc |= VFS_CAP_FLAGS_EFFECTIVE;
        }
    }

    if magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0 {
        for n in 0..VFS_CAP_U32 {
            if permitted[n] | inheritable[n] != effective[n] {
                return log_error_errno!(synthetic(libc::EINVAL), "Inconsistent effective bits");
            }
        }
    }

    if set.rootuid != u32::MAX {
        rootid = set.rootuid;
    }

    log_action!("Would try to set", "Trying to set", " capabilities on ", path);

    if !args().dry_run {
        let mut val = Vec::with_capacity(VFS_NS_CAP_DATA_SIZE);
        val.extend(magic_etc.to_le_bytes());
        for n in 0..VFS_CAP_U32 {
            val.extend(permitted[n].to_le_bytes());
            val.extend(inheritable[n].to_le_bytes());
        }
        val.extend(rootid.to_le_bytes());
        if let Err(r) = shared::xattr::fsetxattr_full(fd, b"security.capability", &val, 0) {
            return log_error_errno!(r, "Failed to setcap '", path, "': ", strerror(r));
        }
    }
    0
}
