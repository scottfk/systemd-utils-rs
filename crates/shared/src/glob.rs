// SPDX-License-Identifier: LGPL-2.1-or-later
//! `glob-util.c`.

use crate::sys;

/// `safe_glob(path, flags, &ret)`: `Err(-ENOENT)` when nothing matches.
pub fn safe_glob(path: &[u8], flags: i32) -> Result<Vec<Vec<u8>>, i32> {
    let (r, v, e) = sys::safe_glob_raw(path, flags);
    if r == libc::GLOB_NOMATCH {
        return Err(-libc::ENOENT);
    }
    if r == libc::GLOB_NOSPACE {
        return Err(-libc::ENOMEM);
    }
    if r != 0 {
        return Err(if e > 0 { -e } else { -libc::EIO });
    }
    if v.is_empty() {
        return Err(-libc::ENOENT);
    }
    Ok(v)
}

/// `glob_extend(&strv, path, flags)`: GLOB_NOSORT|GLOB_BRACE|flags.
pub fn glob_extend(strv: &mut Vec<Vec<u8>>, path: &[u8], flags: i32) -> Result<(), i32> {
    let v = safe_glob(path, libc::GLOB_NOSORT | libc::GLOB_BRACE | flags)?;
    strv.extend(v);
    Ok(())
}
