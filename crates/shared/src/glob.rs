// SPDX-License-Identifier: LGPL-2.1-or-later
//! `glob-util.c`.

use crate::sys;

/// `safe_glob(path, flags, &ret)`: `Err(-ENOENT)` when nothing matches.
pub fn safe_glob(path: &[u8], flags: i32) -> Result<Vec<Vec<u8>>, i32> {
    safe_glob_full(path, flags, None)
}

/// `safe_glob_full(path, flags, opendir_func, &ret)`.
pub fn safe_glob_full(path: &[u8], flags: i32, opendir: Option<sys::OpendirFn>) -> Result<Vec<Vec<u8>>, i32> {
    let (r, v, e) = sys::safe_glob_raw_with(path, flags, opendir);
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

/// `GLOB_CHARS`.
pub const GLOB_CHARS: &[u8] = b"*?[";

/// `glob_non_glob_prefix(path, &ret)`: the leading directories that have no
/// glob characters.
pub fn glob_non_glob_prefix(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut n = path.iter().position(|c| GLOB_CHARS.contains(c)).unwrap_or(path.len());
    if n < path.len() {
        while n > 0 && path[n - 1] != b'/' {
            n -= 1;
        }
    }
    if n == 0 {
        return Err(-libc::ENOENT);
    }
    Ok(path[..n].to_vec())
}
