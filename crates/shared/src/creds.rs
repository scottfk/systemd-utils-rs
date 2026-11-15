// SPDX-License-Identifier: LGPL-2.1-or-later
//! `creds-util.c`: the credentials directory.

use crate::path::{path_is_absolute, path_is_normalized};

/// `get_credentials_dir()`: `Err(-ENXIO)` if $CREDENTIALS_DIRECTORY is unset.
pub fn get_credentials_dir() -> Result<Vec<u8>, i32> {
    let e = crate::sys::secure_getenv("CREDENTIALS_DIRECTORY").ok_or(-libc::ENXIO)?;
    if !path_is_absolute(&e) || !path_is_normalized(&e) {
        return Err(-libc::EINVAL);
    }
    Ok(e)
}

/// `fdname_is_valid()`: printable ASCII except ':', at most 255 bytes.
pub fn fdname_is_valid(s: &[u8]) -> bool {
    s.iter().all(|&c| (b' '..127).contains(&c) && c != b':') && s.len() <= 255
}

/// `credential_name_valid()`.
pub fn credential_name_valid(s: &[u8]) -> bool {
    crate::path::filename_is_valid(s) && fdname_is_valid(s)
}

/// `read_credential(name, &data, &size)`.
pub fn read_credential(name: &[u8]) -> Result<Vec<u8>, i32> {
    if !credential_name_valid(name) {
        return Err(-libc::EINVAL);
    }
    let d = get_credentials_dir()?;
    let mut f = crate::fileio::fopen_re(&crate::path::path_join(&[&d, name]))?;
    f.read_to_end()
}
