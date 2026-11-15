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
