// SPDX-License-Identifier: LGPL-2.1-or-later
//! `env-util.c`: environment lookups.

use crate::parse::parse_boolean;
use crate::sys;

/// `getenv()`.
pub fn getenv(name: &str) -> Option<Vec<u8>> {
    sys::getenv(name)
}

/// `secure_getenv()`.
pub fn secure_getenv(name: &str) -> Option<Vec<u8>> {
    sys::secure_getenv(name)
}

/// `getenv_bool()`: `Err(-ENXIO)` when unset.
pub fn getenv_bool(name: &str) -> Result<bool, i32> {
    match getenv(name) {
        None => Err(-libc::ENXIO),
        Some(v) => parse_boolean(&v),
    }
}

/// `secure_getenv_bool()`.
pub fn secure_getenv_bool(name: &str) -> Result<bool, i32> {
    match secure_getenv(name) {
        None => Err(-libc::ENXIO),
        Some(v) => parse_boolean(&v),
    }
}

/// `set_unset_env(name, value, overwrite=true)`.
pub fn set_unset_env(name: &[u8], value: Option<&[u8]>) -> Result<(), i32> {
    match value {
        Some(v) => sys::setenv(name, v),
        None => sys::unsetenv(name),
    }
}

/// `env_name_is_valid()` (of the first `n` bytes).
pub fn env_name_is_valid(e: &[u8]) -> bool {
    !e.is_empty() && !e[0].is_ascii_digit() && e.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `env_assignment_is_valid()`: NAME=VALUE with a valid name and a UTF-8
/// value (the ARG_MAX limits are not checked).
pub fn env_assignment_is_valid(e: &[u8]) -> bool {
    match e.iter().position(|&c| c == b'=') {
        None => false,
        Some(i) => env_name_is_valid(&e[..i]) && crate::utf8::is_valid(&e[i + 1..]),
    }
}
