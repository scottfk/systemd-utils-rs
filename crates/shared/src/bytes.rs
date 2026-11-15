//! Copied from logrotate-rs (originally openrc-rs crates/compat, same author), 2026-11-15.
//!
//! Byte-string helpers.  systemd deals in C strings, which need not be UTF-8,
//! so messages are assembled as `Vec<u8>` rather than `String`.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// Anything that can be viewed as raw bytes, for [`bcat!`](crate::bcat).
pub trait AsBytes {
    fn as_bytes_ref(&self) -> &[u8];
}

impl AsBytes for [u8] {
    fn as_bytes_ref(&self) -> &[u8] {
        self
    }
}
impl<const N: usize> AsBytes for [u8; N] {
    fn as_bytes_ref(&self) -> &[u8] {
        self
    }
}
impl AsBytes for Vec<u8> {
    fn as_bytes_ref(&self) -> &[u8] {
        self
    }
}
impl AsBytes for str {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsBytes for String {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsBytes for OsStr {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsBytes for OsString {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsBytes for CStr {
    fn as_bytes_ref(&self) -> &[u8] {
        self.to_bytes()
    }
}
impl AsBytes for CString {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl<T: AsBytes + ?Sized> AsBytes for &T {
    fn as_bytes_ref(&self) -> &[u8] {
        (**self).as_bytes_ref()
    }
}

/// Concatenate byte-ish values into a `Vec<u8>`:
/// `bcat!(applet, ": invalid mode '", arg, "'")`.
#[macro_export]
macro_rules! bcat {
    ($($e:expr),* $(,)?) => {{
        let mut v: ::std::vec::Vec<u8> = ::std::vec::Vec::new();
        $( v.extend_from_slice($crate::bytes::AsBytes::as_bytes_ref(&$e)); )*
        v
    }};
}

/// The part of `s` a C function would see: everything before the first NUL.
pub fn c_str_prefix(s: &[u8]) -> &[u8] {
    match s.iter().position(|&b| b == 0) {
        Some(i) => &s[..i],
        None => s,
    }
}

/// Build a `CString` for a syscall; C strings stop at the first NUL anyway.
pub fn to_cstring(s: &[u8]) -> CString {
    CString::new(c_str_prefix(s)).expect("NUL already stripped")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concat() {
        let os = OsStr::new("x");
        assert_eq!(bcat!("a", b"b", String::from("c"), os), b"abcx");
    }
}
