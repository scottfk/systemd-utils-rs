// SPDX-License-Identifier: LGPL-2.1-or-later
//! `dlopen_many_sym_or_warn()` (`dlfcn-util.c`) for the libraries udev
//! loads at runtime (libkmod, libblkid).  Like `sys.rs`, this module holds
//! unsafe code.

use std::ffi::{CStr, CString, c_void};

use crate::errno::synthetic;
use crate::{log_debug, log_full_errno, sys};

fn dlerror_text() -> Vec<u8> {
    // SAFETY: dlerror() returns NULL or a NUL-terminated string.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: as above.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// A symbol's address, sendable between threads (the libraries are never
/// unloaded).
#[derive(Debug, Clone, Copy)]
pub struct Sym(pub *mut c_void);
// SAFETY: a function address in a library loaded with RTLD_NODELETE.
unsafe impl Send for Sym {}
// SAFETY: as above.
unsafe impl Sync for Sym {}

/// `dlopen_many_sym_or_warn(&dl, filename, log_level, symbols...)`: the
/// symbols' addresses, in order.
pub fn dlopen_many(filename: &str, symbols: &[&str], log_level: i32) -> Result<Vec<Sym>, i32> {
    let blocked = crate::sys_acl::dlopen_blocked();
    let mut flags = libc::RTLD_NOW | libc::RTLD_NODELETE;
    if blocked {
        flags |= libc::RTLD_NOLOAD;
    }
    let name = CString::new(filename).expect("no NUL");
    sys::set_errno(0);
    // SAFETY: name is NUL-terminated.
    let dl = unsafe { libc::dlopen(name.as_ptr(), flags) };
    if dl.is_null() {
        if blocked {
            let _ = dlerror_text();
            let r = crate::log_debug_errno!(
                synthetic(libc::EPERM),
                "Refusing loading of '",
                filename,
                "', as loading further dlopen() modules has been blocked."
            );
            return Err(log_full_errno!(
                log_level,
                synthetic(libc::EOPNOTSUPP),
                "Shared library '",
                filename,
                "' is not available: ",
                crate::errno::strerror(r)
            ));
        }
        let e = crate::errno::errno_or_else(libc::ENOPKG);
        let dle = dlerror_text();
        let why = if dle.is_empty() { crate::errno::strerror(e) } else { dle };
        return Err(log_full_errno!(
            log_level,
            synthetic(libc::EOPNOTSUPP),
            "Shared library '",
            filename,
            "' is not available: ",
            why
        ));
    }
    log_debug!("Loaded shared library '", filename, "' via dlopen().");
    let mut out = Vec::with_capacity(symbols.len());
    for s in symbols {
        let c = CString::new(*s).expect("no NUL");
        // SAFETY: dl is a live handle; c is NUL-terminated.
        let p = unsafe { libc::dlsym(dl, c.as_ptr()) };
        if p.is_null() {
            return Err(log_full_errno!(
                log_level,
                synthetic(libc::ELIBBAD),
                "Can't find symbol ",
                *s,
                ": ",
                dlerror_text()
            ));
        }
        out.push(Sym(p));
    }
    Ok(out)
}
