// SPDX-License-Identifier: LGPL-2.1-or-later
//! `specifier.c`: "%x" expansion in config lines.

use crate::id128;
use crate::sys;
use crate::user::{gid_to_name, uid_to_name};

/// A lookup: given the root, the expansion (None or empty means "nothing").
pub type Lookup<'a> = Box<dyn Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>, i32> + 'a>;

/// `Specifier`.
pub struct Specifier<'a> {
    pub c: u8,
    pub lookup: Lookup<'a>,
}

impl std::fmt::Debug for Specifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Specifier('{}')", self.c as char)
    }
}

pub fn spec<'a>(c: u8, f: impl Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>, i32> + 'a) -> Specifier<'a> {
    Specifier { c, lookup: Box::new(f) }
}

/// `specifier_printf(text, max_length, table, root, userdata, &ret)`.
pub fn specifier_printf(
    text: &[u8],
    max_length: usize,
    table: &[Specifier],
    root: Option<&[u8]>,
) -> Result<Vec<u8>, i32> {
    const POSSIBLE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%";
    let text = crate::bytes::c_str_prefix(text);
    let mut t: Vec<u8> = Vec::with_capacity(text.len());
    let mut percent = false;
    for &f in text {
        if percent {
            percent = false;
            if f == b'%' {
                t.push(b'%');
            } else if let Some(i) = table.iter().find(|i| i.c == f) {
                match (i.lookup)(root)? {
                    Some(w) if !w.is_empty() => t.extend_from_slice(crate::bytes::c_str_prefix(&w)),
                    _ => continue,
                }
            } else if POSSIBLE.contains(&f) {
                return Err(-libc::EBADSLT);
            } else {
                t.push(b'%');
                t.push(f);
            }
        } else if f == b'%' {
            percent = true;
        } else {
            t.push(f);
        }
        if t.len() > max_length {
            return Err(-libc::ENAMETOOLONG);
        }
    }
    if percent {
        t.push(b'%');
        if t.len() > max_length {
            return Err(-libc::ENAMETOOLONG);
        }
    }
    Ok(t)
}

/// `RuntimeScope` (system or user; GLOBAL is not used by tmpfiles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

/// `parse_os_release_specifier()`: a missing os-release is EUNATCH.
fn os_release(root: Option<&[u8]>, key: &str) -> Result<Option<Vec<u8>>, i32> {
    match crate::env_file::parse_os_release(root, key) {
        Err(e) if e == -libc::ENOENT => Err(-libc::EUNATCH),
        r => r,
    }
}

/// `uname_architecture()` + `architecture_to_string()` (x86 machines).
fn architecture() -> Option<Vec<u8>> {
    let (m, _) = sys::uname_machine_release().ok()?;
    Some(match &m[..] {
        b"x86_64" => b"x86-64".to_vec(),
        b"i686" | b"i586" | b"i486" | b"i386" => b"x86".to_vec(),
        _ => return None,
    })
}

/// `COMMON_SYSTEM_SPECIFIERS`.
pub fn common_system_specifiers<'a>() -> Vec<Specifier<'a>> {
    vec![
        spec(b'a', |_| Ok(architecture())),
        spec(b'A', |r| os_release(r, "IMAGE_VERSION")),
        spec(b'b', |_| Ok(Some(id128::to_string(&id128::get_boot()?)))),
        spec(b'B', |r| os_release(r, "BUILD_ID")),
        spec(b'H', |_| Ok(Some(crate::hostname::gethostname(false).map_err(|_| -libc::ENOMEM)?))),
        spec(b'l', |_| Ok(Some(crate::hostname::gethostname(true).map_err(|_| -libc::ENOMEM)?))),
        spec(b'q', |_| match crate::hostname::get_pretty_hostname() {
            Ok(n) => Ok(Some(n)),
            Err(_) => Ok(Some(crate::hostname::gethostname(true).map_err(|_| -libc::ENOMEM)?)),
        }),
        spec(b'm', |r| match id128::get_machine(r) {
            Ok(id) => Ok(Some(id128::to_string(&id))),
            Err(e) if e == -libc::ENOENT => Err(-libc::EUNATCH),
            Err(e) => Err(e),
        }),
        spec(b'M', |r| os_release(r, "IMAGE_ID")),
        spec(b'o', |r| os_release(r, "ID")),
        spec(b'v', |_| Ok(Some(sys::uname_machine_release()?.1))),
        spec(b'w', |r| os_release(r, "VERSION_ID")),
        spec(b'W', |r| os_release(r, "VARIANT_ID")),
    ]
}

/// `COMMON_CREDS_SPECIFIERS(scope)`.
pub fn common_creds_specifiers<'a>(scope: RuntimeScope) -> Vec<Specifier<'a>> {
    let user = scope == RuntimeScope::User;
    vec![
        spec(b'g', move |_| Ok(Some(gid_to_name(if user { sys::getgid() } else { 0 })))),
        spec(b'G', move |_| Ok(Some((if user { sys::getgid() } else { 0 }).to_string().into_bytes()))),
        spec(b'u', move |_| Ok(Some(uid_to_name(if user { sys::getuid() } else { 0 })))),
        spec(b'U', move |_| Ok(Some((if user { sys::getuid() } else { 0 }).to_string().into_bytes()))),
    ]
}

/// `COMMON_TMP_SPECIFIERS`.
pub fn common_tmp_specifiers<'a>() -> Vec<Specifier<'a>> {
    vec![
        spec(b'T', |r| if r.is_some() { Ok(Some(b"/tmp".to_vec())) } else { Ok(Some(crate::sd_path::tmp_dir()?)) }),
        spec(
            b'V',
            |r| if r.is_some() { Ok(Some(b"/var/tmp".to_vec())) } else { Ok(Some(crate::sd_path::var_tmp_dir()?)) },
        ),
    ]
}

/// `specifier_user_home()`.
pub fn specifier_user_home() -> Result<Option<Vec<u8>>, i32> {
    Ok(Some(crate::sd_path::get_home_dir()?))
}
