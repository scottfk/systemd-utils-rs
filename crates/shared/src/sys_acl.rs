// SPDX-License-Identifier: LGPL-2.1-or-later
//! `acl-util.c` and `dlfcn-util.c`: libacl, loaded with `dlopen()` as
//! upstream does (it is not linked).  Like `sys.rs`, this module holds
//! unsafe code: the libacl calls go through function pointers.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::sync::OnceLock;

use crate::bytes::to_cstring;
use crate::errno::synthetic;
use crate::{log_debug, log_full_errno, sys};

pub const ACL_READ: c_uint = 0x04;
pub const ACL_WRITE: c_uint = 0x02;
pub const ACL_EXECUTE: c_uint = 0x01;
pub const ACL_USER_OBJ: c_int = 0x01;
pub const ACL_USER: c_int = 0x02;
pub const ACL_GROUP_OBJ: c_int = 0x04;
pub const ACL_GROUP: c_int = 0x08;
pub const ACL_MASK: c_int = 0x10;
pub const ACL_OTHER: c_int = 0x20;
pub const ACL_TYPE_ACCESS: c_uint = 0x8000;
pub const ACL_TYPE_DEFAULT: c_uint = 0x4000;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = 1;
const TEXT_ABBREVIATE: c_int = 0x10;

type AclT = *mut c_void;
type EntryT = *mut c_void;
type PermsetT = *mut c_void;

#[derive(Debug)]
struct Lib {
    #[allow(dead_code)] // for udev's uaccess, later
    add_perm: unsafe extern "C" fn(PermsetT, c_uint) -> c_int,
    calc_mask: unsafe extern "C" fn(*mut AclT) -> c_int,
    copy_entry: unsafe extern "C" fn(EntryT, EntryT) -> c_int,
    create_entry: unsafe extern "C" fn(*mut AclT, *mut EntryT) -> c_int,
    delete_perm: unsafe extern "C" fn(PermsetT, c_uint) -> c_int,
    dup: unsafe extern "C" fn(AclT) -> AclT,
    free: unsafe extern "C" fn(*mut c_void) -> c_int,
    from_mode: unsafe extern "C" fn(libc::mode_t) -> AclT,
    from_text: unsafe extern "C" fn(*const c_char) -> AclT,
    get_entry: unsafe extern "C" fn(AclT, c_int, *mut EntryT) -> c_int,
    get_file: unsafe extern "C" fn(*const c_char, c_uint) -> AclT,
    get_perm: unsafe extern "C" fn(PermsetT, c_uint) -> c_int,
    get_permset: unsafe extern "C" fn(EntryT, *mut PermsetT) -> c_int,
    get_qualifier: unsafe extern "C" fn(EntryT) -> *mut c_void,
    get_tag_type: unsafe extern "C" fn(EntryT, *mut c_int) -> c_int,
    init: unsafe extern "C" fn(c_int) -> AclT,
    set_file: unsafe extern "C" fn(*const c_char, c_uint, AclT) -> c_int,
    to_any_text: unsafe extern "C" fn(AclT, *const c_char, c_char, c_int) -> *mut c_char,
}

static LIB: OnceLock<Lib> = OnceLock::new();
static DLOPEN_BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether `block_dlopen()` was called.
pub fn dlopen_blocked() -> bool {
    DLOPEN_BLOCKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// `block_dlopen()`: forked children may not load new modules.
pub fn block_dlopen() {
    DLOPEN_BLOCKED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn dlerror_text() -> Vec<u8> {
    // SAFETY: dlerror() returns NULL or a NUL-terminated string.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: as above.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// `dlopen_libacl(log_level)`.
pub fn dlopen_libacl(log_level: i32) -> Result<(), i32> {
    if LIB.get().is_some() {
        return Ok(());
    }
    let name = c"libacl.so.1";
    let blocked = DLOPEN_BLOCKED.load(std::sync::atomic::Ordering::Relaxed);
    let mut flags = libc::RTLD_NOW | libc::RTLD_NODELETE;
    if blocked {
        flags |= libc::RTLD_NOLOAD;
    }
    sys::set_errno(0);
    // SAFETY: name is NUL-terminated.
    let dl = unsafe { libc::dlopen(name.as_ptr(), flags) };
    if dl.is_null() {
        if blocked {
            let _ = dlerror_text();
            let r = crate::log_debug_errno!(
                synthetic(libc::EPERM),
                "Refusing loading of 'libacl.so.1', as loading further dlopen() modules has been blocked."
            );
            return Err(log_full_errno!(
                log_level,
                synthetic(libc::EOPNOTSUPP),
                "Shared library 'libacl.so.1' is not available: ",
                crate::errno::strerror(r)
            ));
        }
        let e = crate::errno::errno_or_else(libc::ENOPKG);
        let dle = dlerror_text();
        let why = if dle.is_empty() { crate::errno::strerror(e) } else { dle };
        return Err(log_full_errno!(
            log_level,
            synthetic(libc::EOPNOTSUPP),
            "Shared library 'libacl.so.1' is not available: ",
            why
        ));
    }
    log_debug!("Loaded shared library 'libacl.so.1' via dlopen().");
    let sym = |n: &str| -> Result<*mut c_void, i32> {
        let c = CString::new(n).expect("no NUL");
        // SAFETY: dl is a live handle; c is NUL-terminated.
        let p = unsafe { libc::dlsym(dl, c.as_ptr()) };
        if p.is_null() {
            return Err(log_full_errno!(
                log_level,
                synthetic(libc::ELIBBAD),
                "Can't find symbol ",
                n,
                ": ",
                dlerror_text()
            ));
        }
        Ok(p)
    };
    // SAFETY: each symbol is the libacl function with the signature declared in Lib.
    // (The target types are the fields' types.)
    #[allow(clippy::missing_transmute_annotations)]
    let lib = unsafe {
        Lib {
            add_perm: std::mem::transmute::<*mut c_void, _>(sym("acl_add_perm")?),
            calc_mask: std::mem::transmute::<*mut c_void, _>(sym("acl_calc_mask")?),
            copy_entry: std::mem::transmute::<*mut c_void, _>(sym("acl_copy_entry")?),
            create_entry: std::mem::transmute::<*mut c_void, _>(sym("acl_create_entry")?),
            delete_perm: {
                let _ = sym("acl_delete_entry")?;
                std::mem::transmute::<*mut c_void, _>(sym("acl_delete_perm")?)
            },
            dup: std::mem::transmute::<*mut c_void, _>(sym("acl_dup")?),
            free: {
                let _ = sym("acl_entries")?;
                let _ = sym("acl_extended_file")?;
                std::mem::transmute::<*mut c_void, _>(sym("acl_free")?)
            },
            from_mode: std::mem::transmute::<*mut c_void, _>(sym("acl_from_mode")?),
            from_text: std::mem::transmute::<*mut c_void, _>(sym("acl_from_text")?),
            get_entry: std::mem::transmute::<*mut c_void, _>(sym("acl_get_entry")?),
            get_file: {
                let _ = sym("acl_get_fd")?;
                std::mem::transmute::<*mut c_void, _>(sym("acl_get_file")?)
            },
            get_perm: std::mem::transmute::<*mut c_void, _>(sym("acl_get_perm")?),
            get_permset: std::mem::transmute::<*mut c_void, _>(sym("acl_get_permset")?),
            get_qualifier: std::mem::transmute::<*mut c_void, _>(sym("acl_get_qualifier")?),
            get_tag_type: std::mem::transmute::<*mut c_void, _>(sym("acl_get_tag_type")?),
            init: std::mem::transmute::<*mut c_void, _>(sym("acl_init")?),
            set_file: {
                let _ = sym("acl_set_fd")?;
                std::mem::transmute::<*mut c_void, _>(sym("acl_set_file")?)
            },
            to_any_text: {
                let _ = sym("acl_set_permset")?;
                let _ = sym("acl_set_qualifier")?;
                let _ = sym("acl_set_tag_type")?;
                std::mem::transmute::<*mut c_void, _>(sym("acl_to_any_text")?)
            },
        }
    };
    let _ = LIB.set(lib);
    Ok(())
}

fn lib() -> &'static Lib {
    LIB.get().expect("dlopen_libacl() succeeded before")
}

/// An `acl_t`, freed on drop.
#[derive(Debug)]
pub struct Acl(AclT);

impl Drop for Acl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: freeing an acl_t we own.
            unsafe { (lib().free)(self.0) };
        }
    }
}

fn neg_errno() -> i32 {
    -sys::errno()
}

/// Iterate entries: calls f(entry) until it returns Some.
fn for_each_entry<T>(acl: AclT, mut f: impl FnMut(EntryT) -> Result<Option<T>, i32>) -> Result<Option<T>, i32> {
    let mut e: EntryT = std::ptr::null_mut();
    // SAFETY: acl is a live acl_t; e is a valid out-pointer.
    let mut r = unsafe { (lib().get_entry)(acl, ACL_FIRST_ENTRY, &mut e) };
    while r > 0 {
        if let Some(v) = f(e)? {
            return Ok(Some(v));
        }
        // SAFETY: as above.
        r = unsafe { (lib().get_entry)(acl, ACL_NEXT_ENTRY, &mut e) };
    }
    if r < 0 {
        return Err(neg_errno());
    }
    Ok(None)
}

fn tag_of(e: EntryT) -> Result<c_int, i32> {
    let mut tag: c_int = 0;
    // SAFETY: e is a live entry; tag is a valid out-pointer.
    if unsafe { (lib().get_tag_type)(e, &mut tag) } < 0 {
        return Err(neg_errno());
    }
    Ok(tag)
}

fn qualifier_of(e: EntryT) -> Result<u32, i32> {
    // SAFETY: e is a USER or GROUP entry; the qualifier is an id_t we free.
    unsafe {
        let q = (lib().get_qualifier)(e);
        if q.is_null() {
            return Err(neg_errno());
        }
        let v = *(q as *const u32);
        (lib().free)(q);
        Ok(v)
    }
}

/// `calc_acl_mask_if_needed()`.
fn calc_mask_if_needed(acl: &mut Acl) -> Result<bool, i32> {
    let mut need = false;
    let has_mask = for_each_entry(acl.0, |e| {
        let tag = tag_of(e)?;
        if tag == ACL_MASK {
            return Ok(Some(()));
        }
        if tag == ACL_USER || tag == ACL_GROUP {
            need = true;
        }
        Ok(None)
    })?;
    if has_mask.is_some() {
        return Ok(false);
    }
    // SAFETY: acl.0 is a live acl_t.
    if need && unsafe { (lib().calc_mask)(&mut acl.0) } < 0 {
        return Err(neg_errno());
    }
    Ok(need)
}

/// `add_base_acls_if_needed(&acl, path)`.
fn add_base_acls_if_needed(acl: &mut Acl, path: &[u8]) -> Result<(), i32> {
    let (mut u, mut g, mut o) = (false, false, false);
    let all = for_each_entry(acl.0, |e| {
        match tag_of(e)? {
            ACL_USER_OBJ => u = true,
            ACL_GROUP_OBJ => g = true,
            ACL_OTHER => o = true,
            _ => {}
        }
        Ok(if u && g && o { Some(()) } else { None })
    })?;
    if all.is_some() {
        return Ok(());
    }
    let st = sys::stat(path)?;
    // SAFETY: acl_from_mode() allocates a new acl_t.
    let basic = Acl(unsafe { (lib().from_mode)(st.st_mode) });
    if basic.0.is_null() {
        return Err(neg_errno());
    }
    let mut dst_acl = acl.0;
    for_each_entry(basic.0, |i| {
        let tag = tag_of(i)?;
        if (tag == ACL_USER_OBJ && u) || (tag == ACL_GROUP_OBJ && g) || (tag == ACL_OTHER && o) {
            return Ok(None);
        }
        let mut dst: EntryT = std::ptr::null_mut();
        // SAFETY: dst_acl is live; dst receives a new entry, then i is copied into it.
        unsafe {
            if (lib().create_entry)(&mut dst_acl, &mut dst) < 0 {
                return Err(neg_errno());
            }
            if (lib().copy_entry)(dst, i) < 0 {
                return Err(neg_errno());
            }
        }
        Ok(None::<()>)
    })?;
    acl.0 = dst_acl;
    Ok(())
}

/// The parsed ACLs of an `a`/`A` line (`parse_acl()`).
#[derive(Debug, Default)]
pub struct ParsedAcl {
    pub access: Option<Acl>,
    pub access_exec: Option<Acl>,
    pub default: Option<Acl>,
}

fn from_text(s: &[u8]) -> Result<Acl, i32> {
    let c = to_cstring(s);
    // SAFETY: c is NUL-terminated.
    let a = unsafe { (lib().from_text)(c.as_ptr()) };
    if a.is_null() {
        return Err(neg_errno());
    }
    Ok(Acl(a))
}

/// `parse_acl(text, &access, &access_exec, &default, want_mask)`.
pub fn parse_acl(text: &[u8], want_mask: bool) -> Result<ParsedAcl, i32> {
    use crate::extract::{EXTRACT_DONT_COALESCE_SEPARATORS, EXTRACT_RETAIN_ESCAPE, strv_split_full};
    use crate::string::strv_join;
    let split = crate::string::strv_split(text, b",");
    dlopen_libacl(libc::LOG_DEBUG)?;
    let (mut a, mut e, mut d): (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) = (vec![], vec![], vec![]);
    for entry in &split {
        let mut es = strv_split_full(entry, Some(b":"), EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_RETAIN_ESCAPE)?;
        let n = es.len();
        if !(3..=4).contains(&n) {
            return Err(-libc::EINVAL);
        }
        for b in es[n - 1].iter_mut() {
            if *b == b'X' {
                *b = b'x';
            }
        }
        if n == 4 {
            if es[0] != b"default" && es[0] != b"d" {
                return Err(-libc::EINVAL);
            }
            d.push(strv_join(&es[1..], b":"));
        } else {
            let j = strv_join(&es, b":");
            if j != *entry { e.push(j) } else { a.push(j) }
        }
    }
    let mut out = ParsedAcl::default();
    if !a.is_empty() {
        let mut acl = from_text(&strv_join(&a, b","))?;
        if want_mask {
            calc_mask_if_needed(&mut acl)?;
        }
        out.access = Some(acl);
    }
    if !e.is_empty() {
        out.access_exec = Some(from_text(&strv_join(&e, b","))?);
    }
    if !d.is_empty() {
        let mut acl = from_text(&strv_join(&d, b","))?;
        if want_mask {
            calc_mask_if_needed(&mut acl)?;
        }
        out.default = Some(acl);
    }
    Ok(out)
}

fn get_file(path: &[u8], ty: c_uint) -> Result<Acl, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let a = unsafe { (lib().get_file)(c.as_ptr(), ty) };
    if a.is_null() {
        return Err(neg_errno());
    }
    Ok(Acl(a))
}

fn entry_has_exec(e: EntryT) -> Result<bool, i32> {
    let mut ps: PermsetT = std::ptr::null_mut();
    // SAFETY: e is live; ps is a valid out-pointer.
    unsafe {
        if (lib().get_permset)(e, &mut ps) < 0 {
            return Err(neg_errno());
        }
        let r = (lib().get_perm)(ps, ACL_EXECUTE);
        if r < 0 {
            return Err(neg_errno());
        }
        Ok(r > 0)
    }
}

/// tmpfiles' `parse_acl_cond_exec()`: resolve "X" against the file.
pub fn parse_acl_cond_exec(
    path: &[u8],
    is_dir: bool,
    cond_exec: &Acl,
    access: Option<&Acl>,
    append: bool,
) -> Result<Acl, i32> {
    dlopen_libacl(libc::LOG_DEBUG)?;
    let has_exec = if !is_dir {
        let old = get_file(path, ACL_TYPE_ACCESS)?;
        let mut has = for_each_entry(old.0, |e| {
            let tag = tag_of(e)?;
            if tag == ACL_MASK {
                return Ok(None);
            }
            if !append && (tag == ACL_USER || tag == ACL_GROUP) {
                return Ok(None);
            }
            Ok(if entry_has_exec(e)? { Some(()) } else { None })
        })?
        .is_some();
        if !has && let Some(acc) = access {
            has = for_each_entry(acc.0, |e| Ok(if entry_has_exec(e)? { Some(()) } else { None }))?.is_some();
        }
        has
    } else {
        true
    };
    // SAFETY: dup/init allocate a new acl_t.
    let mut parsed = Acl(unsafe {
        match access {
            Some(a) => (lib().dup)(a.0),
            None => (lib().init)(0),
        }
    });
    if parsed.0.is_null() {
        return Err(neg_errno());
    }
    let mut p = parsed.0;
    for_each_entry(cond_exec.0, |entry| {
        let mut pe: EntryT = std::ptr::null_mut();
        // SAFETY: p is live; pe receives a new entry.
        unsafe {
            if (lib().create_entry)(&mut p, &mut pe) < 0 {
                return Err(neg_errno());
            }
            if (lib().copy_entry)(pe, entry) < 0 {
                return Err(neg_errno());
            }
            if !has_exec {
                let mut ps: PermsetT = std::ptr::null_mut();
                if (lib().get_permset)(pe, &mut ps) < 0 {
                    return Err(neg_errno());
                }
                if (lib().delete_perm)(ps, ACL_EXECUTE) < 0 {
                    return Err(neg_errno());
                }
            }
        }
        Ok(None::<()>)
    })?;
    parsed.0 = p;
    if !append {
        calc_mask_if_needed(&mut parsed)?;
    }
    Ok(parsed)
}

fn entry_equal(a: EntryT, b: EntryT) -> Result<bool, i32> {
    let (ta, tb) = (tag_of(a)?, tag_of(b)?);
    if ta != tb {
        return Ok(false);
    }
    match ta {
        ACL_USER | ACL_GROUP => Ok(qualifier_of(a)? == qualifier_of(b)?),
        _ => Ok(true),
    }
}

/// `acls_for_file(path, type, acl, &ret)`: the file's ACL with acl's entries merged in.
fn acls_for_file(path: &[u8], ty: c_uint, acl: &Acl) -> Result<Acl, i32> {
    dlopen_libacl(libc::LOG_DEBUG)?;
    let mut applied = get_file(path, ty)?;
    let mut ap = applied.0;
    for_each_entry(acl.0, |i| {
        let found = for_each_entry(ap, |j| Ok(if entry_equal(j, i)? { Some(j) } else { None }))?;
        let j = match found {
            Some(j) => j,
            None => {
                let mut j: EntryT = std::ptr::null_mut();
                // SAFETY: ap is live; j receives a new entry.
                if unsafe { (lib().create_entry)(&mut ap, &mut j) } < 0 {
                    return Err(neg_errno());
                }
                j
            }
        };
        // SAFETY: both entries are live.
        if unsafe { (lib().copy_entry)(j, i) } < 0 {
            return Err(neg_errno());
        }
        Ok(None::<()>)
    })?;
    applied.0 = ap;
    Ok(applied)
}

/// `acl_to_any_text(acl, NULL, ',', TEXT_ABBREVIATE)`.
fn to_text(acl: &Acl) -> Option<Vec<u8>> {
    // SAFETY: acl.0 is live; the returned text is freed with acl_free.
    unsafe {
        let p = (lib().to_any_text)(acl.0, std::ptr::null(), b',' as c_char, TEXT_ABBREVIATE);
        if p.is_null() {
            return None;
        }
        let s = CStr::from_ptr(p).to_bytes().to_vec();
        (lib().free)(p as *mut c_void);
        Some(s)
    }
}

/// What tmpfiles' `path_set_acl()` needs: the final ACL and its text,
/// before setting it (so the caller can log first).
pub fn prepare_acl(path: &[u8], ty: c_uint, acl: &Acl, modify: bool) -> Result<(Acl, Option<Vec<u8>>), i32> {
    dlopen_libacl(libc::LOG_DEBUG)?;
    let mut dup = if modify {
        let mut d = acls_for_file(path, ty, acl)?;
        calc_mask_if_needed(&mut d)?;
        d
    } else {
        // SAFETY: acl_dup() allocates a new acl_t.
        let d = unsafe { (lib().dup)(acl.0) };
        if d.is_null() {
            return Err(neg_errno());
        }
        Acl(d)
    };
    add_base_acls_if_needed(&mut dup, path)?;
    let t = to_text(&dup);
    Ok((dup, t))
}

/// `acl_set_file(path, type, acl)`.
pub fn set_file(path: &[u8], ty: c_uint, acl: &Acl) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated and acl.0 is live.
    if unsafe { (lib().set_file)(c.as_ptr(), ty, acl.0) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `dlopen_safe(filename, &dl, &dle)` for a library that's only probed:
/// Ok if it loads (it's closed again), else (-errno, dlerror text).
pub fn dlopen_probe(filename: &[u8]) -> Result<(), (i32, Option<Vec<u8>>)> {
    let blocked = DLOPEN_BLOCKED.load(std::sync::atomic::Ordering::Relaxed);
    let mut flags = libc::RTLD_NOW | libc::RTLD_NODELETE;
    if blocked {
        flags |= libc::RTLD_NOLOAD;
    }
    let name = crate::bytes::to_cstring(filename);
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
            return Err((r, None));
        }
        let e = crate::errno::errno_or_else(libc::ENOPKG);
        let dle = dlerror_text();
        return Err((e, if dle.is_empty() { None } else { Some(dle) }));
    }
    // SAFETY: closing the handle dlopen() returned.
    unsafe { libc::dlclose(dl) };
    Ok(())
}
