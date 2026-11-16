// SPDX-License-Identifier: LGPL-2.1-or-later
//! `module-util.c`: libkmod, loaded with `dlopen()` as upstream does.  Like
//! `sys.rs`, this module holds unsafe code: the libkmod calls go through
//! function pointers.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::sync::OnceLock;

use crate::errno::strerror;
use crate::log::{LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING};
use crate::sys_dl::{Sym, dlopen_many};
use crate::{log_debug, log_full, log_full_errno};

type Ctx = *mut c_void;
type List = *mut c_void;
type Module = *mut c_void;
type LogFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, c_int, *const c_char, *const c_char, *mut c_void);

const KMOD_MODULE_BUILTIN: c_int = 0;
const KMOD_MODULE_LIVE: c_int = 1;
const KMOD_PROBE_APPLY_BLACKLIST: c_uint = 0x20;
const KMOD_RESOURCES_OK: c_int = 0;

#[derive(Debug)]
struct Lib {
    list_next: unsafe extern "C" fn(List, List) -> List,
    load_resources: unsafe extern "C" fn(Ctx) -> c_int,
    module_get_initstate: unsafe extern "C" fn(Module) -> c_int,
    module_get_module: unsafe extern "C" fn(List) -> Module,
    module_get_name: unsafe extern "C" fn(Module) -> *const c_char,
    module_new_from_lookup: unsafe extern "C" fn(Ctx, *const c_char, *mut List) -> c_int,
    module_probe_insert_module:
        unsafe extern "C" fn(Module, c_uint, *const c_char, *const c_void, *const c_void, *const c_void) -> c_int,
    module_unref: unsafe extern "C" fn(Module) -> Module,
    module_unref_list: unsafe extern "C" fn(List) -> c_int,
    new: unsafe extern "C" fn(*const c_char, *const *const c_char) -> Ctx,
    set_log_fn: unsafe extern "C" fn(Ctx, LogFn, *const c_void),
    unref: unsafe extern "C" fn(Ctx) -> Ctx,
    validate_resources: unsafe extern "C" fn(Ctx) -> c_int,
}

static LIB: OnceLock<Result<Lib, i32>> = OnceLock::new();

/// `dlopen_libkmod(log_level)`.
fn lib(log_level: i32) -> Result<&'static Lib, i32> {
    let r = LIB.get_or_init(|| {
        let s = dlopen_many(
            "libkmod.so.2",
            &[
                "kmod_list_next",
                "kmod_load_resources",
                "kmod_module_get_initstate",
                "kmod_module_get_module",
                "kmod_module_get_name",
                "kmod_module_new_from_lookup",
                "kmod_module_probe_insert_module",
                "kmod_module_unref",
                "kmod_module_unref_list",
                "kmod_new",
                "kmod_set_log_fn",
                "kmod_unref",
                "kmod_validate_resources",
            ],
            log_level,
        )?;
        let f = |i: usize| -> Sym { s[i] };
        // SAFETY: each symbol is the libkmod function with the signature
        // declared in Lib.
        #[allow(clippy::missing_transmute_annotations)]
        Ok(unsafe {
            Lib {
                list_next: std::mem::transmute(f(0).0),
                load_resources: std::mem::transmute(f(1).0),
                module_get_initstate: std::mem::transmute(f(2).0),
                module_get_module: std::mem::transmute(f(3).0),
                module_get_name: std::mem::transmute(f(4).0),
                module_new_from_lookup: std::mem::transmute(f(5).0),
                module_probe_insert_module: std::mem::transmute(f(6).0),
                module_unref: std::mem::transmute(f(7).0),
                module_unref_list: std::mem::transmute(f(8).0),
                new: std::mem::transmute(f(9).0),
                set_log_fn: std::mem::transmute(f(10).0),
                unref: std::mem::transmute(f(11).0),
                validate_resources: std::mem::transmute(f(12).0),
            }
        })
    });
    r.as_ref().map_err(|e| *e)
}

unsafe extern "C" {
    #[link_name = "vsnprintf"]
    fn vsnprintf_raw(buf: *mut c_char, size: usize, format: *const c_char, ap: *mut c_void) -> c_int;
}

/// `systemd_kmod_log()`: libkmod's messages go to our log.
unsafe extern "C" fn kmod_log(
    _data: *mut c_void,
    priority: c_int,
    _file: *const c_char,
    _line: c_int,
    _func: *const c_char,
    format: *const c_char,
    args: *mut c_void,
) {
    let mut buf = vec![0u8; 2048];
    // SAFETY: buf is valid for its length; format and args come from libkmod.
    let n = unsafe { vsnprintf_raw(buf.as_mut_ptr().cast(), buf.len(), format, args) };
    if n < 0 {
        return;
    }
    buf.truncate((n as usize).min(buf.len() - 1));
    while buf.last() == Some(&b'\n') {
        buf.pop();
    }
    log_full!(priority, buf);
}

/// A `struct kmod_ctx`.
#[derive(Debug)]
pub struct KmodCtx(Ctx);

// SAFETY: used from one thread at a time.
unsafe impl Send for KmodCtx {}

impl Drop for KmodCtx {
    fn drop(&mut self) {
        if let Ok(l) = lib(LOG_DEBUG) {
            // SAFETY: self.0 is a live context.
            unsafe { (l.unref)(self.0) };
        }
    }
}

fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return b"(null)".to_vec();
    }
    // SAFETY: libkmod returns NUL-terminated strings.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

impl KmodCtx {
    /// `module_setup_context(&ctx)`.
    pub fn new() -> Result<KmodCtx, i32> {
        let l = lib(LOG_DEBUG)?;
        // SAFETY: NULL dirname and config paths mean the defaults.
        let ctx = unsafe { (l.new)(std::ptr::null(), std::ptr::null()) };
        if ctx.is_null() {
            return Err(-libc::ENOMEM);
        }
        // SAFETY: ctx is live; kmod_log has the log function's signature.
        unsafe {
            (l.load_resources)(ctx);
            (l.set_log_fn)(ctx, kmod_log, std::ptr::null());
        }
        Ok(KmodCtx(ctx))
    }

    /// `kmod_validate_resources(ctx) == KMOD_RESOURCES_OK`.
    pub fn resources_ok(&self) -> bool {
        let Ok(l) = lib(LOG_DEBUG) else { return true };
        // SAFETY: self.0 is live.
        unsafe { (l.validate_resources)(self.0) == KMOD_RESOURCES_OK }
    }

    /// `module_load_and_warn(ctx, module, verbose)`.
    pub fn module_load_and_warn(&self, module: &[u8], verbose: bool) -> i32 {
        let l = match lib(LOG_DEBUG) {
            Ok(l) => l,
            Err(r) => return r,
        };
        let lvl = |v: i32| if verbose { v } else { LOG_DEBUG };
        log_debug!("Loading module: ", module);
        let c = CString::new(module.to_vec()).unwrap_or_default();
        let mut list: List = std::ptr::null_mut();
        // SAFETY: valid ctx, NUL-terminated alias, out-pointer.
        let r = unsafe { (l.module_new_from_lookup)(self.0, c.as_ptr(), &mut list) };
        if r < 0 {
            return log_full_errno!(lvl(LOG_ERR), r, "Failed to look up module alias '", module, "': ", strerror(r));
        }
        if list.is_null() {
            return log_full_errno!(
                lvl(LOG_ERR),
                crate::errno::synthetic(libc::ENOENT),
                "Failed to find module '",
                module,
                "'"
            );
        }
        let mut ret = r;
        let mut denylist: Option<Vec<Vec<u8>>> = None;
        let mut itr = list;
        while !itr.is_null() {
            // SAFETY: itr is an entry of the live list.
            let m = unsafe { (l.module_get_module)(itr) };
            // SAFETY: m is a module reference we own until module_unref().
            let (state, name) = unsafe { ((l.module_get_initstate)(m), cstr((l.module_get_name)(m))) };
            match state {
                KMOD_MODULE_BUILTIN => {
                    log_full!(lvl(LOG_INFO), "Module '", &name[..], "' is built in");
                }
                KMOD_MODULE_LIVE => {
                    log_debug!("Module '", &name[..], "' is already loaded");
                }
                _ => {
                    // SAFETY: m is live; NULL options and callbacks.
                    let err = unsafe {
                        (l.module_probe_insert_module)(
                            m,
                            KMOD_PROBE_APPLY_BLACKLIST,
                            std::ptr::null(),
                            std::ptr::null(),
                            std::ptr::null(),
                            std::ptr::null(),
                        )
                    };
                    if err == 0 {
                        log_full!(lvl(LOG_INFO), "Inserted module '", &name[..], "'");
                    } else if err == KMOD_PROBE_APPLY_BLACKLIST as c_int {
                        log_full!(lvl(LOG_INFO), "Module '", &name[..], "' is deny-listed (by kmod)");
                    } else {
                        let mut skip = false;
                        if err == -libc::EPERM {
                            let d = denylist.get_or_insert_with(|| {
                                let mut out = Vec::new();
                                match crate::proc_cmdline::proc_cmdline_strv() {
                                    Err(r) => {
                                        log_full_errno!(
                                            lvl(LOG_WARNING),
                                            r,
                                            "Failed to parse kernel command line, ignoring: ",
                                            strerror(r)
                                        );
                                    }
                                    Ok(words) => {
                                        for w in words {
                                            let (k, v) = match w.iter().position(|&b| b == b'=') {
                                                Some(i) => (w[..i].to_vec(), Some(w[i + 1..].to_vec())),
                                                None => (w.clone(), None),
                                            };
                                            if !crate::proc_cmdline::key_streq(&k, b"module_blacklist") {
                                                continue;
                                            }
                                            if crate::proc_cmdline::value_missing(&k, v.as_deref()) {
                                                continue;
                                            }
                                            for x in v.unwrap_or_default().split(|&b| b == b',') {
                                                if !x.is_empty() && !out.iter().any(|o: &Vec<u8>| o == x) {
                                                    out.push(x.to_vec());
                                                }
                                            }
                                        }
                                    }
                                }
                                out
                            });
                            if d.contains(&name) {
                                log_full!(lvl(LOG_INFO), "Module '", &name[..], "' is deny-listed (by kernel)");
                                skip = true;
                            }
                        }
                        if !skip {
                            let level = if !verbose {
                                LOG_DEBUG
                            } else if err == -libc::ENODEV {
                                LOG_NOTICE
                            } else if err == -libc::ENOENT {
                                LOG_WARNING
                            } else {
                                LOG_ERR
                            };
                            log_full_errno!(level, err, "Failed to insert module '", &name[..], "': ", strerror(err));
                            if err != -libc::ENODEV && err != -libc::ENOENT {
                                ret = err;
                            }
                        }
                    }
                }
            }
            // SAFETY: m was returned with a reference by module_get_module().
            unsafe { (l.module_unref)(m) };
            // SAFETY: list and itr are live.
            itr = unsafe { (l.list_next)(list, itr) };
        }
        // SAFETY: list is the live list from the lookup.
        unsafe { (l.module_unref_list)(list) };
        ret
    }
}
