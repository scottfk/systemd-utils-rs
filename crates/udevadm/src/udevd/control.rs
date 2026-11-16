// SPDX-License-Identifier: LGPL-2.1-or-later
//! `udev-varlink.c`: the io.systemd.Udev and io.systemd.service
//! interfaces of udevd, and the `manager_set_environment()` part of
//! `udev-config.c`.

use shared::errno::strerror;
use shared::json::Json;
use shared::varlink::{Call, Field, FieldType, Interface, Method, SERVER_INHERIT_USERDATA, SERVER_ROOT_ONLY, Server};
use shared::{log_debug, log_debug_errno, log_error_errno, log_warning_errno};

use super::{EVENT_PRIORITY_VARLINK, Ev, Manager};

const UDEV_VARLINK_ADDRESS: &[u8] = b"/run/udev/io.systemd.Udev";

pub static IO_SYSTEMD_SERVICE: Interface = Interface {
    name: "io.systemd.service",
    methods: &[
        Method { name: "Ping", fields: &[] },
        Method {
            name: "Reload",
            fields: &[Field::input("allowInteractiveAuthentication", FieldType::Bool).nullable()],
        },
        Method { name: "SetLogLevel", fields: &[Field::input("level", FieldType::Int).nullable()] },
        Method { name: "GetLogLevel", fields: &[Field::output("level", FieldType::Int)] },
        Method {
            name: "GetEnvironment",
            fields: &[Field::output("environment", FieldType::String).nullable().array()],
        },
    ],
};

pub static IO_SYSTEMD_UDEV: Interface = Interface {
    name: "io.systemd.Udev",
    methods: &[
        Method { name: "SetTrace", fields: &[Field::input("enable", FieldType::Bool)] },
        Method { name: "SetChildrenMax", fields: &[Field::input("number", FieldType::Int)] },
        Method { name: "SetEnvironment", fields: &[Field::input("assignments", FieldType::String).array()] },
        Method { name: "Revert", fields: &[] },
        Method { name: "StartExecQueue", fields: &[] },
        Method { name: "StopExecQueue", fields: &[] },
        Method { name: "Exit", fields: &[] },
    ],
};

fn slot(m: &mut Manager) -> &mut Option<Server<Manager>> {
    &mut m.varlink
}

/// `json_log()` at debug level, as `sd_json_dispatch()` logs.
fn json_log(parts: &[&[u8]]) {
    log_debug!(parts.concat());
}

/// `sd_varlink_dispatch()` of a table with one mandatory field: the field's
/// value (None if null), or the answer's errno.
fn dispatch_one(call: &mut Call, name: &str) -> Result<Option<Json>, i32> {
    let p = call.parameters.clone();
    if let Json::Object(o) = &p {
        for (k, _) in o {
            if k != name.as_bytes() {
                json_log(&[b"Unexpected object field '", k, b"'."]);
                return Err(call.error_invalid_parameter(k));
            }
        }
    }
    match p.get(name) {
        None => {
            json_log(&[b"Missing object field '", name.as_bytes(), b"'."]);
            Err(call.error_invalid_parameter(name.as_bytes()))
        }
        Some(Json::Null) => Ok(None),
        Some(v) => Ok(Some(v.clone())),
    }
}

/// `sd_json_dispatch_int()` and friends: an integer, also one formatted as
/// a decimal string.
fn json_int(v: &Json) -> Option<i64> {
    match v {
        Json::String(s) => std::str::from_utf8(s).ok()?.parse().ok(),
        _ => v.as_i64(),
    }
}

fn vl_ping(_m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    log_debug!("Received io.systemd.service.Ping");
    call.reply(None)
}

fn vl_reload(m: &mut Manager, ev: &mut Ev, call: &mut Call) -> i32 {
    if let Json::Object(o) = call.parameters.clone() {
        for (k, v) in o {
            if k != b"allowInteractiveAuthentication" {
                json_log(&[b"Unexpected object field '", &k, b"'."]);
                return call.error_invalid_parameter(&k);
            }
            if !matches!(v, Json::Bool(_) | Json::Null) {
                json_log(&[b"JSON field 'allowInteractiveAuthentication' is not a boolean."]);
                return call.error_invalid_parameter(&k);
            }
        }
    }
    log_debug!("Received io.systemd.service.Reload()");
    m.reload(ev, true);
    call.reply(None)
}

fn vl_set_log_level(m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let level = match dispatch_one(call, "level") {
        Err(r) => return r,
        Ok(None) => shared::log::LOG_INFO,
        Ok(Some(v)) => match json_int(&v) {
            None => {
                json_log(&[b"JSON field 'level' is not an integer, nor one formatted as decimal string."]);
                return call.error_invalid_parameter(b"level");
            }
            Some(l) if !(0..=7).contains(&l) => {
                json_log(&[b"JSON field 'level' is not a valid log level."]);
                return call.error_invalid_parameter(b"level");
            }
            Some(l) => l as i32,
        },
    };
    log_debug!("Received io.systemd.service.SetLogLevel(", level.to_string(), ")");
    if m.configs.set_log_level(level) {
        m.kill_workers(libc::SIGTERM);
    }
    call.reply(None)
}

fn vl_get_log_level(_m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    log_debug!("Received io.systemd.service.GetLogLevel()");
    call.reply(Some(Json::Object(vec![(b"level".to_vec(), Json::Integer(shared::log::log_get_max_level() as i64))])))
}

fn vl_get_environment(_m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    let uid = match call.peer_uid() {
        Ok(u) => u,
        Err(r) => return r,
    };
    if uid != 0 && uid != shared::sys::getuid() {
        let p = call.parameters.clone();
        return call.error(shared::varlink::ERROR_PERMISSION_DENIED, Some(p));
    }
    log_debug!("Received io.systemd.service.GetEnvironment()");
    use std::os::unix::ffi::OsStrExt;
    let mut l: Vec<Vec<u8>> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let e = shared::bcat!(k.as_bytes(), "=", v.as_bytes());
        if !shared::env::env_assignment_is_valid(&e) {
            let p = call.parameters.clone();
            return call.error("io.systemd.service.InconsistentEnvironment", Some(p));
        }
        // strv_env_replace_strdup()
        let klen = k.as_bytes().len() + 1;
        match l.iter_mut().find(|x| x.len() >= klen && x[..klen] == e[..klen]) {
            Some(x) => *x = e,
            None => l.push(e),
        }
    }
    call.reply(Some(Json::Object(vec![(b"environment".to_vec(), Json::strv(&l))])))
}

fn vl_set_trace(m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let enable = match dispatch_one(call, "enable") {
        Err(r) => return r,
        Ok(None) => false,
        Ok(Some(Json::Bool(b))) => b,
        Ok(Some(_)) => {
            json_log(&[b"JSON field 'enable' is not a boolean."]);
            return call.error_invalid_parameter(b"enable");
        }
    };
    log_debug!("Received io.systemd.service.SetTrace(", if enable { "yes" } else { "no" }, ")");
    if m.configs.set_trace(enable) {
        m.kill_workers(libc::SIGTERM);
    }
    call.reply(None)
}

fn vl_set_children_max(m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let n = match dispatch_one(call, "number") {
        Err(r) => return r,
        Ok(None) => u32::MAX,
        Ok(Some(v)) => {
            let u = match &v {
                Json::String(s) => std::str::from_utf8(s).ok().and_then(|s| s.parse::<u64>().ok()),
                _ => v.as_u64(),
            };
            match u {
                None => {
                    json_log(&[
                        b"JSON field 'number' is not an unsigned integer, nor one formatted as decimal string.",
                    ]);
                    return call.error_invalid_parameter(b"number");
                }
                Some(u) if u > u32::MAX as u64 => {
                    json_log(&[b"JSON field 'number' out of bounds."]);
                    return call.error_invalid_parameter(b"number");
                }
                Some(u) => u as u32,
            }
        }
    };
    log_debug!("Received io.systemd.Udev.SetChildrenMax(", n.to_string(), ")");
    m.configs.set_children_max(n);
    m.notify_ready();
    call.reply(None)
}

/// `manager_set_environment_one()`: Ok(true) if changed.
pub fn set_environment_one(m: &mut Manager, s: &[u8]) -> Result<bool, i32> {
    let i = s.iter().position(|&c| c == b'=').ok_or(-libc::EINVAL)?;
    let (key, value) = (&s[..i], &s[i + 1..]);
    if value.is_empty() {
        let before = m.properties.len();
        m.properties.retain(|(k, _)| k != key);
        return Ok(before != m.properties.len());
    }
    match m.properties.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) if v == value => Ok(false),
        Some((_, v)) => {
            *v = value.to_vec();
            Ok(true)
        }
        None => {
            m.properties.push((key.to_vec(), value.to_vec()));
            Ok(true)
        }
    }
}

fn vl_set_environment(m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let v = match dispatch_one(call, "assignments") {
        Err(r) => return r,
        Ok(None) => Vec::new(),
        Ok(Some(Json::Array(a))) => {
            let mut n: Vec<Vec<u8>> = Vec::new();
            for i in a {
                let Json::String(e) = i else {
                    json_log(&[b"JSON field 'assignments' is not an array of strings."]);
                    return call.error_invalid_parameter(b"assignments");
                };
                if !shared::env::env_assignment_is_valid(&e) {
                    json_log(&[b"JSON field 'assignments' contains invalid environment variable assignment."]);
                    return call.error_invalid_parameter(b"assignments");
                }
                let klen = e.iter().position(|&c| c == b'=').unwrap_or(e.len()) + 1;
                match n.iter_mut().find(|x| x.len() >= klen && x[..klen] == e[..klen]) {
                    Some(x) => *x = e,
                    None => n.push(e),
                }
            }
            n
        }
        Ok(Some(_)) => {
            json_log(&[b"JSON field 'assignments' is not an array."]);
            return call.error_invalid_parameter(b"assignments");
        }
    };
    log_debug!("Received io.systemd.Udev.SetEnvironment()");
    let mut changed = false;
    for s in &v {
        match set_environment_one(m, s) {
            Err(r) => {
                log_debug_errno!(r, "Failed to update environment '", &s[..], "', ignoring: ", strerror(r));
            }
            Ok(c) => changed |= c,
        }
    }
    if changed {
        m.kill_workers(libc::SIGTERM);
    }
    call.reply(None)
}

fn vl_revert(m: &mut Manager, _ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    log_debug!("Received io.systemd.Udev.Revert()");
    m.revert();
    call.reply(None)
}

fn vl_start_stop_exec_queue(m: &mut Manager, ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    log_debug!("Received ", &call.method[..], "()");
    m.stop_exec_queue = call.method == b"io.systemd.Udev.StopExecQueue";
    if m.stop_exec_queue {
        m.reset_kill_workers_timer(ev);
    }
    call.reply(None)
}

fn vl_exit(m: &mut Manager, ev: &mut Ev, call: &mut Call) -> i32 {
    let r = shared::varlink::dispatch_empty(call);
    if r != 0 {
        return r;
    }
    call.flush_close();
    log_debug!("Received io.systemd.udev.Exit()");
    m.exit(ev);
    call.reply(None)
}

/// `symlink_idempotent(from, to, false)`.
fn symlink_idempotent(from: &[u8], to: &[u8]) -> Result<(), i32> {
    match shared::sys::symlinkat(from, libc::AT_FDCWD, to) {
        Ok(()) => Ok(()),
        Err(r) if r != -libc::EEXIST => Err(r),
        Err(r) => match shared::sys::readlink(to) {
            Ok(p) if p == from => Ok(()),
            Ok(_) => Err(r),
            Err(e) if e == -libc::EINVAL => Err(r),
            Err(e) => Err(e),
        },
    }
}

/// `manager_start_varlink_server(manager, fd)`.
pub fn start_varlink_server(m: &mut Manager, ev: &mut Ev, fd: Option<i32>) -> Result<(), i32> {
    let mut v = Server::new(SERVER_ROOT_ONLY | SERVER_INHERIT_USERDATA, slot);
    v.attach_event(EVENT_PRIORITY_VARLINK);
    let r = match fd {
        None => v.listen_address(ev, UDEV_VARLINK_ADDRESS, 0o644),
        Some(fd) => v.listen_fd(ev, fd),
    };
    if let Err(r) = r {
        return Err(log_error_errno!(r, "Failed to bind to Varlink socket: ", strerror(r)));
    }
    if let Err(r) = symlink_idempotent(UDEV_VARLINK_ADDRESS, b"/run/udev/control") {
        log_warning_errno!(
            r,
            "Failed to create symlink /run/udev/control to /run/udev/io.systemd.Udev, ignoring: ",
            strerror(r)
        );
    }
    for i in [&IO_SYSTEMD_SERVICE, &IO_SYSTEMD_UDEV] {
        if let Err(r) = v.add_interface(i) {
            return Err(log_error_errno!(r, "Failed to add Varlink interface: ", strerror(r)));
        }
    }
    let methods: [(&'static str, shared::varlink::MethodFn<Manager>); 12] = [
        ("io.systemd.service.Ping", vl_ping),
        ("io.systemd.service.Reload", vl_reload),
        ("io.systemd.service.SetLogLevel", vl_set_log_level),
        ("io.systemd.service.GetLogLevel", vl_get_log_level),
        ("io.systemd.service.GetEnvironment", vl_get_environment),
        ("io.systemd.Udev.SetTrace", vl_set_trace),
        ("io.systemd.Udev.SetChildrenMax", vl_set_children_max),
        ("io.systemd.Udev.SetEnvironment", vl_set_environment),
        ("io.systemd.Udev.Revert", vl_revert),
        ("io.systemd.Udev.StartExecQueue", vl_start_stop_exec_queue),
        ("io.systemd.Udev.StopExecQueue", vl_start_stop_exec_queue),
        ("io.systemd.Udev.Exit", vl_exit),
    ];
    for (name, f) in methods {
        if let Err(r) = v.bind_method(name, f) {
            return Err(log_error_errno!(r, "Failed to bind Varlink methods: ", strerror(r)));
        }
    }
    m.varlink = Some(v);
    Ok(())
}
