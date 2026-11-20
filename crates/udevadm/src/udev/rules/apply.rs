// SPDX-License-Identifier: GPL-2.0-or-later
//! Applying rules to an event: `udev_rule_apply_token_to_event()` and
//! the line and file loops around it.

use super::*;
use crate::udev::def::{Escape, EventMode, UDEV_NAME_SIZE, UDEV_PATH_SIZE};
use crate::udev::event::Event;
use crate::udev::format::{UDEV_ALLOWED_CHARS_INPUT, strscpy, udev_event_apply_format, udev_resolve_subsys_kernel};
use crate::udev::util::{device_get_property_value_with_fallback, udev_replace_chars};
use shared::sd_device::{Action, device_action_to_string, errno_is_neg_device_absent};
use shared::sys::fnmatch;

/// The line a token belongs to, for logging.
#[derive(Clone, Copy)]
struct Ctx<'a> {
    file: &'a RuleFile,
    line: &'a Line,
}

/// `_log_event_full_errno_zerook(event, token, level, error, ...)`.
fn log_event(ctx: Ctx, event: &Event, token: &Token, level: i32, error: i32, msg: Vec<u8>) -> i32 {
    let dev = if token.is_for_parents() { event.dev_parent.as_deref() } else { Some(&*event.dev) };
    log_rule_file(dev, Some(ctx.file), ctx.line.line_number, level, error, bcat!(token.token_str, ": ", msg))
}

fn log_debug_(ctx: Ctx, event: &Event, token: &Token, msg: Vec<u8>) {
    log_event(ctx, event, token, LOG_DEBUG, 0, msg);
}

fn log_trace(ctx: Ctx, event: &Event, token: &Token, msg: Vec<u8>) {
    if event.trace {
        log_event(ctx, event, token, LOG_DEBUG, 0, msg);
    }
}

fn log_trace_errno(ctx: Ctx, event: &Event, token: &Token, error: i32, msg: Vec<u8>) {
    if event.trace {
        log_event(ctx, event, token, LOG_DEBUG, error, msg);
    }
}

/// `log_event_result(event, token, result)`.
fn result(ctx: Ctx, event: &Event, token: &Token, r: bool) -> Result<bool, i32> {
    log_trace(ctx, event, token, if r { b"PASS".to_vec() } else { b"FAIL".to_vec() });
    Ok(r)
}

/// `log_event_done(event, token)`.
fn done(ctx: Ctx, event: &Event, token: &Token) -> Result<bool, i32> {
    log_trace(ctx, event, token, b"DONE".to_vec());
    Ok(true)
}

/// `log_event_final_set(event, token)`.
fn final_set(ctx: Ctx, event: &Event, token: &Token) -> Result<bool, i32> {
    log_trace(
        ctx,
        event,
        token,
        bcat!(
            "Already assigned final value, ignoring further ",
            if token.op == Op::Remove { "modification" } else { "assignment" },
            "."
        ),
    );
    Ok(true)
}

/// `log_event_error_errno()` as a return value.
fn error(ctx: Ctx, event: &Event, token: &Token, r: i32, msg: Vec<u8>) -> Result<bool, i32> {
    Err(log_event(ctx, event, token, LOG_ERR, r, msg))
}

/// `log_event_line(event, line, ...)`.
fn log_line(ctx: Ctx, event: &Event, msg: Vec<u8>) {
    if event.trace {
        log_rule_file(Some(&event.dev), Some(ctx.file), ctx.line.line_number, LOG_DEBUG, 0, msg);
    }
}

/// `apply_format_full()`: None (logged) if the result is truncated.
fn apply_format_full(
    ctx: Ctx,
    event: &Event,
    token: &Token,
    format: &[u8],
    size: usize,
    replace_whitespace: bool,
    what: &str,
) -> Option<Vec<u8>> {
    let (result, truncated) = udev_event_apply_format(event, format, size, replace_whitespace);
    if truncated {
        if token.ty < tk::M_MAX {
            log_debug_(
                ctx,
                event,
                token,
                bcat!(
                    "The ",
                    what,
                    " is truncated while substituting into \"",
                    format,
                    "\", assuming the token fails."
                ),
            );
        } else {
            log_event(
                ctx,
                event,
                token,
                LOG_WARNING,
                0,
                bcat!(
                    "The ",
                    what,
                    " is truncated while substituting into \"",
                    format,
                    "\", refusing to apply the token."
                ),
            );
        }
        return None;
    }
    if event.trace && format != &result[..] {
        log_trace(ctx, event, token, bcat!("Format substitution: \"", format, "\" -> \"", &result, "\""));
    }
    Some(result)
}

fn apply_format_value(ctx: Ctx, event: &Event, token: &Token, size: usize, what: &str) -> Option<Vec<u8>> {
    apply_format_full(ctx, event, token, token.value.as_deref().unwrap_or_default(), size, false, what)
}

fn apply_format_attr(ctx: Ctx, event: &Event, token: &Token, size: usize, what: &str) -> Option<Vec<u8>> {
    apply_format_full(ctx, event, token, token.data.str(), size, false, what)
}

fn strcaseeq(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `token_match_string(event, token, str, log_result)`.
fn token_match_string(ctx: Ctx, event: &Event, token: &Token, s: Option<&[u8]>, log_result: bool) -> bool {
    let s = s.unwrap_or_default();
    let ci = token.match_type & MATCH_CASE_INSENSITIVE != 0;
    let mt = token.match_type & MATCH_TYPE_MASK;
    let matched = match mt {
        MATCH_TYPE_EMPTY => s.is_empty(),
        MATCH_TYPE_SUBSYSTEM => {
            let set: [&[u8]; 3] = [b"subsystem", b"class", b"bus"];
            if ci { set.iter().any(|x| strcaseeq(x, s)) } else { set.contains(&s) }
        }
        MATCH_TYPE_PLAIN_WITH_EMPTY | MATCH_TYPE_PLAIN => {
            (mt == MATCH_TYPE_PLAIN_WITH_EMPTY && s.is_empty())
                || token.alts.iter().any(|i| if ci { strcaseeq(i, s) } else { i[..] == *s })
        }
        MATCH_TYPE_GLOB_WITH_EMPTY | MATCH_TYPE_GLOB => {
            (mt == MATCH_TYPE_GLOB_WITH_EMPTY && s.is_empty())
                || token.alts.iter().any(|i| fnmatch(i, s, if ci { libc::FNM_CASEFOLD } else { 0 }) == 0)
        }
        _ => unreachable!("match type"),
    };
    let r = token.op == if matched { Op::Match } else { Op::Nomatch };
    if event.trace {
        let tail: &str = if log_result { if r { ": PASS" } else { ": FAIL" } } else { "." };
        match mt {
            MATCH_TYPE_EMPTY => log_trace(
                ctx,
                event,
                token,
                bcat!("String \"", s, "\" is", if matched { "" } else { " not" }, " empty", tail),
            ),
            MATCH_TYPE_SUBSYSTEM => log_trace(
                ctx,
                event,
                token,
                bcat!(
                    "String \"",
                    s,
                    "\" matches ",
                    if matched { "one" } else { "neither" },
                    " of \"subsystem\", \"class\", or \"bus\"",
                    tail
                ),
            ),
            _ => {
                let mut joined: Vec<Vec<u8>> = Vec::new();
                if mt == MATCH_TYPE_PLAIN_WITH_EMPTY || mt == MATCH_TYPE_GLOB_WITH_EMPTY {
                    joined.push(b"\"\"".to_vec());
                }
                for i in &token.alts {
                    joined.push(bcat!("\"", i, "\""));
                }
                let c = joined.len();
                assert!(c > 0);
                let verb = if matched {
                    if c > 1 { "matches one of" } else { "matches" }
                } else if c > 1 {
                    "matches neither of"
                } else {
                    "does not match"
                };
                log_trace(
                    ctx,
                    event,
                    token,
                    bcat!("String \"", s, "\" ", verb, " ", shared::string::strv_join(&joined, b", "), tail),
                );
            }
        }
    }
    r
}

/// `token_match_attr(token, dev, event)`.
fn token_match_attr(ctx: Ctx, token: &Token, dev: &Device, event: &Event) -> bool {
    let attr = token.data.str();
    match token.attr_subst_type {
        SubstType::Format | SubstType::Plain => {
            let name = if token.attr_subst_type == SubstType::Format {
                match apply_format_attr(ctx, event, token, UDEV_NAME_SIZE, "sysfs attribute name") {
                    Some(n) => Some(n),
                    None => return false,
                }
            } else {
                None
            };
            let n = name.as_deref().unwrap_or(attr);
            let value = match dev.get_sysattr_value(n) {
                Ok(v) => v.bytes().to_vec(),
                Err(r) => {
                    let differs = name.is_some();
                    log_trace_errno(
                        ctx,
                        event,
                        token,
                        r,
                        bcat!(
                            "Cannot read sysfs attribute",
                            if differs { " \"" } else { "" },
                            if differs { n } else { b"" },
                            if differs { "\"" } else { "" },
                            ": ",
                            strerror(r)
                        ),
                    );
                    return false;
                }
            };
            let value = if token.match_type & MATCH_REMOVE_TRAILING_WHITESPACE != 0 {
                let v = strscpy(&value, UDEV_NAME_SIZE);
                shared::string::delete_trailing_chars(&v, None).to_vec()
            } else {
                value
            };
            token_match_string(ctx, event, token, Some(&value), true)
        }
        SubstType::Subsys => {
            let mut vbuf = match udev_resolve_subsys_kernel(attr, UDEV_NAME_SIZE, true) {
                Ok(v) => v,
                Err(r) => {
                    log_trace_errno(ctx, event, token, r, bcat!("Cannot read sysfs attribute: ", strerror(r)));
                    return false;
                }
            };
            if token.match_type & MATCH_REMOVE_TRAILING_WHITESPACE != 0 {
                vbuf = shared::string::delete_trailing_chars(&vbuf, None).to_vec();
            }
            token_match_string(ctx, event, token, Some(&vbuf), true)
        }
        SubstType::Invalid => unreachable!("attribute substitution type"),
    }
}

/// `get_property_from_string(line)`: Ok(None) for comments and empty
/// lines.  On failure, the line as C leaves it for the log: it has cut
/// it at the '=' and trimmed the key by then (except when there is no
/// '=').
fn get_property_from_string(line: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>, (i32, Vec<u8>)> {
    let ks = line.len() - skip_leading_chars(line, None).len();
    let key = &line[ks..];
    if key.is_empty() || key[0] == b'#' {
        return Ok(None);
    }
    let Some(eq) = key.iter().position(|&b| b == b'=') else {
        return Err((-libc::EINVAL, line.to_vec()));
    };
    let k = shared::string::strstrip(&key[..eq]);
    let cut = || shared::bcat!(&line[..ks], k);
    if k.is_empty() {
        return Err((-libc::EINVAL, cut()));
    }
    let mut val = shared::string::strstrip(&key[eq + 1..]);
    if val.is_empty() {
        return Err((-libc::EINVAL, cut()));
    }
    if val[0] == b'"' || val[0] == b'\'' {
        let len = val.len();
        if len == 1 || val[len - 1] != val[0] {
            return Err((-libc::EINVAL, cut()));
        }
        val = &val[1..len - 1];
    }
    Ok(Some((k.to_vec(), val.to_vec())))
}

/// `attr_subst_subdir(attr)`: resolve the first "/*/" in the path.
fn attr_subst_subdir(attr: &[u8]) -> Result<Vec<u8>, i32> {
    let Some(t) = attr.windows(3).position(|w| w == b"/*/") else {
        return Ok(attr.to_vec());
    };
    let len = t + 1;
    let tail = &attr[t + 2..];
    if len >= UDEV_PATH_SIZE {
        return Err(-libc::ENOENT);
    }
    let dirpath = &attr[..len];
    let mut dir = shared::sys_net::opendir(dirpath)?;
    let size = UDEV_PATH_SIZE - len;
    loop {
        let Some((name, _)) = shared::conf_files::foreach_dirent_all(&mut dir)? else { break };
        if name.first() == Some(&b'.') {
            continue;
        }
        let p = bcat!(name, tail);
        if p.len() >= size {
            continue;
        }
        if shared::sys::faccessat(dir.fd(), &p, libc::F_OK, 0).is_err() {
            continue;
        }
        return Ok(bcat!(dirpath, p));
    }
    Err(-libc::ENOENT)
}

/// `udev_replace_ifname(event, token, buf)`.
fn udev_replace_ifname(ctx: Ctx, event: &Event, token: &Token, buf: &mut [u8]) {
    let count = if shared::netif_naming_scheme::naming_scheme_has(shared::netif_naming_scheme::NAMING_REPLACE_STRICTLY)
    {
        let mut count = 0;
        for c in buf.iter_mut() {
            if !shared::netlink::ifname_valid_char(*c) {
                *c = b'_';
                count += 1;
            }
        }
        count
    } else {
        udev_replace_chars(buf, Some(b"/"))
    };
    if count > 0 {
        log_trace(
            ctx,
            event,
            token,
            bcat!(
                "Replaced ",
                count.to_string(),
                " character(s) from network interface name, results to \"",
                &*buf,
                "\""
            ),
        );
    }
}

fn udev_replace_chars_and_log(
    ctx: Ctx,
    event: &Event,
    token: &Token,
    buf: &mut [u8],
    allow: Option<&[u8]>,
    what: &str,
) {
    let count = udev_replace_chars(buf, allow);
    if count > 0 {
        log_trace(
            ctx,
            event,
            token,
            bcat!("Replaced ", count.to_string(), " character(s) from ", what, ", results to \"", &*buf, "\""),
        );
    }
}

/// `device_add_property()` of an imported `key=value`, with its logging;
/// Ok(true) if it was added.
fn import_property(ctx: Ctx, event: &Event, token: &Token, dev: &Device, key: &[u8], val: &[u8]) -> Result<bool, i32> {
    match dev.add_property(key, Some(val)) {
        Err(r) if r == -libc::ENOMEM => Err(r),
        Err(r) => {
            log_event(
                ctx,
                event,
                token,
                LOG_WARNING,
                r,
                bcat!("Failed to import property \"", key, "=", val, "\", ignoring: ", strerror(r)),
            );
            Ok(false)
        }
        Ok(()) => {
            log_trace(ctx, event, token, bcat!("Imported property \"", key, "=", val, "\"."));
            Ok(true)
        }
    }
}

/// `strextendf_with_separator()`-built "a, b" of trace messages.
fn join_token_strs(tokens: &[Token]) -> Vec<u8> {
    let v: Vec<Vec<u8>> = tokens.iter().take_while(|t| t.is_for_parents()).map(|t| t.token_str.clone()).collect();
    shared::string::strv_join(&v, b", ")
}

impl Rules {
    /// `udev_rule_apply_token_to_event(token, dev, event)`: Ok(false) if
    /// the token doesn't match, Ok(true) if it does, Err on critical
    /// errors.
    fn apply_token(&self, ctx: Ctx, token: &Token, dev: &Dev, event: &mut Event) -> Result<bool, i32> {
        let t = token;
        match t.ty {
            tk::M_ACTION => {
                let a = match dev.get_action() {
                    Ok(a) => a,
                    Err(r) => {
                        return error(ctx, event, t, r, bcat!("Failed to get uevent action type: ", strerror(r)));
                    }
                };
                Ok(token_match_string(ctx, event, t, Some(device_action_to_string(a).as_bytes()), true))
            }
            tk::M_DEVPATH => Ok(token_match_string(ctx, event, t, Some(dev.get_devpath().bytes()), true)),
            tk::M_KERNEL | tk::M_PARENTS_KERNEL => match dev.get_sysname() {
                Ok(v) => Ok(token_match_string(ctx, event, t, Some(v.bytes()), true)),
                Err(r) => error(ctx, event, t, r, bcat!("Failed to get sysname: ", strerror(r))),
            },
            tk::M_DEVLINK => {
                for l in dev.devlinks() {
                    let v = l.bytes().strip_prefix(b"/dev/").unwrap_or_default();
                    if token_match_string(ctx, event, t, Some(v), false) == (t.op == Op::Match) {
                        return result(ctx, event, t, t.op == Op::Match);
                    }
                }
                result(ctx, event, t, t.op == Op::Nomatch)
            }
            tk::M_NAME => Ok(token_match_string(ctx, event, t, event.name.as_deref(), true)),
            tk::M_ENV => {
                let v =
                    device_get_property_value_with_fallback(dev, t.data.str(), event.worker_properties.as_deref()).ok();
                Ok(token_match_string(ctx, event, t, v.as_deref(), true))
            }
            tk::M_CONST => {
                let v: Option<&str> = match t.data.str() {
                    b"arch" => shared::virt::architecture_to_string(shared::virt::uname_architecture()),
                    b"virt" => shared::virt::detect_virtualization().ok(),
                    b"cvm" => Some(shared::virt::detect_confidential_virtualization()),
                    _ => unreachable!("CONST attribute"),
                };
                Ok(token_match_string(ctx, event, t, v.map(|s| s.as_bytes()), true))
            }
            tk::M_TAG | tk::M_PARENTS_TAG => {
                for tag in dev.current_tags() {
                    if token_match_string(ctx, event, t, Some(tag.bytes()), false) == (t.op == Op::Match) {
                        return result(ctx, event, t, t.op == Op::Match);
                    }
                }
                result(ctx, event, t, t.op == Op::Nomatch)
            }
            tk::M_SUBSYSTEM | tk::M_PARENTS_SUBSYSTEM => match dev.get_subsystem() {
                Ok(v) => Ok(token_match_string(ctx, event, t, Some(v.bytes()), true)),
                Err(r) if r == -libc::ENOENT => Ok(token_match_string(ctx, event, t, None, true)),
                Err(r) => error(ctx, event, t, r, bcat!("Failed to get subsystem: ", strerror(r))),
            },
            tk::M_DRIVER | tk::M_PARENTS_DRIVER => match dev.get_driver() {
                Ok(v) => Ok(token_match_string(ctx, event, t, Some(v.bytes()), true)),
                Err(r) if r == -libc::ENOENT => Ok(token_match_string(ctx, event, t, None, true)),
                Err(r) => error(ctx, event, t, r, bcat!("Failed to get driver: ", strerror(r))),
            },
            tk::M_ATTR | tk::M_PARENTS_ATTR => Ok(token_match_attr(ctx, t, dev, event)),
            tk::M_SYSCTL => {
                let Some(buf) = apply_format_attr(ctx, event, t, UDEV_PATH_SIZE, "sysctl entry name") else {
                    return Ok(false);
                };
                let value = match shared::sysctl_util::sysctl_read(&shared::sysctl_util::sysctl_normalize(&buf)) {
                    Ok(v) => Some(v),
                    Err(r) if r == -libc::ENOENT => None,
                    Err(r) => {
                        return error(ctx, event, t, r, bcat!("Failed to read sysctl \"", &buf, "\": ", strerror(r)));
                    }
                };
                let v = value.as_deref().map(shared::string::strstrip);
                Ok(token_match_string(ctx, event, t, v, true))
            }
            tk::M_TEST => self.apply_test(ctx, t, dev, event),
            tk::M_PROGRAM => {
                event.program_result = None;
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_LINE_SIZE, "command") else {
                    return Ok(false);
                };
                log_debug_(ctx, event, t, bcat!("Running command \"", &buf, "\""));
                match crate::udev::spawn::udev_event_spawn(event, true, &buf, Some(UDEV_LINE_SIZE)) {
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_WARNING,
                            r,
                            bcat!("Failed to execute \"", &buf, "\": ", strerror(r)),
                        );
                        result(ctx, event, t, t.op == Op::Nomatch)
                    }
                    Ok((r, _, _)) if r > 0 => {
                        log_debug_(ctx, event, t, bcat!("Command \"", &buf, "\" returned ", r.to_string(), " (error)"));
                        result(ctx, event, t, t.op == Op::Nomatch)
                    }
                    Ok((_, out, _)) => {
                        let mut out = shared::string::delete_trailing_chars(&out, Some(b"\n")).to_vec();
                        udev_replace_chars_and_log(
                            ctx,
                            event,
                            t,
                            &mut out,
                            Some(UDEV_ALLOWED_CHARS_INPUT),
                            "command output",
                        );
                        event.program_result = Some(out);
                        result(ctx, event, t, t.op == Op::Match)
                    }
                }
            }
            tk::M_IMPORT_FILE => {
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_PATH_SIZE, "file name to be imported") else {
                    return Ok(false);
                };
                log_debug_(ctx, event, t, bcat!("Importing properties from \"", &buf, "\""));
                let mut f = match shared::fileio::fopen_re(&buf) {
                    Ok(f) => f,
                    Err(r) if r == -libc::ENOENT => return result(ctx, event, t, t.op == Op::Nomatch),
                    Err(r) => return error(ctx, event, t, r, bcat!("Failed to open \"", &buf, "\": ", strerror(r))),
                };
                loop {
                    let line = match read_line(&mut f, shared::fileio::LONG_LINE_MAX) {
                        Err(r) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_DEBUG,
                                r,
                                bcat!("Failed to read \"", &buf, "\", ignoring: ", strerror(r)),
                            );
                            return result(ctx, event, t, t.op == Op::Nomatch);
                        }
                        Ok((0, _)) => return result(ctx, event, t, t.op == Op::Match),
                        Ok((_, l)) => l,
                    };
                    match get_property_from_string(&line) {
                        Err((r, shown)) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_DEBUG,
                                r,
                                bcat!("Failed to parse key and value from \"", &shown, "\", ignoring: ", strerror(r)),
                            );
                        }
                        Ok(None) => {}
                        Ok(Some((k, v))) => {
                            import_property(ctx, event, t, dev, &k, &v)?;
                        }
                    }
                }
            }
            tk::M_IMPORT_PROGRAM => {
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_LINE_SIZE, "command") else {
                    return Ok(false);
                };
                log_debug_(ctx, event, t, bcat!("Importing properties from results of \"", &buf, "\""));
                let (mut out, truncated) =
                    match crate::udev::spawn::udev_event_spawn(event, true, &buf, Some(UDEV_LINE_SIZE)) {
                        Err(r) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_WARNING,
                                r,
                                bcat!("Failed to execute \"", &buf, "\", ignoring: ", strerror(r)),
                            );
                            return result(ctx, event, t, t.op == Op::Nomatch);
                        }
                        Ok((r, _, _)) if r > 0 => {
                            log_debug_(
                                ctx,
                                event,
                                t,
                                bcat!("Command \"", &buf, "\" returned ", r.to_string(), " (error), ignoring"),
                            );
                            return result(ctx, event, t, t.op == Op::Nomatch);
                        }
                        Ok((_, out, tr)) => (out, tr),
                    };
                if truncated {
                    log_debug_(
                        ctx,
                        event,
                        t,
                        bcat!(
                            "Result of \"",
                            &buf,
                            "\" is too long and truncated, ignoring the last line of the result."
                        ),
                    );
                    match out.iter().rposition(|c| shared::string::NEWLINE.contains(c)) {
                        Some(p) => out.truncate(p),
                        None => out.clear(),
                    }
                }
                let lines =
                    match shared::extract::strv_split_newlines_full(&out, shared::extract::EXTRACT_RETAIN_ESCAPE) {
                        Ok(l) => l,
                        Err(r) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_WARNING,
                                r,
                                bcat!(
                                    "Failed to extract lines from result of command \"",
                                    &buf,
                                    "\", ignoring: ",
                                    strerror(r)
                                ),
                            );
                            return result(ctx, event, t, false);
                        }
                    };
                for line in &lines {
                    match get_property_from_string(line) {
                        Err((r, shown)) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_DEBUG,
                                r,
                                bcat!("Failed to parse key and value from \"", &shown, "\", ignoring: ", strerror(r)),
                            );
                        }
                        Ok(None) => {}
                        Ok(Some((k, v))) => {
                            import_property(ctx, event, t, dev, &k, &v)?;
                        }
                    }
                }
                result(ctx, event, t, t.op == Op::Match)
            }
            tk::M_IMPORT_BUILTIN => {
                let Data::Builtin(cmd) = t.data else { unreachable!("builtin token") };
                let mask = crate::udev::builtin::mask(cmd);
                if crate::udev::builtin::udev_builtin_run_once(cmd) {
                    if event.builtin_run & mask != 0 {
                        log_debug_(
                            ctx,
                            event,
                            t,
                            bcat!(
                                "Builtin command \"",
                                crate::udev::builtin::udev_builtin_name(cmd),
                                "\" has already run, skipping."
                            ),
                        );
                        let failed = event.builtin_ret & mask != 0;
                        return result(ctx, event, t, t.op == if failed { Op::Nomatch } else { Op::Match });
                    }
                    event.builtin_run |= mask;
                }
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_LINE_SIZE, "builtin command") else {
                    return Ok(false);
                };
                log_debug_(
                    ctx,
                    event,
                    t,
                    bcat!("Importing properties from results of builtin command \"", &buf, "\"."),
                );
                let r = crate::udev::builtin::udev_builtin_run(event, cmd, &buf);
                if let Err(e) = r {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_DEBUG,
                        e,
                        bcat!("Failed to run builtin \"", &buf, "\": ", strerror(e)),
                    );
                    event.builtin_ret |= mask;
                }
                result(ctx, event, t, t.op == if r.is_ok() { Op::Match } else { Op::Nomatch })
            }
            tk::M_IMPORT_DB => {
                let key = t.value_str();
                let Some(clone) = event.dev_db_clone.clone() else {
                    return result(ctx, event, t, t.op == Op::Nomatch);
                };
                let val = match clone.get_property_value(key) {
                    Ok(v) => v.bytes().to_vec(),
                    Err(r) if r == -libc::ENOENT => return result(ctx, event, t, t.op == Op::Nomatch),
                    Err(r) => {
                        return error(
                            ctx,
                            event,
                            t,
                            r,
                            bcat!("Failed to get property \"", key, "\" from database: ", strerror(r)),
                        );
                    }
                };
                import_property(ctx, event, t, dev, key, &val)?;
                result(ctx, event, t, t.op == Op::Match)
            }
            tk::M_IMPORT_CMDLINE => {
                let key = t.value_str();
                let value = match shared::proc_cmdline::proc_cmdline_get_key(key, true) {
                    Ok(v) => v,
                    Err(r) => {
                        return error(
                            ctx,
                            event,
                            t,
                            r,
                            bcat!("Failed to read \"", key, "\" option from /proc/cmdline: ", strerror(r)),
                        );
                    }
                };
                let Some(value) = value else {
                    return result(ctx, event, t, t.op == Op::Nomatch);
                };
                let val = value.unwrap_or_else(|| b"1".to_vec());
                import_property(ctx, event, t, dev, key, &val)?;
                result(ctx, event, t, t.op == Op::Match)
            }
            tk::M_IMPORT_PARENT => {
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_PATH_SIZE, "property name") else {
                    return Ok(false);
                };
                let parent = match dev.get_parent() {
                    Ok(p) => p,
                    Err(r) if errno_is_neg_device_absent(r) => return result(ctx, event, t, t.op == Op::Nomatch),
                    Err(r) => return error(ctx, event, t, r, bcat!("Failed to get parent device: ", strerror(r))),
                };
                let mut have = false;
                for (k, v) in parent.properties() {
                    if fnmatch(&buf, k.bytes(), 0) != 0 {
                        continue;
                    }
                    if import_property(ctx, event, t, dev, k.bytes(), v.bytes())? {
                        have = true;
                    }
                }
                result(ctx, event, t, t.op == if have { Op::Match } else { Op::Nomatch })
            }
            tk::M_RESULT => {
                let r = event.program_result.clone();
                Ok(token_match_string(ctx, event, t, r.as_deref(), true))
            }
            tk::A_OPTIONS_DUMP => {
                let Data::JsonFlags(flags) = t.data else { unreachable!("dump token") };
                log_event(ctx, event, t, LOG_INFO, 0, b"Dumping current state:".to_vec());
                let buf = crate::udev::dump::dump_event_to_string(event, flags);
                shared::log_device_full_errno!(dev, LOG_INFO, 0, buf);
                log_event(ctx, event, t, LOG_INFO, 0, b"DONE".to_vec());
                Ok(true)
            }
            tk::A_OPTIONS_STRING_ESCAPE_NONE => {
                event.esc = Escape::None;
                done(ctx, event, t)
            }
            tk::A_OPTIONS_STRING_ESCAPE_REPLACE => {
                event.esc = Escape::Replace;
                done(ctx, event, t)
            }
            tk::A_OPTIONS_DB_PERSIST => {
                dev.set_db_persist();
                done(ctx, event, t)
            }
            tk::A_OPTIONS_INOTIFY_WATCH => {
                if event.inotify_watch_final {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    event.inotify_watch_final = true;
                }
                event.inotify_watch = t.data == Data::Int(1);
                done(ctx, event, t)
            }
            tk::A_OPTIONS_DEVLINK_PRIORITY => {
                let Data::Int(prio) = t.data else { unreachable!("priority token") };
                dev.set_devlink_priority(prio);
                done(ctx, event, t)
            }
            tk::A_OPTIONS_LOG_LEVEL => {
                let Data::Int(mut level) = t.data else { unreachable!("log level token") };
                if level < 0 {
                    level = event.default_log_level;
                }
                if event.event_mode == EventMode::UdevWorker {
                    shared::log::log_set_max_level(level);
                } else {
                    log_debug_(
                        ctx,
                        event,
                        t,
                        bcat!(
                            "Running in test mode, skipping changing maximum log level to ",
                            log_level_name(level),
                            "."
                        ),
                    );
                }
                if level == LOG_DEBUG && !event.log_level_was_debug {
                    if event.event_mode == EventMode::UdevWorker {
                        crate::udev::util::log_device_uevent(
                            dev,
                            b"The log level is changed to 'debug' while processing device",
                        );
                    }
                    event.log_level_was_debug = true;
                }
                done(ctx, event, t)
            }
            tk::A_OWNER | tk::A_GROUP => {
                let group = t.ty == tk::A_GROUP;
                if if group { event.group_final } else { event.owner_final } {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    if group {
                        event.group_final = true;
                    } else {
                        event.owner_final = true;
                    }
                }
                let what = if group { "group name" } else { "user name" };
                let Some(name) = apply_format_value(ctx, event, t, UDEV_NAME_SIZE, what) else {
                    return Ok(true);
                };
                let r = if group {
                    shared::userdb::groupdb_gid_by_name(&name)
                } else {
                    shared::userdb::userdb_uid_by_name(&name)
                };
                let acct = if group { "group" } else { "user" };
                match r {
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_ERR,
                            r,
                            bcat!(
                                "Failed to resolve ",
                                acct,
                                " \"",
                                &name,
                                "\", ignoring: ",
                                shared::user::strerror_account(r, acct)
                            ),
                        );
                    }
                    Ok(id) => {
                        if !shared::userdb::id_is_system(id) {
                            log_event_syntax_not_system(ctx, event, t, group, &name);
                        }
                        if group {
                            event.gid = id;
                            log_debug_(ctx, event, t, bcat!("Set group: ", &name, "(", id.to_string(), ")"));
                        } else {
                            event.uid = id;
                            log_debug_(ctx, event, t, bcat!("Set owner: ", &name, "(", id.to_string(), ")"));
                        }
                    }
                }
                Ok(true)
            }
            tk::A_MODE => {
                if event.mode_final {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    event.mode_final = true;
                }
                let Some(mode_str) = apply_format_value(ctx, event, t, UDEV_NAME_SIZE, "mode") else {
                    return Ok(true);
                };
                match shared::parse::parse_mode(&mode_str) {
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_ERR,
                            r,
                            bcat!("Failed to parse mode \"", &mode_str, "\", ignoring: ", strerror(r)),
                        );
                    }
                    Ok(m) => {
                        event.mode = m;
                        log_debug_(ctx, event, t, bcat!("Set mode: ", alt_octal(m)));
                    }
                }
                Ok(true)
            }
            tk::A_OWNER_ID | tk::A_GROUP_ID | tk::A_MODE_ID => {
                let fin = match t.ty {
                    tk::A_OWNER_ID => &mut event.owner_final,
                    tk::A_GROUP_ID => &mut event.group_final,
                    _ => &mut event.mode_final,
                };
                if *fin {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    *fin = true;
                }
                match (t.ty, &t.data) {
                    (tk::A_OWNER_ID, Data::Id(u)) => {
                        event.uid = *u;
                        log_debug_(ctx, event, t, bcat!("Set owner ID: ", u.to_string()));
                    }
                    (tk::A_GROUP_ID, Data::Id(g)) => {
                        event.gid = *g;
                        log_debug_(ctx, event, t, bcat!("Set group ID: ", g.to_string()));
                    }
                    (_, Data::Mode(m)) => {
                        event.mode = *m;
                        log_debug_(ctx, event, t, bcat!("Set mode: ", alt_octal(*m)));
                    }
                    _ => unreachable!("ID token data"),
                }
                Ok(true)
            }
            tk::A_SECLABEL => {
                let name = t.data.str().to_vec();
                let Some(label_str) = apply_format_value(ctx, event, t, UDEV_LINE_SIZE, "security label") else {
                    return Ok(true);
                };
                let label = if !label_str.is_empty() { label_str } else { t.value_str().to_vec() };
                if t.op == Op::Assign {
                    event.seclabel_list.clear();
                }
                // The map is keyed by pointer: a name given twice is kept twice.
                log_debug_(ctx, event, t, bcat!("Set security label: ", &name, "=", &label));
                event.seclabel_list.push((name, label));
                Ok(true)
            }
            tk::A_ENV => self.apply_env(ctx, t, dev, event),
            tk::A_TAG => {
                let Some(buf) = apply_format_value(ctx, event, t, UDEV_PATH_SIZE, "tag name") else {
                    return Ok(true);
                };
                if t.op == Op::Remove {
                    dev.remove_tag(&buf);
                    log_trace(ctx, event, t, bcat!("Removed tag \"", &buf, "\"."));
                    return Ok(true);
                }
                if t.op == Op::Assign
                    && let Err(r) = dev.cleanup_tags(event.dev_db_clone.as_deref())
                {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_WARNING,
                        r,
                        bcat!("Failed to clear previously assigned tags, ignoring: ", strerror(r)),
                    );
                }
                match dev.add_tag(&buf, true) {
                    Err(r) if r == -libc::ENOMEM => return Err(r),
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_WARNING,
                            r,
                            bcat!(
                                "Failed to ",
                                if t.op == Op::Assign { "set" } else { "add" },
                                " tag \"",
                                &buf,
                                "\", ignoring: ",
                                strerror(r)
                            ),
                        );
                    }
                    Ok(()) => log_trace(
                        ctx,
                        event,
                        t,
                        bcat!(if t.op == Op::Assign { "Set" } else { "Added" }, " tag \"", &buf, "\"."),
                    ),
                }
                Ok(true)
            }
            tk::A_NAME => {
                if event.name_final {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    event.name_final = true;
                }
                if dev.get_ifindex().is_err() {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_WARNING,
                        0,
                        b"Only network interfaces can be renamed, ignoring.".to_vec(),
                    );
                    return Ok(true);
                }
                let Some(mut buf) = apply_format_value(ctx, event, t, UDEV_PATH_SIZE, "network interface name") else {
                    return Ok(true);
                };
                if matches!(event.esc, Escape::Unset | Escape::Replace) {
                    udev_replace_ifname(ctx, event, t, &mut buf);
                }
                log_debug_(ctx, event, t, bcat!("Set network interface name: ", &buf));
                event.name = Some(buf);
                Ok(true)
            }
            tk::A_DEVLINK => self.apply_devlink(ctx, t, dev, event),
            tk::A_ATTR => self.apply_attr(ctx, t, dev, event),
            tk::A_SYSCTL => {
                let Some(buf) = apply_format_attr(ctx, event, t, UDEV_PATH_SIZE, "sysctl entry name") else {
                    return Ok(true);
                };
                let Some(value) = apply_format_value(ctx, event, t, UDEV_NAME_SIZE, "sysctl value") else {
                    return Ok(true);
                };
                let buf = shared::sysctl_util::sysctl_normalize(&buf);
                if event.destructive() {
                    log_debug_(ctx, event, t, bcat!("Writing \"", &value, "\" to sysctl entry \"", &buf, "\"."));
                    match shared::sysctl_util::sysctl_write(&buf, &value) {
                        Err(r) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_ERR,
                                r,
                                bcat!(
                                    "Failed to write \"",
                                    &value,
                                    "\" to sysctl entry \"",
                                    &buf,
                                    "\", ignoring: ",
                                    strerror(r)
                                ),
                            );
                        }
                        Ok(()) => {
                            crate::udev::dump::event_cache_written_sysctl(event, &buf, &value);
                            let _ = done(ctx, event, t);
                        }
                    }
                } else {
                    log_debug_(
                        ctx,
                        event,
                        t,
                        bcat!(
                            "Running in test mode, skipping writing \"",
                            &value,
                            "\" to sysctl entry \"",
                            &buf,
                            "\"."
                        ),
                    );
                    let path = shared::path::path_join(&[b"/proc/sys/", &buf]);
                    match shared::stat_util::verify_regular_at(shared::fd::AT_FDCWD, &path, true) {
                        Err(r) if !shared::errno::is_neg_privilege(r) => {
                            log_event(
                                ctx,
                                event,
                                t,
                                LOG_ERR,
                                r,
                                bcat!("Failed to verify sysctl entry \"", &buf, "\" is a regular file: ", strerror(r)),
                            );
                        }
                        _ => crate::udev::dump::event_cache_written_sysctl(event, &buf, &value),
                    }
                }
                Ok(true)
            }
            tk::A_RUN_BUILTIN | tk::A_RUN_PROGRAM => {
                if event.run_final {
                    return final_set(ctx, event, t);
                }
                if t.op == Op::AssignFinal {
                    event.run_final = true;
                }
                if matches!(t.op, Op::Assign | Op::AssignFinal) {
                    event.run_list.clear();
                }
                let Some(cmd) = apply_format_value(ctx, event, t, UDEV_LINE_SIZE, "command") else {
                    return Ok(true);
                };
                let data = match t.data {
                    Data::Builtin(b) => Some(b),
                    _ => None,
                };
                // Keyed by pointer too: the same command queued twice runs twice.
                event.run_list.push((cmd.clone(), data));
                log_debug_(ctx, event, t, bcat!("Set command: ", &cmd));
                Ok(true)
            }
            tk::A_OPTIONS_STATIC_NODE => Ok(true),
            _ => unreachable!("token type {}", t.ty),
        }
    }

    /// `TK_M_TEST`.
    fn apply_test(&self, ctx: Ctx, t: &Token, dev: &Dev, event: &mut Event) -> Result<bool, i32> {
        let Data::Mode(mode) = t.data else { unreachable!("test token") };
        let Some(mut buf) = apply_format_value(ctx, event, t, UDEV_PATH_SIZE, "file name") else {
            return Ok(false);
        };
        if !shared::path::path_is_absolute(&buf) {
            match udev_resolve_subsys_kernel(&buf, UDEV_PATH_SIZE, false) {
                Ok(v) => buf = v,
                Err(_) => {
                    let val = dev.get_syspath();
                    let joined = bcat!(val.bytes(), "/", &buf);
                    if joined.len() >= UDEV_PATH_SIZE {
                        return result(ctx, event, t, false);
                    }
                    buf = joined;
                }
            }
        }
        let buf = match attr_subst_subdir(&buf) {
            Ok(b) => b,
            Err(r) if r == -libc::ENOENT => return result(ctx, event, t, t.op == Op::Nomatch),
            Err(r) => {
                return error(
                    ctx,
                    event,
                    t,
                    r,
                    bcat!("Failed to test for the existence of \"", &buf, "\": ", strerror(r)),
                );
            }
        };
        let st = match shared::sys::stat(&buf) {
            Ok(st) => st,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_WARNING,
                        r,
                        bcat!("Failed to stat \"", &buf, "\", ignoring: ", strerror(r)),
                    );
                }
                return result(ctx, event, t, t.op == Op::Nomatch);
            }
        };
        if mode == MODE_INVALID {
            return result(ctx, event, t, t.op == Op::Match);
        }
        let matched = st.st_mode & mode > 0;
        result(ctx, event, t, t.op == if matched { Op::Match } else { Op::Nomatch })
    }

    /// `TK_A_ENV`.
    fn apply_env(&self, ctx: Ctx, t: &Token, dev: &Dev, event: &mut Event) -> Result<bool, i32> {
        let name = t.data.str();
        let value = t.value_str();
        if value.is_empty() {
            if t.op == Op::Add {
                return done(ctx, event, t);
            }
            if let Err(r) = dev.add_property(name, None) {
                return error(ctx, event, t, r, bcat!("Failed to remove property \"", name, "\": ", strerror(r)));
            }
            log_trace(ctx, event, t, bcat!("Removed property \"", name, "\"."));
            return Ok(true);
        }
        let mut prefix: Vec<u8> = Vec::new();
        let mut l = UDEV_NAME_SIZE;
        if t.op == Op::Add
            && let Ok(val) = device_get_property_value_with_fallback(dev, name, event.worker_properties.as_deref())
        {
            // strpcpyl_full(&p, l, &truncated, val, " ", NULL)
            let joined = bcat!(&val, " ");
            if joined.len() >= l {
                log_event(
                    ctx,
                    event,
                    t,
                    LOG_WARNING,
                    0,
                    bcat!(
                        "The buffer for the property is full, refusing to append new property \"",
                        name,
                        "=",
                        value,
                        "\"."
                    ),
                );
                return Ok(true);
            }
            l -= joined.len();
            prefix = joined;
        }
        let Some(mut p) = apply_format_value(ctx, event, t, l, "property value") else {
            return Ok(true);
        };
        if event.esc == Escape::Replace {
            udev_replace_chars_and_log(ctx, event, t, &mut p, None, "property value");
        }
        let value_new = bcat!(prefix, p);
        match dev.add_property(name, Some(&value_new)) {
            Err(r) if r == -libc::ENOMEM => return Err(r),
            Err(r) => {
                log_event(
                    ctx,
                    event,
                    t,
                    LOG_WARNING,
                    r,
                    bcat!("Failed to set property \"", name, "=", &value_new, "\", ignoring: ", strerror(r)),
                );
            }
            Ok(()) => log_trace(ctx, event, t, bcat!("Set property \"", name, "=", &value_new, "\".")),
        }
        Ok(true)
    }

    /// `TK_A_DEVLINK`.
    fn apply_devlink(&self, ctx: Ctx, t: &Token, dev: &Dev, event: &mut Event) -> Result<bool, i32> {
        if event.devlink_final {
            return final_set(ctx, event, t);
        }
        if dev.get_devnum().is_err() {
            log_debug_(
                ctx,
                event,
                t,
                b"Device does not have device node, ignoring to manage device node symlink.".to_vec(),
            );
            return Ok(true);
        }
        if t.op == Op::AssignFinal {
            event.devlink_final = true;
        }
        if matches!(t.op, Op::Assign | Op::AssignFinal) {
            dev.cleanup_devlinks();
        }
        let Some(mut buf) = apply_format_full(
            ctx,
            event,
            t,
            t.value_str(),
            UDEV_PATH_SIZE,
            event.esc != Escape::None,
            "symbolic link path",
        ) else {
            return Ok(true);
        };
        match event.esc {
            Escape::Unset => udev_replace_chars_and_log(ctx, event, t, &mut buf, Some(b"/ "), "device node symlink"),
            Escape::Replace => udev_replace_chars_and_log(ctx, event, t, &mut buf, Some(b"/"), "device node symlink"),
            Escape::None => {}
        }
        let mut p: Option<&[u8]> = Some(&buf);
        loop {
            let path = match shared::extract::extract_first_word(&mut p, None, shared::extract::EXTRACT_RETAIN_ESCAPE) {
                Err(r) => {
                    shared::log_warning_errno!(
                        r,
                        "Failed to extract first path in device node symlinks, ignoring: ",
                        strerror(r)
                    );
                    return Ok(true);
                }
                Ok(None) => return Ok(true),
                Ok(Some(w)) => w,
            };
            if t.op == Op::Remove {
                match dev.remove_devlink(&path) {
                    Err(r) if r == -libc::ENOMEM => return Err(r),
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_WARNING,
                            r,
                            bcat!("Failed to remove device node symlink \"", &path, "\", ignoring: ", strerror(r)),
                        );
                    }
                    Ok(true) => log_debug_(ctx, event, t, bcat!("Removed device node symlink \"", &path, "\"")),
                    Ok(false) => {}
                }
            } else {
                match dev.add_devlink(&path) {
                    Err(r) if r == -libc::ENOMEM => return Err(r),
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_WARNING,
                            r,
                            bcat!("Failed to add device node symlink \"", &path, "\", ignoring: ", strerror(r)),
                        );
                    }
                    Ok(true) => log_debug_(ctx, event, t, bcat!("Added device node symlink \"", &path, "\".")),
                    Ok(false) => {}
                }
            }
        }
    }

    /// `TK_A_ATTR`.
    fn apply_attr(&self, ctx: Ctx, t: &Token, dev: &Dev, event: &mut Event) -> Result<bool, i32> {
        let key = t.data.str();
        let buf = match udev_resolve_subsys_kernel(key, UDEV_PATH_SIZE, false) {
            Err(r) if r == -libc::ENOMEM => return Err(r),
            Err(r) if errno_is_neg_device_absent(r) => {
                log_event(
                    ctx,
                    event,
                    t,
                    LOG_WARNING,
                    r,
                    bcat!("Failed to resolve sysfs attribute \"", key, "\", ignoring: ", strerror(r)),
                );
                return Ok(true);
            }
            Ok(b) => b,
            Err(_) => {
                let syspath = dev.get_syspath();
                let b = bcat!(syspath.bytes(), "/", key);
                if b.len() >= UDEV_PATH_SIZE {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_WARNING,
                        0,
                        bcat!(
                            "The path to the attribute \"",
                            syspath.bytes(),
                            "/",
                            key,
                            "\" is too long, refusing to set the attribute."
                        ),
                    );
                    return Ok(true);
                }
                match attr_subst_subdir(&b) {
                    Ok(x) => x,
                    Err(r) => {
                        log_event(
                            ctx,
                            event,
                            t,
                            LOG_ERR,
                            r,
                            bcat!("Could not find file matches \"", &b, "\", ignoring: ", strerror(r)),
                        );
                        return Ok(true);
                    }
                }
            }
        };
        let (resolved, fd) = match dev.chase(&buf, 0, true) {
            Ok(x) => x,
            Err(r) => {
                log_event(
                    ctx,
                    event,
                    t,
                    LOG_ERR,
                    r,
                    bcat!("Could not chase sysfs attribute \"", &buf, "\", ignoring: ", strerror(r)),
                );
                return Ok(true);
            }
        };
        let Some(value) = apply_format_value(ctx, event, t, UDEV_NAME_SIZE, "attribute value") else {
            return Ok(true);
        };
        if event.destructive() {
            log_debug_(ctx, event, t, bcat!("Writing \"", &value, "\" to sysfs attribute \"", &resolved, "\"."));
            match dev.set_sysattr_value(&resolved, Some(&value)) {
                Err(r) => {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_ERR,
                        r,
                        bcat!(
                            "Failed to write \"",
                            &value,
                            "\" to sysfs attribute \"",
                            &resolved,
                            "\", ignoring: ",
                            strerror(r)
                        ),
                    );
                }
                Ok(()) => {
                    crate::udev::dump::event_cache_written_sysattr(event, &resolved, &value);
                    let _ = done(ctx, event, t);
                }
            }
        } else {
            log_debug_(
                ctx,
                event,
                t,
                bcat!(
                    "Running in test mode, skipping writing \"",
                    &value,
                    "\" to sysfs attribute \"",
                    &resolved,
                    "\"."
                ),
            );
            let fd = fd.expect("requested");
            match shared::stat_util::fd_verify_regular(fd.raw()) {
                Err(r) if !shared::errno::is_neg_privilege(r) => {
                    log_event(
                        ctx,
                        event,
                        t,
                        LOG_ERR,
                        r,
                        bcat!("Failed to verify sysfs attribute \"", &resolved, "\" is a regular file: ", strerror(r)),
                    );
                }
                _ => {
                    crate::udev::dump::event_cache_written_sysattr(event, &resolved, &value);
                    dev.cache_sysattr_value(&resolved, &value, 0);
                }
            }
        }
        Ok(true)
    }

    /// `udev_rule_apply_parent_token_to_event(head_token, event)`: the
    /// parent tokens from `first` on.
    fn apply_parent_tokens(&self, ctx: Ctx, tokens: &[Token], event: &mut Event) -> Result<bool, i32> {
        if event.trace {
            log_line(
                ctx,
                event,
                bcat!("Checking conditions for parent devices (including self): ", join_token_strs(tokens)),
            );
        }
        event.dev_parent = Some(event.dev.clone());
        loop {
            let parent = event.dev_parent.clone().expect("set");
            let mut r = true;
            for token in tokens {
                if !token.is_for_parents() {
                    break;
                }
                r = self.apply_token(ctx, token, &parent, event)?;
                if !r {
                    break;
                }
            }
            if r {
                if event.trace {
                    log_line(
                        ctx,
                        event,
                        bcat!("Parent device \"", parent.get_syspath().bytes(), "\" passed all parent conditions."),
                    );
                }
                return Ok(true);
            }
            match parent.get_parent() {
                Ok(p) => event.dev_parent = Some(p),
                Err(_) => {
                    event.dev_parent = None;
                    log_line(ctx, event, b"No parent device passed parent conditions.".to_vec());
                    return Ok(false);
                }
            }
        }
    }

    /// `udev_rule_apply_line_to_event(line, event, &next_line)`: the GOTO
    /// target, if the line has one and applied.
    fn apply_line(&self, file: &RuleFile, line: &Line, event: &mut Event) -> Result<Option<usize>, i32> {
        let mut mask = LINE_HAS_GOTO | LINE_UPDATE_SOMETHING;
        let action = event.dev.get_action()?;
        if action != Action::Remove {
            if event.dev.get_devnum().is_ok() {
                mask |= LINE_HAS_DEVLINK;
            }
            if event.dev.get_ifindex().is_ok() {
                mask |= LINE_HAS_NAME;
            }
        }
        if line.ty & mask == 0 {
            return Ok(None);
        }
        event.esc = Escape::Unset;
        let ctx = Ctx { file, line };
        let dev = event.dev.clone();
        let mut parents_done = false;
        for (i, token) in line.tokens.iter().enumerate() {
            if token.is_for_parents() {
                if parents_done {
                    continue;
                }
                if !self.apply_parent_tokens(ctx, &line.tokens[i..], event)? {
                    return Ok(None);
                }
                parents_done = true;
                continue;
            }
            if !self.apply_token(ctx, token, &dev, event)? {
                return Ok(None);
            }
        }
        if let Some(g) = line.goto_line {
            log_line(ctx, event, bcat!("GOTO=", line.goto_label.as_deref().unwrap_or(b"n/a")));
            return Ok(Some(g));
        }
        Ok(None)
    }

    /// `udev_rules_apply_to_event(rules, event)`.
    pub fn apply_to_event(&self, event: &mut Event) -> Result<(), i32> {
        for file in &self.files {
            let mut i = 0;
            while i < file.lines.len() {
                i = match self.apply_line(file, &file.lines[i], event)? {
                    Some(g) => g,
                    None => i + 1,
                };
            }
        }
        Ok(())
    }
}

/// `log_level_to_string_alloc(level)` (`strna()` on failure).
fn log_level_name(level: i32) -> Vec<u8> {
    match shared::log::log_level_to_string(level) {
        Some(s) => s.as_bytes().to_vec(),
        None if level >= 0 => level.to_string().into_bytes(),
        None => b"n/a".to_vec(),
    }
}

/// `%#o`.
fn alt_octal(m: u32) -> String {
    if m == 0 { "0".to_string() } else { format!("0{m:o}") }
}

/// `log_udev_event_syntax(event, token, LOG_WARNING, ...)` for an owner
/// that is not a system account.
fn log_event_syntax_not_system(ctx: Ctx, event: &Event, token: &Token, group: bool, name: &[u8]) {
    let dev = if token.is_for_parents() { event.dev_parent.as_deref() } else { Some(&*event.dev) };
    let sysname = dev.and_then(|d| d.get_sysname().ok()).map(|s| s.bytes().to_vec()).unwrap_or_default();
    let (w, ws) = if group { ("Group", "group") } else { ("User", "user") };
    shared::log::log_struct_full(
        LOG_WARNING,
        0,
        shared::log::Loc { file: file!(), line: line!(), func: "" },
        &[],
        &bcat!(
            ctx.file.filename,
            ":",
            ctx.line.line_number.to_string(),
            " ",
            token.token_str,
            ":",
            w,
            " ",
            name,
            " configured to own a device node is not a system ",
            ws,
            ". Support for device node ownership by non-system accounts is deprecated and will be removed in the future."
        ),
        &[MESSAGE_SYSTEM_ACCOUNT_REQUIRED.as_bytes().to_vec(), bcat!("DEVICE=", sysname)],
    );
}

impl Rules {
    /// `udev_rules_apply_static_dev_perms(rules)`.
    pub fn apply_static_dev_perms(&self) -> Result<(), i32> {
        for file in &self.files {
            for line in &file.lines {
                if line.ty & LINE_HAS_STATIC_NODE == 0 {
                    continue;
                }
                let (mut uid, mut gid, mut mode) =
                    (crate::udev::def::UID_INVALID, crate::udev::def::GID_INVALID, crate::udev::def::MODE_INVALID);
                let mut tags: Vec<Vec<u8>> = Vec::new();
                for t in &line.tokens {
                    match (t.ty, &t.data) {
                        (tk::A_OWNER_ID, Data::Id(u)) => uid = *u,
                        (tk::A_GROUP_ID, Data::Id(g)) => gid = *g,
                        (tk::A_MODE_ID, Data::Mode(m)) => mode = *m,
                        (tk::A_TAG, _) => tags.push(t.value_str().to_vec()),
                        (tk::A_OPTIONS_STATIC_NODE, _) => {
                            super::super::node::static_node_apply_permissions(t.value_str(), mode, uid, gid, &tags)?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}
