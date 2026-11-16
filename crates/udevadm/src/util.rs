// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-util.c`, and `invoked_as()` (`argv-util.c`).

use shared::conf_files::{
    CONF_FILES_FILTER_MASKED, CONF_FILES_REGULAR, CONF_FILES_WARN, ConfFile, conf_file_new, conf_files_list_strv_full,
    conf_paths,
};
use shared::errno::{strerror, synthetic};
use shared::path::{filename_is_valid, is_path, last_path_component, path_join, path_startswith, skip_leading_slash};
use shared::sd_device::{Action, Dev, Device, device_action_from_string};
use shared::{log_debug_errno, log_error_errno, log_warning_errno, printo};

use crate::udev::def::ResolveNameTiming;

/// `invoked_as(argv, token)`.
pub fn invoked_as(argv: &[Vec<u8>], token: &[u8]) -> bool {
    let env = shared::env::secure_getenv("SYSTEMD_INVOKED_AS").filter(|e| !e.is_empty());
    let progname = match env {
        Some(e) => e,
        None => match argv.first() {
            Some(a) => a.clone(),
            None => return false,
        },
    };
    if progname.is_empty() || token.is_empty() {
        return false;
    }
    last_path_component(&progname).windows(token.len()).any(|w| w == token)
}

const VALID_CHARS_WITH_AT: &[u8] = b"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_.\\";
const UNIT_TYPES: &[&[u8]] = &[
    b"service",
    b"socket",
    b"target",
    b"device",
    b"mount",
    b"automount",
    b"swap",
    b"timer",
    b"path",
    b"slice",
    b"scope",
];

/// `unit_name_is_valid(n, UNIT_NAME_PLAIN)` (`plain`) or `UNIT_NAME_ANY`.
fn unit_name_is_valid(n: &[u8], plain_only: bool) -> bool {
    if n.is_empty() || n.len() >= 256 {
        return false;
    }
    let Some(e) = n.iter().rposition(|&b| b == b'.') else { return false };
    if e == 0 || !UNIT_TYPES.contains(&&n[e + 1..]) {
        return false;
    }
    let mut at = None;
    for (i, &c) in n[..e].iter().enumerate() {
        if c == b'@' && at.is_none() {
            at = Some(i);
        }
        if !VALID_CHARS_WITH_AT.contains(&c) {
            return false;
        }
    }
    match at {
        Some(0) => false,
        None => true,
        // An instance (e > a + 1) or a template (e == a + 1).
        Some(a) => !plain_only && e > a,
    }
}

/// `unit_name_is_hashed(name)`.
fn unit_name_is_hashed(name: &[u8]) -> bool {
    if !unit_name_is_valid(name, true) {
        return false;
    }
    let s = name.iter().rposition(|&b| b == b'.').expect("valid");
    if s < 17 {
        return false;
    }
    let h = s - 16;
    name[h - 1] == b'_' && name[h..s].iter().all(|c| b"0123456789abcdef".contains(c))
}

/// `unit_name_to_path(name)`.
fn unit_name_to_path(name: &[u8]) -> Result<Vec<u8>, i32> {
    if !unit_name_is_valid(name, false) {
        return Err(-libc::EINVAL);
    }
    let p = name.iter().position(|&b| b == b'@').or_else(|| name.iter().rposition(|&b| b == b'.')).expect("valid");
    let prefix = &name[..p];
    if unit_name_is_hashed(name) {
        return Err(-libc::ENAMETOOLONG);
    }
    // unit_name_path_unescape()
    if prefix.is_empty() {
        return Err(-libc::EINVAL);
    }
    if prefix == b"-" {
        return Ok(b"/".to_vec());
    }
    let mut w = Vec::new();
    let mut i = 0;
    while i < prefix.len() {
        match prefix[i] {
            b'-' => w.push(b'/'),
            b'\\' => {
                if prefix.get(i + 1) != Some(&b'x') {
                    return Err(-libc::EINVAL);
                }
                let a = prefix.get(i + 2).and_then(|&c| shared::extract::unhexchar(c)).ok_or(-libc::EINVAL)?;
                let b = prefix.get(i + 3).and_then(|&c| shared::extract::unhexchar(c)).ok_or(-libc::EINVAL)?;
                w.push(((a << 4) | b) as u8);
                i += 3;
            }
            c => w.push(c),
        }
        i += 1;
    }
    if w.starts_with(b"/") || w.ends_with(b"/") {
        return Err(-libc::EINVAL);
    }
    let s = shared::bcat!("/", w);
    if !shared::path::path_is_normalized(&s) {
        return Err(-libc::EINVAL);
    }
    Ok(s)
}

/// `find_device_from_unit()`.  There is no systemd to ask for the
/// unit's `SysFSPath=`: connecting to `/run/systemd/private` fails, and
/// the unit name is used as the path, as C does then.
fn find_device_from_unit(unit_name: &[u8]) -> Result<Dev, i32> {
    if !unit_name_is_valid(unit_name, true) {
        return Err(-libc::EINVAL);
    }
    if !unit_name.ends_with(b".device") {
        return Err(-libc::EINVAL);
    }
    // bus_connect_system_systemd(): sd-bus logs its state changes.
    let arrow = shared::locale::glyph(shared::locale::Glyph::ArrowRight);
    shared::log_debug!("Bus n/a: changing state UNSET ", arrow, " OPENING");
    shared::log_debug!("sd-bus: starting bus by connecting to /run/systemd/private...");
    let r = shared::sys_net::unix_connect_probe(b"/run/systemd/private");
    shared::log_debug!("Bus n/a: changing state OPENING ", arrow, " CLOSED");
    let r = match r {
        Err(e) => e,
        // A systemd that answers isn't supported: ask it nothing, and fall
        // back the same way.
        Ok(()) => -libc::EOPNOTSUPP,
    };
    log_debug_errno!(r, "Failed to open connection to systemd, using unit name as syspath: ", strerror(r));
    let path = match unit_name_to_path(unit_name) {
        Ok(p) => p,
        Err(e) => {
            return Err(log_debug_errno!(e, "Failed to convert \"", unit_name, "\" to a device path: ", strerror(e)));
        }
    };
    Device::new_from_path(&path)
}

/// `find_device(id, prefix)`.
pub fn find_device(id: &[u8], prefix: Option<&[u8]>) -> Result<Dev, i32> {
    if let Ok(d) = Device::new_from_device_id(id) {
        return Ok(d);
    }
    if let Ok(d) = Device::new_from_path(id) {
        return Ok(d);
    }
    if let Some(p) = prefix
        && path_startswith(id, p).is_none()
    {
        let path = path_join(&[p, id]);
        if let Ok(d) = Device::new_from_path(&path) {
            return Ok(d);
        }
    }
    if is_path(id) {
        return Err(-libc::ENODEV);
    }
    find_device_from_unit(id)
}

/// `find_device_with_action(id, action)`.
pub fn find_device_with_action(id: &[u8], action: Action) -> Result<Dev, i32> {
    let dev = find_device(id, Some(b"/sys"))?;
    dev.read_uevent_file()?;
    dev.set_action(action)?;
    Ok(dev)
}

/// `DUMP_STRING_TABLE()`.
fn dump_string_table(names: &[&str]) {
    for n in names {
        printo!(n, "\n");
    }
}

/// `parse_device_action(str)`: `Ok(None)` after "help".
pub fn parse_device_action(s: &[u8]) -> Result<Option<Action>, i32> {
    if s == b"help" {
        dump_string_table(shared::sd_device::DEVICE_ACTION_NAMES);
        return Ok(None);
    }
    match device_action_from_string(s) {
        Ok(a) => Ok(Some(a)),
        Err(r) => Err(log_error_errno!(r, "Invalid action '", s, "'.")),
    }
}

/// `parse_resolve_name_timing(str)`: `Ok(None)` after "help".
pub fn parse_resolve_name_timing(s: &[u8]) -> Result<Option<ResolveNameTiming>, i32> {
    if s == b"help" {
        dump_string_table(&["never", "late", "early"]);
        return Ok(None);
    }
    match ResolveNameTiming::from_string(s) {
        Some(v) => Ok(Some(v)),
        None => Err(log_error_errno!(synthetic(libc::EINVAL), "--resolve-names= must be 'early', 'late', or 'never'.")),
    }
}

/// `parse_key_value_argument(str, require_value)`.
pub fn parse_key_value_argument(s: &[u8], require_value: bool) -> Result<(Vec<u8>, Option<Vec<u8>>), i32> {
    let mut p = Some(s);
    let words = match shared::extract::extract_many_words(
        &mut p,
        Some(b"="),
        shared::extract::EXTRACT_DONT_COALESCE_SEPARATORS,
        2,
    ) {
        Ok(w) => w,
        Err(r) => return Err(log_error_errno!(r, "Failed to parse key/value pair ", s, ": ", strerror(r))),
    };
    if require_value && words.len() < 2 {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Missing '=' in key/value pair ", s, "."));
    }
    let Some(k) = words.first().cloned() else {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "(null) is not a valid key name"));
    };
    if !filename_is_valid(&k) {
        return Err(log_error_errno!(synthetic(libc::EINVAL), k, " is not a valid key name"));
    }
    Ok((k, words.get(1).cloned()))
}

fn empty_to_root(root: Option<&[u8]>) -> &[u8] {
    match root {
        Some(r) if !r.is_empty() => r,
        _ => b"/",
    }
}

/// `search_rules_file_in_conf_dirs()`: Ok(true) if found (or masked).
fn search_rules_file_in_conf_dirs(s: &[u8], root: Option<&[u8]>, files: &mut Vec<ConfFile>) -> Result<bool, i32> {
    if s.is_empty() || is_path(s) {
        return Ok(false);
    }
    let s: Vec<u8> = if s.ends_with(b".rules") { s.to_vec() } else { shared::bcat!(s, ".rules") };
    if !filename_is_valid(&s) {
        return Ok(false);
    }
    for p in conf_paths("udev/rules.d") {
        let path = path_join(&[&p, &s]);
        match conf_file_new(&path, root, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED) {
            Err(r) if r == -libc::ERFKILL => {
                log_warning_errno!(
                    r,
                    "File '",
                    empty_to_root(root),
                    skip_leading_slash(&path),
                    "' is a mask, ignoring."
                );
                return Ok(true);
            }
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => {
                return Err(log_error_errno!(
                    r,
                    "Failed to chase '",
                    empty_to_root(root),
                    skip_leading_slash(&path),
                    "': ",
                    strerror(r)
                ));
            }
            Ok(c) => {
                files.push(c);
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// `search_rules_file()`.
fn search_rules_file(s: &[u8], root: Option<&[u8]>, files: &mut Vec<ConfFile>) -> Result<(), i32> {
    if search_rules_file_in_conf_dirs(s, root, files)? {
        return Ok(());
    }
    match conf_file_new(s, root, CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED) {
        Err(r) if r == -libc::ERFKILL => {
            log_warning_errno!(r, "File '", empty_to_root(root), skip_leading_slash(s), "' is a mask, ignoring.");
            return Ok(());
        }
        Ok(c) => {
            files.push(c);
            return Ok(());
        }
        Err(r) if r != -libc::EISDIR => {
            return Err(log_error_errno!(
                r,
                "Failed to chase '",
                empty_to_root(root),
                skip_leading_slash(s),
                "': ",
                strerror(r)
            ));
        }
        Err(_) => {}
    }
    match conf_files_list_strv_full(Some(b".rules"), root, CONF_FILES_REGULAR | CONF_FILES_WARN, &[s.to_vec()]) {
        Ok(f) => {
            files.extend(f);
            Ok(())
        }
        Err(r) => Err(log_error_errno!(
            r,
            "Failed to enumerate rules files in '",
            empty_to_root(root),
            skip_leading_slash(s),
            "': ",
            strerror(r)
        )),
    }
}

/// `search_rules_files(a, root)`.
pub fn search_rules_files(a: &[Vec<u8>], root: Option<&[u8]>) -> Result<Vec<ConfFile>, i32> {
    let mut files = Vec::new();
    if a.is_empty() {
        files = match conf_files_list_strv_full(
            Some(b".rules"),
            root,
            CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
            &conf_paths("udev/rules.d"),
        ) {
            Ok(f) => f,
            Err(r) => return Err(log_error_errno!(r, "Failed to enumerate rules files: ", strerror(r))),
        };
        if let Some(r) = root
            && files.is_empty()
        {
            return Err(log_error_errno!(synthetic(libc::ENOENT), "No rules files found in '", r, "'."));
        }
    } else {
        for s in a {
            search_rules_file(s, root, &mut files)?;
        }
    }
    Ok(files)
}

/// `parse_path_argument(path, suppress_root)`.
pub fn parse_path_argument(path: &[u8], suppress_root: bool) -> Result<Option<Vec<u8>>, i32> {
    if path.is_empty() {
        return Ok(None);
    }
    let p = match shared::path::path_make_absolute_cwd(path) {
        Ok(p) => shared::path::path_simplify(&p),
        Err(r) => {
            return Err(log_error_errno!(r, "Failed to parse path \"", path, "\" and make it absolute: ", strerror(r)));
        }
    };
    if suppress_root && shared::path::empty_or_root(Some(&p)) {
        return Ok(None);
    }
    Ok(Some(p))
}
