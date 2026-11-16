// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-info.c`.

use std::sync::atomic::Ordering;

use shared::device_enumerator::{Enumerator, MatchInitialized};
use shared::errno::{is_neg_privilege as errno_is_privilege, ret_gather, strerror, synthetic};
use shared::json::{Json, format_enabled, set_field, string_checked};
use shared::locale::{Glyph, glyph};
use shared::options::{OPTION_HELP_ENTRY_VERBATIM, OPTION_OPTIONAL_ARG, Opt, OptionParser, common};
use shared::path::{path_join, path_startswith};
use shared::sd_device::{Dev, Device};
use shared::terminal::ansi;
use shared::{bcat, log_error_errno, log_info, log_warning, printo};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const QUERY: i32 = 0x102;
const PROPERTY: i32 = 0x103;
const VALUE: i32 = 0x104;
const PATH: i32 = 0x105;
const NAME: i32 = 0x106;
const ROOT: i32 = 0x107;
const ATTRIBUTE_WALK: i32 = 0x108;
const TREE: i32 = 0x109;
const DEVICE_ID_OF_FILE: i32 = 0x10a;
const EXPORT: i32 = 0x10b;
const EXPORT_PREFIX: i32 = 0x10c;
const EXPORT_DB: i32 = 0x10d;
const CLEANUP_DB: i32 = 0x10e;
const WAIT: i32 = 0x10f;
const NO_PAGER: i32 = 0x110;
const JSON: i32 = 0x111;
const SUBSYSTEM_MATCH: i32 = 0x112;
const SUBSYSTEM_NOMATCH: i32 = 0x113;
const ATTR_MATCH: i32 = 0x114;
const ATTR_NOMATCH: i32 = 0x115;
const PROPERTY_MATCH: i32 = 0x116;
const TAG_MATCH: i32 = 0x117;
const SYSNAME_MATCH: i32 = 0x118;
const NAME_MATCH: i32 = 0x119;
const PARENT_MATCH: i32 = 0x11a;
const INITIALIZED_MATCH: i32 = 0x11b;
const INITIALIZED_NOMATCH: i32 = 0x11c;
const INTROSPECT: i32 = 0x11d;

const fn verbatim(long: &'static str, help: &'static str) -> Opt {
    Opt::long(QUERY, long, None, Some(help)).with_flags(OPTION_HELP_ENTRY_VERBATIM)
}

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(QUERY, b'q', Some("query"), Some("TYPE"), Some("Query device information:")),
    verbatim("        name", "- name of device node"),
    verbatim("        symlink", "- pointing to node"),
    verbatim("        path", "- sysfs device path"),
    verbatim("        property", "- the device properties"),
    verbatim("        all", "- all values"),
    Opt::long(PROPERTY, "property", Some("NAME"), Some("Show only properties by this name")),
    Opt::long(VALUE, "value", None, Some("Print only values")),
    Opt::new(PATH, b'p', Some("path"), Some("SYSPATH"), Some("sysfs device path used for query or attribute walk")),
    Opt::new(NAME, b'n', Some("name"), Some("NAME"), Some("Node or symlink name used for query or attribute walk")),
    Opt::new(ROOT, b'r', Some("root"), None, Some("Prepend dev directory to path names")),
    Opt::new(
        ATTRIBUTE_WALK,
        b'a',
        Some("attribute-walk"),
        None,
        Some("Print all key matches walking along the chain of parent devices"),
    ),
    Opt::new(TREE, b't', Some("tree"), None, Some("Show tree of devices")),
    Opt::new(
        DEVICE_ID_OF_FILE,
        b'd',
        Some("device-id-of-file"),
        Some("FILE"),
        Some("Print major:minor of device containing this file"),
    ),
    Opt::new(EXPORT, b'x', Some("export"), None, Some("Export key/value pairs")),
    Opt::new(EXPORT_PREFIX, b'P', Some("export-prefix"), Some("NAME"), Some("Export the key name with a prefix")),
    Opt::new(EXPORT_DB, b'e', Some("export-db"), None, Some("Export the content of the udev database")),
    Opt::new(CLEANUP_DB, b'c', Some("cleanup-db"), None, Some("Clean up the udev database")),
    Opt::new(WAIT, b'w', Some("wait-for-initialization"), Some("SECS"), Some("Wait for device to be initialized"))
        .with_flags(OPTION_OPTIONAL_ARG),
    common::no_pager(NO_PAGER),
    Opt::long(JSON, "json", Some("FORMAT"), Some("Generate JSON output (pretty, short, or off)")),
    Opt::long(SUBSYSTEM_MATCH, "subsystem-match", Some("SUBSYSTEM"), Some("Query devices matching a subsystem")),
    Opt::long(
        SUBSYSTEM_NOMATCH,
        "subsystem-nomatch",
        Some("SUBSYSTEM"),
        Some("Query devices not matching a subsystem"),
    ),
    Opt::long(ATTR_MATCH, "attr-match", Some("FILE[=VALUE]"), Some("Query devices that match an attribute")),
    Opt::long(ATTR_NOMATCH, "attr-nomatch", Some("FILE[=VALUE]"), Some("Query devices that do not match an attribute")),
    Opt::long(PROPERTY_MATCH, "property-match", Some("KEY=VALUE"), Some("Query devices with matching properties")),
    Opt::long(TAG_MATCH, "tag-match", Some("TAG"), Some("Query devices with a matching tag")),
    Opt::long(SYSNAME_MATCH, "sysname-match", Some("NAME"), Some("Query devices with this /sys path")),
    Opt::long(NAME_MATCH, "name-match", Some("NAME"), Some("Query devices with this /dev name")),
    Opt::long(PARENT_MATCH, "parent-match", Some("NAME"), Some("Query devices with this parent device")),
    Opt::long(INITIALIZED_MATCH, "initialized-match", None, Some("Query devices that are already initialized")),
    Opt::long(INITIALIZED_NOMATCH, "initialized-nomatch", None, Some("Query devices that are not initialized yet")),
    common::introspect_cli(INTROSPECT),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionType {
    Query,
    AttributeWalk,
    DeviceIdFile,
    Tree,
    Export,
    CleanupDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryType {
    Name,
    Path,
    Symlink,
    Property,
    All,
}

/// The `arg_*` globals.
#[derive(Debug)]
struct Args {
    properties: Option<Vec<Vec<u8>>>,
    root: bool,
    export: bool,
    value: bool,
    export_prefix: Option<Vec<u8>>,
    wait_for_initialization_timeout: u64,
    json: u32,
    action: ActionType,
    query: QueryType,
    devices: Vec<Vec<u8>>,
    name: Option<Vec<u8>>,
    attr_match: Vec<Vec<u8>>,
    attr_nomatch: Vec<Vec<u8>>,
    name_match: Vec<Vec<u8>>,
    parent_match: Vec<Vec<u8>>,
    property_match: Vec<Vec<u8>>,
    subsystem_match: Vec<Vec<u8>>,
    subsystem_nomatch: Vec<Vec<u8>>,
    sysname_match: Vec<Vec<u8>>,
    tag_match: Vec<Vec<u8>>,
    initialized_match: Option<MatchInitialized>,
}

/// `TREE_DEPTH_MAX`.
const TREE_DEPTH_MAX: u32 = 64;

/// `skip_attribute()`.
fn skip_attribute(name: &[u8]) -> bool {
    matches!(name, b"uevent" | b"dev" | b"modalias" | b"resource" | b"driver" | b"subsystem" | b"module")
}

/// The attributes `print_all_attributes()` shows, sorted by name.
fn printable_attributes(device: &Device) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut sysattrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut a = device.get_sysattr_first();
    while let Some(name) = a {
        let n = name.bytes().to_vec();
        a = device.get_sysattr_next();
        if skip_attribute(&n) {
            continue;
        }
        let value = match device.get_sysattr_safe_string(&n) {
            Ok(v) => {
                let v = v.bytes().to_vec();
                if v.first() == Some(&b'/') {
                    continue;
                }
                if !v.iter().all(|&c| (0x20..0x7f).contains(&c)) {
                    continue;
                }
                v
            }
            Err(r) if errno_is_privilege(r) => b"(not readable)".to_vec(),
            Err(_) => continue,
        };
        sysattrs.push((n, value));
    }
    sysattrs.sort_by(|x, y| x.0.cmp(&y.0));
    sysattrs
}

fn bytes_or_empty(r: Result<shared::sd_device::DStr, i32>) -> Vec<u8> {
    r.map(|v| v.bytes().to_vec()).unwrap_or_default()
}

/// `print_all_attributes()`.
fn print_all_attributes(device: &Device, is_parent: bool) {
    if is_parent {
        printo!("\n");
    }
    printo!("  looking at ", if is_parent { "parent " } else { "" }, "device '", device.get_devpath().bytes(), "':\n");
    printo!("    ", if is_parent { "KERNELS" } else { "KERNEL" }, "==\"", bytes_or_empty(device.get_sysname()), "\"\n");
    printo!(
        "    ",
        if is_parent { "SUBSYSTEMS" } else { "SUBSYSTEM" },
        "==\"",
        bytes_or_empty(device.get_subsystem()),
        "\"\n"
    );
    printo!("    ", if is_parent { "DRIVERS" } else { "DRIVER" }, "==\"", bytes_or_empty(device.get_driver()), "\"\n");
    for (n, v) in printable_attributes(device) {
        printo!("    ", if is_parent { "ATTRS" } else { "ATTR" }, "{", n, "}==\"", v, "\"\n");
    }
}

/// `print_device_chain()`.
fn print_device_chain(device: &Dev) {
    printo!(
        "\n",
        "Udevadm info starts with the device specified by the devpath and then\n",
        "walks up the chain of parent devices. It prints for every device\n",
        "found, all possible attributes in the udev rules key format.\n",
        "A rule to match, can be composed by the attributes of the device\n",
        "and the attributes from one single parent device.\n",
        "\n"
    );
    print_all_attributes(device, false);
    let mut child = device.clone();
    while let Ok(parent) = child.get_parent() {
        print_all_attributes(&parent, true);
        child = parent;
    }
}

/// A string field that may be NULL: JSON null then.
fn opt_string(r: Result<shared::sd_device::DStr, i32>) -> Result<Json, i32> {
    match r {
        Ok(v) => string_checked(v.bytes()),
        Err(_) => Ok(Json::Null),
    }
}

/// `print_all_attributes_in_json()`.
fn print_all_attributes_in_json(device: &Device, is_parent: bool, flags: u32) -> Result<(), i32> {
    let mut v: Vec<(Vec<u8>, Json)> = Vec::new();
    set_field(&mut v, b"DEVPATH", string_checked(device.get_devpath().bytes())?);
    set_field(&mut v, if is_parent { b"KERNELS" } else { b"KERNEL" }, opt_string(device.get_sysname())?);
    set_field(&mut v, if is_parent { &b"SUBSYSTEMS"[..] } else { b"SUBSYSTEM" }, opt_string(device.get_subsystem())?);
    set_field(&mut v, if is_parent { b"DRIVERS" } else { b"DRIVER" }, opt_string(device.get_driver())?);
    let mut w: Vec<(Vec<u8>, Json)> = Vec::new();
    for (n, val) in printable_attributes(device) {
        set_field(&mut w, &n, string_checked(&val)?);
    }
    set_field(
        &mut v,
        if is_parent { b"ATTRS" } else { b"ATTR" },
        if w.is_empty() { Json::Null } else { Json::Object(w) },
    );
    shared::stdio::out(&shared::json::dump(&Json::Object(v), flags));
    Ok(())
}

/// `print_device_chain_in_json()`.
fn print_device_chain_in_json(device: &Dev, a: &mut Args) -> Result<(), i32> {
    a.json |= shared::json::SD_JSON_FORMAT_SEQ;
    print_all_attributes_in_json(device, false, a.json)?;
    let mut child = device.clone();
    while let Ok(parent) = child.get_parent() {
        print_all_attributes_in_json(&parent, true, a.json)?;
        child = parent;
    }
    Ok(())
}

/// `print_record(device, prefix)`.
fn print_record(device: &Device, prefix: &[u8]) {
    let h = ansi::highlight();
    let n = ansi::normal();
    printo!(prefix, "P: ", h, device.get_devpath().bytes(), n, "\n");
    if let Ok(s) = device.get_sysname() {
        printo!(prefix, "M: ", h, s.bytes(), n, "\n");
    }
    if let Ok(s) = device.get_sysnum() {
        printo!(prefix, "R: ", h, s.bytes(), n, "\n");
    }
    if let Ok(s) = device.get_device_id() {
        printo!(prefix, "J: ", h, s.bytes(), n, "\n");
    }
    let subsys = device.get_subsystem().ok();
    if let Some(s) = &subsys {
        printo!(prefix, "U: ", ansi::highlight_green(), s.bytes(), n, "\n");
    }
    if let Ok(s) = device.get_driver_subsystem() {
        printo!(prefix, "B: ", ansi::highlight_green(), s.bytes(), n, "\n");
    }
    if let Ok(s) = device.get_devtype() {
        printo!(prefix, "T: ", ansi::highlight_green(), s.bytes(), n, "\n");
    }
    if let Ok(devnum) = device.get_devnum() {
        let block = subsys.as_ref().is_some_and(|s| s.bytes() == b"block");
        printo!(
            prefix,
            "D: ",
            ansi::highlight_cyan(),
            if block { "b" } else { "c" },
            format!(" {}:{}", libc::major(devnum), libc::minor(devnum)),
            n,
            "\n"
        );
    }
    if let Ok(ifi) = device.get_ifindex() {
        printo!(prefix, "I: ", ansi::highlight_cyan(), ifi.to_string(), n, "\n");
    }
    if let Ok(s) = device.get_devname() {
        let val = path_startswith(s.bytes(), b"/dev/").expect("devnames are below /dev/");
        printo!(prefix, "N: ", ansi::highlight_cyan(), val, n, "\n");
        if let Ok(i) = device.get_devlink_priority() {
            printo!(prefix, "L: ", ansi::highlight_cyan(), i.to_string(), n, "\n");
        }
        for link in device.devlinks() {
            let val = path_startswith(link.bytes(), b"/dev/").expect("devlinks are below /dev/");
            printo!(prefix, "S: ", ansi::highlight_cyan(), val, n, "\n");
        }
    }
    if let Ok(q) = device.get_diskseq() {
        printo!(prefix, "Q: ", ansi::highlight_magenta(), q.to_string(), n, "\n");
    }
    if let Ok(s) = device.get_driver() {
        printo!(prefix, "V: ", ansi::highlight_yellow4(), s.bytes(), n, "\n");
    }
    for (k, v) in device.properties() {
        printo!(prefix, "E: ", k.bytes(), "=", v.bytes(), "\n");
    }
    if prefix.is_empty() {
        printo!("\n");
    }
}

/// `record_to_json()`.
fn record_to_json(device: &Device) -> Result<Json, i32> {
    let mut v: Vec<(Vec<u8>, Json)> = Vec::new();
    if let Ok(s) = device.get_sysname() {
        set_field(&mut v, b"SYSNAME", string_checked(s.bytes())?);
    }
    if let Ok(s) = device.get_sysnum() {
        set_field(&mut v, b"SYSNUM", string_checked(s.bytes())?);
    }
    if let Ok(s) = device.get_driver_subsystem() {
        set_field(&mut v, b"DRIVER_SUBSYSTEM", string_checked(s.bytes())?);
    }
    if let Ok(s) = device.get_device_id() {
        set_field(&mut v, b"DEVICE_ID", string_checked(s.bytes())?);
    }
    for (k, val) in device.properties() {
        set_field(&mut v, k.bytes(), string_checked(val.bytes())?);
    }
    Ok(Json::Object(v))
}

/// `stat_device()`.
fn stat_device(a: &Args) -> i32 {
    let name = a.name.as_deref().expect("set with -d");
    let st = match shared::sys::stat(name) {
        Ok(st) => st,
        Err(r) => return r,
    };
    let (maj, min) = (libc::major(st.st_dev), libc::minor(st.st_dev));
    if a.export {
        let prefix: &[u8] = a.export_prefix.as_deref().unwrap_or(b"INFO_");
        printo!(prefix, "MAJOR=", maj.to_string(), "\n", prefix, "MINOR=", min.to_string(), "\n");
    } else {
        printo!(format!("{maj}:{min}\n"));
    }
    0
}

/// `add_match_parent()`.
fn add_match_parent(e: &mut Enumerator, s: &[u8], prefix: &[u8]) -> Result<(), i32> {
    let dev = match crate::util::find_device(s, Some(prefix)) {
        Ok(d) => d,
        Err(r) => return Err(log_error_errno!(r, "Failed to open the device '", s, "': ", strerror(r))),
    };
    e.add_match_parent_incremental(&dev);
    Ok(())
}

/// `setup_matches()`.
fn setup_matches(e: &mut Enumerator, a: &Args) -> Result<(), i32> {
    for n in &a.name_match {
        add_match_parent(e, n, b"/dev")?;
    }
    for p in &a.parent_match {
        add_match_parent(e, p, b"/sys")?;
    }
    for s in &a.subsystem_match {
        e.add_match_subsystem(s, true);
    }
    for s in &a.subsystem_nomatch {
        e.add_match_subsystem(s, false);
    }
    for m in &a.attr_match {
        let (k, v) = crate::util::parse_key_value_argument(m, false)?;
        e.add_match_sysattr(&k, v.as_deref(), true);
    }
    for m in &a.attr_nomatch {
        let (k, v) = crate::util::parse_key_value_argument(m, false)?;
        e.add_match_sysattr(&k, v.as_deref(), false);
    }
    for p in &a.property_match {
        let (k, v) = crate::util::parse_key_value_argument(p, true)?;
        e.add_match_property_required(&k, v.as_deref());
    }
    for t in &a.tag_match {
        e.add_match_tag(t);
    }
    for s in &a.sysname_match {
        e.add_match_sysname(s, true);
    }
    if let Some(m) = a.initialized_match {
        e.add_match_is_initialized(m);
    }
    Ok(())
}

/// `export_devices()`.
fn export_devices(a: &Args) -> i32 {
    let mut e = Enumerator::new();
    e.allow_uninitialized();
    if let Err(r) = setup_matches(&mut e, a) {
        return r;
    }
    let r = e.scan_devices();
    if r < 0 {
        return log_error_errno!(r, "Failed to scan devices: ", strerror(r));
    }
    // FOREACH_DEVICE_AND_SUBSYSTEM()
    let mut d = e.get_first();
    while let Some(dev) = d {
        if format_enabled(a.json) {
            match record_to_json(&dev) {
                Ok(v) => shared::stdio::out(&shared::json::dump(&v, a.json)),
                Err(r) => return r,
            }
        } else {
            print_record(&dev, b"");
        }
        d = e.get_next();
    }
    0
}

/// `cleanup_dir(dir, mask, depth)`.
fn cleanup_dir(path: &[u8], mask: u32, depth: u32) {
    if depth == 0 {
        return;
    }
    let Ok(mut dir) = shared::sys_net::opendir(path) else { return };
    let fd = dir.fd();
    while let Ok(Some((name, _))) = shared::conf_files::foreach_dirent_all(&mut dir) {
        if shared::path::dot_or_dot_dot(&name) {
            continue;
        }
        let Ok(st) = shared::sys::fstatat(fd, &name, libc::AT_SYMLINK_NOFOLLOW) else { continue };
        if st.st_mode & mask != 0 {
            continue;
        }
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let sub = path_join(&[path, &name]);
            match shared::sys::openat(
                fd,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            ) {
                Err(r) => {
                    shared::log_debug_errno!(r, "Failed to open subdirectory '", &name, "', ignoring: ", strerror(r));
                }
                Ok(f) => {
                    drop(shared::sys::OwnedFd::new(f));
                    cleanup_dir(&sub, mask, depth - 1);
                }
            }
            let _ = shared::sys::unlinkat(fd, &name, libc::AT_REMOVEDIR);
        } else {
            let _ = shared::sys::unlinkat(fd, &name, 0);
        }
    }
}

/// `cleanup_dir_after_db_cleanup(dir, datadir)`.
fn cleanup_dir_after_db_cleanup(path: &[u8], datadir: Option<i32>) {
    let Ok(mut dir) = shared::sys_net::opendir(path) else { return };
    let fd = dir.fd();
    while let Ok(Some((name, _))) = shared::conf_files::foreach_dirent_all(&mut dir) {
        if shared::path::dot_or_dot_dot(&name) {
            continue;
        }
        if let Some(d) = datadir
            && shared::sys::faccessat(d, &name, libc::F_OK, libc::AT_SYMLINK_NOFOLLOW).is_ok()
        {
            continue;
        }
        let _ = shared::sys::unlinkat(fd, &name, 0);
    }
}

/// `cleanup_dirs_after_db_cleanup(dir, datadir)`.
fn cleanup_dirs_after_db_cleanup(path: &[u8], datadir: Option<i32>) {
    let Ok(mut dir) = shared::sys_net::opendir(path) else { return };
    let fd = dir.fd();
    while let Ok(Some((name, _))) = shared::conf_files::foreach_dirent_all(&mut dir) {
        if shared::path::dot_or_dot_dot(&name) {
            continue;
        }
        let Ok(st) = shared::sys::fstatat(fd, &name, libc::AT_SYMLINK_NOFOLLOW) else { continue };
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            match shared::sys::openat(
                fd,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            ) {
                Err(r) => {
                    shared::log_debug_errno!(r, "Failed to open subdirectory '", &name, "', ignoring: ", strerror(r));
                }
                Ok(f) => {
                    drop(shared::sys::OwnedFd::new(f));
                    cleanup_dir_after_db_cleanup(&path_join(&[path, &name]), datadir);
                }
            }
            let _ = shared::sys::unlinkat(fd, &name, libc::AT_REMOVEDIR);
        } else {
            let _ = shared::sys::unlinkat(fd, &name, 0);
        }
    }
}

/// `cleanup_db()`.
fn cleanup_db() -> i32 {
    let data = shared::sys::open(b"/run/udev/data", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)
        .ok()
        .map(shared::sys::OwnedFd::new);
    if data.is_some() {
        cleanup_dir(b"/run/udev/data", libc::S_ISVTX, 1);
    }
    let dfd = data.as_ref().map(|d| d.raw());
    cleanup_dirs_after_db_cleanup(b"/run/udev/links", dfd);
    cleanup_dirs_after_db_cleanup(b"/run/udev/tags", dfd);
    cleanup_dir(b"/run/udev/static_node-tags", 0, 2);
    0
}

/// `query_device(query, device)`.
fn query_device(a: &Args, device: &Device) -> i32 {
    match a.query {
        QueryType::Name => {
            let node = match device.get_devname() {
                Ok(n) => n,
                Err(r) => return log_error_errno!(r, "No device node found: ", strerror(r)),
            };
            let n = node.bytes();
            let n = if a.root { n } else { path_startswith(n, b"/dev/").expect("below /dev/") };
            printo!(n, "\n");
            0
        }
        QueryType::Symlink => {
            let mut prefix = "";
            for l in device.devlinks() {
                let l = l.bytes();
                let l = if a.root { l } else { path_startswith(l, b"/dev/").expect("below /dev/") };
                if a.value {
                    printo!(l, "\n");
                } else {
                    printo!(prefix, l);
                    prefix = " ";
                }
            }
            printo!("\n");
            0
        }
        QueryType::Path => {
            printo!(device.get_devpath().bytes(), "\n");
            0
        }
        QueryType::Property => {
            for (k, v) in device.properties() {
                if let Some(p) = &a.properties
                    && !p.iter().any(|x| x == k.bytes())
                {
                    continue;
                }
                if a.export {
                    printo!(a.export_prefix.as_deref().unwrap_or_default(), k.bytes(), "='", v.bytes(), "'\n");
                } else if a.value {
                    printo!(v.bytes(), "\n");
                } else {
                    printo!(k.bytes(), "=", v.bytes(), "\n");
                }
            }
            0
        }
        QueryType::All => {
            if format_enabled(a.json) {
                match record_to_json(device) {
                    Ok(v) => shared::stdio::out(&shared::json::dump(&v, a.json)),
                    Err(r) => return r,
                }
                0
            } else {
                print_record(device, b"");
                0
            }
        }
    }
}

/// `output_tree_device()`.
fn output_tree_device(device: &Dev, s: &[u8], prefix: &[u8], more: bool, array: &[Dev], level: u32) -> i32 {
    printo!(prefix, glyph(if more { Glyph::TreeBranch } else { Glyph::TreeRight }), s, "\n");
    let subprefix = bcat!(prefix, glyph(if more { Glyph::TreeVertical } else { Glyph::TreeSpace }));
    let subsubprefix = bcat!(&subprefix, glyph(Glyph::VerticalDotted), " ");
    print_record(device, &subsubprefix);
    draw_tree(Some(device), array, &subprefix, level + 1)
}

/// `draw_tree(parent, array, n, prefix, level)`.
fn draw_tree(parent: Option<&Dev>, array: &[Dev], prefix: &[u8], level: u32) -> i32 {
    if array.is_empty() {
        return 0;
    }
    let parent_path = parent.map(|p| p.get_devpath().bytes().to_vec());
    if level > TREE_DEPTH_MAX {
        log_warning!("Eliding tree below '", parent_path.as_deref().unwrap_or(b"n/a"), "', too deep.");
        return 0;
    }
    let mut i = 0;
    while i < array.len() {
        let device = &array[i];
        let device_path = device.get_devpath().bytes().to_vec();
        let mut more = false;
        let mut j = i + 1;
        while j < array.len() {
            let next_path = array[j].get_devpath();
            if path_startswith(next_path.bytes(), &device_path).is_none() {
                more = parent_path.as_deref().is_none_or(|pp| path_startswith(next_path.bytes(), pp).is_some());
                break;
            }
            j += 1;
        }
        let s: Vec<u8> = match &parent_path {
            Some(pp) => path_startswith(&device_path, pp).expect("below the parent").to_vec(),
            None => device_path.clone(),
        };
        let r = output_tree_device(device, &s, prefix, more, &array[i + 1..j], level);
        if r < 0 {
            return r;
        }
        i = j;
    }
    0
}

/// `print_tree(below)`.
fn print_tree(below: Option<&Dev>) -> i32 {
    let mut e = Enumerator::new();
    if let Some(b) = below {
        e.add_match_parent(b);
    }
    e.allow_uninitialized();
    let r = e.scan_devices_and_subsystems();
    if r < 0 {
        return log_error_errno!(r, "Failed to scan for devices and subsystems: ", strerror(r));
    }
    if let Some(b) = below
        && let Err(r) = e.add_parent_devices(b)
    {
        return log_error_errno!(r, "Failed to add parent devices: ", strerror(r));
    }
    let array = e.get_devices().unwrap_or_default();
    if array.is_empty() {
        log_info!("No items.");
        return 0;
    }
    let r = draw_tree(None, &array, b"", 0);
    if r < 0 {
        return r;
    }
    printo!("\n", array.len().to_string(), " items shown.\n");
    0
}

/// `parse_argv()`: Ok(None) to exit successfully.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
    let mut a = Args {
        properties: None,
        root: false,
        export: false,
        value: false,
        export_prefix: None,
        wait_for_initialization_timeout: 0,
        json: shared::json::SD_JSON_FORMAT_OFF,
        action: ActionType::Query,
        query: QueryType::All,
        devices: Vec::new(),
        name: None,
        attr_match: Vec::new(),
        attr_nomatch: Vec::new(),
        name_match: Vec::new(),
        parent_match: Vec::new(),
        property_match: Vec::new(),
        subsystem_match: Vec::new(),
        subsystem_nomatch: Vec::new(),
        sysname_match: Vec::new(),
        tag_match: Vec::new(),
        initialized_match: None,
    };
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("info");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                shared::build::version_only();
                return Ok(None);
            }
            QUERY => {
                a.query = match &arg[..] {
                    b"name" => QueryType::Name,
                    b"path" => QueryType::Path,
                    b"symlink" => QueryType::Symlink,
                    b"property" => QueryType::Property,
                    b"all" => QueryType::All,
                    b"env" => QueryType::Property,
                    _ => {
                        return Err(log_error_errno!(synthetic(libc::EINVAL), "Unknown query type '", &arg, "'"));
                    }
                };
            }
            PROPERTY => {
                if arg.is_empty() && a.properties.is_none() {
                    a.properties = Some(Vec::new());
                } else {
                    let l = a.properties.get_or_insert_with(Vec::new);
                    for w in shared::extract::strv_split_full(&arg, Some(b","), 0)? {
                        if !l.contains(&w) {
                            l.push(w);
                        }
                    }
                }
            }
            VALUE => a.value = true,
            PATH | NAME => {
                let prefix: &[u8] = if c == NAME { b"/dev/" } else { b"/sys/" };
                let path =
                    if path_startswith(&arg, prefix).is_some() { arg.clone() } else { path_join(&[prefix, &arg]) };
                a.devices.push(path);
            }
            ROOT => a.root = true,
            ATTRIBUTE_WALK => a.action = ActionType::AttributeWalk,
            TREE => a.action = ActionType::Tree,
            DEVICE_ID_OF_FILE => {
                a.action = ActionType::DeviceIdFile;
                a.name = Some(arg);
            }
            EXPORT => a.export = true,
            EXPORT_PREFIX => {
                a.export = true;
                a.export_prefix = Some(arg);
            }
            EXPORT_DB => a.action = ActionType::Export,
            CLEANUP_DB => a.action = ActionType::CleanupDb,
            WAIT => {
                if let Some(s) = &opts.arg {
                    match shared::time::parse_sec(s) {
                        Ok(t) => a.wait_for_initialization_timeout = t,
                        Err(r) => return Err(log_error_errno!(r, "Failed to parse timeout value: ", strerror(r))),
                    }
                } else {
                    a.wait_for_initialization_timeout = shared::time::USEC_INFINITY;
                }
            }
            NO_PAGER => {
                crate::PAGER_FLAGS.fetch_or(shared::pager::PAGER_DISABLE, Ordering::Relaxed);
            }
            JSON => match shared::json::parse_json_argument(&arg)? {
                Some(f) => a.json = f,
                None => return Ok(None),
            },
            SUBSYSTEM_MATCH => a.subsystem_match.push(arg),
            SUBSYSTEM_NOMATCH => a.subsystem_nomatch.push(arg),
            ATTR_MATCH => a.attr_match.push(arg),
            ATTR_NOMATCH => a.attr_nomatch.push(arg),
            PROPERTY_MATCH => {
                if !arg.contains(&b'=') {
                    return Err(log_error_errno!(
                        synthetic(libc::EINVAL),
                        "Expected <PROPERTY>=<value> instead of '",
                        &arg,
                        "'"
                    ));
                }
                a.property_match.push(arg);
            }
            TAG_MATCH => a.tag_match.push(arg),
            SYSNAME_MATCH => a.sysname_match.push(arg),
            NAME_MATCH => a.name_match.push(arg),
            PARENT_MATCH => a.parent_match.push(arg),
            INITIALIZED_MATCH => a.initialized_match = Some(MatchInitialized::Yes),
            INITIALIZED_NOMATCH => a.initialized_match = Some(MatchInitialized::No),
            INTROSPECT => {
                let r = crate::introspect(a.json);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            _ => unreachable!("option id {c}"),
        }
    }
    a.devices.extend(opts.args().iter().cloned());
    if matches!(a.action, ActionType::DeviceIdFile | ActionType::CleanupDb) && !a.devices.is_empty() {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Devices are not allowed with -d/--device-id-of-file and -c/--cleanup-db."
        ));
    }
    if !matches!(a.action, ActionType::DeviceIdFile | ActionType::CleanupDb | ActionType::Export | ActionType::Tree)
        && a.devices.is_empty()
    {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "A device name or path is required"));
    }
    if matches!(a.action, ActionType::AttributeWalk | ActionType::Tree) && a.devices.len() > 1 {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Only one device may be specified with -a/--attribute-walk and -t/--tree"
        ));
    }
    if a.export && a.value {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "-x/--export or -P/--export-prefix cannot be used with --value"
        ));
    }
    Ok(Some(a))
}

/// `verb_info_main()`.
pub fn verb_info_main(argv: Vec<Vec<u8>>) -> i32 {
    let mut a = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    if a.action == ActionType::CleanupDb {
        return cleanup_db();
    }
    if a.action == ActionType::DeviceIdFile {
        return stat_device(&a);
    }
    let mut pager_flags = crate::pager_flags();
    if a.action == ActionType::Query && a.query == QueryType::Symlink && !a.value {
        pager_flags |= shared::pager::PAGER_DISABLE;
    }
    shared::pager::pager_open(pager_flags);
    if a.action == ActionType::Export {
        return export_devices(&a);
    }
    if a.devices.is_empty() {
        return print_tree(None);
    }
    let mut ret = 0;
    for p in a.devices.clone() {
        let mut device = match crate::util::find_device(&p, None) {
            Ok(d) => d,
            Err(r) => {
                if r == -libc::EINVAL {
                    log_error_errno!(
                        r,
                        "Bad argument \"",
                        &p,
                        "\", expected an absolute path in /dev/ or /sys/, device ID, or a unit name: ",
                        strerror(r)
                    );
                } else {
                    log_error_errno!(r, "Unknown device \"", &p, "\": ", strerror(r));
                }
                ret_gather(&mut ret, r);
                continue;
            }
        };
        if a.wait_for_initialization_timeout > 0 {
            match crate::udev::wait::device_wait_for_initialization(&device, a.wait_for_initialization_timeout) {
                Ok(d) => device = d,
                Err(r) => return r,
            }
        }
        let r = match a.action {
            ActionType::Query => query_device(&a, &device),
            ActionType::AttributeWalk => {
                if format_enabled(a.json) {
                    match print_device_chain_in_json(&device, &mut a) {
                        Ok(()) => 0,
                        Err(r) => r,
                    }
                } else {
                    print_device_chain(&device);
                    0
                }
            }
            ActionType::Tree => print_tree(Some(&device)),
            _ => unreachable!("action"),
        };
        if r < 0 {
            return r;
        }
    }
    ret
}
