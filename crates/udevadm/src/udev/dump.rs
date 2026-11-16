// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-dump.c`: what an event did, for `udevadm test` and
//! `OPTIONS="dump"`.

use shared::bcat;
use shared::json::{Json, format_enabled, set_field, string_checked};
use shared::terminal::ansi;
use shared::user::{gid_to_name, uid_to_name};

use super::def::{GID_INVALID, MODE_INVALID, UID_INVALID};
use super::event::Event;

/// `event_cache_written_value()`: replace in place, or append.
fn cache_written(values: &mut Vec<(Vec<u8>, Vec<u8>)>, attr: &[u8], value: &[u8]) {
    values.retain(|(k, _)| !shared::path::path_equal(k, attr));
    values.push((attr.to_vec(), value.to_vec()));
}

/// `event_cache_written_sysattr()`.
pub fn event_cache_written_sysattr(event: &mut Event, attr: &[u8], value: &[u8]) {
    cache_written(&mut event.written_sysattrs, attr, value);
}

/// `event_cache_written_sysctl()`.
pub fn event_cache_written_sysctl(event: &mut Event, attr: &[u8], value: &[u8]) {
    cache_written(&mut event.written_sysctls, attr, value);
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

fn strv_checked(v: &[Vec<u8>]) -> Result<Json, i32> {
    Ok(Json::Array(v.iter().map(|s| string_checked(s)).collect::<Result<_, _>>()?))
}

/// `dump_event_json()`: the JSON text.
fn dump_event_json(event: &Event, flags: u32) -> Result<Vec<u8>, i32> {
    let dev = &event.dev;
    let mut v: Vec<(Vec<u8>, Json)> = Vec::new();
    let s = |x: &[u8]| string_checked(x);
    set_field(&mut v, b"path", s(dev.get_devpath().bytes())?);
    if let Ok(n) = dev.get_sysname() {
        set_field(&mut v, b"name", s(n.bytes())?);
    }
    if let Ok(n) = dev.get_sysnum_unsigned() {
        set_field(&mut v, b"number", Json::Unsigned(n as u64));
    }
    if let Ok(id) = dev.get_device_id() {
        set_field(&mut v, b"id", s(id.bytes())?);
    }
    let subsys = dev.get_subsystem().ok();
    if let Some(ss) = &subsys {
        set_field(&mut v, b"subsystem", s(ss.bytes())?);
    }
    if let Ok(ds) = dev.get_driver_subsystem() {
        set_field(&mut v, b"driverSubsystem", s(ds.bytes())?);
    }
    if let Ok(t) = dev.get_devtype() {
        set_field(&mut v, b"type", s(t.bytes())?);
    }
    if let Ok(d) = dev.get_driver() {
        set_field(&mut v, b"driver", s(d.bytes())?);
    }
    if let Ok(devname) = dev.get_devname() {
        let mut node: Vec<(Vec<u8>, Json)> = Vec::new();
        set_field(&mut node, b"path", s(devname.bytes())?);
        let block = subsys.as_ref().is_some_and(|x| x.bytes() == b"block");
        set_field(&mut node, b"type", Json::str(if block { "block" } else { "char" }));
        if let Ok(devnum) = dev.get_devnum() {
            let rdev = if devnum == 0 {
                Json::Null
            } else {
                Json::Object(vec![
                    (b"major".to_vec(), Json::Unsigned(libc::major(devnum) as u64)),
                    (b"minor".to_vec(), Json::Unsigned(libc::minor(devnum) as u64)),
                ])
            };
            set_field(&mut node, b"rdev", rdev);
        }
        let mut owner: Vec<(Vec<u8>, Json)> = Vec::new();
        let mut uid = event.uid;
        if uid == UID_INVALID {
            uid = dev.get_devnode_uid().unwrap_or(UID_INVALID);
        }
        if uid != UID_INVALID {
            set_field(&mut owner, b"uid", Json::Unsigned(uid as u64));
            set_field(&mut owner, b"userName", s(&uid_to_name(uid))?);
        }
        let mut gid = event.gid;
        if gid == GID_INVALID {
            gid = dev.get_devnode_gid().unwrap_or(GID_INVALID);
        }
        if gid != GID_INVALID {
            set_field(&mut owner, b"gid", Json::Unsigned(gid as u64));
            set_field(&mut owner, b"groupName", s(&gid_to_name(gid))?);
        }
        if !owner.is_empty() {
            set_field(&mut node, b"owner", Json::Object(owner));
        }
        let mut mode = event.mode;
        if mode == MODE_INVALID {
            mode = dev.get_devnode_mode().unwrap_or(MODE_INVALID);
        }
        if mode != MODE_INVALID {
            set_field(&mut node, b"mode", Json::str(format!("{:04o}", mode & !libc::S_IFMT)));
        }
        let links: Vec<Vec<u8>> = dev.devlinks().iter().map(|l| l.bytes().to_vec()).collect();
        if !links.is_empty() {
            let prio = dev.get_devlink_priority().unwrap_or(0);
            set_field(&mut node, b"symlinkPriority", Json::Integer(prio as i64));
            set_field(&mut node, b"symlinks", strv_checked(&sorted(links))?);
        }
        let labels: Vec<Json> = event
            .seclabel_list
            .iter()
            .map(|(n, l)| {
                Ok(Json::Object(vec![(b"name".to_vec(), string_checked(n)?), (b"label".to_vec(), string_checked(l)?)]))
            })
            .collect::<Result<_, i32>>()?;
        if !labels.is_empty() {
            set_field(&mut node, b"securityLabels", Json::Array(labels));
        }
        set_field(&mut node, b"inotifyWatch", Json::Bool(event.inotify_watch));
        set_field(&mut v, b"node", Json::Object(node));
    }
    if let Ok(ifindex) = dev.get_ifindex() {
        let mut netif: Vec<(Vec<u8>, Json)> = Vec::new();
        set_field(&mut netif, b"index", Json::Integer(ifindex as i64));
        if let Some(n) = event.name.as_ref().filter(|n| !n.is_empty()) {
            set_field(&mut netif, b"name", s(n)?);
        }
        if !event.altnames.is_empty() {
            set_field(&mut netif, b"alternativeNames", strv_checked(&sorted(event.altnames.clone()))?);
        }
        set_field(&mut v, b"networkInterface", Json::Object(netif));
    }
    let pairs = |l: &[(Vec<u8>, Vec<u8>)]| -> Result<Vec<Json>, i32> {
        l.iter()
            .map(|(k, x)| {
                Ok(Json::Object(vec![(b"path".to_vec(), string_checked(k)?), (b"value".to_vec(), string_checked(x)?)]))
            })
            .collect()
    };
    let sysattrs = pairs(&event.written_sysattrs)?;
    if !sysattrs.is_empty() {
        set_field(&mut v, b"sysfsAttributes", Json::Array(sysattrs));
    }
    let sysctls = pairs(&event.written_sysctls)?;
    if !sysctls.is_empty() {
        set_field(&mut v, b"sysctl", Json::Array(sysctls));
    }
    let tags: Vec<Vec<u8>> = dev.tags().iter().map(|t| t.bytes().to_vec()).collect();
    if !tags.is_empty() {
        set_field(&mut v, b"tags", strv_checked(&sorted(tags))?);
    }
    let ctags: Vec<Vec<u8>> = dev.current_tags().iter().map(|t| t.bytes().to_vec()).collect();
    if !ctags.is_empty() {
        set_field(&mut v, b"currentTags", strv_checked(&sorted(ctags))?);
    }
    if let Ok(props) = dev.get_properties_strv() {
        let p: Vec<Vec<u8>> = props.iter().map(|x| x.bytes().to_vec()).collect();
        if !p.is_empty() {
            set_field(&mut v, b"properties", strv_checked(&sorted(p))?);
        }
    }
    let commands: Vec<Json> = event
        .run_list
        .iter()
        .map(|(c, b)| {
            Ok(Json::Object(vec![
                (b"type".to_vec(), Json::str(if b.is_some() { "builtin" } else { "program" })),
                (b"command".to_vec(), string_checked(c)?),
            ]))
        })
        .collect::<Result<_, i32>>()?;
    if !commands.is_empty() {
        set_field(&mut v, b"queuedCommands", Json::Array(commands));
    }
    Ok(shared::json::dump(&Json::Object(v), flags))
}

/// `dump_event(event, flags, f)`: the text to print.
pub fn dump_event(event: &Event, flags: u32) -> Result<Vec<u8>, i32> {
    if format_enabled(flags) {
        return dump_event_json(event, flags);
    }
    let dev = &event.dev;
    let h = ansi::highlight();
    let n = ansi::normal();
    let mut f: Vec<u8> = Vec::new();
    let section = |f: &mut Vec<u8>, title: &str, value: &[u8]| {
        f.extend(bcat!(h, title, ":", n, "\n  ", value, "\n"));
    };
    section(&mut f, "Device path", dev.get_devpath().bytes());
    if let Ok(s) = dev.get_sysname() {
        section(&mut f, "Device name", s.bytes());
    }
    if let Ok(s) = dev.get_sysnum() {
        section(&mut f, "Device number", s.bytes());
    }
    if let Ok(s) = dev.get_device_id() {
        section(&mut f, "Device ID", s.bytes());
    }
    let subsys = dev.get_subsystem().ok();
    if let Some(ss) = &subsys {
        let ds = dev.get_driver_subsystem().ok();
        f.extend(bcat!(
            h,
            "Subsystem:",
            n,
            "\n  ",
            ss.bytes(),
            if ds.is_some() { " (" } else { "" },
            ds.as_ref().map(|d| d.bytes()).unwrap_or_default(),
            if ds.is_some() { ")" } else { "" },
            "\n"
        ));
    }
    if let Ok(s) = dev.get_devtype() {
        section(&mut f, "Device type", s.bytes());
    }
    if let Ok(s) = dev.get_driver() {
        section(&mut f, "Device driver", s.bytes());
    }
    if let Ok(devname) = dev.get_devname() {
        if let Ok(devnum) = dev.get_devnum() {
            let block = subsys.as_ref().is_some_and(|x| x.bytes() == b"block");
            f.extend(bcat!(
                h,
                "Device node:",
                n,
                "\n  ",
                devname.bytes(),
                " (",
                if block { "block" } else { "char" },
                " ",
                format!("{}:{}", libc::major(devnum), libc::minor(devnum)),
                ")\n"
            ));
        }
        let mut uid = event.uid;
        if uid == UID_INVALID {
            uid = dev.get_devnode_uid().unwrap_or(UID_INVALID);
        }
        if uid != UID_INVALID {
            f.extend(bcat!(
                h,
                "Device node owner user:",
                n,
                "\n  ",
                uid_to_name(uid),
                " (uid=",
                uid.to_string(),
                ")\n"
            ));
        }
        let mut gid = event.gid;
        if gid == GID_INVALID {
            gid = dev.get_devnode_gid().unwrap_or(GID_INVALID);
        }
        if gid != GID_INVALID {
            f.extend(bcat!(
                h,
                "Device node owner group:",
                n,
                "\n  ",
                gid_to_name(gid),
                " (gid=",
                gid.to_string(),
                ")\n"
            ));
        }
        let mut mode = event.mode;
        if mode == MODE_INVALID {
            mode = dev.get_devnode_mode().unwrap_or(MODE_INVALID);
        }
        if mode != MODE_INVALID {
            f.extend(bcat!(h, "Device node permission:", n, "\n  ", format!("{mode:04o}"), "\n"));
        }
        let links = dev.devlinks();
        if !links.is_empty() {
            let prio = dev.get_devlink_priority().unwrap_or(0);
            f.extend(bcat!(h, "Device node symlinks:", n, " (priority=", prio.to_string(), ")\n"));
            for l in &links {
                f.extend(bcat!("  ", l.bytes(), "\n"));
            }
        }
        if !event.seclabel_list.is_empty() {
            f.extend(bcat!(h, "Device node security label:", n, "\n"));
            for (name, label) in &event.seclabel_list {
                f.extend(bcat!("  ", name, " : ", label, "\n"));
            }
        }
        section(&mut f, "Inotify watch", if event.inotify_watch { b"enabled" } else { b"disabled" });
    }
    if let Ok(ifindex) = dev.get_ifindex() {
        section(&mut f, "Network interface index", ifindex.to_string().as_bytes());
        if let Some(name) = event.name.as_ref().filter(|n| !n.is_empty()) {
            section(&mut f, "Network interface name", name);
        }
        if !event.altnames.is_empty() {
            f.extend(bcat!(h, "Alternative interface names:", n));
            for a in sorted(event.altnames.clone()) {
                f.extend(bcat!("\n  ", a));
            }
            f.push(b'\n');
        }
    }
    if !event.written_sysattrs.is_empty() {
        f.extend(bcat!(h, "Written sysfs attributes:", n, "\n"));
        for (k, v) in &event.written_sysattrs {
            f.extend(bcat!("  ", k, " : ", v, "\n"));
        }
    }
    if !event.written_sysctls.is_empty() {
        f.extend(bcat!(h, "Written sysctl entries:", n, "\n"));
        for (k, v) in &event.written_sysctls {
            f.extend(bcat!("  ", k, " : ", v, "\n"));
        }
    }
    let tags = dev.tags();
    if !tags.is_empty() {
        f.extend(bcat!(h, "Tags:", n, "\n"));
        for t in &tags {
            f.extend(bcat!("  ", t.bytes(), "\n"));
        }
    }
    let ctags = dev.current_tags();
    if !ctags.is_empty() {
        f.extend(bcat!(h, "Current Tags:", n, "\n"));
        for t in &ctags {
            f.extend(bcat!("  ", t.bytes(), "\n"));
        }
    }
    if let Ok(props) = dev.get_properties_strv() {
        let p: Vec<Vec<u8>> = props.iter().map(|x| x.bytes().to_vec()).collect();
        if !p.is_empty() {
            f.extend(bcat!(h, "Properties:", n));
            for x in sorted(p) {
                f.extend(bcat!("\n  ", x));
            }
            f.push(b'\n');
        }
    }
    if !event.run_list.is_empty() {
        f.extend(bcat!(h, "Queued commands:", n, "\n"));
        for (c, b) in &event.run_list {
            f.extend(bcat!("  RUN{", if b.is_some() { "builtin" } else { "program" }, "} : ", c, "\n"));
        }
    }
    Ok(f)
}

/// `OPTIONS="dump"`: `dump_event()` into a memory stream.
pub fn dump_event_to_string(event: &Event, flags: u32) -> Vec<u8> {
    dump_event(event, flags).unwrap_or_default()
}
