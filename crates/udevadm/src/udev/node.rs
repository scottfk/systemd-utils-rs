// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-node.c`: device node permissions, and the `/dev` symlinks with
//! their stack directories under `/run/udev/links/`.  This only runs in
//! the destructive event modes (udevd and the rule runner).

use shared::errno::{strerror, synthetic};
use shared::fd::AT_FDCWD;
use shared::path::{path_join, path_startswith};
use shared::sd_device::{Device, errno_is_neg_device_absent};
use shared::sys::{self, OwnedFd};
use shared::{bcat, log_debug_errno, log_device_debug, log_device_debug_errno, log_device_warning_errno};

use super::def::{GID_INVALID, MODE_INVALID, UID_INVALID};

/// `UDEV_NODE_HASH_KEY`.
const UDEV_NODE_HASH_KEY: [u8; 16] =
    [0xb9, 0x6a, 0xf1, 0xce, 0x40, 0x31, 0x44, 0x1a, 0x9e, 0x19, 0xec, 0x8b, 0xae, 0xf3, 0xe3, 0x2f];

/// `ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY()`.
fn absent_or_empty(r: i32) -> bool {
    errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM
}

/// `rmdir_parents(path, stop)`.
pub fn rmdir_parents(path: &[u8], stop: &[u8]) -> Result<(), i32> {
    if !shared::path::path_is_safe(path) || !shared::path::path_is_safe(stop) {
        return Err(-libc::EINVAL);
    }
    let mut p = path.to_vec();
    loop {
        let (r, _, e) = shared::path::path_find_last_component(&p, false)?;
        if r == 0 {
            return Ok(());
        }
        // e is where the last component's slash is.
        let slash = e;
        if slash == 0 {
            return Ok(());
        }
        p.truncate(slash);
        if path_startswith(stop, &p).is_some() {
            return Ok(());
        }
        if let Err(r) = sys::rmdir(&p)
            && r != -libc::ENOENT
        {
            return Err(r);
        }
    }
}

/// `node_remove_symlink()`.
fn node_remove_symlink(dev: &Device, slink: &[u8]) -> Result<(), i32> {
    if let Err(r) = sys::unlinkat(AT_FDCWD, slink, 0)
        && r != -libc::ENOENT
    {
        return Err(log_device_debug_errno!(dev, r, "Failed to remove '", slink, "': ", strerror(r)));
    }
    let _ = rmdir_parents(slink, b"/dev");
    Ok(())
}

/// `node_create_symlink(dev, devnode, slink)`.
fn node_create_symlink(dev: &Device, devnode: Option<&[u8]>, slink: &[u8]) -> Result<(), i32> {
    let devnode: Vec<u8> = match devnode {
        Some(d) => d.to_vec(),
        None => match dev.get_devname() {
            Ok(d) => d.bytes().to_vec(),
            Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r))),
        },
    };
    match sys::lstat(slink) {
        Ok(st) => {
            if st.st_mode & libc::S_IFMT != libc::S_IFLNK {
                return Err(log_device_debug_errno!(
                    dev,
                    synthetic(libc::EEXIST),
                    "Conflicting inode '",
                    slink,
                    "' found, symlink to '",
                    &devnode,
                    "' will not be created."
                ));
            }
        }
        Err(r) if r != -libc::ENOENT => {
            return Err(log_device_debug_errno!(dev, r, "Failed to lstat() '", slink, "': ", strerror(r)));
        }
        Err(_) => {}
    }
    if let Err(r) = shared::fs::mkdirat_parents(AT_FDCWD, slink, 0o755) {
        return Err(log_device_debug_errno!(
            dev,
            r,
            "Failed to create parent directory of '",
            slink,
            "': ",
            strerror(r)
        ));
    }
    // symlinkat_atomic_full(devnode, AT_FDCWD, slink, SYMLINK_MAKE_RELATIVE|SYMLINK_LABEL)
    let r = shared::path::path_extract_directory(slink)
        .and_then(|from| shared::path::path_make_relative(&from, &devnode))
        .and_then(|rel| shared::fs::symlinkat_atomic(&rel, AT_FDCWD, slink));
    if let Err(r) = r {
        return Err(log_device_debug_errno!(
            dev,
            r,
            "Failed to create symlink '",
            slink,
            "' to '",
            &devnode,
            "': ",
            strerror(r)
        ));
    }
    log_device_debug!(dev, "Successfully created symlink '", slink, "' to '", &devnode, "'");
    Ok(())
}

/// `stack_directory_read_one(dirfd, id, &devnode, &priority)`: Ok(true)
/// if updated.
fn stack_directory_read_one(
    dirfd: i32,
    id: &[u8],
    devnode: Option<&mut Option<Vec<u8>>>,
    priority: &mut i32,
) -> Result<bool, i32> {
    let buf = match sys::readlinkat(dirfd, id) {
        Ok(b) => b,
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENODEV),
        Err(r) => return Err(r),
    };
    let Some(colon) = buf.iter().position(|&b| b == b':').filter(|&c| c > 0) else {
        return Err(-libc::EINVAL);
    };
    let node = &buf[colon + 1..];
    if shared::sys_net::access(node, libc::F_OK).is_err() {
        return Err(-libc::ENODEV);
    }
    let tmp_prio = shared::parse::safe_atoi(&buf[..colon])?;
    if let Some(d) = devnode {
        if d.is_some() && tmp_prio <= *priority {
            return Ok(false);
        }
        *d = Some(node.to_vec());
    }
    *priority = tmp_prio;
    Ok(true)
}

/// `stack_directory_find_prioritized_devnode(dev, dirfd, add)`.
fn stack_directory_find_prioritized_devnode(dev: &Device, dirfd: i32, add: bool) -> Result<Option<Vec<u8>>, i32> {
    let mut devnode: Option<Vec<u8>> = None;
    let mut priority = 0;
    if add {
        priority = dev.get_devlink_priority()?;
        devnode = Some(dev.get_devname()?.bytes().to_vec());
    }
    let mut dir = sys::fdopendir_dup(dirfd)?;
    let id = dev.get_device_id()?;
    while let Some((name, _)) = shared::conf_files::foreach_dirent(&mut dir)? {
        if name == id.bytes() {
            continue;
        }
        if let Err(r) = stack_directory_read_one(dirfd, &name, Some(&mut devnode), &mut priority)
            && r != -libc::ENODEV
        {
            log_debug_errno!(r, "Failed to read '", &name, "', ignoring: ", strerror(r));
        }
    }
    Ok(devnode)
}

/// `link_search_and_update()`.
fn link_search_and_update(dev: &Device, slink: &[u8], dirfd: i32, add: bool) -> Result<(), i32> {
    match stack_directory_find_prioritized_devnode(dev, dirfd, add) {
        Err(r) => Err(log_device_debug_errno!(
            dev,
            r,
            "Failed to determine device node with the highest priority for '",
            slink,
            "': ",
            strerror(r)
        )),
        Ok(Some(d)) => node_create_symlink(dev, Some(&d), slink),
        Ok(None) => {
            log_device_debug!(dev, "No reference left for '", slink, "', removing");
            node_remove_symlink(dev, slink)
        }
    }
}

/// `stack_directory_update()`: Ok(true) if updated.
fn stack_directory_update(dev: &Device, fd: i32, add: bool) -> Result<bool, i32> {
    let id = dev.get_device_id()?;
    if add {
        let devname = dev.get_devname()?;
        let priority = dev.get_devlink_priority()?;
        let data = bcat!(priority.to_string(), ":", devname.bytes());
        if sys::readlinkat(fd, id.bytes()).is_ok_and(|b| b == data) {
            return Ok(false);
        }
        let _ = sys::unlinkat(fd, id.bytes(), 0);
        sys::symlinkat(&data, fd, id.bytes())?;
    } else {
        match sys::unlinkat(fd, id.bytes(), 0) {
            Err(r) if r == -libc::ENOENT => return Ok(false),
            Err(r) => return Err(r),
            Ok(()) => {}
        }
    }
    Ok(true)
}

/// `urlsafe_base64char()`.
fn urlsafe_base64char(x: u64) -> u8 {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[(x & 63) as usize]
}

/// `udev_node_escape_path(src, dest, size)`.
pub fn udev_node_escape_path(src: &[u8], size: usize) -> Vec<u8> {
    let mut dest: Vec<u8> = Vec::new();
    let mut toolong = false;
    for &c in src {
        let piece: &[u8] = match c {
            b'/' => b"\\x2f",
            b'\\' => b"\\x5c",
            _ => std::slice::from_ref(&c),
        };
        if dest.len() + piece.len() > size - 12 {
            toolong = true;
            break;
        }
        dest.extend_from_slice(piece);
    }
    if !toolong {
        return dest;
    }
    // Suffix with a string made from the hash of the path.
    let h = shared::siphash::siphash24(src, &UDEV_NODE_HASH_KEY);
    dest.resize(size - 1, 0);
    for k in 0..=10usize {
        dest[size - k - 2] = urlsafe_base64char(h >> (k * 6));
    }
    dest
}

/// `stack_directory_get_name(slink)`.
fn stack_directory_get_name(slink: &[u8]) -> Result<Vec<u8>, i32> {
    let s = shared::path::path_simplify(slink);
    if !shared::path::path_is_normalized(&s) {
        return Err(-libc::EINVAL);
    }
    let name = path_startswith(&s, b"/dev");
    if shared::path::empty_or_root(name) {
        return Err(-libc::EINVAL);
    }
    Ok(udev_node_escape_path(name.unwrap_or_default(), shared::path::NAME_MAX + 1))
}

/// `LockFile`: an OFD-locked file, unlinked again when released with
/// the exclusive lock held.
struct LockFile {
    path: Vec<u8>,
    _fd: OwnedFd,
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = sys::unlinkat(AT_FDCWD, &self.path, 0);
    }
}

/// The stack directory, removed (if empty) when dropped.
struct StackDir {
    path: Vec<u8>,
    fd: Option<OwnedFd>,
}

impl Drop for StackDir {
    fn drop(&mut self) {
        self.fd = None;
        let _ = sys::rmdir(&self.path);
    }
}

/// `stack_directory_open_and_lock()`: the directory, then its lock (so
/// they're dropped in this order).
fn stack_directory_open_and_lock(dev: &Device, slink: &[u8]) -> Result<(StackDir, LockFile), i32> {
    let name = match stack_directory_get_name(slink) {
        Ok(n) => n,
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to build stack directory name for '",
                slink,
                "': ",
                strerror(r)
            ));
        }
    };
    for s in [&b"/run/udev/links/"[..], b"/run/udev/links.lock/"] {
        if let Err(r) = shared::fs::mkdir_p(s, 0o755) {
            return Err(log_device_debug_errno!(dev, r, "Failed to create '", s, "': ", strerror(r)));
        }
    }
    let lockname = path_join(&[b"/run/udev/links.lock/", &name]);
    let lock = match sys::open_ofd_lock(&lockname) {
        Ok(fd) => LockFile { path: lockname, _fd: OwnedFd::new(fd) },
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Failed to create and lock '", &lockname, "': ", strerror(r)));
        }
    };
    let dirpath = path_join(&[b"/run/udev/links/", &name]);
    let fd = match shared::fs::open_mkdir(
        &dirpath,
        libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY,
        0o755,
    ) {
        Ok(fd) => fd,
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to open stack directory '",
                &dirpath,
                "': ",
                strerror(r)
            ));
        }
    };
    Ok((StackDir { path: dirpath, fd: Some(fd) }, lock))
}

/// `node_get_current(slink, dirfd)`: the device ID, and priority.
fn node_get_current(slink: &[u8], dirfd: i32) -> Result<(Vec<u8>, i32), i32> {
    let dev = Device::new_from_devname(slink)?;
    let id = dev.get_device_id()?.bytes().to_vec();
    let mut prio = 0;
    stack_directory_read_one(dirfd, &id, None, &mut prio)?;
    Ok((id, prio))
}

/// `link_update(dev, slink, add)`.
fn link_update(dev: &Device, slink: &[u8], add: bool) -> Result<(), i32> {
    let (dir, _lock) = stack_directory_open_and_lock(dev, slink)?;
    let dirfd = dir.fd.as_ref().expect("open").raw();
    let mut current: Option<(Vec<u8>, i32)> = None;
    if add {
        match node_get_current(slink, dirfd) {
            Ok(c) => current = Some(c),
            Err(r) if absent_or_empty(r) => {}
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to get the current device node priority for '",
                    slink,
                    "': ",
                    strerror(r)
                ));
            }
        }
    }
    if let Err(r) = stack_directory_update(dev, dirfd, add) {
        return Err(log_device_debug_errno!(
            dev,
            r,
            "Failed to update stack directory for '",
            slink,
            "': ",
            strerror(r)
        ));
    }
    if !add {
        let target = match sys::readlink(slink) {
            Ok(t) => t,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_device_debug_errno!(
                        dev,
                        r,
                        "Failed to read symbolic link '",
                        slink,
                        "', ignoring: ",
                        strerror(r)
                    );
                }
                return link_search_and_update(dev, slink, dirfd, add);
            }
        };
        let node = match dev.get_devname() {
            Ok(n) => n,
            Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r))),
        };
        if node.bytes() == &target[..] {
            return link_search_and_update(dev, slink, dirfd, add);
        }
        if path_startswith(&target, b"/dev/").is_none() {
            log_device_debug!(
                dev,
                "Symbolic link '",
                slink,
                "' points to '",
                &target,
                "' which is outside of '/dev/', updating it."
            );
            return link_search_and_update(dev, slink, dirfd, add);
        }
        let st = match sys::lstat(&target) {
            Ok(st) => st,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_device_debug_errno!(dev, r, "Failed to stat '", &target, "', ignoring: ", strerror(r));
                }
                return link_search_and_update(dev, slink, dirfd, add);
            }
        };
        let fmt = st.st_mode & libc::S_IFMT;
        if fmt != libc::S_IFBLK && fmt != libc::S_IFCHR {
            log_device_debug!(
                dev,
                "Symbolic link '",
                slink,
                "' points to '",
                &target,
                "' which is not a device node, updating it."
            );
            return link_search_and_update(dev, slink, dirfd, add);
        }
        return Ok(());
    }
    let Some((current_id, current_prio)) = current else {
        return link_search_and_update(dev, slink, dirfd, add);
    };
    let id = match dev.get_device_id() {
        Ok(i) => i,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device id: ", strerror(r))),
    };
    let prio = match dev.get_devlink_priority() {
        Ok(p) => p,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get devlink priority: ", strerror(r))),
    };
    if current_id == id.bytes() {
        if current_prio <= prio {
            return Ok(());
        }
        return link_search_and_update(dev, slink, dirfd, add);
    }
    if current_prio > prio {
        return Ok(());
    }
    node_create_symlink(dev, None, slink)
}

/// `device_get_devpath_by_devnum()`: "/dev/{block,char}/MAJ:MIN".
fn device_get_devpath_by_devnum(dev: &Device) -> Result<Vec<u8>, i32> {
    let devnum = dev.get_devnum()?;
    let block = dev.in_subsystem(&[b"block"])?;
    Ok(format!("/dev/{}/{}:{}", if block { "block" } else { "char" }, libc::major(devnum), libc::minor(devnum))
        .into_bytes())
}

/// `udev_node_update(dev, dev_old)`.
pub fn udev_node_update(dev: &Device, dev_old: &Device) -> Result<(), i32> {
    for devlink in dev_old.devlinks() {
        if dev.has_devlink(devlink.bytes()) {
            continue;
        }
        log_device_debug!(
            dev,
            "Removing/updating old device symlink '",
            devlink.bytes(),
            "', which is no longer belonging to this device."
        );
        if let Err(r) = link_update(dev, devlink.bytes(), false) {
            log_device_warning_errno!(
                dev,
                r,
                "Failed to remove/update device symlink '",
                devlink.bytes(),
                "', ignoring: ",
                strerror(r)
            );
        }
    }
    for devlink in dev.devlinks() {
        if let Err(r) = link_update(dev, devlink.bytes(), true) {
            log_device_warning_errno!(
                dev,
                r,
                "Failed to create/update device symlink '",
                devlink.bytes(),
                "', ignoring: ",
                strerror(r)
            );
        }
    }
    let filename = match device_get_devpath_by_devnum(dev) {
        Ok(f) => f,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device path: ", strerror(r))),
    };
    if let Err(r) = node_create_symlink(dev, None, &filename) {
        return Err(log_device_warning_errno!(
            dev,
            r,
            "Failed to create device symlink '",
            &filename,
            "': ",
            strerror(r)
        ));
    }
    Ok(())
}

/// `udev_node_remove(dev)`.
pub fn udev_node_remove(dev: &Device) -> Result<(), i32> {
    for devlink in dev.devlinks() {
        if let Err(r) = link_update(dev, devlink.bytes(), false) {
            log_device_warning_errno!(
                dev,
                r,
                "Failed to remove/update device symlink '",
                devlink.bytes(),
                "', ignoring: ",
                strerror(r)
            );
        }
    }
    let filename = match device_get_devpath_by_devnum(dev) {
        Ok(f) => f,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get device path: ", strerror(r))),
    };
    node_remove_symlink(dev, &filename)
}

fn mode_str(m: u32) -> String {
    if m == 0 { "0".to_string() } else { format!("0{m:o}") }
}

/// `udev_node_apply_permissions_impl()`.
fn apply_permissions_impl(
    dev: Option<&Device>,
    node_fd: i32,
    devnode: &[u8],
    apply_mac: bool,
    mut mode: u32,
    uid: u32,
    gid: u32,
    seclabel_list: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), i32> {
    let log = |level: i32, err: i32, msg: Vec<u8>| shared::sd_device::log_device_full(dev, level, err, msg);
    let st = match sys::fstat(node_fd) {
        Ok(st) => st,
        Err(r) => return Err(log(shared::log::LOG_DEBUG, r, bcat!("cannot stat() node ", devnode, ": ", strerror(r)))),
    };
    if mode == MODE_INVALID && gid != GID_INVALID && gid > 0 {
        mode = 0o660;
    }
    let apply_mode = mode != MODE_INVALID && (st.st_mode & 0o777) != (mode & 0o777);
    let apply_uid = uid != UID_INVALID && st.st_uid != uid;
    let apply_gid = gid != GID_INVALID && st.st_gid != gid;
    if apply_mode || apply_uid || apply_gid || apply_mac {
        let shown_uid = if uid != UID_INVALID { uid } else { st.st_uid };
        let shown_gid = if gid != GID_INVALID { gid } else { st.st_gid };
        let shown_mode = if mode != MODE_INVALID { mode & 0o777 } else { st.st_mode & 0o777 };
        let what = bcat!(
            devnode,
            ", uid=",
            shown_uid.to_string(),
            ", gid=",
            shown_gid.to_string(),
            ", mode=",
            mode_str(shown_mode)
        );
        if apply_mode || apply_uid || apply_gid {
            log(shared::log::LOG_DEBUG, 0, bcat!("Setting permissions ", &what));
            if let Err(r) = shared::fs::fchmod_and_chown(node_fd, mode, uid, gid) {
                log(
                    if r == -libc::ENOENT { shared::log::LOG_DEBUG } else { shared::log::LOG_ERR },
                    r,
                    bcat!(
                        "Failed to set owner/mode of ",
                        devnode,
                        " to uid=",
                        shown_uid.to_string(),
                        ", gid=",
                        shown_gid.to_string(),
                        ", mode=",
                        mode_str(shown_mode),
                        ": ",
                        strerror(r)
                    ),
                );
            }
        } else {
            log(shared::log::LOG_DEBUG, 0, bcat!("Preserve permissions of ", &what));
        }
        // SECLABEL{$module}=$label: no SELinux or SMACK in this build.
        for (name, label) in seclabel_list {
            if name == b"selinux" || name == b"smack" {
                log(
                    shared::log::LOG_DEBUG,
                    0,
                    bcat!(
                        "SECLABEL: set ",
                        if name == b"selinux" { "SELinux" } else { "SMACK" },
                        " label '",
                        label,
                        "'"
                    ),
                );
            } else {
                log(shared::log::LOG_ERR, 0, bcat!("SECLABEL: unknown subsystem, ignoring '", name, "'='", label, "'"));
            }
        }
    }
    if let Err(r) = sys::futimens_opath(node_fd) {
        log(shared::log::LOG_DEBUG, r, bcat!("Failed to adjust timestamp of node ", devnode, ": ", strerror(r)));
    }
    Ok(())
}

/// `sd_device_open(dev, O_PATH|O_CLOEXEC)`.
fn device_open_path(dev: &Device) -> Result<OwnedFd, i32> {
    let devname = match dev.get_devname() {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENOEXEC),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    let devnum = match dev.get_devnum() {
        Err(r) if r == -libc::ENOENT => return Err(-libc::ENOEXEC),
        Err(r) => return Err(r),
        Ok(d) => d,
    };
    let fd = OwnedFd::new(sys::open(devname.bytes(), libc::O_PATH | libc::O_CLOEXEC, 0)?);
    let st = sys::fstat(fd.raw())?;
    if st.st_rdev != devnum {
        return Err(-libc::ENXIO);
    }
    let block = dev.in_subsystem(&[b"block"])?;
    let fmt = st.st_mode & libc::S_IFMT;
    if if block { fmt != libc::S_IFBLK } else { fmt != libc::S_IFCHR } {
        return Err(-libc::ENXIO);
    }
    Ok(fd)
}

/// `udev_node_apply_permissions(dev, apply_mac, mode, uid, gid, seclabel_list)`.
pub fn udev_node_apply_permissions(
    dev: &Device,
    apply_mac: bool,
    mode: u32,
    uid: u32,
    gid: u32,
    seclabel_list: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), i32> {
    let devnode = match dev.get_devname() {
        Ok(d) => d,
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to get devname: ", strerror(r))),
    };
    let fd = match device_open_path(dev) {
        Ok(fd) => fd,
        Err(r) if absent_or_empty(r) => {
            log_device_debug_errno!(dev, r, "Device node ", devnode.bytes(), " is missing, skipping handling.");
            return Ok(());
        }
        Err(r) => {
            return Err(log_device_debug_errno!(dev, r, "Cannot open node ", devnode.bytes(), ": ", strerror(r)));
        }
    };
    apply_permissions_impl(Some(dev), fd.raw(), devnode.bytes(), apply_mac, mode, uid, gid, seclabel_list)
}

/// `xescape(s, bad)`: `\xNN` for control characters, bytes >= 127,
/// backslashes and the bytes in `bad`.
pub(crate) fn xescape(s: &[u8], bad: &[u8]) -> Vec<u8> {
    let hex = b"0123456789abcdef";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if !(b' '..127).contains(&c) || c == b'\\' || bad.contains(&c) {
            out.extend_from_slice(&[b'\\', b'x', hex[(c >> 4) as usize], hex[(c & 15) as usize]]);
        } else {
            out.push(c);
        }
    }
    out
}

/// `static_node_apply_permissions(name, mode, uid, gid, tags)`.
pub fn static_node_apply_permissions(name: &[u8], mode: u32, uid: u32, gid: u32, tags: &[Vec<u8>]) -> Result<(), i32> {
    if uid == UID_INVALID && gid == GID_INVALID && mode == MODE_INVALID && tags.is_empty() {
        return Ok(());
    }
    let devnode = bcat!("/dev/", name);
    let fd = match sys::open(&devnode, libc::O_PATH | libc::O_CLOEXEC, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => {
            let ignore = absent_or_empty(r);
            shared::log_full_errno!(
                if ignore { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                r,
                "Failed to open device node '",
                &devnode[..],
                "'",
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { Ok(()) } else { Err(r) };
        }
    };
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(r) => return Err(shared::log_error_errno!(r, "Failed to stat ", &devnode[..], ": ", strerror(r))),
    };
    let fmt = st.st_mode & libc::S_IFMT;
    if fmt != libc::S_IFBLK && fmt != libc::S_IFCHR {
        shared::log_warning!(&devnode[..], " is neither block nor character device, ignoring.");
        return Ok(());
    }
    let unescaped = xescape(name, b"/.");
    for t in tags {
        let p = path_join(&[b"/run/udev/static_node-tags/", t, &unescaped]);
        if let Err(r) = shared::fs::mkdirat_parents(AT_FDCWD, &p, 0o755) {
            return Err(shared::log_error_errno!(
                r,
                "Failed to create parent directory for ",
                &p[..],
                ": ",
                strerror(r)
            ));
        }
        match sys::symlinkat(&devnode, AT_FDCWD, &p) {
            Err(r) if r != -libc::EEXIST => {
                return Err(shared::log_error_errno!(
                    r,
                    "Failed to create symlink ",
                    &p[..],
                    " -> ",
                    &devnode[..],
                    ": ",
                    strerror(r)
                ));
            }
            _ => {}
        }
    }
    apply_permissions_impl(None, fd.raw(), &devnode, false, mode, uid, gid, &[])
}
