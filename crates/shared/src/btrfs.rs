// SPDX-License-Identifier: LGPL-2.1-or-later
//! `btrfs-util.c` (basic and shared): the subvolume and qgroup calls that
//! tmpfiles and rm_rf() make.

use crate::fd::{XAT_FDROOT, fd_reopen};
use crate::path::{filename_is_valid, path_extract_directory, path_extract_filename};
use crate::stat_util::{BTRFS_SUPER_MAGIC, is_fs_type_at, xopenat};
use crate::sys::{self, Fd, OwnedFd, ioctl_none, ioctl_ptr};

pub const BTRFS_REMOVE_RECURSIVE: u32 = 1 << 0;
pub const BTRFS_REMOVE_QUOTA: u32 = 1 << 1;

const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;
const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
const BTRFS_QUOTA_TREE_OBJECTID: u64 = 8;
const BTRFS_ROOT_BACKREF_KEY: u32 = 144;
const BTRFS_QGROUP_RELATION_KEY: u32 = 246;
const BTRFS_QGROUP_LEVEL_SHIFT: u32 = 48;

const BTRFS_IOC_SUBVOL_CREATE: u64 = 0x5000940e;
const BTRFS_IOC_SNAP_DESTROY: u64 = 0x5000940f;
const BTRFS_IOC_TREE_SEARCH: u64 = 0xd0009411;
const BTRFS_IOC_INO_LOOKUP: u64 = 0xd0009412;
const BTRFS_IOC_SUBVOL_GETFLAGS: u64 = 0x80089419;
const BTRFS_IOC_SUBVOL_SETFLAGS: u64 = 0x4008941a;
const BTRFS_IOC_QGROUP_ASSIGN: u64 = 0x40189429;
const BTRFS_IOC_QGROUP_CREATE: u64 = 0x4010942a;
const BTRFS_IOC_QUOTA_RESCAN: u64 = 0x4040942c;
const BTRFS_IOC_QUOTA_RESCAN_WAIT: u64 = 0x942e;
const BTRFS_IOC_GET_SUBVOL_ROOTREF: u64 = 0xd000943d;
const BTRFS_IOC_INO_LOOKUP_USER: u64 = 0xd000943e;

/// `struct btrfs_ioctl_vol_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct VolArgs {
    fd: i64,
    name: [u8; 4088],
}

impl VolArgs {
    fn new(name: &[u8]) -> VolArgs {
        let mut a = VolArgs { fd: 0, name: [0; 4088] };
        // strncpy(args.name, name, sizeof(args.name)-1)
        let n = name.len().min(a.name.len() - 1);
        a.name[..n].copy_from_slice(&name[..n]);
        a
    }
}

/// `struct btrfs_ioctl_ino_lookup_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InoLookupArgs {
    treeid: u64,
    objectid: u64,
    name: [u8; 4080],
}

/// `struct btrfs_ioctl_search_key`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SearchKey {
    tree_id: u64,
    min_objectid: u64,
    max_objectid: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64,
    max_transid: u64,
    min_type: u32,
    max_type: u32,
    nr_items: u32,
    unused: u32,
    unused1: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
}

/// `struct btrfs_ioctl_search_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SearchArgs {
    key: SearchKey,
    buf: [u8; 4096 - 104],
}

/// `struct btrfs_ioctl_search_header`, as read from the buffer.
#[derive(Clone, Copy, Default)]
struct SearchHeader {
    objectid: u64,
    offset: u64,
    ty: u32,
    len: u32,
}

/// `struct btrfs_ioctl_qgroup_assign_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct QgroupAssignArgs {
    assign: u64,
    src: u64,
    dst: u64,
}

/// `struct btrfs_ioctl_qgroup_create_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct QgroupCreateArgs {
    create: u64,
    qgroupid: u64,
}

/// `struct btrfs_ioctl_quota_rescan_args`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct QuotaRescanArgs {
    flags: u64,
    progress: u64,
    reserved: [u64; 6],
}

/// `struct btrfs_ioctl_get_subvol_rootref_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RootrefArgs {
    min_treeid: u64,
    rootref: [[u64; 2]; 255],
    num_items: u8,
    align: [u8; 7],
}

/// `struct btrfs_ioctl_ino_lookup_user_args`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InoLookupUserArgs {
    dirid: u64,
    treeid: u64,
    name: [u8; 256],
    path: [u8; 3824],
}

fn c_str(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `fd_is_fs_type(fd, BTRFS_SUPER_MAGIC)`, as ENOTTY when not.
fn require_btrfs(fd: Fd) -> Result<(), i32> {
    if is_fs_type_at(fd, None, BTRFS_SUPER_MAGIC)? { Ok(()) } else { Err(-libc::ENOTTY) }
}

/// `btrfs_validate_subvolume_name()`.
pub fn validate_subvolume_name(name: &[u8]) -> Result<(), i32> {
    if !filename_is_valid(name) {
        return Err(-libc::EINVAL);
    }
    if name.len() > BTRFS_SUBVOL_NAME_MAX {
        return Err(-libc::E2BIG);
    }
    Ok(())
}

/// `btrfs_subvol_make(dir_fd, path)`.
pub fn subvol_make(dir_fd: Fd, path: &[u8]) -> Result<(), i32> {
    let subvolume = path_extract_filename(path)?;
    validate_subvolume_name(&subvolume)?;
    let parent = match path_extract_directory(path) {
        Ok(p) => Some(p),
        Err(e) if e == -libc::EDESTADDRREQ => None,
        Err(e) => return Err(e),
    };
    let fd =
        xopenat(dir_fd, Some(parent.as_deref().unwrap_or(b".")), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC)?;
    let mut args = VolArgs::new(&subvolume);
    ioctl_ptr(fd.raw(), BTRFS_IOC_SUBVOL_CREATE, &mut args)?;
    Ok(())
}

/// `btrfs_might_be_subvol()`.
pub fn might_be_subvol(st: &sys::Stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_ino == 256
}

/// `btrfs_is_subvol_at(dir_fd, path)`.
pub fn is_subvol_at(dir_fd: Fd, path: Option<&[u8]>) -> Result<bool, i32> {
    let p = path.unwrap_or_default();
    let st = sys::fstatat(dir_fd, p, if p.is_empty() { libc::AT_EMPTY_PATH } else { 0 })?;
    if !might_be_subvol(&st) {
        return Ok(false);
    }
    is_fs_type_at(dir_fd, path, BTRFS_SUPER_MAGIC)
}

/// `btrfs_subvol_get_id_fd(fd, &ret)`.
pub fn subvol_get_id_fd(fd: Fd) -> Result<u64, i32> {
    require_btrfs(fd)?;
    let mut args = InoLookupArgs { treeid: 0, objectid: BTRFS_FIRST_FREE_OBJECTID, name: [0; 4080] };
    ioctl_ptr(fd, BTRFS_IOC_INO_LOOKUP, &mut args)?;
    Ok(args.treeid)
}

/// `btrfs_subvol_get_read_only_fd(fd)`.
pub fn subvol_get_read_only_fd(fd: Fd) -> Result<bool, i32> {
    let st = sys::fstat(fd)?;
    if !might_be_subvol(&st) {
        return Err(-libc::EINVAL);
    }
    let mut flags: u64 = 0;
    ioctl_ptr(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &mut flags)?;
    Ok(flags & BTRFS_SUBVOL_RDONLY != 0)
}

/// `btrfs_subvol_set_read_only_fd(fd, b)`.
pub fn subvol_set_read_only_fd(fd: Fd, b: bool) -> Result<(), i32> {
    let fd = xopenat(fd, None, libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY)?;
    let st = sys::fstat(fd.raw())?;
    if !might_be_subvol(&st) {
        return Err(-libc::EINVAL);
    }
    let mut flags: u64 = 0;
    ioctl_ptr(fd.raw(), BTRFS_IOC_SUBVOL_GETFLAGS, &mut flags)?;
    let mut nflags = if b { flags | BTRFS_SUBVOL_RDONLY } else { flags & !BTRFS_SUBVOL_RDONLY };
    if flags == nflags {
        return Ok(());
    }
    ioctl_ptr(fd.raw(), BTRFS_IOC_SUBVOL_SETFLAGS, &mut nflags)?;
    Ok(())
}

/// A tree search over objectid == id and one key type, as
/// `btrfs_qgroup_find_parents()` and `btrfs_subvol_get_parent()` do it.
fn search_args(tree_id: u64, ty: u32, id: u64) -> SearchArgs {
    SearchArgs {
        key: SearchKey {
            tree_id,
            min_objectid: id,
            max_objectid: id,
            min_type: ty,
            max_type: ty,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            ..Default::default()
        },
        buf: [0; 4096 - 104],
    }
}

/// `btrfs_ioctl_search_args_compare(&args) <= 0`.
fn search_args_le(a: &SearchArgs) -> bool {
    (a.key.min_objectid, a.key.min_type, a.key.min_offset) <= (a.key.max_objectid, a.key.max_type, a.key.max_offset)
}

/// `btrfs_ioctl_search_args_inc()`.
fn search_args_inc(a: &mut SearchArgs) -> bool {
    if a.key.min_offset < u64::MAX {
        a.key.min_offset += 1;
        return true;
    }
    if a.key.min_type < u8::MAX as u32 {
        a.key.min_type += 1;
        a.key.min_offset = 0;
        return true;
    }
    if a.key.min_objectid < u64::MAX {
        a.key.min_objectid += 1;
        a.key.min_offset = 0;
        a.key.min_type = 0;
        return true;
    }
    false
}

/// `FOREACH_BTRFS_IOCTL_SEARCH_HEADER()`: the headers of one result, or
/// EBADMSG for a malformed buffer (as `btrfs_iterate()` would stop).
fn search_headers(a: &SearchArgs) -> Vec<SearchHeader> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let size = a.buf.len();
    for _ in 0..a.key.nr_items {
        if off > size - 32 {
            break;
        }
        let u64_at = |o: usize| u64::from_ne_bytes(a.buf[o..o + 8].try_into().expect("8 bytes"));
        let u32_at = |o: usize| u32::from_ne_bytes(a.buf[o..o + 4].try_into().expect("4 bytes"));
        let h = SearchHeader {
            objectid: u64_at(off + 8),
            offset: u64_at(off + 16),
            ty: u32_at(off + 24),
            len: u32_at(off + 28),
        };
        // Unsigned arithmetic as in C: a huge len wraps and passes.
        if off > (size - 32).wrapping_sub(h.len as usize) {
            break;
        }
        off = off.saturating_add(32 + h.len as usize);
        out.push(h);
    }
    out
}

/// `btrfs_qgroup_find_parents(fd, qgroupid, &ret)`.
pub fn qgroup_find_parents(fd: Fd, qgroupid: u64) -> Result<Vec<u64>, i32> {
    let qgroupid = if qgroupid == 0 {
        subvol_get_id_fd(fd)?
    } else {
        require_btrfs(fd)?;
        qgroupid
    };
    let mut args = search_args(BTRFS_QUOTA_TREE_OBJECTID, BTRFS_QGROUP_RELATION_KEY, qgroupid);
    let mut items = Vec::new();
    while search_args_le(&args) {
        args.key.nr_items = 256;
        match ioctl_ptr(fd, BTRFS_IOC_TREE_SEARCH, &mut args) {
            Err(e) if e == -libc::ENOENT => break, // quota tree missing: quota is disabled
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if args.key.nr_items == 0 {
            break;
        }
        for sh in search_headers(&args) {
            args.key.min_objectid = sh.objectid;
            args.key.min_type = sh.ty;
            args.key.min_offset = sh.offset;
            if sh.ty != BTRFS_QGROUP_RELATION_KEY || sh.offset < sh.objectid || sh.objectid != qgroupid {
                continue;
            }
            items.push(sh.offset);
        }
        if !search_args_inc(&mut args) {
            break;
        }
    }
    Ok(items)
}

/// `btrfs_subvol_get_parent(fd, subvol_id, &ret)`.
fn subvol_get_parent(fd: Fd, subvol_id: u64) -> Result<u64, i32> {
    let subvol_id = if subvol_id == 0 {
        subvol_get_id_fd(fd)?
    } else {
        require_btrfs(fd)?;
        subvol_id
    };
    let mut args = search_args(BTRFS_ROOT_TREE_OBJECTID, BTRFS_ROOT_BACKREF_KEY, subvol_id);
    // QUIRK: like C, this does not advance the search key between rounds,
    // so a round that matches nothing repeats forever.
    while search_args_le(&args) {
        args.key.nr_items = 256;
        ioctl_ptr(fd, BTRFS_IOC_TREE_SEARCH, &mut args)?;
        if args.key.nr_items == 0 {
            break;
        }
        for sh in search_headers(&args) {
            if sh.ty == BTRFS_ROOT_BACKREF_KEY && sh.objectid == subvol_id {
                return Ok(sh.offset);
            }
        }
    }
    Err(-libc::ENXIO)
}

fn qgroupid_make(level: u64, id: u64) -> Result<u64, i32> {
    if level >= 1u64 << (64 - BTRFS_QGROUP_LEVEL_SHIFT) || id >= 1u64 << BTRFS_QGROUP_LEVEL_SHIFT {
        return Err(-libc::EINVAL);
    }
    Ok((level << BTRFS_QGROUP_LEVEL_SHIFT) | id)
}

fn qgroupid_split(q: u64) -> (u64, u64) {
    (q >> BTRFS_QGROUP_LEVEL_SHIFT, q & ((1u64 << BTRFS_QGROUP_LEVEL_SHIFT) - 1))
}

fn quota_scan_wait(fd: Fd) {
    let _ = ioctl_none(fd, BTRFS_IOC_QUOTA_RESCAN_WAIT);
}

/// `qgroup_create_or_destroy()`.
fn qgroup_create_or_destroy(fd: Fd, b: bool, qgroupid: u64) -> Result<(), i32> {
    require_btrfs(fd)?;
    let mut args = QgroupCreateArgs { create: b as u64, qgroupid };
    let mut c = 0;
    loop {
        match ioctl_ptr(fd, BTRFS_IOC_QGROUP_CREATE, &mut args) {
            Ok(_) => return Ok(()),
            Err(e) if e == -libc::EINVAL || e == -libc::ENOTCONN => return Err(-libc::ENOTCONN),
            Err(e) if e == -libc::EBUSY && c < 10 => {
                quota_scan_wait(fd);
                c += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// `qgroup_assign_or_unassign()`: true if a rescan was requested.
fn qgroup_assign_or_unassign(fd: Fd, b: bool, child: u64, parent: u64) -> Result<bool, i32> {
    require_btrfs(fd)?;
    let mut args = QgroupAssignArgs { assign: b as u64, src: child, dst: parent };
    let mut c = 0;
    loop {
        match ioctl_ptr(fd, BTRFS_IOC_QGROUP_ASSIGN, &mut args) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                let mut rescan = QuotaRescanArgs::default();
                let _ = ioctl_ptr(fd, BTRFS_IOC_QUOTA_RESCAN, &mut rescan);
                return Ok(true);
            }
            Err(e) if e == -libc::EBUSY && c < 10 => {
                quota_scan_wait(fd);
                c += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// `btrfs_qgroup_destroy_recursive(fd, qgroupid)`.
fn qgroup_destroy_recursive(fd: Fd, qgroupid: u64) -> Result<(), i32> {
    let (_, subvol_id) = qgroupid_split(qgroupid);
    for q in qgroup_find_parents(fd, qgroupid)? {
        let (_, id) = qgroupid_split(q);
        qgroup_assign_or_unassign(fd, false, qgroupid, q)?;
        if id != subvol_id {
            continue;
        }
        let _ = qgroup_destroy_recursive(fd, q);
    }
    qgroup_create_or_destroy(fd, false, qgroupid)
}

/// `btrfs_subvol_auto_qgroup_fd(fd, subvol_id, insert_intermediary_qgroup)`:
/// whether anything changed.
pub fn subvol_auto_qgroup_fd(fd: Fd, subvol_id: u64, insert_intermediary_qgroup: bool) -> Result<bool, i32> {
    // fd_reopen_condition(fd, O_RDONLY|O_CLOEXEC, O_PATH, &real_fd)
    let _real;
    let fd = if sys::fd_is_opath(fd)? {
        _real = OwnedFd::new(fd_reopen(fd, libc::O_RDONLY | libc::O_CLOEXEC)?);
        _real.raw()
    } else {
        fd
    };
    let mut subvol_id = subvol_id;
    if subvol_id == 0 {
        if !is_subvol_at(fd, None)? {
            return Err(-libc::ENOTTY);
        }
        subvol_id = subvol_get_id_fd(fd)?;
    }
    if !qgroup_find_parents(fd, subvol_id)?.is_empty() {
        return Ok(false);
    }
    let qgroups = match subvol_get_parent(fd, subvol_id) {
        Err(e) if e == -libc::ENXIO => Vec::new(),
        Err(e) => return Err(e),
        Ok(parent) => qgroup_find_parents(fd, parent)?,
    };
    let mut changed = false;
    if insert_intermediary_qgroup {
        let lowest = qgroups.iter().map(|&q| qgroupid_split(q).0).fold(256, u64::min);
        if lowest <= 1 {
            return Err(-libc::EBUSY);
        }
        let new_qgroupid = qgroupid_make(lowest - 1, subvol_id)?;
        let mut created = false;
        match qgroup_create_or_destroy(fd, true, new_qgroupid) {
            Ok(()) => {
                changed = true;
                created = true;
            }
            Err(e) if e == -libc::EEXIST => {}
            Err(e) => return Err(e),
        }
        for &q in qgroups.iter().chain(std::iter::once(&u64::MAX)) {
            let (child, parent) = if q == u64::MAX { (subvol_id, new_qgroupid) } else { (new_qgroupid, q) };
            match qgroup_assign_or_unassign(fd, true, child, parent) {
                Ok(_) => changed = true,
                Err(e) if e == -libc::EEXIST => {}
                Err(e) => {
                    if created {
                        let _ = qgroup_destroy_recursive(fd, new_qgroupid);
                    }
                    return Err(e);
                }
            }
        }
    } else {
        for &q in &qgroups {
            match qgroup_assign_or_unassign(fd, true, subvol_id, q) {
                Ok(_) => changed = true,
                Err(e) if e == -libc::EEXIST => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(changed)
}

/// `subvol_remove_children(fd, subvolume, subvol_id, flags)`.
fn subvol_remove_children(fd: Fd, subvolume: &[u8], subvol_id: u64, flags: u32) -> Result<(), i32> {
    if sys::fstat(fd)?.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(-libc::ENOTDIR);
    }
    let subvol_fd = OwnedFd::new(sys::openat(
        fd,
        subvolume,
        libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?);
    if !is_subvol_at(subvol_fd.raw(), None)? {
        return Err(-libc::ENOTTY);
    }
    let mut subvol_id = subvol_id;
    'finish: {
        if sys::unlinkat(fd, subvolume, libc::AT_REMOVEDIR).is_ok() {
            break 'finish;
        }
        if subvol_id == 0 {
            subvol_id = subvol_get_id_fd(subvol_fd.raw())?;
        }
        let mut vol_args = VolArgs::new(subvolume);
        let mut made_writable = false;
        let destroy_errno = loop {
            let e = match ioctl_ptr(fd, BTRFS_IOC_SNAP_DESTROY, &mut vol_args) {
                Ok(_) => break 'finish,
                Err(e) => e,
            };
            if made_writable || !crate::errno::is_neg_fs_write_refused(e) {
                break e;
            }
            if !subvol_get_read_only_fd(subvol_fd.raw())? {
                break e;
            }
            subvol_set_read_only_fd(subvol_fd.raw(), false)?;
            made_writable = true;
        };
        if flags & BTRFS_REMOVE_RECURSIVE == 0 || destroy_errno != -libc::ENOTEMPTY {
            return Err(destroy_errno);
        }
        let mut rootref = RootrefArgs { min_treeid: 0, rootref: [[0; 2]; 255], num_items: 0, align: [0; 7] };
        loop {
            let res = ioctl_ptr(subvol_fd.raw(), BTRFS_IOC_GET_SUBVOL_ROOTREF, &mut rootref);
            if let Err(e) = res
                && e != -libc::EOVERFLOW
            {
                return Err(e);
            }
            for i in 0..rootref.num_items as usize {
                let [child_id, dirid] = rootref.rootref[i];
                let mut lookup = InoLookupUserArgs { dirid, treeid: child_id, name: [0; 256], path: [0; 3824] };
                ioctl_ptr(subvol_fd.raw(), BTRFS_IOC_INO_LOOKUP_USER, &mut lookup)?;
                if !made_writable {
                    subvol_set_read_only_fd(subvol_fd.raw(), false)?;
                    made_writable = true;
                }
                let path = c_str(&lookup.path);
                let name = c_str(&lookup.name);
                if path.is_empty() {
                    subvol_remove_children(subvol_fd.raw(), name, child_id, flags)?;
                } else {
                    let child_fd = OwnedFd::new(sys::openat(
                        subvol_fd.raw(),
                        path,
                        libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        0,
                    )?);
                    subvol_remove_children(child_fd.raw(), name, child_id, flags)?;
                }
            }
            if res.is_ok() {
                break;
            }
        }
        ioctl_ptr(fd, BTRFS_IOC_SNAP_DESTROY, &mut vol_args)?;
    }
    // For the leaf subvolumes, the qgroup id is identical to the subvol id.
    let _ = qgroup_destroy_recursive(fd, subvol_id);
    Ok(())
}

/// `btrfs_subvol_remove_at(dir_fd, path, flags)`.
pub fn subvol_remove_at(dir_fd: Fd, path: &[u8], flags: u32) -> Result<(), i32> {
    use crate::chase::{CHASE_EXTRACT_FILENAME, CHASE_PARENT, chaseat};
    let c = chaseat(XAT_FDROOT, dir_fd, path, CHASE_PARENT | CHASE_EXTRACT_FILENAME, true, true)?;
    let subvolume = c.path.expect("requested");
    let pfd = c.fd.expect("requested");
    let fd = xopenat(pfd.raw(), None, libc::O_CLOEXEC)?;
    validate_subvolume_name(&subvolume)?;
    subvol_remove_children(fd.raw(), &subvolume, 0, flags)
}
