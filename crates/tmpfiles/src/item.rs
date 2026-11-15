// SPDX-License-Identifier: LGPL-2.1-or-later
//! tmpfiles.c: the `Item` type, the specifier table and `parse_line()`.

use std::collections::HashMap;

use shared::errno::{strerror, synthetic};
use shared::extract::{EXTRACT_CUNESCAPE, EXTRACT_UNQUOTE, cunescape, extract_first_word, extract_many_words};
use shared::parse::{parse_devnum, parse_mode, split_pair};
use shared::path::{empty_or_root, path_is_absolute, path_join, path_simplify, path_startswith};
use shared::sd_path::{SdPath, sd_path_lookup};
use shared::specifier::{
    RuntimeScope, Specifier, common_creds_specifiers, common_system_specifiers, common_tmp_specifiers, spec,
    specifier_printf, specifier_user_home,
};
use shared::sys_acl::ParsedAcl;
use shared::user::{get_group_gid, get_user_uid, parse_uid, strerror_account};
use shared::{log_debug, log_error_errno, log_full, log_full_errno, log_syntax, log_warning, log_warning_errno};

use crate::{Context, args};

pub const CREATE_FILE: u8 = b'f';
pub const TRUNCATE_FILE: u8 = b'F';
pub const CREATE_DIRECTORY: u8 = b'd';
pub const TRUNCATE_DIRECTORY: u8 = b'D';
pub const CREATE_SUBVOLUME: u8 = b'v';
pub const CREATE_SUBVOLUME_INHERIT_QUOTA: u8 = b'q';
pub const CREATE_SUBVOLUME_NEW_QUOTA: u8 = b'Q';
pub const CREATE_FIFO: u8 = b'p';
pub const CREATE_SYMLINK: u8 = b'L';
pub const CREATE_CHAR_DEVICE: u8 = b'c';
pub const CREATE_BLOCK_DEVICE: u8 = b'b';
pub const COPY_FILES: u8 = b'C';
pub const WRITE_FILE: u8 = b'w';
pub const EMPTY_DIRECTORY: u8 = b'e';
pub const SET_XATTR: u8 = b't';
pub const RECURSIVE_SET_XATTR: u8 = b'T';
pub const SET_ACL: u8 = b'a';
pub const RECURSIVE_SET_ACL: u8 = b'A';
pub const SET_FCAPS: u8 = b'k';
pub const RECURSIVE_SET_FCAPS: u8 = b'K';
pub const SET_ATTRIBUTE: u8 = b'h';
pub const RECURSIVE_SET_ATTRIBUTE: u8 = b'H';
pub const IGNORE_PATH: u8 = b'x';
pub const IGNORE_DIRECTORY_PATH: u8 = b'X';
pub const REMOVE_PATH: u8 = b'r';
pub const RECURSIVE_REMOVE_PATH: u8 = b'R';
pub const RELABEL_PATH: u8 = b'z';
pub const RECURSIVE_RELABEL_PATH: u8 = b'Z';
pub const ADJUST_MODE: u8 = b'm';

pub const AGE_BY_ATIME: u32 = 1 << 0;
pub const AGE_BY_BTIME: u32 = 1 << 1;
pub const AGE_BY_CTIME: u32 = 1 << 2;
pub const AGE_BY_MTIME: u32 = 1 << 3;
pub const AGE_BY_DEFAULT_FILE: u32 = AGE_BY_ATIME | AGE_BY_BTIME | AGE_BY_CTIME | AGE_BY_MTIME;
pub const AGE_BY_DEFAULT_DIR: u32 = AGE_BY_ATIME | AGE_BY_BTIME | AGE_BY_MTIME;

pub const OPERATION_CREATE: u32 = 1 << 0;
pub const OPERATION_REMOVE: u32 = 1 << 1;
pub const OPERATION_CLEAN: u32 = 1 << 2;
pub const OPERATION_PURGE: u32 = 1 << 3;

/// `FCapsPatch`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FCapsPatch {
    pub mask: u64,
    pub set: u64,
}

/// `FCapsUpdate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FCapsUpdate {
    pub rootuid: u32,
    pub inheritable: FCapsPatch,
    pub permitted: FCapsPatch,
    pub effective: FCapsPatch,
}

/// `Item`.
#[derive(Debug, Default)]
pub struct Item {
    pub ty: u8,
    pub path: Vec<u8>,
    pub argument: Option<Vec<u8>>,
    pub binary_argument: Option<Vec<u8>>,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    pub acl: ParsedAcl,
    pub fcaps: FCapsUpdate,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub age: u64,
    pub age_by_file: u32,
    pub age_by_dir: u32,
    pub major_minor: u64,
    pub attribute_value: u32,
    pub attribute_mask: u32,
    pub uid_set: bool,
    pub gid_set: bool,
    pub mode_set: bool,
    pub uid_only_create: bool,
    pub gid_only_create: bool,
    pub mode_only_create: bool,
    pub age_set: bool,
    pub mask_perms: bool,
    pub attribute_set: bool,
    pub keep_first_level: bool,
    pub append_or_force: bool,
    pub allow_failure: bool,
    pub try_replace: bool,
    pub purge: bool,
    pub ignore_if_target_missing: bool,
    pub fcaps_set: bool,
    pub done: std::cell::Cell<u32>,
}

impl Item {
    /// `item_binary_argument()`.
    pub fn binary_argument(&self) -> Option<&[u8]> {
        self.binary_argument.as_deref().or(self.argument.as_deref())
    }

    /// `item_binary_argument_size()`.
    pub fn binary_argument_size(&self) -> usize {
        self.binary_argument().map(|a| a.len()).unwrap_or(0)
    }
}

/// `ItemArray`.
#[derive(Debug, Default)]
pub struct ItemArray {
    pub items: Vec<Item>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

/// `needs_purge()`.
pub fn needs_purge(t: u8) -> bool {
    matches!(
        t,
        CREATE_FILE
            | TRUNCATE_FILE
            | CREATE_DIRECTORY
            | TRUNCATE_DIRECTORY
            | CREATE_SUBVOLUME
            | CREATE_SUBVOLUME_INHERIT_QUOTA
            | CREATE_SUBVOLUME_NEW_QUOTA
            | CREATE_FIFO
            | CREATE_SYMLINK
            | CREATE_CHAR_DEVICE
            | CREATE_BLOCK_DEVICE
            | COPY_FILES
            | WRITE_FILE
            | EMPTY_DIRECTORY
    )
}

/// `needs_glob()`.
pub fn needs_glob(t: u8) -> bool {
    matches!(
        t,
        WRITE_FILE
            | EMPTY_DIRECTORY
            | SET_XATTR
            | RECURSIVE_SET_XATTR
            | SET_ACL
            | RECURSIVE_SET_ACL
            | SET_FCAPS
            | RECURSIVE_SET_FCAPS
            | SET_ATTRIBUTE
            | RECURSIVE_SET_ATTRIBUTE
            | IGNORE_PATH
            | IGNORE_DIRECTORY_PATH
            | REMOVE_PATH
            | RECURSIVE_REMOVE_PATH
            | RELABEL_PATH
            | RECURSIVE_RELABEL_PATH
            | ADJUST_MODE
    )
}

/// `takes_ownership()`.
pub fn takes_ownership(t: u8) -> bool {
    matches!(
        t,
        CREATE_FILE
            | TRUNCATE_FILE
            | CREATE_DIRECTORY
            | TRUNCATE_DIRECTORY
            | CREATE_SUBVOLUME
            | CREATE_SUBVOLUME_INHERIT_QUOTA
            | CREATE_SUBVOLUME_NEW_QUOTA
            | CREATE_FIFO
            | CREATE_SYMLINK
            | CREATE_CHAR_DEVICE
            | CREATE_BLOCK_DEVICE
            | COPY_FILES
            | WRITE_FILE
            | EMPTY_DIRECTORY
            | IGNORE_PATH
            | IGNORE_DIRECTORY_PATH
            | REMOVE_PATH
            | RECURSIVE_REMOVE_PATH
    )
}

/// `item_compare()`.
fn item_compare(a: &Item, b: &Item) -> std::cmp::Ordering {
    match (takes_ownership(a.ty), takes_ownership(b.ty)) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.ty.cmp(&b.ty),
    }
}

/// `item_compatible()`.
fn item_compatible(a: &Item, b: &Item) -> bool {
    if takes_ownership(a.ty) && takes_ownership(b.ty) {
        return a.binary_argument().unwrap_or_default() == b.binary_argument().unwrap_or_default()
            && a.uid_set == b.uid_set
            && a.uid == b.uid
            && a.uid_only_create == b.uid_only_create
            && a.gid_set == b.gid_set
            && a.gid == b.gid
            && a.gid_only_create == b.gid_only_create
            && a.mode_set == b.mode_set
            && a.mode == b.mode
            && a.mode_only_create == b.mode_only_create
            && a.age_set == b.age_set
            && a.age == b.age
            && a.age_by_file == b.age_by_file
            && a.age_by_dir == b.age_by_dir
            && a.mask_perms == b.mask_perms
            && a.keep_first_level == b.keep_first_level
            && a.major_minor == b.major_minor;
    }
    true
}

/// `is_duplicated_item()`.
fn is_duplicated_item(existing: &ItemArray, i: &Item) -> bool {
    for e in &existing.items {
        if item_compatible(e, i) {
            continue;
        }
        if e.ty != WRITE_FILE || !e.append_or_force || i.ty != WRITE_FILE || !i.append_or_force {
            return true;
        }
    }
    false
}

/// `ERRNO_IS_NEG_NOINFO()`.
pub fn errno_is_neg_noinfo(r: i32) -> bool {
    [libc::EUNATCH, libc::ENOMEDIUM, libc::ENOPKG, libc::ENXIO].iter().any(|&e| r == -e)
}

/// `specifier_directory()`.
fn specifier_directory(which: usize) -> Result<Option<Vec<u8>>, i32> {
    let user = args().runtime_scope == RuntimeScope::User;
    let (t, suffix): (SdPath, Option<&[u8]>) = if user {
        match which {
            0 => (SdPath::UserRuntime, None),
            1 => (SdPath::UserStatePrivate, None),
            2 => (SdPath::UserStateCache, None),
            3 => (SdPath::UserStatePrivate, Some(b"log")),
            _ => (SdPath::UserShared, None),
        }
    } else {
        match which {
            0 => (SdPath::SystemRuntime, None),
            1 => (SdPath::SystemStatePrivate, None),
            2 => (SdPath::SystemStateCache, None),
            3 => (SdPath::SystemStateLogs, None),
            _ => (SdPath::SystemShared, None),
        }
    };
    Ok(Some(sd_path_lookup(t, suffix)?))
}

/// The table in `parse_line()`.
fn specifier_table<'a>() -> Vec<Specifier<'a>> {
    let mut t = vec![
        spec(b'h', |_| specifier_user_home()),
        spec(b'C', |_| specifier_directory(2)),
        spec(b'D', |_| specifier_directory(4)),
        spec(b'L', |_| specifier_directory(3)),
        spec(b'S', |_| specifier_directory(1)),
        spec(b't', |_| specifier_directory(0)),
    ];
    t.extend(common_system_specifiers());
    t.extend(common_creds_specifiers(args().runtime_scope));
    t.extend(common_tmp_specifiers());
    t
}

thread_local! {
    static UNRESOLVABLE_NOTIFIED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `log_unresolvable_specifier()`.
fn log_unresolvable_specifier(fname: &[u8], line: u32) -> i32 {
    let notified = UNRESOLVABLE_NOTIFIED.with(|n| n.get());
    let lvl = if notified || args().root.is_some() || crate::running_in_chroot() > 0 {
        libc::LOG_DEBUG
    } else {
        libc::LOG_NOTICE
    };
    log_syntax!(
        lvl,
        Some(fname),
        line,
        0,
        "Failed to resolve specifier: ",
        if args().runtime_scope == RuntimeScope::User {
            "Required $XDG_... variable not defined"
        } else {
            "uninitialized /etc/ detected"
        },
        ", skipping."
    );
    if !notified {
        log_full!(lvl, "All rules containing unresolvable specifiers will be skipped.");
    }
    UNRESOLVABLE_NOTIFIED.with(|n| n.set(true));
    0
}

/// `should_include_path()`.
fn should_include_path(path: &[u8]) -> bool {
    let a = args();
    for prefix in &a.exclude_prefixes {
        if path_startswith(path, prefix).is_some() {
            log_debug!("Entry \"", path, "\" matches exclude prefix \"", prefix, "\", skipping.");
            return false;
        }
    }
    for prefix in &a.include_prefixes {
        if path_startswith(path, prefix).is_some() {
            log_debug!("Entry \"", path, "\" matches include prefix \"", prefix, "\".");
            return true;
        }
    }
    if a.include_prefixes.is_empty() {
        return true;
    }
    log_debug!("Entry \"", path, "\" does not match any include prefix, skipping.");
    false
}

/// `specifier_expansion_from_arg()`.
fn specifier_expansion_from_arg(table: &[Specifier], i: &mut Item) -> Result<(), i32> {
    let Some(arg) = i.argument.clone() else { return Ok(()) };
    match i.ty {
        COPY_FILES | CREATE_SYMLINK | CREATE_FILE | TRUNCATE_FILE | WRITE_FILE => {
            let unescaped = match cunescape(&arg) {
                Ok(u) => u,
                Err(l) => return Err(log_error_errno!(l, "Failed to unescape parameter to write: ", arg)),
            };
            i.argument = Some(specifier_printf(&unescaped, 4095, table, args().root.as_deref())?);
        }
        SET_XATTR | RECURSIVE_SET_XATTR => {
            for (n, v) in i.xattrs.iter_mut() {
                // C stores name and value as alternating strv entries and
                // expands each of them.
                *n = specifier_printf(n, usize::MAX, table, args().root.as_deref())?;
                *v = specifier_printf(v, usize::MAX, table, args().root.as_deref())?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `patch_var_run()`.
fn patch_var_run(fname: &[u8], line: u32, path: &mut Vec<u8>) {
    let Some(k) = path_startswith(path, b"/var/run/") else { return };
    if k.is_empty() {
        return;
    }
    let n = path_join(&[b"/run", k]);
    log_syntax!(
        libc::LOG_NOTICE,
        Some(fname),
        line,
        0,
        "Line references path below legacy directory /var/run/, updating ",
        &path[..],
        " \u{2192} ",
        n,
        "; please update the tmpfiles.d/ drop-in file accordingly."
    );
    *path = n;
}

/// `find_uid()`.
fn find_uid(user: &[u8], cache: &mut Option<HashMap<Vec<u8>, u32>>) -> Result<u32, i32> {
    if let Ok(u) = parse_uid(user) {
        return Ok(u);
    }
    let root = args().root.as_deref();
    if root.is_none() {
        return get_user_uid(user);
    }
    if user == b"root" {
        return Ok(0);
    }
    if cache.is_none() {
        *cache = Some(crate::offline::populate_cache(root, true)?);
    }
    cache.as_ref().expect("filled").get(user).copied().ok_or(-libc::ESRCH)
}

/// `find_gid()`.
fn find_gid(group: &[u8], cache: &mut Option<HashMap<Vec<u8>, u32>>) -> Result<u32, i32> {
    if let Ok(g) = parse_uid(group) {
        return Ok(g);
    }
    let root = args().root.as_deref();
    if root.is_none() {
        return get_group_gid(group);
    }
    if group == b"root" {
        return Ok(0);
    }
    if cache.is_none() {
        *cache = Some(crate::offline::populate_cache(root, false)?);
    }
    cache.as_ref().expect("filled").get(group).copied().ok_or(-libc::ESRCH)
}

/// `parse_age_by_from_arg()`.
fn parse_age_by_from_arg(s: &[u8], item: &mut Item) -> Result<(), i32> {
    const TYPES: [(u8, u32); 4] =
        [(b'a', AGE_BY_ATIME), (b'b', AGE_BY_BTIME), (b'c', AGE_BY_CTIME), (b'm', AGE_BY_MTIME)];
    if s.is_empty() {
        return Err(-libc::EINVAL);
    }
    let (mut f, mut d) = (0u32, 0u32);
    for &c in s {
        if shared::string::WHITESPACE.contains(&c) {
            continue;
        }
        match TYPES.iter().find(|(ch, _)| *ch == c || ch.to_ascii_uppercase() == c) {
            Some((ch, flag)) => {
                if *ch == c {
                    f |= flag;
                } else {
                    d |= flag;
                }
            }
            None => return Err(-libc::EINVAL),
        }
    }
    if f == 0 && d == 0 {
        return Err(-libc::EINVAL);
    }
    item.age_by_file = if f > 0 { f } else { AGE_BY_DEFAULT_FILE };
    item.age_by_dir = if d > 0 { d } else { AGE_BY_DEFAULT_DIR };
    Ok(())
}

/// `parse_xattrs_from_arg()`.
fn parse_xattrs_from_arg(i: &mut Item) {
    let arg = i.argument.clone().unwrap_or_default();
    let mut p = Some(&arg[..]);
    loop {
        let before = p;
        let xattr = match extract_first_word(&mut p, None, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE) {
            Err(r) => {
                log_warning_errno!(
                    r,
                    "Failed to parse extended attribute '",
                    before.unwrap_or_default(),
                    "', ignoring: ",
                    strerror(r)
                );
                break;
            }
            Ok(None) => break,
            Ok(Some(x)) => x,
        };
        let Ok((name, value)) = split_pair(&xattr, b"=") else {
            let r = -libc::EINVAL;
            log_warning_errno!(r, "Failed to parse extended attribute, ignoring: ", xattr);
            continue;
        };
        if name.is_empty() || value.is_empty() {
            log_warning!("Malformed extended attribute found, ignoring: ", xattr);
            continue;
        }
        i.xattrs.push((name.to_vec(), value.to_vec()));
    }
}

/// `parse_acls_from_arg()`.
fn parse_acls_from_arg(item: &mut Item) {
    let arg = item.argument.clone().unwrap_or_default();
    match shared::sys_acl::parse_acl(&arg, !item.append_or_force) {
        Ok(a) => item.acl = a,
        Err(r) => {
            let lvl = if args().graceful && [-libc::EINVAL, -libc::ENOENT, -libc::ESRCH].contains(&r) {
                libc::LOG_DEBUG
            } else {
                libc::LOG_WARNING
            };
            log_full_errno!(lvl, r, "Failed to parse ACL \"", arg, "\", ignoring: ", strerror(r));
        }
    }
}

/// `parse_caps_from_arg()`.
fn parse_caps_from_arg(item: &mut Item) {
    let arg = item.argument.clone().unwrap_or_default();
    match crate::fcaps::capability_vfs_from_string(&arg) {
        Ok(f) => {
            item.fcaps_set = true;
            item.fcaps = f;
        }
        Err(r) => {
            log_full_errno!(
                if args().graceful { libc::LOG_DEBUG } else { libc::LOG_WARNING },
                r,
                "Failed to parse capabilities \"",
                arg,
                "\", ignoring: ",
                strerror(r)
            );
        }
    }
}

/// `parse_attribute_from_arg()`.
fn parse_attribute_from_arg(item: &mut Item) -> Result<(), i32> {
    use shared::chattr::*;
    const ATTRS: [(u8, u32); 15] = [
        (b'A', FS_NOATIME_FL),
        (b'S', FS_SYNC_FL),
        (b'D', FS_DIRSYNC_FL),
        (b'a', FS_APPEND_FL),
        (b'c', FS_COMPR_FL),
        (b'd', FS_NODUMP_FL),
        (b'e', FS_EXTENT_FL),
        (b'i', FS_IMMUTABLE_FL),
        (b'j', FS_JOURNAL_DATA_FL),
        (b's', FS_SECRM_FL),
        (b'u', FS_UNRM_FL),
        (b't', FS_NOTAIL_FL),
        (b'T', FS_TOPDIR_FL),
        (b'C', FS_NOCOW_FL),
        (b'P', FS_PROJINHERIT_FL),
    ];
    #[derive(PartialEq)]
    enum M {
        Add,
        Del,
        Set,
    }
    let arg = item.argument.clone().unwrap_or_default();
    let mut p = &arg[..];
    let mut mode = M::Add;
    match p.first() {
        Some(b'+') => p = &p[1..],
        Some(b'-') => {
            mode = M::Del;
            p = &p[1..];
        }
        Some(b'=') => {
            mode = M::Set;
            p = &p[1..];
        }
        _ => {}
    }
    if p.is_empty() && mode != M::Set {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Setting file attribute on '",
            item.path,
            "' needs an attribute specification."
        ));
    }
    let (mut value, mut mask) = (0u32, 0u32);
    for &c in p {
        let Some((_, v)) = ATTRS.iter().find(|(ch, _)| *ch == c) else {
            return Err(log_error_errno!(
                synthetic(libc::EINVAL),
                "Unknown file attribute '",
                [c],
                "' on '",
                item.path,
                "'."
            ));
        };
        if mode == M::Add || mode == M::Set {
            value |= v;
        } else {
            value &= !v;
        }
        mask |= v;
    }
    if mode == M::Set {
        mask |= CHATTR_ALL_FL;
    }
    item.attribute_mask = mask;
    item.attribute_value = value;
    item.attribute_set = true;
    Ok(())
}

/// `empty_or_dash()`.
fn empty_or_dash(s: Option<&[u8]>) -> bool {
    matches!(s, None | Some(b"") | Some(b"-"))
}

/// `parse_line(fname, line, buffer, &invalid_config, context)`.
pub fn parse_line(c: &mut Context, fname: &[u8], line: u32, buffer: &[u8], invalid_config: &mut bool) -> i32 {
    let mut i = Item { age_by_file: AGE_BY_DEFAULT_FILE, age_by_dir: AGE_BY_DEFAULT_DIR, ..Default::default() };
    let table = specifier_table();

    let mut p = Some(buffer);
    let words = match extract_many_words(&mut p, None, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE, 6) {
        Ok(w) => w,
        Err(r) => {
            if r == -libc::EINVAL || r == -libc::EBADSLT {
                *invalid_config = true;
            }
            return log_syntax!(libc::LOG_ERR, Some(fname), line, r, "Failed to parse line: ", strerror(r));
        }
    };
    if words.len() < 2 {
        *invalid_config = true;
        return log_syntax!(libc::LOG_ERR, Some(fname), line, synthetic(libc::EBADMSG), "Syntax error.");
    }
    let w = |n: usize| words.get(n).map(|v| &v[..]);
    let action = &words[0][..];
    let path = &words[1][..];
    let (mode, user, group, age) = (w(2), w(3), w(4), w(5));

    if !empty_or_dash(p) {
        i.argument = p.map(|x| x.to_vec());
    }
    if action.is_empty() {
        *invalid_config = true;
        return log_syntax!(
            libc::LOG_ERR,
            Some(fname),
            line,
            synthetic(libc::EBADMSG),
            "Command too short '",
            action,
            "'."
        );
    }

    let (mut boot, mut append_or_force, mut allow_failure, mut try_replace) = (false, false, false, false);
    let (mut unbase64, mut from_cred, mut purge, mut ignore_if_target_missing) = (false, false, false, false);
    for &ch in &action[1..] {
        match ch {
            b'!' if !boot => boot = true,
            b'+' if !append_or_force => append_or_force = true,
            b'-' if !allow_failure => allow_failure = true,
            b'=' if !try_replace => try_replace = true,
            b'~' if !unbase64 => unbase64 = true,
            b'^' if !from_cred => from_cred = true,
            b'$' if !purge => purge = true,
            b'?' if !ignore_if_target_missing => ignore_if_target_missing = true,
            _ => {
                *invalid_config = true;
                return log_syntax!(
                    libc::LOG_ERR,
                    Some(fname),
                    line,
                    synthetic(libc::EBADMSG),
                    "Unknown modifiers in command: ",
                    action
                );
            }
        }
    }

    if boot && !args().boot {
        log_syntax!(
            libc::LOG_DEBUG,
            Some(fname),
            line,
            0,
            "Ignoring entry ",
            action,
            " \"",
            path,
            "\" because --boot is not specified."
        );
        return 0;
    }

    i.ty = action[0];
    i.append_or_force = append_or_force;
    i.allow_failure = allow_failure;
    i.try_replace = try_replace;
    i.purge = purge;
    i.ignore_if_target_missing = ignore_if_target_missing;

    i.path = match specifier_printf(path, 4095, &table, args().root.as_deref()) {
        Ok(p) => p,
        Err(r) if errno_is_neg_noinfo(r) => return log_unresolvable_specifier(fname, line),
        Err(r) => {
            if r == -libc::EINVAL || r == -libc::EBADSLT {
                *invalid_config = true;
            }
            return log_syntax!(
                libc::LOG_ERR,
                Some(fname),
                line,
                r,
                "Failed to replace specifiers in '",
                path,
                "': ",
                strerror(r)
            );
        }
    };

    patch_var_run(fname, line, &mut i.path);

    if !path_is_absolute(&i.path) {
        *invalid_config = true;
        return log_syntax!(
            libc::LOG_ERR,
            Some(fname),
            line,
            synthetic(libc::EBADMSG),
            "Path '",
            i.path,
            "' not absolute."
        );
    }
    i.path = path_simplify(&i.path);

    macro_rules! bad {
        ($($e:expr),*) => {{
            *invalid_config = true;
            return log_syntax!(libc::LOG_ERR, Some(fname), line, synthetic(libc::EBADMSG), $($e),*);
        }};
    }

    match i.ty {
        CREATE_DIRECTORY
        | CREATE_SUBVOLUME
        | CREATE_SUBVOLUME_INHERIT_QUOTA
        | CREATE_SUBVOLUME_NEW_QUOTA
        | EMPTY_DIRECTORY
        | TRUNCATE_DIRECTORY
        | CREATE_FIFO
        | IGNORE_PATH
        | IGNORE_DIRECTORY_PATH
        | REMOVE_PATH
        | RECURSIVE_REMOVE_PATH
        | ADJUST_MODE
        | RELABEL_PATH
        | RECURSIVE_RELABEL_PATH => {
            if i.argument.is_some() {
                bad!([i.ty], " lines don't take argument fields.");
            }
        }
        CREATE_FILE | TRUNCATE_FILE => {}
        CREATE_SYMLINK => {
            if unbase64 {
                bad!("base64 decoding not supported for symlink targets.");
            }
        }
        WRITE_FILE => {
            if i.argument.is_none() {
                bad!("Write file requires argument.");
            }
        }
        COPY_FILES => {
            if unbase64 {
                bad!("base64 decoding not supported for copy sources.");
            }
        }
        CREATE_CHAR_DEVICE | CREATE_BLOCK_DEVICE => {
            if unbase64 {
                bad!("base64 decoding not supported for device node creation.");
            }
            let Some(arg) = i.argument.clone() else {
                bad!("Device file requires argument.");
            };
            match parse_devnum(&arg) {
                Ok(d) => i.major_minor = d,
                Err(r) => {
                    *invalid_config = true;
                    return log_syntax!(
                        libc::LOG_ERR,
                        Some(fname),
                        line,
                        r,
                        "Can't parse device file major/minor '",
                        arg,
                        "'."
                    );
                }
            }
        }
        SET_XATTR | RECURSIVE_SET_XATTR => {
            if unbase64 {
                bad!("base64 decoding not supported for extended attributes.");
            }
            if i.argument.is_none() {
                bad!("Set extended attribute requires argument.");
            }
            parse_xattrs_from_arg(&mut i);
        }
        SET_ACL | RECURSIVE_SET_ACL => {
            if unbase64 {
                bad!("base64 decoding not supported for ACLs.");
            }
            if i.argument.is_none() {
                bad!("Set ACLs requires argument.");
            }
            parse_acls_from_arg(&mut i);
        }
        SET_FCAPS | RECURSIVE_SET_FCAPS => {
            if unbase64 {
                bad!("base64 decoding not supported for capabilities.");
            }
            if i.argument.is_none() {
                bad!("Set capabilities requires argument.");
            }
            parse_caps_from_arg(&mut i);
        }
        SET_ATTRIBUTE | RECURSIVE_SET_ATTRIBUTE => {
            if unbase64 {
                bad!("base64 decoding not supported for file attributes.");
            }
            if i.argument.is_none() {
                bad!("Set file attribute requires argument.");
            }
            if let Err(r) = parse_attribute_from_arg(&mut i) {
                if r == -libc::EINVAL || r == -libc::EBADSLT {
                    *invalid_config = true;
                }
                return r;
            }
        }
        _ => bad!("Unknown command type '", [i.ty], "'."),
    }

    if i.purge && !needs_purge(i.ty) {
        bad!("Purge flag '$' combined with line type '", [i.ty], "' which does not support purging.");
    }
    if i.ignore_if_target_missing && i.ty != CREATE_SYMLINK {
        bad!("Modifier '?' combined with line type '", [i.ty], "' which does not support this modifier.");
    }

    if !should_include_path(&i.path) {
        return 0;
    }

    if !unbase64 {
        match specifier_expansion_from_arg(&table, &mut i) {
            Ok(()) => {}
            Err(r) if errno_is_neg_noinfo(r) => return log_unresolvable_specifier(fname, line),
            Err(r) => {
                if r == -libc::EINVAL || r == -libc::EBADSLT {
                    *invalid_config = true;
                }
                return log_syntax!(
                    libc::LOG_ERR,
                    Some(fname),
                    line,
                    r,
                    "Failed to substitute specifiers in argument: ",
                    strerror(r)
                );
            }
        }
    }

    match i.ty {
        CREATE_SYMLINK => {
            if i.argument.is_none() {
                i.argument = Some(path_join(&[b"/usr/share/factory", &i.path]));
            }
        }
        COPY_FILES => {
            match &i.argument {
                None => i.argument = Some(path_join(&[b"/usr/share/factory", &i.path])),
                Some(a) if !path_is_absolute(a) => {
                    let a = a.clone();
                    bad!("Source path '", a, "' is not absolute.");
                }
                Some(_) => {}
            }
            let root = args().root.clone();
            if !empty_or_root(root.as_deref()) {
                i.argument =
                    Some(path_join(&[root.as_deref().unwrap_or_default(), i.argument.as_deref().unwrap_or_default()]));
            }
            let a = path_simplify(i.argument.as_deref().unwrap_or_default());
            i.argument = Some(a.clone());
            if let Err(e) = shared::sys::fstatat(libc::AT_FDCWD, &a, libc::AT_SYMLINK_NOFOLLOW)
                && e == -libc::ENOENT
            {
                log_syntax!(
                    libc::LOG_DEBUG,
                    Some(fname),
                    line,
                    0,
                    "Copy source path '",
                    a,
                    "' does not exist, skipping line."
                );
                return 0;
            }
        }
        _ => {}
    }

    if from_cred {
        let Some(name) = i.argument.clone() else {
            return log_syntax!(
                libc::LOG_ERR,
                Some(fname),
                line,
                synthetic(libc::EINVAL),
                "Reading from credential requested, but no credential name specified."
            );
        };
        if !shared::creds::credential_name_valid(&name) {
            return log_syntax!(
                libc::LOG_ERR,
                Some(fname),
                line,
                synthetic(libc::EINVAL),
                "Credential name not valid: ",
                name
            );
        }
        match shared::creds::read_credential(&name) {
            Err(r) if r == -libc::ENXIO || r == -libc::ENOENT => {
                log_syntax!(
                    libc::LOG_DEBUG,
                    Some(fname),
                    line,
                    0,
                    "Credential '",
                    name,
                    "' not specified, skipping line."
                );
                return 0;
            }
            Err(r) => return log_error_errno!(r, "Failed to read credential '", name, "': ", strerror(r)),
            Ok(d) => i.binary_argument = Some(d),
        }
    }

    if unbase64 && let Some(b) = i.binary_argument() {
        match shared::hexdecoct::unbase64mem(b) {
            Ok(d) => i.binary_argument = Some(d),
            Err(r) => {
                return log_syntax!(
                    libc::LOG_ERR,
                    Some(fname),
                    line,
                    r,
                    "Failed to base64 decode specified argument '",
                    i.argument.as_deref().unwrap_or(b"(null)"),
                    "': ",
                    strerror(r)
                );
            }
        }
    }

    let root = args().root.clone();
    if !empty_or_root(root.as_deref()) {
        i.path = path_join(&[root.as_deref().unwrap_or_default(), &i.path]);
    }

    let mut missing_user_or_group = false;
    if !empty_or_dash(user) {
        let user = user.unwrap_or_default();
        let u = match user.strip_prefix(b":") {
            Some(u) => {
                i.uid_only_create = true;
                u
            }
            None => user,
        };
        match find_uid(u, &mut c.uid_cache) {
            Err(r) if r == -libc::ESRCH && args().graceful => {
                log_syntax!(
                    libc::LOG_DEBUG,
                    Some(fname),
                    line,
                    r,
                    &i.path[..],
                    ": user '",
                    u,
                    "' not found, not adjusting ownership."
                );
                missing_user_or_group = true;
            }
            Err(r) => {
                *invalid_config = true;
                return log_syntax!(
                    libc::LOG_ERR,
                    Some(fname),
                    line,
                    r,
                    "Failed to resolve user '",
                    u,
                    "': ",
                    strerror_account(r, "user")
                );
            }
            Ok(uid) => {
                i.uid = uid;
                i.uid_set = true;
            }
        }
    }
    if !empty_or_dash(group) {
        let group = group.unwrap_or_default();
        let g = match group.strip_prefix(b":") {
            Some(g) => {
                i.gid_only_create = true;
                g
            }
            None => group,
        };
        match find_gid(g, &mut c.gid_cache) {
            Err(r) if r == -libc::ESRCH && args().graceful => {
                log_syntax!(
                    libc::LOG_DEBUG,
                    Some(fname),
                    line,
                    r,
                    &i.path[..],
                    ": group '",
                    g,
                    "' not found, not adjusting ownership."
                );
                missing_user_or_group = true;
            }
            Err(r) => {
                *invalid_config = true;
                return log_syntax!(
                    libc::LOG_ERR,
                    Some(fname),
                    line,
                    r,
                    "Failed to resolve group '",
                    g,
                    "': ",
                    strerror_account(r, "group")
                );
            }
            Ok(gid) => {
                i.gid = gid;
                i.gid_set = true;
            }
        }
    }

    if !empty_or_dash(mode) {
        let mode = mode.unwrap_or_default();
        let mut mm = mode;
        loop {
            match mm.first() {
                Some(b'~') => i.mask_perms = true,
                Some(b':') => i.mode_only_create = true,
                _ => break,
            }
            mm = &mm[1..];
        }
        match parse_mode(mm) {
            Ok(m) => {
                i.mode = m;
                i.mode_set = true;
            }
            Err(r) => {
                *invalid_config = true;
                return log_syntax!(libc::LOG_ERR, Some(fname), line, r, "Invalid mode '", mode, "'.");
            }
        }
    } else {
        i.mode = if matches!(
            i.ty,
            CREATE_DIRECTORY
                | TRUNCATE_DIRECTORY
                | CREATE_SUBVOLUME
                | CREATE_SUBVOLUME_INHERIT_QUOTA
                | CREATE_SUBVOLUME_NEW_QUOTA
        ) {
            0o755
        } else {
            0o644
        };
    }

    if missing_user_or_group && i.mode & !0o777 != 0 {
        let adjusted = i.mode & 0o777;
        log_syntax!(
            libc::LOG_INFO,
            Some(fname),
            line,
            0,
            "Changing mode 0",
            format!("{:o}", i.mode),
            " to 0",
            format!("{adjusted:o}"),
            " because of changed ownership."
        );
        i.mode = adjusted;
    }

    if !empty_or_dash(age) {
        let age = age.unwrap_or_default();
        let mut a = age;
        if a.first() == Some(&b'~') {
            if i.ty == REMOVE_PATH {
                bad!("Age modifier '~' is not supported for ", [i.ty], " lines.");
            }
            i.keep_first_level = true;
            a = &a[1..];
        }
        if let Ok((age_by, seconds)) = split_pair(a, b":") {
            if let Err(r) = parse_age_by_from_arg(age_by, &mut i) {
                *invalid_config = true;
                return log_syntax!(libc::LOG_ERR, Some(fname), line, r, "Invalid age-by '", age_by, "'.");
            }
            a = seconds;
        }
        match shared::time::parse_sec(a) {
            Ok(s) => {
                i.age = s;
                i.age_set = true;
            }
            Err(r) => {
                *invalid_config = true;
                return log_syntax!(libc::LOG_ERR, Some(fname), line, r, "Invalid age '", a, "'.");
            }
        }
    }

    let glob = needs_glob(i.ty);
    let path = i.path.clone();
    let existing = if glob { c.globs.get(&path) } else { c.items.get(&path) }.copied();
    let idx = match existing {
        Some(idx) => {
            if is_duplicated_item(&c.arrays[idx], &i) {
                log_syntax!(
                    libc::LOG_NOTICE,
                    Some(fname),
                    line,
                    0,
                    "Duplicate line for path \"",
                    path,
                    "\", ignoring."
                );
                return 0;
            }
            idx
        }
        None => {
            c.arrays.push(ItemArray::default());
            let idx = c.arrays.len() - 1;
            if glob {
                c.globs.insert(path.clone(), idx);
                c.globs_order.push(idx);
            } else {
                c.items.insert(path.clone(), idx);
                c.items_order.push(idx);
            }
            idx
        }
    };
    let a = &mut c.arrays[idx];
    a.items.push(i);
    // typesafe_qsort() is not stable, but item_compare() only ties for
    // items of the same type, which is_duplicated_item() lets through only
    // for w+ lines, whose order is then kept.
    a.items.sort_by(item_compare);
    0
}
