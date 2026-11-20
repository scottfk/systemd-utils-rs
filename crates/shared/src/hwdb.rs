// SPDX-License-Identifier: LGPL-2.1-or-later
//! `hwdb-util.c` (compiling `hwdb.d` into `hwdb.bin`) and `sd-hwdb.c`
//! (looking up modaliases in it).

use crate::conf_files::{CONF_FILES_FILTER_MASKED, CONF_FILES_REGULAR, CONF_FILES_WARN, conf_files_list_strv_full};
use crate::errno::{ret_gather, strerror, synthetic};
use crate::fd::{AT_FDCWD, proc_fd_path};
use crate::fileio::{LONG_LINE_MAX, read_line_full};
use crate::path::{path_extract_directory, path_join, path_make_absolute_cwd, path_simplify};
use crate::strbuf::Strbuf;
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_debug_errno, log_error_errno, log_info, log_syntax, printo};

/// `conf_file_dirs`.
const CONF_FILE_DIRS: [&[u8]; 2] = [b"/etc/udev/hwdb.d", b"/usr/lib/udev/hwdb.d"];

/// `HWDB_BIN_PATHS`.
pub const HWDB_BIN_PATHS: [&[u8]; 4] = [
    b"/etc/systemd/hwdb/hwdb.bin",
    b"/etc/udev/hwdb.bin",
    b"/usr/lib/systemd/hwdb/hwdb.bin",
    b"/usr/lib/udev/hwdb.bin",
];

const HWDB_SIG: &[u8; 8] = b"KSLPHHRH";

// On-disk sizes (the `_packed_` structs of hwdb-internal.h).
const HEADER_SIZE: u64 = 80;
const NODE_SIZE: u64 = 24;
const CHILD_ENTRY_SIZE: u64 = 16;
const VALUE_ENTRY_SIZE: u64 = 16;
const VALUE_ENTRY2_SIZE: u64 = 32;

// In-memory sizes C reports in its debug output (x86_64).
const MEM_NODE_SIZE: usize = 40;
const MEM_CHILD_ENTRY_SIZE: usize = 16;
const MEM_VALUE_ENTRY_SIZE: usize = 32;

/// `struct trie_value_entry`.
#[derive(Debug, Clone, Copy)]
struct ValueEntry {
    key_off: usize,
    value_off: usize,
    filename_off: usize,
    line_number: u32,
    file_priority: u16,
}

/// `struct trie_node`.
#[derive(Debug, Default)]
struct TrieNode {
    prefix_off: usize,
    /// Sorted by the byte.
    children: Vec<(u8, usize)>,
    /// Sorted by key.
    values: Vec<ValueEntry>,
}

/// `struct trie`: the nodes live in an arena, the root is node 0.
#[derive(Debug)]
struct Trie {
    nodes: Vec<TrieNode>,
    strings: Strbuf,
    nodes_count: usize,
    children_count: usize,
    values_count: usize,
}

/// The NUL-terminated string at `off`.
fn cstr_at(buf: &[u8], off: usize) -> &[u8] {
    let s = &buf[off..];
    &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]
}

/// `s[i]`, with C's terminating NUL past the end.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

impl Trie {
    /// `node_add_child()`.
    fn add_child(&mut self, node: usize, child: usize, c: u8) {
        self.children_count += 1;
        let ch = &mut self.nodes[node].children;
        let pos = ch.partition_point(|&(k, _)| k < c);
        ch.insert(pos, (c, child));
        self.nodes_count += 1;
    }

    /// `trie_node_add_value()`.
    fn add_value(
        &mut self,
        node: usize,
        key: &[u8],
        value: &[u8],
        filename: &[u8],
        file_priority: u16,
        line_number: u32,
        compat: bool,
    ) {
        let k = self.strings.add(key);
        let v = self.strings.add(value);
        let fname = if compat { 0 } else { self.strings.add(filename) };
        let buf = &self.strings.buf;
        let vals = &mut self.nodes[node].values;
        match vals.binary_search_by(|e| cstr_at(buf, e.key_off).cmp(cstr_at(buf, k))) {
            Ok(i) => {
                // The same property for the same match: files are read in
                // order, so the later one replaces the earlier.
                let e = &mut vals[i];
                e.value_off = v;
                e.filename_off = fname;
                e.file_priority = file_priority;
                e.line_number = line_number;
            }
            Err(i) => {
                vals.insert(
                    i,
                    ValueEntry { key_off: k, value_off: v, filename_off: fname, line_number, file_priority },
                );
                self.values_count += 1;
            }
        }
    }

    /// `trie_insert()`.
    fn insert(
        &mut self,
        search: &[u8],
        key: &[u8],
        value: &[u8],
        filename: &[u8],
        file_priority: u16,
        line_number: u32,
        compat: bool,
    ) {
        let mut node = 0usize;
        let mut i = 0usize;
        loop {
            let mut p = 0usize;
            loop {
                let c = self.strings.buf[self.nodes[node].prefix_off + p];
                if c == 0 {
                    break;
                }
                if c == at(search, i + p) {
                    p += 1;
                    continue;
                }
                // Split the node: its values and children move to a new child.
                let old = std::mem::take(&mut self.nodes[node]);
                let prefix: Vec<u8> = self.strings.buf[old.prefix_off..old.prefix_off + p].to_vec();
                self.nodes.push(TrieNode {
                    prefix_off: old.prefix_off + p + 1,
                    children: old.children,
                    values: old.values,
                });
                let new_child = self.nodes.len() - 1;
                let off = self.strings.add(&prefix);
                self.nodes[node] = TrieNode { prefix_off: off, ..Default::default() };
                self.add_child(node, new_child, c);
                break;
            }
            i += p;

            let c = at(search, i);
            if c == 0 {
                return self.add_value(node, key, value, filename, file_priority, line_number, compat);
            }
            let child = self.nodes[node]
                .children
                .binary_search_by_key(&c, |&(k, _)| k)
                .ok()
                .map(|k| self.nodes[node].children[k].1);
            match child {
                Some(ch) => node = ch,
                None => {
                    let off = self.strings.add(&search[(i + 1).min(search.len())..]);
                    self.nodes.push(TrieNode { prefix_off: off, ..Default::default() });
                    let new_child = self.nodes.len() - 1;
                    self.add_child(node, new_child, c);
                    return self.add_value(new_child, key, value, filename, file_priority, line_number, compat);
                }
            }
            i += 1;
        }
    }
}

/// The counts `trie_store_nodes()` keeps.
#[derive(Default)]
struct StoreCounts {
    strings_off: u64,
    nodes_count: u64,
    children_count: u64,
    values_count: u64,
}

/// `trie_store_nodes_size()`.
fn store_nodes_size(t: &Trie, node: usize, compat: bool, out: &mut StoreCounts) {
    let n = &t.nodes[node];
    for &(_, child) in &n.children {
        store_nodes_size(t, child, compat, out);
    }
    out.strings_off += NODE_SIZE;
    out.strings_off += CHILD_ENTRY_SIZE * n.children.len() as u64;
    out.strings_off += (if compat { VALUE_ENTRY_SIZE } else { VALUE_ENTRY2_SIZE }) * n.values.len() as u64;
}

/// `trie_store_nodes()`: post-order; returns the node's offset.
fn store_nodes(t: &Trie, node: usize, compat: bool, file: &mut Vec<u8>, cnt: &mut StoreCounts) -> u64 {
    let n = &t.nodes[node];
    let mut children: Vec<(u8, u64)> = Vec::with_capacity(n.children.len());
    for &(c, child) in &n.children {
        children.push((c, store_nodes(t, child, compat, file, cnt)));
    }
    let node_off = file.len() as u64;
    file.extend((cnt.strings_off + n.prefix_off as u64).to_le_bytes());
    file.push(n.children.len() as u8);
    file.extend([0u8; 7]);
    file.extend((n.values.len() as u64).to_le_bytes());
    cnt.nodes_count += 1;
    for (c, off) in &children {
        file.push(*c);
        file.extend([0u8; 7]);
        file.extend(off.to_le_bytes());
    }
    cnt.children_count += children.len() as u64;
    for v in &n.values {
        file.extend((cnt.strings_off + v.key_off as u64).to_le_bytes());
        file.extend((cnt.strings_off + v.value_off as u64).to_le_bytes());
        if !compat {
            file.extend((cnt.strings_off + v.filename_off as u64).to_le_bytes());
            file.extend(v.line_number.to_le_bytes());
            file.extend(v.file_priority.to_le_bytes());
            file.extend([0u8; 2]);
        }
    }
    cnt.values_count += n.values.len() as u64;
    node_off
}

/// `fopen_tmpfile_linkable()` + `flink_tmpfile(..., LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC)`
/// with the data, made 0444.
fn write_linkable(filename: &[u8], data: &[u8]) -> Result<(), i32> {
    let dir = path_extract_directory(filename)?;
    let flags = libc::O_WRONLY | libc::O_CLOEXEC;
    let (fd, tmp) = match sys::open(&dir, libc::O_TMPFILE | flags, 0o640) {
        Ok(fd) => (OwnedFd::new(fd), None),
        Err(e) => {
            if !crate::chattr::is_neg_not_supported(e) {
                log_debug_errno!(e, "Failed to use O_TMPFILE for ", filename, ": ", strerror(e));
            }
            let t = crate::fs::tempfn_random(filename, None)?;
            let fd = sys::open(&t, libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NOCTTY | flags, 0o640)?;
            (OwnedFd::new(fd), Some(t))
        }
    };
    let res = (|| {
        sys::fchmod(fd.raw(), 0o444)?;
        sys::write_all(fd.raw(), data)?;
        sys::fsync(fd.raw())?;
        match &tmp {
            Some(t) => sys::renameat(AT_FDCWD, t, AT_FDCWD, filename)?,
            None => linkat_replace_fd(fd.raw(), filename)?,
        }
        // fsync_full(): the file and its directory.
        sys::fsync(fd.raw())?;
        let dfd = OwnedFd::new(sys::open(&dir, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?);
        sys::fsync(dfd.raw())
    })();
    if res.is_err()
        && let Some(t) = &tmp
    {
        let _ = sys::unlink(t);
    }
    res
}

/// `link_fd(fd, AT_FDCWD, newpath)`.
fn link_fd(fd: i32, newpath: &[u8]) -> Result<(), i32> {
    match sys::linkat(fd, b"", AT_FDCWD, newpath, libc::AT_EMPTY_PATH) {
        Err(e) if e == -libc::ENOENT => {
            match sys::linkat(AT_FDCWD, &proc_fd_path(fd), AT_FDCWD, newpath, libc::AT_SYMLINK_FOLLOW) {
                Err(e) if e == -libc::ENOENT && !crate::fs::proc_mounted() => Err(-libc::ENOSYS),
                r => r,
            }
        }
        r => r,
    }
}

/// `linkat_replace(fd, NULL, AT_FDCWD, newpath)`.
fn linkat_replace_fd(fd: i32, newpath: &[u8]) -> Result<(), i32> {
    match link_fd(fd, newpath) {
        Ok(()) => return Ok(()),
        Err(e) if e != -libc::EEXIST => return Err(e),
        Err(_) => {}
    }
    let old = sys::fstat(fd)?;
    if old.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Err(-libc::EISDIR);
    }
    let new = sys::fstatat(AT_FDCWD, newpath, libc::AT_SYMLINK_NOFOLLOW)?;
    if new.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Err(-libc::EEXIST);
    }
    if crate::stat_util::stat_inode_same(&old, &new) {
        return Ok(());
    }
    let tmp = crate::fs::tempfn_random(newpath, None)?;
    link_fd(fd, &tmp)?;
    if let Err(e) = sys::renameat(AT_FDCWD, &tmp, AT_FDCWD, newpath) {
        let _ = sys::unlink(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `trie_store()`.
fn trie_store(t: &Trie, filename: &[u8], compat: bool) -> Result<(), i32> {
    let mut cnt = StoreCounts { strings_off: HEADER_SIZE, ..Default::default() };
    store_nodes_size(t, 0, compat, &mut cnt);

    let mut file = vec![0u8; HEADER_SIZE as usize];
    let root_off = store_nodes(t, 0, compat, &mut file, &mut cnt);
    let nodes_len = file.len() as u64 - HEADER_SIZE;
    file.extend_from_slice(&t.strings.buf);
    let size = file.len() as u64;

    let value_size = if compat { VALUE_ENTRY_SIZE } else { VALUE_ENTRY2_SIZE };
    let mut h = Vec::with_capacity(HEADER_SIZE as usize);
    h.extend_from_slice(HWDB_SIG);
    for v in [
        crate::build::PROJECT_VERSION as u64,
        size,
        HEADER_SIZE,
        NODE_SIZE,
        CHILD_ENTRY_SIZE,
        value_size,
        root_off,
        nodes_len,
        t.strings.len() as u64,
    ] {
        h.extend(v.to_le_bytes());
    }
    file[..HEADER_SIZE as usize].copy_from_slice(&h);

    write_linkable(filename, &file)?;

    log_debug!("=== trie on-disk ===");
    log_debug!("filename:         ", filename);
    log_debug!("size:             ", format!("{size:8}"), " bytes");
    log_debug!("header:           ", format!("{HEADER_SIZE:8}"), " bytes");
    log_debug!(
        "nodes:            ",
        format!("{:8}", cnt.nodes_count * NODE_SIZE),
        " bytes (",
        format!("{:8}", cnt.nodes_count),
        ")"
    );
    log_debug!(
        "child pointers:   ",
        format!("{:8}", cnt.children_count * CHILD_ENTRY_SIZE),
        " bytes (",
        format!("{:8}", cnt.children_count),
        ")"
    );
    log_debug!(
        "value pointers:   ",
        format!("{:8}", cnt.values_count * value_size),
        " bytes (",
        format!("{:8}", cnt.values_count),
        ")"
    );
    log_debug!("string store:     ", format!("{:8}", t.strings.len()), " bytes");
    log_debug!("strings start:    ", format!("{:8}", cnt.strings_off));
    Ok(())
}

fn isblank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `insert_data()`: line starts with a space.
fn insert_data(
    t: &mut Trie,
    matches: &[Vec<u8>],
    line: &[u8],
    filename: &[u8],
    file_priority: u16,
    line_number: u32,
    compat: bool,
) {
    let Some(eq) = line.iter().position(|&b| b == b'=') else {
        log_syntax!(
            libc::LOG_WARNING,
            Some(filename),
            line_number,
            synthetic(libc::EINVAL),
            "Key-value pair expected but got \"",
            line,
            "\", ignoring."
        );
        return;
    };
    let value = &line[eq + 1..];
    let mut key = &line[..eq];
    // Replace multiple leading spaces by a single one.
    while key.len() >= 2 && isblank(key[0]) && isblank(key[1]) {
        key = &key[1..];
    }
    if key.len() <= 1 {
        log_syntax!(
            libc::LOG_WARNING,
            Some(filename),
            line_number,
            synthetic(libc::EINVAL),
            "Empty key in \"",
            key,
            "=",
            value,
            "\", ignoring."
        );
        return;
    }
    for m in matches {
        t.insert(m, key, value, filename, file_priority, line_number, compat);
    }
}

/// `import_file()`: 0, or a read error.
fn import_file(t: &mut Trie, fd: i32, filename: &[u8], file_priority: u16, compat: bool) -> i32 {
    #[derive(PartialEq)]
    enum S {
        None,
        Match,
        Data,
    }
    let mut f = match crate::fileio::fopen_re(&proc_fd_path(fd)) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let mut state = S::None;
    let mut matches: Vec<Vec<u8>> = Vec::new();
    let mut line_number = 0u32;
    let r;
    loop {
        let mut line = match read_line_full(&mut f, LONG_LINE_MAX, false) {
            Err(e) => return e,
            Ok((0, _)) => {
                r = 0;
                break;
            }
            Ok((_, l)) => l,
        };
        line_number += 1;
        if line.first() == Some(&b'#') {
            continue;
        }
        // C works on the NUL-terminated line: cut at a NUL, then at '#'.
        if let Some(z) = line.iter().position(|&b| b == 0) {
            line.truncate(z);
        }
        // QUIRK: as in C, a '#' anywhere starts a comment, also in a value.
        if let Some(h) = line.iter().position(|&b| b == b'#') {
            line.truncate(h);
        }
        while line.last().is_some_and(|&c| isspace(c)) {
            line.pop();
        }
        let len = line.len();
        match state {
            S::None => {
                if len == 0 {
                    continue;
                }
                if line[0] == b' ' {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(filename),
                        line_number,
                        0,
                        "Match expected but got indented property \"",
                        line,
                        "\", ignoring line."
                    );
                    continue;
                }
                state = S::Match;
                matches.push(line);
            }
            S::Match => {
                if len == 0 {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(filename),
                        line_number,
                        0,
                        "Property expected, ignoring record with no properties."
                    );
                    state = S::None;
                    matches.clear();
                    continue;
                }
                if line[0] != b' ' {
                    matches.push(line);
                    continue;
                }
                state = S::Data;
                insert_data(t, &matches, &line, filename, file_priority, line_number, compat);
            }
            S::Data => {
                if len == 0 {
                    state = S::None;
                    matches.clear();
                    continue;
                }
                if line[0] != b' ' {
                    log_syntax!(
                        libc::LOG_WARNING,
                        Some(filename),
                        line_number,
                        0,
                        "Property or empty line expected, got \"",
                        line,
                        "\", ignoring record."
                    );
                    state = S::None;
                    matches.clear();
                    continue;
                }
                insert_data(t, &matches, &line, filename, file_priority, line_number, compat);
            }
        }
    }
    if state == S::Match {
        log_syntax!(
            libc::LOG_WARNING,
            Some(filename),
            line_number,
            0,
            "Property expected, ignoring record with no properties."
        );
    }
    r
}

/// `hwdb_update(root, hwdb_bin_dir, strict, compat)`.
pub fn hwdb_update(root: Option<&[u8]>, hwdb_bin_dir: Option<&[u8]>, strict: bool, compat: bool) -> i32 {
    let root = match crate::chase::empty_or_root_harder_to_null(root) {
        Ok(r) => r,
        Err(r) => {
            return log_error_errno!(
                r,
                "Failed to determine if '",
                root.unwrap_or_default(),
                "' points to the root directory: ",
                strerror(r)
            );
        }
    };
    let root_abs = match root {
        Some(rt) => match path_make_absolute_cwd(rt) {
            Ok(a) => Some(path_simplify(&a)),
            Err(r) => return log_error_errno!(r, "Failed to make '", rt, "' absolute: ", strerror(r)),
        },
        None => None,
    };
    let hwdb_bin =
        path_join(&[root_abs.as_deref().unwrap_or_default(), hwdb_bin_dir.unwrap_or(b"/etc/udev"), b"hwdb.bin"]);

    let mut t = Trie {
        nodes: vec![TrieNode::default()],
        strings: Strbuf::new(),
        nodes_count: 1,
        children_count: 0,
        values_count: 0,
    };

    let dirs: Vec<Vec<u8>> = CONF_FILE_DIRS.iter().map(|d| d.to_vec()).collect();
    let files = match conf_files_list_strv_full(
        Some(b".hwdb"),
        root_abs.as_deref(),
        CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
        &dirs,
    ) {
        Ok(f) => f,
        Err(r) => return log_error_errno!(r, "Failed to enumerate hwdb files: ", strerror(r)),
    };

    if files.is_empty() {
        match sys::unlink(&hwdb_bin) {
            Err(e) if e != -libc::ENOENT => {
                return log_error_errno!(e, "Failed to remove compiled hwdb database ", hwdb_bin, ": ", strerror(e));
            }
            Err(_) => {
                log_info!("No hwdb files found, skipping.");
            }
            Ok(()) => {
                log_info!("No hwdb files found, compiled hwdb database ", hwdb_bin, " removed.");
            }
        }
        return 0;
    }

    let root_s: &[u8] = match &root_abs {
        Some(r) if !r.is_empty() => r,
        _ => b"/",
    };
    let mut ret = 0;
    let mut file_priority = 1u16;
    for c in &files {
        log_debug!("Reading file \"", c.original_path, "\" -> \"", c.resolved_path, "\"");
        // path_startswith_full(original, root, PATH_STARTSWITH_RETURN_LEADING_SLASH)
        let in_root = if root_s == b"/" {
            c.original_path.clone()
        } else {
            let rest = crate::path::path_startswith(&c.original_path, root_s).expect("below root");
            crate::bcat!("/", crate::path::skip_leading_slash(rest))
        };
        let k = import_file(&mut t, c.fd.raw(), &in_root, file_priority, compat);
        file_priority = file_priority.wrapping_add(1);
        ret_gather(&mut ret, k);
    }

    let strings = &t.strings;
    log_debug!("=== trie in-memory ===");
    log_debug!(
        "nodes:            ",
        format!("{:8}", t.nodes_count * MEM_NODE_SIZE),
        " bytes (",
        format!("{:8}", t.nodes_count),
        ")"
    );
    log_debug!(
        "children arrays:  ",
        format!("{:8}", t.children_count * MEM_CHILD_ENTRY_SIZE),
        " bytes (",
        format!("{:8}", t.children_count),
        ")"
    );
    log_debug!(
        "values arrays:    ",
        format!("{:8}", t.values_count * MEM_VALUE_ENTRY_SIZE),
        " bytes (",
        format!("{:8}", t.values_count),
        ")"
    );
    log_debug!("strings:          ", format!("{:8}", strings.len()), " bytes");
    log_debug!(
        "strings incoming: ",
        format!("{:8}", strings.in_len),
        " bytes (",
        format!("{:8}", strings.in_count),
        ")"
    );
    log_debug!(
        "strings dedup'ed: ",
        format!("{:8}", strings.dedup_len),
        " bytes (",
        format!("{:8}", strings.dedup_count),
        ")"
    );
    t.strings.complete();

    let _ = crate::fs::mkdirat_parents(AT_FDCWD, &hwdb_bin, 0o755);
    if let Err(r) = trie_store(&t, &hwdb_bin, compat) {
        return log_error_errno!(r, "Failed to write database ", hwdb_bin, ": ", strerror(r));
    }
    // label_fix(): no SELinux labels in this build.
    // QUIRK: ret only holds read errors; parse warnings never make
    // --strict fail.
    if strict { ret } else { 0 }
}

// ---------------------------------------------------------------------------
// sd-hwdb

/// `sd_hwdb`: the file's contents, and the properties of the last lookup
/// (key → offset of its value entry), in insertion order.
#[derive(Debug)]
pub struct Hwdb {
    map: sys::Mmap,
    properties: Vec<(Vec<u8>, usize)>,
    properties_modified: bool,
    iterator: usize,
    pub mtime: (i64, i64),
}

/// `LINE_MAX`, the size of `struct linebuf`.
const LINE_MAX: usize = 2048;

/// `struct linebuf`.
struct Linebuf {
    bytes: Vec<u8>,
}

impl Linebuf {
    fn get(&self) -> Option<&[u8]> {
        if self.bytes.len() + 1 >= LINE_MAX { None } else { Some(&self.bytes) }
    }
    fn add(&mut self, s: &[u8]) -> bool {
        if self.bytes.len() + s.len() >= LINE_MAX {
            return false;
        }
        self.bytes.extend_from_slice(s);
        true
    }
    fn add_char(&mut self, c: u8) -> bool {
        if self.bytes.len() + 1 >= LINE_MAX {
            return false;
        }
        self.bytes.push(c);
        true
    }
    fn rem(&mut self, n: usize) {
        // C's size_t would wrap after a failed add_char(); only reachable
        // with keys longer than LINE_MAX.
        let l = self.bytes.len().saturating_sub(n);
        self.bytes.truncate(l);
    }
}

const HWDB_RECURSION_MAX: u32 = 2048;

impl Hwdb {
    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.map[off..off + 8].try_into().expect("8 bytes"))
    }
    fn node_size(&self) -> u64 {
        self.u64_at(32)
    }
    fn child_entry_size(&self) -> u64 {
        self.u64_at(40)
    }
    fn value_entry_size(&self) -> u64 {
        self.u64_at(48)
    }

    /// `hwdb_at(off, size)`.
    fn at(&self, off: u64, size: u64) -> Option<usize> {
        let file_size = self.map.len() as u64;
        if off >= file_size || file_size - off < size {
            return None;
        }
        Some(off as usize)
    }

    /// `trie_node_from_off()`.
    fn node_from_off(&self, off: u64) -> Option<usize> {
        let (ns, cs, vs) = (self.node_size(), self.child_entry_size(), self.value_entry_size());
        if ns < NODE_SIZE || cs < CHILD_ENTRY_SIZE || vs < VALUE_ENTRY_SIZE {
            return None;
        }
        let node = self.at(off, ns)?;
        let children = (self.map[node + 8] as u64).checked_mul(cs)?;
        let values = self.u64_at(node + 16).checked_mul(vs)?;
        let total = ns.checked_add(children)?.checked_add(values)?;
        self.at(off, total)?;
        Some(node)
    }

    /// `trie_string()`.
    fn string(&self, off: u64) -> Option<&[u8]> {
        let p = self.at(off, 1)?;
        let s = &self.map[p..];
        s.iter().position(|&b| b == 0).map(|z| &s[..z])
    }

    fn children_count(&self, node: usize) -> usize {
        self.map[node + 8] as usize
    }
    fn values_count(&self, node: usize) -> u64 {
        self.u64_at(node + 16)
    }
    fn prefix_off(&self, node: usize) -> u64 {
        self.u64_at(node)
    }
    /// `trie_node_child()`: (c, child_off).
    fn child(&self, node: usize, idx: usize) -> (u8, u64) {
        let base = node + self.node_size() as usize + idx * self.child_entry_size() as usize;
        (self.map[base], self.u64_at(base + 8))
    }
    /// `trie_node_value()`.
    fn value(&self, node: usize, idx: u64) -> usize {
        node + self.node_size() as usize
            + self.children_count(node) * self.child_entry_size() as usize
            + idx as usize * self.value_entry_size() as usize
    }

    /// `node_lookup_f()`: bsearch() over the children.
    fn lookup(&self, node: usize, c: u8) -> Option<usize> {
        let (mut lo, mut hi) = (0usize, self.children_count(node));
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (mc, off) = self.child(node, mid);
            match mc.cmp(&c) {
                std::cmp::Ordering::Equal => return self.node_from_off(off),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// `hwdb_add_property()`.
    fn add_property(&mut self, entry: usize) -> Result<(), i32> {
        let key = self.string(self.u64_at(entry)).ok_or(-libc::EBADMSG)?;
        if key.first() != Some(&b' ') {
            return Ok(());
        }
        let key = key[1..].to_vec();
        let pos = self.properties.iter().position(|(k, _)| *k == key);
        if self.value_entry_size() >= VALUE_ENTRY2_SIZE
            && let Some(i) = pos
        {
            let old = self.properties[i].1;
            let fname = |e: usize| self.u64_at(e + 16);
            let line = |e: usize| u32::from_le_bytes(self.map[e + 24..e + 28].try_into().expect("4"));
            let prio = |e: usize| u16::from_le_bytes(self.map[e + 28..e + 30].try_into().expect("2"));
            let lower = if prio(entry) == 0 {
                fname(entry) < fname(old) || (fname(entry) == fname(old) && line(entry) < line(old))
            } else {
                prio(entry) < prio(old) || (prio(entry) == prio(old) && line(entry) < line(old))
            };
            if lower {
                return Ok(());
            }
        }
        match pos {
            Some(i) => self.properties[i].1 = entry,
            None => self.properties.push((key, entry)),
        }
        self.properties_modified = true;
        Ok(())
    }

    /// `trie_fnmatch_f()`.
    fn fnmatch_f(&mut self, node: usize, p: usize, buf: &mut Linebuf, search: &[u8], depth: u32) -> Result<(), i32> {
        if depth >= HWDB_RECURSION_MAX {
            return Err(-libc::EBADMSG);
        }
        let prefix = self.string(self.prefix_off(node)).ok_or(-libc::EBADMSG)?.to_vec();
        if p > prefix.len() {
            return Err(-libc::EBADMSG);
        }
        let len = prefix.len() - p;
        if !buf.add(&prefix[p..]) {
            return Err(-libc::EINVAL);
        }
        for i in 0..self.children_count(node) {
            let (c, off) = self.child(node, i);
            buf.add_char(c);
            let child = self.node_from_off(off).ok_or(-libc::EBADMSG)?;
            self.fnmatch_f(child, 0, buf, search, depth + 1)?;
            buf.rem(1);
        }
        let nv = self.values_count(node);
        if nv != 0 {
            let line = buf.get().ok_or(-libc::EBADMSG)?.to_vec();
            if sys::fnmatch(&line, search, 0) == 0 {
                for i in 0..nv {
                    let v = self.value(node, i);
                    self.add_property(v)?;
                }
            }
        }
        buf.rem(len);
        Ok(())
    }

    /// `trie_search_f()`.
    fn search(&mut self, search: &[u8]) -> Result<(), i32> {
        let mut buf = Linebuf { bytes: Vec::with_capacity(LINE_MAX) };
        let mut node = Some(self.node_from_off(self.u64_at(56)).ok_or(-libc::EBADMSG)?);
        let mut i = 0usize;
        while let Some(n) = node {
            let mut p = 0usize;
            if self.prefix_off(n) != 0 {
                let prefix = self.string(self.prefix_off(n)).ok_or(-libc::EBADMSG)?.to_vec();
                while p < prefix.len() {
                    let c = prefix[p];
                    if matches!(c, b'*' | b'?' | b'[') {
                        let rest = search.get(i + p..).unwrap_or_default();
                        return self.fnmatch_f(n, p, &mut buf, rest, 0);
                    }
                    if c != at(search, i + p) {
                        return Ok(());
                    }
                    p += 1;
                }
                i += p;
            }
            for g in *b"*?[" {
                if let Some(child) = self.lookup(n, g) {
                    buf.add_char(g);
                    let rest = search.get(i..).unwrap_or_default();
                    self.fnmatch_f(child, 0, &mut buf, rest, 0)?;
                    buf.rem(1);
                }
            }
            if at(search, i) == 0 {
                for k in 0..self.values_count(n) {
                    let v = self.value(n, k);
                    self.add_property(v)?;
                }
                return Ok(());
            }
            node = self.lookup(n, at(search, i));
            i += 1;
        }
        Ok(())
    }

    /// `hwdb_new(path)`.
    fn open(path: Option<&[u8]>) -> Result<Hwdb, i32> {
        let (fd, path) = match path {
            Some(p) if !p.is_empty() => {
                log_debug!("Trying to open \"", p, "\"...");
                match sys::open(p, libc::O_RDONLY | libc::O_CLOEXEC, 0) {
                    Ok(fd) => (OwnedFd::new(fd), p.to_vec()),
                    Err(e) => return Err(log_debug_errno!(e, "Failed to open ", p, ": ", strerror(e))),
                }
            }
            _ => {
                let mut found = None;
                for p in HWDB_BIN_PATHS {
                    log_debug!("Trying to open \"", p, "\"...");
                    match sys::open(p, libc::O_RDONLY | libc::O_CLOEXEC, 0) {
                        Ok(fd) => {
                            found = Some((OwnedFd::new(fd), p.to_vec()));
                            break;
                        }
                        Err(e) if e != -libc::ENOENT => {
                            return Err(log_debug_errno!(e, "Failed to open ", p, ": ", strerror(e)));
                        }
                        Err(_) => {}
                    }
                }
                match found {
                    Some(x) => x,
                    None => {
                        return Err(log_debug_errno!(
                            synthetic(libc::ENOENT),
                            "hwdb.bin does not exist, please run 'systemd-hwdb update'."
                        ));
                    }
                }
            }
        };
        let st = match sys::fstat(fd.raw()) {
            Ok(st) => st,
            Err(e) => return Err(log_debug_errno!(e, "Failed to stat ", path, ": ", strerror(e))),
        };
        if st.st_size < HEADER_SIZE as i64 {
            return Err(log_debug_errno!(synthetic(libc::EIO), "File ", path, " is too short."));
        }
        // file_offset_beyond_memory_size()
        if st.st_size as u64 > usize::MAX as u64 {
            return Err(log_debug_errno!(synthetic(libc::EFBIG), "File ", path, " is too long."));
        }
        let map = match sys::Mmap::map_readonly(fd.raw(), st.st_size as usize) {
            Ok(m) => m,
            Err(e) => return Err(log_debug_errno!(e, "Failed to map ", path, ": ", strerror(e))),
        };
        let h =
            Hwdb { map, properties: Vec::new(), properties_modified: false, iterator: 0, mtime: sys::stat_mtime(&st) };
        if h.map.len() < HEADER_SIZE as usize || &h.map[..8] != HWDB_SIG || st.st_size as u64 != h.u64_at(16) {
            return Err(log_debug_errno!(synthetic(libc::EINVAL), "Failed to recognize the format of ", path, "."));
        }
        log_debug!("=== trie on-disk ===");
        log_debug!("tool version:          ", h.u64_at(8).to_string());
        log_debug!("file size:        ", format!("{:8}", st.st_size), " bytes");
        log_debug!("header size       ", format!("{:8}", h.u64_at(24)), " bytes");
        log_debug!("strings           ", format!("{:8}", h.u64_at(72)), " bytes");
        log_debug!("nodes             ", format!("{:8}", h.u64_at(64)), " bytes");
        Ok(h)
    }

    /// `sd_hwdb_new_from_path()`.
    pub fn new_from_path(path: &[u8]) -> Result<Hwdb, i32> {
        Hwdb::open(Some(path))
    }

    /// `sd_hwdb_new()`.
    pub fn new() -> Result<Hwdb, i32> {
        Hwdb::open(None)
    }

    /// `properties_prepare()`.
    fn prepare(&mut self, modalias: &[u8]) -> Result<(), i32> {
        self.properties.clear();
        self.properties_modified = true;
        self.search(modalias)
    }

    /// `sd_hwdb_get()`.
    pub fn get(&mut self, modalias: &[u8], key: &[u8]) -> Result<Vec<u8>, i32> {
        self.prepare(modalias)?;
        let e = self.properties.iter().find(|(k, _)| k == key).map(|(_, e)| *e).ok_or(-libc::ENOENT)?;
        Ok(self.string(self.u64_at(e + 8)).ok_or(-libc::EBADMSG)?.to_vec())
    }

    /// `sd_hwdb_seek()`.
    pub fn seek(&mut self, modalias: &[u8]) -> Result<(), i32> {
        self.prepare(modalias)?;
        self.properties_modified = false;
        self.iterator = 0;
        Ok(())
    }

    /// `sd_hwdb_enumerate()`: Ok(None) at the end.
    pub fn enumerate(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, i32> {
        if self.properties_modified {
            return Err(-libc::EAGAIN);
        }
        let Some((k, e)) = self.properties.get(self.iterator).cloned() else { return Ok(None) };
        self.iterator += 1;
        let v = self.string(self.u64_at(e + 8)).ok_or(-libc::EBADMSG)?.to_vec();
        Ok(Some((k, v)))
    }

    /// `SD_HWDB_FOREACH_PROPERTY()`: errors end the loop silently.
    /// QUIRK: so `systemd-hwdb query` on a corrupt database prints nothing and
    /// succeeds.
    pub fn properties(&mut self, modalias: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let _ = self.seek(modalias);
        let mut out = Vec::new();
        while let Ok(Some(kv)) = self.enumerate() {
            out.push(kv);
        }
        out
    }
}

/// `hwdb_query(modalias, root)`.
pub fn hwdb_query(modalias: &[u8], root: Option<&[u8]>) -> i32 {
    let res = match root {
        Some(r) if !r.is_empty() => {
            let mut res = Err(-libc::ENOENT);
            for p in HWDB_BIN_PATHS {
                res = Hwdb::new_from_path(&path_join(&[r, p]));
                if res.is_ok() {
                    break;
                }
            }
            res
        }
        _ => Hwdb::new(),
    };
    let mut hwdb = match res {
        Ok(h) => h,
        Err(r) => return r,
    };
    for (k, v) in hwdb.properties(modalias) {
        printo!(k, "=", v, "\n");
    }
    0
}

/// `hwdb_bypass()`.
pub fn hwdb_bypass() -> bool {
    crate::options::should_bypass("SYSTEMD_HWDB_UPDATE")
}
