// SPDX-License-Identifier: LGPL-2.1-or-later
//! `fileio.c`: line reading, whole-file reading, `write_string_file()`.

use crate::fd::{AT_FDCWD, fd_reopen};
use crate::path::{is_path, path_is_absolute, path_join, path_make_absolute_cwd, path_simplify};
use crate::string::streq_skip_trailing_chars;
use crate::sys::{self, OwnedFd};
use crate::terminal::isatty_safe;

/// `LONG_LINE_MAX`.
pub const LONG_LINE_MAX: usize = 1024 * 1024;
/// `READ_VIRTUAL_BYTES_MAX`.
const READ_VIRTUAL_BYTES_MAX: usize = 4 * 1024 * 1024 - 2;

/// A C `FILE*` opened for reading: a buffer over an fd, with one byte of
/// `ungetc()`.  (Or stdin, which is not closed.)
#[derive(Debug)]
pub struct CReader {
    fd: i32,
    owned: bool,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    error: i32,
    tty: Option<bool>,
}

impl CReader {
    /// Take ownership of fd (like `take_fdopen()`).
    pub fn from_fd(fd: i32) -> CReader {
        CReader { fd, owned: true, buf: Vec::new(), pos: 0, eof: false, error: 0, tty: None }
    }

    /// `stdin`.
    pub fn stdin() -> CReader {
        CReader { fd: 0, owned: false, buf: Vec::new(), pos: 0, eof: false, error: 0, tty: None }
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// `fgetc()`: `Ok(None)` at EOF.
    pub fn getc(&mut self) -> Result<Option<u8>, i32> {
        if self.pos < self.buf.len() {
            let c = self.buf[self.pos];
            self.pos += 1;
            return Ok(Some(c));
        }
        if self.eof {
            return Ok(None);
        }
        // glibc sizes the buffer by st_blksize (at most BUFSIZ-ish); the
        // exact size only matters for files that change while read.
        let size = match sys::fstat(self.fd) {
            Ok(st) if st.st_blksize > 0 => st.st_blksize as usize,
            _ => 8192,
        };
        let mut b = vec![0u8; size];
        loop {
            match sys::read(self.fd, &mut b) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(None);
                }
                Ok(n) => {
                    b.truncate(n);
                    self.buf = b;
                    self.pos = 1;
                    return Ok(Some(self.buf[0]));
                }
                Err(e) if e == -libc::EINTR => continue,
                Err(e) => {
                    self.error = e;
                    return Err(e);
                }
            }
        }
    }

    /// `ungetc(c)` after a `getc()`.
    pub fn ungetc(&mut self) {
        assert!(self.pos > 0);
        self.pos -= 1;
    }

    /// `ferror()`.
    pub fn has_error(&self) -> bool {
        self.error != 0
    }

    fn is_tty(&mut self) -> bool {
        *self.tty.get_or_insert_with(|| isatty_safe(self.fd))
    }

    /// Read everything that is left.
    pub fn read_to_end(&mut self) -> Result<Vec<u8>, i32> {
        let mut out = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        let mut b = vec![0u8; 8192];
        loop {
            match sys::read(self.fd, &mut b) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(out);
                }
                Ok(n) => out.extend_from_slice(&b[..n]),
                Err(e) if e == -libc::EINTR => {}
                Err(e) => {
                    self.error = e;
                    return Err(e);
                }
            }
        }
    }
}

impl Drop for CReader {
    fn drop(&mut self) {
        if self.owned {
            sys::close(self.fd);
        }
    }
}

/// `fopen(path, "re")`.
pub fn fopen_re(path: &[u8]) -> Result<CReader, i32> {
    let fd = sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    Ok(CReader::from_fd(fd))
}

const EOL_ZERO: u8 = 1;
const EOL_TEN: u8 = 2;
const EOL_THIRTEEN: u8 = 4;

fn categorize_eol(c: u8, only_nul: bool) -> u8 {
    if !only_nul {
        if c == b'\n' {
            return EOL_TEN;
        }
        if c == b'\r' {
            return EOL_THIRTEEN;
        }
    }
    if c == 0 {
        return EOL_ZERO;
    }
    0
}

/// `read_line_full(f, limit, flags, &ret)`: (bytes consumed, line).
/// `Ok((0, _))` at EOF.
pub fn read_line_full(f: &mut CReader, limit: usize, only_nul: bool) -> Result<(usize, Vec<u8>), i32> {
    let mut buffer = Vec::new();
    let mut count = 0usize;
    let mut previous_eol = 0u8;
    loop {
        if buffer.len() >= limit {
            return Err(-libc::ENOBUFS);
        }
        if count >= i32::MAX as usize {
            return Err(-libc::ENOBUFS);
        }
        let c = match f.getc() {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => return Err(e),
        };
        let eol = categorize_eol(c, only_nul);
        if previous_eol & EOL_ZERO != 0 || (eol == 0 && previous_eol != 0) || (eol != 0 && (previous_eol & eol) != 0) {
            f.ungetc();
            break;
        }
        count += 1;
        if eol != 0 {
            if f.is_tty() {
                break;
            }
            previous_eol |= eol;
            continue;
        }
        buffer.push(c);
    }
    Ok((count, buffer))
}

/// `read_line(f, limit, &ret)`.
pub fn read_line(f: &mut CReader, limit: usize) -> Result<(usize, Vec<u8>), i32> {
    read_line_full(f, limit, false)
}

/// `read_stripped_line()`: `Ok(None)` at EOF.
pub fn read_stripped_line(f: &mut CReader, limit: usize) -> Result<Option<Vec<u8>>, i32> {
    let (n, s) = read_line(f, limit)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(crate::string::strstrip(&s).to_vec()))
}

/// `read_one_line_file(fn, &line)`: the first line, without its end.
pub fn read_one_line_file(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut f = fopen_re(path)?;
    Ok(read_line(&mut f, LONG_LINE_MAX)?.1)
}

/// `read_full_file(filename, &ret, NULL)`: refuses embedded NULs (EBADMSG).
pub fn read_full_file(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut f = fopen_re(path)?;
    let data = f.read_to_end()?;
    if data.contains(&0) {
        return Err(-libc::EBADMSG);
    }
    Ok(data)
}

/// `read_virtual_file_fd(fd, max_size, &ret, NULL)`: (contents, untruncated).
pub fn read_virtual_file_fd(fd: i32, max_size: usize) -> Result<(Vec<u8>, bool), i32> {
    let fd = OwnedFd::new(fd_reopen(fd, libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC)?);
    read_virtual_file_owned(fd, max_size)
}

/// `read_virtual_file_at(dir_fd, filename, max_size, &ret, NULL)`.
pub fn read_virtual_file(path: &[u8], max_size: usize) -> Result<(Vec<u8>, bool), i32> {
    let fd = OwnedFd::new(sys::openat(AT_FDCWD, path, libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC, 0)?);
    read_virtual_file_owned(fd, max_size)
}

fn read_virtual_file_owned(fd: OwnedFd, max_size: usize) -> Result<(Vec<u8>, bool), i32> {
    let mut n_retries = 3;
    let mut truncated = false;
    let (buf, n) = loop {
        let st = sys::fstat(fd.raw())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(-libc::EBADF);
        }
        let mut size;
        if st.st_size > 0 && n_retries > 1 {
            size = (st.st_size as usize).min(max_size);
            if size > READ_VIRTUAL_BYTES_MAX {
                return Err(-libc::EFBIG);
            }
            n_retries -= 1;
        } else if n_retries > 1 {
            size = (sys::page_size() - 1).min(READ_VIRTUAL_BYTES_MAX).min(max_size);
            n_retries = 1;
        } else {
            size = READ_VIRTUAL_BYTES_MAX.min(max_size);
            n_retries = 0;
        }
        // MALLOC_SIZEOF_SAFE(buf) - 1: use the slack malloc() gives us.
        size = (sys::malloc_usable(size + 1) - 1).min(max_size).min(READ_VIRTUAL_BYTES_MAX);
        let mut buf = vec![0u8; size + 1];
        let mut n = loop {
            match sys::read(fd.raw(), &mut buf) {
                Ok(k) => break k,
                Err(e) if e == -libc::EINTR => {}
                Err(e) => return Err(e),
            }
        };
        if n <= size {
            break (buf, n);
        }
        if max_size != usize::MAX && n > max_size {
            n = size;
            truncated = true;
            break (buf, n);
        }
        if n_retries <= 0 {
            return Err(-libc::EFBIG);
        }
        sys::lseek(fd.raw(), 0, libc::SEEK_SET)?;
    };
    let mut buf = buf;
    buf.truncate(n);
    if buf.contains(&0) {
        return Err(-libc::EBADMSG);
    }
    Ok((buf, !truncated))
}

/// `verify_file_at(AT_FDCWD, fn, blob, accept_extra_nl)`: Ok(true) if the
/// file holds exactly blob (plus maybe a newline).
pub fn verify_file(path: &[u8], blob: &[u8], mut accept_extra_nl: bool) -> Result<bool, i32> {
    let l = blob.len();
    if accept_extra_nl && blob.ends_with(b"\n") {
        accept_extra_nl = false;
    }
    let want = l + accept_extra_nl as usize + 1;
    let fd = OwnedFd::new(sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0)?);
    // fread(): keep reading until want bytes or EOF.
    let mut buf = Vec::with_capacity(want);
    let mut chunk = vec![0u8; want.max(1)];
    while buf.len() < want {
        let need = want - buf.len();
        match sys::read(fd.raw(), &mut chunk[..need]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e == -libc::EINTR => {}
            Err(e) => return Err(e),
        }
    }
    let k = buf.len();
    if k != l && k != l + accept_extra_nl as usize {
        return Ok(false);
    }
    if buf[..l] != *blob {
        return Ok(false);
    }
    if k > l && buf[l] != b'\n' {
        return Ok(false);
    }
    Ok(true)
}

pub const WRITE_STRING_FILE_CREATE: u32 = 1 << 0;
pub const WRITE_STRING_FILE_TRUNCATE: u32 = 1 << 1;
pub const WRITE_STRING_FILE_ATOMIC: u32 = 1 << 2;
pub const WRITE_STRING_FILE_AVOID_NEWLINE: u32 = 1 << 3;
pub const WRITE_STRING_FILE_VERIFY_ON_FAILURE: u32 = 1 << 4;
pub const WRITE_STRING_FILE_VERIFY_IGNORE_NEWLINE: u32 = 1 << 5;
pub const WRITE_STRING_FILE_SYNC: u32 = 1 << 6;
pub const WRITE_STRING_FILE_DISABLE_BUFFER: u32 = 1 << 7;
pub const WRITE_STRING_FILE_NOFOLLOW: u32 = 1 << 8;
pub const WRITE_STRING_FILE_MKDIR_0755: u32 = 1 << 9;
pub const WRITE_STRING_FILE_MODE_0600: u32 = 1 << 10;
pub const WRITE_STRING_FILE_MODE_0444: u32 = 1 << 11;
pub const WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL: u32 = 1 << 12;

/// `write_string_stream_full(f, line, flags, NULL)` on an fd.
fn write_string_stream(fd: i32, line: &[u8], flags: u32) -> Result<(), i32> {
    if flags & WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL != 0 {
        if let Ok((t, true)) = read_virtual_file_fd(fd, line.len() + 1)
            && streq_skip_trailing_chars(line, &t, Some(crate::string::NEWLINE))
        {
            crate::log_debug!("No change in value '", line, "', suppressing write");
            return Ok(());
        }
        sys::lseek(fd, 0, libc::SEEK_SET)?;
    }
    let needs_nl = flags & WRITE_STRING_FILE_AVOID_NEWLINE == 0 && !line.ends_with(b"\n");
    let mut data = line.to_vec();
    if needs_nl {
        // Unbuffered: newline appended to the string, one write. Buffered:
        // fputs()+fputc()+fflush() also end up as one write for short lines.
        data.push(b'\n');
    }
    sys::write_all(fd, &data)?;
    if flags & WRITE_STRING_FILE_SYNC != 0 {
        // fflush_sync_and_check(): fsync the file (directory sync not needed by callers yet).
        crate::sys::fsync(fd)?;
    }
    Ok(())
}

/// `write_string_file(fn, line, flags)` (non-atomic forms).
pub fn write_string_file(path: &[u8], line: &[u8], flags: u32) -> Result<(), i32> {
    assert!(flags & WRITE_STRING_FILE_ATOMIC == 0, "atomic writes are not ported yet");
    let mut made_file = false;
    let mut oflags = libc::O_CLOEXEC | libc::O_NOCTTY;
    if flags & WRITE_STRING_FILE_NOFOLLOW != 0 {
        oflags |= libc::O_NOFOLLOW;
    }
    if flags & WRITE_STRING_FILE_TRUNCATE != 0 {
        oflags |= libc::O_TRUNC;
    }
    oflags |= if flags & WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL != 0 { libc::O_RDWR } else { libc::O_WRONLY };
    let mode = if flags & WRITE_STRING_FILE_MODE_0600 != 0 {
        0o600
    } else if flags & WRITE_STRING_FILE_MODE_0444 != 0 {
        0o444
    } else {
        0o644
    };
    let r = (|| {
        let fd = if flags & WRITE_STRING_FILE_CREATE != 0 {
            let (fd, made) = openat_report_new(AT_FDCWD, path, oflags, mode)?;
            made_file = made;
            fd
        } else {
            sys::openat(AT_FDCWD, path, oflags, mode)?
        };
        let fd = OwnedFd::new(fd);
        write_string_stream(fd.raw(), line, flags)
    })();
    let Err(r) = r else { return Ok(()) };
    if made_file {
        let _ = sys::unlinkat(AT_FDCWD, path, 0);
    }
    if flags & WRITE_STRING_FILE_VERIFY_ON_FAILURE == 0 {
        return Err(r);
    }
    let accept = flags & WRITE_STRING_FILE_AVOID_NEWLINE == 0 || flags & WRITE_STRING_FILE_VERIFY_IGNORE_NEWLINE != 0;
    if let Ok(true) = verify_file(path, line, accept) {
        return Ok(());
    }
    Err(r)
}

/// `openat_report_new()`: open with O_CREAT and say whether we created it.
pub fn openat_report_new(dirfd: i32, path: &[u8], flags: i32, mode: u32) -> Result<(i32, bool), i32> {
    if flags & libc::O_CREAT == 0 || flags & libc::O_EXCL != 0 {
        let fd = sys::openat(dirfd, path, flags, mode)?;
        return Ok((fd, flags & libc::O_EXCL != 0));
    }
    for _ in 0..32 {
        match sys::openat(dirfd, path, flags & !libc::O_CREAT, mode) {
            Ok(fd) => return Ok((fd, false)),
            Err(e) if e != -libc::ENOENT => return Err(e),
            Err(_) => {}
        }
        match sys::openat(dirfd, path, flags | libc::O_EXCL, mode) {
            Ok(fd) => return Ok((fd, true)),
            Err(e) if e != -libc::EEXIST => return Err(e),
            Err(_) => {}
        }
    }
    Err(-libc::EEXIST)
}

/// `fopen_mode_to_flags("re")` and friends, for the modes used here.
fn mode_to_flags(mode: &str) -> i32 {
    let mut flags = match mode.as_bytes().first() {
        Some(b'r') => libc::O_RDONLY,
        Some(b'w') => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        Some(b'a') => libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
        _ => libc::O_RDONLY,
    };
    for c in mode.bytes().skip(1) {
        match c {
            b'+' => flags = (flags & !libc::O_ACCMODE) | libc::O_RDWR,
            b'x' => flags |= libc::O_EXCL,
            b'e' => flags |= libc::O_CLOEXEC,
            _ => {}
        }
    }
    flags
}

/// `path_strv_resolve_uniq(search, root)` for root == NULL: resolve each
/// search directory's symlinks (`chase()`), dropping ones that fail
/// otherwise than with ENOENT, then drop duplicates.
pub fn path_strv_resolve_uniq(search: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for s in search {
        let u = match crate::chase::chase(s, None, 0, true, false) {
            Ok(c) => c.path.expect("requested"),
            Err(e) if e == -libc::ENOENT => s.clone(),
            Err(_) => continue,
        };
        out.push(u);
    }
    let mut uniq: Vec<Vec<u8>> = Vec::new();
    for u in out {
        if !uniq.contains(&u) {
            uniq.push(u);
        }
    }
    uniq
}

/// `search_and_fopen(path, mode, root=NULL, search, &f, &found)`.
pub fn search_and_fopen(path: &[u8], mode: &str, search: &[Vec<u8>]) -> Result<(CReader, Vec<u8>), i32> {
    let flags = mode_to_flags(mode);
    if path_is_absolute(path) {
        let fd = sys::open(path, flags, 0o777)?;
        return Ok((CReader::from_fd(fd), path_simplify(path)));
    }
    let search = path_strv_resolve_uniq(search);
    for i in &search {
        let p = path_join(&[i, path]);
        match sys::open(&p, flags, 0o777) {
            Ok(fd) => return Ok((CReader::from_fd(fd), path_simplify(&p))),
            Err(e) if e != -libc::ENOENT => return Err(e),
            Err(_) => {}
        }
    }
    Err(-libc::ENOENT)
}

/// `conf_file_read()`'s opening part: "-" for stdin, a path, or a name to
/// search for.  Returns the stream and the name to report.
pub fn open_config(path: &[u8], search: &[Vec<u8>]) -> Result<(CReader, Vec<u8>), (i32, Vec<u8>)> {
    if path == b"-" {
        return Ok((CReader::stdin(), b"<stdin>".to_vec()));
    }
    if is_path(path) {
        let abs = path_make_absolute_cwd(path).map_err(|e| (e, path.to_vec()))?;
        return match fopen_re(&abs) {
            Ok(f) => Ok((f, abs)),
            Err(e) => Err((e, abs)),
        };
    }
    search_and_fopen(path, "re", search).map_err(|e| (e, path.to_vec()))
}
