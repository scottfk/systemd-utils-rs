// SPDX-License-Identifier: LGPL-2.1-or-later
//! C stdio emulation for `stdout`: glibc's buffering decides when bytes
//! reach the fd, which is visible when stdout and stderr share a terminal
//! or a pipe.  Adapted from metalog-rs's `src/stdio.rs` (same author).
//!
//! glibc allocates the buffer on the first write: BUFSIZ, or st_blksize if
//! smaller, and makes a terminal line-buffered.  Output written before a
//! pager takes over fd 1 is therefore buffered for the pager's pipe.

use std::cell::RefCell;

use crate::sys;

/// glibc's `BUFSIZ`.
const BUFSIZ: usize = 8192;

/// A fully- or line-buffered output stream on an fd.
#[derive(Debug)]
pub struct CFile {
    fd: sys::Fd,
    buf: Vec<u8>,
    cap: Option<usize>,
    line_buffered: bool,
    unbuffered: bool,
    error: i32,
}

impl CFile {
    pub const fn from_fd(fd: sys::Fd) -> CFile {
        CFile { fd, buf: Vec::new(), cap: None, line_buffered: false, unbuffered: false, error: 0 }
    }

    /// `_IO_file_doallocate`.
    fn allocate(&mut self) -> usize {
        if let Some(c) = self.cap {
            return c;
        }
        let mut size = BUFSIZ;
        if let Ok(st) = sys::fstat(self.fd) {
            if st.st_mode & libc::S_IFMT == libc::S_IFCHR && sys::isatty(self.fd).0 {
                self.line_buffered = true;
            }
            if st.st_blksize > 0 && (st.st_blksize as usize) < BUFSIZ {
                size = st.st_blksize as usize;
            }
        }
        self.cap = Some(size);
        size
    }

    fn write_direct(&mut self, data: &[u8]) -> bool {
        if let Err(e) = sys::write_all(self.fd, data) {
            self.error = e;
            return false;
        }
        true
    }

    /// `fputs()`/`fprintf()`: glibc's `_IO_new_file_xsputn`.
    pub fn write(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.unbuffered {
            self.write_direct(data);
            return;
        }
        let first = self.cap.is_none();
        let cap = self.allocate();
        let space = if first { 0 } else { cap - self.buf.len() };
        let mut count = space;
        let mut must_flush = false;
        if self.line_buffered
            && !first
            && count >= data.len()
            && let Some(nl) = data.iter().rposition(|&b| b == b'\n')
        {
            count = nl + 1;
            must_flush = true;
        }
        let mut rest = data;
        if count > 0 {
            let n = count.min(rest.len());
            self.buf.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        if !rest.is_empty() || must_flush {
            if !self.flush() {
                return;
            }
            let block = cap;
            let do_write = rest.len() - if block >= 128 { rest.len() % block } else { 0 };
            if do_write > 0 {
                if !self.write_direct(&rest[..do_write]) {
                    return;
                }
                rest = &rest[do_write..];
            }
            if !rest.is_empty() {
                self.buf.extend_from_slice(rest);
                if self.line_buffered && rest.contains(&b'\n') {
                    self.flush();
                }
            }
        }
    }

    /// `fflush()`.
    pub fn flush(&mut self) -> bool {
        if self.buf.is_empty() {
            return true;
        }
        let data = std::mem::take(&mut self.buf);
        let ok = self.write_direct(&data);
        self.buf = data;
        self.buf.clear();
        ok
    }

    /// `ferror()` with the errno it saw.
    pub fn error(&self) -> i32 {
        self.error
    }

    pub fn clear_error(&mut self) {
        self.error = 0;
    }
}

thread_local! {
    static STDOUT: RefCell<CFile> = const { RefCell::new(CFile::from_fd(1)) };
}

/// `fputs(data, stdout)`.
pub fn out(data: &[u8]) {
    STDOUT.with(|s| s.borrow_mut().write(data));
}

/// `fflush(stdout)`.
pub fn flush_stdout() -> bool {
    STDOUT.with(|s| s.borrow_mut().flush())
}

/// `fflush_and_check(stdout)`: 0 or the negative errno.
pub fn fflush_and_check_stdout() -> i32 {
    STDOUT.with(|s| {
        let mut s = s.borrow_mut();
        s.flush();
        if s.error() != 0 { s.error() } else { 0 }
    })
}

/// `fputs(data, stderr)`: unbuffered, one write per call.
pub fn err(data: &[u8]) {
    let _ = sys::write_all(2, data);
}

/// `printf(...)` with byte pieces.
#[macro_export]
macro_rules! printo {
    ($($e:expr),* $(,)?) => { $crate::stdio::out(&$crate::bcat!($($e),*)) };
}
