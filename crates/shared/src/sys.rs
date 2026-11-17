// SPDX-License-Identifier: LGPL-2.1-or-later
//! Every libc call the shared code makes: the only `unsafe` in this crate.
//!
//! Conventions, following systemd's C: a failing call returns `Err(-errno)`
//! (a negative errno, like systemd's `int r`), and paths are byte strings.

use std::ffi::{CStr, CString};

use libc::{c_char, c_int, c_void};

use crate::bytes::to_cstring;

pub type Fd = c_int;

unsafe extern "C" {
    #[link_name = "secure_getenv"]
    fn secure_getenv_c(name: *const c_char) -> *mut c_char;
    fn fgetpwent(stream: *mut libc::FILE) -> *mut libc::passwd;
    fn fgetgrent(stream: *mut libc::FILE) -> *mut libc::group;
    fn strerrorname_np(errnum: c_int) -> *const c_char;
    #[link_name = "program_invocation_short_name"]
    static PROGRAM_INVOCATION_SHORT_NAME: *const c_char;
}
/// `struct stat` with 64-bit offsets and inodes: what C gets with
/// `_FILE_OFFSET_BITS=64` (as systemd builds), also on 32-bit x86.
pub type Stat = libc::stat64;
/// `st_atime` and its nanoseconds (32-bit on x86, where `time_t` is).
#[allow(clippy::unnecessary_cast)]
pub fn stat_atime(st: &Stat) -> (i64, i64) {
    (st.st_atime as i64, st.st_atime_nsec as i64)
}

/// `st_mtime` and its nanoseconds.
#[allow(clippy::unnecessary_cast)]
pub fn stat_mtime(st: &Stat) -> (i64, i64) {
    (st.st_mtime as i64, st.st_mtime_nsec as i64)
}

/// `struct statfs` likewise.
pub type StatFs = libc::statfs64;

/// `F_TYPE_EQUAL()`'s view of `f_type`: the magic as an unsigned 32-bit
/// value (on 32-bit x86, `f_type` is a signed int).
pub fn f_type(s: &StatFs) -> i64 {
    s.f_type as u32 as i64
}

/// `errno`.
pub fn errno() -> i32 {
    // SAFETY: __errno_location() always returns a valid thread-local pointer.
    unsafe { *libc::__errno_location() }
}

/// `errno = e`.
pub fn set_errno(e: i32) {
    // SAFETY: as in errno().
    unsafe { *libc::__errno_location() = e }
}

/// `-errno` of the last failed call.
pub fn neg_errno() -> i32 {
    -errno()
}

/// `strerror(e)` (glibc's text, in the current locale).
pub fn strerror(e: i32) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    // SAFETY: buf is valid for buf.len() bytes; the XSI strerror_r writes a
    // NUL-terminated string into it.
    let r = unsafe { libc::strerror_r(e, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if r != 0 {
        return format!("Unknown error {e}").into_bytes();
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf[..n].to_vec()
}

/// `getenv(name)`.
pub fn getenv(name: &str) -> Option<Vec<u8>> {
    let c = CString::new(name).ok()?;
    // SAFETY: c is NUL-terminated; getenv returns NULL or a NUL-terminated string.
    let p = unsafe { libc::getenv(c.as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: p is a valid NUL-terminated string from the environment.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `secure_getenv(name)`.
pub fn secure_getenv(name: &str) -> Option<Vec<u8>> {
    let c = CString::new(name).ok()?;
    // SAFETY: as in getenv().
    let p = unsafe { secure_getenv_c(c.as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: as in getenv().
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `setenv(name, value, 1)`.
pub fn setenv(name: &[u8], value: &[u8]) -> Result<(), i32> {
    let n = to_cstring(name);
    let v = to_cstring(value);
    // SAFETY: both are NUL-terminated.
    if unsafe { libc::setenv(n.as_ptr(), v.as_ptr(), 1) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `unsetenv(name)`.
pub fn unsetenv(name: &[u8]) -> Result<(), i32> {
    let n = to_cstring(name);
    // SAFETY: n is NUL-terminated.
    if unsafe { libc::unsetenv(n.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn getpid() -> i32 {
    // SAFETY: getpid() has no preconditions.
    unsafe { libc::getpid() }
}

/// glibc's `program_invocation_short_name`.
pub fn program_invocation_short_name() -> Vec<u8> {
    // SAFETY: glibc sets it before main() to a NUL-terminated string (or it
    // stays NULL in odd cases, which is checked).
    unsafe {
        let p = PROGRAM_INVOCATION_SHORT_NAME;
        if p.is_null() { Vec::new() } else { CStr::from_ptr(p).to_bytes().to_vec() }
    }
}

pub fn gettid() -> i32 {
    // SAFETY: gettid() has no preconditions.
    unsafe { libc::gettid() }
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid() has no preconditions.
    unsafe { libc::geteuid() }
}

pub fn getuid() -> u32 {
    // SAFETY: getuid() has no preconditions.
    unsafe { libc::getuid() }
}

pub fn umask(m: u32) -> u32 {
    // SAFETY: umask() has no preconditions.
    unsafe { libc::umask(m) }
}

/// `isatty(fd)`, returning errno too.
pub fn isatty(fd: Fd) -> (bool, i32) {
    // SAFETY: isatty() accepts any fd.
    let r = unsafe { libc::isatty(fd) };
    (r == 1, if r == 1 { 0 } else { errno() })
}

/// `ioctl(fd, TIOCGWINSZ)`: (columns, rows).
pub fn winsize(fd: Fd) -> Result<(u16, u16), i32> {
    // SAFETY: winsize is plain old data.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes a struct winsize.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } < 0 {
        return Err(neg_errno());
    }
    Ok((ws.ws_col, ws.ws_row))
}

pub fn stat_zero() -> Stat {
    // SAFETY: struct stat is plain old data.
    unsafe { std::mem::zeroed() }
}

pub fn fstat(fd: Fd) -> Result<Stat, i32> {
    let mut st = stat_zero();
    // SAFETY: st is a valid out-pointer.
    if unsafe { libc::fstat64(fd, &mut st) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

pub fn stat(path: &[u8]) -> Result<Stat, i32> {
    let c = to_cstring(path);
    let mut st = stat_zero();
    // SAFETY: c is NUL-terminated, st is a valid out-pointer.
    if unsafe { libc::stat64(c.as_ptr(), &mut st) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

/// `fstatat(dirfd, path, flags)`.
pub fn fstatat(dirfd: Fd, path: &[u8], flags: c_int) -> Result<Stat, i32> {
    let c = to_cstring(path);
    let mut st = stat_zero();
    // SAFETY: c is NUL-terminated, st is a valid out-pointer.
    if unsafe { libc::fstatat64(dirfd, c.as_ptr(), &mut st, flags) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

pub fn open(path: &[u8], flags: c_int, mode: u32) -> Result<Fd, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let fd = unsafe { libc::open64(c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd) }
}

pub fn openat(dirfd: Fd, path: &[u8], flags: c_int, mode: u32) -> Result<Fd, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let fd = unsafe { libc::openat64(dirfd, c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd) }
}

/// `openat2(dirfd, path, how)`; `Err(-ENOSYS)` etc. are passed through.
pub fn openat2(dirfd: Fd, path: &[u8], flags: u64, mode: u64, resolve: u64) -> Result<Fd, i32> {
    let c = to_cstring(path);
    // SAFETY: open_how is plain old data.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags;
    how.mode = mode;
    how.resolve = resolve;
    // SAFETY: c is NUL-terminated and how is a valid struct open_how.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, dirfd, c.as_ptr(), &how as *const libc::open_how, size_of::<libc::open_how>())
    };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd as Fd) }
}

pub fn close(fd: Fd) -> i32 {
    // SAFETY: closing an fd we own.
    unsafe { libc::close(fd) }
}

pub fn dup2(old: Fd, new: Fd) -> Result<Fd, i32> {
    // SAFETY: dup2() accepts any fds.
    let r = unsafe { libc::dup2(old, new) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `fcntl(fd, F_DUPFD_CLOEXEC, min)`.
pub fn dup_cloexec(fd: Fd, min: Fd) -> Result<Fd, i32> {
    // SAFETY: F_DUPFD_CLOEXEC takes an int argument.
    let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

pub fn fcntl_getfd(fd: Fd) -> Result<c_int, i32> {
    // SAFETY: F_GETFD takes no argument.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

pub fn read(fd: Fd, buf: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: buf is valid for buf.len() bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

pub fn write(fd: Fd, buf: &[u8]) -> Result<usize, i32> {
    // SAFETY: buf is valid for buf.len() bytes.
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const c_void, buf.len()) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// Write everything, retrying on EINTR and short writes (what glibc's
/// unbuffered `fputs` amounts to).
pub fn write_all(fd: Fd, mut data: &[u8]) -> Result<(), i32> {
    while !data.is_empty() {
        match write(fd, data) {
            Ok(0) => return Err(-libc::EIO),
            Ok(n) => data = &data[n..],
            Err(e) if e == -libc::EINTR => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `writev(fd, iov)`: one syscall, like systemd's log writers.
pub fn writev(fd: Fd, parts: &[&[u8]]) -> Result<usize, i32> {
    let iov: Vec<libc::iovec> =
        parts.iter().map(|p| libc::iovec { iov_base: p.as_ptr() as *mut c_void, iov_len: p.len() }).collect();
    // SAFETY: every iovec points into a live slice.
    let n = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as c_int) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// `sendmsg(fd, {iov}, MSG_NOSIGNAL)` on a connected socket.
pub fn sendmsg_iov(fd: Fd, parts: &[&[u8]]) -> Result<usize, i32> {
    let mut iov: Vec<libc::iovec> =
        parts.iter().map(|p| libc::iovec { iov_base: p.as_ptr() as *mut c_void, iov_len: p.len() }).collect();
    // SAFETY: msghdr is plain old data.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_iov = iov.as_mut_ptr();
    mh.msg_iovlen = iov.len();
    // SAFETY: mh points at live iovecs.
    let n = unsafe { libc::sendmsg(fd, &mh, libc::MSG_NOSIGNAL) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// `sendto(fd, data, MSG_NOSIGNAL, addr)` for an AF_UNIX path (or `@abstract`) address.
pub fn sendto_unix(fd: Fd, data: &[u8], path: &[u8]) -> Result<usize, i32> {
    let (sa, len) = sockaddr_un(path)?;
    // SAFETY: sa is a valid sockaddr_un of length len.
    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
            &sa as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        )
    };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

pub fn lseek(fd: Fd, off: i64, whence: c_int) -> Result<i64, i32> {
    // SAFETY: lseek() has no memory preconditions.
    let r = unsafe { libc::lseek64(fd, off, whence) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

pub fn pipe2(flags: c_int) -> Result<(Fd, Fd), i32> {
    let mut fds = [0; 2];
    // SAFETY: fds is a valid int[2].
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } < 0 { Err(neg_errno()) } else { Ok((fds[0], fds[1])) }
}

pub fn socket(domain: c_int, ty: c_int, proto: c_int) -> Result<Fd, i32> {
    // SAFETY: socket() has no memory preconditions.
    let fd = unsafe { libc::socket(domain, ty, proto) };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd) }
}

/// Build a `sockaddr_un`, the way systemd's `sockaddr_un_set_path()` does:
/// a leading '@' means an abstract socket.
pub fn sockaddr_un(path: &[u8]) -> Result<(libc::sockaddr_un, libc::socklen_t), i32> {
    // SAFETY: sockaddr_un is plain old data.
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let max = sa.sun_path.len();
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    let abstract_ = path[0] == b'@';
    if path.len() > max || (!abstract_ && path.len() >= max) {
        return Err(-libc::EINVAL);
    }
    for (i, &b) in path.iter().enumerate() {
        sa.sun_path[i] = b as c_char;
    }
    let len = if abstract_ {
        sa.sun_path[0] = 0;
        std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len()
    } else {
        std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1
    };
    Ok((sa, len as libc::socklen_t))
}

/// `connect(fd, AF_UNIX path)`.
pub fn connect_unix(fd: Fd, path: &[u8]) -> Result<(), i32> {
    let (sa, len) = sockaddr_un(path)?;
    // SAFETY: sa is a valid sockaddr_un of length len.
    let r = unsafe { libc::connect(fd, &sa as *const libc::sockaddr_un as *const libc::sockaddr, len) };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `setsockopt(fd, level, name, &int)`.
pub fn setsockopt_int(fd: Fd, level: c_int, name: c_int, v: c_int) -> Result<(), i32> {
    // SAFETY: v lives for the call.
    let r = unsafe {
        libc::setsockopt(fd, level, name, &v as *const c_int as *const c_void, size_of::<c_int>() as libc::socklen_t)
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `getsockopt(fd, level, name)` for an int option.
pub fn getsockopt_int(fd: Fd, level: c_int, name: c_int) -> Result<c_int, i32> {
    let mut v: c_int = 0;
    let mut l = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: v and l are valid out-pointers.
    let r = unsafe { libc::getsockopt(fd, level, name, &mut v as *mut c_int as *mut c_void, &mut l) };
    if r < 0 { Err(neg_errno()) } else { Ok(v) }
}

/// `setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, usec)`.
pub fn set_sndtimeo(fd: Fd, usec: u64) -> Result<(), i32> {
    let tv =
        libc::timeval { tv_sec: (usec / 1_000_000) as libc::time_t, tv_usec: (usec % 1_000_000) as libc::suseconds_t };
    // SAFETY: tv lives for the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const c_void,
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn unlink(path: &[u8]) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::unlink(c.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn unlinkat(dirfd: Fd, path: &[u8], flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::unlinkat(dirfd, c.as_ptr(), flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn mkdirat(dirfd: Fd, path: &[u8], mode: u32) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::mkdirat(dirfd, c.as_ptr(), mode) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn renameat(olddir: Fd, old: &[u8], newdir: Fd, new: &[u8]) -> Result<(), i32> {
    let o = to_cstring(old);
    let n = to_cstring(new);
    // SAFETY: both NUL-terminated.
    if unsafe { libc::renameat(olddir, o.as_ptr(), newdir, n.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

pub fn fchmod(fd: Fd, mode: u32) -> Result<(), i32> {
    // SAFETY: fchmod() has no memory preconditions.
    if unsafe { libc::fchmod(fd, mode) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `readlinkat(dirfd, path)`.
pub fn readlinkat(dirfd: Fd, path: &[u8]) -> Result<Vec<u8>, i32> {
    let c = to_cstring(path);
    let mut size = 256usize;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: buf is valid for size bytes.
        let n = unsafe { libc::readlinkat(dirfd, c.as_ptr(), buf.as_mut_ptr() as *mut c_char, size) };
        if n < 0 {
            return Err(neg_errno());
        }
        let n = n as usize;
        if n < size {
            buf.truncate(n);
            return Ok(buf);
        }
        size *= 2;
    }
}

/// `getcwd()`.
pub fn getcwd() -> Result<Vec<u8>, i32> {
    let mut size = 256usize;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: buf is valid for size bytes.
        let p = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut c_char, size) };
        if !p.is_null() {
            let n = buf.iter().position(|&b| b == 0).unwrap_or(size);
            buf.truncate(n);
            return Ok(buf);
        }
        if errno() != libc::ERANGE {
            return Err(neg_errno());
        }
        size *= 2;
    }
}

/// A directory stream (`DIR*`), read with `readdir()` so the entry order is
/// the kernel's, as in C.
#[derive(Debug)]
pub struct Dir(*mut libc::DIR);

impl Dir {
    /// `fdopendir(fd)`: takes ownership of fd.
    pub fn from_fd(fd: Fd) -> Result<Dir, i32> {
        // SAFETY: fdopendir() takes ownership of a valid directory fd.
        let d = unsafe { libc::fdopendir(fd) };
        if d.is_null() {
            let e = neg_errno();
            close(fd);
            return Err(e);
        }
        Ok(Dir(d))
    }

    /// `readdir()`, skipping nothing. `Ok(None)` at the end.
    pub fn next_entry(&mut self) -> Result<Option<(Vec<u8>, u8)>, i32> {
        set_errno(0);
        // SAFETY: self.0 is a live DIR*.
        let e = unsafe { libc::readdir64(self.0) };
        if e.is_null() {
            let er = errno();
            return if er != 0 { Err(-er) } else { Ok(None) };
        }
        // SAFETY: e points to a valid dirent with a NUL-terminated d_name.
        let (name, ty) = unsafe { (CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec(), (*e).d_type) };
        Ok(Some((name, ty)))
    }

    pub fn fd(&self) -> Fd {
        // SAFETY: self.0 is a live DIR*.
        unsafe { libc::dirfd(self.0) }
    }

    /// `rewinddir()`.
    pub fn rewind(&mut self) {
        // SAFETY: self.0 is a live DIR*.
        unsafe { libc::rewinddir(self.0) }
    }

    /// Give up ownership of the `DIR*`.
    fn into_raw(self) -> *mut libc::DIR {
        let d = self.0;
        std::mem::forget(self);
        d
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: self.0 is a live DIR* we own.
        unsafe { libc::closedir(self.0) };
    }
}

/// `glob(pattern, flags)`: (return code, paths, errno at failure).
pub fn glob(pattern: &[u8], flags: c_int) -> (c_int, Vec<Vec<u8>>, i32) {
    let c = to_cstring(pattern);
    // SAFETY: glob_t is plain old data.
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    set_errno(0);
    // SAFETY: c is NUL-terminated; g is a valid glob_t.
    let r = unsafe { libc::glob(c.as_ptr(), flags, None, &mut g) };
    let e = errno();
    let mut out = Vec::new();
    for i in 0..g.gl_pathc {
        // SAFETY: gl_pathv has gl_pathc valid entries.
        let p = unsafe { *g.gl_pathv.add(i) };
        if !p.is_null() {
            // SAFETY: each entry is a NUL-terminated string.
            out.push(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec());
        }
    }
    // SAFETY: g was filled by glob().
    unsafe { libc::globfree(&mut g) };
    (r, out, e)
}

/// `fnmatch(pattern, s, flags)`.
pub fn fnmatch(pattern: &[u8], s: &[u8], flags: c_int) -> c_int {
    let p = to_cstring(pattern);
    let s = to_cstring(s);
    // SAFETY: both NUL-terminated.
    unsafe { libc::fnmatch(p.as_ptr(), s.as_ptr(), flags) }
}

/// `strtoul(s, &end, base)`: (value, bytes consumed, errno).
pub fn strtoul(s: &[u8], base: c_int) -> (u64, usize, i32) {
    let c = to_cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: c is NUL-terminated and end is a valid out-pointer.
    let v = unsafe { libc::strtoul(c.as_ptr(), &mut end, base) };
    let e = errno();
    // SAFETY: end points into c.
    let consumed = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as u64, consumed, e)
}

/// `strtol(s, &end, base)`: (value, bytes consumed, errno).
pub fn strtol(s: &[u8], base: c_int) -> (i64, usize, i32) {
    let c = to_cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: as in strtoul().
    let v = unsafe { libc::strtol(c.as_ptr(), &mut end, base) };
    let e = errno();
    // SAFETY: end points into c.
    let consumed = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as i64, consumed, e)
}

/// `strtoull(s, &end, base)`: (value, bytes consumed, errno).
pub fn strtoull(s: &[u8], base: c_int) -> (u64, usize, i32) {
    let c = to_cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: as in strtoul().
    let v = unsafe { libc::strtoull(c.as_ptr(), &mut end, base) };
    let e = errno();
    // SAFETY: end points into c.
    let consumed = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as u64, consumed, e)
}

/// `setlocale(LC_ALL, "")`: false if it failed.
pub fn setlocale_all_default() -> bool {
    // SAFETY: the empty string is a valid locale argument.
    !unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) }.is_null()
}

/// `setlocale(LC_CTYPE, NULL)`.
pub fn setlocale_ctype_query() -> Option<Vec<u8>> {
    // SAFETY: a NULL locale argument only queries.
    let p = unsafe { libc::setlocale(libc::LC_CTYPE, std::ptr::null()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: setlocale returns a NUL-terminated string.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `nl_langinfo(CODESET)`.
pub fn langinfo_codeset() -> Option<Vec<u8>> {
    // SAFETY: nl_langinfo() returns a static string or NULL.
    let p = unsafe { libc::nl_langinfo(libc::CODESET) };
    if p.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `setlogmask(LOG_UPTO(level))`.
pub fn setlogmask_upto(level: i32) {
    let mask = if level < 0 { 0 } else { (1 << (level + 1)) - 1 };
    // SAFETY: setlogmask() has no memory preconditions.
    unsafe { libc::setlogmask(mask) };
}

/// The current `CLOCK_REALTIME` in microseconds.
pub fn now_realtime_usec() -> u64 {
    clock_usec(libc::CLOCK_REALTIME)
}

pub fn clock_usec(clock: libc::clockid_t) -> u64 {
    // SAFETY: timespec is plain old data.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: ts is a valid out-pointer.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000
}

/// `localtime_r(t)`.
pub fn localtime(t: i64) -> Option<libc::tm> {
    // SAFETY: tm is plain old data.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tt = t as libc::time_t;
    // SAFETY: both pointers are valid.
    if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() { None } else { Some(tm) }
}

/// `gmtime_r(t)`.
pub fn gmtime(t: i64) -> Option<libc::tm> {
    // SAFETY: tm is plain old data.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tt = t as libc::time_t;
    // SAFETY: both pointers are valid.
    if unsafe { libc::gmtime_r(&tt, &mut tm) }.is_null() { None } else { Some(tm) }
}

/// `tm.tm_zone`.
pub fn tm_zone(tm: &libc::tm) -> Option<Vec<u8>> {
    if tm.tm_zone.is_null() {
        return None;
    }
    // SAFETY: tm_zone points to a NUL-terminated string set by localtime_r().
    Some(unsafe { CStr::from_ptr(tm.tm_zone) }.to_bytes().to_vec())
}

/// `strftime(buf, size, fmt, tm)`; `None` when it returns 0.
pub fn strftime(fmt: &CStr, tm: &libc::tm, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    // SAFETY: buf is valid for size bytes, fmt is NUL-terminated.
    let n = unsafe { libc::strftime(buf.as_mut_ptr() as *mut c_char, size, fmt.as_ptr(), tm) };
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// `uname()`'s nodename.
pub fn uname_nodename() -> Result<Vec<u8>, i32> {
    // SAFETY: utsname is plain old data.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is a valid out-pointer.
    if unsafe { libc::uname(&mut u) } < 0 {
        return Err(neg_errno());
    }
    // SAFETY: nodename is NUL-terminated.
    Ok(unsafe { CStr::from_ptr(u.nodename.as_ptr()) }.to_bytes().to_vec())
}

/// `fork()`.
pub fn fork() -> Result<i32, i32> {
    // SAFETY: the callers only use async-signal-safe calls (and exec) in the child.
    let r = unsafe { libc::fork() };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `waitid(P_PID, pid, WEXITED)`, retrying on EINTR.
pub fn wait_for_terminate(pid: i32) -> Result<(), i32> {
    loop {
        // SAFETY: siginfo_t is plain old data.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: si is a valid out-pointer.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
        if r >= 0 {
            return Ok(());
        }
        if errno() != libc::EINTR {
            return Err(neg_errno());
        }
    }
}

pub fn kill(pid: i32, sig: c_int) -> Result<(), i32> {
    // SAFETY: kill() has no memory preconditions.
    if unsafe { libc::kill(pid, sig) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `_exit(code)`.
pub fn exit_now(code: c_int) -> ! {
    // SAFETY: _exit() never returns.
    unsafe { libc::_exit(code) }
}

/// `prctl(PR_SET_PDEATHSIG, sig)`.
pub fn set_pdeathsig(sig: c_int) -> Result<(), i32> {
    // SAFETY: PR_SET_PDEATHSIG takes an int.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `prctl(PR_SET_NAME, name)`.
pub fn set_comm(name: &[u8]) {
    let c = to_cstring(name);
    // SAFETY: c is NUL-terminated; the kernel truncates to 15 bytes.
    unsafe { libc::prctl(libc::PR_SET_NAME, c.as_ptr() as libc::c_ulong) };
}

pub fn getppid() -> i32 {
    // SAFETY: getppid() has no preconditions.
    unsafe { libc::getppid() }
}

/// Reset every signal to SIG_DFL and unblock all signals (systemd's
/// `reset_all_signal_handlers()` plus `reset_signal_mask()`).
pub fn reset_signals() {
    for sig in 1..libc::SIGRTMAX() {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        // SAFETY: sigaction is plain old data; installing SIG_DFL is always valid.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    // SAFETY: an empty sigset unblocks everything.
    unsafe {
        let mut ss: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut ss);
        libc::sigprocmask(libc::SIG_SETMASK, &ss, std::ptr::null_mut());
    }
}

/// `sigaction(sig, SIG_IGN)`.
pub fn ignore_signal(sig: c_int) {
    // SAFETY: installing SIG_IGN is always valid.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

/// `getrlimit(RLIMIT_NOFILE)`: (soft, hard).
pub fn getrlimit_nofile() -> Result<(u64, u64), i32> {
    // SAFETY: rlimit is plain old data and the pointer is valid.
    unsafe {
        let mut rl: libc::rlimit64 = std::mem::zeroed();
        if libc::getrlimit64(libc::RLIMIT_NOFILE, &mut rl) < 0 {
            return Err(neg_errno());
        }
        Ok((rl.rlim_cur, rl.rlim_max))
    }
}

/// `setrlimit(RLIMIT_NOFILE, {soft, hard})`.
pub fn setrlimit_nofile(soft: u64, hard: u64) -> Result<(), i32> {
    let rl = libc::rlimit64 { rlim_cur: soft, rlim_max: hard };
    // SAFETY: rl is a valid rlimit.
    if unsafe { libc::setrlimit64(libc::RLIMIT_NOFILE, &rl) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `execvp(file, argv)`; returns only on failure, with errno set.
pub fn execvp(file: &[u8], args: &[Vec<u8>]) {
    let f = to_cstring(file);
    let cargs: Vec<CString> = args.iter().map(|a| to_cstring(a)).collect();
    let mut ptrs: Vec<*const c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: f and every argument are NUL-terminated; ptrs ends in NULL.
    unsafe { libc::execvp(f.as_ptr(), ptrs.as_ptr()) };
}

/// The real uid/gid in `/proc/self/status`-free form: `getauxval(AT_SECURE)`.
pub fn at_secure() -> bool {
    // SAFETY: getauxval() has no preconditions.
    unsafe { libc::getauxval(libc::AT_SECURE) != 0 }
}

/// `sysconf(_SC_PAGESIZE)`.
pub fn page_size() -> usize {
    // SAFETY: sysconf() has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// `malloc_usable_size(malloc(n))`: read_virtual_file() sizes its buffer
/// with it, so the read size matches C's.
pub fn malloc_usable(n: usize) -> usize {
    // SAFETY: the block is freed right away.
    unsafe {
        let p = libc::malloc(n);
        if p.is_null() {
            return n;
        }
        let u = libc::malloc_usable_size(p);
        libc::free(p);
        u
    }
}

/// `mkostemp`-style creation: `open(path, O_CREAT|O_EXCL|...)`.
pub fn open_excl(path: &[u8], flags: c_int, mode: u32) -> Result<Fd, i32> {
    open(path, flags | libc::O_CREAT | libc::O_EXCL, mode)
}

/// `getrandom(buf, 0)`, falling back to nothing.
pub fn getrandom(buf: &mut [u8]) -> Result<(), i32> {
    // SAFETY: buf is valid for buf.len() bytes.
    let n = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    if n < 0 || n as usize != buf.len() { Err(-libc::EIO) } else { Ok(()) }
}

/// An fd closed on drop (`_cleanup_close_`).
#[derive(Debug)]
pub struct OwnedFd(Fd);

impl OwnedFd {
    pub fn new(fd: Fd) -> OwnedFd {
        OwnedFd(fd)
    }

    pub fn raw(&self) -> Fd {
        self.0
    }

    /// `TAKE_FD()`.
    pub fn into_raw(self) -> Fd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            close(self.0);
        }
    }
}

/// What chase() needs from `statx()`: type, uid, inode, and the mount id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statx {
    pub mode: u32,
    pub uid: u32,
    pub ino: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub mnt_id: Option<u64>,
}

/// `statx(fd, "", AT_EMPTY_PATH, STATX_TYPE|STATX_UID|STATX_INO|STATX_MNT_ID)`.
pub fn statx_fd(fd: Fd) -> Result<Statx, i32> {
    statx_at(fd, b"", libc::AT_EMPTY_PATH)
}

/// `statx(dirfd, path, flags, STATX_TYPE|STATX_UID|STATX_INO|STATX_MNT_ID)`.
pub fn statx_at(dirfd: Fd, path: &[u8], flags: c_int) -> Result<Statx, i32> {
    let c = to_cstring(path);
    // SAFETY: statx is plain old data.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_TYPE | libc::STATX_UID | libc::STATX_INO | libc::STATX_MNT_ID;
    // SAFETY: c is NUL-terminated and sx a valid out-pointer.
    let r = unsafe { libc::statx(dirfd, c.as_ptr(), flags, mask, &mut sx) };
    if r < 0 {
        return Err(neg_errno());
    }
    Ok(Statx {
        mode: sx.stx_mode as u32,
        uid: sx.stx_uid,
        ino: sx.stx_ino,
        dev_major: sx.stx_dev_major,
        dev_minor: sx.stx_dev_minor,
        mnt_id: if sx.stx_mask & libc::STATX_MNT_ID != 0 { Some(sx.stx_mnt_id) } else { None },
    })
}

/// `getpwuid_r(uid)`'s `pw_name`.
pub fn getpwuid_name(uid: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: passwd is plain old data.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid; buf outlives the use of pw.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    // SAFETY: pw_name points into buf and is NUL-terminated.
    Some(unsafe { CStr::from_ptr(pw.pw_name) }.to_bytes().to_vec())
}

/// `getgrgid_r(gid)`'s `gr_name`.
pub fn getgrgid_name(gid: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: group is plain old data.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid; buf outlives the use of gr.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    // SAFETY: gr_name points into buf and is NUL-terminated.
    Some(unsafe { CStr::from_ptr(gr.gr_name) }.to_bytes().to_vec())
}

pub fn fsync(fd: Fd) -> Result<(), i32> {
    // SAFETY: fsync() has no memory preconditions.
    if unsafe { libc::fsync(fd) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `sigprocmask(SIG_BLOCK, all)`: returns the old mask.
pub fn block_all_signals() -> libc::sigset_t {
    // SAFETY: sigset_t is plain old data and the pointers are valid.
    unsafe {
        let mut ss: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut ss);
        libc::sigprocmask(libc::SIG_BLOCK, &ss, &mut old);
        old
    }
}

/// `sigprocmask(SIG_SETMASK, saved)`.
pub fn restore_signal_mask(saved: &libc::sigset_t) {
    // SAFETY: saved is a valid sigset.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, saved, std::ptr::null_mut()) };
}

pub fn fchmodat(dirfd: Fd, path: &[u8], mode: u32) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::fchmodat(dirfd, c.as_ptr(), mode, 0) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// glibc's `glob_t`, including the GLOB_ALTDIRFUNC hooks the libc crate hides.
#[repr(C)]
struct GlobT {
    gl_pathc: libc::size_t,
    gl_pathv: *mut *mut c_char,
    gl_offs: libc::size_t,
    gl_flags: c_int,
    gl_closedir: Option<unsafe extern "C" fn(*mut c_void)>,
    gl_readdir: Option<unsafe extern "C" fn(*mut c_void) -> *mut libc::dirent>,
    gl_opendir: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
    gl_lstat: Option<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>,
    gl_stat: Option<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>,
}

unsafe extern "C" {
    #[link_name = "glob"]
    fn glob_c(pattern: *const c_char, flags: c_int, errfunc: *const c_void, pglob: *mut GlobT) -> c_int;
    #[link_name = "globfree"]
    fn globfree_c(pglob: *mut GlobT);
}

unsafe extern "C" fn closedir_wrapper(d: *mut c_void) {
    // SAFETY: glob passes back the DIR* our opendir hook returned.
    unsafe { libc::closedir(d as *mut libc::DIR) };
}

/// `readdir_no_dot()`.
unsafe extern "C" fn readdir_no_dot(d: *mut c_void) -> *mut libc::dirent {
    loop {
        // SAFETY: d is the DIR* from our opendir hook.
        let e = unsafe { libc::readdir(d as *mut libc::DIR) };
        if e.is_null() {
            return e;
        }
        // SAFETY: e is a valid dirent with a NUL-terminated name.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            return e;
        }
    }
}

/// The `opendir_func` of `safe_glob_full()`, if not plain opendir().
pub type OpendirFn = fn(&[u8]) -> Result<Dir, i32>;

thread_local! {
    static GLOB_OPENDIR: std::cell::Cell<Option<OpendirFn>> = const { std::cell::Cell::new(None) };
}

unsafe extern "C" fn opendir_hook(p: *const c_char) -> *mut c_void {
    if let Some(f) = GLOB_OPENDIR.with(|g| g.get()) {
        // SAFETY: glob passes a NUL-terminated path.
        let path = unsafe { CStr::from_ptr(p) }.to_bytes();
        return match f(path) {
            Ok(d) => d.into_raw() as *mut c_void,
            Err(e) => {
                set_errno(-e);
                std::ptr::null_mut()
            }
        };
    }
    // SAFETY: glob passes a NUL-terminated path.
    unsafe { libc::opendir(p) as *mut c_void }
}

unsafe extern "C" fn lstat_hook(p: *const c_char, st: *mut libc::stat) -> c_int {
    // SAFETY: glob passes valid pointers.
    unsafe { libc::lstat(p, st) }
}

unsafe extern "C" fn stat_hook(p: *const c_char, st: *mut libc::stat) -> c_int {
    // SAFETY: glob passes valid pointers.
    unsafe { libc::stat(p, st) }
}

/// `safe_glob_full(path, flags, NULL)`: glob() with GLOB_ALTDIRFUNC and
/// `readdir_no_dot()`, so "." and ".." never match.  (rc, paths, errno).
pub fn safe_glob_raw(pattern: &[u8], flags: c_int) -> (c_int, Vec<Vec<u8>>, i32) {
    safe_glob_raw_with(pattern, flags, None)
}

/// `safe_glob_full(path, flags, opendir_func)`: like `safe_glob_raw()`.
pub fn safe_glob_raw_with(pattern: &[u8], flags: c_int, opendir: Option<OpendirFn>) -> (c_int, Vec<Vec<u8>>, i32) {
    let saved = GLOB_OPENDIR.with(|g| g.replace(opendir));
    let r = safe_glob_inner(pattern, flags);
    GLOB_OPENDIR.with(|g| g.set(saved));
    r
}

fn safe_glob_inner(pattern: &[u8], flags: c_int) -> (c_int, Vec<Vec<u8>>, i32) {
    let c = to_cstring(pattern);
    let mut g = GlobT {
        gl_pathc: 0,
        gl_pathv: std::ptr::null_mut(),
        gl_offs: 0,
        gl_flags: 0,
        gl_closedir: Some(closedir_wrapper),
        gl_readdir: Some(readdir_no_dot),
        gl_opendir: Some(opendir_hook),
        gl_lstat: Some(lstat_hook),
        gl_stat: Some(stat_hook),
    };
    set_errno(0);
    // SAFETY: c is NUL-terminated and g is a valid glob_t with all hooks set.
    let r = unsafe { glob_c(c.as_ptr(), flags | libc::GLOB_ALTDIRFUNC, std::ptr::null(), &mut g) };
    let e = errno();
    let mut out = Vec::new();
    for i in 0..g.gl_pathc {
        // SAFETY: gl_pathv has gl_pathc valid entries.
        let p = unsafe { *g.gl_pathv.add(i) };
        if !p.is_null() {
            // SAFETY: each entry is NUL-terminated.
            out.push(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec());
        }
    }
    // SAFETY: g was filled by glob().
    unsafe { globfree_c(&mut g) };
    (r, out, e)
}

unsafe extern "C" {
    static mut program_invocation_name: *mut c_char;
}

/// The original argv[0] (glibc's `program_invocation_name`).
pub fn invocation_name() -> Vec<u8> {
    // SAFETY: glibc sets program_invocation_name to argv[0] before main().
    let p = unsafe { program_invocation_name };
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: argv[0] is NUL-terminated.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// `strncpy(program_invocation_name, name, strlen(...))`, then zero the
/// other argv strings, which follow argv[0] in memory (their lengths are
/// `rest`).  Returns the new argv[0] as C now sees it.
pub fn rewrite_argv(name: &[u8], rest: &[usize]) -> Vec<u8> {
    // SAFETY: argv[0] and the argv strings after it are writable memory of
    // the lengths std read at startup; we never write past them.
    unsafe {
        let p = program_invocation_name as *mut u8;
        if p.is_null() {
            return Vec::new();
        }
        let k = libc::strlen(p as *const c_char);
        for i in 0..k {
            *p.add(i) = if i < name.len() { name[i] } else { 0 };
        }
        let mut q = p.add(k + 1);
        for &len in rest {
            std::ptr::write_bytes(q, 0, len);
            q = q.add(len + 1);
        }
        CStr::from_ptr(p as *const c_char).to_bytes().to_vec()
    }
}

/// `have_effective_cap(cap)`.
pub fn have_effective_cap(cap: u32) -> Result<bool, i32> {
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut h = Hdr { version: 0x20080522, pid: 0 };
    let mut d = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: capget with a v3 header and room for two data structs.
    let r = unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut Hdr, d.as_mut_ptr()) };
    if r < 0 {
        return Err(neg_errno());
    }
    let (i, bit) = ((cap / 32) as usize, cap % 32);
    Ok(d[i].effective & (1 << bit) != 0)
}

/// mmap() an anonymous page-aligned buffer holding `name` + NUL, for
/// PR_SET_MM_ARG_START/END: (address, size).
pub fn mmap_name(name: &[u8]) -> Result<(usize, usize), i32> {
    let ps = page_size();
    let size = (name.len() + 1).div_ceil(ps) * ps;
    // SAFETY: an anonymous private mapping; no existing memory is touched.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(neg_errno());
    }
    // SAFETY: p is a fresh mapping of size bytes; strncpy semantics (rest is zero already).
    unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), p as *mut u8, name.len().min(size)) };
    Ok((p as usize, size))
}

pub fn munmap(addr: usize, size: usize) {
    // SAFETY: unmapping a region we mapped.
    unsafe { libc::munmap(addr as *mut c_void, size) };
}

/// `prctl(PR_SET_MM, what, value)`.
pub fn prctl_set_mm(what: c_int, value: usize) -> Result<(), i32> {
    // SAFETY: PR_SET_MM only changes this process's mm fields; failure is reported.
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_MM,
            what as libc::c_ulong,
            value as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `prctl(PR_SET_NAME, name)`, reporting failure.
pub fn try_set_comm(name: &[u8]) -> Result<(), i32> {
    let mut buf = [0u8; 16];
    let n = name.len().min(15);
    buf[..n].copy_from_slice(&name[..n]);
    // SAFETY: buf is NUL-terminated.
    if unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `getpwuid_r(uid)`'s `pw_dir`.
pub fn getpwuid_dir(uid: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: passwd is plain old data.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid; buf outlives the use of pw.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into buf and is NUL-terminated.
    Some(unsafe { CStr::from_ptr(pw.pw_dir) }.to_bytes().to_vec())
}

/// `uname()`'s machine and release.
pub fn uname_machine_release() -> Result<(Vec<u8>, Vec<u8>), i32> {
    // SAFETY: utsname is plain old data.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is a valid out-pointer.
    if unsafe { libc::uname(&mut u) } < 0 {
        return Err(neg_errno());
    }
    // SAFETY: both fields are NUL-terminated.
    unsafe {
        Ok((
            CStr::from_ptr(u.machine.as_ptr()).to_bytes().to_vec(),
            CStr::from_ptr(u.release.as_ptr()).to_bytes().to_vec(),
        ))
    }
}

pub fn getgid() -> u32 {
    // SAFETY: getgid() has no preconditions.
    unsafe { libc::getgid() }
}

/// `statfs(path).f_type`.
pub fn statfs_type(path: &[u8]) -> Result<i64, i32> {
    let c = to_cstring(path);
    // SAFETY: statfs is plain old data; c is NUL-terminated.
    let mut s: StatFs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::statfs64(c.as_ptr(), &mut s) } < 0 {
        return Err(neg_errno());
    }
    Ok(f_type(&s))
}

/// `fstatfs(fd).f_type`.
pub fn fstatfs_type(fd: Fd) -> Result<i64, i32> {
    // SAFETY: statfs is plain old data.
    let mut s: StatFs = unsafe { std::mem::zeroed() };
    // SAFETY: s is a valid out-pointer.
    if unsafe { libc::fstatfs64(fd, &mut s) } < 0 {
        return Err(neg_errno());
    }
    Ok(f_type(&s))
}

/// `strtoll(s, &end, base)`: (value, bytes consumed, errno).
pub fn strtoll(s: &[u8], base: c_int) -> (i64, usize, i32) {
    let c = to_cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: c is NUL-terminated and end is a valid out-pointer.
    let v = unsafe { libc::strtoll(c.as_ptr(), &mut end, base) };
    let e = errno();
    // SAFETY: end points into c.
    let consumed = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v, consumed, e)
}

/// Every (name, uid) from a passwd-format file, via `fgetpwent()` (an
/// error ends the list quietly, as in `populate_uid_cache()`).  Takes fd.
pub fn fgetpwent_all(fd: Fd) -> Vec<(Vec<u8>, u32)> {
    // SAFETY: fd is ours; fdopen() takes ownership of it.
    let f = unsafe { libc::fdopen(fd, c"r".as_ptr()) };
    if f.is_null() {
        close(fd);
        return Vec::new();
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: f is a valid FILE*; the returned record is copied right away.
        let p = unsafe { fgetpwent(f) };
        if p.is_null() {
            break;
        }
        // SAFETY: p points to a valid passwd record.
        unsafe { out.push((CStr::from_ptr((*p).pw_name).to_bytes().to_vec(), (*p).pw_uid)) };
    }
    // SAFETY: closing the FILE* we opened.
    unsafe { libc::fclose(f) };
    out
}

/// Every (name, gid) from a group-format file, via `fgetgrent()`.  Takes fd.
pub fn fgetgrent_all(fd: Fd) -> Vec<(Vec<u8>, u32)> {
    // SAFETY: fd is ours; fdopen() takes ownership of it.
    let f = unsafe { libc::fdopen(fd, c"r".as_ptr()) };
    if f.is_null() {
        close(fd);
        return Vec::new();
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: f is a valid FILE*; the returned record is copied right away.
        let p = unsafe { fgetgrent(f) };
        if p.is_null() {
            break;
        }
        // SAFETY: p points to a valid group record.
        unsafe { out.push((CStr::from_ptr((*p).gr_name).to_bytes().to_vec(), (*p).gr_gid)) };
    }
    // SAFETY: closing the FILE* we opened.
    unsafe { libc::fclose(f) };
    out
}

/// `getpwnam_r(name)`: Ok(Some((uid, gid))), Ok(None) if absent, Err(-errno).
pub fn getpwnam_ids(name: &[u8]) -> Result<Option<(u32, u32, Vec<u8>)>, i32> {
    let n = to_cstring(name);
    let mut size = 16384usize;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: passwd is plain old data.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call.
        let r = unsafe { libc::getpwnam_r(n.as_ptr(), &mut pw, buf.as_mut_ptr() as *mut c_char, size, &mut res) };
        if r == 0 {
            if res.is_null() {
                return Ok(None);
            }
            // SAFETY: pw_name points into buf.
            let nm = unsafe { CStr::from_ptr(pw.pw_name) }.to_bytes().to_vec();
            return Ok(Some((pw.pw_uid, pw.pw_gid, nm)));
        }
        if r != libc::ERANGE {
            return Err(-r);
        }
        size *= 2;
    }
}

/// `getgrnam_r(name)`: Ok(Some(gid)), Ok(None) if absent, Err(-errno).
pub fn getgrnam_id(name: &[u8]) -> Result<Option<u32>, i32> {
    let n = to_cstring(name);
    let mut size = 16384usize;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: group is plain old data.
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call.
        let r = unsafe { libc::getgrnam_r(n.as_ptr(), &mut gr, buf.as_mut_ptr() as *mut c_char, size, &mut res) };
        if r == 0 {
            return Ok(if res.is_null() { None } else { Some(gr.gr_gid) });
        }
        if r != libc::ERANGE {
            return Err(-r);
        }
        size *= 2;
    }
}

/// `getpwuid_r(uid)` existence: Ok(true/false), Err(-errno).
pub fn getpwuid_exists(uid: u32) -> Result<bool, i32> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: passwd is plain old data.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res) };
    if r != 0 {
        return Err(-r);
    }
    Ok(!res.is_null())
}

/// `getgrgid_r(gid)` existence: Ok(true/false), Err(-errno).
pub fn getgrgid_exists(gid: u32) -> Result<bool, i32> {
    let mut buf = vec![0u8; 16384];
    // SAFETY: group is plain old data.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut res) };
    if r != 0 {
        return Err(-r);
    }
    Ok(!res.is_null())
}

/// `fd_is_opath()`.
pub fn fd_is_opath(fd: Fd) -> Result<bool, i32> {
    // SAFETY: F_GETFL takes no argument.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if r < 0 {
        return Err(neg_errno());
    }
    Ok(r & libc::O_PATH != 0)
}

/// `getxattr(path, name)` (follow) or `fgetxattr(fd, name)`: the value.
pub fn getxattr_any(fd: Option<Fd>, path: &[u8], name: &[u8]) -> Result<Vec<u8>, i32> {
    let n = to_cstring(name);
    let p = to_cstring(path);
    let call = |buf: *mut c_void, size: usize| -> isize {
        // SAFETY: buf is NULL with size 0 or valid for size bytes; names are NUL-terminated.
        unsafe {
            match fd {
                Some(fd) => libc::fgetxattr(fd, n.as_ptr(), buf, size),
                None => libc::getxattr(p.as_ptr(), n.as_ptr(), buf, size),
            }
        }
    };
    for _ in 0..7 {
        let l = call(std::ptr::null_mut(), 0);
        if l < 0 {
            return Err(neg_errno());
        }
        let mut v = vec![0u8; l as usize + 1];
        let k = call(v.as_mut_ptr() as *mut c_void, v.len());
        if k >= 0 {
            v.truncate(k as usize);
            return Ok(v);
        }
        if errno() != libc::ERANGE {
            return Err(neg_errno());
        }
    }
    Err(-libc::EBUSY)
}

/// `setxattr(path, name, value)` (follow) or `fsetxattr(fd, ...)`.
pub fn setxattr_any(fd: Option<Fd>, path: &[u8], name: &[u8], value: &[u8], flags: c_int) -> Result<(), i32> {
    let n = to_cstring(name);
    let p = to_cstring(path);
    // SAFETY: value is valid for value.len() bytes; names are NUL-terminated.
    let r = unsafe {
        match fd {
            Some(fd) => libc::fsetxattr(fd, n.as_ptr(), value.as_ptr() as *const c_void, value.len(), flags),
            None => libc::setxattr(p.as_ptr(), n.as_ptr(), value.as_ptr() as *const c_void, value.len(), flags),
        }
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `ioctl(fd, FS_IOC_GETFLAGS)`.
pub fn fs_ioc_getflags(fd: Fd) -> Result<u32, i32> {
    let mut v: c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int.
    if unsafe { libc::ioctl(fd, libc::FS_IOC_GETFLAGS, &mut v) } < 0 {
        return Err(neg_errno());
    }
    Ok(v as u32)
}

/// `ioctl(fd, FS_IOC_SETFLAGS, &v)`.
pub fn fs_ioc_setflags(fd: Fd, v: u32) -> Result<(), i32> {
    let v = v as c_int;
    // SAFETY: FS_IOC_SETFLAGS reads an int.
    if unsafe { libc::ioctl(fd, libc::FS_IOC_SETFLAGS, &v) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `statx(dirfd, path, flags, mask)`: the raw result.
pub fn statx_raw(dirfd: Fd, path: &[u8], flags: c_int, mask: u32) -> Result<libc::statx, i32> {
    let c = to_cstring(path);
    // SAFETY: statx is plain old data.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and sx a valid out-pointer.
    if unsafe { libc::statx(dirfd, c.as_ptr(), flags, mask, &mut sx) } < 0 {
        return Err(neg_errno());
    }
    Ok(sx)
}

/// `flock(fd, op)`.
pub fn flock(fd: Fd, op: c_int) -> Result<(), i32> {
    // SAFETY: plain syscall.
    if unsafe { libc::flock(fd, op) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `futimens(fd, ts)`; None is `UTIME_OMIT`.
pub fn futimens(fd: Fd, atime_nsec: Option<u64>, mtime_nsec: Option<u64>) -> Result<(), i32> {
    let t = |v: Option<u64>| match v {
        Some(n) => libc::timespec { tv_sec: (n / 1_000_000_000) as libc::time_t, tv_nsec: (n % 1_000_000_000) as _ },
        None => libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
    };
    let ts = [t(atime_nsec), t(mtime_nsec)];
    // SAFETY: ts holds two valid timespecs.
    if unsafe { libc::futimens(fd, ts.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// glibc's `fchmodat(fd, path, mode, flags)` (with AT_EMPTY_PATH support).
pub fn fchmodat_flags(dirfd: Fd, path: &[u8], mode: u32, flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::fchmodat(dirfd, c.as_ptr(), mode, flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// The raw `fchmodat2()` syscall.
pub fn fchmodat2(dirfd: Fd, path: &[u8], mode: u32, flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated; fchmodat2 takes (int, const char*, mode_t, int).
    if unsafe { libc::syscall(452, dirfd, c.as_ptr(), mode, flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `chmod(path, mode)`.
pub fn chmod(path: &[u8], mode: u32) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::chmod(c.as_ptr(), mode) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `fchownat(fd, path, uid, gid, flags)`; `u32::MAX` leaves an id alone.
pub fn fchownat(dirfd: Fd, path: &[u8], uid: u32, gid: u32, flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::fchownat(dirfd, c.as_ptr(), uid, gid, flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `mknodat(dirfd, path, mode, dev)`.
pub fn mknodat(dirfd: Fd, path: &[u8], mode: u32, dev: u64) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::mknodat(dirfd, c.as_ptr(), mode, dev) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `mkfifoat(dirfd, path, mode)`.
pub fn mkfifoat(dirfd: Fd, path: &[u8], mode: u32) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::mkfifoat(dirfd, c.as_ptr(), mode) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `symlinkat(target, dirfd, path)`.
pub fn symlinkat(target: &[u8], dirfd: Fd, path: &[u8]) -> Result<(), i32> {
    let t = to_cstring(target);
    let c = to_cstring(path);
    // SAFETY: both are NUL-terminated.
    if unsafe { libc::symlinkat(t.as_ptr(), dirfd, c.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `remove(path)`.
pub fn remove(path: &[u8]) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::remove(c.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `rmdir(path)`.
pub fn rmdir(path: &[u8]) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::rmdir(c.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `ftruncate(fd, len)`.
pub fn ftruncate(fd: Fd, len: i64) -> Result<(), i32> {
    // SAFETY: plain syscall.
    if unsafe { libc::ftruncate64(fd, len) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `syncfs(fd)`.
pub fn syncfs(fd: Fd) -> Result<(), i32> {
    // SAFETY: plain syscall.
    if unsafe { libc::syncfs(fd) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `faccessat(dirfd, path, mode, flags)`.
pub fn faccessat(dirfd: Fd, path: &[u8], mode: c_int, flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    if unsafe { libc::faccessat(dirfd, c.as_ptr(), mode, flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `getdents64()` on fd: are there entries other than the ones `skip` matches?
pub fn dir_has_entry(fd: Fd, skip: &dyn Fn(&[u8]) -> bool) -> Result<bool, i32> {
    let mut buf = vec![0u8; 16 * 280];
    loop {
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(neg_errno());
        }
        if n == 0 {
            return Ok(false);
        }
        let mut off = 0usize;
        while off < n as usize {
            // linux_dirent64: d_ino u64, d_off i64, d_reclen u16, d_type u8, d_name[].
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let name = &buf[off + 19..off + reclen];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            if !skip(name) {
                return Ok(true);
            }
            off += reclen;
        }
    }
}

/// `fstatfs(fd)`: the whole struct.
pub fn fstatfs(fd: Fd) -> Result<StatFs, i32> {
    // SAFETY: statfs is plain old data.
    let mut s: StatFs = unsafe { std::mem::zeroed() };
    // SAFETY: s is a valid out-pointer.
    if unsafe { libc::fstatfs64(fd, &mut s) } < 0 {
        return Err(neg_errno());
    }
    Ok(s)
}

/// `ioctl(fd, req, arg)` for the btrfs ioctls, which all take a pointer to
/// a plain-old-data struct (`T` must be one); returns the ioctl's value.
pub fn ioctl_ptr<T: Copy>(fd: Fd, req: u64, arg: &mut T) -> Result<c_int, i32> {
    // SAFETY: arg is a valid, writable T of the size the request encodes.
    let r = unsafe { libc::ioctl(fd, req as _, arg as *mut T) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `ioctl(fd, req, value)` with an integer argument.
pub fn ioctl_int(fd: Fd, req: u64, value: libc::c_ulong) -> Result<c_int, i32> {
    // SAFETY: the request takes its argument by value, no pointers.
    let r = unsafe { libc::ioctl(fd, req as _, value) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `ioctl(fd, req)` with no argument.
pub fn ioctl_none(fd: Fd, req: u64) -> Result<c_int, i32> {
    // SAFETY: the request takes no argument.
    let r = unsafe { libc::ioctl(fd, req as _) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `prctl(PR_CAPBSET_READ, cap)`.
pub fn capbset_read(cap: i32) -> Result<bool, i32> {
    // SAFETY: PR_CAPBSET_READ takes an unsigned long and no pointers.
    let r = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) };
    if r < 0 { Err(neg_errno()) } else { Ok(r > 0) }
}

/// `flistxattr(fd)`: the NUL-separated names.
pub fn flistxattr(fd: Fd) -> Result<Vec<u8>, i32> {
    loop {
        // SAFETY: a NULL buffer with size 0 asks for the size.
        let l = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if l < 0 {
            return Err(neg_errno());
        }
        let mut v = vec![0u8; l as usize];
        // SAFETY: v is valid for v.len() bytes.
        let k = unsafe { libc::flistxattr(fd, v.as_mut_ptr() as *mut c_char, v.len()) };
        if k >= 0 {
            v.truncate(k as usize);
            return Ok(v);
        }
        if errno() != libc::ERANGE {
            return Err(neg_errno());
        }
    }
}

/// `utimensat(dirfd, path, {atime, mtime}, flags)`, nanosecond timestamps.
pub fn utimensat(dirfd: Fd, path: &[u8], atime: (i64, i64), mtime: (i64, i64), flags: c_int) -> Result<(), i32> {
    let c = to_cstring(path);
    let ts = [
        libc::timespec { tv_sec: atime.0 as libc::time_t, tv_nsec: atime.1 as _ },
        libc::timespec { tv_sec: mtime.0 as libc::time_t, tv_nsec: mtime.1 as _ },
    ];
    // SAFETY: c is NUL-terminated and ts holds two timespecs.
    if unsafe { libc::utimensat(dirfd, c.as_ptr(), ts.as_ptr(), flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `futimens(fd, {atime, mtime})`, nanosecond timestamps.
pub fn futimens_ts(fd: Fd, atime: (i64, i64), mtime: (i64, i64)) -> Result<(), i32> {
    let ts = [
        libc::timespec { tv_sec: atime.0 as libc::time_t, tv_nsec: atime.1 as _ },
        libc::timespec { tv_sec: mtime.0 as libc::time_t, tv_nsec: mtime.1 as _ },
    ];
    // SAFETY: ts holds two timespecs.
    if unsafe { libc::futimens(fd, ts.as_ptr()) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `linkat(olddir, old, newdir, new, flags)`.
pub fn linkat(olddir: Fd, old: &[u8], newdir: Fd, new: &[u8], flags: c_int) -> Result<(), i32> {
    let o = to_cstring(old);
    let n = to_cstring(new);
    // SAFETY: both are NUL-terminated.
    if unsafe { libc::linkat(olddir, o.as_ptr(), newdir, n.as_ptr(), flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `fchown(fd, uid, gid)`.
pub fn fchown(fd: Fd, uid: u32, gid: u32) -> Result<(), i32> {
    // SAFETY: plain syscall.
    if unsafe { libc::fchown(fd, uid, gid) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `ioctl(outfd, FICLONE, infd)`.
pub fn ficlone(outfd: Fd, infd: Fd) -> Result<(), i32> {
    // SAFETY: FICLONE takes the source fd as its argument.
    if unsafe { libc::ioctl(outfd, libc::FICLONE as _, infd) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `copy_file_range(infd, NULL, outfd, NULL, len, 0)`.
pub fn copy_file_range(infd: Fd, outfd: Fd, len: usize) -> Result<usize, i32> {
    // SAFETY: NULL offsets use and advance the file positions.
    let n = unsafe { libc::copy_file_range(infd, std::ptr::null_mut(), outfd, std::ptr::null_mut(), len, 0) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// The SIGPIPE disposition the process was started with, recorded before
/// Rust's runtime sets it to SIG_IGN (usize::MAX: not recorded).
static INHERITED_SIGPIPE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

extern "C" fn record_sigpipe() {
    // SAFETY: sigaction with a NULL new action only reads the current one.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: old is a valid out-pointer.
    if unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut old) } == 0 {
        INHERITED_SIGPIPE.store(old.sa_sigaction, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Runs before main(), and so before the Rust runtime's own setup.
#[used]
#[unsafe(link_section = ".init_array")]
static RECORD_SIGPIPE: extern "C" fn() = record_sigpipe;

/// Put SIGPIPE back the way it was inherited, as a C program has it.
pub fn restore_inherited_sigpipe() {
    let h = INHERITED_SIGPIPE.load(std::sync::atomic::Ordering::Relaxed);
    let h = if h == usize::MAX { libc::SIG_DFL } else { h };
    // SAFETY: h is SIG_DFL, SIG_IGN or the handler we were started with.
    unsafe { libc::signal(libc::SIGPIPE, h) };
}

/// `execve(path, argv, envp)`: only returns on failure, with -errno.
pub fn execve(path: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>]) -> i32 {
    let p = to_cstring(path);
    let a: Vec<CString> = argv.iter().map(|s| to_cstring(s)).collect();
    let e: Vec<CString> = envp.iter().map(|s| to_cstring(s)).collect();
    let mut ap: Vec<*const c_char> = a.iter().map(|s| s.as_ptr()).collect();
    ap.push(std::ptr::null());
    let mut ep: Vec<*const c_char> = e.iter().map(|s| s.as_ptr()).collect();
    ep.push(std::ptr::null());
    // SAFETY: NULL-terminated arrays of valid C strings, alive for the call.
    unsafe { libc::execve(p.as_ptr(), ap.as_ptr(), ep.as_ptr()) };
    neg_errno()
}

/// `close_all_fds(except, n)`: close every fd above 2 but these.
pub fn close_all_fds_except(keep: &[Fd]) -> Result<(), i32> {
    let mut k: Vec<Fd> = keep.iter().copied().filter(|&f| f > 2).collect();
    k.sort_unstable();
    k.dedup();
    let mut start: u32 = 3;
    for &f in &k {
        let f = f as u32;
        if f > start {
            // SAFETY: close_range() only closes descriptors.
            if unsafe { libc::syscall(libc::SYS_close_range, start, f - 1, 0) } < 0 {
                return Err(neg_errno());
            }
        }
        start = f + 1;
    }
    // SAFETY: as above.
    if unsafe { libc::syscall(libc::SYS_close_range, start, u32::MAX, 0) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `waitid(P_PID, pid, WEXITED|WNOHANG)`: Some((si_code, si_status)) once
/// the child has exited.
pub fn waitid_nohang(pid: i32) -> Result<Option<(i32, i32)>, i32> {
    // SAFETY: siginfo_t is plain old data.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: si is a valid out-pointer.
    let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOHANG) };
    if r < 0 {
        return Err(neg_errno());
    }
    // SAFETY: reading the union fields waitid() filled in.
    let (spid, status) = unsafe { (si.si_pid(), si.si_status()) };
    if spid == 0 {
        return Ok(None);
    }
    Ok(Some((si.si_code, status)))
}

/// `ppoll()` on several fds: the revents, in order.  `timeout_usec` of
/// `u64::MAX` waits forever.
pub fn poll_many(fds: &[(Fd, i16)], timeout_usec: u64) -> Result<Vec<i16>, i32> {
    let mut p: Vec<libc::pollfd> = fds.iter().map(|&(fd, events)| libc::pollfd { fd, events, revents: 0 }).collect();
    let ts = libc::timespec {
        tv_sec: (timeout_usec / 1_000_000) as libc::time_t,
        tv_nsec: ((timeout_usec % 1_000_000) * 1000) as libc::c_long,
    };
    let tsp = if timeout_usec == u64::MAX { std::ptr::null() } else { &ts as *const libc::timespec };
    // SAFETY: p is a valid array of pollfd, tsp NULL or valid.
    let r = unsafe { libc::ppoll(p.as_mut_ptr(), p.len() as libc::nfds_t, tsp, std::ptr::null()) };
    if r < 0 {
        return Err(neg_errno());
    }
    Ok(p.iter().map(|x| x.revents).collect())
}

/// `rearrange_stdio(in, out, err)`: negative fds mean /dev/null; the fds
/// above 2 are closed.  Then `stdio_disable_nonblock()`.
pub fn rearrange_stdio(fds: [Fd; 3]) -> Result<(), i32> {
    let null_readable = fds[0] < 0;
    let null_writable = fds[1] < 0 || fds[2] < 0;
    let mut null_fd: Fd = -1;
    let mut copies: [Fd; 3] = [-1; 3];
    let mut fd = fds;
    let close_above = |f: Fd| {
        if f > 2 {
            // SAFETY: closing a descriptor this function owns.
            unsafe { libc::close(f) };
        }
    };
    let result = (|| -> Result<(), i32> {
        if null_readable || null_writable {
            let mode = if null_readable && null_writable {
                libc::O_RDWR
            } else if null_readable {
                libc::O_RDONLY
            } else {
                libc::O_WRONLY
            };
            null_fd = open(b"/dev/null", mode | libc::O_CLOEXEC, 0)?;
            if null_fd < 3 {
                // SAFETY: fcntl() on a valid fd.
                let copy = unsafe { libc::fcntl(null_fd, libc::F_DUPFD_CLOEXEC, 3) };
                if copy < 0 {
                    return Err(neg_errno());
                }
                // SAFETY: as above.
                unsafe { libc::close(null_fd) };
                null_fd = copy;
            }
        }
        for i in 0..3 {
            if fd[i] < 0 {
                fd[i] = null_fd;
            } else if fd[i] != i as Fd && fd[i] < 3 {
                // SAFETY: fcntl() on a valid fd.
                let c = unsafe { libc::fcntl(fd[i], libc::F_DUPFD_CLOEXEC, 3) };
                if c < 0 {
                    return Err(neg_errno());
                }
                copies[i] = c;
                fd[i] = c;
            }
        }
        for (i, &f) in fd.iter().enumerate() {
            if f == i as Fd {
                // SAFETY: clearing FD_CLOEXEC on a valid fd.
                unsafe {
                    let fl = libc::fcntl(f, libc::F_GETFD);
                    if fl >= 0 {
                        libc::fcntl(f, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
                    }
                }
            } else {
                // SAFETY: dup2() on valid fds.
                if unsafe { libc::dup2(f, i as Fd) } < 0 {
                    return Err(neg_errno());
                }
            }
        }
        Ok(())
    })();
    close_above(fds[0]);
    if fds[1] != fds[0] {
        close_above(fds[1]);
    }
    if fds[2] != fds[0] && fds[2] != fds[1] {
        close_above(fds[2]);
    }
    for c in copies {
        if c >= 0 {
            // SAFETY: closing a copy made above.
            unsafe { libc::close(c) };
        }
    }
    close_above(null_fd);
    result?;
    for i in 0..3 {
        // SAFETY: clearing O_NONBLOCK on stdio.
        unsafe {
            let fl = libc::fcntl(i, libc::F_GETFL);
            if fl >= 0 && fl & libc::O_NONBLOCK != 0 {
                libc::fcntl(i, libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
        }
    }
    Ok(())
}

/// `lstat(path)`.
pub fn lstat(path: &[u8]) -> Result<Stat, i32> {
    fstatat(libc::AT_FDCWD, path, libc::AT_SYMLINK_NOFOLLOW)
}

/// `readlink_malloc(path)`.
pub fn readlink(path: &[u8]) -> Result<Vec<u8>, i32> {
    readlinkat(libc::AT_FDCWD, path)
}

/// `fdopendir(fcntl(fd, F_DUPFD_CLOEXEC, 3))` (`xopendirat(fd, NULL, 0)`).
pub fn fdopendir_dup(fd: Fd) -> Result<Dir, i32> {
    // SAFETY: fcntl() on a caller's fd.
    let d = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if d < 0 {
        return Err(neg_errno());
    }
    let dir = Dir::from_fd(d)?;
    // SAFETY: rewind to the start, as a fresh opendir() would be.
    unsafe { libc::rewinddir(dir.0) };
    Ok(dir)
}

/// `make_lock_file(path, LOCK_EX)`: create and take an exclusive
/// open-file-description lock (`LOCK_UNPOSIX`).
pub fn open_ofd_lock(path: &[u8]) -> Result<Fd, i32> {
    let fd = open(path, libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY, 0o600)?;
    let fl =
        libc::flock { l_type: libc::F_WRLCK as i16, l_whence: libc::SEEK_SET as i16, l_start: 0, l_len: 0, l_pid: 0 };
    loop {
        // SAFETY: fl is a valid flock.
        let r = unsafe { libc::fcntl(fd, libc::F_OFD_SETLKW, &fl) };
        if r >= 0 {
            return Ok(fd);
        }
        let e = neg_errno();
        if e == -libc::EINTR {
            continue;
        }
        // SAFETY: closing our fd.
        unsafe { libc::close(fd) };
        return Err(if e == -libc::EAGAIN { -libc::EBUSY } else { e });
    }
}

/// `futimens_opath(fd, NULL)`: set both times to now, O_PATH fds too.
pub fn futimens_opath(fd: Fd) -> Result<(), i32> {
    // SAFETY: utimensat() with AT_EMPTY_PATH and NULL times.
    if unsafe { libc::utimensat(fd, c"".as_ptr(), std::ptr::null(), libc::AT_EMPTY_PATH) } >= 0 {
        return Ok(());
    }
    let e = neg_errno();
    if e != -libc::EINVAL {
        return Err(e);
    }
    let p = to_cstring(&crate::fd::proc_fd_path(fd));
    // SAFETY: as above, through /proc/self/fd/.
    if unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), std::ptr::null(), 0) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `pidfd_open(pid, 0)`.
pub fn pidfd_open(pid: i32) -> Result<Fd, i32> {
    // SAFETY: a syscall without memory arguments.
    let r = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if r < 0 { Err(neg_errno()) } else { Ok(r as Fd) }
}

/// `uname().machine`.
pub fn uname_machine() -> Vec<u8> {
    // SAFETY: utsname is plain old data.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is a valid out-pointer.
    unsafe { libc::uname(&mut u) };
    // SAFETY: uname() NUL-terminates the fields.
    unsafe { CStr::from_ptr(u.machine.as_ptr()) }.to_bytes().to_vec()
}

/// `unshare(flags)`.
pub fn unshare(flags: c_int) -> Result<(), i32> {
    // SAFETY: unshare() has no memory arguments.
    if unsafe { libc::unshare(flags) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `mount(source, target, type, flags, data)`.
pub fn mount(source: Option<&[u8]>, target: &[u8], fstype: Option<&[u8]>, flags: libc::c_ulong) -> Result<(), i32> {
    let s = source.map(to_cstring);
    let t = to_cstring(target);
    let f = fstype.map(to_cstring);
    // SAFETY: NULL or valid C strings, alive for the call.
    let r = unsafe {
        libc::mount(
            s.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            t.as_ptr(),
            f.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            flags,
            std::ptr::null(),
        )
    };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `sigprocmask_many(SIG_BLOCK, NULL, sigs...)`.
pub fn block_signals(sigs: &[c_int]) -> Result<(), i32> {
    // SAFETY: sigset_t is plain old data, initialized by sigemptyset().
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: valid set pointer.
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        // SAFETY: as above.
        unsafe { libc::sigaddset(&mut set, s) };
    }
    // SAFETY: valid set pointer; the old mask isn't wanted.
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `__get_cpuid_max(0)`, then `__cpuid_count(leaf, subleaf)`: None if the
/// leaf is above the highest basic leaf (as `__get_cpuid()` fails).
#[cfg(target_arch = "x86_64")]
pub fn cpuid_count(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let r = std::arch::x86_64::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

#[cfg(target_arch = "x86")]
pub fn cpuid_count(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let r = std::arch::x86::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// `pread(fd, buf, offset)`.
pub fn pread(fd: Fd, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
    // SAFETY: buf is valid for writes of its length.
    let n = unsafe { libc::pread64(fd, buf.as_mut_ptr().cast(), buf.len(), offset as libc::off64_t) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// `epoll_create1(EPOLL_CLOEXEC)`.
pub fn epoll_create() -> Result<Fd, i32> {
    // SAFETY: a syscall without memory arguments.
    let r = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `epoll_ctl(epfd, op, fd, {events, data.u64 = data})`.
pub fn epoll_ctl(epfd: Fd, op: c_int, fd: Fd, events: u32, data: u64) -> Result<(), i32> {
    let mut ev = libc::epoll_event { events, u64: data };
    // SAFETY: ev is a valid epoll_event.
    if unsafe { libc::epoll_ctl(epfd, op, fd, &mut ev) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `epoll_wait()` with a timeout in µs (`u64::MAX` waits forever, rounded
/// up to ms like sd-event's fallback): the (events, data) pairs.
pub fn epoll_wait(epfd: Fd, max: usize, timeout_usec: u64) -> Result<Vec<(u32, u64)>, i32> {
    let mut evs: Vec<libc::epoll_event> = vec![libc::epoll_event { events: 0, u64: 0 }; max.max(1)];
    let msec: c_int =
        if timeout_usec == u64::MAX { -1 } else { timeout_usec.div_ceil(1000).min(c_int::MAX as u64) as c_int };
    // SAFETY: evs is valid for max entries.
    let r = unsafe { libc::epoll_wait(epfd, evs.as_mut_ptr(), evs.len() as c_int, msec) };
    if r < 0 {
        return Err(neg_errno());
    }
    Ok(evs[..r as usize].iter().map(|e| (e.events, e.u64)).collect())
}

/// A `sigset_t` holding `sigs`.
fn sigset_of(sigs: &[c_int]) -> libc::sigset_t {
    // SAFETY: sigset_t is plain old data, initialized by sigemptyset().
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: valid set pointer.
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        // SAFETY: as above.
        unsafe { libc::sigaddset(&mut set, s) };
    }
    set
}

/// `signalfd(fd, {sigs}, SFD_NONBLOCK|SFD_CLOEXEC)`: `fd` -1 makes a new one.
pub fn signalfd(fd: Fd, sigs: &[c_int]) -> Result<Fd, i32> {
    let set = sigset_of(sigs);
    // SAFETY: valid set pointer.
    let r = unsafe { libc::signalfd(fd, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// The fields of a `struct signalfd_siginfo` that callers look at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignalInfo {
    pub signo: u32,
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub int: i32,
}

/// One `read()` of a signalfd: None on EAGAIN.
pub fn read_signalfd(fd: Fd) -> Result<Option<SignalInfo>, i32> {
    // SAFETY: signalfd_siginfo is plain old data.
    let mut si: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: si is valid for writes of its size.
    let n = unsafe { libc::read(fd, (&mut si as *mut libc::signalfd_siginfo).cast(), size) };
    if n < 0 {
        let e = errno();
        if e == libc::EAGAIN || e == libc::EINTR {
            return Ok(None);
        }
        return Err(-e);
    }
    if n as usize != size {
        return Err(-libc::EIO);
    }
    Ok(Some(SignalInfo { signo: si.ssi_signo, code: si.ssi_code, pid: si.ssi_pid, uid: si.ssi_uid, int: si.ssi_int }))
}

/// `sigprocmask(SIG_UNBLOCK, {sigs})`.
pub fn unblock_signals(sigs: &[c_int]) -> Result<(), i32> {
    let set = sigset_of(sigs);
    // SAFETY: valid set pointer; the old mask isn't wanted.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// The fields of a `siginfo_t` from `waitid()`: (pid, code, status).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChildInfo {
    pub pid: i32,
    pub code: i32,
    pub status: i32,
}

/// `waitid(P_PIDFD, pidfd, &si, options)`.
#[allow(clippy::unnecessary_cast)]
pub fn waitid_pidfd(pidfd: Fd, options: c_int) -> Result<ChildInfo, i32> {
    // SAFETY: siginfo_t is plain old data.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: si is a valid out-pointer.
    let r = unsafe { libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut si, options) };
    if r < 0 {
        return Err(neg_errno());
    }
    // SAFETY: reading the union fields waitid() filled in.
    let (pid, status) = unsafe { (si.si_pid(), si.si_status()) };
    Ok(ChildInfo { pid, code: si.si_code, status })
}

/// `pidfd_send_signal(pidfd, sig, NULL, 0)`.
pub fn pidfd_send_signal(pidfd: Fd, sig: c_int) -> Result<(), i32> {
    // SAFETY: a syscall without memory arguments (NULL info).
    let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, sig, std::ptr::null::<c_void>(), 0) };
    if r < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `sigqueue(pid, sig, {.sival_int = value})`, as `pidref_sigqueue()`.
pub fn sigqueue(pid: i32, sig: c_int, value: c_int) -> Result<(), i32> {
    // sival_int overlays the low bytes of sival_ptr (little endian).
    let v = libc::sigval { sival_ptr: value as u32 as usize as *mut c_void };
    // SAFETY: a call without memory arguments.
    if unsafe { libc::sigqueue(pid, sig, v) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `inotify_rm_watch(fd, wd)`.
pub fn inotify_rm_watch(fd: Fd, wd: c_int) -> Result<(), i32> {
    // SAFETY: a syscall without memory arguments.
    if unsafe { libc::inotify_rm_watch(fd, wd) } < 0 { Err(neg_errno()) } else { Ok(()) }
}

/// `accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC)`.
pub fn accept4(fd: Fd) -> Result<Fd, i32> {
    // SAFETY: NULL address arguments are allowed.
    let r = unsafe {
        libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
    };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`: (pid, uid, gid).
pub fn peer_cred(fd: Fd) -> Result<(i32, u32, u32), i32> {
    let mut c = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: c and len are valid out-pointers of matching size.
    let r = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut c as *mut libc::ucred).cast(), &mut len)
    };
    if r < 0 { Err(neg_errno()) } else { Ok((c.pid, c.uid, c.gid)) }
}

/// `bind()` of an AF_UNIX socket to `path` (a leading '@' is abstract),
/// then `listen(fd, backlog)`.
pub fn bind_listen_unix(fd: Fd, path: &[u8], backlog: c_int) -> Result<(), i32> {
    let (sa, len) = sockaddr_un(path)?;
    // SAFETY: sa is a valid sockaddr_un of length len.
    if unsafe { libc::bind(fd, (&sa as *const libc::sockaddr_un).cast(), len) } < 0 {
        return Err(neg_errno());
    }
    // SAFETY: a syscall without memory arguments.
    if unsafe { libc::listen(fd, backlog) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `recv(fd, buf, flags)`.
pub fn recv(fd: Fd, buf: &mut [u8], flags: c_int) -> Result<usize, i32> {
    // SAFETY: buf is valid for writes of its length.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// `send(fd, buf, MSG_DONTWAIT|MSG_NOSIGNAL)`.
pub fn send_nosignal(fd: Fd, buf: &[u8]) -> Result<usize, i32> {
    // SAFETY: buf is valid for reads of its length.
    let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    if n < 0 { Err(neg_errno()) } else { Ok(n as usize) }
}

/// `fcntl(fd, F_SETFL, flags | O_NONBLOCK)`.
pub fn set_nonblock(fd: Fd, on: bool) -> Result<(), i32> {
    // SAFETY: fcntl() without memory arguments.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(neg_errno());
    }
    let nf = if on { fl | libc::O_NONBLOCK } else { fl & !libc::O_NONBLOCK };
    // SAFETY: as above.
    if nf != fl && unsafe { libc::fcntl(fd, libc::F_SETFL, nf) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `strerrorname_np(e)`: the errno's symbolic name, as
/// `errno_name_no_fallback()` (which uses the same table).
pub fn errno_name(e: i32) -> Option<Vec<u8>> {
    // SAFETY: returns NULL or a static string.
    let p = unsafe { strerrorname_np(e) };
    if p.is_null() {
        return None;
    }
    // SAFETY: p is a static NUL-terminated string.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// `bind()` of an AF_UNIX socket to `path` (a leading '@' is abstract).
pub fn bind_unix(fd: Fd, path: &[u8]) -> Result<(), i32> {
    let (sa, len) = sockaddr_un(path)?;
    // SAFETY: sa is a valid sockaddr_un of length len.
    if unsafe { libc::bind(fd, (&sa as *const libc::sockaddr_un).cast(), len) } < 0 {
        return Err(neg_errno());
    }
    Ok(())
}

/// `recvmsg(fd, MSG_DONTWAIT|MSG_CMSG_CLOEXEC)` of one datagram of at most
/// `max` bytes: the data and the SCM_CREDENTIALS pid.  Passed fds are
/// closed; truncation fails with -EXFULL (data) or -ECHRNG (control).
pub fn recv_with_creds(fd: Fd, max: usize) -> Result<(Vec<u8>, Option<i32>), i32> {
    let mut buf = vec![0u8; max];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // u64 for alignment; room for credentials and a few fds.
    let mut control = [0u64; 64];
    // SAFETY: msghdr is plain old data.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_iov = &mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control.as_mut_ptr().cast();
    mh.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: mh points at valid buffers for the call.
    let n = unsafe { libc::recvmsg(fd, &mut mh, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(neg_errno());
    }
    let mut pid = None;
    // SAFETY: walking the control messages recvmsg() filled in.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&mh);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET {
                if (*c).cmsg_type == libc::SCM_CREDENTIALS {
                    let u = libc::CMSG_DATA(c).cast::<libc::ucred>().read_unaligned();
                    pid = Some(u.pid);
                } else if (*c).cmsg_type == libc::SCM_RIGHTS {
                    let n = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<c_int>();
                    for i in 0..n {
                        libc::close(libc::CMSG_DATA(c).cast::<c_int>().add(i).read_unaligned());
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&mh, c);
        }
    }
    if mh.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(-libc::ECHRNG);
    }
    if mh.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(-libc::EXFULL);
    }
    buf.truncate(n as usize);
    Ok((buf, pid))
}

/// `malloc_trim(0)`, with `mallinfo2()`'s hblkhd+arena before and after.
pub fn malloc_trim_info() -> (bool, usize) {
    // SAFETY: plain glibc calls without pointer arguments.
    let before = unsafe { libc::mallinfo2() };
    // SAFETY: as above.
    let r = unsafe { libc::malloc_trim(0) };
    // SAFETY: as above.
    let after = unsafe { libc::mallinfo2() };
    (r > 0, before.hblkhd.saturating_sub(after.hblkhd) + before.arena.saturating_sub(after.arena))
}

/// `cpus_in_affinity_mask()`.
pub fn cpus_in_affinity_mask() -> Result<u32, i32> {
    let mut n: usize = 16;
    loop {
        let words = n.div_ceil(64);
        let mut set = vec![0u64; words];
        // SAFETY: set is valid for words*8 bytes, the size passed.
        let r = unsafe { libc::sched_getaffinity(0, words * 8, set.as_mut_ptr().cast()) };
        if r >= 0 {
            let k: u32 = set.iter().map(|w| w.count_ones()).sum();
            return if k == 0 { Err(-libc::EINVAL) } else { Ok(k) };
        }
        let e = errno();
        if e != libc::EINVAL {
            return Err(-e);
        }
        if n > usize::MAX / 2 {
            return Err(-libc::ENOMEM);
        }
        n *= 2;
    }
}

/// `sysconf(_SC_PHYS_PAGES)`.
pub fn phys_pages() -> u64 {
    // SAFETY: sysconf() has no memory arguments.
    let r = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    r.max(0) as u64
}

/// `memfd_new_full(name, MFD_ALLOW_SEALING)`.
pub fn memfd_create(name: &[u8]) -> Result<Fd, i32> {
    let c = to_cstring(name);
    // SAFETY: c is NUL-terminated.
    let r = unsafe { libc::memfd_create(c.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if r < 0 { Err(neg_errno()) } else { Ok(r) }
}

/// `terminal_detach_session()`: `setsid()`, then drop the controlling
/// terminal if there still is one.
pub fn setsid_detach() {
    // SAFETY: setsid() has no arguments.
    unsafe { libc::setsid() };
    if let Ok(fd) = open(b"/dev/tty", libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK, 0) {
        // SAFETY: TIOCNOTTY takes no argument.
        unsafe { libc::ioctl(fd, libc::TIOCNOTTY) };
        close(fd);
    }
}

/// `ioctl(fd, SIOCETHTOOL, &ifr)` with `ifr.ifr_data` pointing at `data`
/// (an ethtool command struct, its first u32 the command).
pub fn siocethtool(fd: Fd, ifname: &[u8], data: &mut [u8]) -> Result<(), i32> {
    // SAFETY: ifreq is plain old data.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in ifr.ifr_name.iter_mut().zip(ifname.iter().take(libc::IFNAMSIZ - 1)) {
        *d = *s as c_char;
    }
    ifr.ifr_ifru.ifru_data = data.as_mut_ptr().cast();
    // SAFETY: ifr is valid and its data pointer refers to `data`, which is
    // as large as the command struct the kernel reads and writes.
    if unsafe {
        libc::ioctl(fd, 0x8946 /* SIOCETHTOOL */, &mut ifr)
    } < 0
    {
        Err(neg_errno())
    } else {
        Ok(())
    }
}

unsafe extern "C" {
    #[link_name = "inet_pton"]
    fn inet_pton_raw(af: c_int, src: *const c_char, dst: *mut libc::c_void) -> c_int;
}

/// `inet_pton(family, s, buf)`: the address bytes, None if `s` isn't one.
pub fn inet_pton(family: c_int, s: &[u8]) -> Option<Vec<u8>> {
    let c = to_cstring(s);
    let mut buf = [0u8; 16];
    // SAFETY: c is NUL-terminated; buf holds an in6_addr.
    let r = unsafe { inet_pton_raw(family, c.as_ptr(), buf.as_mut_ptr().cast()) };
    if r <= 0 {
        return None;
    }
    Some(buf[..if family == libc::AF_INET { 4 } else { 16 }].to_vec())
}

unsafe extern "C" {
    #[link_name = "gnu_get_libc_version"]
    fn gnu_get_libc_version_raw() -> *const c_char;
}

/// `gnu_get_libc_version()`.
pub fn gnu_get_libc_version() -> Vec<u8> {
    // SAFETY: glibc returns a static NUL-terminated string.
    unsafe { CStr::from_ptr(gnu_get_libc_version_raw()) }.to_bytes().to_vec()
}

/// `printf("%g")` (or `"%.Ng"` with a precision) of `v`, by libc.
pub fn format_g(v: f64, precision: Option<i32>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    // SAFETY: buf is valid for its length; the formats take one double
    // (and an int precision), which is what is passed.
    let n = unsafe {
        match precision {
            None => libc::snprintf(buf.as_mut_ptr().cast(), buf.len(), c"%g".as_ptr(), v),
            Some(p) => libc::snprintf(buf.as_mut_ptr().cast(), buf.len(), c"%.*g".as_ptr(), p, v),
        }
    };
    buf[..(n.max(0) as usize).min(buf.len() - 1)].to_vec()
}

/// `SG_IO`.
const SG_IO: u64 = 0x2285;

/// The status fields an `SG_IO` request reports.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgStatus {
    /// v4: device_status, transport_status, driver_status.  v3: status,
    /// host_status, driver_status.
    pub a: u32,
    pub b: u32,
    pub c: u32,
    /// v3: the residual count (`resid`); v4: din_resid.
    pub resid: i32,
    /// v3: msg_status; v4: 0.
    pub msg_status: u32,
    /// The sense bytes written: v3 sb_len_wr, v4 response_len.
    pub sense_len: u32,
}

/// `ioctl(fd, SG_IO, &io_v4)` with a `struct sg_io_v4` for a SCSI command
/// reading into `data` (BSG_PROTOCOL_SCSI, BSG_SUB_PROTOCOL_SCSI_CMD).
pub fn sg_io_v4(fd: Fd, cdb: &[u8], sense: &mut [u8], data: &mut [u8], timeout_ms: u32) -> Result<SgStatus, i32> {
    let mut io = [0u8; 160];
    let put32 = |io: &mut [u8; 160], o: usize, v: u32| io[o..o + 4].copy_from_slice(&v.to_ne_bytes());
    let put64 = |io: &mut [u8; 160], o: usize, v: u64| io[o..o + 8].copy_from_slice(&v.to_ne_bytes());
    put32(&mut io, 0, b'Q' as u32);
    put32(&mut io, 12, cdb.len() as u32);
    put64(&mut io, 16, cdb.as_ptr() as usize as u64);
    put32(&mut io, 44, sense.len() as u32);
    put64(&mut io, 48, sense.as_mut_ptr() as usize as u64);
    put32(&mut io, 68, data.len() as u32);
    put64(&mut io, 80, data.as_mut_ptr() as usize as u64);
    put32(&mut io, 88, timeout_ms);
    // SAFETY: io is a struct sg_io_v4 whose pointers refer to cdb (read
    // only), sense and data, all valid for the lengths given and
    // exclusively borrowed for the call.
    if unsafe { libc::ioctl(fd, SG_IO as _, io.as_mut_ptr()) } != 0 {
        return Err(neg_errno());
    }
    let get32 = |o: usize| u32::from_ne_bytes(io[o..o + 4].try_into().expect("4 bytes"));
    Ok(SgStatus {
        a: get32(116),
        b: get32(112),
        c: get32(108),
        resid: get32(136) as i32,
        msg_status: 0,
        sense_len: get32(132),
    })
}

/// `ioctl(fd, SG_IO, &io_hdr)` with a `struct sg_io_hdr` (version 3)
/// reading into `data` (SG_DXFER_FROM_DEV), or writing nothing when
/// `data` is empty and `dir` is SG_DXFER_NONE.
pub fn sg_io_v3(
    fd: Fd,
    cdb: &[u8],
    sense: &mut [u8],
    data: &mut [u8],
    dir: i32,
    timeout_ms: u32,
) -> Result<SgStatus, i32> {
    #[cfg(target_pointer_width = "64")]
    const L: (usize, usize, usize, usize, usize, usize, usize, usize) = (88, 16, 24, 32, 40, 64, 68, 70);
    #[cfg(target_pointer_width = "32")]
    const L: (usize, usize, usize, usize, usize, usize, usize, usize) = (64, 16, 20, 24, 28, 44, 48, 50);
    let (size, dxferp, cmdp, sbp, timeout, status, host, driver) = L;
    let mut io = vec![0u8; size];
    io[0..4].copy_from_slice(&(b'S' as i32).to_ne_bytes());
    io[4..8].copy_from_slice(&dir.to_ne_bytes());
    io[8] = cdb.len() as u8;
    io[9] = sense.len() as u8;
    io[12..16].copy_from_slice(&(data.len() as u32).to_ne_bytes());
    let ptr = |io: &mut Vec<u8>, o: usize, p: usize| {
        let b = p.to_ne_bytes();
        io[o..o + b.len()].copy_from_slice(&b);
    };
    ptr(&mut io, dxferp, if data.is_empty() { 0 } else { data.as_mut_ptr() as usize });
    ptr(&mut io, cmdp, cdb.as_ptr() as usize);
    ptr(&mut io, sbp, sense.as_mut_ptr() as usize);
    io[timeout..timeout + 4].copy_from_slice(&timeout_ms.to_ne_bytes());
    // SAFETY: io is a struct sg_io_hdr whose pointers refer to cdb (read
    // only), sense and data, all valid for the lengths given and
    // exclusively borrowed for the call.
    if unsafe { libc::ioctl(fd, SG_IO as _, io.as_mut_ptr()) } != 0 {
        return Err(neg_errno());
    }
    // resid follows driver_status (72 or 52).
    let resid = status + 8;
    Ok(SgStatus {
        a: io[status] as u32,
        b: u16::from_ne_bytes([io[host], io[host + 1]]) as u32,
        c: u16::from_ne_bytes([io[driver], io[driver + 1]]) as u32,
        resid: i32::from_ne_bytes(io[resid..resid + 4].try_into().expect("4 bytes")),
        msg_status: io[status + 2] as u32,
        sense_len: io[status + 3] as u32,
    })
}
