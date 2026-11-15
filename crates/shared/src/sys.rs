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
}
pub type Stat = libc::stat;

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
    if unsafe { libc::fstat(fd, &mut st) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

pub fn stat(path: &[u8]) -> Result<Stat, i32> {
    let c = to_cstring(path);
    let mut st = stat_zero();
    // SAFETY: c is NUL-terminated, st is a valid out-pointer.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

/// `fstatat(dirfd, path, flags)`.
pub fn fstatat(dirfd: Fd, path: &[u8], flags: c_int) -> Result<Stat, i32> {
    let c = to_cstring(path);
    let mut st = stat_zero();
    // SAFETY: c is NUL-terminated, st is a valid out-pointer.
    if unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, flags) } < 0 { Err(neg_errno()) } else { Ok(st) }
}

pub fn open(path: &[u8], flags: c_int, mode: u32) -> Result<Fd, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let fd = unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 { Err(neg_errno()) } else { Ok(fd) }
}

pub fn openat(dirfd: Fd, path: &[u8], flags: c_int, mode: u32) -> Result<Fd, i32> {
    let c = to_cstring(path);
    // SAFETY: c is NUL-terminated.
    let fd = unsafe { libc::openat(dirfd, c.as_ptr(), flags, mode as libc::c_uint) };
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
    let r = unsafe { libc::lseek(fd, off, whence) };
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
        let e = unsafe { libc::readdir(self.0) };
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
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) < 0 {
            return Err(neg_errno());
        }
        Ok((rl.rlim_cur, rl.rlim_max))
    }
}

/// `setrlimit(RLIMIT_NOFILE, {soft, hard})`.
pub fn setrlimit_nofile(soft: u64, hard: u64) -> Result<(), i32> {
    let rl = libc::rlimit { rlim_cur: soft, rlim_max: hard };
    // SAFETY: rl is a valid rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } < 0 { Err(neg_errno()) } else { Ok(()) }
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

unsafe extern "C" fn opendir_hook(p: *const c_char) -> *mut c_void {
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
