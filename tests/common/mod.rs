// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential test harness: run the C build and the port in the same
//! sandbox and compare everything observable.  Each crate's integration
//! tests include this file with `#[path = "../../../tests/common/mod.rs"]`.
//!
//! # The sandbox
//!
//! Each run gets a fresh directory `T` under `target/difftest/<case>/<impl>`
//! and runs in new user and mount namespaces.  Ids are mapped with the
//! setuid `newuidmap`/`newgidmap` helpers and the invoking user's
//! subordinate ranges (`/etc/subuid`, `/etc/subgid`): namespace id 0 is the
//! invoking user, and ids 1-65536 are the first subordinate ids.  So the
//! sandbox has a real root and real other users.
//!
//! `T` mirrors the real paths the program sees: a case's `etc/sysctl.d/x`
//! is `/etc/sysctl.d/x` in the sandbox.  The sandbox's `/etc` is `T/etc`, a
//! farm of symlinks to the real `/etc` (bound aside at `T/.realetc`),
//! except for the harness's `passwd` and `group` and the names the program
//! owns (`Case::etc_own`, e.g. `sysctl.d`), which hold only what the case
//! puts there.  Other directories are bound over the real ones
//! (`Case::bind`, e.g. `T/proc/sys` over `/proc/sys`).  Always bound:
//! `T/dev/kmsg` (a plain file) over `/dev/kmsg` and `T/devlog` (a socket
//! the harness reads) over `/dev/log`.  `@T@` in arguments, environment
//! and files stands for `T` as the program sees it.  The clock is the
//! LD_PRELOAD shim in tests/shim/.
//!
//! # What is compared
//!
//! The exit status, stdout, stderr (or, on a pty, the combined terminal
//! output), the syslog and journal messages, and every file under `T`
//! (type, mode, owner, contents; binary files, which the snapshot's
//! separators can't carry, by size and SHA-256), with `T` and pids
//! normalized.  The
//! snapshot and the cleanup run as root inside the sandbox, so files owned
//! by other users are covered too.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::{CString, c_char, c_int};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 2025-11-11 14:00:00 UTC, a Tuesday.
pub const DEFAULT_TIME: (i64, i64) = (1_762_869_600, 0);

pub const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
alice:x:1001:1001:Alice:/home/alice:/bin/sh
bob:x:1002:1002:Bob:/home/bob:/bin/sh
nobody:x:65534:65534:nobody:/var/empty:/sbin/nologin
";
pub const GROUP: &str = "\
root:x:0:
adm:x:4:
users:x:100:alice,bob
alice:x:1001:
bob:x:1002:
nobody:x:65534:
";

/// Who the program runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As {
    Root,
    /// A test user: (uid, gid, supplementary groups).
    User(u32, u32, &'static [u32]),
}

pub const ALICE: As = As::User(1001, 1001, &[1001, 100]);
pub const BOB: As = As::User(1002, 1002, &[1002, 100]);

/// What to make before the run.
#[derive(Debug, Clone)]
pub enum Node {
    /// A file: contents, mode, owner, group.
    File(Vec<u8>, u32, u32, u32),
    /// A directory: mode, owner, group.
    Dir(u32, u32, u32),
    /// A symbolic link to the target.
    Symlink(String),
    /// A FIFO, mode.
    Fifo(u32),
    /// A hard link to an earlier node (path under T).
    Hardlink(String),
    /// A unix socket nobody listens on any more.
    Socket,
}

#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Paths under T, made in order.
    pub nodes: Vec<(String, Node)>,
    pub time: (i64, i64),
    pub user: As,
    /// Names in /etc that only the case provides.
    pub etc_own: Vec<String>,
    /// (real path, path under T) bound in the sandbox.
    pub binds: Vec<(String, String)>,
    /// Run on a pty of this size (rows, columns) instead of files.
    pub pty: Option<(u16, u16)>,
    /// stdin contents (default /dev/null).
    pub stdin: Option<Vec<u8>>,
    /// Capture journal datagrams at /run/systemd/journal/socket.
    pub journal: bool,
    /// Paths as the sandbox sees them (after the binds), to make
    /// read-only (to get EROFS).
    pub read_only: Vec<String>,
    /// Compare output lines sorted: for output that two processes write
    /// concurrently (e.g. the parent's and the pager's debug logs).
    pub sorted: bool,
    /// Also snapshot extended attributes (ACLs and capabilities included),
    /// file attributes (lsattr), and access and modification times (those
    /// within an hour of the real time are "recent").
    pub meta: bool,
    /// (path under T, seconds): set its access and modification times,
    /// after every node is made.
    pub touch: Vec<(String, i64)>,
    /// Run with a root of the sandbox's own: a tmpfs owned by the
    /// sandbox's root, holding binds of the system directories, the repo
    /// and the reference build.  Otherwise "/" belongs to the real root,
    /// which the sandbox sees as nobody, and every path from "/" down to
    /// `T` has an unsafe nobody → root transition (CHASE_SAFE refuses it).
    pub own_root: bool,
    /// Run this `sh -c` script instead of the program; in it, the
    /// program's name runs the implementation under test (a symlink in
    /// `T/.bin`, first on $PATH).  The case's args are then unused.
    pub shell: Option<String>,
    /// Run in a network namespace of its own (the sandbox's root then has
    /// CAP_NET_ADMIN there, e.g. to broadcast on the uevent netlink socket).
    pub netns: bool,
    /// Preload the clock shim (the default); off for 32-bit programs,
    /// which can't load the 64-bit shim.
    pub faketime: bool,
    /// Rewrites stdout and stderr of both runs before they're compared
    /// (for output that is the same by design but varies, such as
    /// timestamps).
    pub mask: Option<fn(&str) -> String>,
    /// Host paths bound over real paths: (host path, real path), for
    /// shared fixtures outside T.
    pub host_binds: Vec<(String, String)>,
}

impl Case {
    pub fn new(name: &str, args: &[&str]) -> Case {
        Case {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: vec![("TZ".into(), "UTC".into()), ("PATH".into(), "/usr/bin:/bin".into())],
            nodes: Vec::new(),
            time: DEFAULT_TIME,
            user: As::Root,
            etc_own: Vec::new(),
            binds: Vec::new(),
            pty: None,
            stdin: None,
            journal: false,
            read_only: Vec::new(),
            sorted: false,
            meta: false,
            touch: Vec::new(),
            own_root: false,
            shell: None,
            netns: false,
            faketime: true,
            mask: None,
            host_binds: Vec::new(),
        }
    }

    pub fn env(mut self, k: &str, v: &str) -> Case {
        self.env.retain(|(kk, _)| kk != k);
        self.env.push((k.into(), v.into()));
        self
    }

    pub fn no_env(mut self, k: &str) -> Case {
        self.env.retain(|(kk, _)| kk != k);
        self
    }

    /// A root-owned file.
    pub fn file(self, path: &str, contents: &[u8], mode: u32) -> Case {
        self.file_owned(path, contents, mode, 0, 0)
    }

    pub fn file_owned(mut self, path: &str, contents: &[u8], mode: u32, uid: u32, gid: u32) -> Case {
        self.nodes.retain(|(p, _)| p != path);
        self.nodes.push((path.into(), Node::File(contents.to_vec(), mode, uid, gid)));
        self
    }

    /// A root-owned text file, mode 0644.
    pub fn conf(self, path: &str, contents: &str) -> Case {
        self.file(path, contents.as_bytes(), 0o644)
    }

    pub fn dir(self, path: &str, mode: u32) -> Case {
        self.dir_owned(path, mode, 0, 0)
    }

    pub fn dir_owned(mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Case {
        self.nodes.push((path.into(), Node::Dir(mode, uid, gid)));
        self
    }

    pub fn symlink(mut self, path: &str, target: &str) -> Case {
        self.nodes.retain(|(p, _)| p != path);
        self.nodes.push((path.into(), Node::Symlink(target.into())));
        self
    }

    pub fn fifo(mut self, path: &str, mode: u32) -> Case {
        self.nodes.push((path.into(), Node::Fifo(mode)));
        self
    }

    pub fn hardlink(mut self, path: &str, existing: &str) -> Case {
        self.nodes.push((path.to_string(), Node::Hardlink(existing.to_string())));
        self
    }
    pub fn socket(mut self, path: &str) -> Case {
        self.nodes.push((path.to_string(), Node::Socket));
        self
    }
    pub fn no_node(mut self, path: &str) -> Case {
        self.nodes.retain(|(p, _)| p != path);
        self
    }

    pub fn time(mut self, sec: i64) -> Case {
        self.time = (sec, 0);
        self
    }

    pub fn run_as(mut self, user: As) -> Case {
        self.user = user;
        self
    }

    pub fn etc_own(mut self, name: &str) -> Case {
        self.etc_own.push(name.into());
        self
    }

    /// Bind `T/<under_t>` over `real` in the sandbox.
    pub fn bind(mut self, real: &str, under_t: &str) -> Case {
        self.binds.push((real.into(), under_t.into()));
        self
    }

    pub fn pty(mut self, rows: u16, cols: u16) -> Case {
        self.pty = Some((rows, cols));
        self
    }

    pub fn stdin(mut self, data: &[u8]) -> Case {
        self.stdin = Some(data.to_vec());
        self
    }

    pub fn journal(mut self) -> Case {
        self.journal = true;
        self
    }

    /// Compare output lines in sorted order (see [`Case::sorted`]).
    pub fn sorted(mut self) -> Case {
        self.sorted = true;
        self
    }

    /// Make `path` read-only in the sandbox: a path the program sees, e.g.
    /// `/proc/sys/kernel` (`@T@` works too).
    pub fn meta(mut self) -> Case {
        self.meta = true;
        self
    }
    pub fn shell(mut self, script: &str) -> Case {
        self.shell = Some(script.to_string());
        self
    }
    pub fn mask(mut self, f: fn(&str) -> String) -> Case {
        self.mask = Some(f);
        self
    }
    /// Bind a host path (outside T) over `real`.
    pub fn bind_host(mut self, host: &str, real: &str) -> Case {
        self.host_binds.push((host.to_string(), real.to_string()));
        self
    }
    pub fn netns(mut self) -> Case {
        self.netns = true;
        self
    }
    pub fn no_faketime(mut self) -> Case {
        self.faketime = false;
        self
    }
    pub fn own_root(mut self) -> Case {
        self.own_root = true;
        self
    }
    pub fn touch(mut self, path: &str, sec: i64) -> Case {
        self.touch.push((path.to_string(), sec));
        self
    }
    pub fn read_only(mut self, path: &str) -> Case {
        self.read_only.push(path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: String,
    pub stdout: String,
    pub stderr: String,
    pub syslog: String,
    pub journal: String,
    pub files: BTreeMap<String, String>,
}

/// The two implementations of one program.
#[derive(Debug, Clone)]
pub struct Program {
    /// argv[0].
    pub name: &'static str,
    pub c: PathBuf,
    pub rust: PathBuf,
}

pub fn repo_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// The C build tree: `$SYSTEMD_REFERENCE/build`, by default `../systemd/build`.
pub fn reference_build() -> PathBuf {
    let dir = std::env::var_os("SYSTEMD_REFERENCE").map_or_else(|| repo_dir().join("../systemd"), PathBuf::from);
    dir.join("build")
}

fn difftest_dir() -> PathBuf {
    let d = repo_dir().join("target/difftest");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn shim() -> &'static Path {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let dir = difftest_dir();
        let out = dir.join("faketime.so");
        let tmp = dir.join(format!("faketime.so.{}", std::process::id()));
        let st = Command::new("cc")
            .args(["-shared", "-fPIC", "-O2", "-o"])
            .arg(&tmp)
            .arg(repo_dir().join("tests/shim/faketime.c"))
            .arg("-ldl")
            .status()
            .expect("run cc");
        assert!(st.success(), "building the faketime shim failed");
        std::fs::rename(&tmp, &out).unwrap();
        out
    })
}

/// Where every run's `T` appears inside its sandbox, so the C and Rust runs
/// see the same paths (each binds its own directory there).
pub fn fixed_root() -> PathBuf {
    let p = difftest_dir().join(".root");
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn subst(s: &str) -> String {
    s.replace("@T@", fixed_root().to_str().unwrap())
}

fn subst_bytes(s: &[u8]) -> Vec<u8> {
    let root = fixed_root();
    let rep = root.to_str().unwrap().as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(b"@T@") {
            out.extend_from_slice(rep);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

fn cstr(s: impl AsRef<[u8]>) -> CString {
    CString::new(s.as_ref().to_vec()).unwrap()
}

fn path_c(p: &Path) -> CString {
    cstr(p.to_str().unwrap())
}

/// The invoking user's first subordinate id, from /etc/subuid or /etc/subgid.
fn subordinate(file: &str, name: &str, id: u32) -> u32 {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() == 3 && (f[0] == name || f[0] == id.to_string()) && f[2].parse::<u32>().unwrap_or(0) >= 65536 {
            return f[1].parse().unwrap();
        }
    }
    panic!("no subordinate range of 65536 ids for {name} in {file}: the sandbox needs one");
}

/// What the child does between fork and exec, prepared beforehand.
struct Spawn {
    binds: Vec<(CString, CString)>,
    /// Bind targets to remount read-only.
    read_only: Vec<CString>,
    /// (path, owner, group, mode) fixups made as root in the sandbox
    /// (lchown, and chmod unless the mode is u32::MAX).
    chowns: Vec<(CString, u32, u32, u32)>,
    user: As,
    dir: CString,
    stdio: [c_int; 3],
    /// Make the pty (stdio[0]) the controlling terminal.
    ctty: bool,
    /// Chroot into a root of our own before exec.
    newroot: Option<NewRoot>,
    /// Also unshare the network namespace.
    netns: bool,
    exe: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
}

/// What makes up `Case::own_root`, prepared before fork.
struct NewRoot {
    /// Where the tmpfs goes (an empty directory in T, outside the snapshot).
    dir: CString,
    /// Directories to make in it, parents first.
    mkdirs: Vec<CString>,
    /// (target, link) symlinks to make in it.
    symlinks: Vec<(CString, CString)>,
    /// (source, target in it) recursive binds.
    binds: Vec<(CString, CString)>,
}

impl NewRoot {
    fn new(t: &Path, bin: &Path) -> NewRoot {
        let dir = t.join(".newroot");
        std::fs::create_dir_all(&dir).unwrap();
        let mut mkdirs: Vec<PathBuf> = Vec::new();
        let mut symlinks = Vec::new();
        let mut binds = Vec::new();
        let add_dirs = |p: &Path, mkdirs: &mut Vec<PathBuf>| {
            for a in p.ancestors().collect::<Vec<_>>().into_iter().rev().skip(1) {
                if !mkdirs.iter().any(|m| m == a) {
                    mkdirs.push(a.to_path_buf());
                }
            }
        };
        for sys in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run", "/var", "/tmp"]
        {
            let p = Path::new(sys);
            match p.symlink_metadata() {
                Ok(m) if m.file_type().is_symlink() => {
                    symlinks.push((std::fs::read_link(p).unwrap(), p.to_path_buf()));
                }
                Ok(_) => {
                    add_dirs(p, &mut mkdirs);
                    binds.push((p.to_path_buf(), p.to_path_buf()));
                }
                Err(_) => {}
            }
        }
        // The repo (target/, the shim, and T at fixed_root()), the
        // reference build, and the binary's directory.
        let mut extra = vec![repo_dir(), reference_build()];
        if let Some(d) = bin.parent() {
            extra.push(d.canonicalize().unwrap());
        }
        for p in extra {
            if binds.iter().any(|(s, _): &(PathBuf, PathBuf)| p.starts_with(s)) {
                continue;
            }
            add_dirs(&p, &mut mkdirs);
            binds.push((p.clone(), p));
        }
        let under = |p: &Path| path_c(&dir.join(p.strip_prefix("/").unwrap()));
        NewRoot {
            dir: path_c(&dir),
            mkdirs: mkdirs.iter().map(|m| under(m)).collect(),
            symlinks: symlinks.iter().map(|(t, l)| (path_c(t), under(l))).collect(),
            binds: binds.iter().map(|(s, d)| (path_c(s), under(d))).collect(),
        }
    }
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

/// fork(); the child enters the sandbox and execs.  Returns the pid once
/// the child has reached exec.
fn spawn_in_sandbox(s: Spawn) -> u32 {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let name = std::env::var("USER").unwrap_or_default();
    let subuid = subordinate("/etc/subuid", &name, uid);
    let subgid = subordinate("/etc/subgid", &name, gid);

    let mut argv: Vec<*const c_char> = s.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const c_char> = s.envp.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    let gs: Vec<libc::gid_t> = match s.user {
        As::User(_, _, groups) => groups.to_vec(),
        As::Root => Vec::new(),
    };
    let (up_r, up_w) = pipe();
    let (go_r, go_w) = pipe();
    let root = cstr("/");

    // SAFETY: between fork and exec the child only makes async-signal-safe
    // system calls on memory prepared above, then execs or _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::close(go_w);
            libc::close(up_r);
            let net = if s.netns { libc::CLONE_NEWNET } else { 0 };
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | net) != 0 {
                libc::_exit(120);
            }
            libc::write(up_w, b"u".as_ptr().cast(), 1);
            let mut b = [0u8; 1];
            if libc::read(go_r, b.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(121);
            }
            let none = std::ptr::null::<c_char>();
            if libc::mount(none, root.as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                libc::_exit(122);
            }
            for (src, dst) in &s.binds {
                if libc::mount(src.as_ptr(), dst.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0 {
                    libc::_exit(123);
                }
            }
            for (path, owner, group, mode) in &s.chowns {
                if libc::lchown(path.as_ptr(), *owner, *group) != 0
                    || (*mode != u32::MAX && libc::chmod(path.as_ptr(), *mode) != 0)
                {
                    libc::_exit(124);
                }
            }
            for p in &s.read_only {
                let fl = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY;
                if libc::mount(p.as_ptr(), p.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0
                    || libc::mount(none, p.as_ptr(), none, fl, std::ptr::null()) != 0
                {
                    libc::_exit(119);
                }
            }
            if let Some(nr) = &s.newroot {
                let tmpfs = cstr("tmpfs");
                let opts = cstr("mode=0755");
                if libc::mount(tmpfs.as_ptr(), nr.dir.as_ptr(), tmpfs.as_ptr(), 0, opts.as_ptr().cast()) != 0 {
                    libc::_exit(118);
                }
                for d in &nr.mkdirs {
                    libc::mkdir(d.as_ptr(), 0o755);
                }
                for (target, link) in &nr.symlinks {
                    libc::symlink(target.as_ptr(), link.as_ptr());
                }
                for (src, dst) in &nr.binds {
                    if libc::mount(src.as_ptr(), dst.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null())
                        != 0
                    {
                        libc::_exit(118);
                    }
                }
                let dot = cstr(".");
                if libc::chdir(nr.dir.as_ptr()) != 0 || libc::chroot(dot.as_ptr()) != 0 {
                    libc::_exit(118);
                }
            }
            if let As::User(u, g, _) = s.user
                && (libc::setgroups(gs.len(), gs.as_ptr()) != 0 || libc::setgid(g) != 0 || libc::setuid(u) != 0)
            {
                libc::_exit(125);
            }
            for (i, fd) in s.stdio.iter().enumerate() {
                libc::dup2(*fd, i as c_int);
            }
            if s.ctty {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY, 0);
            }
            if libc::chdir(s.dir.as_ptr()) != 0 {
                libc::_exit(126);
            }
            // up_w is close-on-exec: EOF tells the parent we reached exec.
            libc::execve(s.exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    // SAFETY: closing our copies of the child's ends.
    unsafe {
        libc::close(go_r);
        libc::close(up_w);
    }
    let mut b = [0u8; 1];
    // SAFETY: reading one byte into b.
    let n = unsafe { libc::read(up_r, b.as_mut_ptr().cast(), 1) };
    if n != 1 {
        panic!("sandbox child failed before unshare ({})", wait(pid as u32, Duration::from_secs(5)));
    }
    for (tool, host, sub) in [("newuidmap", uid, subuid), ("newgidmap", gid, subgid)] {
        let st = Command::new(tool)
            .arg(pid.to_string())
            .args(["0", &host.to_string(), "1", "1", &sub.to_string(), "65536"])
            .status()
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(st.success(), "{tool} failed");
    }
    // SAFETY: writing one byte from a static buffer, then closing.
    unsafe {
        libc::write(go_w, b"g".as_ptr().cast(), 1);
        libc::close(go_w);
    }
    // SAFETY: reading into b; then closing.
    unsafe {
        libc::read(up_r, b.as_mut_ptr().cast(), 1);
        libc::close(up_r);
    }
    pid as u32
}

/// waitpid with a timeout; the status as text.
fn wait(pid: u32, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let mut st: c_int = 0;
        // SAFETY: st is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid as i32, &mut st, libc::WNOHANG) };
        if r == pid as i32 {
            return if libc::WIFEXITED(st) {
                format!("exit {}", libc::WEXITSTATUS(st))
            } else if libc::WIFSIGNALED(st) {
                format!("signal {}", libc::WTERMSIG(st))
            } else {
                "unknown".into()
            };
        }
        if Instant::now() > deadline {
            // SAFETY: killing and reaping our own child.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, &mut st, 0);
            }
            return "timeout".into();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Run a shell script as root in a sandbox (no binds), for snapshots and
/// cleanup, which must see files owned by the sandbox's other users.
fn root_shell(t: &Path, script: &str) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let out = t.with_extension("rootsh.out");
    let outf = std::fs::File::create(&out).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let pid = spawn_in_sandbox(Spawn {
        binds: Vec::new(),
        read_only: Vec::new(),
        chowns: Vec::new(),
        user: As::Root,
        dir: cstr("/"),
        stdio: [null.as_raw_fd(), outf.as_raw_fd(), outf.as_raw_fd()],
        ctty: false,
        newroot: None,
        netns: false,
        exe: cstr("/bin/sh"),
        argv: vec![cstr("sh"), cstr("-c"), cstr(script)],
        envp: vec![cstr("PATH=/usr/bin:/bin"), cstr("LC_ALL=C")],
    });
    let st = wait(pid, Duration::from_secs(30));
    let data = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_file(&out);
    assert_eq!(st, "exit 0", "root shell failed: {script}\n{}", String::from_utf8_lossy(&data));
    data
}

/// Remove a previous run's directory, including files sandbox users made.
/// (Never `rm -rf` target/difftest by hand: such files can't be removed.)
fn clean(t: &Path) {
    if !t.exists() || std::fs::remove_dir_all(t).is_ok() {
        return;
    }
    root_shell(t, &format!("chown -R 0:0 '{0}' 2>/dev/null; chmod -R u+rwX '{0}' 2>/dev/null; exit 0", t.display()));
    std::fs::remove_dir_all(t).unwrap_or_else(|e| panic!("can't clean {}: {e}", t.display()));
}

/// Replace `T` with `@T@`, the program's pid with `@PID@`, and the pids of
/// children it reports ("as PID N.") with `@CHILD@`.
pub fn normalize(s: &str, t: &Path, pid: u32) -> String {
    let s = s.replace(t.to_str().unwrap(), "@T@").replace(fixed_root().to_str().unwrap(), "@T@");
    let s = {
        let mut out = String::new();
        let mut rest = s.as_str();
        while let Some(k) = rest.find(" as PID ") {
            out.push_str(&rest[..k + 8]);
            rest = &rest[k + 8..];
            let n = rest.bytes().take_while(u8::is_ascii_digit).count();
            if n > 0 {
                out.push_str("@CHILD@");
                rest = &rest[n..];
            }
        }
        out.push_str(rest);
        out
    };
    let pid_s = pid.to_string();
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let j = i + b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            let after_ok = j == b.len() || !b[j].is_ascii_alphanumeric();
            out.push_str(if after_ok && s[i..j] == pid_s { "@PID@" } else { &s[i..j] });
            i = j;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// The tree under `t`, as root in the sandbox: type, mode, owner, contents
/// (and "now" for regular files modified during the run).
fn snapshot(t: &Path, pid: u32, meta: bool) -> BTreeMap<String, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let meta_sh = if meta {
        format!(
            "x=$(stat -c %X \"$f\"); y=$(stat -c %Y \"$f\")
             [ \"$x\" -gt {recent} ] && [ \"$x\" -lt {soon} ] && x=recent
             [ \"$y\" -gt {recent} ] && [ \"$y\" -lt {soon} ] && y=recent
             printf ' times=%s,%s links=%s' \"$x\" \"$y\" \"$(stat -c %h \"$f\")\"
             if [ ! -L \"$f\" ] && {{ [ -f \"$f\" ] || [ -d \"$f\" ]; }}; then
               printf ' attr=%s' \"$(lsattr -d \"$f\" 2>/dev/null | cut -d' ' -f1)\"
             fi
             printf '%s' \"$(getfattr -h -d -e hex -m - \"$f\" 2>/dev/null | grep -v '^#' | grep . | tr '\\n' ' ')\"",
            recent = now - 3600,
            soon = now + 3600
        )
    } else {
        String::new()
    };
    let script = format!(
        "cd '{}' || exit 1
         find . -mindepth 1 \\( -path ./.realetc -o -path ./.newroot -o -path ./.bin -o -path ./devlog -o -path ./.faketime -o -path ./.stdin \
            -o -path ./.stdout -o -path ./.stderr -o -path ./run/systemd/journal/socket \
            -o \\( -type l -path './etc/*' \\) \\) -prune -o -print | LC_ALL=C sort | while read -r f; do
           printf '\\001%s\\002%s' \"$f\" \"$(stat -c '%F %a %u:%g' \"$f\")\"
           {meta_sh}
           if [ -f \"$f\" ] && [ ! -L \"$f\" ]; then
             m=$(stat -c %Y \"$f\"); [ \"$m\" -gt {recent} ] && printf ' modified'
           fi
           printf '\\002'
           if [ -L \"$f\" ]; then readlink \"$f\"
           elif [ -f \"$f\" ] && [ -n \"$(tr -dc '\\001\\002' < \"$f\" 2>/dev/null | head -c1)\" ]; then
             printf 'binary %s bytes sha256 %s' \"$(stat -c %s \"$f\")\" \"$(sha256sum < \"$f\" | cut -d' ' -f1)\"
           elif [ -f \"$f\" ]; then cat \"$f\"
           fi
         done; exit 0",
        t.display(),
        recent = now - 3600
    );
    let raw = root_shell(t, &script);
    let text = String::from_utf8_lossy(&raw).to_string();
    let mut out = BTreeMap::new();
    for rec in text.split('\u{1}').skip(1) {
        let mut parts = rec.splitn(3, '\u{2}');
        let (name, meta, data) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        out.insert(normalize(name, t, pid), normalize(&format!("{meta}\n{data}"), t, pid));
    }
    out
}

/// Build `T/etc`: symlinks to the real /etc (seen at `T/.realetc` inside
/// the sandbox), plus the harness's own files; names in `own` are left to
/// the case.
fn build_etc(t: &Path, own: &[String]) {
    let etc = t.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    for ent in std::fs::read_dir("/etc").unwrap().flatten() {
        let name = ent.file_name();
        let n = name.to_str().unwrap_or("");
        if ["passwd", "group", "shadow", "gshadow"].contains(&n) || own.iter().any(|o| o == n) {
            continue;
        }
        if etc.join(&name).symlink_metadata().is_ok() {
            continue;
        }
        std::os::unix::fs::symlink(t.join(".realetc").join(&name), etc.join(&name)).unwrap();
    }
    std::fs::write(etc.join("passwd"), PASSWD).unwrap();
    std::fs::write(etc.join("group"), GROUP).unwrap();
}

/// Open a pty pair of the given size: (master, slave).
fn openpty(rows: u16, cols: u16) -> (c_int, c_int) {
    let (mut m, mut s) = (0, 0);
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: m and s are valid out-pointers; ws is a valid winsize.
    let r = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) };
    assert_eq!(r, 0, "openpty failed");
    (m, s)
}

pub fn run(case: &Case, prog: &Program, label: &str, bin: &Path) -> Outcome {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let t = difftest_dir().join(&case.name).join(label);
    clean(&t);
    for d in [".realetc", "dev"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    std::fs::write(t.join("dev/kmsg"), b"").unwrap();
    std::fs::set_permissions(t.join("dev/kmsg"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut chowns: Vec<(CString, u32, u32, u32)> = Vec::new();
    for (path, node) in &case.nodes {
        let p = t.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        match node {
            Node::File(data, mode, uid, gid) => {
                std::fs::write(&p, subst_bytes(data)).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode & 0o777)).unwrap();
                if *uid != 0 || *gid != 0 || *mode > 0o777 {
                    chowns.push((path_c(&p), *uid, *gid, *mode));
                }
            }
            Node::Dir(mode, uid, gid) => {
                std::fs::create_dir_all(&p).unwrap();
                chowns.push((path_c(&p), *uid, *gid, *mode));
            }
            Node::Symlink(target) => {
                std::os::unix::fs::symlink(subst(target), &p).unwrap();
            }
            Node::Hardlink(existing) => {
                std::fs::hard_link(t.join(existing), &p).unwrap();
            }
            Node::Socket => {
                drop(std::os::unix::net::UnixListener::bind(&p).unwrap());
            }
            Node::Fifo(mode) => {
                let c = path_c(&p);
                // SAFETY: c is NUL-terminated.
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), *mode) }, 0);
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
            }
        }
    }
    build_etc(&t, &case.etc_own);
    // File times: an hour before the case's time.
    for (path, node) in &case.nodes {
        if let Node::File(..) = node {
            let c = path_c(&t.join(path));
            let tt = case.time.0 - 3600;
            let ts = [libc::timespec { tv_sec: tt, tv_nsec: 0 }, libc::timespec { tv_sec: tt, tv_nsec: 0 }];
            // SAFETY: c is NUL-terminated and ts holds two timespecs.
            unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        }
    }
    for (path, sec) in &case.touch {
        let c = path_c(&t.join(path));
        let ts = [libc::timespec { tv_sec: *sec, tv_nsec: 0 }, libc::timespec { tv_sec: *sec, tv_nsec: 0 }];
        // SAFETY: c is NUL-terminated and ts holds two timespecs.
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    }
    // Directories' modes last, innermost first, so the files inside them
    // could be made.  (chown and chmod leave the times alone.)
    let (mut dirs, mut chowns): (Vec<_>, Vec<_>) =
        chowns.into_iter().partition(|(p, ..)| Path::new(std::str::from_utf8(p.as_bytes()).unwrap()).is_dir());
    dirs.sort_by_key(|(p, ..)| std::cmp::Reverse(p.as_bytes().len()));
    chowns.extend(dirs);

    std::fs::write(t.join(".faketime"), format!("{} {}\n", case.time.0, case.time.1)).unwrap();

    // Sockets the harness reads: /dev/log, and optionally the journal.
    let mut readers = Vec::new();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut sockets = vec![t.join("devlog")];
    if case.journal {
        std::fs::create_dir_all(t.join("run/systemd/journal")).unwrap();
        sockets.push(t.join("run/systemd/journal/socket"));
    }
    for path in &sockets {
        let sock = UnixDatagram::bind(path).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let stop = stop.clone();
        readers.push(std::thread::spawn(move || {
            let mut msgs: Vec<Vec<u8>> = Vec::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match sock.recv(&mut buf) {
                    Ok(n) => msgs.push(buf[..n].to_vec()),
                    Err(_) if stop.load(std::sync::atomic::Ordering::SeqCst) => break,
                    Err(_) => {}
                }
            }
            msgs
        }));
    }

    let mut binds = vec![
        (path_c(&t), path_c(&fixed_root())),
        (cstr("/etc"), path_c(&t.join(".realetc"))),
        (path_c(&t.join("etc")), cstr("/etc")),
        (path_c(&t.join("dev/kmsg")), cstr("/dev/kmsg")),
    ];
    if Path::new("/dev/log").exists() {
        binds.push((path_c(&t.join("devlog")), cstr("/dev/log")));
    }
    for (real, under) in &case.binds {
        let p = t.join(under);
        if !p.exists() {
            std::fs::create_dir_all(&p).unwrap();
        }
        binds.push((path_c(&p), cstr(real)));
    }
    for (host, real) in &case.host_binds {
        binds.push((cstr(host), cstr(real)));
    }
    let read_only: Vec<CString> = case.read_only.iter().map(|p| cstr(subst(p))).collect();

    std::fs::write(t.join(".stdin"), case.stdin.clone().unwrap_or_default()).unwrap();
    let stdin =
        std::fs::File::open(if case.stdin.is_some() { t.join(".stdin") } else { PathBuf::from("/dev/null") }).unwrap();
    let stdout = std::fs::File::create(t.join(".stdout")).unwrap();
    let stderr = std::fs::File::create(t.join(".stderr")).unwrap();
    let pty = case.pty.map(|(r, c)| openpty(r, c));
    let stdio = match pty {
        Some((_, s)) => [s, s, s],
        None => [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()],
    };

    let mut envp = Vec::new();
    if case.faketime {
        envp.push(cstr(format!("LD_PRELOAD={}", shim().display())));
        envp.push(cstr(format!("TEST_FAKETIME={}", fixed_root().join(".faketime").display())));
    }
    for (k, v) in &case.env {
        envp.push(cstr(format!("{k}={}", subst(v))));
    }
    let mut argv = vec![cstr(prog.name)];
    argv.extend(case.args.iter().map(|a| cstr(subst(a))));
    let mut exe = path_c(bin);
    if let Some(script) = &case.shell {
        std::fs::create_dir_all(t.join(".bin")).unwrap();
        std::os::unix::fs::symlink(bin.canonicalize().unwrap(), t.join(".bin").join(prog.name)).unwrap();
        argv = vec![cstr("sh"), cstr("-c"), cstr(subst(script))];
        exe = cstr("/bin/sh");
        envp.retain(|e| !e.as_bytes().starts_with(b"PATH="));
        envp.push(cstr(format!("PATH={}/.bin:/usr/bin:/bin", fixed_root().display())));
    }

    let pid = spawn_in_sandbox(Spawn {
        binds,
        read_only,
        chowns,
        user: case.user,
        dir: path_c(&fixed_root()),
        stdio,
        ctty: pty.is_some(),
        newroot: if case.own_root { Some(NewRoot::new(&t, bin)) } else { None },
        netns: case.netns,
        exe,
        argv,
        envp,
    });
    // On a pty: read the master until the child is gone and the output drained.
    let mut tty_out = Vec::new();
    let status = if let Some((m, s)) = pty {
        // SAFETY: closing our copy of the slave.
        unsafe { libc::close(s) };
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                // SAFETY: reading into buf from the master we own.
                let n = unsafe { libc::read(m, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n as usize]);
            }
            // SAFETY: closing the master we own.
            unsafe { libc::close(m) };
            out
        });
        let st = wait(pid, Duration::from_secs(20));
        tty_out = reader.join().unwrap();
        st
    } else {
        wait(pid, Duration::from_secs(20))
    };
    assert_ne!(status, "timeout", "{}: {label}: did not exit", case.name);
    if let Some(code) = status.strip_prefix("exit ").and_then(|c| c.parse::<i32>().ok()) {
        assert!(!(118..=127).contains(&code), "{}: {label}: sandbox setup failed ({status})", case.name);
    }

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut logs = Vec::new();
    for r in readers {
        logs.push(r.join().unwrap());
    }
    let mut syslog = String::new();
    for raw in &logs[0] {
        // "<pri>Mmm dd hh:mm:ss ident[pid]: msg": keep the timestamp (the
        // shim controls it), normalize the pid.
        syslog += &normalize(&String::from_utf8_lossy(raw), &t, pid);
        syslog.push('\n');
    }
    let mut journal = String::new();
    if case.journal {
        for raw in &logs[1] {
            let text = String::from_utf8_lossy(raw);
            for l in text.lines() {
                // TID and the code location differ between C and Rust by nature.
                if l.starts_with("TID=")
                    || l.starts_with("CODE_FILE=")
                    || l.starts_with("CODE_LINE=")
                    || l.starts_with("CODE_FUNC=")
                {
                    continue;
                }
                journal += &normalize(l, &t, pid);
                journal.push('\n');
            }
            journal.push_str("--\n");
        }
    }
    let rd = |n: &str| normalize(&String::from_utf8_lossy(&std::fs::read(t.join(n)).unwrap()), &t, pid);
    let (out, err) = if pty.is_some() {
        (normalize(&String::from_utf8_lossy(&tty_out), &t, pid), String::new())
    } else {
        (rd(".stdout"), rd(".stderr"))
    };
    let (out, err) = if case.sorted { (sort_lines(&out), sort_lines(&err)) } else { (out, err) };
    let (out, err) = match case.mask {
        Some(f) => (f(&out), f(&err)),
        None => (out, err),
    };
    let files = snapshot(&t, pid, case.meta);
    Outcome { status, stdout: out, stderr: err, syslog, journal, files }
}

fn sort_lines(s: &str) -> String {
    let mut l: Vec<&str> = s.split_inclusive('\n').collect();
    l.sort();
    l.concat()
}

/// Run a case with the C build and with the port; assert identical outcomes.
pub fn check(prog: &Program, case: Case) -> Outcome {
    assert!(
        prog.c.exists(),
        "reference {} not found (run tools/build-reference.sh or set SYSTEMD_REFERENCE)",
        prog.c.display()
    );
    let c = run(&case, prog, "c", &prog.c);
    let r = run(&case, prog, "r", &prog.rust);
    if c != r {
        let mut msg = format!("case {}: outcomes differ\n", case.name);
        for (what, a, b) in [
            ("status", &c.status, &r.status),
            ("stdout", &c.stdout, &r.stdout),
            ("stderr", &c.stderr, &r.stderr),
            ("syslog", &c.syslog, &r.syslog),
            ("journal", &c.journal, &r.journal),
        ] {
            if a != b {
                msg += &format!("{what}:\n--- C\n{a}\n--- Rust\n{b}\n");
            }
        }
        for k in c.files.keys().chain(r.files.keys()).collect::<std::collections::BTreeSet<_>>() {
            let (a, b) = (c.files.get(k), r.files.get(k));
            if a != b {
                msg += &format!(
                    "file {k}:\n--- C\n{}\n--- Rust\n{}\n",
                    a.map_or("(missing)", |s| s),
                    b.map_or("(missing)", |s| s)
                );
            }
        }
        panic!("{msg}");
    }
    if std::env::var_os("SYSTEMD_DIFF_SHOW").is_some() {
        eprintln!("== {} ==\n{c:#?}", case.name);
    }
    c
}
