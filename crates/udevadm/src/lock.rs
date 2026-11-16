// SPDX-License-Identifier: GPL-2.0-or-later
//! `udevadm-lock.c`.
//!
//! Known difference: `--backing=` on btrfs (whose files have no block
//! device number) fails with ENOTBLK; C asks btrfs for its device.

use shared::errno::{strerror, synthetic};
use shared::locale::{Glyph, glyph};
use shared::options::{Opt, OptionParser, ParserMode, common};
use shared::sd_device::Device;
use shared::sys::{self, OwnedFd};
use shared::{log_debug, log_error_errno, log_info, printo};

const HELP: i32 = 0x100;
const VERSION: i32 = 0x101;
const DEVICE: i32 = 0x102;
const BACKING: i32 = 0x103;
const TIMEOUT: i32 = 0x104;
const PRINT: i32 = 0x105;
const INTROSPECT: i32 = 0x106;

pub const OPTIONS: &[Opt] = &[
    common::help(HELP),
    common::version_with_v(VERSION),
    Opt::new(DEVICE, b'd', Some("device"), Some("DEVICE"), Some("Block device to lock")),
    Opt::new(BACKING, b'b', Some("backing"), Some("FILE"), Some("File whose backing block device to lock")),
    Opt::new(TIMEOUT, b't', Some("timeout"), Some("SECS"), Some("Block at most the specified time waiting for lock")),
    Opt::new(
        PRINT,
        b'p',
        Some("print"),
        None,
        Some("Only show which device would be locked, without running the command"),
    ),
    common::introspect_cli(INTROSPECT),
];

struct Args {
    timeout: u64,
    devices: Vec<Vec<u8>>,
    backing: Vec<Vec<u8>>,
    cmdline: Vec<Vec<u8>>,
    print: bool,
}

fn major(d: u64) -> u32 {
    libc::major(d)
}

fn minor(d: u64) -> u32 {
    libc::minor(d)
}

/// `parse_argv()`: Ok(None) to exit with 0.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<Args>, i32> {
    let mut a = Args { timeout: u64::MAX, devices: Vec::new(), backing: Vec::new(), cmdline: Vec::new(), print: false };
    let mut opts = OptionParser::new(argv, OPTIONS);
    opts.mode = ParserMode::StopAtFirstNonoption;
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            HELP => {
                let r = crate::print_verb_help("lock");
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            VERSION => {
                let r = shared::build::version_only();
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            DEVICE | BACKING => {
                let s = shared::path::path_make_absolute_cwd(&arg)
                    .map_err(|r| log_error_errno!(r, "Failed to make path '", &arg[..], "' absolute: ", strerror(r)))?;
                let s = shared::path::path_simplify(&s);
                let l = if c == DEVICE { &mut a.devices } else { &mut a.backing };
                if !l.contains(&s) {
                    l.push(s);
                }
            }
            TIMEOUT => {
                a.timeout = shared::time::parse_sec(&arg)
                    .map_err(|r| log_error_errno!(r, "Failed to parse --timeout= parameter: ", &arg[..]))?;
            }
            PRINT => a.print = true,
            INTROSPECT => {
                let r = crate::introspect(shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            c => unreachable!("option id {c}"),
        }
    }
    let args = opts.args().to_vec();
    if a.print {
        if !args.is_empty() {
            return Err(log_error_errno!(synthetic(libc::EINVAL), "No arguments expected."));
        }
    } else {
        if args.is_empty() {
            return Err(log_error_errno!(synthetic(libc::EINVAL), "Too few arguments, command to execute."));
        }
        a.cmdline = args;
    }
    if a.devices.is_empty() && a.backing.is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "No devices to lock specified, refusing."));
    }
    Ok(Some(a))
}

/// `block_get_whole_disk(d, &ret)`.
fn block_get_whole_disk(d: u64) -> Result<u64, i32> {
    if major(d) == 0 {
        return Err(-libc::ENODEV);
    }
    let p = |d: u64, s: &str| format!("/sys/dev/block/{}:{}{}", major(d), minor(d), s).into_bytes();
    match shared::sys_net::access(&p(d, "/queue"), libc::F_OK) {
        Ok(()) => return Ok(d),
        Err(r) if r != -libc::ENOENT => return Err(r),
        Err(_) => {}
    }
    shared::sys_net::access(&p(d, "/partition"), libc::F_OK)?;
    let s = shared::fileio::read_one_line_file(&p(d, "/../dev"))?;
    let (ma, mi) = s.split_at(s.iter().position(|&c| c == b':').ok_or(-libc::EINVAL)?);
    let devt = libc::makedev(shared::parse::safe_atou(ma)?, shared::parse::safe_atou(&mi[1..])?);
    shared::sys_net::access(&p(devt, "/queue"), libc::F_OK)?;
    Ok(devt)
}

/// `path_get_whole_disk(path, backing, &ret)`.
fn path_get_whole_disk(path: &[u8], backing: bool) -> Result<u64, i32> {
    let fd = OwnedFd::new(sys::open(path, libc::O_CLOEXEC | libc::O_PATH, 0)?);
    let st = sys::fstat(fd.raw())?;
    let fmt = st.st_mode & libc::S_IFMT;
    let devnum = if fmt == libc::S_IFBLK {
        st.st_rdev
    } else if !backing || (fmt != libc::S_IFREG && fmt != libc::S_IFDIR) || major(st.st_dev) == 0 {
        return Err(-libc::ENOTBLK);
    } else {
        st.st_dev
    };
    block_get_whole_disk(devnum)
}

/// `find_devno()`.
fn find_devno(devnos: &mut Vec<u64>, device: &[u8], backing: bool) -> Result<(), i32> {
    let devt = path_get_whole_disk(device, backing)
        .map_err(|r| log_error_errno!(r, "Failed to find whole block device for '", device, "': ", strerror(r)))?;
    if devnos.contains(&devt) {
        log_debug!(
            "Device ",
            major(devt).to_string(),
            ":",
            minor(devt).to_string(),
            " already listed for locking, ignoring."
        );
        return Ok(());
    }
    devnos.push(devt);
    devnos.sort_unstable_by_key(|&d| (major(d), minor(d)));
    Ok(())
}

/// `lock_generic_with_timeout(fd, LOCK_BSD, LOCK_EX, timeout)`.
fn lock_with_timeout(fd: i32, timeout: u64) -> Result<(), i32> {
    match sys::flock(fd, libc::LOCK_EX | if timeout == u64::MAX { 0 } else { libc::LOCK_NB }) {
        Err(r) if r == -libc::EAGAIN && timeout != 0 => {}
        x => return x,
    }
    let pid = match shared::process::safe_fork(
        "(sd-flock)",
        shared::process::FORK_RESET_SIGNALS | shared::process::FORK_DEATHSIG_SIGKILL,
    ) {
        Ok(p) => p,
        Err(r) => return Err(log_error_errno!(r, "Failed to flock block device in child process: ", strerror(r))),
    };
    if pid == 0 {
        if let Err(r) = sys::flock(fd, libc::LOCK_EX) {
            log_error_errno!(r, "Unable to get an exclusive lock on the device: ", strerror(r));
            sys::exit_now(libc::EXIT_FAILURE);
        }
        sys::exit_now(libc::EXIT_SUCCESS);
    }
    let pidfd = OwnedFd::new(sys::pidfd_open(pid)?);
    let deadline = shared::time::now_monotonic().saturating_add(timeout);
    loop {
        let left = deadline.saturating_sub(shared::time::now_monotonic());
        match shared::sys_net::poll_one(pidfd.raw(), libc::POLLIN, left) {
            Err(r) if r == -libc::EINTR => continue,
            Err(r) => return Err(r),
            Ok(0) => {
                // pidref_done_sigkill_wait()
                let _ = sys::pidfd_send_signal(pidfd.raw(), libc::SIGKILL);
                let _ = sys::waitid_pidfd(pidfd.raw(), libc::WEXITED);
                return Err(-libc::ETIMEDOUT);
            }
            Ok(_) => break,
        }
    }
    let ci = sys::waitid_pidfd(pidfd.raw(), libc::WEXITED)?;
    if ci.code == libc::CLD_EXITED && ci.status == 0 { Ok(()) } else { Err(-libc::EPROTO) }
}

/// `lock_device()`.
fn lock_device(path: &[u8], devno: u64, deadline: u64) -> Result<OwnedFd, i32> {
    let fd = match sys::open(path, libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => return Err(log_error_errno!(r, "Failed to open '", path, "': ", strerror(r))),
    };
    let st = sys::fstat(fd.raw()).map_err(|r| log_error_errno!(r, "Failed to stat '", path, "': ", strerror(r)))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFBLK || st.st_rdev != devno {
        return Err(log_error_errno!(
            synthetic(libc::ENXIO),
            "Path '",
            path,
            "' no longer refers to specified block device ",
            major(devno).to_string(),
            ":",
            minor(devno).to_string(),
            "."
        ));
    }
    if let Err(r) = sys::flock(fd.raw(), libc::LOCK_EX | libc::LOCK_NB) {
        if r != -libc::EAGAIN {
            return Err(log_error_errno!(r, "Failed to lock device '", path, "': ", strerror(r)));
        }
        if deadline == 0 {
            return Err(log_error_errno!(synthetic(libc::EBUSY), "Device '", path, "' is currently locked."));
        }
        let r = if deadline == u64::MAX {
            log_info!("Device '", path, "' is currently locked, waiting", glyph(Glyph::Ellipsis));
            sys::flock(fd.raw(), libc::LOCK_EX)
        } else {
            let left = deadline.saturating_sub(shared::time::now_monotonic());
            log_info!(
                "Device '",
                path,
                "' is currently locked, waiting ",
                shared::time::format_timespan(left, 0),
                glyph(Glyph::Ellipsis)
            );
            match lock_with_timeout(fd.raw(), left) {
                Err(r) if r == -libc::ETIMEDOUT => return Err(log_error_errno!(r, "Timeout reached.")),
                x => x,
            }
        };
        if let Err(r) = r {
            return Err(log_error_errno!(r, "Failed to lock device '", path, "': ", strerror(r)));
        }
    }
    log_debug!(
        "Successfully locked ",
        path,
        " (",
        major(devno).to_string(),
        ":",
        minor(devno).to_string(),
        ")",
        glyph(Glyph::Ellipsis)
    );
    Ok(fd)
}

/// `devname_from_devnum(S_IFBLK, devnum, &node)`.
fn devname_from_devnum(devnum: u64) -> Result<Vec<u8>, i32> {
    if devnum == 0 {
        return Ok(b"/run/systemd/inaccessible/blk".to_vec());
    }
    let dev = Device::new_from_mode_and_devnum(libc::S_IFBLK, devnum)?;
    Ok(dev.get_devname()?.bytes().to_vec())
}

/// `verb_lock_main()`.
pub fn verb_lock_main(argv: Vec<Vec<u8>>) -> i32 {
    let a = match parse_argv(argv) {
        Ok(Some(a)) => a,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    let mut devnos = Vec::new();
    for (list, backing) in [(&a.devices, false), (&a.backing, true)] {
        for i in list {
            if let Err(r) = find_devno(&mut devnos, i, backing) {
                return r;
            }
        }
    }
    let deadline = if a.timeout == 0 || a.timeout == u64::MAX {
        a.timeout
    } else {
        shared::time::now_monotonic().saturating_add(a.timeout)
    };
    let mut fds = Vec::new();
    for &d in &devnos {
        let node = match devname_from_devnum(d) {
            Ok(n) => n,
            Err(r) => return log_error_errno!(r, "Failed to format block device path: ", strerror(r)),
        };
        if a.print {
            printo!(&node[..], "\n");
        } else {
            match lock_device(&node, d, deadline) {
                Ok(fd) => fds.push(fd),
                Err(r) => return r,
            }
        }
    }
    if a.print {
        return 0;
    }
    sys::ignore_signal(libc::SIGINT);
    // The child closes all fds, the locks stay with ours.
    let pid = match shared::process::safe_fork_full(
        "(lock)",
        None,
        &[],
        shared::process::FORK_RESET_SIGNALS
            | shared::process::FORK_DEATHSIG_SIGTERM
            | shared::process::FORK_CLOSE_ALL_FDS
            | shared::process::FORK_RLIMIT_NOFILE_SAFE
            | shared::process::FORK_LOG,
    ) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if pid == 0 {
        sys::execvp(&a.cmdline[0], &a.cmdline);
        let e = sys::errno();
        shared::log::log_open();
        log_error_errno!(-e, "Failed to execute ", &a.cmdline[0][..], ": ", strerror(-e));
        sys::exit_now(libc::EXIT_FAILURE);
    }
    let r = shared::process::wait_for_terminate_and_check(&a.cmdline[0], pid);
    drop(fds);
    r
}
