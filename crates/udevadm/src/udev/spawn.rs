// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-spawn.c`: running `PROGRAM=`, `IMPORT{program}=` and `RUN=`
//! commands, and `pin_callout_binary()` (`build-path.c`).
//!
//! C waits in an sd-event loop: the pipes at normal priority, the child
//! one lower, so output is read before the exit is handled.  Here a
//! `ppoll()` on the pipes and a pidfd does the same.

use shared::errno::{strerror, synthetic};
use shared::sys::{self, OwnedFd};
use shared::time::{USEC_INFINITY, USEC_PER_SEC, format_timespan, now_monotonic};
use shared::{
    log_device_debug, log_device_error, log_device_error_errno, log_device_full_errno, log_device_warning,
    log_device_warning_errno,
};

use super::builtin::udev_builtin_run;
use super::def::EventMode;
use super::event::{DEFAULT_WORKER_TIMEOUT_USEC, Event};

/// `UDEVLIBEXECDIR`.
const UDEVLIBEXECDIR: &[u8] = b"/usr/lib/udev";

/// `udev_warn_timeout(timeout_usec)`.
fn udev_warn_timeout(t: u64) -> u64 {
    if t == USEC_INFINITY { USEC_INFINITY } else { t.div_ceil(3) }
}

/// `open_and_check_executable(name, root=NULL, &path, &fd)`.
fn open_and_check_executable(name: &[u8]) -> Result<(OwnedFd, Vec<u8>), i32> {
    let fd = OwnedFd::new(sys::open(name, libc::O_PATH | libc::O_CLOEXEC, 0)?);
    shared::stat_util::fd_verify_regular(fd.raw())?;
    if let Err(r) = shared::sys_net::access(&shared::fd::proc_fd_path(fd.raw()), libc::X_OK) {
        if r == -libc::ENOENT {
            // /proc/ is not mounted: fall back to access().
            shared::sys_net::access(name, libc::X_OK)?;
        } else {
            return Err(r);
        }
    }
    let p = shared::path::path_simplify(&shared::path::path_make_absolute_cwd(name)?);
    Ok((fd, p))
}

/// `pin_callout_binary(path, &found)`.  `$FOO_ID_PATH` overrides
/// `foo_id`; there is no build directory to look in.
fn pin_callout_binary(path: &[u8]) -> Result<(OwnedFd, Vec<u8>), i32> {
    let f = shared::path::path_extract_filename(path)?;
    if path.ends_with(b"/") {
        return Err(-libc::EISDIR);
    }
    let mut var: Vec<u8> = f.to_ascii_uppercase().iter().map(|&c| if c == b'-' { b'_' } else { c }).collect();
    var.extend_from_slice(b"_PATH");
    if let Some(e) = shared::env::secure_getenv(std::str::from_utf8(&var).unwrap_or("")) {
        return open_and_check_executable(&e);
    }
    // find_executable_full(path, ...): the path is absolute here.
    open_and_check_executable(path)
}

/// What the event loop keeps (`Spawn`).
struct Spawn<'a> {
    event: &'a Event,
    cmd: &'a [u8],
    pid: i32,
    accept_failure: bool,
    fd_stdout: Option<OwnedFd>,
    fd_stderr: Option<OwnedFd>,
    stdout_on: bool,
    stderr_on: bool,
    result: Option<Vec<u8>>,
    result_size: usize,
    truncated: bool,
    log_output: bool,
}

impl Spawn<'_> {
    /// `on_spawn_io()`.
    fn on_io(&mut self, is_stdout: bool) {
        let dev = &self.event.dev;
        let fd = if is_stdout { self.fd_stdout.as_ref() } else { self.fd_stderr.as_ref() }.expect("open").raw();
        let read_to_result = is_stdout && self.result.is_some() && !self.truncated;
        let size = if read_to_result { self.result_size - self.result.as_ref().expect("set").len() } else { 4096 - 1 };
        let mut buf = vec![0u8; size];
        let l = match sys::read(fd, &mut buf) {
            Err(e) => {
                log_device_full_errno!(
                    dev,
                    if e == -libc::EAGAIN || e == -libc::EINTR {
                        shared::log::LOG_DEBUG
                    } else {
                        shared::log::LOG_WARNING
                    },
                    e,
                    "Failed to read ",
                    if is_stdout { "stdout" } else { "stderr" },
                    " of '",
                    self.cmd,
                    "', ignoring: ",
                    strerror(e)
                );
                return;
            }
            Ok(0) => {
                if is_stdout {
                    self.stdout_on = false;
                } else {
                    self.stderr_on = false;
                }
                return;
            }
            Ok(l) => l,
        };
        let mut l = l;
        if read_to_result {
            if l == size {
                log_device_warning!(
                    dev,
                    "Truncating stdout of '",
                    self.cmd,
                    "' up to ",
                    (self.result_size - 1).to_string(),
                    " byte."
                );
                l -= 1;
                self.truncated = true;
            }
            self.result.as_mut().expect("set").extend_from_slice(&buf[..l]);
        }
        let chunk = &buf[..l];
        let chunk = &chunk[..chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len())];
        if l > 0 && self.log_output {
            match shared::extract::strv_split_newlines_full(chunk, shared::extract::EXTRACT_RETAIN_ESCAPE) {
                Err(_) => {
                    log_device_debug!(
                        dev,
                        "Failed to split output from '",
                        self.cmd,
                        "'(",
                        if is_stdout { "out" } else { "err" },
                        "), ignoring: ",
                        strerror(-libc::EINVAL)
                    );
                }
                Ok(v) => {
                    for q in v {
                        log_device_debug!(
                            dev,
                            "'",
                            self.cmd,
                            "'(",
                            if is_stdout { "out" } else { "err" },
                            ") '",
                            q,
                            "'"
                        );
                    }
                }
            }
        }
    }

    /// `on_spawn_exit()`: the loop's exit code.
    fn on_exit(&self, code: i32, status: i32) -> i32 {
        let dev = &self.event.dev;
        match code {
            libc::CLD_EXITED => {
                if status == 0 {
                    log_device_debug!(dev, "Process '", self.cmd, "' succeeded.");
                } else {
                    shared::log_device_full_errno!(
                        dev,
                        if self.accept_failure { shared::log::LOG_DEBUG } else { shared::log::LOG_WARNING },
                        0,
                        "Process '",
                        self.cmd,
                        "' failed with exit code ",
                        status.to_string(),
                        "."
                    );
                }
                status
            }
            libc::CLD_KILLED | libc::CLD_DUMPED => {
                log_device_error!(
                    dev,
                    "Process '",
                    self.cmd,
                    "' terminated by signal ",
                    shared::signal::signal_to_string(status),
                    "."
                );
                -libc::EIO
            }
            _ => {
                log_device_error!(dev, "Process '", self.cmd, "' failed due to unknown reason.");
                -libc::EIO
            }
        }
    }

    /// `spawn_wait()`.
    fn wait(&mut self, cmd_birth_usec: u64, timeout_usec: u64, timeout_warn_usec: u64, timeout_signal: i32) -> i32 {
        let dev = self.event.dev.clone();
        let pidfd = match sys::pidfd_open(self.pid) {
            Ok(f) => OwnedFd::new(f),
            Err(r) => {
                return log_device_debug_errno(&dev, r, "Failed to create sigchild event source: ");
            }
        };
        let mut warned = timeout_usec == USEC_INFINITY || timeout_warn_usec >= timeout_usec;
        let mut killed = timeout_usec == USEC_INFINITY;
        loop {
            let mut fds: Vec<(i32, i16)> = Vec::new();
            let mut which: Vec<u8> = Vec::new();
            if self.stdout_on {
                fds.push((self.fd_stdout.as_ref().expect("open").raw(), libc::POLLIN));
                which.push(1);
            }
            if self.stderr_on {
                fds.push((self.fd_stderr.as_ref().expect("open").raw(), libc::POLLIN));
                which.push(2);
            }
            fds.push((pidfd.raw(), libc::POLLIN));
            which.push(0);
            let now = now_monotonic();
            let mut deadline = u64::MAX;
            if !warned {
                deadline = deadline.min(cmd_birth_usec.saturating_add(timeout_warn_usec));
            }
            if !killed {
                deadline = deadline.min(cmd_birth_usec.saturating_add(timeout_usec));
            }
            let wait = if deadline == u64::MAX { u64::MAX } else { deadline.saturating_sub(now) };
            let revents = match sys::poll_many(&fds, wait) {
                Ok(r) => r,
                Err(r) if r == -libc::EINTR => continue,
                Err(r) => return r,
            };
            let ready = |w: u8| which.iter().zip(&revents).any(|(&x, &re)| x == w && re != 0);
            if ready(1) {
                self.on_io(true);
                continue;
            }
            if ready(2) {
                self.on_io(false);
                continue;
            }
            if ready(0) {
                match sys::waitid_nohang(self.pid) {
                    Ok(Some((code, status))) => return self.on_exit(code, status),
                    Ok(None) => continue,
                    Err(r) => return r,
                }
            }
            let now = now_monotonic();
            if !killed && now >= cmd_birth_usec.saturating_add(timeout_usec) {
                killed = true;
                log_device_error!(
                    dev,
                    "Spawned process '",
                    self.cmd,
                    "' [",
                    self.pid.to_string(),
                    "] timed out after ",
                    format_timespan(timeout_usec, USEC_PER_SEC),
                    ", killing."
                );
                // pidref_kill_and_sigcont()
                let _ = sys::kill(self.pid, timeout_signal);
                if timeout_signal != libc::SIGCONT && timeout_signal != libc::SIGKILL {
                    let _ = sys::kill(self.pid, libc::SIGCONT);
                }
            } else if !warned && now >= cmd_birth_usec.saturating_add(timeout_warn_usec) {
                warned = true;
                log_device_warning!(
                    dev,
                    "Spawned process '",
                    self.cmd,
                    "' [",
                    self.pid.to_string(),
                    "] is taking longer than ",
                    format_timespan(timeout_warn_usec, USEC_PER_SEC),
                    " to complete."
                );
            }
        }
    }
}

fn log_device_debug_errno(dev: &shared::sd_device::Device, r: i32, msg: &str) -> i32 {
    shared::log_device_debug_errno!(dev, r, msg, strerror(r))
}

/// `udev_event_spawn(event, accept_failure, cmd, result, result_size,
/// &truncated)`: (exit status, the result, truncated).  The status is 0
/// on success and positive if the program failed.
pub fn udev_event_spawn(
    event: &Event,
    accept_failure: bool,
    cmd: &[u8],
    result_size: Option<usize>,
) -> Result<(i32, Vec<u8>, bool), i32> {
    let dev = &event.dev;
    if event.event_mode == EventMode::UdevadmTest
        && ![&b"ata_id"[..], b"cdrom_id", b"dmi_memory_id", b"fido_id", b"mtd_probe", b"scsi_id"]
            .iter()
            .any(|p| cmd.starts_with(p))
    {
        log_device_debug!(dev, "Running in test mode, skipping execution of '", cmd, "'.");
        return Ok((0, Vec::new(), false));
    }
    let (timeout_usec, timeout_signal, _) =
        event.worker_timeouts.unwrap_or((DEFAULT_WORKER_TIMEOUT_USEC, libc::SIGKILL, 0));
    let now_usec = now_monotonic();
    let age_usec = now_usec.saturating_sub(event.birth_usec);
    let cmd_timeout_usec = timeout_usec.saturating_sub(age_usec);
    if cmd_timeout_usec == 0 {
        return Err(log_device_warning_errno!(
            dev,
            synthetic(libc::ETIME),
            "The event already takes longer (",
            format_timespan(age_usec, 1),
            ") than the timeout (",
            format_timespan(timeout_usec, 1),
            "), skipping execution of '",
            cmd,
            "'."
        ));
    }
    let log_info = shared::log::log_get_max_level() >= shared::log::LOG_INFO;
    let outpipe = if result_size.is_some() || log_info {
        match sys::pipe2(libc::O_NONBLOCK | libc::O_CLOEXEC) {
            Ok((r, w)) => Some((OwnedFd::new(r), OwnedFd::new(w))),
            Err(e) => {
                return Err(log_device_error_errno!(
                    dev,
                    e,
                    "Failed to create pipe for command '",
                    cmd,
                    "': ",
                    strerror(e)
                ));
            }
        }
    } else {
        None
    };
    let errpipe = if log_info {
        match sys::pipe2(libc::O_NONBLOCK | libc::O_CLOEXEC) {
            Ok((r, w)) => Some((OwnedFd::new(r), OwnedFd::new(w))),
            Err(e) => {
                return Err(log_device_error_errno!(
                    dev,
                    e,
                    "Failed to create pipe for command '",
                    cmd,
                    "': ",
                    strerror(e)
                ));
            }
        }
    } else {
        None
    };
    let mut argv = match shared::extract::strv_split_full(
        cmd,
        None,
        shared::extract::EXTRACT_UNQUOTE | shared::extract::EXTRACT_RELAX | shared::extract::EXTRACT_RETAIN_ESCAPE,
    ) {
        Ok(a) => a,
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to split command: ", strerror(r))),
    };
    if argv.first().is_none_or(|a| a.is_empty()) {
        return Err(log_device_error_errno!(dev, synthetic(libc::EINVAL), "Invalid command '", cmd, "'"));
    }
    if !shared::path::path_is_absolute(&argv[0]) {
        argv[0] = shared::path::path_join(&[UDEVLIBEXECDIR, &argv[0]]);
    }
    let (fd_executable, found) = match pin_callout_binary(&argv[0]) {
        Ok(x) => x,
        Err(r) => {
            return Err(log_device_error_errno!(
                dev,
                r,
                "Failed to find and pin callout binary \"",
                &argv[0],
                "\": ",
                strerror(r)
            ));
        }
    };
    log_device_debug!(dev, "Found callout binary: \"", &found, "\".");
    argv[0] = found;
    let envp: Vec<Vec<u8>> = match dev.get_properties_strv() {
        Ok(p) => p.iter().map(|x| x.bytes().to_vec()).collect(),
        Err(r) => return Err(log_device_error_errno!(dev, r, "Failed to get device properties")),
    };
    log_device_debug!(dev, "Starting '", cmd, "'");
    let out_w = outpipe.as_ref().map(|(_, w)| w.raw()).unwrap_or(-libc::EBADF);
    let err_w = errpipe.as_ref().map(|(_, w)| w.raw()).unwrap_or(-libc::EBADF);
    let pid = match shared::process::safe_fork_full(
        "(spawn)",
        Some([-libc::EBADF, out_w, err_w]),
        &[fd_executable.raw()],
        shared::process::FORK_RESET_SIGNALS
            | shared::process::FORK_CLOSE_ALL_FDS
            | shared::process::FORK_DEATHSIG_SIGTERM
            | shared::process::FORK_REARRANGE_STDIO
            | shared::process::FORK_LOG
            | shared::process::FORK_RLIMIT_NOFILE_SAFE,
    ) {
        Ok(p) => p,
        Err(r) => {
            return Err(log_device_error_errno!(
                dev,
                r,
                "Failed to fork() to execute command '",
                cmd,
                "': ",
                strerror(r)
            ));
        }
    };
    if pid == 0 {
        // fexecve_or_execve() without fexecve (ENABLE_FEXECVE is 0).
        let _ = sys::execve(&argv[0], &argv, &envp);
        sys::exit_now(libc::EXIT_FAILURE);
    }
    let (out_r, out_w) = match outpipe {
        Some((r, w)) => (Some(r), Some(w)),
        None => (None, None),
    };
    let (err_r, err_w) = match errpipe {
        Some((r, w)) => (Some(r), Some(w)),
        None => (None, None),
    };
    drop(out_w);
    drop(err_w);
    let mut spawn = Spawn {
        event,
        cmd,
        pid,
        accept_failure,
        stdout_on: out_r.is_some(),
        stderr_on: err_r.is_some(),
        log_output: err_r.is_some(),
        fd_stdout: out_r,
        fd_stderr: err_r,
        result: result_size.map(|_| Vec::new()),
        result_size: result_size.unwrap_or(0),
        truncated: false,
    };
    let r = spawn.wait(now_usec, cmd_timeout_usec, udev_warn_timeout(cmd_timeout_usec), timeout_signal);
    if r < 0 {
        return Err(log_device_error_errno!(dev, r, "Failed to wait for spawned command '", cmd, "': ", strerror(r)));
    }
    let mut result = spawn.result.take().unwrap_or_default();
    if let Some(n) = result.iter().position(|&b| b == 0) {
        result.truncate(n);
    }
    Ok((r, result, spawn.truncated))
}

/// `udev_event_execute_run(event)`.
pub fn udev_event_execute_run(event: &mut Event) {
    let list = event.run_list.clone();
    for (command, builtin) in list {
        if let Some(b) = builtin {
            log_device_debug!(event.dev, "Running built-in command \"", &command, "\"");
            if let Err(r) = udev_builtin_run(event, b, &command) {
                shared::log_device_debug_errno!(
                    event.dev,
                    r,
                    "Failed to run built-in command \"",
                    &command,
                    "\", ignoring: ",
                    strerror(r)
                );
            }
        } else {
            if let Some((timeout_usec, _, exec_delay_usec)) = event.worker_timeouts
                && exec_delay_usec > 0
            {
                let age_usec = now_monotonic().saturating_sub(event.birth_usec);
                if exec_delay_usec >= timeout_usec.saturating_sub(age_usec) {
                    log_device_warning!(
                        event.dev,
                        "Cannot delay execution of \"",
                        &command,
                        "\" for ",
                        format_timespan(exec_delay_usec, USEC_PER_SEC),
                        ", skipping."
                    );
                    continue;
                }
                log_device_debug!(
                    event.dev,
                    "Delaying execution of \"",
                    &command,
                    "\" for ",
                    format_timespan(exec_delay_usec, USEC_PER_SEC),
                    "."
                );
                std::thread::sleep(std::time::Duration::from_micros(exec_delay_usec));
            }
            log_device_debug!(event.dev, "Running command \"", &command, "\"");
            match udev_event_spawn(event, false, &command, None) {
                Err(r) => {
                    log_device_warning_errno!(
                        event.dev,
                        r,
                        "Failed to execute '",
                        &command,
                        "', ignoring: ",
                        strerror(r)
                    );
                }
                Ok((r, _, _)) if r > 0 => {
                    log_device_debug!(
                        event.dev,
                        "Command \"",
                        &command,
                        "\" returned ",
                        r.to_string(),
                        " (error), ignoring."
                    );
                }
                Ok(_) => {}
            }
        }
    }
}
