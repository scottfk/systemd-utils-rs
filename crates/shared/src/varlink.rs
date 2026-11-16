// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-varlink.c` and `json-stream.c`: Varlink over AF_UNIX stream sockets,
//! with the same state machine and debug logging as C.
//!
//! The client side is synchronous (`Client::call()`), as udevadm uses it.
//! The server side runs on `event::Event<T>`; it lives in the loop's user
//! state, which method handlers also get.
//!
//! Known differences: no fd passing, no "more"/"oneway"/"upgrade" calls on
//! the client side, no deferred replies (a method handler answers before it
//! returns), and `org.varlink.service.GetInterfaceDescription` answers
//! `MethodNotImplemented`, as the IDL text is not ported.

use crate::errno::{strerror, synthetic};
use crate::event::{Enabled, Event, Fired, Id};
use crate::json::{self, Json};
use crate::locale::{Glyph, glyph};
use crate::sys::{self, Fd};
use crate::{log_debug, log_debug_errno};

pub const ERROR_DISCONNECTED: &str = "io.systemd.Disconnected";
pub const ERROR_TIMEOUT: &str = "io.systemd.TimedOut";
pub const ERROR_PROTOCOL: &str = "io.systemd.Protocol";
pub const ERROR_SYSTEM: &str = "io.systemd.System";
pub const ERROR_INTERFACE_NOT_FOUND: &str = "org.varlink.service.InterfaceNotFound";
pub const ERROR_METHOD_NOT_FOUND: &str = "org.varlink.service.MethodNotFound";
pub const ERROR_METHOD_NOT_IMPLEMENTED: &str = "org.varlink.service.MethodNotImplemented";
pub const ERROR_INVALID_PARAMETER: &str = "org.varlink.service.InvalidParameter";
pub const ERROR_PERMISSION_DENIED: &str = "org.varlink.service.PermissionDenied";
pub const ERROR_EXPECTED_MORE: &str = "org.varlink.service.ExpectedMore";
pub const ERROR_EXPECTED_UPGRADE: &str = "org.varlink.service.ExpectedUpgrade";

/// `VARLINK_DEFAULT_TIMEOUT_USEC`.
pub const DEFAULT_TIMEOUT_USEC: u64 = 45 * 1_000_000;
/// `JSON_STREAM_BUFFER_MAX_DEFAULT`.
const BUFFER_MAX: usize = 16 * 1024 * 1024;
/// `JSON_STREAM_READ_SIZE_DEFAULT`.
const READ_SIZE: usize = 64 * 1024;

pub const SERVER_ROOT_ONLY: u32 = 1 << 0;
pub const SERVER_MYSELF_ONLY: u32 = 1 << 1;
pub const SERVER_INHERIT_USERDATA: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    IdleClient,
    AwaitingReply,
    Calling,
    Called,
    ProcessingReply,
    IdleServer,
    ProcessingMethod,
    ProcessingMethodOneway,
    ProcessedMethod,
    PendingMethod,
    PendingDisconnect,
    PendingTimeout,
    ProcessingDisconnect,
    ProcessingTimeout,
    ProcessingFailure,
    Disconnected,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::IdleClient => "idle-client",
            State::AwaitingReply => "awaiting-reply",
            State::Calling => "calling",
            State::Called => "called",
            State::ProcessingReply => "processing-reply",
            State::IdleServer => "idle-server",
            State::ProcessingMethod => "processing-method",
            State::ProcessingMethodOneway => "processing-method-oneway",
            State::ProcessedMethod => "processed-method",
            State::PendingMethod => "pending-method",
            State::PendingDisconnect => "pending-disconnect",
            State::PendingTimeout => "pending-timeout",
            State::ProcessingDisconnect => "processing-disconnect",
            State::ProcessingTimeout => "processing-timeout",
            State::ProcessingFailure => "processing-failure",
            State::Disconnected => "disconnected",
        }
    }

    /// `VARLINK_STATE_IS_ALIVE()`.
    fn is_alive(self) -> bool {
        !matches!(
            self,
            State::PendingDisconnect
                | State::PendingTimeout
                | State::ProcessingDisconnect
                | State::ProcessingTimeout
                | State::ProcessingFailure
                | State::Disconnected
        )
    }
}

/// `JsonStreamPhase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reading,
    AwaitingReply,
    IdleClient,
    PendingOutput,
    Other,
}

/// One connection: the transport (`JsonStream`) and the Varlink state.
#[derive(Debug)]
pub struct Link {
    fd: Fd,
    description: Option<Vec<u8>>,
    state: Option<State>,
    connecting: bool,
    read_disconnected: bool,
    write_disconnected: bool,
    got_pollhup: bool,
    input: Vec<u8>,
    input_unscanned: usize,
    output: Vec<u8>,
    current: Option<Json>,
    n_pending: u32,
    timeout: u64,
    last_activity: u64,
    ucred: Option<(i32, u32, u32)>,
    // Event sources, when attached.
    io: Option<Id>,
    time: Option<Id>,
    defer: Option<Id>,
    quit: Option<Id>,
}

impl Drop for Link {
    fn drop(&mut self) {
        if self.fd >= 0 {
            sys::close(self.fd);
        }
    }
}

impl Link {
    fn new(fd: Fd) -> Link {
        Link {
            fd,
            description: None,
            state: None,
            connecting: false,
            read_disconnected: false,
            write_disconnected: false,
            got_pollhup: false,
            input: Vec::new(),
            input_unscanned: 0,
            output: Vec::new(),
            current: None,
            n_pending: 0,
            timeout: DEFAULT_TIMEOUT_USEC,
            last_activity: 0,
            ucred: None,
            io: None,
            time: None,
            defer: None,
            quit: None,
        }
    }

    /// `varlink_description()`.
    fn desc(&self) -> &[u8] {
        self.description.as_deref().unwrap_or(b"varlink")
    }

    /// `json_stream_description()`.
    fn js_desc(&self) -> &[u8] {
        self.description.as_deref().unwrap_or(b"json-stream")
    }

    pub fn state(&self) -> State {
        self.state.unwrap_or(State::Disconnected)
    }

    /// `varlink_set_state()`.
    fn set_state(&mut self, state: State) {
        match self.state {
            None => {
                log_debug!(self.desc(), ": Setting state ", state.name());
            }
            Some(old) => {
                log_debug!(
                    self.desc(),
                    ": Changing state ",
                    old.name(),
                    " ",
                    glyph(Glyph::ArrowRight),
                    " ",
                    state.name()
                );
            }
        }
        self.state = Some(state);
    }

    /// `varlink_phase()`.
    fn phase(&self) -> Phase {
        let st = self.state();
        if matches!(st, State::AwaitingReply | State::Calling) && self.current.is_none() {
            return Phase::AwaitingReply;
        }
        if st == State::IdleServer && self.current.is_none() {
            return Phase::Reading;
        }
        if st == State::IdleClient {
            return Phase::IdleClient;
        }
        if st == State::PendingMethod {
            return Phase::PendingOutput;
        }
        Phase::Other
    }

    /// `json_stream_get_events()`.
    fn get_events(&self) -> u32 {
        if self.connecting {
            return libc::POLLOUT as u32;
        }
        let mut ret = 0;
        if matches!(self.phase(), Phase::Reading | Phase::AwaitingReply)
            && !self.read_disconnected
            && self.input_unscanned == 0
        {
            ret |= libc::POLLIN as u32;
        }
        if !self.write_disconnected && !self.output.is_empty() {
            ret |= libc::POLLOUT as u32;
        }
        ret
    }

    /// `json_stream_handle_revents()`.
    fn handle_revents(&mut self, revents: u32) {
        if self.connecting {
            if revents & (libc::POLLOUT | libc::POLLHUP) as u32 == 0 {
                return;
            }
            log_debug!(self.js_desc(), ": Asynchronous connection completed.");
            self.connecting = false;
            return;
        }
        if revents & libc::POLLHUP as u32 != 0 {
            log_debug!(self.js_desc(), ": Got POLLHUP from socket.");
            self.got_pollhup = true;
        }
    }

    /// `json_stream_get_timeout()`.
    fn get_timeout(&self) -> u64 {
        if self.phase() != Phase::AwaitingReply {
            return u64::MAX;
        }
        self.last_activity.saturating_add(self.timeout)
    }

    /// `json_stream_should_disconnect()`.
    fn should_disconnect(&self) -> bool {
        if self.connecting {
            return false;
        }
        if !self.output.is_empty() && !self.write_disconnected {
            return false;
        }
        if self.read_disconnected && self.write_disconnected {
            return true;
        }
        let phase = self.phase();
        if matches!(phase, Phase::Reading | Phase::AwaitingReply) && self.read_disconnected {
            return true;
        }
        if phase == Phase::IdleClient && (self.write_disconnected || self.got_pollhup) {
            return true;
        }
        if phase == Phase::PendingOutput && (self.write_disconnected || self.output.is_empty()) && self.got_pollhup {
            return true;
        }
        false
    }

    /// `json_stream_enqueue()` via `json_stream_format_json()`.
    fn enqueue(&mut self, m: &Json) -> Result<(), i32> {
        let text = json::dump(m, 0);
        if self.output.len() + text.len() + 1 > BUFFER_MAX {
            return Err(-libc::ENOBUFS);
        }
        if crate::log::debug_logging() {
            log_debug!(self.js_desc(), ": Sending message: ", &text[..]);
        }
        self.output.extend_from_slice(&text);
        self.output.push(0);
        Ok(())
    }

    /// `json_stream_write()`.
    fn write(&mut self) -> Result<i32, i32> {
        if self.connecting || self.write_disconnected || self.output.is_empty() {
            return Ok(0);
        }
        match sys::send_nosignal(self.fd, &self.output) {
            Err(e) if e == -libc::EAGAIN || e == -libc::EINTR => Ok(0),
            Err(e) if is_disconnect(e) => {
                self.write_disconnected = true;
                Ok(1)
            }
            Err(e) => Err(e),
            Ok(n) => {
                self.output.drain(..n);
                self.last_activity = crate::time::now_monotonic();
                Ok(1)
            }
        }
    }

    /// `json_stream_read()`.
    fn read(&mut self) -> Result<i32, i32> {
        if self.connecting || self.input_unscanned > 0 || self.read_disconnected {
            return Ok(0);
        }
        if self.input.len() >= BUFFER_MAX {
            return Err(-libc::ENOBUFS);
        }
        let mut buf = vec![0u8; READ_SIZE.min(BUFFER_MAX - self.input.len())];
        match sys::recv(self.fd, &mut buf, libc::MSG_DONTWAIT) {
            Err(e) if e == -libc::EAGAIN || e == -libc::EINTR => Ok(0),
            Err(e) if is_disconnect(e) => {
                self.read_disconnected = true;
                Ok(1)
            }
            Err(e) => Err(e),
            Ok(0) => {
                self.read_disconnected = true;
                Ok(1)
            }
            Ok(n) => {
                self.input.extend_from_slice(&buf[..n]);
                self.input_unscanned = n;
                Ok(1)
            }
        }
    }

    /// `json_stream_parse()` into `current`.
    fn parse(&mut self) -> Result<i32, i32> {
        if self.current.is_some() || self.input_unscanned == 0 {
            return Ok(0);
        }
        let start = self.input.len() - self.input_unscanned;
        let Some(off) = self.input[start..].iter().position(|&c| c == 0) else {
            self.input_unscanned = 0;
            return Ok(0);
        };
        let end = start + off;
        let parsed = json::parse(&self.input[..end]);
        let m = match parsed {
            Err(r) => {
                self.input.clear();
                self.input_unscanned = 0;
                return Err(log_debug_errno!(r, self.js_desc(), ": Failed to parse JSON object: ", strerror(r)));
            }
            Ok(m) => m,
        };
        if crate::log::debug_logging() {
            log_debug!(self.js_desc(), ": Received message: ", json::dump(&m, 0));
        }
        self.input.drain(..=end);
        self.input_unscanned = self.input.len();
        self.current = Some(m);
        Ok(1)
    }

    /// `varlink_test_disconnect()`.
    fn test_disconnect(&mut self) -> bool {
        if !self.state().is_alive() || !self.should_disconnect() {
            return false;
        }
        self.set_state(State::PendingDisconnect);
        true
    }

    /// `varlink_test_timeout()`.
    fn test_timeout(&mut self) -> bool {
        let deadline = self.get_timeout();
        if deadline == u64::MAX || crate::time::now_monotonic() < deadline {
            return false;
        }
        self.set_state(State::PendingTimeout);
        true
    }

    /// `json_stream_wait()`.
    fn wait(&mut self, timeout: u64) -> Result<i32, i32> {
        let events = self.get_events();
        let deadline = self.get_timeout();
        let timeout = if deadline != u64::MAX {
            timeout.min(deadline.saturating_sub(crate::time::now_monotonic()))
        } else {
            timeout
        };
        match sys::poll_many(&[(self.fd, events as i16)], timeout) {
            Err(e) if e == -libc::EINTR || e == -libc::EAGAIN => Ok(1),
            Err(e) => Err(e),
            Ok(rev) => {
                if rev[0] == 0 {
                    return Ok(0);
                }
                self.handle_revents(rev[0] as u16 as u32);
                Ok(1)
            }
        }
    }

    /// `json_stream_flush()`.
    fn flush(&mut self) -> Result<i32, i32> {
        let mut ret = 0;
        loop {
            if self.output.is_empty() {
                break;
            }
            if self.write_disconnected {
                return Err(-libc::ECONNRESET);
            }
            if self.write()? > 0 {
                ret = 1;
                continue;
            }
            if let Err(r) = self.wait(u64::MAX) {
                return Err(log_debug_errno!(r, self.js_desc(), ": Poll failed on fd: ", strerror(r)));
            }
        }
        Ok(ret)
    }

    pub fn peer_uid(&mut self) -> Result<u32, i32> {
        if self.ucred.is_none() {
            self.ucred = Some(sys::peer_cred(self.fd)?);
        }
        Ok(self.ucred.map(|c| c.1).unwrap_or(u32::MAX))
    }
}

/// `ERRNO_IS_NEG_DISCONNECT()`.
pub fn is_disconnect(e: i32) -> bool {
    matches!(
        -e,
        libc::ECONNABORTED
            | libc::ECONNREFUSED
            | libc::ECONNRESET
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::ENETRESET
            | libc::ENETUNREACH
            | libc::ENONET
            | libc::ENOPROTOOPT
            | libc::ENOTCONN
            | libc::EPIPE
            | libc::EPROTO
            | libc::ESHUTDOWN
            | libc::ETIMEDOUT
    )
}

/// `sd_varlink_error_to_errno(error, parameters)`.
pub fn error_to_errno(error: &[u8], parameters: Option<&Json>) -> i32 {
    let table: &[(&str, i32)] = &[
        (ERROR_DISCONNECTED, -libc::ECONNRESET),
        (ERROR_TIMEOUT, -libc::ETIMEDOUT),
        (ERROR_PROTOCOL, -libc::EPROTO),
        (ERROR_INTERFACE_NOT_FOUND, -libc::EADDRNOTAVAIL),
        (ERROR_METHOD_NOT_FOUND, -libc::ENXIO),
        (ERROR_METHOD_NOT_IMPLEMENTED, -libc::ENOTTY),
        (ERROR_INVALID_PARAMETER, -libc::EINVAL),
        (ERROR_PERMISSION_DENIED, -libc::EACCES),
        (ERROR_EXPECTED_MORE, -libc::EBADE),
        (ERROR_EXPECTED_UPGRADE, -libc::EPROTOTYPE),
    ];
    if let Some((_, v)) = table.iter().find(|(e, _)| e.as_bytes() == error) {
        return *v;
    }
    if error != ERROR_SYSTEM.as_bytes() {
        return -libc::EBADR;
    }
    let Some(p) = parameters else { return -libc::EBADR };
    if let Some(o) = p.get("origin")
        && o.as_str() != Some(b"linux")
    {
        return -libc::EBADR;
    }
    if let Some(n) = p.get("errnoName") {
        let Some(n) = n.as_str() else { return -libc::EBADR };
        if let Some(v) = (1..4096).find(|&e| sys::errno_name(e).as_deref() == Some(n)) {
            return -v;
        }
    }
    match p.get("errno").and_then(Json::as_i64) {
        Some(e) if e > 0 && e < 4096 => -(e as i32),
        _ => -libc::EBADR,
    }
}

/// `JSON_BUILD_PAIR_VARIANT_NON_EMPTY()`: null and `{}` are left out.
fn non_empty(p: Option<Json>) -> Option<Json> {
    match p {
        None | Some(Json::Null) => None,
        Some(Json::Object(o)) if o.is_empty() => None,
        Some(v) => Some(v),
    }
}

/// `varlink_sanitize_incoming_parameters()`.
fn sanitize(p: Option<&Json>) -> Result<Json, i32> {
    match p {
        None | Some(Json::Null) => Ok(Json::Object(Vec::new())),
        Some(v @ Json::Object(_)) => Ok(v.clone()),
        Some(_) => Err(-libc::EINVAL),
    }
}

/// A synchronous client connection (`sd_varlink` on the client side).
#[derive(Debug)]
pub struct Client {
    link: Link,
}

impl Drop for Client {
    /// `sd_varlink_flush_close_unref()`.
    fn drop(&mut self) {
        if self.link.state() != State::Disconnected {
            let _ = self.link.flush();
        }
        self.close();
    }
}

impl Client {
    /// `sd_varlink_connect_address(&v, address)`.
    pub fn connect_address(address: &[u8]) -> Result<Client, i32> {
        let mut link = Link::new(-1);
        let fd = match sys::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) {
            Ok(fd) => fd,
            Err(r) => {
                return Err(log_debug_errno!(r, link.js_desc(), ": Failed to create AF_UNIX socket: ", strerror(r)));
            }
        };
        link.fd = crate::log::fd_move_above_stdio(fd);
        if let Err(r) = sys::connect_unix(link.fd, address) {
            if r != -libc::EAGAIN && r != -libc::EINPROGRESS {
                return Err(log_debug_errno!(r, link.js_desc(), ": Failed to connect to ", address, ": ", strerror(r)));
            }
            link.connecting = true;
        }
        link.set_state(State::IdleClient);
        Ok(Client { link })
    }

    /// `sd_varlink_set_description()`.
    pub fn set_description(&mut self, d: &[u8]) {
        self.link.description = Some(d.to_vec());
    }

    /// `sd_varlink_set_relative_timeout()`: 0 is the default.
    pub fn set_relative_timeout(&mut self, t: u64) {
        self.link.timeout = if t == 0 { DEFAULT_TIMEOUT_USEC } else { t };
    }

    /// `sd_varlink_close()`.
    pub fn close(&mut self) {
        if self.link.state() == State::Disconnected {
            return;
        }
        self.link.set_state(State::Disconnected);
        self.link.current = None;
        if self.link.fd >= 0 {
            sys::close(self.link.fd);
            self.link.fd = -1;
        }
    }

    /// `varlink_dispatch_reply()` for a synchronous call.
    fn dispatch_reply(&mut self) -> i32 {
        let l = &mut self.link;
        if l.state() != State::Calling {
            return 0;
        }
        let Some(cur) = &l.current else { return 0 };
        let mut ok = false;
        if let Json::Object(o) = cur {
            ok = true;
            let (mut error, mut params, mut continues) = (false, false, false);
            for (k, e) in o {
                match &k[..] {
                    b"error" if !error && matches!(e, Json::String(_)) => error = true,
                    b"parameters" if !params && matches!(e, Json::Object(_) | Json::Null) => params = true,
                    b"continues" if !continues && matches!(e, Json::Bool(_)) => {
                        continues = true;
                        // A 'continues' reply is only fine for 'more' calls.
                        if e.as_bool() == Some(true) {
                            ok = false;
                        }
                    }
                    _ => ok = false,
                }
            }
        }
        if !ok {
            l.set_state(State::ProcessingFailure);
            self.close();
            return 1;
        }
        l.set_state(State::Called);
        1
    }

    /// `sd_varlink_process()` for the client states used here.
    fn process(&mut self) -> Result<i32, i32> {
        if self.link.state() == State::Disconnected {
            return Err(log_debug_errno!(synthetic(libc::ENOTCONN), self.link.desc(), ": Not connected."));
        }
        let r = (|| -> Result<i32, i32> {
            if self.link.state().is_alive() {
                match self.link.write() {
                    Err(r) => {
                        log_debug_errno!(r, self.link.desc(), ": Write failed: ", strerror(r));
                        return Err(r);
                    }
                    Ok(0) => {}
                    Ok(r) => return Ok(r),
                }
            }
            let r = self.dispatch_reply();
            if r != 0 {
                return Ok(r);
            }
            match self.link.parse() {
                Err(r) => {
                    log_debug_errno!(r, self.link.desc(), ": Message parsing failed: ", strerror(r));
                    return Err(r);
                }
                Ok(0) => {}
                Ok(r) => return Ok(r),
            }
            if matches!(self.link.state(), State::AwaitingReply | State::Calling) && self.link.current.is_none() {
                match self.link.read() {
                    Err(r) => {
                        log_debug_errno!(r, self.link.desc(), ": Read failed: ", strerror(r));
                        return Err(r);
                    }
                    Ok(0) => {}
                    Ok(r) => return Ok(r),
                }
            }
            if self.link.test_disconnect() {
                return Ok(1);
            }
            if self.link.state() == State::PendingDisconnect {
                self.link.set_state(State::ProcessingDisconnect);
                self.close();
                return Ok(1);
            }
            if self.link.test_timeout() {
                return Ok(1);
            }
            if self.link.state() == State::PendingTimeout {
                self.link.set_state(State::ProcessingTimeout);
                self.close();
                return Ok(1);
            }
            Ok(0)
        })();
        if let Err(_e) = r {
            if self.link.state().is_alive() {
                self.link.set_state(State::PendingDisconnect);
            } else {
                self.close();
            }
        }
        r
    }

    /// `sd_varlink_call(v, method, parameters, &reply, &error_id)`.
    pub fn call(&mut self, method: &str, parameters: Option<Json>) -> Result<(Json, Option<Vec<u8>>), i32> {
        let mut m = vec![(b"method".to_vec(), Json::str(method))];
        if let Some(p) = non_empty(parameters) {
            m.push((b"parameters".to_vec(), p));
        }
        let m = Json::Object(m);
        match self.link.state() {
            State::Disconnected => {
                return Err(log_debug_errno!(synthetic(libc::ENOTCONN), self.link.desc(), ": Not connected."));
            }
            State::IdleClient => {}
            _ => return Err(log_debug_errno!(synthetic(libc::EBUSY), self.link.desc(), ": Connection busy.")),
        }
        self.link.current = None;
        if let Err(r) = self.link.enqueue(&m) {
            return Err(log_debug_errno!(r, self.link.desc(), ": Failed to enqueue json message: ", strerror(r)));
        }
        self.link.set_state(State::Calling);
        self.link.n_pending += 1;
        self.link.last_activity = crate::time::now_monotonic();
        while self.link.state() == State::Calling {
            if self.process()? > 0 {
                continue;
            }
            if self.link.state() == State::Disconnected {
                break;
            }
            self.link.wait(u64::MAX)?;
        }
        match self.link.state() {
            State::Called => {}
            State::PendingDisconnect | State::Disconnected => {
                return Err(log_debug_errno!(
                    synthetic(libc::ECONNRESET),
                    self.link.desc(),
                    ": Connection was closed."
                ));
            }
            State::PendingTimeout => {
                return Err(log_debug_errno!(synthetic(libc::ETIME), self.link.desc(), ": Connection timed out."));
            }
            _ => return Err(-libc::EPROTO),
        }
        self.link.set_state(State::IdleClient);
        self.link.n_pending -= 1;
        let cur = self.link.current.clone().unwrap_or(Json::Null);
        let error = cur.get("error").and_then(Json::as_str).map(<[u8]>::to_vec);
        let params = sanitize(cur.get("parameters")).unwrap_or(Json::Object(Vec::new()));
        Ok((params, error))
    }

    /// `varlink_call_and_log(v, method, parameters, &reply)`.
    pub fn call_and_log(&mut self, method: &str, parameters: Option<Json>) -> Result<Json, i32> {
        let (reply, error) = match self.call(method, parameters) {
            Ok(x) => x,
            Err(r) => {
                return Err(crate::log_error_errno!(r, "Failed to issue ", method, "() varlink call: ", strerror(r)));
            }
        };
        if let Some(e) = error {
            let r = error_to_errno(&e, Some(&reply));
            if r != -libc::EBADR {
                return Err(crate::log_error_errno!(r, "Failed to issue ", method, "() varlink call: ", strerror(r)));
            }
            return Err(crate::log_error_errno!(r, "Failed to issue ", method, "() varlink call: ", e));
        }
        Ok(reply)
    }
}

/// The type of an IDL field (`sd_varlink_field_type_t`), as far as
/// validation goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Bool,
    Int,
    Float,
    String,
    Object,
    Any,
}

/// An input or output field of a method (`sd_varlink_field`).
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub ty: FieldType,
    pub nullable: bool,
    pub array: bool,
    pub input: bool,
}

impl Field {
    pub const fn input(name: &'static str, ty: FieldType) -> Field {
        Field { name, ty, nullable: false, array: false, input: true }
    }
    pub const fn output(name: &'static str, ty: FieldType) -> Field {
        Field { name, ty, nullable: false, array: false, input: false }
    }
    pub const fn nullable(mut self) -> Field {
        self.nullable = true;
        self
    }
    pub const fn array(mut self) -> Field {
        self.array = true;
        self
    }
}

/// A method of an interface (`sd_varlink_symbol` of type METHOD).
#[derive(Debug, Clone, Copy)]
pub struct Method {
    pub name: &'static str,
    pub fields: &'static [Field],
}

/// `sd_varlink_interface`: its full method names are "interface.Method".
#[derive(Debug)]
pub struct Interface {
    pub name: &'static str,
    pub methods: &'static [Method],
}

/// `varlink_idl_log()`.
fn idl_log(r: i32, parts: &[&[u8]]) -> i32 {
    log_debug_errno!(r, "Varlink-IDL: ", parts.concat())
}

/// `varlink_idl_validate_field_element_type()`.
fn validate_element(f: &Field, v: &Json) -> Result<(), i32> {
    let bad = |what: &str| -> i32 {
        idl_log(
            synthetic(libc::EMEDIUMTYPE),
            &[
                b"Field '",
                f.name.as_bytes(),
                b"' should be ",
                what.as_bytes(),
                b", but it is of type '",
                v.type_name().as_bytes(),
                b"', refusing.",
            ],
        )
    };
    if *v == Json::Null {
        return Err(idl_log(
            synthetic(libc::EMEDIUMTYPE),
            &[b"Field '", f.name.as_bytes(), b"' element is null, refusing."],
        ));
    }
    let ok = match f.ty {
        FieldType::Bool => matches!(v, Json::Bool(_)),
        FieldType::Int => matches!(v, Json::Integer(_) | Json::Unsigned(_) | Json::String(_)),
        FieldType::Float => matches!(v, Json::Integer(_) | Json::Unsigned(_) | Json::Real(_)),
        FieldType::String => matches!(v, Json::String(_)),
        FieldType::Object => matches!(v, Json::Object(_)),
        FieldType::Any => true,
    };
    if ok {
        return Ok(());
    }
    Err(bad(match f.ty {
        FieldType::Bool => "a bool",
        FieldType::Int => "an int",
        FieldType::Float => "a float",
        FieldType::String => "a string",
        _ => "an object",
    }))
}

/// `varlink_idl_validate_method_call()`: Err((errno, bad field)).
fn validate_call(m: &Method, params: &Json) -> Result<(), (i32, Vec<u8>)> {
    let Json::Object(o) = params else {
        let r = idl_log(
            synthetic(libc::EMEDIUMTYPE),
            &[b"Passed non-object to field '", m.name.as_bytes(), b"', refusing."],
        );
        return Err((r, m.name.as_bytes().to_vec()));
    };
    for f in m.fields.iter().filter(|f| f.input) {
        let v = params.get(f.name);
        let r = match v {
            None | Some(Json::Null) => {
                if f.nullable {
                    Ok(())
                } else {
                    Err(idl_log(
                        synthetic(libc::ENOANO),
                        &[b"Mandatory field '", f.name.as_bytes(), b"' is null or missing on object, refusing."],
                    ))
                }
            }
            Some(v) if f.array => match v {
                Json::Array(a) => a.iter().try_for_each(|e| validate_element(f, e)),
                _ => Err(idl_log(
                    synthetic(libc::EMEDIUMTYPE),
                    &[
                        b"Field '",
                        f.name.as_bytes(),
                        b"' should be an array, but it is of type '",
                        v.type_name().as_bytes(),
                        b"', refusing.",
                    ],
                )),
            },
            Some(v) => validate_element(f, v),
        };
        if let Err(r) = r {
            return Err((r, f.name.as_bytes().to_vec()));
        }
    }
    for (k, _) in o {
        if !m.fields.iter().any(|f| f.name.as_bytes() == &k[..]) {
            let r = idl_log(synthetic(libc::EBUSY), &[b"Field '", k, b"' not defined for object, refusing."]);
            return Err((r, k.clone()));
        }
    }
    Ok(())
}

/// What a method handler gets, and how it answers (`sd_varlink_reply()`,
/// `sd_varlink_error()`); the answer is sent when the handler returns.
#[derive(Debug)]
pub struct Call {
    pub method: Vec<u8>,
    pub parameters: Json,
    peer_uid: Option<u32>,
    answer: Option<Json>,
    close: bool,
}

impl Call {
    /// `sd_varlink_reply(link, parameters)`.
    pub fn reply(&mut self, parameters: Option<Json>) -> i32 {
        let mut m = Vec::new();
        if let Some(p) = non_empty(parameters) {
            m.push((b"parameters".to_vec(), p));
        }
        self.answer = Some(Json::Object(m));
        1
    }

    /// `sd_varlink_error(link, error_id, parameters)`: the error as errno.
    pub fn error(&mut self, error_id: &str, parameters: Option<Json>) -> i32 {
        let mut m = vec![(b"error".to_vec(), Json::str(error_id))];
        let p = non_empty(parameters);
        if let Some(p) = &p {
            m.push((b"parameters".to_vec(), p.clone()));
        }
        self.answer = Some(Json::Object(m));
        error_to_errno(error_id.as_bytes(), p.as_ref())
    }

    /// `sd_varlink_error_errno(link, error)`.
    pub fn error_errno(&mut self, error: i32) -> i32 {
        let e = error.abs();
        let mut p = vec![(b"origin".to_vec(), Json::str("linux")), (b"errno".to_vec(), Json::Integer(e as i64))];
        if let Some(n) = sys::errno_name(e) {
            p.push((b"errnoName".to_vec(), Json::String(n)));
        }
        self.error(ERROR_SYSTEM, Some(Json::Object(p)))
    }

    /// `sd_varlink_error_invalid_parameter_name(link, name)`.
    pub fn error_invalid_parameter(&mut self, name: &[u8]) -> i32 {
        self.error(ERROR_INVALID_PARAMETER, Some(Json::Object(vec![(b"parameter".to_vec(), Json::str(name))])))
    }

    /// The peer's uid (`sd_varlink_get_peer_uid()`).
    pub fn peer_uid(&self) -> Result<u32, i32> {
        self.peer_uid.ok_or(-libc::ENODATA)
    }

    /// Flush and close the connection after the answer is queued, as
    /// `_cleanup_(sd_varlink_flush_close_unrefp)` on a reference does.
    pub fn flush_close(&mut self) {
        self.close = true;
    }
}

/// A method implementation.  Negative returns without an answer are sent
/// back as `io.systemd.System` errors.
pub type MethodFn<T> = fn(&mut T, &mut Event<T>, &mut Call) -> i32;

/// Where a server lives in the loop's user state.
pub type ServerSlot<T> = fn(&mut T) -> &mut Option<Server<T>>;

/// `sd_varlink_server`.
pub struct Server<T> {
    flags: u32,
    description: Option<Vec<u8>>,
    priority: i64,
    slot: ServerSlot<T>,
    listen: Vec<(Fd, Option<Id>)>,
    links: Vec<Option<(u64, Link)>>,
    serial: u64,
    methods: Vec<(&'static str, MethodFn<T>)>,
    interfaces: Vec<&'static Interface>,
    connections_max: u32,
    released: bool,
    info: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
}

impl<T> std::fmt::Debug for Server<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("links", &self.links.len()).finish_non_exhaustive()
    }
}

impl<T> Drop for Server<T> {
    fn drop(&mut self) {
        for (fd, _) in &self.listen {
            sys::close(*fd);
        }
    }
}

/// The `org.varlink.service` interface every server has.
pub static ORG_VARLINK_SERVICE: Interface = Interface {
    name: "org.varlink.service",
    methods: &[
        Method {
            name: "GetInfo",
            fields: &[
                Field::output("vendor", FieldType::String),
                Field::output("product", FieldType::String),
                Field::output("version", FieldType::String),
                Field::output("url", FieldType::String),
                Field::output("interfaces", FieldType::String).array(),
            ],
        },
        Method {
            name: "GetInterfaceDescription",
            fields: &[Field::input("interface", FieldType::String), Field::output("description", FieldType::String)],
        },
    ],
};

/// The `io.systemd` interface (errors only).
pub static IO_SYSTEMD: Interface = Interface { name: "io.systemd", methods: &[] };

/// `connection_key`: (slot, serial).
type Key = (usize, u64);

impl<T: 'static> Server<T> {
    /// `varlink_server_new(&s, flags, userdata)` (with
    /// `varlink_set_info_systemd()`).
    pub fn new(flags: u32, slot: ServerSlot<T>) -> Server<T> {
        let connections_max = match sys::getrlimit_nofile() {
            Ok((soft, _)) if soft != u64::MAX => (soft as u32 / 4 * 3).min(4096),
            _ => 4096,
        };
        Server {
            flags,
            description: None,
            priority: 0,
            slot,
            listen: Vec::new(),
            links: Vec::new(),
            serial: 0,
            methods: Vec::new(),
            interfaces: vec![&IO_SYSTEMD, &ORG_VARLINK_SERVICE],
            connections_max,
            released: false,
            info: (
                b"The systemd Project".to_vec(),
                crate::bcat!("systemd (", sys::program_invocation_short_name(), ")"),
                format!("{} ({})", crate::build::PROJECT_VERSION_FULL, crate::build::GIT_VERSION).into_bytes(),
                b"https://systemd.io/".to_vec(),
            ),
        }
    }

    /// `varlink_server_description()`.
    fn desc(&self) -> &[u8] {
        self.description.as_deref().unwrap_or(b"varlink")
    }

    /// `sd_varlink_server_add_interface()`.
    pub fn add_interface(&mut self, i: &'static Interface) -> Result<(), i32> {
        if self.interfaces.iter().any(|x| x.name == i.name) {
            return Err(log_debug_errno!(
                synthetic(libc::EEXIST),
                self.desc(),
                ": Duplicate registration of interface '",
                i.name,
                "'."
            ));
        }
        self.interfaces.push(i);
        Ok(())
    }

    /// `sd_varlink_server_bind_method()`.
    pub fn bind_method(&mut self, method: &'static str, f: MethodFn<T>) -> Result<(), i32> {
        if method.starts_with("org.varlink.service.") {
            return Err(log_debug_errno!(
                synthetic(libc::EEXIST),
                self.desc(),
                ": Cannot bind server to '",
                method,
                "'."
            ));
        }
        if self.methods.iter().any(|(m, _)| *m == method) {
            return Err(log_debug_errno!(
                synthetic(libc::EEXIST),
                self.desc(),
                ": Duplicate registration of method '",
                method,
                "'."
            ));
        }
        self.methods.push((method, f));
        Ok(())
    }

    /// The IDL of a method, by its full name.
    fn symbol(&self, method: &[u8]) -> Option<&'static Method> {
        for i in &self.interfaces {
            if let Some(rest) = method.strip_prefix(i.name.as_bytes())
                && let Some(name) = rest.strip_prefix(b".")
                && let Some(m) = i.methods.iter().find(|m| m.name.as_bytes() == name)
            {
                return Some(m);
            }
        }
        None
    }

    /// `sd_varlink_server_attach_event(s, e, priority)`.
    pub fn attach_event(&mut self, priority: i64) {
        self.priority = priority;
    }

    /// `sd_varlink_server_listen_address(s, address, mode)`.
    pub fn listen_address(&mut self, ev: &mut Event<T>, address: &[u8], mode: u32) -> Result<(), i32> {
        let fd = sys::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0)?;
        let fd = crate::log::fd_move_above_stdio(fd);
        let _ = sys::unlink(address);
        let old = sys::umask(!mode & 0o777);
        let r = sys::bind_listen_unix(fd, address, libc::SOMAXCONN);
        sys::umask(old);
        if let Err(r) = r {
            sys::close(fd);
            return Err(r);
        }
        self.listen_fd(ev, fd)
    }

    /// `sd_varlink_server_listen_fd(s, fd)`.
    pub fn listen_fd(&mut self, ev: &mut Event<T>, fd: Fd) -> Result<(), i32> {
        sys::set_nonblock(fd, true)?;
        let slot = self.slot;
        let id = ev.add_io(
            fd,
            libc::EPOLLIN as u32,
            Box::new(move |state: &mut T, ev: &mut Event<T>, _id, f| {
                if let Fired::Io { fd, .. } = f {
                    connect_callback(state, ev, slot, fd);
                }
                0
            }),
        )?;
        ev.set_priority(id, self.priority)?;
        self.listen.push((fd, Some(id)));
        Ok(())
    }

    /// `sd_varlink_server_unref()` by its owner: the listening sockets
    /// stay until the last connection is gone, as the connections hold
    /// references on the server.
    pub fn release(slot: ServerSlot<T>, state: &mut T, ev: &mut Event<T>) {
        let Some(s) = slot(state).as_mut() else { return };
        s.released = true;
        if s.links.iter().all(Option::is_none)
            && let Some(s) = slot(state).take()
        {
            for (_, id) in &s.listen {
                if let Some(id) = id {
                    ev.remove(*id);
                }
            }
        }
    }

    /// The number of live connections.
    pub fn n_connections(&self) -> usize {
        self.links.iter().flatten().count()
    }
}

fn link_mut<T: 'static>(state: &mut T, slot: ServerSlot<T>, key: Key) -> Option<&mut Link> {
    match slot(state).as_mut()?.links.get_mut(key.0)? {
        Some((serial, l)) if *serial == key.1 => Some(l),
        _ => None,
    }
}

/// `connect_callback()`: a new connection on a listening socket.
fn connect_callback<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, fd: Fd) {
    let Some(server) = slot(state).as_mut() else { return };
    log_debug!(server.desc(), ": New incoming connection.");
    let cfd = match sys::accept4(fd) {
        Ok(c) => c,
        Err(e) if matches!(-e, libc::EAGAIN | libc::EINTR | libc::ECONNABORTED | libc::EPROTO) => return,
        Err(e) => {
            log_debug_errno!(e, server.desc(), ": Failed to accept incoming socket: ", strerror(e));
            return;
        }
    };
    let _ = add_connection(state, ev, slot, cfd);
}

/// `sd_varlink_server_add_connection(server, fd, &v)`.
fn add_connection<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, fd: Fd) -> Result<(), i32> {
    let server = slot(state).as_mut().ok_or(-libc::ENOENT)?;
    let mut ucred = None;
    if server.flags & (SERVER_ROOT_ONLY | SERVER_MYSELF_ONLY) != 0 {
        let c = match sys::peer_cred(fd) {
            Ok(c) => c,
            Err(r) => {
                sys::close(fd);
                return Err(log_debug_errno!(
                    r,
                    server.desc(),
                    ": Failed to acquire peer credentials of incoming socket, refusing: ",
                    strerror(r)
                ));
            }
        };
        let mut allowed = None;
        if server.flags & SERVER_ROOT_ONLY != 0 {
            allowed = Some(c.1 == 0);
        }
        if server.flags & SERVER_MYSELF_ONLY != 0 {
            allowed = Some(allowed == Some(true) || c.1 == sys::getuid());
        }
        if allowed == Some(false) {
            log_debug!(server.desc(), ": Unprivileged client attempted connection, refusing.");
            sys::close(fd);
            return Err(-libc::EPERM);
        }
        ucred = Some(c);
    }
    if server.n_connections() as u32 >= server.connections_max {
        log_debug!(server.desc(), ": Connection limit of ", server.connections_max.to_string(), " reached, refusing.");
        sys::close(fd);
        return Err(-libc::EPERM);
    }
    let mut link = Link::new(fd);
    link.ucred = ucred;
    link.description = Some(crate::bcat!(server.desc(), "-", fd.to_string(), "-", fd.to_string()));
    server.serial += 1;
    let serial = server.serial;
    let index = match server.links.iter().position(Option::is_none) {
        Some(i) => i,
        None => {
            server.links.push(None);
            server.links.len() - 1
        }
    };
    let priority = server.priority;
    let key = (index, serial);
    server.links[index] = Some((serial, link));
    if let Err(r) = attach_link(ev, slot, key, fd, priority, state) {
        let l = link_mut(state, slot, key).expect("link exists");
        log_debug_errno!(r, l.desc(), ": Failed to attach new connection: ", strerror(r));
        close_link(state, ev, slot, key);
        return Err(r);
    }
    let l = link_mut(state, slot, key).expect("link exists");
    l.set_state(State::IdleServer);
    Ok(())
}

/// `sd_varlink_attach_event()` (with `json_stream_attach_event()`).
fn attach_link<T: 'static>(
    ev: &mut Event<T>,
    slot: ServerSlot<T>,
    key: Key,
    fd: Fd,
    priority: i64,
    state: &mut T,
) -> Result<(), i32> {
    let io = ev.add_io(
        fd,
        0,
        Box::new(move |state: &mut T, ev: &mut Event<T>, _id, f| {
            if let Fired::Io { revents, .. } = f
                && let Some(l) = link_mut(state, slot, key)
            {
                l.handle_revents(revents);
            }
            let r = process(state, ev, slot, key);
            if r < 0
                && let Some(l) = link_mut(state, slot, key)
            {
                log_debug_errno!(r, l.js_desc(), ": Dispatch callback failed, ignoring: ", strerror(r));
            }
            1
        }),
    )?;
    ev.set_prepare(
        io,
        Box::new(move |state: &mut T, ev: &mut Event<T>, _id, _f| {
            let Some(l) = link_mut(state, slot, key) else { return 0 };
            let (events, io, time, deadline) = (l.get_events(), l.io, l.time, l.get_timeout());
            if let Some(io) = io
                && let Err(r) = ev.set_io_events(io, events)
            {
                return log_debug_errno!(r, l.js_desc(), ": Failed to set io events: ", strerror(r));
            }
            rearm_time(ev, time, deadline);
            1
        }),
    );
    ev.set_priority(io, priority)?;
    ev.set_description(io, b"json-stream-input");
    let time = ev.add_time(
        libc::CLOCK_MONOTONIC,
        0,
        Box::new(move |state: &mut T, ev: &mut Event<T>, id, _f| {
            let _ = ev.set_enabled(id, Enabled::Off);
            let r = process(state, ev, slot, key);
            if r < 0
                && let Some(l) = link_mut(state, slot, key)
            {
                log_debug_errno!(r, l.js_desc(), ": Dispatch callback failed, ignoring: ", strerror(r));
            }
            1
        }),
    )?;
    ev.set_priority(time, priority)?;
    ev.set_description(time, b"json-stream-time");
    ev.set_enabled(time, Enabled::Off)?;
    let quit = ev.add_exit(Box::new(move |state: &mut T, ev: &mut Event<T>, _id, _f| {
        if let Some(l) = link_mut(state, slot, key)
            && l.state() != State::Disconnected
        {
            let _ = l.flush();
        }
        close_link(state, ev, slot, key);
        1
    }))?;
    ev.set_priority(quit, priority)?;
    ev.set_description(quit, b"varlink-quit");
    let defer = ev.add_defer(Box::new(move |state: &mut T, ev: &mut Event<T>, _id, _f| {
        let _ = process(state, ev, slot, key);
        1
    }))?;
    ev.set_priority(defer, priority)?;
    ev.set_description(defer, b"varlink-defer");
    let l = link_mut(state, slot, key).ok_or(-libc::ENOENT)?;
    l.io = Some(io);
    l.time = Some(time);
    l.quit = Some(quit);
    l.defer = Some(defer);
    Ok(())
}

/// `json_stream_rearm_time_source()`.
fn rearm_time<T>(ev: &mut Event<T>, time: Option<Id>, deadline: u64) {
    let Some(t) = time else { return };
    if deadline == u64::MAX {
        let _ = ev.set_enabled(t, Enabled::Off);
        return;
    }
    let _ = ev.set_time(t, deadline);
    let _ = ev.set_enabled(t, Enabled::On);
}

/// `sd_varlink_close()` of a server connection.
fn close_link<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, key: Key) {
    let Some(l) = link_mut(state, slot, key) else { return };
    if l.state() == State::Disconnected {
        return;
    }
    l.set_state(State::Disconnected);
    for id in [l.io.take(), l.time.take(), l.quit.take(), l.defer.take()].into_iter().flatten() {
        ev.remove(id);
    }
    let Some(server) = slot(state).as_mut() else { return };
    server.links[key.0] = None;
    if server.released && server.links.iter().all(Option::is_none) {
        Server::release(slot, state, ev);
    }
}

/// `sd_varlink_process()` of a server connection.
fn process<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, key: Key) -> i32 {
    let Some(l) = link_mut(state, slot, key) else { return -libc::ENOTCONN };
    if l.state() == State::Disconnected {
        return log_debug_errno!(synthetic(libc::ENOTCONN), l.desc(), ": Not connected.");
    }
    let r = process_steps(state, ev, slot, key);
    let Some(l) = link_mut(state, slot, key) else { return r };
    if r >= 0
        && let Some(d) = l.defer
    {
        let _ = ev.set_enabled(d, if r > 0 { Enabled::On } else { Enabled::Off });
    }
    if r < 0 {
        if l.state().is_alive() {
            l.set_state(State::PendingDisconnect);
        } else {
            close_link(state, ev, slot, key);
        }
    }
    r
}

fn process_steps<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, key: Key) -> i32 {
    let l = link_mut(state, slot, key).expect("link exists");
    if l.state().is_alive() {
        match l.write() {
            Err(r) => return log_debug_errno!(r, l.desc(), ": Write failed: ", strerror(r)),
            Ok(0) => {}
            Ok(r) => return r,
        }
    }
    match dispatch_method(state, ev, slot, key) {
        0 => {}
        r if r < 0 => {
            if let Some(l) = link_mut(state, slot, key) {
                log_debug_errno!(r, l.desc(), ": Method dispatch failed: ", strerror(r));
            }
            return r;
        }
        r => return r,
    }
    let Some(l) = link_mut(state, slot, key) else { return 1 };
    match l.parse() {
        Err(r) => return log_debug_errno!(r, l.desc(), ": Message parsing failed: ", strerror(r)),
        Ok(0) => {}
        Ok(r) => return r,
    }
    if l.state() == State::IdleServer && l.current.is_none() {
        match l.read() {
            Err(r) => return log_debug_errno!(r, l.desc(), ": Read failed: ", strerror(r)),
            Ok(0) => {}
            Ok(r) => return r,
        }
    }
    if l.test_disconnect() {
        return 1;
    }
    if l.state() == State::PendingDisconnect {
        l.set_state(State::ProcessingDisconnect);
        close_link(state, ev, slot, key);
        return 1;
    }
    if l.test_timeout() {
        return 1;
    }
    if l.state() == State::PendingTimeout {
        l.set_state(State::ProcessingTimeout);
        close_link(state, ev, slot, key);
        return 1;
    }
    0
}

/// `varlink_dispatch_method()`.
fn dispatch_method<T: 'static>(state: &mut T, ev: &mut Event<T>, slot: ServerSlot<T>, key: Key) -> i32 {
    let l = link_mut(state, slot, key).expect("link exists");
    if l.state() != State::IdleServer {
        return 0;
    }
    let Some(cur) = l.current.clone() else { return 0 };
    let fail = |state: &mut T, ev: &mut Event<T>, r: i32| -> i32 {
        if let Some(l) = link_mut(state, slot, key) {
            l.set_state(State::ProcessingFailure);
        }
        close_link(state, ev, slot, key);
        r
    };
    let Json::Object(o) = &cur else { return fail(state, ev, -libc::EINVAL) };
    let mut method: Option<Vec<u8>> = None;
    let mut parameters: Option<Json> = None;
    let mut oneway = false;
    let mut flag_seen = false;
    for (k, e) in o {
        match &k[..] {
            b"method" => {
                if method.is_some() {
                    return fail(state, ev, -libc::EINVAL);
                }
                let Json::String(m) = e else { return fail(state, ev, -libc::EINVAL) };
                method = Some(m.clone());
            }
            b"parameters" => {
                if parameters.is_some() || !matches!(e, Json::Object(_) | Json::Null) {
                    return fail(state, ev, -libc::EINVAL);
                }
                parameters = Some(e.clone());
            }
            b"oneway" | b"more" | b"upgrade" => {
                if flag_seen {
                    return fail(state, ev, -libc::EINVAL);
                }
                let Json::Bool(b) = e else { return fail(state, ev, -libc::EINVAL) };
                flag_seen = true;
                if *b {
                    if &k[..] != b"oneway" {
                        // "more" and "upgrade" calls are not supported here.
                        return fail(state, ev, -libc::EOPNOTSUPP);
                    }
                    oneway = true;
                }
            }
            _ => return fail(state, ev, -libc::EINVAL),
        }
    }
    let Some(method) = method else { return fail(state, ev, -libc::EINVAL) };
    let parameters = match sanitize(parameters.as_ref()) {
        Ok(p) => p,
        Err(r) => return fail(state, ev, r),
    };
    let l = link_mut(state, slot, key).expect("link exists");
    l.set_state(if oneway { State::ProcessingMethodOneway } else { State::ProcessingMethod });
    let peer_uid = l.ucred.map(|c| c.1);
    let server = slot(state).as_mut().expect("server exists");
    let callback = server.methods.iter().find(|(m, _)| m.as_bytes() == &method[..]).map(|(_, f)| *f);
    let generic =
        matches!(&method[..], b"org.varlink.service.GetInfo" | b"org.varlink.service.GetInterfaceDescription");
    let mut call = Call { method: method.clone(), parameters, peer_uid, answer: None, close: false };
    if callback.is_some() || generic {
        let symbol = server.symbol(&method);
        let mut invalid = false;
        match symbol {
            None => {
                let l = link_mut(state, slot, key).expect("link exists");
                log_debug!(
                    l.desc(),
                    ": No interface description defined for method '",
                    &method[..],
                    "', not validating."
                );
            }
            Some(sym) => {
                if let Err((r, bad)) = validate_call(sym, &call.parameters) {
                    let l = link_mut(state, slot, key).expect("link exists");
                    log_debug_errno!(
                        r,
                        l.desc(),
                        ": Parameters for method ",
                        &method[..],
                        "() didn't pass validation on field '",
                        &bad[..],
                        "': ",
                        strerror(r)
                    );
                    if !oneway {
                        call.error_invalid_parameter(&bad);
                    }
                    invalid = true;
                }
            }
        }
        if !invalid {
            let r = match callback {
                Some(f) => f(state, ev, &mut call),
                None => generic_method(state, slot, &mut call),
            };
            if !oneway && call.answer.is_none() {
                if r < 0 {
                    if let Some(l) = link_mut(state, slot, key) {
                        log_debug_errno!(
                            r,
                            l.desc(),
                            ": Callback for '",
                            &method[..],
                            "' returned error: ",
                            strerror(r)
                        );
                    }
                    call.error_errno(r);
                } else {
                    let r = match link_mut(state, slot, key) {
                        Some(l) => log_debug_errno!(
                            synthetic(libc::EPROTO),
                            l.desc(),
                            ": Callback for method '",
                            &method[..],
                            "' returned without enqueuing a reply or stashing connection, failing."
                        ),
                        None => -libc::EPROTO,
                    };
                    return fail(state, ev, r);
                }
            }
        }
    } else if !oneway {
        call.error(
            ERROR_METHOD_NOT_FOUND,
            Some(Json::Object(vec![(b"method".to_vec(), Json::String(method.clone()))])),
        );
    }
    let Some(l) = link_mut(state, slot, key) else { return 1 };
    if l.state() == State::Disconnected {
        return 1;
    }
    if let Some(answer) = call.answer.take()
        && !oneway
    {
        if let Err(r) = l.enqueue(&answer) {
            log_debug_errno!(r, l.desc(), ": Failed to enqueue json message: ", strerror(r));
            return fail(state, ev, r);
        }
        l.set_state(State::ProcessedMethod);
    }
    if call.close {
        let _ = l.flush();
        close_link(state, ev, slot, key);
        return 1;
    }
    let l = link_mut(state, slot, key).expect("link exists");
    match l.state() {
        State::ProcessedMethod | State::ProcessingMethodOneway => {
            l.current = None;
            l.set_state(State::IdleServer);
        }
        State::ProcessingMethod => l.set_state(State::PendingMethod),
        _ => {}
    }
    1
}

/// `generic_method_get_info()`, and `GetInterfaceDescription()`.
fn generic_method<T: 'static>(state: &mut T, slot: ServerSlot<T>, call: &mut Call) -> i32 {
    let Some(server) = slot(state).as_ref() else { return -libc::ENOTCONN };
    if &call.method[..] == b"org.varlink.service.GetInterfaceDescription" {
        let name = call.parameters.get("interface").and_then(Json::as_str).map(<[u8]>::to_vec);
        let Some(name) = name else { return call.error_invalid_parameter(b"interface") };
        if !server.interfaces.iter().any(|i| i.name.as_bytes() == &name[..]) {
            return call.error(
                ERROR_INTERFACE_NOT_FOUND,
                Some(Json::Object(vec![(b"interface".to_vec(), Json::String(name))])),
            );
        }
        return call.error(ERROR_METHOD_NOT_IMPLEMENTED, None);
    }
    if let Json::Object(o) = &call.parameters
        && let Some((k, _)) = o.first()
    {
        let k = k.clone();
        return call.error_invalid_parameter(&k);
    }
    let mut names: Vec<&str> = server.interfaces.iter().map(|i| i.name).collect();
    names.sort_unstable();
    let (vendor, product, version, url) = server.info.clone();
    call.reply(Some(Json::Object(vec![
        (b"vendor".to_vec(), Json::String(vendor)),
        (b"product".to_vec(), Json::String(product)),
        (b"version".to_vec(), Json::String(version)),
        (b"url".to_vec(), Json::String(url)),
        (b"interfaces".to_vec(), Json::strv(&names)),
    ])))
}

/// `sd_json_dispatch()` with no table (`sd_varlink_dispatch(link, p, NULL, NULL)`):
/// any field is refused.  Returns the answer's errno, or 0.
pub fn dispatch_empty(call: &mut Call) -> i32 {
    if let Json::Object(o) = &call.parameters
        && let Some((k, _)) = o.first()
    {
        let k = k.clone();
        return call.error_invalid_parameter(&k);
    }
    0
}
