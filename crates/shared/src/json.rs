// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-json.c`: building and dumping the JSON values the ported code emits
//! (`--introspect-cli`).  Objects keep insertion order, as sd-json does.

use crate::terminal::{ansi, colors_enabled, on_tty};

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Unsigned(u64),
    Integer(i64),
    Real(f64),
    String(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

pub const SD_JSON_FORMAT_OFF: u32 = 1 << 0;
pub const SD_JSON_FORMAT_NEWLINE: u32 = 1 << 1;
pub const SD_JSON_FORMAT_PRETTY: u32 = 1 << 2;
pub const SD_JSON_FORMAT_PRETTY_AUTO: u32 = 1 << 3;
pub const SD_JSON_FORMAT_COLOR: u32 = 1 << 4;
pub const SD_JSON_FORMAT_COLOR_AUTO: u32 = 1 << 5;
pub const SD_JSON_FORMAT_SSE: u32 = 1 << 7;
pub const SD_JSON_FORMAT_SEQ: u32 = 1 << 8;

/// `sd_json_format_enabled(flags)`.
pub fn format_enabled(flags: u32) -> bool {
    flags & SD_JSON_FORMAT_OFF == 0
}

/// `sd_json_variant_new_string()`: strings must be valid UTF-8.
pub fn string_checked(s: &[u8]) -> Result<Json, i32> {
    if crate::utf8::is_valid(s) { Ok(Json::String(s.to_vec())) } else { Err(-libc::EUCLEAN) }
}

/// `parse_json_argument(s, &ret)`: Ok(None) after "help".
pub fn parse_json_argument(s: &[u8]) -> Result<Option<u32>, i32> {
    match s {
        b"pretty" => Ok(Some(SD_JSON_FORMAT_PRETTY | SD_JSON_FORMAT_COLOR_AUTO)),
        b"short" => Ok(Some(SD_JSON_FORMAT_NEWLINE)),
        b"off" => Ok(Some(SD_JSON_FORMAT_OFF)),
        b"help" => {
            crate::printo!("pretty\nshort\noff\n");
            Ok(None)
        }
        _ => Err(crate::log_error_errno!(
            crate::errno::synthetic(libc::EINVAL),
            "Unknown argument to --json= switch: ",
            s
        )),
    }
}

impl Json {
    pub fn str(s: impl AsRef<[u8]>) -> Json {
        Json::String(s.as_ref().to_vec())
    }

    /// `SD_JSON_BUILD_STRV()`.
    pub fn strv<S: AsRef<[u8]>>(v: &[S]) -> Json {
        Json::Array(v.iter().map(Json::str).collect())
    }
}

/// `json_format_string()`.
fn format_string(out: &mut Vec<u8>, q: &[u8], flags: u32) {
    out.push(b'"');
    if flags & SD_JSON_FORMAT_COLOR != 0 {
        out.extend_from_slice(ansi::green().as_bytes());
    }
    for &c in q {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < b' ' => out.extend_from_slice(format!("\\u{:04x}", c).as_bytes()),
            c => out.push(c),
        }
    }
    if flags & SD_JSON_FORMAT_COLOR != 0 {
        out.extend_from_slice(ansi::NORMAL.as_bytes());
    }
    out.push(b'"');
}

/// `"%.*e"` with `DECIMAL_DIG` digits, as sd-json prints reals.
fn format_real(r: f64) -> String {
    let t = format!("{:.*e}", 21, r);
    // Rust writes "1.5e0"; C writes "1.5e+00".
    match t.split_once('e') {
        Some((m, e)) => {
            let (sign, digits) = if let Some(d) = e.strip_prefix('-') { ('-', d) } else { ('+', e) };
            format!("{m}e{sign}{digits:0>2}")
        }
        None => t,
    }
}

/// `json_format()`.
fn format(out: &mut Vec<u8>, v: &Json, flags: u32, prefix: &[u8]) {
    let color = flags & SD_JSON_FORMAT_COLOR != 0;
    let pretty = flags & SD_JSON_FORMAT_PRETTY != 0;
    let wrap = |out: &mut Vec<u8>, on: &str, text: &[u8]| {
        if color {
            out.extend_from_slice(on.as_bytes());
        }
        out.extend_from_slice(text);
        if color {
            out.extend_from_slice(ansi::NORMAL.as_bytes());
        }
    };
    match v {
        Json::Null => wrap(out, ansi::HIGHLIGHT, b"null"),
        Json::Bool(b) => wrap(out, ansi::HIGHLIGHT, if *b { b"true" } else { b"false" }),
        Json::Unsigned(u) => wrap(out, ansi::highlight_blue(), u.to_string().as_bytes()),
        Json::Integer(i) => wrap(out, ansi::highlight_blue(), i.to_string().as_bytes()),
        Json::Real(r) => wrap(out, ansi::highlight_blue(), format_real(*r).as_bytes()),
        Json::String(s) => format_string(out, s, flags),
        Json::Array(a) => {
            if a.is_empty() {
                out.extend_from_slice(b"[]");
                return;
            }
            let prefix2 = if pretty { [prefix, b"\t"].concat() } else { prefix.to_vec() };
            out.extend_from_slice(if pretty { b"[\n" } else { b"[" });
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(if pretty { b",\n" } else { b"," });
                }
                if pretty {
                    out.extend_from_slice(&prefix2);
                }
                format(out, e, flags, &prefix2);
            }
            if pretty {
                out.push(b'\n');
                out.extend_from_slice(prefix);
            }
            out.push(b']');
        }
        Json::Object(o) => {
            if o.is_empty() {
                out.extend_from_slice(b"{}");
                return;
            }
            let prefix2 = if pretty { [prefix, b"\t"].concat() } else { prefix.to_vec() };
            out.extend_from_slice(if pretty { b"{\n" } else { b"{" });
            for (i, (k, e)) in o.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(if pretty { b",\n" } else { b"," });
                }
                if pretty {
                    out.extend_from_slice(&prefix2);
                }
                format_string(out, k, flags);
                out.extend_from_slice(if pretty { b" : " } else { b":" });
                format(out, e, flags, &prefix2);
            }
            if pretty {
                out.push(b'\n');
                out.extend_from_slice(prefix);
            }
            out.push(b'}');
        }
    }
}

/// `sd_json_variant_dump(v, flags, f, NULL)`: the bytes to write.
pub fn dump(v: &Json, mut flags: u32) -> Vec<u8> {
    if flags & (SD_JSON_FORMAT_COLOR_AUTO | SD_JSON_FORMAT_COLOR) == SD_JSON_FORMAT_COLOR_AUTO && colors_enabled() {
        flags |= SD_JSON_FORMAT_COLOR;
    }
    if flags & (SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_PRETTY) == SD_JSON_FORMAT_PRETTY_AUTO {
        flags |= if on_tty() { SD_JSON_FORMAT_PRETTY } else { SD_JSON_FORMAT_NEWLINE };
    }
    let mut out = Vec::new();
    if flags & SD_JSON_FORMAT_SSE != 0 {
        out.extend_from_slice(b"data: ");
    }
    if flags & SD_JSON_FORMAT_SEQ != 0 {
        out.push(0x1e);
    }
    format(&mut out, v, flags, b"");
    if flags & (SD_JSON_FORMAT_PRETTY | SD_JSON_FORMAT_SEQ | SD_JSON_FORMAT_SSE | SD_JSON_FORMAT_NEWLINE) != 0 {
        out.push(b'\n');
    }
    if flags & SD_JSON_FORMAT_SSE != 0 {
        out.push(b'\n');
    }
    out
}

/// `sd_json_variant_set_field(&v, field, value)`: an existing field is
/// dropped and the new one goes last.
pub fn set_field(obj: &mut Vec<(Vec<u8>, Json)>, field: &[u8], value: Json) {
    obj.retain(|(k, _)| k != field);
    obj.push((field.to_vec(), value));
}

/// `JSON_DEPTH_MAX`.
const JSON_DEPTH_MAX: usize = 2048;

struct Parser<'a> {
    s: &'a [u8],
    p: usize,
}

impl Parser<'_> {
    fn peek(&self) -> u8 {
        self.s.get(self.p).copied().unwrap_or(0)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\n' | b'\r') {
            self.p += 1;
        }
    }

    fn unhex4(&self, at: usize) -> Result<u16, i32> {
        let h = self.s.get(at..at + 4).ok_or(-libc::EINVAL)?;
        let mut x: u16 = 0;
        for &c in h {
            let d = (c as char).to_digit(16).ok_or(-libc::EINVAL)? as u16;
            x = x << 4 | d;
        }
        Ok(x)
    }

    /// `json_parse_string()`.
    fn string(&mut self) -> Result<Vec<u8>, i32> {
        if self.peek() != b'"' {
            return Err(-libc::EINVAL);
        }
        self.p += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek();
            if c == 0 || c < b' ' || c == 0x7f {
                return Err(-libc::EINVAL);
            }
            if c == b'"' {
                self.p += 1;
                return Ok(out);
            }
            if c == b'\\' {
                self.p += 1;
                let e = self.peek();
                let ch = match e {
                    b'"' | b'\\' | b'/' => e,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        let x = self.unhex4(self.p + 1)?;
                        self.p += 5;
                        let cp = if !(0xd800..=0xdfff).contains(&x) {
                            x as u32
                        } else if x >= 0xdc00 {
                            return Err(-libc::EINVAL);
                        } else {
                            if self.s.get(self.p..self.p + 2) != Some(b"\\u") {
                                return Err(-libc::EINVAL);
                            }
                            let y = self.unhex4(self.p + 2)?;
                            self.p += 6;
                            if !(0xdc00..=0xdfff).contains(&y) {
                                return Err(-libc::EINVAL);
                            }
                            0x10000 + (((x as u32) & 0x3ff) << 10 | ((y as u32) & 0x3ff))
                        };
                        let mut b = [0u8; 4];
                        // Lone surrogates were refused above; NUL is kept as C's
                        // utf8_encode_unichar() writes it.
                        match char::from_u32(cp) {
                            Some(ch) => out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes()),
                            None => return Err(-libc::EINVAL),
                        }
                        continue;
                    }
                    _ => return Err(-libc::EINVAL),
                };
                out.push(ch);
                self.p += 1;
                continue;
            }
            let len = crate::utf8::encoded_valid_unichar(&self.s[self.p..]).ok_or(-libc::EINVAL)?;
            out.extend_from_slice(&self.s[self.p..self.p + len]);
            self.p += len;
        }
    }

    /// `json_parse_number()`.
    fn number(&mut self) -> Result<Json, i32> {
        let start = self.p;
        let negative = self.peek() == b'-';
        if negative {
            self.p += 1;
        }
        let mut is_real = false;
        let mut i: i64 = 0;
        let mut u: u64 = 0;
        if self.peek() == b'0' {
            self.p += 1;
        } else {
            if !self.peek().is_ascii_digit() {
                return Err(-libc::EINVAL);
            }
            while self.peek().is_ascii_digit() {
                let d = (self.peek() - b'0') as i64;
                if !is_real {
                    if negative {
                        match i.checked_mul(10).and_then(|t| t.checked_sub(d)) {
                            Some(v) => i = v,
                            None => is_real = true,
                        }
                    } else {
                        match u.checked_mul(10).and_then(|t| t.checked_add(d as u64)) {
                            Some(v) => u = v,
                            None => is_real = true,
                        }
                    }
                }
                self.p += 1;
            }
        }
        if self.peek() == b'.' {
            is_real = true;
            self.p += 1;
            if !self.peek().is_ascii_digit() {
                return Err(-libc::EINVAL);
            }
            while self.peek().is_ascii_digit() {
                self.p += 1;
            }
        }
        if matches!(self.peek(), b'e' | b'E') {
            is_real = true;
            self.p += 1;
            if matches!(self.peek(), b'-' | b'+') {
                self.p += 1;
            }
            if !self.peek().is_ascii_digit() {
                return Err(-libc::EINVAL);
            }
            while self.peek().is_ascii_digit() {
                self.p += 1;
            }
        }
        if is_real {
            let t = std::str::from_utf8(&self.s[start..self.p]).map_err(|_| -libc::EINVAL)?;
            return Ok(Json::Real(t.parse::<f64>().map_err(|_| -libc::EINVAL)?));
        }
        Ok(if negative { Json::Integer(i) } else { Json::Unsigned(u) })
    }

    fn value(&mut self, depth: usize) -> Result<Json, i32> {
        if depth >= JSON_DEPTH_MAX {
            return Err(-libc::ELNRNG);
        }
        self.skip_ws();
        match self.peek() {
            b'{' => {
                self.p += 1;
                let mut o: Vec<(Vec<u8>, Json)> = Vec::new();
                self.skip_ws();
                if self.peek() == b'}' {
                    self.p += 1;
                    return Ok(Json::Object(o));
                }
                loop {
                    self.skip_ws();
                    let k = self.string()?;
                    self.skip_ws();
                    if self.peek() != b':' {
                        return Err(-libc::EINVAL);
                    }
                    self.p += 1;
                    let v = self.value(depth + 1)?;
                    // sd_json_variant_new_object() refuses duplicate keys.
                    if o.iter().any(|(x, _)| *x == k) {
                        return Err(-libc::ENOTUNIQ);
                    }
                    o.push((k, v));
                    self.skip_ws();
                    match self.peek() {
                        b',' => self.p += 1,
                        b'}' => {
                            self.p += 1;
                            return Ok(Json::Object(o));
                        }
                        _ => return Err(-libc::EINVAL),
                    }
                }
            }
            b'[' => {
                self.p += 1;
                let mut a = Vec::new();
                self.skip_ws();
                if self.peek() == b']' {
                    self.p += 1;
                    return Ok(Json::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.skip_ws();
                    match self.peek() {
                        b',' => self.p += 1,
                        b']' => {
                            self.p += 1;
                            return Ok(Json::Array(a));
                        }
                        _ => return Err(-libc::EINVAL),
                    }
                }
            }
            b'"' => Ok(Json::String(self.string()?)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => {
                for (word, v) in
                    [(&b"true"[..], Json::Bool(true)), (b"false", Json::Bool(false)), (b"null", Json::Null)]
                {
                    if self.s[self.p..].starts_with(word) {
                        let after = self.s.get(self.p + word.len()).copied().unwrap_or(0);
                        if after.is_ascii_alphanumeric() || after == b'_' {
                            return Err(-libc::EINVAL);
                        }
                        self.p += word.len();
                        return Ok(v);
                    }
                }
                Err(-libc::EINVAL)
            }
        }
    }
}

/// `sd_json_parse(s, 0, &v, NULL, NULL)`.
pub fn parse(s: &[u8]) -> Result<Json, i32> {
    let mut p = Parser { s, p: 0 };
    let v = p.value(0)?;
    p.skip_ws();
    if p.p != s.len() {
        return Err(-libc::EINVAL);
    }
    Ok(v)
}

impl Json {
    /// `sd_json_variant_by_key(v, key)`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(o) => o.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&[u8]> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }

    /// The value as an i64, if it is an integer that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Integer(i) => Some(*i),
            Json::Unsigned(u) => i64::try_from(*u).ok(),
            Json::Real(r) if r.fract() == 0.0 && *r >= i64::MIN as f64 && *r <= i64::MAX as f64 => Some(*r as i64),
            _ => None,
        }
    }

    /// The value as a u64, if it is a non-negative integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Unsigned(u) => Some(*u),
            Json::Integer(i) => u64::try_from(*i).ok(),
            Json::Real(r) if r.fract() == 0.0 && *r >= 0.0 && *r <= u64::MAX as f64 => Some(*r as u64),
            _ => None,
        }
    }

    /// `sd_json_variant_type_to_string()` of the value's type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "boolean",
            Json::Unsigned(_) => "unsigned",
            Json::Integer(_) => "integer",
            Json::Real(_) => "real",
            Json::String(_) => "string",
            Json::Array(_) => "array",
            Json::Object(_) => "object",
        }
    }
}
