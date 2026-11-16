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
