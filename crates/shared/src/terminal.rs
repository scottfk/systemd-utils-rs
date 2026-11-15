// SPDX-License-Identifier: LGPL-2.1-or-later
//! `terminal-util.c` and `ansi-color.c`/`ansi-color.h`: tty detection,
//! terminal size, and whether (and which) ANSI colors to emit.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::env::getenv;
use crate::parse::safe_atou_bounded;
use crate::sys;

static CACHED_COLUMNS: AtomicU32 = AtomicU32::new(0);
static CACHED_LINES: AtomicU32 = AtomicU32::new(0);
static CACHED_ON_TTY: AtomicI32 = AtomicI32::new(-1);
static CACHED_ON_DEV_NULL: AtomicI32 = AtomicI32::new(-1);
static CACHED_COLOR_MODE: AtomicI32 = AtomicI32::new(-1);
static CACHED_UNDERLINE: AtomicI32 = AtomicI32::new(-1);

/// `isatty_safe(fd)`: a hung-up tty (EIO) still counts.
pub fn isatty_safe(fd: sys::Fd) -> bool {
    let (tty, e) = sys::isatty(fd);
    tty || e == libc::EIO
}

/// `fd_columns(fd)`.
pub fn fd_columns(fd: sys::Fd) -> Result<u32, i32> {
    let (c, _) = sys::winsize(fd)?;
    if c == 0 {
        return Err(-libc::ENODATA);
    }
    Ok(c as u32)
}

/// `getenv_columns()`.
pub fn getenv_columns() -> Result<u32, i32> {
    let e = getenv("COLUMNS").ok_or(-libc::ENXIO)?;
    safe_atou_bounded(&e, 1, u16::MAX as u32)
}

/// `columns()`.
pub fn columns() -> u32 {
    let c = CACHED_COLUMNS.load(Ordering::Relaxed);
    if c > 0 {
        return c;
    }
    let c = getenv_columns().or_else(|_| fd_columns(1)).unwrap_or(80);
    CACHED_COLUMNS.store(c, Ordering::Relaxed);
    c
}

/// `lines()`.
pub fn lines() -> u32 {
    let c = CACHED_LINES.load(Ordering::Relaxed);
    if c > 0 {
        return c;
    }
    let l = getenv("LINES").and_then(|e| crate::parse::safe_atoi(&e).ok()).unwrap_or(0);
    let l = if l <= 0 || l > u16::MAX as i32 {
        match sys::winsize(1) {
            Ok((_, r)) if r > 0 => r as u32,
            _ => 24,
        }
    } else {
        l as u32
    };
    CACHED_LINES.store(l, Ordering::Relaxed);
    l
}

/// `on_tty()`: both stdout and stderr are ttys.
pub fn on_tty() -> bool {
    let c = CACHED_ON_TTY.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = isatty_safe(1) && isatty_safe(2);
    CACHED_ON_TTY.store(v as i32, Ordering::Relaxed);
    v
}

/// `on_dev_null()`: both stdout and stderr are /dev/null.
fn on_dev_null() -> bool {
    let c = CACHED_ON_DEV_NULL.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = match (sys::stat(b"/dev/null"), sys::fstat(1), sys::fstat(2)) {
        (Ok(d), Ok(o), Ok(e)) => {
            let same = |a: &sys::Stat, b: &sys::Stat| a.st_dev == b.st_dev && a.st_ino == b.st_ino;
            same(&d, &o) && same(&d, &e)
        }
        _ => false,
    };
    CACHED_ON_DEV_NULL.store(v as i32, Ordering::Relaxed);
    v
}

/// `getenv_terminal_is_dumb()`.
pub fn getenv_terminal_is_dumb() -> bool {
    match getenv("TERM") {
        None => true,
        Some(t) => t == b"dumb",
    }
}

/// `terminal_is_dumb()`.
pub fn terminal_is_dumb() -> bool {
    if !on_tty() && !on_dev_null() {
        return true;
    }
    getenv_terminal_is_dumb()
}

/// `ColorMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ColorMode {
    Off = 0,
    C16 = 1,
    C256 = 2,
    C24Bit = 3,
    Auto16 = 4,
    Auto256 = 5,
    Auto24Bit = 6,
    True = 7,
}

/// `color_mode_from_string()` (a string table with a boolean fallback).
fn color_mode_from_string(s: &[u8]) -> Option<ColorMode> {
    Some(match s {
        b"off" => ColorMode::Off,
        b"16" => ColorMode::C16,
        b"256" => ColorMode::C256,
        b"24bit" => ColorMode::C24Bit,
        b"auto-16" => ColorMode::Auto16,
        b"auto-256" => ColorMode::Auto256,
        b"auto-24bit" => ColorMode::Auto24Bit,
        b"true" => ColorMode::True,
        _ => match crate::parse::parse_boolean(s) {
            Ok(true) => ColorMode::True,
            Ok(false) => ColorMode::Off,
            Err(_) => return None,
        },
    })
}

/// `parse_systemd_colors()`.
pub fn parse_systemd_colors() -> Option<ColorMode> {
    color_mode_from_string(&getenv("SYSTEMD_COLORS")?)
}

/// `get_color_mode_impl()`.
fn get_color_mode_impl() -> ColorMode {
    let m = parse_systemd_colors();
    if let Some(m) = m
        && (m as i32) < (ColorMode::Auto16 as i32)
    {
        return m;
    }
    if m != Some(ColorMode::True) {
        if getenv("NO_COLOR").is_some() {
            return ColorMode::Off;
        }
        let dumb = if sys::getpid() == 1 { getenv_terminal_is_dumb() } else { terminal_is_dumb() };
        if dumb {
            return ColorMode::Off;
        }
    }
    match m {
        Some(ColorMode::Auto16) => return ColorMode::C16,
        Some(ColorMode::Auto256) => return ColorMode::C256,
        Some(ColorMode::Auto24Bit) => return ColorMode::C24Bit,
        _ => {}
    }
    if let Some(ct) = getenv("COLORTERM")
        && (ct == b"truecolor" || ct == b"24bit")
    {
        return ColorMode::C24Bit;
    }
    ColorMode::C256
}

/// `get_color_mode()` (cached).
pub fn get_color_mode() -> ColorMode {
    let c = CACHED_COLOR_MODE.load(Ordering::Relaxed);
    let m = if c >= 0 {
        c
    } else {
        let m = get_color_mode_impl() as i32;
        CACHED_COLOR_MODE.store(m, Ordering::Relaxed);
        m
    };
    match m {
        0 => ColorMode::Off,
        1 => ColorMode::C16,
        2 => ColorMode::C256,
        _ => ColorMode::C24Bit,
    }
}

/// `colors_enabled()`.
pub fn colors_enabled() -> bool {
    get_color_mode() != ColorMode::Off
}

/// `underline_enabled()`.
pub fn underline_enabled() -> bool {
    let c = CACHED_UNDERLINE.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = if colors_enabled() { getenv("TERM").as_deref() != Some(b"linux") } else { false };
    CACHED_UNDERLINE.store(v as i32, Ordering::Relaxed);
    v
}

/// `reset_terminal_feature_caches()`.
pub fn reset_terminal_feature_caches() {
    CACHED_COLUMNS.store(0, Ordering::Relaxed);
    CACHED_LINES.store(0, Ordering::Relaxed);
    CACHED_ON_TTY.store(-1, Ordering::Relaxed);
    CACHED_ON_DEV_NULL.store(-1, Ordering::Relaxed);
    CACHED_COLOR_MODE.store(-1, Ordering::Relaxed);
    CACHED_UNDERLINE.store(-1, Ordering::Relaxed);
}

pub mod ansi {
    //! The `ANSI_*` sequences and the `ansi_*()` functions.

    use super::{ColorMode, colors_enabled, get_color_mode, underline_enabled};

    pub const NORMAL: &str = "\x1B[0m";
    pub const RED: &str = "\x1B[0;31m";
    pub const HIGHLIGHT: &str = "\x1B[0;1;39m";
    pub const HIGHLIGHT_RED: &str = "\x1B[0;1;31m";
    pub const HIGHLIGHT_GREEN: &str = "\x1B[0;1;32m";
    pub const HIGHLIGHT_BLUE: &str = "\x1B[0;1;34m";
    pub const HIGHLIGHT_MAGENTA: &str = "\x1B[0;1;35m";
    pub const HIGHLIGHT_CYAN: &str = "\x1B[0;1;36m";
    pub const GREEN: &str = "\x1B[0;32m";
    pub const BRIGHT_BLACK: &str = "\x1B[0;90m";
    pub const BRIGHT_BLUE: &str = "\x1B[0;94m";
    pub const GREY: &str = "\x1B[0;38:5:245m";
    pub const HIGHLIGHT_YELLOW4: &str = "\x1B[0;1;38:5:100m";
    pub const HIGHLIGHT_KHAKI3: &str = "\x1B[0;1;38:5:185m";
    pub const HIGHLIGHT_GREY: &str = "\x1B[0;1;38:5:245m";
    pub const HIGHLIGHT_GREY_FALLBACK: &str = "\x1B[0;1;90m";
    pub const HIGHLIGHT_YELLOW_FALLBACK: &str = "\x1B[0;1;33m";
    pub const GREY_UNDERLINE: &str = "\x1B[0;4;38:5:245m";
    pub const BRIGHT_BLACK_UNDERLINE: &str = "\x1B[0;4;90m";
    pub const UNDERLINE: &str = "\x1B[0;4m";
    pub const ADD_UNDERLINE: &str = "\x1B[4m";
    pub const ADD_UNDERLINE_GREY: &str = "\x1B[4m\x1B[58:5:245m";
    pub const ITALICS: &str = "\x1B[0;3m";
    pub const ADD_ITALICS: &str = "\x1B[3m";
    pub const OSC: &str = "\x1B]";
    pub const ST: &str = "\x1B\\";

    fn simple(s: &'static str) -> &'static str {
        if colors_enabled() { s } else { "" }
    }

    /// `DEFINE_ANSI_FUNC_256`: the fallback first in 256 mode.
    fn c256(name: &'static str, fallback: &'static str, both: &'static str) -> &'static str {
        match get_color_mode() {
            ColorMode::Off => "",
            ColorMode::C16 => fallback,
            ColorMode::C256 => both,
            _ => name,
        }
    }

    pub fn normal() -> &'static str {
        simple(NORMAL)
    }
    pub fn highlight() -> &'static str {
        simple(HIGHLIGHT)
    }
    pub fn red() -> &'static str {
        simple(RED)
    }
    pub fn green() -> &'static str {
        simple(GREEN)
    }
    pub fn bright_blue() -> &'static str {
        simple(BRIGHT_BLUE)
    }
    pub fn highlight_red() -> &'static str {
        simple(HIGHLIGHT_RED)
    }
    pub fn highlight_green() -> &'static str {
        simple(HIGHLIGHT_GREEN)
    }
    pub fn highlight_blue() -> &'static str {
        simple(HIGHLIGHT_BLUE)
    }
    pub fn highlight_magenta() -> &'static str {
        simple(HIGHLIGHT_MAGENTA)
    }
    pub fn highlight_cyan() -> &'static str {
        simple(HIGHLIGHT_CYAN)
    }
    pub fn grey() -> &'static str {
        c256(GREY, BRIGHT_BLACK, "\x1B[0;90m\x1B[0;38:5:245m")
    }
    pub fn highlight_yellow() -> &'static str {
        c256(HIGHLIGHT_KHAKI3, HIGHLIGHT_YELLOW_FALLBACK, "\x1B[0;1;33m\x1B[0;1;38:5:185m")
    }
    pub fn highlight_yellow4() -> &'static str {
        c256(HIGHLIGHT_YELLOW4, HIGHLIGHT_YELLOW_FALLBACK, "\x1B[0;1;33m\x1B[0;1;38:5:100m")
    }
    pub fn highlight_grey() -> &'static str {
        c256(HIGHLIGHT_GREY, HIGHLIGHT_GREY_FALLBACK, "\x1B[0;1;90m\x1B[0;1;38:5:245m")
    }
    pub fn underline() -> &'static str {
        if underline_enabled() { UNDERLINE } else { "" }
    }
    pub fn add_underline() -> &'static str {
        if underline_enabled() { ADD_UNDERLINE } else { "" }
    }
    pub fn add_underline_grey() -> &'static str {
        if underline_enabled() { if colors_enabled() { ADD_UNDERLINE_GREY } else { ADD_UNDERLINE } } else { "" }
    }
    pub fn add_italics() -> &'static str {
        if underline_enabled() { ADD_ITALICS } else { "" }
    }
    /// `ansi_grey_underline()` (DEFINE_ANSI_FUNC_UNDERLINE_256).
    pub fn grey_underline() -> &'static str {
        if underline_enabled() {
            match get_color_mode() {
                ColorMode::Off => "",
                ColorMode::C16 => BRIGHT_BLACK_UNDERLINE,
                ColorMode::C256 => "\x1B[0;4;90m\x1B[0;4;38:5:245m",
                _ => GREY_UNDERLINE,
            }
        } else {
            grey()
        }
    }
}

/// `get_log_colors(priority)`: (on, off, highlight).
pub fn get_log_colors(priority: i32) -> (Option<&'static str>, Option<&'static str>, Option<&'static str>) {
    use ansi::*;
    if priority <= libc::LOG_ERR {
        (Some(highlight_red()), Some(normal()), Some(highlight()))
    } else if priority <= libc::LOG_WARNING {
        (Some(highlight_yellow()), Some(normal()), Some(highlight()))
    } else if priority <= libc::LOG_NOTICE {
        (Some(highlight()), Some(normal()), Some(highlight_red()))
    } else if priority >= libc::LOG_DEBUG {
        (Some(grey()), Some(normal()), Some(highlight_red()))
    } else {
        (None, None, None)
    }
}
