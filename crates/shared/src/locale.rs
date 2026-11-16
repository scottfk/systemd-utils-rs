// SPDX-License-Identifier: LGPL-2.1-or-later
//! `locale-util.c`'s `is_locale_utf8()` and `glyph-util.c`.

use std::sync::atomic::{AtomicI8, Ordering};

use crate::env::{getenv, getenv_bool, secure_getenv_bool};
use crate::sys;

static LOCALE_UTF8: AtomicI8 = AtomicI8::new(-1);

/// `is_main_thread()`.
pub fn is_main_thread() -> bool {
    sys::gettid() == sys::getpid()
}

/// `is_locale_utf8_impl()`.
fn is_locale_utf8_impl() -> bool {
    match secure_getenv_bool("SYSTEMD_UTF8") {
        Ok(b) => return b,
        Err(r) if r != -libc::ENXIO => {
            crate::log_debug_errno!(r, "Failed to parse $SYSTEMD_UTF8, ignoring: ", crate::errno::strerror(r));
        }
        Err(_) => {}
    }
    if !is_main_thread() {
        return true;
    }
    if !sys::setlocale_all_default() {
        return true;
    }
    match sys::langinfo_codeset() {
        None => return true,
        Some(s) if s == b"UTF-8" => return true,
        Some(_) => {}
    }
    let Some(set) = sys::setlocale_ctype_query() else {
        return true;
    };
    (set == b"C" || set == b"POSIX")
        && getenv("LC_ALL").is_none()
        && getenv("LC_CTYPE").is_none()
        && getenv("LANG").is_none()
}

/// `is_locale_utf8()` (cached).
pub fn is_locale_utf8() -> bool {
    let c = LOCALE_UTF8.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = is_locale_utf8_impl();
    LOCALE_UTF8.store(v as i8, Ordering::Relaxed);
    v
}

/// The glyphs the ported programs use (`Glyph` in glyph-util.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    Ellipsis,
    ArrowRight,
    HorizontalDotted,
    HorizontalFat,
    CheckMark,
    CrossMark,
    TreeVertical,
    TreeBranch,
    TreeRight,
    TreeSpace,
    VerticalDotted,
    Bullet,
}

/// `glyph_full(code, force_utf)`.
pub fn glyph_full(code: Glyph, force_utf: bool) -> &'static [u8] {
    let utf = force_utf || is_locale_utf8();
    let (ascii, uni): (&'static str, &'static str) = match code {
        Glyph::Ellipsis => ("...", "…"),
        Glyph::ArrowRight => ("->", "→"),
        Glyph::HorizontalDotted => ("-", "┄"),
        Glyph::HorizontalFat => ("=", "━"),
        Glyph::CheckMark => ("+", "✓"),
        Glyph::CrossMark => ("-", "✗"),
        Glyph::TreeVertical => ("| ", "│ "),
        Glyph::TreeBranch => ("|-", "├─"),
        Glyph::TreeRight => ("`-", "└─"),
        Glyph::TreeSpace => ("  ", "  "),
        Glyph::VerticalDotted => (":", "┆"),
        Glyph::Bullet => ("*", "•"),
    };
    if utf { uni.as_bytes() } else { ascii.as_bytes() }
}

/// `glyph(code)`.
pub fn glyph(code: Glyph) -> &'static [u8] {
    glyph_full(code, false)
}

/// `emoji_enabled()`.
pub fn emoji_enabled() -> bool {
    static CACHE: AtomicI8 = AtomicI8::new(-1);
    let c = CACHE.load(Ordering::Relaxed);
    if c >= 0 {
        return c > 0;
    }
    let v = if let Ok(b) = getenv_bool("SYSTEMD_EMOJI") {
        b
    } else {
        match getenv("TERM") {
            None => false,
            Some(t) if t == b"dumb" || t == b"linux" => false,
            Some(_) => is_locale_utf8(),
        }
    };
    CACHE.store(v as i8, Ordering::Relaxed);
    v
}
