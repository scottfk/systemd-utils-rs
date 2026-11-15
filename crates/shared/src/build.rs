// SPDX-License-Identifier: LGPL-2.1-or-later
//! `build.c`: the version and feature string of the C build this port matches.

use crate::terminal::{ansi, colors_enabled};

pub const PROJECT_VERSION: u32 = 262;
pub const PROJECT_VERSION_STR: &str = "262";
pub const PROJECT_VERSION_FULL: &str = "262";
/// `GIT_VERSION`.
pub const GIT_VERSION: &str = "262";

/// `systemd_features` for Gentoo's systemd-utils-262 with USE="acl kmod sysctl tmpfiles udev".
pub const SYSTEMD_FEATURES: &str = "-PAM -AUDIT -SELINUX -APPARMOR -IMA -IPE -SMACK -SECCOMP -GNUTLS -OPENSSL +ACL +BLKID -CURL -ELFUTILS -FIDO2 -IDN2 +KMOD -LIBCRYPTSETUP -LIBCRYPTSETUP_PLUGINS -LIBFDISK -PCRE2 -PWQUALITY -P11KIT -QRENCODE -TPM2 -BZIP2 -LZ4 -XZ -ZLIB -ZSTD -BPF_FRAMEWORK -BTF -XKBCOMMON -UTMP -LIBARCHIVE";

/// `systemd_features_with_color()`.
fn features_with_color() -> String {
    SYSTEMD_FEATURES
        .split(' ')
        .map(|w| match w.as_bytes()[0] {
            b'+' => format!("{}+{}{}{}", ansi::HIGHLIGHT_GREEN, ansi::GREEN, &w[1..], ansi::NORMAL),
            b'-' => format!("{}-{}{}{}", ansi::HIGHLIGHT_RED, ansi::RED, &w[1..], ansi::NORMAL),
            _ => w.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `version()`.
pub fn version() -> i32 {
    let b = if colors_enabled() { features_with_color() } else { SYSTEMD_FEATURES.to_string() };
    crate::printo!(
        ansi::highlight(),
        "systemd ",
        PROJECT_VERSION.to_string(),
        ansi::normal(),
        " (",
        GIT_VERSION,
        ")\n",
        b,
        "\n"
    );
    0
}

/// `version_only()`.
pub fn version_only() -> i32 {
    crate::printo!(PROJECT_VERSION_STR, "\n");
    0
}
