// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-def.h`.

pub const UDEV_NAME_SIZE: usize = 512;
pub const UDEV_PATH_SIZE: usize = 1024;
pub const UDEV_LINE_SIZE: usize = 16384;

/// `MODE_INVALID`, `UID_INVALID`, `GID_INVALID`.
pub const MODE_INVALID: u32 = u32::MAX;
pub const UID_INVALID: u32 = u32::MAX;
pub const GID_INVALID: u32 = u32::MAX;

/// `EventMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventMode {
    UdevWorker,
    UdevadmTest,
    UdevadmTestBuiltin,
    TestRuleRunner,
    TestSpawn,
}

/// `UdevRuleEscapeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    Unset,
    None,
    Replace,
}

/// `ResolveNameTiming`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolveNameTiming {
    Never,
    Late,
    Early,
}

impl ResolveNameTiming {
    pub fn from_string(s: &[u8]) -> Option<ResolveNameTiming> {
        match s {
            b"never" => Some(ResolveNameTiming::Never),
            b"late" => Some(ResolveNameTiming::Late),
            b"early" => Some(ResolveNameTiming::Early),
            _ => None,
        }
    }
}
