// SPDX-License-Identifier: LGPL-2.1-or-later
//! `gpt.c`: partition designators and the GPT partition type table.

use crate::gpt_types::{GPT_TYPES, GptType};

pub const SD_GPT_FLAG_REQUIRED_PARTITION: u64 = 1 << 0;
pub const SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL: u64 = 1 << 1;
pub const SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE: u64 = 1 << 2;
pub const SD_GPT_FLAG_GROWFS: u64 = 1 << 59;
pub const SD_GPT_FLAG_READ_ONLY: u64 = 1 << 60;
pub const SD_GPT_FLAG_NO_AUTO: u64 = 1 << 63;

/// `SD_GPT_LINUX_GENERIC`.
pub const SD_GPT_LINUX_GENERIC: [u8; 16] =
    [0x0f, 0xc6, 0x3d, 0xaf, 0x84, 0x83, 0x47, 0x72, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4];
/// `SD_GPT_VAR`.
pub const SD_GPT_VAR: [u8; 16] =
    [0x4d, 0x21, 0xb0, 0x16, 0xb5, 0x34, 0x45, 0xc2, 0xa9, 0xfb, 0x5c, 0x16, 0xe0, 0x91, 0xfd, 0x2d];

/// `PartitionDesignator`, in C's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Designator {
    Root,
    Usr,
    Home,
    Srv,
    Esp,
    Xbootldr,
    Swap,
    RootVerity,
    UsrVerity,
    RootVeritySig,
    UsrVeritySig,
    Tmp,
    Var,
}

/// `_PARTITION_DESIGNATOR_MAX`.
pub const N_DESIGNATORS: usize = 13;

pub const ALL: [Designator; N_DESIGNATORS] = [
    Designator::Root,
    Designator::Usr,
    Designator::Home,
    Designator::Srv,
    Designator::Esp,
    Designator::Xbootldr,
    Designator::Swap,
    Designator::RootVerity,
    Designator::UsrVerity,
    Designator::RootVeritySig,
    Designator::UsrVeritySig,
    Designator::Tmp,
    Designator::Var,
];

impl Designator {
    pub fn index(self) -> usize {
        self as usize
    }

    /// `partition_designator_to_string()`.
    pub fn as_str(self) -> &'static str {
        match self {
            Designator::Root => "root",
            Designator::Usr => "usr",
            Designator::Home => "home",
            Designator::Srv => "srv",
            Designator::Esp => "esp",
            Designator::Xbootldr => "xbootldr",
            Designator::Swap => "swap",
            Designator::RootVerity => "root-verity",
            Designator::UsrVerity => "usr-verity",
            Designator::RootVeritySig => "root-verity-sig",
            Designator::UsrVeritySig => "usr-verity-sig",
            Designator::Tmp => "tmp",
            Designator::Var => "var",
        }
    }

    /// `partition_designator_from_string()`.
    pub fn from_bytes(s: &[u8]) -> Option<Designator> {
        ALL.into_iter().find(|d| d.as_str().as_bytes() == s)
    }

    /// The name the generated table uses.
    fn from_table(s: &str) -> Option<Designator> {
        Some(match s {
            "Root" => Designator::Root,
            "RootVerity" => Designator::RootVerity,
            "RootVeritySig" => Designator::RootVeritySig,
            "Usr" => Designator::Usr,
            "UsrVerity" => Designator::UsrVerity,
            "UsrVeritySig" => Designator::UsrVeritySig,
            "Esp" => Designator::Esp,
            "Xbootldr" => Designator::Xbootldr,
            "Swap" => Designator::Swap,
            "Home" => Designator::Home,
            "Srv" => Designator::Srv,
            "Var" => Designator::Var,
            "Tmp" => Designator::Tmp,
            _ => return None,
        })
    }

    /// `partition_designator_is_versioned()`.
    pub fn is_versioned(self) -> bool {
        matches!(
            self,
            Designator::Root
                | Designator::Usr
                | Designator::RootVerity
                | Designator::UsrVerity
                | Designator::RootVeritySig
                | Designator::UsrVeritySig
        )
    }

    /// `partition_verity_hash_of()`.
    pub fn verity_hash_of(self) -> Option<Designator> {
        match self {
            Designator::Root => Some(Designator::RootVerity),
            Designator::Usr => Some(Designator::UsrVerity),
            _ => None,
        }
    }

    /// `partition_verity_sig_of()`.
    pub fn verity_sig_of(self) -> Option<Designator> {
        match self {
            Designator::Root => Some(Designator::RootVeritySig),
            Designator::Usr => Some(Designator::UsrVeritySig),
            _ => None,
        }
    }

    /// `partition_verity_hash_to_data()`.
    pub fn verity_hash_to_data(self) -> Option<Designator> {
        match self {
            Designator::RootVerity => Some(Designator::Root),
            Designator::UsrVerity => Some(Designator::Usr),
            _ => None,
        }
    }

    /// `partition_verity_sig_to_data()`.
    pub fn verity_sig_to_data(self) -> Option<Designator> {
        match self {
            Designator::RootVeritySig => Some(Designator::Root),
            Designator::UsrVeritySig => Some(Designator::Usr),
            _ => None,
        }
    }

    /// `partition_verity_to_data()`.
    pub fn verity_to_data(self) -> Option<Designator> {
        self.verity_hash_to_data().or_else(|| self.verity_sig_to_data())
    }

    /// `partition_designator_is_verity()`.
    pub fn is_verity(self) -> bool {
        self.verity_to_data().is_some()
    }
}

/// The native architecture's name.
pub const NATIVE_ARCHITECTURE: &str = if cfg!(target_arch = "x86_64") { "x86-64" } else { "x86" };
/// `ARCHITECTURE_SECONDARY`, if the build has one.
pub const SECONDARY_ARCHITECTURE: Option<&str> = if cfg!(target_arch = "x86_64") { Some("x86") } else { None };

/// A `GptPartitionType`.
#[derive(Debug, Clone, Copy)]
pub struct GptPartitionType {
    pub uuid: [u8; 16],
    pub arch: Option<&'static str>,
    pub designator: Option<Designator>,
}

fn arch_of(t: &GptType) -> Option<&'static str> {
    match t.arch {
        "" => None,
        "@NATIVE@" => Some(NATIVE_ARCHITECTURE),
        "@SECONDARY@" => SECONDARY_ARCHITECTURE,
        a => Some(a),
    }
}

/// `gpt_partition_type_from_uuid(id)`.
pub fn gpt_partition_type_from_uuid(id: &[u8; 16]) -> GptPartitionType {
    match GPT_TYPES.iter().find(|t| t.uuid == *id) {
        Some(t) => {
            GptPartitionType { uuid: t.uuid, arch: arch_of(t), designator: Designator::from_table(t.designator) }
        }
        None => GptPartitionType { uuid: *id, arch: None, designator: None },
    }
}
