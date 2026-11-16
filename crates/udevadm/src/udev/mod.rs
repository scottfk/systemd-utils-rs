// SPDX-License-Identifier: GPL-2.0-or-later
//! The udev engine: what `udevadm test` and (later) udevd share.

pub mod builtin;
pub mod def;
pub mod dump;
pub mod event;
pub mod format;
pub mod node;
pub mod rules;
pub mod spawn;
pub mod util;
pub mod varlink;
pub mod wait;
