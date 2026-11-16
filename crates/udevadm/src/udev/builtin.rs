// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin.c`: the builtin table and dispatcher.  The builtins
//! themselves are phase 7: until then running one fails with
//! `EOPNOTSUPP`.

use shared::errno::strerror;
use shared::printo;
use shared::string::WHITESPACE;
use shared::{log_device_debug, log_device_debug_errno};

use super::event::Event;

/// `UdevBuiltinCommand`, in the order of `udev-def.h` for this build
/// (blkid, kmod and uaccess on; tpm2 off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltinCommand {
    Blkid,
    Btrfs,
    DissectImage,
    FactoryReset,
    Hwdb,
    InputId,
    Keyboard,
    Kmod,
    NetDriver,
    NetId,
    NetLink,
    PathId,
    Uaccess,
    UsbId,
}

struct Builtin {
    cmd: BuiltinCommand,
    name: &'static str,
    help: &'static str,
    run_once: bool,
}

const BUILTINS: &[Builtin] = &[
    Builtin { cmd: BuiltinCommand::Blkid, name: "blkid", help: "Filesystem and partition probing", run_once: true },
    Builtin { cmd: BuiltinCommand::Btrfs, name: "btrfs", help: "btrfs volume management", run_once: false },
    Builtin { cmd: BuiltinCommand::DissectImage, name: "dissect_image", help: "Dissect Disk Images", run_once: true },
    Builtin { cmd: BuiltinCommand::FactoryReset, name: "factory_reset", help: "Factory Reset Mode", run_once: true },
    Builtin { cmd: BuiltinCommand::Hwdb, name: "hwdb", help: "Hardware database", run_once: false },
    Builtin { cmd: BuiltinCommand::InputId, name: "input_id", help: "Input device properties", run_once: false },
    Builtin {
        cmd: BuiltinCommand::Keyboard,
        name: "keyboard",
        help: "Keyboard scancode mapping and touchpad/pointingstick characteristics",
        run_once: false,
    },
    Builtin { cmd: BuiltinCommand::Kmod, name: "kmod", help: "Kernel module loader", run_once: false },
    Builtin {
        cmd: BuiltinCommand::NetDriver,
        name: "net_driver",
        help: "Set driver for network device",
        run_once: true,
    },
    Builtin { cmd: BuiltinCommand::NetId, name: "net_id", help: "Network device properties", run_once: false },
    Builtin { cmd: BuiltinCommand::NetLink, name: "net_setup_link", help: "Configure network link", run_once: false },
    Builtin { cmd: BuiltinCommand::PathId, name: "path_id", help: "Compose persistent device path", run_once: true },
    Builtin { cmd: BuiltinCommand::Uaccess, name: "uaccess", help: "Manage device node user ACL", run_once: false },
    Builtin { cmd: BuiltinCommand::UsbId, name: "usb_id", help: "USB device properties", run_once: true },
];

fn builtin(cmd: BuiltinCommand) -> &'static Builtin {
    BUILTINS.iter().find(|b| b.cmd == cmd).expect("every command is in the table")
}

/// `1u << cmd`, for `builtin_run`/`builtin_ret`.
pub fn mask(cmd: BuiltinCommand) -> u32 {
    1u32 << (cmd as u32)
}

/// `udev_builtin_init()`.  Until the builtins are ported, this only does
/// what their init has an effect on later: dissect_image's reads the
/// kernel command line, and with it, detects (and caches) whether we run
/// in a container.
pub fn udev_builtin_init() {
    let _ = shared::proc_cmdline::proc_cmdline_get_key(b"systemd.image_policy", false);
}

/// `udev_builtin_exit()`.
pub fn udev_builtin_exit() {}

/// `udev_builtin_list()`.
pub fn udev_builtin_list() {
    for b in BUILTINS {
        printo!(format!("  {:<14}  {}\n", b.name, b.help));
    }
}

/// `udev_builtin_name(cmd)`.
pub fn udev_builtin_name(cmd: BuiltinCommand) -> &'static str {
    builtin(cmd).name
}

/// `udev_builtin_run_once(cmd)`.
pub fn udev_builtin_run_once(cmd: BuiltinCommand) -> bool {
    builtin(cmd).run_once
}

/// `udev_builtin_lookup(command)`: by the first word.
pub fn udev_builtin_lookup(command: &[u8]) -> Option<BuiltinCommand> {
    let c = shared::string::skip_leading_chars(command, Some(WHITESPACE));
    let n = c.iter().position(|b| WHITESPACE.contains(b)).unwrap_or(c.len());
    BUILTINS.iter().find(|b| b.name.as_bytes() == &c[..n]).map(|b| b.cmd)
}

/// `udev_builtin_run(event, cmd, command)`.
pub fn udev_builtin_run(event: &mut Event, cmd: BuiltinCommand, command: &[u8]) -> Result<(), i32> {
    let _argv = shared::extract::strv_split_full(
        command,
        None,
        shared::extract::EXTRACT_UNQUOTE | shared::extract::EXTRACT_RELAX | shared::extract::EXTRACT_RETAIN_ESCAPE,
    )?;
    log_device_debug!(event.dev, "Built-in command '", builtin(cmd).name, "' is not ported yet.");
    Err(-libc::EOPNOTSUPP)
}

/// `udev_builtin_add_property(event, key, val)`.
pub fn udev_builtin_add_property(event: &Event, key: &[u8], val: Option<&[u8]>) -> Result<(), i32> {
    let val = val.filter(|v| !v.is_empty());
    if let Err(r) = event.dev.add_property(key, val) {
        return Err(log_device_debug_errno!(
            event.dev,
            r,
            "Failed to ",
            if val.is_some() { "add" } else { "remove" },
            " property '",
            key,
            if val.is_some() { "=" } else { "" },
            val.unwrap_or_default(),
            "'"
        ));
    }
    if event.event_mode == super::def::EventMode::UdevadmTestBuiltin {
        match val {
            Some(v) => printo!(key, "=", v, "\n"),
            None => printo!(key, " (removed)\n"),
        }
    }
    let _ = strerror;
    Ok(())
}
