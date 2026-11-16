// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-kmod.c`.

use std::cell::RefCell;

use shared::errno::{strerror, synthetic};
use shared::sys_kmod::KmodCtx;
use shared::{log_debug, log_device_debug, log_device_warning_errno, log_error_errno};

use super::super::def::EventMode;
use super::super::event::Event;

thread_local! {
    static CTX: RefCell<Option<KmodCtx>> = const { RefCell::new(None) };
}

/// `builtin_kmod()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if event.event_mode != EventMode::UdevWorker {
        log_device_debug!(dev, "Running in test mode, skipping execution of 'kmod' builtin command.");
        return Ok(());
    }
    if CTX.with(|c| c.borrow().is_none()) {
        return Ok(());
    }
    if argv.len() < 2 || argv[1] != b"load" {
        return Err(log_device_warning_errno!(
            dev,
            synthetic(libc::EINVAL),
            &argv[0][..],
            ": expected: load [module\u{2026}]"
        ));
    }
    let modules: Vec<Vec<u8>> = argv[2..].to_vec();
    let modules = if modules.is_empty() {
        match dev.get_property_value(b"MODALIAS") {
            Ok(m) => vec![m.bytes().to_vec()],
            Err(r) => {
                return Err(log_device_warning_errno!(dev, r, "Failed to read property \"MODALIAS\": ", strerror(r)));
            }
        }
    } else {
        modules
    };
    CTX.with(|c| {
        if let Some(ctx) = c.borrow().as_ref() {
            for m in &modules {
                let _ = ctx.module_load_and_warn(m, false);
            }
        }
    });
    Ok(())
}

/// `builtin_kmod_init()`.
pub fn init() {
    if CTX.with(|c| c.borrow().is_some()) {
        return;
    }
    match KmodCtx::new() {
        Err(r) => {
            log_error_errno!(r, "Failed to initialize libkmod context: ", strerror(r));
        }
        Ok(ctx) => {
            CTX.with(|c| *c.borrow_mut() = Some(ctx));
            log_debug!("Loaded kernel module index.");
        }
    }
}

/// `builtin_kmod_exit()`.
pub fn exit() {
    if CTX.with(|c| c.borrow_mut().take()).is_some() {
        log_debug!("Unloaded kernel module index.");
    }
}

/// `builtin_kmod_should_reload()`.
pub fn should_reload() -> bool {
    let reload = CTX.with(|c| c.borrow().as_ref().is_some_and(|ctx| !ctx.resources_ok()));
    if reload {
        log_debug!("Kernel module index needs reloading.");
    }
    reload
}
