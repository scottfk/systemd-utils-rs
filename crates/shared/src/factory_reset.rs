// SPDX-License-Identifier: LGPL-2.1-or-later
//! `factory-reset.c`: the factory reset mode.

use crate::errno::strerror;
use crate::json::Json;
use crate::{log_debug, log_debug_errno};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetMode {
    Unsupported,
    Unspecified,
    Off,
    On,
    Complete,
    Pending,
}

impl FactoryResetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            FactoryResetMode::Unsupported => "unsupported",
            FactoryResetMode::Unspecified => "unspecified",
            FactoryResetMode::Off => "off",
            FactoryResetMode::On => "on",
            FactoryResetMode::Complete => "complete",
            FactoryResetMode::Pending => "pending",
        }
    }
}

/// `factory_reset_supported()`.
fn supported() -> bool {
    match crate::env::secure_getenv_bool("SYSTEMD_FACTORY_RESET_SUPPORTED") {
        Ok(b) => b,
        Err(r) => {
            if r != -libc::ENXIO {
                log_debug_errno!(r, "Unable to parse $SYSTEMD_FACTORY_RESET_SUPPORTED, ignoring: ", strerror(r));
            }
            true
        }
    }
}

/// `factory_reset_mode_efi_variable()`.
fn efi_variable() -> Result<FactoryResetMode, i32> {
    if !crate::efivars::is_efi_boot() {
        log_debug!("Not booted in EFI mode, not checking FactoryResetRequest variable.");
        return Ok(FactoryResetMode::Unspecified);
    }
    let var = format!("FactoryResetRequest-{}", crate::efivars::EFI_VENDOR_SYSTEMD);
    let s = match crate::efivars::efi_get_variable_string(&var) {
        Err(r) if r == -libc::ENOENT => {
            log_debug_errno!(r, "EFI variable FactoryResetRequest is not set, skipping.");
            return Ok(FactoryResetMode::Unspecified);
        }
        Err(r) => return Err(log_debug_errno!(r, "Failed to get EFI variable FactoryResetRequest: ", strerror(r))),
        Ok(s) => s,
    };
    let v = match crate::json::parse(&s) {
        Err(r) => {
            log_debug_errno!(r, "EFI variable FactoryResetRequest set to invalid JSON, ignoring: ", strerror(r));
            return Ok(FactoryResetMode::Unspecified);
        }
        Ok(v) => v,
    };
    let field = |k: &str, mandatory: bool| -> Result<Option<Vec<u8>>, i32> {
        match v.get(k) {
            None if mandatory => Err(-libc::ENXIO),
            None | Some(Json::Null) => Ok(None),
            Some(Json::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(-libc::EINVAL),
        }
    };
    let parsed = (|| -> Result<(Vec<u8>, Option<Vec<u8>>, crate::id128::Id128), i32> {
        if !v.is_object() {
            return Err(-libc::EINVAL);
        }
        let id = field("osReleaseId", true)?.ok_or(-libc::EINVAL)?;
        let image_id = field("osReleaseImageId", false)?;
        let boot = field("bootId", true)?.ok_or(-libc::EINVAL)?;
        let boot = crate::id128::from_string(&boot)?;
        Ok((id, image_id, boot))
    })();
    let (id, image_id, boot) = match parsed {
        Err(r) => {
            log_debug_errno!(r, "Unable to dispatch EFI variable FactoryResetRequest, ignoring: ", strerror(r));
            return Ok(FactoryResetMode::Unspecified);
        }
        Ok(x) => x,
    };
    let os_id = crate::env_file::parse_os_release(None, "ID")
        .map_err(|r| log_debug_errno!(r, "Failed to parse os-release: ", strerror(r)))?;
    let os_image = crate::env_file::parse_os_release(None, "IMAGE_ID")
        .map_err(|r| log_debug_errno!(r, "Failed to parse os-release: ", strerror(r)))?;
    if Some(id) != os_id || image_id != os_image {
        log_debug!("FactoryResetRequest EFI variable set, but not for us, ignoring.");
        return Ok(FactoryResetMode::Unspecified);
    }
    let current =
        crate::id128::get_boot().map_err(|r| log_debug_errno!(r, "Failed to query boot ID: ", strerror(r)))?;
    if current == boot {
        log_debug!("EFI variable FactoryResetRequest set for next boot.");
        return Ok(FactoryResetMode::Pending);
    }
    Ok(FactoryResetMode::On)
}

/// `factory_reset_mode()`.
pub fn factory_reset_mode() -> Result<FactoryResetMode, i32> {
    if !supported() {
        return Ok(FactoryResetMode::Unsupported);
    }
    match crate::sys_net::access(b"/run/systemd/factory-reset-complete", libc::F_OK) {
        Ok(()) => return Ok(FactoryResetMode::Complete),
        Err(r) if r != -libc::ENOENT => {
            return Err(log_debug_errno!(
                r,
                "Can't determine if /run/systemd/factory-reset-complete exists: ",
                strerror(r)
            ));
        }
        Err(_) => {}
    }
    let b = match crate::proc_cmdline::proc_cmdline_get_key(b"systemd.factory_reset", true) {
        Err(r) => {
            return Err(log_debug_errno!(
                r,
                "Failed to parse systemd.factory_reset kernel command line argument: ",
                strerror(r)
            ));
        }
        Ok(None) => return efi_variable(),
        Ok(Some(None)) => true,
        Ok(Some(Some(v))) => crate::parse::parse_boolean(&v).map_err(|r| {
            log_debug_errno!(r, "Failed to parse systemd.factory_reset kernel command line argument: ", strerror(r))
        })?,
    };
    Ok(if b { FactoryResetMode::On } else { FactoryResetMode::Off })
}
