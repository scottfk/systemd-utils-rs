// SPDX-License-Identifier: LGPL-2.1-or-later
//! The reading half of `efivars.c`.

use crate::errno::{strerror, synthetic};
use crate::sys::{self, OwnedFd};
use crate::{log_debug, log_debug_errno};

/// `EFI_VENDOR_SYSTEMD_STR`.
pub const EFI_VENDOR_SYSTEMD: &str = "8cf2644b-4b0b-428f-9387-6d876050dc67";

thread_local! {
    static EFI_BOOT: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// `is_efi_boot()`.
pub fn is_efi_boot() -> bool {
    if let Some(b) = EFI_BOOT.with(|c| c.get()) {
        return b;
    }
    let b = if crate::virt::detect_container().is_ok_and(|v| v != crate::virt::NONE) {
        false
    } else {
        match crate::sys_net::access(b"/sys/firmware/efi/", libc::F_OK) {
            Ok(()) => true,
            Err(r) => {
                if r != -libc::ENOENT {
                    log_debug_errno!(
                        r,
                        "Unable to test whether /sys/firmware/efi/ exists, assuming EFI not available: ",
                        strerror(r)
                    );
                }
                false
            }
        }
    };
    EFI_BOOT.with(|c| c.set(Some(b)));
    b
}

/// `efi_get_variable(variable, &attr, &value, &size)`: (attributes, value).
pub fn efi_get_variable(variable: &str) -> Result<(u32, Vec<u8>), i32> {
    let p = format!("/sys/firmware/efi/efivars/{variable}");
    let debug = crate::log::debug_logging();
    let begin = if debug {
        log_debug!("Reading EFI variable ", &p[..], ".");
        crate::time::now_monotonic()
    } else {
        0
    };
    let fd = match sys::open(p.as_bytes(), libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC, 0) {
        Ok(fd) => OwnedFd::new(fd),
        Err(r) => return Err(log_debug_errno!(r, "open(\"", &p[..], "\") failed: ", strerror(r))),
    };
    let mut data;
    let mut tries = 0u32;
    loop {
        let st =
            sys::fstat(fd.raw()).map_err(|r| log_debug_errno!(r, "fstat(\"", &p[..], "\") failed: ", strerror(r)))?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            let r = if st.st_mode & libc::S_IFMT == libc::S_IFDIR { -libc::EISDIR } else { -libc::EBADFD };
            return Err(log_debug_errno!(
                r,
                "EFI variable '",
                &p[..],
                "' is not a regular file, refusing: ",
                strerror(r)
            ));
        }
        let size = st.st_size as u64;
        if size == 0 {
            return Err(log_debug_errno!(synthetic(libc::ENOENT), "EFI variable '", &p[..], "' is uncommitted"));
        }
        if size < 4 {
            return Err(log_debug_errno!(
                synthetic(libc::ENODATA),
                "EFI variable '",
                &p[..],
                "' is shorter than 4 bytes, refusing."
            ));
        }
        if size > 4 + 4 * 1024 * 1024 {
            return Err(log_debug_errno!(
                synthetic(libc::E2BIG),
                "EFI variable '",
                &p[..],
                "' is ridiculously large, refusing."
            ));
        }
        let read_limit = size as usize + 1;
        data = vec![0u8; read_limit];
        match sys::read(fd.raw(), &mut data) {
            Err(r) if r != -libc::EINTR => {
                return Err(log_debug_errno!(r, "Reading from '", &p[..], "' failed: ", strerror(r)));
            }
            Err(_) => {
                log_debug!("Reading from '", &p[..], "' failed with EINTR, retrying.");
            }
            Ok(n) if n == read_limit => {
                log_debug!("EFI variable '", &p[..], "' larger than expected, retrying.");
            }
            Ok(n) => {
                data.truncate(n);
                break;
            }
        }
        if tries >= 50 {
            return Err(log_debug_errno!(
                synthetic(libc::EBUSY),
                "Reading EFI variable '",
                &p[..],
                "' failed even after ",
                tries.to_string(),
                " tries, giving up."
            ));
        }
        if tries >= 5 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        tries += 1;
        let _ = sys::lseek(fd.raw(), 0, libc::SEEK_SET);
    }
    if data.is_empty() {
        return Err(log_debug_errno!(synthetic(libc::ENOENT), "EFI variable ", &p[..], " is uncommitted"));
    }
    if data.len() < 4 {
        return Err(log_debug_errno!(
            synthetic(libc::EIO),
            "Read ",
            data.len().to_string(),
            " bytes from EFI variable ",
            &p[..],
            ", expected >= 4"
        ));
    }
    let attr = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if debug {
        let end = crate::time::now_monotonic();
        if end > begin + 50_000 {
            log_debug!(
                "Detected slow EFI variable read access on ",
                variable,
                ": ",
                crate::time::format_timespan(end - begin, 1)
            );
        }
    }
    Ok((attr, data[4..].to_vec()))
}

/// `utf16_to_utf8(s, length)`: little-endian UTF-16 up to the first NUL;
/// unpaired surrogates become U+FFFD.
pub fn utf16_to_utf8(s: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units).into_bytes()
}

/// `efi_get_variable_string(variable, &ret)`.
pub fn efi_get_variable_string(variable: &str) -> Result<Vec<u8>, i32> {
    efi_get_variable(variable).map(|(_, v)| utf16_to_utf8(&v))
}
