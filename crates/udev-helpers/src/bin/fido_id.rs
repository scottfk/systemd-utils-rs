// SPDX-License-Identifier: LGPL-2.1-or-later
//! `fido_id`: identify FIDO CTAP1 ("U2F")/CTAP2 security tokens by the
//! usage their HID report descriptor declares.  A port of systemd's
//! `src/udev/fido_id/fido_id.c` and `fido_id_desc.c` (v262).

use std::os::unix::ffi::OsStringExt;

use shared::errno::{strerror, synthetic};
use shared::options::Command;
use shared::sd_device::Device;
use shared::{log_device_debug_errno, log_device_error_errno, log_error_errno, sys};
use udev_helpers::out;

const COMMAND: Command = Command {
    names: &["fido_id"],
    abstract_: "Identify FIDO security tokens.",
    argspec: &["[SYSFS_PATH]"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const FIDO_FULL_USAGE_CTAPHID: u32 = 0xf1d0_0001;

/// `is_fido_security_token_desc()`.
fn is_fido_security_token_desc(desc: &[u8]) -> Result<bool, i32> {
    let mut usage: u32 = 0;
    let mut pos = 0usize;
    while pos < desc.len() {
        if desc[pos] == 0xfe {
            if pos + 1 >= desc.len() {
                return Err(-libc::EINVAL);
            }
            pos += desc[pos + 1] as usize + 3;
            continue;
        }
        let tag = desc[pos] >> 4;
        let ty = (desc[pos] >> 2) & 0x3;
        let size_code = desc[pos] & 0x3;
        let size = if size_code < 3 { size_code as usize } else { 4 };
        pos += 1;
        if pos + size > desc.len() {
            return Err(-libc::EINVAL);
        }
        let mut value: u32 = 0;
        for i in 0..size {
            value |= (desc[pos + i] as u32) << (8 * i);
        }
        pos += size;
        if ty == 1 && tag == 0 {
            if size > 2 {
                return Err(-libc::EINVAL);
            }
            usage = (value & 0xffff) << 16;
        }
        if ty == 2 && tag == 0 {
            usage = if size == 4 { value } else { (usage & 0xffff_0000) | (value & 0xffff) };
            if usage == FIDO_FULL_USAGE_CTAPHID {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let _ = udevadm::udev::util::udev_parse_config();
    shared::log::log_setup();
    let args = match udev_helpers::parse_common_argv(argv, &COMMAND) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if args.len() > 1 {
        return log_error_errno!(synthetic(libc::EINVAL), "Error: unexpected argument.");
    }
    let device = match args.first() {
        Some(p) => match Device::new_from_syspath(p) {
            Ok(d) => d,
            Err(r) => {
                return log_error_errno!(r, "Failed to get device from syspath ", &p[..], ": ", strerror(r));
            }
        },
        None => {
            let env: Vec<Vec<u8>> =
                std::env::vars_os().map(|(k, v)| shared::bcat!(k.into_vec(), "=", v.into_vec())).collect();
            let refs: Vec<&[u8]> = env.iter().map(|e| &e[..]).collect();
            match Device::new_from_strv(&refs) {
                Ok(d) => d,
                Err(r) => {
                    return log_error_errno!(r, "Failed to get current device from environment: ", strerror(r));
                }
            }
        }
    };
    let hid = match device.get_parent() {
        Ok(h) => h,
        Err(r) => return log_device_error_errno!(device, r, "Failed to get parent HID device: ", strerror(r)),
    };
    let desc_path = shared::path::path_join(&[hid.get_syspath().bytes(), b"report_descriptor"]);
    let fd = match sys::open(&desc_path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
        Ok(fd) => sys::OwnedFd::new(fd),
        Err(r) => {
            return log_device_error_errno!(
                hid,
                r,
                "Failed to open report descriptor at '",
                &desc_path[..],
                "': ",
                strerror(r)
            );
        }
    };
    let mut desc = vec![0u8; HID_MAX_DESCRIPTOR_SIZE];
    let n = match sys::read(fd.raw(), &mut desc) {
        Ok(n) => n,
        Err(r) => {
            return log_device_error_errno!(
                hid,
                r,
                "Failed to read report descriptor at '",
                &desc_path[..],
                "': ",
                strerror(r)
            );
        }
    };
    if n == 0 {
        return log_device_debug_errno!(
            hid,
            synthetic(libc::EINVAL),
            "Empty report descriptor at '",
            &desc_path[..],
            "'."
        );
    }
    match is_fido_security_token_desc(&desc[..n]) {
        Err(r) => log_device_debug_errno!(hid, r, "Failed to parse report descriptor at '", &desc_path[..], "'."),
        Ok(true) => {
            out!("ID_FIDO_TOKEN=1\n", "ID_SECURITY_TOKEN=1\n");
            0
        }
        Ok(false) => 0,
    }
}

fn main() {
    shared::main_func::main_with(run)
}

#[cfg(test)]
mod tests {
    //! Upstream's `test-fido-id-desc.c`.
    use super::is_fido_security_token_desc as f;

    const U2F: &[u8] = &[
        0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
    ];
    const KEYBOARD: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
        0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01,
        0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
        0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0x09, 0x03, 0x75, 0x08, 0x95, 0x08, 0xb1, 0x02, 0xc0,
    ];

    #[test]
    fn fido() {
        assert_eq!(f(U2F), Ok(true));
        assert_eq!(f(&[KEYBOARD, U2F].concat()), Ok(true));
    }

    #[test]
    fn non_fido() {
        // Wrong usage page, then wrong usage.
        let mut page = U2F.to_vec();
        page[2] = 0xf0;
        assert_eq!(f(&page), Ok(false));
        let mut usage = U2F.to_vec();
        usage[4] = 0x02;
        assert_eq!(f(&usage), Ok(false));
        assert_eq!(f(KEYBOARD), Ok(false));
    }

    #[test]
    fn invalid() {
        for d in [&[0x01][..], &[0x02, 0x01], &[0x03, 0x01, 0x02, 0x03], &[0xfe], &[0x07, 0x01, 0x02, 0x03, 0x04]] {
            assert_eq!(f(d), Err(-libc::EINVAL));
        }
    }
}
