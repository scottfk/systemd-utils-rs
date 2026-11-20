// SPDX-License-Identifier: GPL-2.0-or-later
//! `mtd_probe`: identify SmartMedia flash on MTD devices.  A port of
//! systemd's `src/udev/mtd_probe/mtd_probe.c` and `probe_smartmedia.c`
//! (v262).

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_WARNING};
use shared::options::Command;
use shared::{log_debug_errno, log_error_errno, log_full_errno, sys};
use udev_helpers::out;

const COMMAND: Command = Command {
    names: &["mtd_probe"],
    abstract_: "Probe MTD devices.",
    argspec: &["/dev/mtdN"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const MEMGETINFO: u64 = 0x8020_4d01;
const MTD_NANDFLASH: u8 = 4;
const SM_SECTOR_SIZE: usize = 512;
const SM_SMALL_PAGE: usize = 256;
const CIS_SIGNATURE: [u8; 10] = [0x01, 0x03, 0xD9, 0x01, 0xFF, 0x18, 0x02, 0xDF, 0x01, 0x20];

/// `probe_smart_media()`.
fn probe_smart_media(fd: i32, info: &[u8; 32]) -> i32 {
    let rd = |o: usize| u32::from_ne_bytes(info[o..o + 4].try_into().expect("4 bytes"));
    if info[0] != MTD_NANDFLASH {
        return log_debug_errno!(synthetic(libc::EINVAL), "Not marked MTD_NANDFLASH.");
    }
    let sector_size = rd(0x10) as i32;
    let block_size = rd(0x0c) as i32;
    let size_in_megs = (rd(0x08) / (1024 * 1024)) as i32;
    if sector_size != SM_SECTOR_SIZE as i32 && sector_size != SM_SMALL_PAGE as i32 {
        return log_debug_errno!(synthetic(libc::EINVAL), format!("Unexpected sector size: {sector_size}"));
    }
    let spare_count = match size_in_megs {
        1 | 2 => 6,
        4 => 12,
        _ => 24,
    };
    let mut buf = vec![0u8; SM_SECTOR_SIZE];
    let mut found = false;
    let mut offset: i32 = 0;
    while offset < block_size.wrapping_mul(spare_count) {
        let _ = sys::lseek(fd, offset as i64, libc::SEEK_SET);
        if sys::read(fd, &mut buf) == Ok(SM_SECTOR_SIZE) {
            found = true;
            break;
        }
        offset += sector_size;
    }
    if !found {
        return log_debug_errno!(synthetic(libc::EINVAL), "CIS not found");
    }
    if buf[..CIS_SIGNATURE.len()] != CIS_SIGNATURE
        && buf[SM_SMALL_PAGE..SM_SMALL_PAGE + CIS_SIGNATURE.len()] != CIS_SIGNATURE
    {
        return log_debug_errno!(synthetic(libc::EINVAL), "CIS signature didn't match");
    }
    out!("MTD_FTL=smartmedia\n");
    0
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let args = match udev_helpers::parse_common_argv(argv, &COMMAND) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if args.len() != 1 {
        return log_error_errno!(synthetic(libc::EINVAL), "Need exactly one DEVICE argument.");
    }
    let device = &args[0];
    let fd = match sys::open(device, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
        Ok(fd) => sys::OwnedFd::new(fd),
        Err(r) => {
            let ignore = shared::sd_device::errno_is_neg_device_absent(r) || r == -libc::ENOMEDIUM;
            log_full_errno!(
                if ignore { LOG_DEBUG } else { LOG_WARNING },
                r,
                "Failed to open device node '",
                &device[..],
                "'",
                if ignore { ", ignoring" } else { "" },
                ": ",
                strerror(r)
            );
            return if ignore { 0 } else { r };
        }
    };
    let mut info = [0u8; 32];
    if let Err(r) = sys::ioctl_ptr(fd.raw(), MEMGETINFO, &mut info) {
        return log_error_errno!(r, "MEMGETINFO ioctl failed: ", strerror(r));
    }
    probe_smart_media(fd.raw(), &info)
}

fn main() {
    shared::main_func::main_with(run)
}
