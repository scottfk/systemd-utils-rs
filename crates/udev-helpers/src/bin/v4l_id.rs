// SPDX-License-Identifier: GPL-2.0-or-later
//! `v4l_id`: identify Video4Linux devices.  A port of systemd's
//! `src/udev/v4l_id/v4l_id.c` (v262).

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_WARNING};
use shared::options::Command;
use shared::{log_error_errno, log_full_errno, sys};
use udev_helpers::out;

const COMMAND: Command = Command {
    names: &["v4l_id"],
    abstract_: "Identify Video4Linux devices.",
    argspec: &["DEVICE"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const VIDIOC_QUERYCAP: u64 = 0x8068_5600;
const CAP_VIDEO_CAPTURE: u32 = 0x1;
const CAP_VIDEO_OUTPUT: u32 = 0x2;
const CAP_VIDEO_OVERLAY: u32 = 0x4;
const CAP_VIDEO_CAPTURE_MPLANE: u32 = 0x1000;
const CAP_VIDEO_OUTPUT_MPLANE: u32 = 0x2000;
const CAP_TUNER: u32 = 0x10000;
const CAP_AUDIO: u32 = 0x20000;
const CAP_RADIO: u32 = 0x40000;
const CAP_DEVICE_CAPS: u32 = 0x8000_0000;

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
    let mut cap = [0u8; 0x68];
    if sys::ioctl_ptr(fd.raw(), VIDIOC_QUERYCAP, &mut cap).is_ok() {
        out!("ID_V4L_VERSION=2\n");
        let card = shared::bytes::c_str_prefix(&cap[0x10..0x30]);
        if shared::utf8::is_valid(card) && !card.iter().any(|&c| c < b' ' || c == 127) {
            out!("ID_V4L_PRODUCT=", card, "\n");
        }
        out!("ID_V4L_CAPABILITIES=:");
        let rd = |o: usize| u32::from_ne_bytes(cap[o..o + 4].try_into().expect("4 bytes"));
        let (caps, dcaps) = (rd(0x54), rd(0x58));
        let c = if caps & CAP_DEVICE_CAPS != 0 { dcaps } else { caps };
        if c & (CAP_VIDEO_CAPTURE | CAP_VIDEO_CAPTURE_MPLANE) != 0 {
            out!("capture:");
        }
        if c & (CAP_VIDEO_OUTPUT | CAP_VIDEO_OUTPUT_MPLANE) != 0 {
            out!("video_output:");
        }
        if c & CAP_VIDEO_OVERLAY != 0 {
            out!("video_overlay:");
        }
        if c & CAP_AUDIO != 0 {
            out!("audio:");
        }
        if c & CAP_TUNER != 0 {
            out!("tuner:");
        }
        if c & CAP_RADIO != 0 {
            out!("radio:");
        }
        out!("\n");
    }
    0
}

fn main() {
    shared::main_func::main_with(run)
}
