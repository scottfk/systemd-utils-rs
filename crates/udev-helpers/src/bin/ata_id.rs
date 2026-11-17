// SPDX-License-Identifier: GPL-2.0-or-later
//! `ata_id`: read product and serial number from ATA drives.  A port of
//! systemd's `src/udev/ata_id/ata_id.c` (v262).

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_WARNING};
use shared::options::{Command, Opt, OptionParser, common};
use shared::{log_debug_errno, log_error_errno, log_full_errno, sys};
use udev_helpers::{OPT_HELP, OPT_INTROSPECT_CLI, OPT_VERSION, common_option, out};
use udevadm::udev::util::{encode_devnode_name, udev_replace_chars, udev_replace_whitespace};

const OPT_EXPORT: i32 = 0x110;

const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::new(OPT_EXPORT, b'x', Some("export"), None, Some("Print values as environment keys")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["ata_id"],
    abstract_: "Identify ATA storage devices.",
    argspec: &["DEVICE"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const TIMEOUT_MS: u32 = 30 * 1000;
const SG_DXFER_FROM_DEV: i32 = -3;
const HDIO_GET_IDENTITY: u64 = 0x030d;

/// The SG_IO v4 request, falling back to v3 on EINVAL: Ok(Some(sense
/// check passed)) for v4, Ok(None) for a v3 request that went through.
enum Sg {
    V4,
    V3(sys::SgStatus),
}

fn sg_io(fd: i32, cdb: &[u8], sense: &mut [u8; 32], buf: &mut [u8]) -> Result<(Sg, sys::SgStatus), i32> {
    match sys::sg_io_v4(fd, cdb, sense, buf, TIMEOUT_MS) {
        Ok(st) => Ok((Sg::V4, st)),
        Err(e) if e != -libc::EINVAL => Err(log_debug_errno!(e, "ioctl v4 failed: ", strerror(e))),
        Err(_) => match sys::sg_io_v3(fd, cdb, sense, buf, SG_DXFER_FROM_DEV, TIMEOUT_MS) {
            Ok(st) => Ok((Sg::V3(st), st)),
            Err(e) => Err(log_debug_errno!(e, "ioctl v3 failed: ", strerror(e))),
        },
    }
}

/// `disk_scsi_inquiry_command()`.
fn disk_scsi_inquiry_command(fd: i32, buf: &mut [u8]) -> Result<(), i32> {
    let cdb = [0x12, 0, 0, (buf.len() >> 8) as u8, (buf.len() & 0xff) as u8, 0];
    let mut sense = [0u8; 32];
    match sg_io(fd, &cdb, &mut sense, buf)? {
        (Sg::V3(st), _) => {
            if st.a != 0 || st.b != 0 || st.c != 0 {
                return Err(log_debug_errno!(synthetic(libc::EIO), "ioctl v3 failed."));
            }
        }
        (Sg::V4, st) => {
            if st.a != 0 || st.b != 0 || st.c != 0 {
                return Err(log_debug_errno!(synthetic(libc::EIO), "ioctl v4 failed."));
            }
        }
    }
    Ok(())
}

/// `disk_identify_command()`.
fn disk_identify_command(fd: i32, buf: &mut [u8]) -> Result<(), i32> {
    let cdb = [0xa1, 4 << 1, 0x2e, 0, 1, 0, 0, 0, 0, 0xEC, 0, 0];
    let mut sense = [0u8; 32];
    if let (Sg::V4, _) = sg_io(fd, &cdb, &mut sense, buf)? {
        let desc = &sense[8..];
        if !((sense[0] & 0x7f) == 0x72 && desc[0] == 0x9 && desc[1] == 0x0c)
            && !((sense[0] & 0x7f) == 0x70 && sense[12] == 0x00 && sense[13] == 0x1d)
        {
            return Err(log_debug_errno!(synthetic(libc::EIO), "ioctl v4 failed."));
        }
    }
    Ok(())
}

/// `disk_identify_packet_device_command()`.
fn disk_identify_packet_device_command(fd: i32, buf: &mut [u8]) -> Result<(), i32> {
    let cdb = [0x85, 4 << 1, 0x2e, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xA1, 0];
    let mut sense = [0u8; 32];
    if let (Sg::V4, _) = sg_io(fd, &cdb, &mut sense, buf)? {
        let desc = &sense[8..];
        if (sense[0] & 0x7f) != 0x72 || desc[0] != 0x9 || desc[1] != 0x0c {
            return Err(log_debug_errno!(synthetic(libc::EIO), "ioctl v4 failed."));
        }
    }
    Ok(())
}

/// `disk_identify()`: the peripheral device type.
fn disk_identify(fd: i32, identify: &mut [u8; 512]) -> Result<i32, i32> {
    identify.fill(0);
    let mut inquiry = [0u8; 36];
    disk_scsi_inquiry_command(fd, &mut inquiry)?;
    let pdt = (inquiry[0] & 0x1f) as i32;
    if pdt == 0x05 {
        disk_identify_packet_device_command(fd, identify)?;
    } else {
        if pdt != 0x00 && pdt != 0x14 {
            return Err(log_debug_errno!(synthetic(libc::EIO), "Unsupported device type."));
        }
        disk_identify_command(fd, identify)?;
    }
    if identify.iter().all(|&b| b == 0) {
        return Err(log_debug_errno!(synthetic(libc::EIO), "IDENTIFY data is all zeroes."));
    }
    Ok(pdt)
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let _ = udevadm::udev::util::udev_parse_config();
    shared::log::log_setup();
    let mut export = false;
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(OPT_EXPORT)) => export = true,
            Ok(Some(c)) => {
                if let Some(r) = common_option(c, &COMMAND, OPTIONS) {
                    return r.min(0);
                }
            }
        }
    }
    let args = opts.args().to_vec();
    if args.len() != 1 {
        return log_error_errno!(synthetic(libc::EINVAL), "Need exactly one DEVICE argument.");
    }
    let device = &args[0];
    let fd = match sys::open(device, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
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
    let mut identify = [0u8; 512];
    let mut pdt = -1;
    // `id` is the struct hd_driveid view, in native byte order.
    let mut id = [0u8; 512];
    match disk_identify(fd.raw(), &mut identify) {
        Ok(p) => {
            pdt = p;
            // disk_identify_fixup_string(): swap the bytes of each word.
            for (off, len) in [(10usize, 20usize), (23, 8), (27, 40)] {
                for w in 0..len / 2 {
                    identify.swap((off + w) * 2, (off + w) * 2 + 1);
                }
            }
            // disk_identify_fixup_uint16(): little-endian to native.
            for w in [0usize, 75, 76, 82, 83, 84, 85, 86, 87, 89, 90, 91, 94, 108, 109, 110, 111, 128, 217] {
                let v = u16::from_le_bytes([identify[w * 2], identify[w * 2 + 1]]);
                identify[w * 2..w * 2 + 2].copy_from_slice(&v.to_ne_bytes());
            }
            id = identify;
        }
        Err(_) => {
            if let Err(r) = sys::ioctl_ptr(fd.raw(), HDIO_GET_IDENTITY, &mut id) {
                return log_debug_errno!(r, &device[..], ": HDIO_GET_IDENTITY failed: ", strerror(r));
            }
        }
    }
    let w = |b: &[u8; 512], o: usize| u16::from_ne_bytes([b[o], b[o + 1]]) as u32;
    let wyde = |n: usize| w(&identify, n * 2);
    let model_raw = &id[54..94];
    let model_c = &model_raw[..model_raw.iter().position(|&c| c == 0).unwrap_or(40)];
    let model_enc = encode_devnode_name(model_c, 256);
    let mut model = udev_replace_whitespace(model_raw, 40);
    udev_replace_chars(&mut model, None);
    let mut serial = udev_replace_whitespace(&id[20..40], 20);
    udev_replace_chars(&mut serial, None);
    let mut revision = udev_replace_whitespace(&id[46..54], 8);
    udev_replace_chars(&mut revision, None);
    if !export {
        if serial.is_empty() {
            out!(&model[..], "\n");
        } else {
            out!(&model[..], "_", &serial[..], "\n");
        }
        return 0;
    }
    let config = w(&id, 0);
    let cs1 = w(&id, 164);
    let cs2 = w(&id, 166);
    let cfs1 = w(&id, 170);
    let cfs2 = w(&id, 172);
    let dlf = w(&id, 256);
    let b = |v: u32, bit: u32| if v & (1 << bit) != 0 { 1 } else { 0 };
    out!("ID_ATA=1\n");
    if (config >> 8) & 0x80 != 0 {
        out!(match (config >> 8) & 0x1f {
            0 | 5 => "ID_TYPE=cd\n",
            1 => "ID_TYPE=tape\n",
            7 => "ID_TYPE=optical\n",
            _ => "ID_TYPE=generic\n",
        });
    } else {
        out!("ID_TYPE=disk\n");
    }
    out!("ID_BUS=ata\n", "ID_MODEL=", &model[..], "\n", "ID_MODEL_ENC=", &model_enc[..], "\n");
    out!("ID_REVISION=", &revision[..], "\n");
    if !serial.is_empty() {
        out!("ID_SERIAL=", &model[..], "_", &serial[..], "\n", "ID_SERIAL_SHORT=", &serial[..], "\n");
    } else {
        out!("ID_SERIAL=", &model[..], "\n");
    }
    for (bit, name) in
        [(5, "ATA_WRITE_CACHE"), (6, "ATA_READ_LOOKAHEAD"), (10, "ATA_FEATURE_SET_HPA"), (3, "ATA_FEATURE_SET_PM")]
    {
        if cs1 & (1 << bit) != 0 {
            out!(format!("ID_{name}=1\nID_{name}_ENABLED={}\n", b(cfs1, bit)));
        }
    }
    if cs1 & (1 << 1) != 0 {
        out!("ID_ATA_FEATURE_SET_SECURITY=1\n");
        out!(format!("ID_ATA_FEATURE_SET_SECURITY_ENABLED={}\n", b(cfs1, 1)));
        out!(format!("ID_ATA_FEATURE_SET_SECURITY_ERASE_UNIT_MIN={}\n", w(&id, 178) * 2));
        if cfs1 & (1 << 1) != 0 {
            if dlf & (1 << 8) != 0 {
                out!("ID_ATA_FEATURE_SET_SECURITY_LEVEL=maximum\n");
            } else {
                out!("ID_ATA_FEATURE_SET_SECURITY_LEVEL=high\n");
            }
        }
        if dlf & (1 << 5) != 0 {
            out!(format!("ID_ATA_FEATURE_SET_SECURITY_ENHANCED_ERASE_UNIT_MIN={}\n", w(&id, 180) * 2));
        }
        if dlf & (1 << 4) != 0 {
            out!("ID_ATA_FEATURE_SET_SECURITY_EXPIRE=1\n");
        }
        if dlf & (1 << 3) != 0 {
            out!("ID_ATA_FEATURE_SET_SECURITY_FROZEN=1\n");
        }
        if dlf & (1 << 2) != 0 {
            out!("ID_ATA_FEATURE_SET_SECURITY_LOCKED=1\n");
        }
    }
    if cs1 & 1 != 0 {
        out!(format!("ID_ATA_FEATURE_SET_SMART=1\nID_ATA_FEATURE_SET_SMART_ENABLED={}\n", b(cfs1, 0)));
    }
    if cs2 & (1 << 9) != 0 {
        let acoustic = w(&id, 188);
        out!(format!("ID_ATA_FEATURE_SET_AAM=1\nID_ATA_FEATURE_SET_AAM_ENABLED={}\n", b(cfs2, 9)));
        out!(format!("ID_ATA_FEATURE_SET_AAM_VENDOR_RECOMMENDED_VALUE={}\n", acoustic >> 8));
        out!(format!("ID_ATA_FEATURE_SET_AAM_CURRENT_VALUE={}\n", acoustic & 0xff));
    }
    if cs2 & (1 << 5) != 0 {
        out!(format!("ID_ATA_FEATURE_SET_PUIS=1\nID_ATA_FEATURE_SET_PUIS_ENABLED={}\n", b(cfs2, 5)));
    }
    if cs2 & (1 << 3) != 0 {
        out!(format!("ID_ATA_FEATURE_SET_APM=1\nID_ATA_FEATURE_SET_APM_ENABLED={}\n", b(cfs2, 3)));
        if cfs2 & (1 << 3) != 0 {
            out!(format!("ID_ATA_FEATURE_SET_APM_CURRENT_VALUE={}\n", w(&id, 182) & 0xff));
        }
    }
    if cs2 & 1 != 0 {
        out!("ID_ATA_DOWNLOAD_MICROCODE=1\n");
    }
    let word = wyde(76);
    if word != 0 && word != 0xffff {
        out!("ID_ATA_SATA=1\n");
        if word & (1 << 2) != 0 {
            out!("ID_ATA_SATA_SIGNAL_RATE_GEN2=1\n");
        }
        if word & (1 << 1) != 0 {
            out!("ID_ATA_SATA_SIGNAL_RATE_GEN1=1\n");
        }
    }
    let word = wyde(217);
    if word == 1 {
        out!("ID_ATA_ROTATION_RATE_RPM=0\n");
    } else if (0x0401..=0xfffe).contains(&word) {
        out!(format!("ID_ATA_ROTATION_RATE_RPM={word}\n"));
    }
    if wyde(108) & 0xf000 == 0x5000 {
        let wwn = (wyde(108) as u64) << 48 | (wyde(109) as u64) << 32 | (wyde(110) as u64) << 16 | wyde(111) as u64;
        out!(format!("ID_WWN=0x{wwn:x}\nID_WWN_WITH_EXTENSION=0x{wwn:x}\n"));
    }
    if wyde(0) == 0x848a || wyde(0) == 0x844a || wyde(83) & 0xc004 == 0x4004 {
        out!("ID_ATA_CFA=1\n");
    }
    if pdt >= 0 {
        out!(format!("ID_ATA_PERIPHERAL_DEVICE_TYPE={pdt}\n"));
    }
    0
}

fn main() {
    shared::main_func::main_with(run)
}
