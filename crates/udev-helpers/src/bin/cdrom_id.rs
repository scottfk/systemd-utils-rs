// SPDX-License-Identifier: GPL-2.0-or-later
//! `cdrom_id`: optical drive and media information prober.  A port of
//! systemd's `src/udev/cdrom_id/cdrom_id.c` (v262).

use shared::errno::{strerror, synthetic};
use shared::options::{Command, Opt, OptionParser, common};
use shared::{log_debug, log_debug_errno, log_error_errno, log_warning_errno, sys};
use udev_helpers::{OPT_HELP, OPT_INTROSPECT_CLI, OPT_VERSION, common_option, out};

const OPT_LOCK: i32 = 0x110;
const OPT_UNLOCK: i32 = 0x111;
const OPT_EJECT: i32 = 0x112;
const OPT_DEBUG: i32 = 0x113;

const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::new(OPT_LOCK, b'l', Some("lock-media"), None, Some("Lock the media (to enable eject request events)")),
    Opt::new(OPT_UNLOCK, b'u', Some("unlock-media"), None, Some("Unlock the media")),
    Opt::new(OPT_EJECT, b'e', Some("eject-media"), None, Some("Eject the media")),
    Opt::new(OPT_DEBUG, b'd', Some("debug"), None, Some("Print debug messages to stderr")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["cdrom_id"],
    abstract_: "Identify CD/DVD drives and their media.",
    argspec: &["DEVICE"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

// Feature (profile) numbers.
const FEATURE_MO_SE: i32 = 0x03;
const FEATURE_MO_WO: i32 = 0x04;
const FEATURE_MO_AS: i32 = 0x05;
const FEATURE_CD_ROM: i32 = 0x08;
const FEATURE_CD_R: i32 = 0x09;
const FEATURE_CD_RW: i32 = 0x0a;
const FEATURE_DVD_ROM: i32 = 0x10;
const FEATURE_DVD_R: i32 = 0x11;
const FEATURE_DVD_RAM: i32 = 0x12;
const FEATURE_DVD_RW_RO: i32 = 0x13;
const FEATURE_DVD_RW_SEQ: i32 = 0x14;
const FEATURE_DVD_R_DL_SEQ: i32 = 0x15;
const FEATURE_DVD_R_DL_JR: i32 = 0x16;
const FEATURE_DVD_R_DDR: i32 = 0x18;
const FEATURE_DVD_PLUS_RW: i32 = 0x1a;
const FEATURE_DVD_PLUS_RW_DL: i32 = 0x2a;
const FEATURE_BD_R_SRM: i32 = 0x41;
const FEATURE_BD_R_RRM: i32 = 0x42;
const FEATURE_MRW: i32 = 0x5b;
const FEATURE_MRW_W: i32 = 0x5c;
const FEATURE_INVALID: i32 = -libc::EINVAL;

/// `feature_to_string[]`, sorted by feature.
const FEATURE_TO_STRING: &[(i32, &str)] = &[
    (0x01, "RW_NONREMOVABLE"),
    (0x02, "RW_REMOVABLE"),
    (0x03, "MO_SE"),
    (0x04, "MO_WO"),
    (0x05, "MO_AS"),
    (0x08, "CD"),
    (0x09, "CD_R"),
    (0x0a, "CD_RW"),
    (0x10, "DVD"),
    (0x11, "DVD_R"),
    (0x12, "DVD_RAM"),
    (0x13, "DVD_RW_RO"),
    (0x14, "DVD_RW_SEQ"),
    (0x15, "DVD_R_DL_SEQ"),
    (0x16, "DVD_R_DL_JR"),
    (0x17, "DVD_RW_DL"),
    (0x18, "DVD_R_DDR"),
    (0x1a, "DVD_PLUS_RW"),
    (0x1b, "DVD_PLUS_R"),
    (0x20, "DDCD"),
    (0x21, "DDCD_R"),
    (0x22, "DDCD_RW"),
    (0x2a, "DVD_PLUS_RW_DL"),
    (0x2b, "DVD_PLUS_R_DL"),
    (0x40, "BD"),
    (0x41, "BD_R_SRM"),
    (0x42, "BD_R_RRM"),
    (0x43, "BD_RE"),
    (0x50, "HDDVD"),
    (0x51, "HDDVD_R"),
    (0x52, "HDDVD_RAM"),
    (0x53, "HDDVD_RW"),
    (0x58, "HDDVD_R_DL"),
    (0x5a, "HDDVD_RW_DL"),
    (FEATURE_MRW, "MRW"),
    (FEATURE_MRW_W, "MRW_W"),
];

const MEDIA_STATE_BLANK: i32 = 0;
const MEDIA_STATE_APPENDABLE: i32 = 1;
const MEDIA_STATE_COMPLETE: i32 = 2;
const MEDIA_STATE_OTHER: i32 = 3;
const MEDIA_STATE_TABLE: [&str; 4] = ["blank", "appendable", "complete", "other"];

const CDROM_CLEAR_OPTIONS: u64 = 0x5321;
const CDO_LOCK: libc::c_ulong = 0x8;
const CDROM_LOCKDOOR: u64 = 0x5329;
const CDROM_GET_CAPABILITY: u64 = 0x5331;
const CDROM_DRIVE_STATUS: u64 = 0x5326;
const CDSL_CURRENT: libc::c_ulong = i32::MAX as libc::c_ulong;
const CDS_NO_INFO: i32 = 0;
const CDS_NO_DISC: i32 = 1;
const CDS_TRAY_OPEN: i32 = 2;
const CDS_DRIVE_NOT_READY: i32 = 3;
const CDS_DISC_OK: i32 = 4;

const GPCMD_START_STOP_UNIT: u8 = 0x1b;
const GPCMD_INQUIRY: u8 = 0x12;
const GPCMD_READ_DISC_INFO: u8 = 0x51;
const GPCMD_GET_CONFIGURATION: u8 = 0x46;
const GPCMD_READ_DVD_STRUCTURE: u8 = 0xad;
const GPCMD_READ_FORMAT_CAPACITIES: u8 = 0x23;
const GPCMD_READ_10: u8 = 0x28;
const GPCMD_READ_TOC_PMA_ATIP: u8 = 0x43;

const SG_DXFER_NONE: i32 = -1;
const SG_DXFER_FROM_DEV: i32 = -3;
const SG_FLAG_DIRECT_IO: u32 = 1;
const SG_FLAG_LUN_INHIBIT: u32 = 2;

/// `Context`.
struct Context {
    fd: Option<sys::OwnedFd>,
    drive_features: Vec<i32>,
    media_feature: i32,
    has_media: bool,
    media_state: Option<i32>,
    media_session_next: u32,
    media_session_count: u32,
    media_track_count: u32,
    media_track_count_data: u32,
    media_track_count_audio: u32,
    media_session_last_offset: u64,
}

impl Context {
    fn fd(&self) -> i32 {
        self.fd.as_ref().expect("open").raw()
    }

    fn drive_has_feature(&self, f: i32) -> bool {
        self.drive_features.contains(&f)
    }

    fn set_drive_feature(&mut self, f: i32) {
        if !self.drive_has_feature(f) {
            self.drive_features.push(f);
        }
    }
}

fn sk(e: i32) -> u32 {
    (e as u32 >> 16) & 0xf
}

fn asc(e: i32) -> u32 {
    (e as u32 >> 8) & 0xff
}

fn ascq(e: i32) -> u32 {
    e as u32 & 0xff
}

/// `log_scsi_debug_errno()`.
fn log_scsi_debug_errno(error: i32, msg: &str) -> i32 {
    if error < 0 {
        return log_debug_errno!(error, "Failed to ", msg, ": ", strerror(error));
    }
    log_debug_errno!(
        synthetic(libc::EIO),
        format!("Failed to {msg} with SK={:X}/ASC={:02X}/ACQ={:02X}", sk(error), asc(error), ascq(error))
    )
}

/// `struct scsi_cmd`: the CDB (CDROM_PACKET_SIZE bytes) and its length.
struct ScsiCmd {
    cmd: [u8; 12],
    len: usize,
}

impl ScsiCmd {
    /// `scsi_cmd_init()`.
    fn new() -> ScsiCmd {
        ScsiCmd { cmd: [0; 12], len: 0 }
    }

    /// `scsi_cmd_set()`.
    fn set(&mut self, i: usize, arg: u8) -> &mut ScsiCmd {
        self.len = i + 1;
        self.cmd[i] = arg;
        self
    }

    /// `scsi_cmd_run()`: 0, a negative errno, or a positive SCSI error.
    fn run(&self, fd: i32, buf: &mut [u8]) -> i32 {
        let mut sense = [0u8; 18];
        let dir = if buf.is_empty() { SG_DXFER_NONE } else { SG_DXFER_FROM_DEV };
        let st = match sys::sg_io_v3_full(
            fd,
            &self.cmd[..self.len],
            &mut sense,
            buf,
            dir,
            SG_FLAG_LUN_INHIBIT | SG_FLAG_DIRECT_IO,
            0,
        ) {
            Ok(st) => st,
            Err(e) => return e,
        };
        if st.info & 1 != 0 {
            if st.masked_status & 1 != 0 {
                let r = ((sense[2] as i32 & 0x0f) << 16) | (sense[12] as i32) << 8 | sense[13] as i32;
                if r != 0 {
                    return r;
                }
            }
            return -libc::EIO;
        }
        0
    }

    /// `scsi_cmd_run_and_log()`.
    fn run_and_log(&self, fd: i32, buf: &mut [u8], msg: &str) -> i32 {
        let r = self.run(fd, buf);
        if r != 0 {
            return log_scsi_debug_errno(r, msg);
        }
        0
    }
}

/// `media_lock()`.
fn media_lock(fd: i32, lock: bool) -> i32 {
    if let Err(e) = sys::ioctl_int(fd, CDROM_CLEAR_OPTIONS, CDO_LOCK) {
        log_debug_errno!(e, "Failed to issue ioctl(CDROM_CLEAR_OPTIONS, CDO_LOCK), ignoring: ", strerror(e));
    }
    if let Err(e) = sys::ioctl_int(fd, CDROM_LOCKDOOR, lock as libc::c_ulong) {
        return log_debug_errno!(e, "Failed to issue ioctl(CDROM_LOCKDOOR): ", strerror(e));
    }
    0
}

/// `media_eject()`.
fn media_eject(fd: i32) -> i32 {
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_START_STOP_UNIT).set(4, 0x02).set(5, 0);
    sc.run_and_log(fd, &mut [], "start/stop unit")
}

/// `cd_capability_compat()`.
fn cd_capability_compat(c: &mut Context) -> i32 {
    let cap = match sys::ioctl_int(c.fd(), CDROM_GET_CAPABILITY, 0) {
        Ok(v) => v,
        Err(e) => return log_debug_errno!(e, "CDROM_GET_CAPABILITY failed"),
    };
    for (bit, f) in [
        (0x2000, FEATURE_CD_R),
        (0x4000, FEATURE_CD_RW),
        (0x8000, FEATURE_DVD_ROM),
        (0x10000, FEATURE_DVD_R),
        (0x20000, FEATURE_DVD_RAM),
        (0x80000, FEATURE_MRW),
        (0x100000, FEATURE_MRW_W),
    ] {
        if cap & bit != 0 {
            c.set_drive_feature(f);
        }
    }
    0
}

/// `cd_media_compat()`.
fn cd_media_compat(c: &mut Context) -> i32 {
    let r = match sys::ioctl_int(c.fd(), CDROM_DRIVE_STATUS, CDSL_CURRENT) {
        Ok(v) => v,
        Err(e) => return log_debug_errno!(e, "ioctl(CDROM_DRIVE_STATUS) failed: ", strerror(e)),
    };
    if r != CDS_DISC_OK {
        let what = match r {
            CDS_NO_INFO => "no info",
            CDS_NO_DISC => "no disc",
            CDS_TRAY_OPEN => "tray open",
            CDS_DRIVE_NOT_READY => "drive not ready",
            _ => "unknown status",
        };
        return log_debug_errno!(
            synthetic(libc::ENOMEDIUM),
            format!("ioctl(CDROM_DRIVE_STATUS) \u{2192} {r} ({what}), ignoring.")
        );
    }
    c.has_media = true;
    0
}

/// `%.Ns`.
fn cstr_n(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `cd_inquiry()`.
fn cd_inquiry(c: &mut Context) -> i32 {
    let mut inq = [0u8; 36];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_INQUIRY).set(4, inq.len() as u8).set(5, 0);
    let r = sc.run_and_log(c.fd(), &mut inq, "inquire");
    if r < 0 {
        return r;
    }
    if inq[0] & 0x1f != 5 {
        return log_debug_errno!(synthetic(libc::EINVAL), "Not an MMC unit.");
    }
    log_debug!("INQUIRY: [", cstr_n(&inq[8..16]), "][", cstr_n(&inq[16..32]), "][", cstr_n(&inq[32..36]), "]");
    0
}

fn be16(b: &[u8]) -> u32 {
    u16::from_be_bytes([b[0], b[1]]) as u32
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// `feature_profiles()`.
fn feature_profiles(c: &mut Context, profiles: &[u8]) {
    let mut i = 0;
    while i + 4 <= profiles.len() {
        c.set_drive_feature(be16(&profiles[i..]) as i32);
        i += 4;
    }
}

/// `cd_profiles_old_mmc()`.
fn cd_profiles_old_mmc(c: &mut Context) -> i32 {
    // disc_information: 36 bytes, starting with the be16 length; byte 2
    // holds disc_status (bits 0-1) and erasable (bit 4).
    let mut discinfo = [0u8; 36];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_DISC_INFO).set(8, 2).set(9, 0);
    let mut r = sc.run_and_log(c.fd(), &mut discinfo[..2], "read disc information");
    if r >= 0 {
        let len = (be16(&discinfo) as usize + 2).min(discinfo.len());
        let mut sc = ScsiCmd::new();
        sc.set(0, GPCMD_READ_DISC_INFO).set(8, len as u8).set(9, 0);
        r = sc.run_and_log(c.fd(), &mut discinfo[..len], "read disc information");
    }
    if r < 0 {
        if c.has_media {
            log_debug!("No current profile, but disc is present; assuming CD-ROM.");
            c.media_feature = FEATURE_CD_ROM;
            c.media_track_count = 1;
            c.media_track_count_data = 1;
            return 1;
        }
        return log_debug_errno!(synthetic(libc::ENOMEDIUM), "no current profile, assuming no media.");
    }
    c.has_media = true;
    c.media_feature = if discinfo[2] & 0x10 != 0 {
        FEATURE_CD_RW
    } else if (discinfo[2] & 3) < 2 && c.drive_has_feature(FEATURE_CD_R) {
        FEATURE_CD_R
    } else {
        FEATURE_CD_ROM
    };
    0
}

/// `cd_profiles()`.
fn cd_profiles(c: &mut Context) -> i32 {
    const SIZE: usize = 65530;
    let mut features = vec![0u8; SIZE];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_GET_CONFIGURATION).set(8, 8).set(9, 0);
    let r = sc.run(c.fd(), &mut features[..8]);
    if r != 0 {
        if r > 0 && sk(r) == 0x5 && (asc(r) == 0x20 || asc(r) == 0x24) {
            log_debug!(
                "Drive is pre-MMC2 and does not support 46h get configuration command; trying to work around the problem."
            );
            return cd_profiles_old_mmc(c);
        }
        return log_scsi_debug_errno(r, "get configuration");
    }
    let cur_profile = be16(&features[6..]);
    if cur_profile > 0 {
        log_debug!(format!("current profile 0x{cur_profile:02x}"));
        c.media_feature = cur_profile as i32;
        c.has_media = true;
    } else {
        log_debug!("no current profile, assuming no media");
        c.has_media = false;
    }
    let mut len = be32(&features) as usize;
    log_debug!(format!("GET CONFIGURATION: size of features buffer {len}"));
    if len > SIZE {
        log_debug!("Cannot get features in a single query, truncating.");
        len = SIZE;
    } else if len <= 8 {
        len = SIZE;
    }
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_GET_CONFIGURATION).set(7, (len >> 8) as u8).set(8, len as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut features[..len], "get configuration");
    if r < 0 {
        return r;
    }
    let mut len = be32(&features) as usize;
    log_debug!(format!("GET CONFIGURATION: size of features buffer {len}"));
    if len > SIZE {
        log_debug!("Cannot get features in a single query, truncating.");
        len = SIZE;
    }
    let mut i = 8;
    while i + 4 < len {
        let feature = be16(&features[i..]);
        let n = features[i + 3] as usize;
        if feature == 0 {
            log_debug!(format!("GET CONFIGURATION: feature 'profiles', with {} entries", n / 4));
            let end = i + 4 + n.min(len - i - 4);
            let profiles = features[i + 4..end].to_vec();
            feature_profiles(c, &profiles);
        } else {
            log_debug!(format!("GET CONFIGURATION: feature 0x{feature:04x} <ignored>, with 0x{n:02x} bytes"));
        }
        i += 4 + n;
    }
    c.has_media as i32
}

/// `dvd_ram_media_update_state()`: 1 if the media state is determined.
fn dvd_ram_media_update_state(c: &mut Context) -> i32 {
    if c.media_feature != FEATURE_DVD_RAM {
        return 0;
    }
    let mut dvdstruct = [0u8; 8];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_DVD_STRUCTURE).set(7, 0xC0).set(9, dvdstruct.len() as u8).set(11, 0);
    let r = sc.run_and_log(c.fd(), &mut dvdstruct, "read DVD structure");
    if r < 0 {
        return r;
    }
    if dvdstruct[4] & 0x02 != 0 {
        c.media_state = Some(MEDIA_STATE_COMPLETE);
        log_debug!("Write-protected DVD-RAM media inserted");
        return 1;
    }
    let mut format = [0u8; 12];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_FORMAT_CAPACITIES).set(8, format.len() as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut format, "read DVD format capacities");
    if r < 0 {
        return r;
    }
    let len = format[3];
    if len & 7 != 0 || len < 16 {
        return log_debug_errno!(synthetic(libc::EINVAL), "Invalid format capacities length.");
    }
    match format[8] & 3 {
        1 => {
            log_debug!("Unformatted DVD-RAM media inserted.");
            1
        }
        2 => {
            log_debug!("Formatted DVD-RAM media inserted.");
            0
        }
        3 => {
            c.has_media = false;
            log_debug_errno!(synthetic(libc::ENOMEDIUM), "Format capacities returned no media.")
        }
        _ => 0,
    }
}

/// `dvd_media_update_state()`.
fn dvd_media_update_state(c: &mut Context) -> i32 {
    let r = dvd_ram_media_update_state(c);
    if r != 0 {
        return r;
    }
    let mut buffer = vec![0u8; 32 * 2048];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_10).set(5, 0).set(8, 32).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut buffer, "read first 32 blocks");
    if r < 0 {
        c.has_media = false;
        return r;
    }
    if buffer[32768..32768 + 2048].iter().any(|&b| b != 0) {
        log_debug!("Data in block 16, assuming complete.");
        return 0;
    }
    if buffer[..2048].iter().any(|&b| b != 0) {
        log_debug!("Data in block 0, assuming complete.");
        return 0;
    }
    log_debug!("No data in blocks 0 or 16, assuming blank.");
    c.media_state = Some(MEDIA_STATE_BLANK);
    0
}

/// `cd_media_info()`.
fn cd_media_info(c: &mut Context) -> i32 {
    let mut header = [0u8; 32];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_DISC_INFO).set(8, header.len() as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut header, "read disc information");
    if r < 0 {
        return r;
    }
    c.has_media = true;
    log_debug!(format!("disk type {:02x}", header[8]));
    let state = (header[2] & 0x03) as i32;
    log_debug!("hardware reported media status: ", MEDIA_STATE_TABLE[state as usize]);
    if c.media_feature != FEATURE_CD_ROM {
        c.media_state = Some(state);
    }
    if c.media_feature == FEATURE_DVD_RW_RO && state == MEDIA_STATE_APPENDABLE {
        c.media_state = Some(MEDIA_STATE_BLANK);
    }
    if [FEATURE_DVD_RW_RO, FEATURE_DVD_PLUS_RW, FEATURE_DVD_PLUS_RW_DL, FEATURE_DVD_RAM].contains(&c.media_feature)
        && (state == MEDIA_STATE_COMPLETE || state == MEDIA_STATE_OTHER)
    {
        let r = dvd_media_update_state(c);
        if r < 0 {
            return r;
        }
    }
    if c.media_feature != FEATURE_DVD_RW_RO && (state == MEDIA_STATE_BLANK || state == MEDIA_STATE_APPENDABLE) {
        c.media_session_next = (header[10] as u32) << 8 | header[5] as u32;
    }
    c.media_session_count = (header[9] as u32) << 8 | header[4] as u32;
    c.media_track_count = (header[11] as u32) << 8 | header[6] as u32;
    0
}

/// `cd_media_toc()`.
fn cd_media_toc(c: &mut Context) -> i32 {
    let mut header = [0u8; 12];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_TOC_PMA_ATIP).set(6, 1).set(8, header.len() as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut header, "read TOC");
    if r < 0 {
        return r;
    }
    let len = be16(&header) as usize + 2;
    log_debug!(format!("READ TOC: len: {len}, start track: {}, end track: {}", header[2], header[3]));
    const TOC: usize = 65536;
    if len > TOC {
        return -1;
    }
    if len < 8 {
        return 0;
    }
    // unsigned arithmetic, as in C.
    let mut num_tracks = (header[3] as u32).wrapping_sub(header[2] as u32).wrapping_add(1);
    let mut toc = vec![0u8; TOC];
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_TOC_PMA_ATIP).set(6, header[2]).set(7, (len >> 8) as u8).set(8, len as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut toc[..len], "read TOC (tracks)");
    if r < 0 {
        return r;
    }
    let mut i = 4;
    while i + 8 <= len && num_tracks > 0 {
        let is_data = toc[i + 1] & 0x04 != 0;
        let block = be32(&toc[i + 4..]);
        log_debug!(format!(
            "track={} info=0x{:x}({}) start_block={block}",
            toc[i + 2],
            toc[i + 1] & 0x0f,
            if is_data { "data" } else { "audio" }
        ));
        if is_data {
            c.media_track_count_data += 1;
        } else {
            c.media_track_count_audio += 1;
        }
        i += 8;
        num_tracks -= 1;
    }
    let mut sc = ScsiCmd::new();
    sc.set(0, GPCMD_READ_TOC_PMA_ATIP).set(2, 1).set(8, header.len() as u8).set(9, 0);
    let r = sc.run_and_log(c.fd(), &mut header, "read TOC (multi session)");
    if r < 0 {
        return r;
    }
    let len = be32(&header[8..]);
    log_debug!(format!("last track {} starts at block {len}", header[6]));
    c.media_session_last_offset = len as u64 * 2048;
    0
}

/// `open_drive()`.
fn open_drive(c: &mut Context, node: &[u8]) -> i32 {
    // QUIRK: as upstream, cnt is incremented twice per failed attempt, so an
    // EBUSY device is tried 11 times rather than 20.
    let mut cnt = 0;
    let fd = loop {
        match sys::open(node, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
            Ok(fd) => break fd,
            Err(e) => {
                cnt += 1;
                if cnt >= 20 || e != -libc::EBUSY {
                    return log_debug_errno!(e, "Unable to open '", node, "': ", strerror(e));
                }
            }
        }
        let mut r = [0u8; 8];
        let _ = sys::getrandom(&mut r);
        let extra = u64::from_ne_bytes(r) % 100_000;
        std::thread::sleep(std::time::Duration::from_micros(100_000 + extra));
        cnt += 1;
    };
    log_debug!("probing: '", node, "'");
    c.fd = Some(sys::OwnedFd::new(fd));
    0
}

/// `print_feature()`.
fn print_feature(feature: i32, prefix: &str) {
    match FEATURE_TO_STRING.binary_search_by_key(&feature, |&(f, _)| f) {
        Ok(i) => out!(prefix, "_", FEATURE_TO_STRING[i].1, "=1\n"),
        Err(_) => {
            log_debug!(format!("Unknown feature 0x{:02x}, ignoring.", feature as u32));
        }
    }
}

/// `print_properties()`.
fn print_properties(c: &Context) {
    out!("ID_CDROM=1\n");
    for &f in &c.drive_features {
        print_feature(f, "ID_CDROM");
    }
    let any = |fs: &[i32]| fs.iter().any(|&f| c.drive_has_feature(f));
    if any(&[FEATURE_MO_SE, FEATURE_MO_WO, FEATURE_MO_AS]) {
        out!("ID_CDROM_MO=1\n");
    }
    if any(&[FEATURE_DVD_RW_RO, FEATURE_DVD_RW_SEQ]) {
        out!("ID_CDROM_DVD_RW=1\n");
    }
    if any(&[FEATURE_DVD_R_DL_SEQ, FEATURE_DVD_R_DL_JR]) {
        out!("ID_CDROM_DVD_R_DL=1\n");
    }
    if any(&[FEATURE_DVD_R_DDR]) {
        out!("ID_CDROM_DVD_R=1\n");
    }
    if any(&[FEATURE_BD_R_SRM, FEATURE_BD_R_RRM]) {
        out!("ID_CDROM_BD_R=1\n");
    }
    if c.has_media {
        out!("ID_CDROM_MEDIA=1\n");
        print_feature(c.media_feature, "ID_CDROM_MEDIA");
        let m = c.media_feature;
        if [FEATURE_MO_SE, FEATURE_MO_WO, FEATURE_MO_AS].contains(&m) {
            out!("ID_CDROM_MEDIA_MO=1\n");
        }
        if [FEATURE_DVD_RW_RO, FEATURE_DVD_RW_SEQ].contains(&m) {
            out!("ID_CDROM_MEDIA_DVD_RW=1\n");
        }
        if [FEATURE_DVD_R_DL_SEQ, FEATURE_DVD_R_DL_JR].contains(&m) {
            out!("ID_CDROM_MEDIA_DVD_R_DL=1\n");
        }
        if m == FEATURE_DVD_R_DDR {
            out!("ID_CDROM_MEDIA_DVD_R=1\n");
        }
        if [FEATURE_BD_R_SRM, FEATURE_BD_R_RRM].contains(&m) {
            out!("ID_CDROM_MEDIA_BD_R=1\n");
        }
    }
    if let Some(s) = c.media_state {
        out!("ID_CDROM_MEDIA_STATE=", MEDIA_STATE_TABLE[s as usize], "\n");
    }
    if c.media_session_next > 0 {
        out!(format!("ID_CDROM_MEDIA_SESSION_NEXT={}\n", c.media_session_next));
    }
    if c.media_session_count > 0 {
        out!(format!("ID_CDROM_MEDIA_SESSION_COUNT={}\n", c.media_session_count));
    }
    if c.media_session_count > 1 && c.media_session_last_offset > 0 {
        out!(format!("ID_CDROM_MEDIA_SESSION_LAST_OFFSET={}\n", c.media_session_last_offset));
    }
    if c.media_track_count > 0 {
        out!(format!("ID_CDROM_MEDIA_TRACK_COUNT={}\n", c.media_track_count));
    }
    if c.media_track_count_audio > 0 {
        out!(format!("ID_CDROM_MEDIA_TRACK_COUNT_AUDIO={}\n", c.media_track_count_audio));
    }
    if c.media_track_count_data > 0 {
        out!(format!("ID_CDROM_MEDIA_TRACK_COUNT_DATA={}\n", c.media_track_count_data));
    }
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let _ = udevadm::udev::util::udev_parse_config();
    shared::log::log_setup();
    let (mut lock, mut unlock, mut eject) = (false, false, false);
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(OPT_LOCK)) => lock = true,
            Ok(Some(OPT_UNLOCK)) => unlock = true,
            Ok(Some(OPT_EJECT)) => eject = true,
            Ok(Some(OPT_DEBUG)) => {
                shared::log::log_set_target(shared::log::LogTarget::Console);
                shared::log::log_set_max_level(shared::log::LOG_DEBUG);
                shared::log::log_open();
            }
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
    let node = &args[0];
    let mut c = Context {
        fd: None,
        drive_features: Vec::new(),
        media_feature: FEATURE_INVALID,
        has_media: false,
        media_state: None,
        media_session_next: 0,
        media_session_count: 0,
        media_track_count: 0,
        media_track_count_data: 0,
        media_track_count_audio: 0,
        media_session_last_offset: 0,
    };
    let r = open_drive(&mut c, node);
    if shared::sd_device::errno_is_neg_device_absent(r) {
        return 0;
    }
    if r < 0 {
        return log_warning_errno!(r, "Failed to open device node '", &node[..], "': ", strerror(r));
    }
    let r = cd_capability_compat(&mut c);
    if r < 0 {
        return r;
    }
    let _ = cd_media_compat(&mut c);
    if cd_inquiry(&mut c) >= 0 && cd_profiles(&mut c) > 0 {
        let _ = cd_media_toc(&mut c);
        let _ = cd_media_info(&mut c);
    }
    if lock && c.has_media {
        log_debug!("PREVENT_ALLOW_MEDIUM_REMOVAL (lock)");
        let _ = media_lock(c.fd(), true);
    }
    if unlock && c.has_media {
        log_debug!("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
        let _ = media_lock(c.fd(), false);
    }
    if eject {
        log_debug!("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
        let _ = media_lock(c.fd(), false);
        log_debug!("START_STOP_UNIT (eject)");
        let _ = media_eject(c.fd());
    }
    print_properties(&c);
    0
}

fn main() {
    shared::main_func::main_with(run)
}
