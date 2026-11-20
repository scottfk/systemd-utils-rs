// SPDX-License-Identifier: GPL-2.0-or-later
//! `scsi_id`: identify SCSI devices by their INQUIRY data and VPD pages.
//! A port of systemd's `src/udev/scsi_id/scsi_id.c` and `scsi_serial.c`
//! (v262).

use std::cell::RefCell;

use shared::errno::{strerror, synthetic};
use shared::extract::extract_first_word;
use shared::options::{Command, Opt, OptionParser, common, option_get_synopsis};
use shared::{log_debug, log_debug_errno, log_error_errno, sys};
use udev_helpers::{OPT_HELP, OPT_INTROSPECT_CLI, OPT_VERSION, common_option, out};
use udevadm::udev::util::{encode_devnode_name, udev_replace_chars, udev_replace_whitespace};

const OPT_V: i32 = 0x110;
const OPT_DEVICE: i32 = 0x111;
const OPT_CONFIG: i32 = 0x112;
const OPT_PAGE: i32 = 0x113;
const OPT_SG_VERSION: i32 = 0x114;
const OPT_DENYLISTED: i32 = 0x115;
const OPT_BLACKLISTED: i32 = 0x116;
const OPT_ALLOWLISTED: i32 = 0x117;
const OPT_WHITELISTED: i32 = 0x118;
const OPT_REPLACE_WHITESPACE: i32 = 0x119;
const OPT_VERBOSE: i32 = 0x11a;
const OPT_EXPORT: i32 = 0x11b;

const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::new(OPT_V, b'V', None, None, None),
    Opt::new(OPT_DEVICE, b'd', Some("device"), Some("PATH"), Some("Device node for SG_IO commands")),
    Opt::new(OPT_CONFIG, b'f', Some("config"), Some("PATH"), Some("Location of config file")),
    Opt::new(OPT_PAGE, b'p', Some("page"), Some("0x80|0x83|pre-spc3-83"), Some("SCSI page")),
    Opt::new(OPT_SG_VERSION, b's', Some("sg-version"), Some("3|4"), Some("Use SGv3 or SGv4")),
    Opt::new(OPT_DENYLISTED, b'b', Some("denylisted"), None, Some("Treat device as denylisted")),
    Opt::new(OPT_BLACKLISTED, b'b', Some("blacklisted"), None, None),
    Opt::new(OPT_ALLOWLISTED, b'g', Some("allowlisted"), None, Some("Treat device as allowlisted")),
    Opt::new(OPT_WHITELISTED, b'g', Some("whitelisted"), None, None),
    Opt::new(
        OPT_REPLACE_WHITESPACE,
        b'u',
        Some("replace-whitespace"),
        None,
        Some("Replace all whitespace by underscores"),
    ),
    Opt::new(OPT_VERBOSE, b'v', Some("verbose"), None, Some("Verbose logging")),
    Opt::new(OPT_EXPORT, b'x', Some("export"), None, Some("Print values as environment keys")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["scsi_id"],
    abstract_: "Identify SCSI devices.",
    argspec: &["[DEVICE]"],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const MAX_PATH_LEN: usize = 512;
const MAX_SERIAL_LEN: usize = 512;
const MAX_BUFFER_LEN: usize = 256;
const DEF_TIMEOUT: u32 = 5000;
const SENSE_BUFF_LEN: usize = 32;
const SCSI_INQ_BUFF_LEN: usize = 254;
const VENDOR_LENGTH: usize = 8;
const MODEL_LENGTH: usize = 16;
const SG_DXFER_FROM_DEV: i32 = -3;

const PAGE_83_PRE_SPC3: i32 = -0x83;
const PAGE_UNSPECIFIED: i32 = 0;
const PAGE_80: i32 = 0x80;
const PAGE_83: i32 = 0x83;

const SCSI_ID_VENDOR_SPECIFIC: u8 = 0;
const SCSI_ID_T10_VENDOR: u8 = 1;
const SCSI_ID_EUI_64: u8 = 2;
const SCSI_ID_NAA: u8 = 3;
const SCSI_ID_TGTGROUP: u8 = 5;
const NAA_DONT_CARE: u8 = 0xff;
const NAA_IEEE_REG: u8 = 0x05;
const NAA_IEEE_REG_EXTENDED: u8 = 0x06;
const BINARY: u8 = 1;
const ASCII: u8 = 2;

/// `id_search_list`: (id_type, naa_type, code_set).
const ID_SEARCH_LIST: &[(u8, u8, u8)] = &[
    (SCSI_ID_TGTGROUP, NAA_DONT_CARE, BINARY),
    (SCSI_ID_NAA, NAA_IEEE_REG_EXTENDED, BINARY),
    (SCSI_ID_NAA, NAA_IEEE_REG_EXTENDED, ASCII),
    (SCSI_ID_NAA, NAA_IEEE_REG, BINARY),
    (SCSI_ID_NAA, NAA_IEEE_REG, ASCII),
    (SCSI_ID_NAA, NAA_DONT_CARE, BINARY),
    (SCSI_ID_NAA, NAA_DONT_CARE, ASCII),
    (SCSI_ID_EUI_64, NAA_DONT_CARE, BINARY),
    (SCSI_ID_EUI_64, NAA_DONT_CARE, ASCII),
    (SCSI_ID_T10_VENDOR, NAA_DONT_CARE, BINARY),
    (SCSI_ID_T10_VENDOR, NAA_DONT_CARE, ASCII),
    (SCSI_ID_VENDOR_SPECIFIC, NAA_DONT_CARE, BINARY),
    (SCSI_ID_VENDOR_SPECIFIC, NAA_DONT_CARE, ASCII),
];

/// The globals of scsi_id.c.
#[derive(Debug)]
struct Globals {
    all_good: bool,
    dev_specified: bool,
    config_file: Vec<u8>,
    default_page_code: i32,
    sg_version: i32,
    reformat_serial: bool,
    export: bool,
    maj_min_dev: Vec<u8>,
}

thread_local! {
    static G: RefCell<Globals> = RefCell::new(Globals {
        all_good: false,
        dev_specified: false,
        config_file: b"/etc/scsi_id.config".to_vec(),
        default_page_code: PAGE_UNSPECIFIED,
        sg_version: 4,
        reformat_serial: false,
        export: false,
        maj_min_dev: Vec::new(),
    });
}

/// `strscpy(dst, len, src)`.
fn strscpy(src: &[u8], len: usize) -> Vec<u8> {
    src[..src.len().min(len - 1)].to_vec()
}

/// `struct scsi_id_device`.
#[derive(Debug, Default)]
struct ScsiIdDevice {
    vendor: Vec<u8>,
    model: Vec<u8>,
    revision: Vec<u8>,
    kernel: Vec<u8>,
    serial: Vec<u8>,
    serial_short: Vec<u8>,
    ty: u32,
    use_sg: i32,
    unit_serial_number: Vec<u8>,
    wwn: Vec<u8>,
    wwn_vendor_extension: Vec<u8>,
    tgpt_group: Vec<u8>,
}

fn set_type(t: u32) -> &'static str {
    match t {
        0 | 0xe => "disk",
        1 => "tape",
        4 | 7 | 0xf => "optical",
        5 => "cd",
        0x14 => "zbc",
        _ => "generic",
    }
}

/// `extract_many_words(&buf, "=\",\n", 0, &key, &value)`: the words, and
/// how many there were.
fn two_words(p: &mut Option<&[u8]>) -> (Option<Vec<u8>>, Option<Vec<u8>>, i32) {
    let seps: &[u8] = b"=\",\n";
    let k = match extract_first_word(p, Some(seps), 0) {
        Ok(Some(k)) => k,
        Ok(None) => return (None, None, 0),
        Err(r) => return (None, None, r),
    };
    match extract_first_word(p, Some(seps), 0) {
        Ok(Some(v)) => (Some(k), Some(v), 2),
        Ok(None) => (Some(k), None, 1),
        Err(r) => (Some(k), None, r),
    }
}

/// `get_file_options(vendor, model, &argv)`: Ok(None) if nothing matched.
fn get_file_options(vendor: Option<&[u8]>, model: &[u8]) -> Result<Option<Vec<Vec<u8>>>, i32> {
    let config_file = G.with(|g| g.borrow().config_file.clone());
    let mut f = match shared::fileio::fopen_re(&config_file) {
        Ok(f) => f,
        Err(r) if r == -libc::ENOENT => return Ok(None),
        Err(r) => return Err(log_error_errno!(r, "Cannot open ", &config_file[..], ": ", strerror(r))),
    };
    let (mut vendor_in, mut model_in, mut options_in): (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) =
        (None, None, None);
    let mut lineno = 0;
    loop {
        let buffer = match shared::fileio::read_line(&mut f, MAX_BUFFER_LEN) {
            Err(r) => {
                return Err(log_error_errno!(
                    r,
                    format!("read_line() on line {lineno} of "),
                    &config_file[..],
                    " failed: ",
                    strerror(r)
                ));
            }
            Ok((0, _)) => break,
            Ok((_, b)) => b,
        };
        lineno += 1;
        let start = buffer.iter().take_while(|c| c.is_ascii_whitespace() || **c == 0x0b).count();
        let line = &buffer[start..];
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let err = |lineno: i32| {
            log_error_errno!(
                synthetic(libc::EINVAL),
                format!("Error parsing config file line {lineno} '"),
                &buffer[..],
                "'"
            )
        };
        let mut p = Some(line);
        let (mut key, mut value, r) = two_words(&mut p);
        if r < 2 {
            return Err(err(lineno));
        }
        if key.as_ref().is_some_and(|k| k.eq_ignore_ascii_case(b"VENDOR")) {
            vendor_in = value.take();
            let (k2, v2, r) = two_words(&mut p);
            if r < 2 {
                return Err(err(lineno));
            }
            key = k2;
            value = v2;
            if key.as_ref().is_some_and(|k| k.eq_ignore_ascii_case(b"MODEL")) {
                model_in = value.take();
                let (k3, v3, r) = two_words(&mut p);
                if r < 2 {
                    return Err(err(lineno));
                }
                key = k3;
                value = v3;
            }
        }
        if key.as_ref().is_some_and(|k| k.eq_ignore_ascii_case(b"OPTIONS")) {
            options_in = value.take();
        }
        if options_in.is_none() || (vendor_in.is_none() && model_in.is_some()) {
            return Err(err(lineno));
        }
        match vendor {
            None => {
                if vendor_in.is_none() {
                    break;
                }
            }
            Some(v) => {
                if let Some(vi) = &vendor_in
                    && v.starts_with(vi)
                    && model_in.as_ref().is_none_or(|mi| model.starts_with(mi))
                {
                    break;
                }
            }
        }
        vendor_in = None;
        model_in = None;
        options_in = None;
    }
    if vendor_in.is_none() && model_in.is_none() && options_in.is_none() {
        return Ok(None);
    }
    let mut argv = vec![Vec::new()];
    argv.extend(shared::string::strv_split(options_in.as_deref().unwrap_or(b""), b" \t"));
    Ok(Some(argv))
}

/// `parse_page_code()`.
fn parse_page_code(v: &[u8]) -> Result<i32, i32> {
    match v {
        b"0x80" => Ok(PAGE_80),
        b"0x83" => Ok(PAGE_83),
        b"pre-spc3-83" => Ok(PAGE_83_PRE_SPC3),
        _ => Err(log_error_errno!(synthetic(libc::EINVAL), "Unknown page code '", v, "'")),
    }
}

/// `set_options()`: Err(r) to return r from run() (0: success).
fn set_options(argv: Vec<Vec<u8>>) -> Result<(), i32> {
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        let c = match opts.next()? {
            None => break,
            Some(c) => c,
        };
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            OPT_V => {
                shared::build::version();
                return Err(0);
            }
            OPT_DEVICE => G.with(|g| {
                let mut g = g.borrow_mut();
                g.dev_specified = true;
                g.maj_min_dev = strscpy(&arg, MAX_PATH_LEN);
            }),
            OPT_CONFIG => G.with(|g| g.borrow_mut().config_file = strscpy(&arg, MAX_PATH_LEN)),
            OPT_PAGE => {
                let p = parse_page_code(&arg)?;
                G.with(|g| g.borrow_mut().default_page_code = p);
            }
            OPT_SG_VERSION => {
                let v = shared::parse::safe_atoi(&arg)
                    .map_err(|r| log_error_errno!(r, "Invalid SG version '", &arg[..], "'"))?;
                if v != 3 && v != 4 {
                    return Err(log_error_errno!(synthetic(libc::ERANGE), "Unknown SG version '", &arg[..], "'"));
                }
                G.with(|g| g.borrow_mut().sg_version = v);
            }
            OPT_DENYLISTED | OPT_BLACKLISTED => G.with(|g| g.borrow_mut().all_good = false),
            OPT_ALLOWLISTED | OPT_WHITELISTED => G.with(|g| g.borrow_mut().all_good = true),
            OPT_REPLACE_WHITESPACE => G.with(|g| g.borrow_mut().reformat_serial = true),
            OPT_VERBOSE => {
                shared::log::log_set_target(shared::log::LogTarget::Console);
                shared::log::log_set_max_level(shared::log::LOG_DEBUG);
                shared::log::log_open();
            }
            OPT_EXPORT => G.with(|g| g.borrow_mut().export = true),
            c => {
                if let Some(r) = common_option(c, &COMMAND, OPTIONS) {
                    return Err(r.min(0));
                }
            }
        }
    }
    if let Some(a) = opts.args().first() {
        G.with(|g| {
            let mut g = g.borrow_mut();
            if !g.dev_specified {
                g.dev_specified = true;
                g.maj_min_dev = strscpy(a, MAX_PATH_LEN);
            }
        });
    }
    Ok(())
}

/// `per_dev_options()`: (good, page code).
fn per_dev_options(vendor_str: &[u8], model_str: &[u8]) -> Result<(bool, i32), i32> {
    let (mut good, mut page) = G.with(|g| {
        let g = g.borrow();
        (g.all_good, g.default_page_code)
    });
    let Some(argv) = get_file_options(Some(vendor_str), model_str)? else { return Ok((good, page)) };
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let opt = OPTIONS.iter().find(|o| o.id == c).expect("listed");
        match opt.short {
            b'b' => good = false,
            b'g' => good = true,
            b'p' => page = parse_page_code(opts.arg.as_deref().unwrap_or(b""))?,
            _ => {
                return Err(log_error_errno!(
                    synthetic(libc::EINVAL),
                    "Option ",
                    option_get_synopsis(opt, Some("/"), false),
                    " not supported in the config file."
                ));
            }
        }
    }
    Ok((good, page))
}

/// `sg_err_category_new()`.
fn sg_err_category(scsi_status: u32, host_status: u32, driver_status: u32, sense: &[u8], sb_len: usize) -> i32 {
    const RECOVERED_ERROR: u8 = 0x01;
    const ILLEGAL_REQUEST: u8 = 0x05;
    const UNIT_ATTENTION: u8 = 0x06;
    let scsi_status = scsi_status & 0x7e;
    if scsi_status == 0 && host_status == 0 && driver_status == 0 {
        return 0; // SG_ERR_CAT_CLEAN
    }
    if scsi_status == 0x02 || scsi_status == 0x22 || driver_status & 0xf == 0x08 {
        if sb_len > 2 {
            let (key, asc) = if sense[0] & 0x2 != 0 {
                (sense[1] & 0xf, sense[2])
            } else {
                (sense[2] & 0xf, if sb_len > 12 { sense[12] } else { 0 })
            };
            if key == RECOVERED_ERROR {
                return 4;
            } else if key == UNIT_ATTENTION {
                if asc == 0x28 {
                    return 1;
                }
                if asc == 0x29 {
                    return 2;
                }
            } else if key == ILLEGAL_REQUEST {
                return 5;
            }
        }
        return 98;
    }
    if host_status != 0 {
        if matches!(host_status, 1..=3) {
            return 3;
        }
        if host_status == 0x0e {
            return 6;
        }
    }
    if driver_status != 0 && driver_status == 0x06 {
        return 3;
    }
    99
}

/// `scsi_dump_sense()`.
fn scsi_dump_sense(d: &ScsiIdDevice, sense: &[u8], sb_len: usize) -> i32 {
    let k = &d.kernel[..];
    if sb_len < 1 {
        return log_debug_errno!(synthetic(libc::EINVAL), k, ": sense buffer empty");
    }
    let class = (sense[0] >> 4) & 0x07;
    let code = sense[0] & 0xf;
    if class == 7 {
        let s = sense[7] as usize + 8;
        if sb_len < s {
            return log_debug_errno!(
                synthetic(libc::EINVAL),
                k,
                format!(": sense buffer too small {sb_len} bytes, {} bytes too short", s - sb_len)
            );
        }
        let (key, asc, ascq) = match code {
            0 | 1 => {
                if s < 14 {
                    return log_debug_errno!(synthetic(libc::EINVAL), k, format!(": sense result too small {s} bytes"));
                }
                (sense[2] & 0xf, sense[12], sense[13])
            }
            2 | 3 => (sense[1] & 0xf, sense[2], sense[3]),
            _ => return log_debug_errno!(synthetic(libc::EINVAL), k, format!(": invalid sense code 0x{code:x}")),
        };
        log_debug!(k, format!(": sense key 0x{key:x} ASC 0x{asc:x} ASCQ 0x{ascq:x}"));
    } else {
        if sb_len < 4 {
            return log_debug_errno!(
                synthetic(libc::EINVAL),
                k,
                format!(": sense buffer too small {sb_len} bytes, {} bytes too short", 4 - sb_len)
            );
        }
        if sense[0] < 15 {
            log_debug!(k, format!(": old sense key: 0x{:x}", sense[0] & 0x0f));
        } else {
            log_debug!(k, format!(": sense = {:2x} {:2x}", sense[0], sense[2]));
        }
        log_debug!(k, format!(": non-extended sense class {class} code 0x{code:x}"));
    }
    -1
}

/// `scsi_inquiry()`: the buffer length, or negative.
fn scsi_inquiry(d: &mut ScsiIdDevice, fd: i32, evpd: u8, page: u8, buf: &mut [u8]) -> i32 {
    let buflen = buf.len();
    if buflen > SCSI_INQ_BUFF_LEN {
        return log_debug_errno!(synthetic(libc::EINVAL), format!("buflen {buflen} too long"));
    }
    let cmd = [0x12, evpd, page, 0, buflen as u8, 0];
    let mut retry = 3;
    let retval = 'out: loop {
        let mut sense = [0u8; SENSE_BUFF_LEN];
        let r = if d.use_sg == 4 {
            sys::sg_io_v4(fd, &cmd, &mut sense, buf, 0)
        } else {
            sys::sg_io_v3(fd, &cmd, &mut sense, buf, SG_DXFER_FROM_DEV, DEF_TIMEOUT)
        };
        let st = match r {
            Err(e) => {
                if (e == -libc::EINVAL || e == -libc::ENOSYS) && d.use_sg == 4 {
                    d.use_sg = 3;
                    continue;
                }
                log_debug_errno!(e, &d.kernel[..], ": ioctl failed: ", strerror(e));
                break 'out -1;
            }
            Ok(st) => st,
        };
        let sense_len = st.sense_len as usize;
        let cat = sg_err_category(st.a, st.b, st.c, &sense, sense_len);
        let mut rv = match cat {
            5 => {
                buf[1] = 0;
                0
            }
            0 | 4 => 0,
            6 => cat,
            _ => {
                // scsi_dump() / scsi_dump_v4()
                let any = st.a != 0 || st.b != 0 || st.c != 0 || (d.use_sg != 4 && st.msg_status != 0);
                if !any {
                    log_debug_errno!(
                        synthetic(libc::EINVAL),
                        if d.use_sg == 4 { "scsi_dump_v4" } else { "scsi_dump" },
                        ": called with no error"
                    )
                } else {
                    if d.use_sg == 4 {
                        log_debug!(
                            &d.kernel[..],
                            format!(": sg_io failed status 0x{:x} 0x{:x} 0x{:x}", st.c, st.b, st.a)
                        );
                    } else {
                        log_debug!(
                            &d.kernel[..],
                            format!(
                                ": sg_io failed status 0x{:x} 0x{:x} 0x{:x} 0x{:x}",
                                st.c, st.b, st.msg_status, st.a
                            )
                        );
                    }
                    if st.a == 0x02 { scsi_dump_sense(d, &sense, sense_len) } else { -1 }
                }
            }
        };
        if rv == 0 {
            rv = buflen as i32;
        } else if rv > 0 {
            retry -= 1;
            if retry > 0 {
                continue;
            }
            rv = -1;
        }
        break rv;
    };
    if retval < 0 {
        log_debug!(&d.kernel[..], format!(": Unable to get INQUIRY vpd {evpd} page 0x{page:x}."));
    }
    retval
}

/// `do_scsi_page0_inquiry()`.
fn page0_inquiry(d: &mut ScsiIdDevice, fd: i32, buffer: &mut [u8]) -> i32 {
    buffer.fill(0);
    if scsi_inquiry(d, fd, 1, 0, buffer) < 0 {
        return 1;
    }
    if buffer[1] != 0 {
        log_debug!(&d.kernel[..], ": page 0 not available.");
        return 1;
    }
    if buffer[3] as usize > buffer.len() {
        log_debug!(&d.kernel[..], format!(": page 0 buffer too long {}", buffer[3]));
        return 1;
    }
    if buffer[3] as usize > MODEL_LENGTH {
        // strneq(buffer + VENDOR_LENGTH, vendor, VENDOR_LENGTH)
        let a = &buffer[VENDOR_LENGTH..2 * VENDOR_LENGTH];
        let a = &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())];
        let b = &d.vendor[..d.vendor.len().min(VENDOR_LENGTH)];
        if a == b {
            log_debug!(&d.kernel[..], ": invalid page0 data");
            return 1;
        }
    }
    0
}

/// `append_vendor_model()`.
fn append_vendor_model(d: &ScsiIdDevice) -> Result<Vec<u8>, i32> {
    if d.vendor.len() != VENDOR_LENGTH {
        return Err(log_debug_errno!(
            synthetic(libc::EINVAL),
            &d.kernel[..],
            ": bad vendor string \"",
            &d.vendor[..],
            "\""
        ));
    }
    if d.model.len() != MODEL_LENGTH {
        return Err(log_debug_errno!(
            synthetic(libc::EINVAL),
            &d.kernel[..],
            ": bad model string \"",
            &d.model[..],
            "\""
        ));
    }
    Ok(shared::bcat!(&d.vendor[..], &d.model[..]))
}

fn hexchar(x: u8) -> u8 {
    b"0123456789abcdef"[(x & 15) as usize]
}

/// `check_fill_0x83_id()`.
fn check_fill_0x83_id(d: &mut ScsiIdDevice, p: &[u8], search: (u8, u8, u8), max_len: usize, full: bool) -> i32 {
    let (id_type, naa_type, code_set) = search;
    if (p[1] & 0x30) == 0x10 {
        if id_type != SCSI_ID_TGTGROUP {
            return 1;
        }
    } else if (p[1] & 0x30) != 0 {
        return 1;
    }
    if (p[1] & 0x0f) != id_type {
        return 1;
    }
    if naa_type != NAA_DONT_CARE && naa_type != (p[4] & 0xf0) >> 4 {
        return 1;
    }
    if (p[0] & 0x0f) != code_set {
        return 1;
    }
    let mut len = p[3] as usize;
    if (p[0] & 0x0f) != ASCII {
        len *= 2;
    }
    len += 2;
    if id_type == SCSI_ID_VENDOR_SPECIFIC {
        len += VENDOR_LENGTH + MODEL_LENGTH;
    }
    if max_len < len {
        log_debug!(&d.kernel[..], format!(": length {max_len} too short - need {len}"));
        return 1;
    }
    if id_type == SCSI_ID_TGTGROUP && full {
        let group = (p[6] as u32) << 8 | p[7] as u32;
        d.tgpt_group = format!("{group:x}").into_bytes();
        return 1;
    }
    let mut serial = vec![hexchar(id_type)];
    if id_type == SCSI_ID_VENDOR_SPECIFIC {
        match append_vendor_model(d) {
            Ok(vm) => serial.extend_from_slice(&vm),
            Err(_) => return 1,
        }
    }
    let s = serial.len();
    let end = 4 + p[3] as usize;
    if (p[0] & 0x0f) == ASCII {
        serial.extend_from_slice(&p[4..end]);
    } else {
        for &b in &p[4..end] {
            serial.push(hexchar(b >> 4));
            serial.push(hexchar(b));
        }
    }
    // As C strings: up to the first NUL.
    let cstr = |v: &[u8]| v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())].to_vec();
    d.serial = cstr(&serial);
    d.serial_short = cstr(&serial[s.min(serial.len())..]);
    if id_type == SCSI_ID_NAA && full {
        let short = d.serial_short.clone();
        d.wwn = short[..short.len().min(16)].to_vec();
        d.wwn_vendor_extension = short.get(16..).map(|x| x[..x.len().min(16)].to_vec()).unwrap_or_default();
    }
    0
}

/// `check_fill_0x83_prespc3()`.
fn check_fill_0x83_prespc3(d: &mut ScsiIdDevice, p: &[u8], max_len: usize) -> i32 {
    let mut serial = vec![hexchar(SCSI_ID_NAA)];
    let page_len = (p[3] as usize).min(SCSI_INQ_BUFF_LEN - 4);
    let mut i = 0;
    while i < page_len && serial.len() + 3 < max_len {
        serial.push(hexchar(p[4 + i] >> 4));
        serial.push(hexchar(p[4 + i]));
        i += 1;
    }
    serial.truncate(max_len - 1);
    d.serial_short = serial.clone();
    d.serial = serial;
    0
}

/// `do_scsi_page83_inquiry()`.
fn page83_inquiry(d: &mut ScsiIdDevice, fd: i32, len: usize) -> i32 {
    let _ = page80_inquiry(d, fd, false, true, MAX_SERIAL_LEN);
    let mut p = vec![0u8; SCSI_INQ_BUFF_LEN];
    if scsi_inquiry(d, fd, 1, PAGE_83 as u8, &mut p) < 0 {
        return 1;
    }
    if p[1] != PAGE_83 as u8 {
        log_debug!(&d.kernel[..], ": Invalid page 0x83");
        return 1;
    }
    if p[6] != 0 {
        return check_fill_0x83_prespc3(d, &p, len);
    }
    let page_end = (((p[2] as usize) << 8) + p[3] as usize + 3).min(SCSI_INQ_BUFF_LEN - 5);
    for &sv in ID_SEARCH_LIST {
        let mut j = 4;
        while j <= page_end {
            if j + (4 + p[j + 3] as usize).max(8) > SCSI_INQ_BUFF_LEN {
                break;
            }
            let r = check_fill_0x83_id(d, &p[j..], sv, len, true);
            if r <= 0 {
                return r;
            }
            j += p[j + 3] as usize + 4;
        }
    }
    1
}

/// `do_scsi_page83_prespc3_inquiry()`.
fn page83_prespc3_inquiry(d: &mut ScsiIdDevice, fd: i32, len: usize) -> i32 {
    let mut p = vec![0u8; SCSI_INQ_BUFF_LEN];
    if scsi_inquiry(d, fd, 1, PAGE_83 as u8, &mut p) < 0 {
        return 1;
    }
    if p[1] != PAGE_83 as u8 {
        log_debug!(&d.kernel[..], ": Invalid page 0x83");
        return 1;
    }
    if p[6] == 0 {
        return 2;
    }
    let mut serial = vec![hexchar(SCSI_ID_NAA)];
    let page_len = (p[3] as usize + 4).min(SCSI_INQ_BUFF_LEN);
    let mut i = 4;
    while i < page_len && serial.len() + 2 < len {
        serial.push(hexchar(p[i] >> 4));
        serial.push(hexchar(p[i]));
        i += 1;
    }
    d.serial = serial;
    0
}

/// `do_scsi_page80_inquiry()`: `serial` fills d.serial and
/// d.serial_short (as scsi_get_serial() passes them); `unit` fills
/// d.unit_serial_number only.
fn page80_inquiry(d: &mut ScsiIdDevice, fd: i32, serial: bool, unit: bool, max_len: usize) -> i32 {
    let mut buf = vec![0u8; SCSI_INQ_BUFF_LEN];
    let r = scsi_inquiry(d, fd, 1, PAGE_80 as u8, &mut buf);
    if r < 0 {
        return r;
    }
    if buf[1] != PAGE_80 as u8 {
        log_debug!(&d.kernel[..], ": Invalid page 0x80");
        return 1;
    }
    let need = 1 + VENDOR_LENGTH + MODEL_LENGTH + buf[3] as usize;
    if max_len < need {
        log_debug!(&d.kernel[..], format!(": length {max_len} too short - need {need}"));
        return 1;
    }
    let page_len = (buf[3] as usize).min(SCSI_INQ_BUFF_LEN - 4);
    let cstr = |v: &[u8]| v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())].to_vec();
    if serial {
        let Ok(vm) = append_vendor_model(d) else { return 1 };
        d.serial = cstr(&shared::bcat!("S", &vm[..], &buf[4..4 + page_len]));
        d.serial_short = cstr(&buf[4..4 + page_len]);
    }
    if unit {
        d.unit_serial_number = cstr(&buf[4..4 + page_len]);
    }
    0
}

/// `scsi_std_inquiry()`.
fn scsi_std_inquiry(d: &mut ScsiIdDevice, devname: &[u8]) -> i32 {
    let fd = match sys::open(devname, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY, 0) {
        Ok(fd) => sys::OwnedFd::new(fd),
        Err(r) => return log_debug_errno!(r, "scsi_id: cannot open ", devname, ": ", strerror(r)),
    };
    let st = match sys::fstat(fd.raw()) {
        Ok(st) => st,
        Err(r) => return log_debug_errno!(r, "scsi_id: cannot stat ", devname, ": ", strerror(r)),
    };
    d.kernel = shared::sd_device::devnum_format(st.st_rdev).into_bytes();
    let mut buf = vec![0u8; SCSI_INQ_BUFF_LEN];
    let r = scsi_inquiry(d, fd.raw(), 0, 0, &mut buf);
    if r < 0 {
        return r;
    }
    let cstr = |v: &[u8]| v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())].to_vec();
    d.vendor = cstr(&buf[8..16]);
    d.model = cstr(&buf[16..32]);
    d.revision = cstr(&buf[32..36]);
    d.ty = (buf[0] & 0x1f) as u32;
    0
}

/// `scsi_get_serial()`.
fn scsi_get_serial(d: &mut ScsiIdDevice, devname: &[u8], page_code: i32, len: usize) -> i32 {
    d.serial.clear();
    let mut fd = Err(-libc::EBUSY);
    for _ in 0..20 {
        fd = sys::open(devname, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY, 0);
        if fd.is_ok() || fd != Err(-libc::EBUSY) {
            break;
        }
        let mut r = [0u8; 8];
        let _ = sys::getrandom(&mut r);
        let extra = u64::from_ne_bytes(r) % 100_000;
        std::thread::sleep(std::time::Duration::from_micros(200_000 + extra));
    }
    let Ok(fd) = fd else { return 1 };
    let fd = sys::OwnedFd::new(fd);
    let fd = fd.raw();
    match page_code {
        PAGE_80 => return if page80_inquiry(d, fd, true, false, len) != 0 { 1 } else { 0 },
        PAGE_83 => return if page83_inquiry(d, fd, len) != 0 { 1 } else { 0 },
        PAGE_83_PRE_SPC3 => {
            let r = page83_prespc3_inquiry(d, fd, len);
            if r == 0 {
                return 0;
            }
            if r == 2 {
                return if page83_inquiry(d, fd, len) != 0 { 1 } else { 0 };
            }
            return 1;
        }
        0 => {}
        c => {
            log_debug!(&d.kernel[..], format!(": unsupported page code 0x{c}"));
            return 1;
        }
    }
    let mut page0 = vec![0u8; SCSI_INQ_BUFF_LEN];
    if page0_inquiry(d, fd, &mut page0) != 0 {
        return 1;
    }
    let end = (page0[3] as usize + 3).min(SCSI_INQ_BUFF_LEN - 1);
    for ind in 4..=end {
        if page0[ind] == PAGE_83 as u8 && page83_inquiry(d, fd, len) == 0 {
            return 0;
        }
    }
    for ind in 4..=end {
        if page0[ind] == PAGE_80 as u8 && page80_inquiry(d, fd, true, false, len) == 0 {
            return 0;
        }
    }
    1
}

fn scsi_string_is_valid(s: &[u8]) -> bool {
    !s.is_empty() && shared::utf8::is_valid(s) && !s.iter().any(|&c| c < b' ' || c == 127)
}

/// `scsi_id()`.
fn scsi_id(maj_min_dev: &[u8]) -> i32 {
    let mut d = ScsiIdDevice { use_sg: G.with(|g| g.borrow().sg_version), ..Default::default() };
    // set_inq_values()
    let r = scsi_std_inquiry(&mut d, maj_min_dev);
    if r < 0 {
        return r;
    }
    let vendor_enc = encode_devnode_name(&d.vendor, 256);
    let model_enc = encode_devnode_name(&d.model, 256);
    let mut vendor_str = udev_replace_whitespace(&d.vendor, 63);
    udev_replace_chars(&mut vendor_str, None);
    let mut model_str = udev_replace_whitespace(&d.model, 63);
    udev_replace_chars(&mut model_str, None);
    let type_str = set_type(d.ty);
    let mut revision_str = udev_replace_whitespace(&d.revision, 15);
    udev_replace_chars(&mut revision_str, None);
    let (good, page_code) = match per_dev_options(&vendor_str, &model_str) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !good {
        return -libc::EIO;
    }
    let _ = scsi_get_serial(&mut d, maj_min_dev, page_code, MAX_SERIAL_LEN);
    let (export, reformat) = G.with(|g| {
        let g = g.borrow();
        (g.export, g.reformat_serial)
    });
    let clean = |s: &[u8]| {
        let mut v = udev_replace_whitespace(s, MAX_SERIAL_LEN - 1);
        udev_replace_chars(&mut v, None);
        v
    };
    if export {
        out!("ID_SCSI=1\n", "ID_VENDOR=", &vendor_str[..], "\n", "ID_VENDOR_ENC=", &vendor_enc[..], "\n");
        out!("ID_MODEL=", &model_str[..], "\n", "ID_MODEL_ENC=", &model_enc[..], "\n");
        out!("ID_REVISION=", &revision_str[..], "\n", "ID_TYPE=", type_str, "\n");
        if !d.serial.is_empty() {
            out!("ID_SERIAL=", clean(&d.serial), "\n", "ID_SERIAL_SHORT=", clean(&d.serial_short), "\n");
        }
        if scsi_string_is_valid(&d.wwn) {
            out!("ID_WWN=0x", &d.wwn[..], "\n");
            if scsi_string_is_valid(&d.wwn_vendor_extension) {
                out!("ID_WWN_VENDOR_EXTENSION=0x", &d.wwn_vendor_extension[..], "\n");
                out!("ID_WWN_WITH_EXTENSION=0x", &d.wwn[..], &d.wwn_vendor_extension[..], "\n");
            } else {
                out!("ID_WWN_WITH_EXTENSION=0x", &d.wwn[..], "\n");
            }
        }
        if scsi_string_is_valid(&d.tgpt_group) {
            out!("ID_TARGET_PORT=", &d.tgpt_group[..], "\n");
        }
        if scsi_string_is_valid(&d.unit_serial_number) {
            out!("ID_SCSI_SERIAL=", &d.unit_serial_number[..], "\n");
        }
        return 0;
    }
    if d.serial.is_empty() {
        return -libc::ENODATA;
    }
    if reformat {
        out!(clean(&d.serial), "\n");
    } else {
        out!(&d.serial[..], "\n");
    }
    0
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let _ = udevadm::udev::util::udev_parse_config();
    shared::log::log_setup();
    match get_file_options(None, b"") {
        Err(r) => return r,
        Ok(Some(newargv)) => {
            if let Err(r) = set_options(newargv) {
                return r;
            }
        }
        Ok(None) => {}
    }
    if let Err(r) = set_options(argv) {
        return r;
    }
    let (specified, dev) = G.with(|g| {
        let g = g.borrow();
        (g.dev_specified, g.maj_min_dev.clone())
    });
    if !specified {
        return log_error_errno!(synthetic(libc::EINVAL), "No device specified.");
    }
    scsi_id(&dev)
}

fn main() {
    shared::main_func::main_with(run)
}
