// SPDX-License-Identifier: GPL-2.0-or-later
//! `dmi_memory_id`: identify memory devices from DMI/SMBIOS data.  A port
//! of systemd's `src/udev/dmi_memory_id/dmi_memory_id.c` (v262).

use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_ERR};
use shared::options::{Command, Opt, OptionParser, common};
use shared::{log_debug, log_error_errno, log_full_errno, sys};
use udev_helpers::{OPT_HELP, OPT_INTROSPECT_CLI, OPT_VERSION, common_option, out};

const OPT_V: i32 = 0x110;
const OPT_FROM_DUMP: i32 = 0x111;

const OPTIONS: &[Opt] = &[
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::new(OPT_V, b'V', None, None, None),
    Opt::new(OPT_FROM_DUMP, b'F', Some("from-dump"), Some("FILE"), Some("Read DMI information from a binary file")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["dmi_memory_id"],
    abstract_: "Identify memory devices from DMI/SMBIOS data.",
    argspec: &[],
    footer: None,
    man_pages: &[],
    verbs: &[],
};

const OUT_OF_SPEC: &str = "<OUT OF SPEC>";
const SYS_ENTRY_FILE: &str = "/sys/firmware/dmi/tables/smbios_entry_point";
const SYS_TABLE_FILE: &str = "/sys/firmware/dmi/tables/DMI";

fn word(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn dword(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}

fn qword(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

fn verify_checksum(buf: &[u8], len: usize) -> bool {
    buf[..len].iter().fold(0u8, |s, b| s.wrapping_add(*b)) == 0
}

/// A structure: its formatted area is `data[..length]`, its strings follow.
struct DmiHeader<'a> {
    ty: u8,
    length: u8,
    data: &'a [u8],
}

/// `dmi_string()`.
fn dmi_string<'a>(h: &DmiHeader<'a>, mut s: u8) -> &'a [u8] {
    if s == 0 {
        return b"Not Specified";
    }
    let at = |p: usize| -> &'a [u8] {
        let rest = h.data.get(p..).unwrap_or(b"");
        &rest[..rest.iter().position(|&c| c == 0).unwrap_or(rest.len())]
    };
    let mut p = h.length as usize;
    while s > 1 && !at(p).is_empty() {
        p += at(p).len() + 1;
        s -= 1;
    }
    let bp = at(p);
    if bp.is_empty() { b"<BAD INDEX>" } else { bp }
}

fn table_str(table: &[(u8, &'static str)], code: u8) -> &'static str {
    table.iter().find(|(c, _)| *c == code).map_or(OUT_OF_SPEC, |(_, s)| *s)
}

/// `dmi_print_memory_size()`: `kb` for MEMORY_SIZE_UNIT_KB.
fn print_memory_size(prefix: &str, suffix: &str, slot: Option<u32>, mut code: u64, kb: bool) {
    if kb {
        code <<= 10;
    }
    match slot {
        Some(n) => out!(format!("{prefix}_{n}_{suffix}={code}\n")),
        None => out!(format!("{prefix}_{suffix}={code}\n")),
    }
}

fn memory_array_location(code: u8) {
    let location: &[(u8, &str)] = &[
        (0x01, "Other"),
        (0x02, "Unknown"),
        (0x03, "System Board Or Motherboard"),
        (0x04, "ISA Add-on Card"),
        (0x05, "EISA Add-on Card"),
        (0x06, "PCI Add-on Card"),
        (0x07, "MCA Add-on Card"),
        (0x08, "PCMCIA Add-on Card"),
        (0x09, "Proprietary Add-on Card"),
        (0x0A, "NuBus"),
        (0xA0, "PC-98/C20 Add-on Card"),
        (0xA1, "PC-98/C24 Add-on Card"),
        (0xA2, "PC-98/E Add-on Card"),
        (0xA3, "PC-98/Local Bus Add-on Card"),
        (0xA4, "CXL Add-on Card"),
    ];
    out!("MEMORY_ARRAY_LOCATION=", table_str(location, code), "\n");
}

fn memory_array_ec_type(code: u8) {
    let ty: &[(u8, &str)] = &[
        (0x01, "Other"),
        (0x02, "Unknown"),
        (0x03, "None"),
        (0x04, "Parity"),
        (0x05, "Single-bit ECC"),
        (0x06, "Multi-bit ECC"),
        (0x07, "CRC"),
    ];
    if code != 0x03 {
        out!("MEMORY_ARRAY_EC_TYPE=", table_str(ty, code), "\n");
    }
}

fn device_string(suffix: &str, slot: u32, h: &DmiHeader, s: u8) {
    let st = shared::string::strstrip(dmi_string(h, s));
    if !st.is_empty() && shared::utf8::is_valid(st) && !st.iter().any(|&c| c < b' ' || c == 127) {
        out!(format!("MEMORY_DEVICE_{slot}_{suffix}="), st, "\n");
    }
}

fn device_width(suffix: &str, slot: u32, code: u16) {
    if code != 0 && code != 0xFFFF {
        out!(format!("MEMORY_DEVICE_{slot}_{suffix}={code}\n"));
    }
}

fn device_size(slot: u32, code: u16) {
    if code == 0 {
        out!(format!("MEMORY_DEVICE_{slot}_PRESENT=0\n"));
        return;
    }
    if code == 0xFFFF {
        return;
    }
    let mut s = (code & 0x7FFF) as u64;
    if code & 0x8000 == 0 {
        s <<= 10;
    }
    print_memory_size("MEMORY_DEVICE", "SIZE", Some(slot), s, true);
}

fn device_voltage(suffix: &str, slot: u32, code: u16) {
    if code == 0 {
        return;
    }
    let v = code as f64 / 1000.0;
    let s = if code % 100 != 0 { sys::format_g(v, None) } else { sys::format_g(v, Some(1)) };
    out!(format!("MEMORY_DEVICE_{slot}_{suffix}="), &s[..], "\n");
}

fn device_form_factor(slot: u32, code: u8) {
    let f: &[(u8, &str)] = &[
        (0x01, "Other"),
        (0x02, "Unknown"),
        (0x03, "SIMM"),
        (0x04, "SIP"),
        (0x05, "Chip"),
        (0x06, "DIP"),
        (0x07, "ZIP"),
        (0x08, "Proprietary Card"),
        (0x09, "DIMM"),
        (0x0A, "TSOP"),
        (0x0B, "Row Of Chips"),
        (0x0C, "RIMM"),
        (0x0D, "SODIMM"),
        (0x0E, "SRIMM"),
        (0x0F, "FB-DIMM"),
        (0x10, "Die"),
    ];
    out!(format!("MEMORY_DEVICE_{slot}_FORM_FACTOR="), table_str(f, code), "\n");
}

fn device_type(slot: u32, code: u8) {
    const T: &[&str] = &[
        "",
        "Other",
        "Unknown",
        "DRAM",
        "EDRAM",
        "VRAM",
        "SRAM",
        "RAM",
        "ROM",
        "Flash",
        "EEPROM",
        "FEPROM",
        "EPROM",
        "CDRAM",
        "3DRAM",
        "SDRAM",
        "SGRAM",
        "RDRAM",
        "DDR",
        "DDR2",
        "DDR2 FB-DIMM",
        "Reserved",
        "Reserved",
        "Reserved",
        "DDR3",
        "FBD2",
        "DDR4",
        "LPDDR",
        "LPDDR2",
        "LPDDR3",
        "LPDDR4",
        "Logical non-volatile device",
        "HBM",
        "HBM2",
        "DDR5",
        "LPDDR5",
        "HBM3",
    ];
    let s = T.get(code as usize).copied().filter(|s| !s.is_empty()).unwrap_or(OUT_OF_SPEC);
    out!(format!("MEMORY_DEVICE_{slot}_TYPE={s}\n"));
}

/// A bit list: the names of the set bits 1.., space separated.
fn bit_list(names: &[&str], code: u16) -> String {
    (1..names.len()).filter(|i| code & (1 << i) != 0).map(|i| names[i]).collect::<Vec<_>>().join(" ")
}

fn device_type_detail(slot: u32, code: u16) {
    const D: &[&str] = &[
        "",
        "Other",
        "Unknown",
        "Fast-paged",
        "Static Column",
        "Pseudo-static",
        "RAMBUS",
        "Synchronous",
        "CMOS",
        "EDO",
        "Window DRAM",
        "Cache DRAM",
        "Non-Volatile",
        "Registered (Buffered)",
        "Unbuffered (Unregistered)",
        "LRDIMM",
    ];
    if code & 0xFFFE == 0 {
        out!(format!("MEMORY_DEVICE_{slot}_TYPE_DETAIL=None\n"));
    } else {
        out!(format!("MEMORY_DEVICE_{slot}_TYPE_DETAIL={}\n", bit_list(D, code)));
    }
}

fn device_speed(suffix: &str, slot: u32, code: u16) {
    if code != 0 {
        out!(format!("MEMORY_DEVICE_{slot}_{suffix}={code}\n"));
    }
}

fn device_technology(slot: u32, code: u8) {
    let t: &[(u8, &str)] = &[
        (0x01, "Other"),
        (0x02, "Unknown"),
        (0x03, "DRAM"),
        (0x04, "NVDIMM-N"),
        (0x05, "NVDIMM-F"),
        (0x06, "NVDIMM-P"),
        (0x07, "Intel Optane persistent memory"),
    ];
    out!(format!("MEMORY_DEVICE_{slot}_MEMORY_TECHNOLOGY="), table_str(t, code), "\n");
}

fn device_operating_mode(slot: u32, code: u16) {
    const M: &[&str] = &[
        "",
        "Other",
        "Unknown",
        "Volatile memory",
        "Byte-accessible persistent memory",
        "Block-accessible persistent memory",
    ];
    if code & 0xFFFE != 0 {
        out!(format!("MEMORY_DEVICE_{slot}_MEMORY_OPERATING_MODE_CAPABILITY={}\n", bit_list(M, code)));
    }
}

fn device_manufacturer_id(suffix: &str, slot: u32, code: u16) {
    if code != 0 {
        out!(format!("MEMORY_DEVICE_{slot}_{suffix}=Bank {}, Hex 0x{:02X}\n", (code & 0x7F) + 1, code >> 8));
    }
}

fn device_product_id(suffix: &str, slot: u32, code: u16) {
    if code != 0 {
        out!(format!("MEMORY_DEVICE_{slot}_{suffix}=0x{code:04X}\n"));
    }
}

fn device_size_detail(suffix: &str, slot: u32, code: u64) {
    if code != 0 && code != u64::MAX {
        print_memory_size("MEMORY_DEVICE", suffix, Some(slot), code, false);
    }
}

/// `dmi_decode()`.
fn dmi_decode(h: &DmiHeader, next_slot: &mut u32) {
    let d = h.data;
    let len = h.length;
    match h.ty {
        16 => {
            log_debug!("Physical Memory Array");
            if len < 0x0F || d[0x05] != 0x03 {
                return;
            }
            log_debug!("Use: System Memory");
            memory_array_location(d[0x04]);
            memory_array_ec_type(d[0x06]);
            if dword(d, 0x07) != 0x8000_0000 {
                print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", None, dword(d, 0x07) as u64, true);
            } else if len >= 0x17 {
                print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", None, qword(d, 0x0F), false);
            }
        }
        17 => {
            let slot = *next_slot;
            *next_slot = slot + 1;
            log_debug!(format!("Memory Device: {slot}"));
            if len < 0x15 {
                return;
            }
            device_width("TOTAL_WIDTH", slot, word(d, 0x08));
            device_width("DATA_WIDTH", slot, word(d, 0x0A));
            if len >= 0x20 && word(d, 0x0C) == 0x7FFF {
                out!(format!("MEMORY_DEVICE_{slot}_SIZE={}\n", dword(d, 0x1C) as u64 * 1024 * 1024));
            } else {
                device_size(slot, word(d, 0x0C));
            }
            device_form_factor(slot, d[0x0E]);
            match d[0x0F] {
                0xFF => out!(format!("MEMORY_DEVICE_{slot}_SET=Unknown\n")),
                0 => {}
                c => out!(format!("MEMORY_DEVICE_{slot}_SET={c}\n")),
            }
            device_string("LOCATOR", slot, h, d[0x10]);
            device_string("BANK_LOCATOR", slot, h, d[0x11]);
            device_type(slot, d[0x12]);
            device_type_detail(slot, word(d, 0x13));
            if len < 0x17 {
                return;
            }
            device_speed("SPEED_MTS", slot, word(d, 0x15));
            if len < 0x1B {
                return;
            }
            device_string("MANUFACTURER", slot, h, d[0x17]);
            device_string("SERIAL_NUMBER", slot, h, d[0x18]);
            device_string("ASSET_TAG", slot, h, d[0x19]);
            device_string("PART_NUMBER", slot, h, d[0x1A]);
            if len < 0x1C {
                return;
            }
            let rank = d[0x1B] & 0x0F;
            if rank != 0 {
                out!(format!("MEMORY_DEVICE_{slot}_RANK={rank}\n"));
            }
            if len < 0x22 {
                return;
            }
            device_speed("CONFIGURED_SPEED_MTS", slot, word(d, 0x20));
            if len < 0x28 {
                return;
            }
            device_voltage("MINIMUM_VOLTAGE", slot, word(d, 0x22));
            device_voltage("MAXIMUM_VOLTAGE", slot, word(d, 0x24));
            device_voltage("CONFIGURED_VOLTAGE", slot, word(d, 0x26));
            if len < 0x34 {
                return;
            }
            device_technology(slot, d[0x28]);
            device_operating_mode(slot, word(d, 0x29));
            device_string("FIRMWARE_VERSION", slot, h, d[0x2B]);
            device_manufacturer_id("MODULE_MANUFACTURER_ID", slot, word(d, 0x2C));
            device_product_id("MODULE_PRODUCT_ID", slot, word(d, 0x2E));
            device_manufacturer_id("MEMORY_SUBSYSTEM_CONTROLLER_MANUFACTURER_ID", slot, word(d, 0x30));
            device_product_id("MEMORY_SUBSYSTEM_CONTROLLER_PRODUCT_ID", slot, word(d, 0x32));
            for (min, off, name) in [
                (0x3C, 0x34, "NON_VOLATILE_SIZE"),
                (0x44, 0x3C, "VOLATILE_SIZE"),
                (0x4C, 0x44, "CACHE_SIZE"),
                (0x54, 0x4C, "LOGICAL_SIZE"),
            ] {
                if len < min {
                    return;
                }
                device_size_detail(name, slot, qword(d, off));
            }
        }
        _ => {}
    }
}

/// `dmi_table_decode()`.
fn dmi_table_decode(buf: &[u8], num: u16) {
    let len = buf.len();
    let mut pos = 0usize;
    let mut next_slot = 0u32;
    let mut i: u16 = 0;
    while (i < num || num == 0) && pos + 4 <= len {
        let ty = buf[pos];
        let length = buf[pos + 1];
        if length < 4 || ty == 127 {
            break;
        }
        let mut next = pos + length as usize;
        while next + 1 < len && (buf[next] != 0 || buf[next + 1] != 0) {
            next += 1;
        }
        next += 2;
        if next > len {
            break;
        }
        if ty != 126 {
            dmi_decode(&DmiHeader { ty, length, data: &buf[pos..next] }, &mut next_slot);
        }
        pos = next;
        i = i.wrapping_add(1);
    }
    if next_slot > 0 {
        out!(format!("MEMORY_ARRAY_NUM_DEVICES={next_slot}\n"));
    }
}

/// `read_full_file_full(AT_FDCWD, path, offset, size, 0, ...)`: up to
/// `size` bytes at `offset`.
fn read_file_part(path: &[u8], offset: u64, size: usize) -> Result<Vec<u8>, i32> {
    let fd = sys::OwnedFd::new(sys::open(path, libc::O_RDONLY | libc::O_CLOEXEC, 0)?);
    if offset > 0 {
        sys::lseek(fd.raw(), offset as i64, libc::SEEK_SET)?;
    }
    let mut out = vec![0u8; size];
    let mut got = 0;
    while got < size {
        let n = sys::read(fd.raw(), &mut out[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    out.truncate(got);
    Ok(out)
}

/// `dmi_table()`.
fn dmi_table(base: u64, len: u32, num: u16, devmem: &[u8], no_file_offset: bool) -> i32 {
    match read_file_part(devmem, if no_file_offset { 0 } else { base }, len as usize) {
        Err(r) => log_error_errno!(r, "Failed to read table: ", strerror(r)),
        Ok(buf) => {
            dmi_table_decode(&buf, num);
            0
        }
    }
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    let _ = udevadm::udev::util::udev_parse_config();
    shared::log::log_setup();
    let mut source: Option<Vec<u8>> = None;
    let mut opts = OptionParser::new(argv, OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(OPT_V)) => {
                shared::build::version();
                return 0;
            }
            Ok(Some(OPT_FROM_DUMP)) => source = opts.arg.clone(),
            Ok(Some(c)) => {
                if let Some(r) = common_option(c, &COMMAND, OPTIONS) {
                    return r.min(0);
                }
            }
        }
    }
    if !opts.args().is_empty() {
        return log_error_errno!(synthetic(libc::EINVAL), "This program takes no arguments.");
    }
    let entry = source.clone().unwrap_or_else(|| SYS_ENTRY_FILE.as_bytes().to_vec());
    let buf = match read_file_part(&entry, 0, 0x20) {
        Ok(b) => b,
        Err(r) => {
            return log_full_errno!(
                if source.is_none() && r == -libc::ENOENT { LOG_DEBUG } else { LOG_ERR },
                r,
                "Reading \"",
                &entry[..],
                "\" failed: ",
                strerror(r)
            );
        }
    };
    let (devmem, no_file_offset) = match &source {
        Some(s) => (s.clone(), false),
        None => (SYS_TABLE_FILE.as_bytes().to_vec(), true),
    };
    let size = buf.len();
    if size >= 24 && buf.starts_with(b"_SM3_") {
        // smbios3_decode()
        if buf[0x06] > 0x20 {
            return log_error_errno!(
                synthetic(libc::EINVAL),
                format!("Entry point length too large ({} bytes, expected 24).", buf[0x06])
            );
        }
        if !verify_checksum(&buf, buf[0x06] as usize) {
            return log_error_errno!(synthetic(libc::EINVAL), "Failed to verify checksum.");
        }
        let offset = qword(&buf, 0x10);
        if cfg!(target_pointer_width = "32") && !no_file_offset && offset >> 32 != 0 {
            return log_error_errno!(synthetic(libc::EINVAL), "64-bit addresses not supported on 32-bit systems.");
        }
        return dmi_table(offset, dword(&buf, 0x0C), 0, &devmem, no_file_offset);
    }
    if size >= 31 && buf.starts_with(b"_SM_") {
        // smbios_decode()
        if buf[0x05] > 0x20 {
            return log_error_errno!(
                synthetic(libc::EINVAL),
                format!("Entry point length too large ({} bytes, expected 31).", buf[0x05])
            );
        }
        if !verify_checksum(&buf, buf[0x05] as usize)
            || &buf[0x10..0x15] != b"_DMI_"
            || !verify_checksum(&buf[0x10..], 0x0F)
        {
            return log_error_errno!(synthetic(libc::EINVAL), "Failed to verify checksum.");
        }
        return dmi_table(dword(&buf, 0x18) as u64, word(&buf, 0x16) as u32, word(&buf, 0x1C), &devmem, no_file_offset);
    }
    if size >= 15 && buf.starts_with(b"_DMI_") {
        // legacy_decode()
        if !verify_checksum(&buf, 0x0F) {
            return log_error_errno!(synthetic(libc::EINVAL), "Failed to verify checksum.");
        }
        return dmi_table(dword(&buf, 0x08) as u64, word(&buf, 0x06) as u32, word(&buf, 0x0C), &devmem, no_file_offset);
    }
    -libc::EINVAL
}

fn main() {
    shared::main_func::main_with(run)
}
