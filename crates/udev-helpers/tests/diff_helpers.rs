// SPDX-License-Identifier: GPL-2.0-or-later
//! Differential tests for the udev helpers (ata_id, cdrom_id, scsi_id,
//! dmi_memory_id, fido_id, iocost, mtd_probe, v4l_id): their command
//! lines, failures on device nodes the sandbox can reach, scsi_id's
//! config file, and dmi_memory_id on upstream's DMI dumps.  Probing real
//! drives needs root on real hardware (the VM pass).

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::{Case, Program, check, reference_build};

fn prog(name: &'static str) -> Program {
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_ata_id")).with_file_name(name);
    Program { name, c: reference_build().join(name), rust }
}

const HELPERS: &[&str] =
    &["ata_id", "cdrom_id", "dmi_memory_id", "fido_id", "iocost", "mtd_probe", "scsi_id", "v4l_id"];

/// A helper case with an /etc/udev of its own (no udev.conf, no hwdb).
fn h(name: &str, args: &[&str]) -> Case {
    Case::new(name, args).etc_own("udev").dir("etc/udev", 0o755)
}

/// The case, then the same case with the debug log.
fn cd(p: &'static str, case: Case) {
    let mut d = case.clone().env("SYSTEMD_LOG_LEVEL", "debug");
    d.name = format!("{}_debug", case.name);
    check(&prog(p), case);
    check(&prog(p), d);
}

#[test]
fn command_lines() {
    for &p in HELPERS {
        for (n, args) in [
            ("help", &["--help"][..]),
            ("h", &["-h"]),
            ("version", &["--version"]),
            ("introspect", &["--introspect-cli"]),
            ("noargs", &[]),
            ("bogus", &["--bogus"]),
            ("bogus_short", &["-Q"]),
            ("two", &["/dev/null", "/dev/zero"]),
        ] {
            cd(p, h(&format!("{p}_{n}"), args));
        }
    }
}

#[test]
fn device_nodes() {
    for &p in &["ata_id", "cdrom_id", "scsi_id", "mtd_probe", "v4l_id"] {
        for (n, dev) in [("null", "/dev/null"), ("missing", "/dev/nonexistent"), ("denied", "@T@/x"), ("dir", "/")] {
            cd(p, h(&format!("{p}_{n}"), &[dev]).file("x", b"", 0o000).run_as(common::ALICE));
        }
    }
    cd("ata_id", h("ata_id_export_null", &["-x", "/dev/null"]));
    cd("ata_id", h("ata_id_export_missing", &["--export", "/dev/nonexistent"]));
    for (n, args) in [
        ("lock", &["-l", "/dev/null"][..]),
        ("unlock", &["--unlock-media", "/dev/null"]),
        ("eject", &["-e", "/dev/null"]),
        ("debug", &["-d", "/dev/null"]),
        ("all", &["-l", "-u", "-e", "-d", "/dev/null"]),
    ] {
        cd("cdrom_id", h(&format!("cdrom_id_{n}"), args));
    }
    cd("iocost", h("iocost_query_null", &["query", "/dev/null"]));
    cd("iocost", h("iocost_apply_missing", &["apply", "/dev/nonexistent"]));
    cd("iocost", h("iocost_apply_solution", &["apply", "/dev/null", "isolation"]));
    cd("iocost", h("iocost_bad_verb", &["frobnicate"]));
    cd("iocost", h("iocost_query_noarg", &["query"]));
    cd("fido_id", h("fido_id_sysfs_null", &["/sys/devices/virtual/mem/null"]));
    cd("fido_id", h("fido_id_sysfs_missing", &["/sys/devices/nonexistent"]));
    cd("fido_id", h("fido_id_devpath", &[]).env("DEVPATH", "/devices/virtual/mem/null"));
}

#[test]
fn scsi_id_options() {
    for (n, args) in [
        ("V", &["-V"][..]),
        ("export_null", &["-x", "/dev/null"]),
        ("verbose_null", &["-v", "-x", "/dev/null"]),
        ("sg3_null", &["-s", "3", "/dev/null"]),
        ("sg5", &["-s", "5", "/dev/null"]),
        ("sg_bad", &["--sg-version=abc", "/dev/null"]),
        ("page_bad", &["-p", "0x99", "/dev/null"]),
        ("page80", &["--page=0x80", "-x", "/dev/null"]),
        ("prespc3", &["-p", "pre-spc3-83", "/dev/null"]),
        ("device_opt", &["-d", "/dev/null", "-x", "/dev/nonexistent"]),
        ("allow_deny", &["-g", "-b", "--whitelisted", "--blacklisted", "-u", "/dev/null"]),
        ("config_missing", &["-f", "/nonexistent", "/dev/null"]),
    ] {
        cd("scsi_id", h(&format!("scsi_id_{n}"), args));
    }
    // The default config file /etc/scsi_id.config: read before the
    // command line, its options apply first.
    for (n, conf) in [
        ("ok", "# comment\n\n   \nOPTIONS=-g -x\n"),
        ("device", "OPTIONS=-u /dev/null\n"),
        ("vendor", "VENDOR=\"ATA\",MODEL=\"X\",OPTIONS=-b\nOPTIONS=-p 0x80\n"),
        ("model_only", "MODEL=\"X\",OPTIONS=-b\n"),
        ("garbage", "garbage\n"),
        ("no_options", "VENDOR=\"ATA\"\n"),
        ("bad_page", "OPTIONS=-p 0x99\n"),
        ("bad_option", "OPTIONS=--bogus\n"),
        ("help", "OPTIONS=--help\n"),
        ("case", "options=-x\n"),
        ("long_line", &format!("OPTIONS=-x{}\n", " ".repeat(300))),
    ] {
        cd(
            "scsi_id",
            h(&format!("scsi_id_conf_{n}"), &["/dev/null"]).etc_own("scsi_id.config").file(
                "etc/scsi_id.config",
                conf.as_bytes(),
                0o644,
            ),
        );
    }
    cd(
        "scsi_id",
        h("scsi_id_conf_unreadable", &["/dev/null"])
            .etc_own("scsi_id.config")
            .file("etc/scsi_id.config", b"OPTIONS=-x\n", 0o000)
            .run_as(common::ALICE),
    );
    cd("scsi_id", h("scsi_id_conf_dir", &["/dev/null"]).etc_own("scsi_id.config").dir("etc/scsi_id.config", 0o755));
}

#[test]
fn dmi_memory_id_dumps() {
    let dumps = reference_build().parent().unwrap().join("test/dmidecode-dumps");
    for d in ["HP-Z600", "Lenovo-Thinkcentre-m720s", "Lenovo-ThinkPad-X280"] {
        let path = dumps.join(format!("{d}.bin"));
        let path = path.to_str().unwrap();
        cd("dmi_memory_id", h(&format!("dmi_{d}"), &["-F", path]));
        cd("dmi_memory_id", h(&format!("dmi_{d}_long"), &[&format!("--from-dump={path}")]));
    }
    cd("dmi_memory_id", h("dmi_missing", &["-F", "/nonexistent"]));
    cd("dmi_memory_id", h("dmi_empty", &["-F", "@T@/e"]).file("e", b"", 0o644));
    cd("dmi_memory_id", h("dmi_short", &["-F", "@T@/e"]).file("e", b"_SM3_\x00\x01", 0o644));
    cd("dmi_memory_id", h("dmi_garbage", &["-F", "@T@/e"]).file("e", &[0x5a; 4096], 0o644));
    cd("dmi_memory_id", h("dmi_dir", &["-F", "/"]));
    // The sandbox's own /sys/firmware/dmi (EACCES for nobody, or data).
    cd("dmi_memory_id", h("dmi_live", &[]).run_as(common::ALICE));
}
