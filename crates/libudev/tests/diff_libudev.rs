// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential tests for libudev.so.1: `probe.c`, built against the C
//! library and against the port (each found by rpath), for both ABIs,
//! runs the same libudev calls in the sandbox; the outputs must match.
//! Real programs that link libudev run against each library too.

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use common::*;

#[derive(Debug)]
struct Setup {
    p64: Program,
    p32: Program,
    consumers: Program,
    lib64: PathBuf,
    lib32: PathBuf,
}

fn build_dir() -> PathBuf {
    let d = repo_dir().join("target/difftest/libudev-bin");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Link the port's libudev.so.1 (both ABIs) and build the probes.
fn setup() -> &'static Setup {
    static S: OnceLock<Setup> = OnceLock::new();
    S.get_or_init(|| {
        let script = repo_dir().join("tools/link-libudev.sh");
        let link = |args: &[&str]| -> PathBuf {
            let out = Command::new(&script).args(args).output().expect("run link-libudev.sh");
            assert!(out.status.success(), "link-libudev.sh {args:?} failed:\n{}", String::from_utf8_lossy(&out.stderr));
            let so = String::from_utf8(out.stdout).unwrap();
            PathBuf::from(so.trim()).parent().unwrap().to_path_buf()
        };
        let lib64 = link(&[]);
        let lib32 = link(&["--target", "i686-unknown-linux-gnu"]);
        let reference = reference_build();
        let c64 = reference.clone();
        let c32 = reference.parent().unwrap().join("build32");
        let dir = build_dir();
        let src = repo_dir().join("crates/libudev/tests/probe.c");
        let inc = repo_dir().join("crates/libudev");
        let probe = |name: &str, libdir: &Path, m32: bool| -> PathBuf {
            let out = dir.join(name);
            let tmp = dir.join(format!("{name}.{}", std::process::id()));
            let mut cmd = Command::new("cc");
            if m32 {
                cmd.arg("-m32");
            }
            let st = cmd
                .args(["-O1", "-Wall", "-Werror", "-Wno-deprecated-declarations", "-I"])
                .arg(&inc)
                .arg("-o")
                .arg(&tmp)
                .arg(&src)
                .arg(format!("-L{}", libdir.display()))
                .arg("-ludev")
                .arg(format!("-Wl,--disable-new-dtags,-rpath,{}", libdir.display()))
                .arg("-lpthread")
                .status()
                .expect("run cc");
            assert!(st.success(), "building {name} failed");
            std::fs::rename(&tmp, &out).unwrap();
            out
        };
        let p64 = Program { name: "probe", c: probe("probe-c", &c64, false), rust: probe("probe-r", &lib64, false) };
        let p32 = Program { name: "probe", c: probe("probe32-c", &c32, true), rust: probe("probe32-r", &lib32, true) };
        // "run PROGRAM ARGS...": the program with the library on LD_LIBRARY_PATH.
        let wrapper = |name: &str, libdir: &Path| -> PathBuf {
            let p = dir.join(name);
            std::fs::write(&p, format!("#!/bin/sh\nLD_LIBRARY_PATH={} exec \"$@\"\n", libdir.display())).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let consumers = Program { name: "run", c: wrapper("run-c", &c64), rust: wrapper("run-r", &lib64) };
        Setup { p64, p32, consumers, lib64, lib32 }
    })
}

fn case(name: &str, args: &[&str]) -> Case {
    Case::new(name, args).no_faketime()
}

/// Run a case on both ABIs.
fn both(c: Case) {
    let s = setup();
    let mut c32 = c.clone();
    c32.name = format!("{}-32", c.name);
    check(&s.p64, c);
    check(&s.p32, c32);
}

// The ABI itself

fn readelf(args: &[&str], file: &Path) -> String {
    let out = Command::new("readelf").args(args).arg(file).output().expect("run readelf");
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// The defined, versioned dynamic symbols: "name@@VERSION".
fn exports(file: &Path) -> Vec<String> {
    let mut v: Vec<String> = readelf(&["--dyn-syms", "-W"], file)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 8 && f[6] != "UND" && f[7].contains('@')).then(|| f[7].to_string())
        })
        .collect();
    v.sort();
    v
}

fn dynamic(file: &Path, tag: &str) -> Vec<String> {
    readelf(&["-d"], file)
        .lines()
        .filter(|l| l.contains(&format!("({tag})")))
        .map(|l| l.rsplit('[').next().unwrap().trim_end_matches(']').to_string())
        .collect()
}

#[test]
fn abi() {
    let s = setup();
    let reference = reference_build();
    for (c, r, loader) in [
        (reference.join("libudev.so.1"), s.lib64.join("libudev.so.1"), "ld-linux-x86-64.so.2"),
        (reference.parent().unwrap().join("build32/libudev.so.1"), s.lib32.join("libudev.so.1"), "ld-linux.so.2"),
    ] {
        let (ce, re) = (exports(&c), exports(&r));
        assert_eq!(ce.len(), 92, "{}", c.display());
        assert_eq!(ce, re, "exported symbols of {} and {}", c.display(), r.display());
        assert_eq!(dynamic(&c, "SONAME"), dynamic(&r, "SONAME"));
        assert_eq!(dynamic(&c, "NEEDED"), vec!["libc.so.6"]);
        // Known difference: libgcc's unwinder (linked in statically) also
        // needs the dynamic loader.
        assert_eq!(dynamic(&r, "NEEDED"), vec!["libc.so.6".to_string(), loader.to_string()]);
    }
}

// The real system: every device, read-only

#[test]
fn real_devices() {
    both(case("real-all", &["log", "7", "enum", "e-scan", "e-dump-attrs"]));
    both(case("real-subsystems", &["log", "7", "enum", "e-scansub", "e-dump-attrs"]));
    both(case("real-init", &["log", "7", "enum", "e-init", "e-scan", "e-list"]));
}

#[test]
fn real_matches() {
    for (name, args) in [
        ("real-block", &["enum", "e-sub", "block", "e-scan", "e-dump"][..]),
        ("real-tag", &["enum", "e-tag", "systemd", "e-scan", "e-list"]),
        ("real-tags", &["enum", "e-tag", "seat", "e-tag", "uaccess", "e-scan", "e-list"]),
        ("real-nomatch", &["enum", "e-nosub", "block", "e-nosub", "net", "e-name", "s*", "e-scan", "e-list"]),
        (
            "real-sysattr",
            &["enum", "e-sub", "net", "e-attr", "address", "*", "e-noattr", "carrier", "0", "e-scan", "e-list"],
        ),
        ("real-property", &["enum", "e-prop", "ID_*", "*USB*", "e-scan", "e-list"]),
        ("real-property-null", &["enum", "e-prop", "ID_BUS", "-", "e-scan", "e-list"]),
        ("real-sound", &["enum", "e-sub", "sound", "e-scan", "e-list"]),
        ("real-modules", &["enum", "e-sub", "module", "e-scansub", "e-list"]),
        ("real-drivers", &["enum", "e-sub", "drivers", "e-scansub", "e-dump"]),
        ("real-buses", &["enum", "e-sub", "subsystem", "e-scansub", "e-dump"]),
        (
            "real-syspaths",
            &["enum", "e-path", "/sys/class/net/lo", "e-path", "/sys/class/mem/null", "e-list", "e-scan", "e-list"],
        ),
        ("real-parent", &["syspath", "/sys/devices/virtual", "enum", "e-parent", "e-sub", "net", "e-scan", "e-list"]),
    ] {
        let mut a = vec!["log", "7"];
        a.extend_from_slice(args);
        both(case(name, &a));
    }
}

#[test]
fn real_lookups() {
    both(case(
        "real-lookups",
        &[
            "log",
            "7",
            "syspath",
            "/sys/class/net/lo",
            "dump-attrs",
            "parents",
            "devnum",
            "c",
            "1:3",
            "dump",
            "devnum",
            "b",
            "1:3",
            "devnum",
            "c",
            "999:3",
            "devnum",
            "x",
            "1:3",
            "devnum",
            "c",
            "0:0",
            "id",
            "c1:3",
            "dump",
            "id",
            "n1",
            "dump",
            "id",
            "n99999",
            "id",
            "n0",
            "id",
            "+net:lo",
            "dump",
            "id",
            "+mem:null",
            "id",
            "+bogus",
            "id",
            "+:",
            "id",
            "x",
            "id",
            "c99999999:1",
            "id",
            "-",
            "subsys",
            "net",
            "lo",
            "dump",
            "subsys",
            "mem",
            "null",
            "subsys",
            "module",
            "kernel",
            "subsys",
            "subsystem",
            "net",
            "subsys",
            "drivers",
            "-",
            "subsys",
            "-",
            "x",
            "subsys",
            "../x",
            "y",
            "subsys",
            "x",
            "../y",
            "syspath",
            "-",
            "syspath",
            "/sys",
            "syspath",
            "/sys/",
            "syspath",
            "/sys/devices",
            "syspath",
            "/proc",
            "syspath",
            "/sys/nonexistent",
            "syspath",
            "/sys/kernel",
            "dump",
            "syspath",
            "/sys/fs/cgroup",
        ],
    ));
}

// A sysfs and udev database made up for the edge cases

fn up(n: usize) -> String {
    "../".repeat(n)
}

const PCI: &str = "sys/devices/pci0000:00/0000:00:1f.2";
const SDA: &str = "sys/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda";

/// The made-up tree: a PCI disk controller with a disk and partition, a
/// network interface, odd misc devices, a CPU, buses, drivers, modules and
/// firmware, plus database files and tags under run/udev.
fn fake(name: &str, args: &[&str]) -> Case {
    let host = format!("{PCI}/host0");
    let target = format!("{host}/target0:0:0");
    let lun = format!("{target}/0:0:0:0");
    let sda1 = format!("{SDA}/sda1");
    let misc = "sys/devices/virtual/misc";
    let mut c = case(name, args)
        .env("SYSTEMD_DEVICE_VERIFY_SYSFS", "0")
        .bind("/sys", "sys")
        .bind("/run/udev", "run/udev")
        .file("sys/devices/pci0000:00/uevent", b"", 0o644)
        .file(&format!("{PCI}/uevent"), b"DRIVER=ahci\nPCI_CLASS=10601\nPCI_ID=8086:A102\nMODALIAS=pci:v00008086d0000A102sv00001458sd0000B005bc01sc06i01\n", 0o644)
        .symlink(&format!("{PCI}/subsystem"), &format!("{}bus/pci", up(3)))
        .symlink(&format!("{PCI}/driver"), &format!("{}bus/pci/drivers/ahci", up(3)))
        .file(&format!("{PCI}/vendor"), b"0x8086\n", 0o444)
        .file(&format!("{PCI}/config"), b"\x86\x80\x02\xa1\x00\x00\x01\n\n", 0o644)
        .file(&format!("{PCI}/hidden"), b"x\n", 0o000)
        .file(&format!("{PCI}/remove"), b"", 0o200)
        .file(&format!("{PCI}/power/control"), b"auto\n", 0o644)
        .file(&format!("{PCI}/power/wakeup"), b"disabled\n", 0o644)
        .file(&format!("{host}/uevent"), b"DEVTYPE=scsi_host\n", 0o644)
        .symlink(&format!("{host}/subsystem"), &format!("{}bus/scsi", up(4)))
        .file(&format!("{target}/uevent"), b"DEVTYPE=scsi_target\n", 0o644)
        .symlink(&format!("{target}/subsystem"), &format!("{}bus/scsi", up(5)))
        .file(&format!("{lun}/uevent"), b"DEVTYPE=scsi_device\nDRIVER=sd\nMODALIAS=scsi:t-0x00\n", 0o644)
        .symlink(&format!("{lun}/subsystem"), &format!("{}bus/scsi", up(6)))
        .file(&format!("{lun}/model"), b"Samsung SSD 870  \n", 0o444)
        .file(&format!("{SDA}/uevent"), b"MAJOR=8\nMINOR=0\nDEVNAME=sda\nDEVTYPE=disk\nDISKSEQ=9\n", 0o644)
        .symlink(&format!("{SDA}/subsystem"), &format!("{}class/block", up(8)))
        .file(&format!("{SDA}/size"), b"1000\n", 0o444)
        .file(&format!("{SDA}/queue/rotational"), b"0\n", 0o644)
        .file(&format!("{sda1}/uevent"), b"MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\nPARTN=1\nPARTNAME=EFI system\n", 0o644)
        .symlink(&format!("{sda1}/subsystem"), &format!("{}class/block", up(9)))
        .file(&format!("{sda1}/partition"), b"1\n", 0o444)
        .file("sys/devices/virtual/net/eth0/uevent", b"INTERFACE=eth0\nIFINDEX=2\n", 0o644)
        .symlink("sys/devices/virtual/net/eth0/subsystem", &format!("{}class/net", up(4)))
        .file("sys/devices/virtual/net/eth0/address", b"52:54:00:12:34:56\n", 0o444)
        .file("sys/devices/virtual/net/eth0/statistics/rx_bytes", b"0\n", 0o444)
        .file(&format!("{misc}/cciss!c0d0/uevent"), b"MAJOR=10\nMINOR=200\nDEVNAME=cciss/c0d0\nDEVMODE=0660\nDEVUID=0\nDEVGID=6\n", 0o644)
        .symlink(&format!("{misc}/cciss!c0d0/subsystem"), &format!("{}class/misc", up(4)))
        .file(&format!("{misc}/1234/uevent"), b"", 0o644)
        .symlink(&format!("{misc}/1234/subsystem"), &format!("{}class/misc", up(4)))
        .file(
            &format!("{misc}/weird7/uevent"),
            b"lowercase=1\nBAD-KEY=x\nNOEQUALS\nGOOD=1\nCTRL=a\x01b\nMAJOR=abc\nMINOR=5\nDEVNAME=../../etc/passwd\nIFINDEX=x\nDEVMODE=99999\nDEVUID=-1\nDISKSEQ=0\nESC=a\\x20b \"q\" *\nQUOTE='x'\n\n\nLAST=1",
            0o644,
        )
        .symlink(&format!("{misc}/weird7/subsystem"), &format!("{}class/misc", up(4)))
        .file(&format!("{misc}/weird7/nul"), b"ab\0cd\n", 0o644)
        .file(&format!("{misc}/weird7/nlnul"), b"ab\n\0cd", 0o644)
        .file(&format!("{misc}/weird7/nl"), b"line\n\n\n", 0o644)
        .file(&format!("{misc}/weird7/empty"), b"", 0o644)
        .symlink(&format!("{misc}/weird7/up"), "../cciss!c0d0")
        .symlink(&format!("{misc}/weird7/out"), "/proc/version")
        .symlink(&format!("{misc}/weird7/driver"), "nowhere")
        .file(&format!("{misc}/nodriver/uevent"), b"DRIVER=\nSUBSYSTEM=misc\n", 0o644)
        .dir(&format!("{misc}/nouevent"), 0o755)
        .file(&format!("{misc}/nouevent/dev"), b"10:1\n", 0o444)
        .symlink(&format!("{misc}/loopy"), "loopy")
        .symlink(&format!("{misc}/outside"), "/tmp")
        .file(&format!("{misc}/notdir"), b"", 0o644)
        .file("sys/devices/system/cpu/cpu0/uevent", b"MODALIAS=cpu:type:x86,ven0000fam0006mod009E:feature:,0000\n", 0o644)
        .symlink("sys/devices/system/cpu/cpu0/subsystem", &format!("{}bus/cpu", up(4)))
        .file("sys/devices/system/cpu/cpu0/online", b"1\n", 0o644)
        .symlink("sys/class/block/sda", &format!("{}{}", up(2), &SDA[4..]))
        .symlink("sys/class/block/sda1", &format!("{}{}", up(2), &sda1[4..]))
        .symlink("sys/class/net/eth0", "../../devices/virtual/net/eth0")
        // An interface with no database entry: not "initialized".
        .file("sys/devices/virtual/net/eth1/uevent", b"INTERFACE=eth1\nIFINDEX=3\n", 0o644)
        .symlink("sys/devices/virtual/net/eth1/subsystem", &format!("{}class/net", up(4)))
        .symlink("sys/class/net/eth1", "../../devices/virtual/net/eth1")
        // md and dm devices sort after the others.
        .file("sys/devices/virtual/block/dm-0/uevent", b"MAJOR=254\nMINOR=0\nDEVNAME=dm-0\nDEVTYPE=disk\n", 0o644)
        .symlink("sys/devices/virtual/block/dm-0/subsystem", &format!("{}class/block", up(4)))
        .file("sys/devices/virtual/block/loop0/uevent", b"MAJOR=7\nMINOR=0\nDEVNAME=loop0\nDEVTYPE=disk\n", 0o644)
        .symlink("sys/devices/virtual/block/loop0/subsystem", &format!("{}class/block", up(4)))
        .file("sys/devices/virtual/block/md127/uevent", b"MAJOR=9\nMINOR=127\nDEVNAME=md127\nDEVTYPE=disk\n", 0o644)
        .symlink("sys/devices/virtual/block/md127/subsystem", &format!("{}class/block", up(4)))
        .symlink("sys/class/block/dm-0", "../../devices/virtual/block/dm-0")
        .symlink("sys/class/block/loop0", "../../devices/virtual/block/loop0")
        .symlink("sys/class/block/md127", "../../devices/virtual/block/md127")
        .symlink("sys/class/misc/cciss!c0d0", "../../devices/virtual/misc/cciss!c0d0")
        .symlink("sys/class/misc/1234", "../../devices/virtual/misc/1234")
        .symlink("sys/class/misc/weird7", "../../devices/virtual/misc/weird7")
        .symlink("sys/class/misc/nouevent", "../../devices/virtual/misc/nouevent")
        .symlink("sys/class/misc/nodriver", "../../devices/virtual/misc/nodriver")
        .symlink("sys/class/misc/loopy", "../../devices/virtual/misc/loopy")
        .file("sys/class/misc/.hidden", b"", 0o644)
        .symlink("sys/dev/block/8:0", &format!("{}{}", up(2), &SDA[4..]))
        .symlink("sys/dev/block/8:1", &format!("{}{}", up(2), &sda1[4..]))
        .symlink("sys/dev/char/10:200", "../../devices/virtual/misc/cciss!c0d0")
        .symlink("sys/dev/char/8:0", &format!("{}{}", up(2), &SDA[4..]))
        .symlink("sys/bus/pci/devices/0000:00:1f.2", &format!("{}{}", up(3), &PCI[4..]))
        .file("sys/bus/pci/uevent", b"", 0o200)
        .file("sys/bus/pci/drivers_autoprobe", b"1\n", 0o644)
        .file("sys/bus/pci/drivers/ahci/uevent", b"", 0o200)
        .file("sys/bus/pci/drivers/ahci/bind", b"", 0o200)
        .symlink("sys/bus/pci/drivers/ahci/module", "../../../../module/ahci")
        .symlink("sys/bus/pci/drivers/ahci/0000:00:1f.2", &format!("{}{}", up(4), &PCI[4..]))
        .file("sys/bus/pci/drivers/pcieport/uevent", b"", 0o200)
        .symlink("sys/bus/scsi/devices/host0", &format!("{}{}", up(3), &host[4..]))
        .symlink("sys/bus/scsi/devices/target0:0:0", &format!("{}{}", up(3), &target[4..]))
        .symlink("sys/bus/scsi/devices/0:0:0:0", &format!("{}{}", up(3), &lun[4..]))
        .file("sys/bus/scsi/drivers/sd/uevent", b"", 0o200)
        .symlink("sys/bus/cpu/devices/cpu0", "../../../devices/system/cpu/cpu0")
        .dir("sys/bus/cpu/drivers", 0o755)
        .file("sys/module/ahci/uevent", b"", 0o200)
        .file("sys/module/ahci/refcnt", b"0\n", 0o444)
        .file("sys/module/ahci/parameters/marvell_enable", b"0\n", 0o644)
        .file("sys/module/usbcore/initstate", b"live\n", 0o444)
        .file("sys/firmware/efi/efivars/x", b"", 0o644)
        .file("sys/kernel/uevent_seqnum", b"1234\n", 0o444)
        .file(
            "run/udev/data/b8:0",
            b"S:disk/by-id/ata-Samsung\nS:disk/by-uuid/1234\nL:10\nI:12345\nE:ID_FS_TYPE=ext4\nE:ID_EMPTY=\nE:.HIDDEN=1\nE:bad-key=1\nE:DEVLINKS=/dev/stale\nG:systemd\nQ:systemd\nG:old\nG:bad/tag\nV:1\nW:7\nX:unknown\nbad line\nE:LAST=no newline",
            0o644,
        )
        .file("run/udev/data/b8:1", b"E:\nE:SWALLOWED=1\nE:ID_PART_ENTRY_NAME=EFI\\x20system\nI:abc\nL:x\nV:x\nS:../../etc\n", 0o644)
        .file("run/udev/data/n2", b"I:1\nE:ID_NET_NAME=eth0\nG:systemd\n", 0o644)
        .file("run/udev/data/+pci:0000:00:1f.2", b"I:5\nE:ID_VENDOR_FROM_DATABASE=Intel Corporation\n", 0o644)
        .file("run/udev/data/c10:200", b"I:7\nS:cciss/c0d0-link\nE:ID_X=\x01ctrl\n", 0o644)
        .file("run/udev/data/+misc:1234", b"", 0o644)
        .file("run/udev/data/+drivers:pci:ahci", b"E:D=1\n", 0o644)
        .file("run/udev/tags/systemd/b8:0", b"", 0o644)
        .file("run/udev/tags/systemd/n2", b"", 0o644)
        .file("run/udev/tags/systemd/+misc:1234", b"", 0o644)
        .file("run/udev/tags/systemd/+bogus:nothing", b"", 0o644)
        .file("run/udev/tags/systemd/.hidden", b"", 0o644)
        .file("run/udev/tags/systemd/x", b"", 0o644)
        .file("run/udev/tags/old/b8:0", b"", 0o644);
    c.env.push(("LC_ALL".into(), "C".into()));
    c
}

#[test]
fn fake_devices() {
    for (name, args) in [
        ("fake-pci", &["syspath", "/sys/bus/pci/devices/0000:00:1f.2", "dump-attrs", "parents"][..]),
        ("fake-sda", &["syspath", "/sys/class/block/sda", "dump-attrs", "parents", "list-name", "rotational"]),
        ("fake-sda1", &["syspath", "/sys/dev/block/8:1", "dump-attrs", "parents"]),
        ("fake-eth0", &["syspath", "/sys/class/net/eth0", "dump-attrs"]),
        ("fake-cciss", &["syspath", "/sys/class/misc/cciss!c0d0", "dump-attrs"]),
        ("fake-number", &["syspath", "/sys/class/misc/1234", "dump-attrs"]),
        ("fake-weird", &["syspath", "/sys/class/misc/weird7", "dump-attrs"]),
        ("fake-nodriver", &["syspath", "/sys/class/misc/nodriver", "dump"]),
        ("fake-cpu", &["syspath", "/sys/bus/cpu/devices/cpu0", "dump-attrs", "parents"]),
        ("fake-root", &["syspath", "/sys/devices/pci0000:00", "dump-attrs", "parents"]),
        ("fake-driver", &["syspath", "/sys/bus/pci/drivers/ahci", "dump-attrs", "parents"]),
        ("fake-drivers", &["syspath", "/sys/bus/pci/drivers", "dump", "parents"]),
        ("fake-bus", &["syspath", "/sys/bus/pci", "dump-attrs", "parents"]),
        ("fake-class", &["syspath", "/sys/class/misc", "dump"]),
        ("fake-module", &["syspath", "/sys/module/ahci", "dump-attrs", "parents"]),
        ("fake-firmware", &["syspath", "/sys/firmware/efi/efivars", "dump-attrs"]),
        ("fake-kernel", &["syspath", "/sys/kernel", "dump"]),
        (
            "fake-bad-paths",
            &[
                "syspath",
                "/sys/class/misc/nouevent",
                "syspath",
                "/sys/class/misc/loopy",
                "syspath",
                "/sys/devices/virtual/misc/outside",
                "syspath",
                "/sys/devices/virtual/misc/notdir",
                "syspath",
                "/sys/class/misc/.hidden",
                "syspath",
                "/sys/class/nothing",
                "syspath",
                "sys/class/net/eth0",
                "syspath",
                "/sys/../sys/class/net/eth0",
                "dump",
            ],
        ),
    ] {
        let mut a = vec!["log", "7"];
        a.extend_from_slice(args);
        both(fake(name, &a));
    }
}

#[test]
fn fake_lookups() {
    both(fake(
        "fake-lookups",
        &[
            "log",
            "7",
            "devnum",
            "b",
            "8:0",
            "dump",
            "devnum",
            "c",
            "8:0",
            "devnum",
            "b",
            "8:1",
            "devnum",
            "c",
            "10:200",
            "dump",
            "devnum",
            "b",
            "10:200",
            "devnum",
            "b",
            "9:9",
            "id",
            "b8:0",
            "id",
            "b8:1",
            "id",
            "+pci:0000:00:1f.2",
            "dump",
            "id",
            "+drivers:pci:ahci",
            "dump",
            "id",
            "+drivers:pci:drivers",
            "dump",
            "id",
            "+drivers:pci",
            "id",
            "+drivers:pci:",
            "id",
            "+misc:cciss!c0d0",
            "dump",
            "id",
            "+module:ahci",
            "dump",
            "id",
            "+subsystem:pci",
            "dump",
            "id",
            "+subsystem:misc",
            "dump",
            "id",
            "+efi:efivars",
            "dump",
            "id",
            "+scsi:0:0:0:0",
            "dump",
            "subsys",
            "misc",
            "cciss/c0d0",
            "subsys",
            "misc",
            "cciss!c0d0",
            "subsys",
            "drivers",
            "pci:ahci",
            "subsys",
            "drivers",
            "scsi:sd",
            "subsys",
            "drivers",
            "pci:nope",
            "subsys",
            "cpu",
            "cpu0",
            "subsys",
            "net",
            "eth0",
            "subsys",
            "block",
            "sda1",
            "subsys",
            "module",
            "usbcore",
            "dump-attrs",
            "subsys",
            "subsystem",
            "scsi",
            "dump",
            "id",
            "n2",
        ],
    ));
}

#[test]
fn fake_attributes() {
    both(fake(
        "fake-attrs",
        &[
            "log",
            "7",
            "syspath",
            "/sys/class/misc/weird7",
            "attr",
            "nul",
            "attr",
            "nlnul",
            "attr",
            "nl",
            "attr",
            "empty",
            "attr",
            "up",
            "attr",
            "up/uevent",
            "attr",
            "out",
            "attr",
            "driver",
            "attr",
            "subsystem",
            "attr",
            "module",
            "attr",
            "nope",
            "attr",
            "nope",
            "attr",
            "../cciss!c0d0/dev",
            "attr",
            "uevent",
            "attr",
            "./nl",
            "attr",
            "nl/",
            "attr",
            "-",
            "attr",
            "",
            "attr",
            "/sys/class/misc/1234/uevent",
            "attr",
            "/proc/version",
            "syspath",
            "/sys/bus/pci/devices/0000:00:1f.2",
            "attr",
            "driver",
            "attr",
            "subsystem",
            "attr",
            "module",
            "attr",
            "config",
            "attr",
            "hidden",
            "attr",
            "remove",
            "attr",
            "power/control",
            "attr",
            "vendor",
            "attr",
            "vendor",
            "syspath",
            "/sys/bus/pci/drivers/ahci",
            "attr",
            "module",
            "attr",
            "driver",
            "attr",
            "uevent",
        ],
    ));
}

#[test]
fn fake_set_attributes() {
    both(fake(
        "fake-setattr",
        &[
            "log",
            "7",
            "syspath",
            "/sys/class/misc/weird7",
            "attr",
            "nl",
            "setattr",
            "nl",
            "new value\n\n",
            "attr",
            "nl",
            "setattr",
            "nl",
            "-",
            "attr",
            "nl",
            "setattr",
            "empty",
            "",
            "attr",
            "empty",
            "setattr",
            "created",
            "x",
            "setattr",
            "up/remove",
            "1",
            "setattr",
            "../1234/uevent",
            "change",
            "attr",
            "../1234/uevent",
            "setattr",
            "out",
            "x",
            "setattr",
            "-",
            "x",
            "setattr",
            "uevent",
            "add",
            "attr",
            "uevent",
            "syspath",
            "/sys/bus/pci/devices/0000:00:1f.2",
            "setattr",
            "power/control",
            "on",
            "attr",
            "power/control",
            "setattr",
            "vendor",
            "0x1234",
            "attr",
            "vendor",
        ],
    ));
    // A long value is cut at 4096 bytes.
    let long = "y".repeat(5000);
    both(fake("fake-setattr-long", &["syspath", "/sys/class/misc/weird7", "setattr", "nl", &long, "attr", "nl"]));
}

#[test]
fn fake_database() {
    both(fake(
        "fake-db",
        &[
            "log",
            "7",
            "syspath",
            "/sys/class/block/sda",
            "prop",
            "ID_FS_TYPE",
            "prop",
            "ID_EMPTY",
            "prop",
            ".HIDDEN",
            "prop",
            "LAST",
            "prop",
            "DEVLINKS",
            "prop",
            "TAGS",
            "prop",
            "CURRENT_TAGS",
            "prop",
            "USEC_INITIALIZED",
            "prop",
            "MAJOR",
            "prop",
            "-",
            "tag",
            "systemd",
            "tag",
            "old",
            "tag",
            "nope",
            "ctag",
            "systemd",
            "ctag",
            "old",
            "tag",
            "-",
            "ctag",
            "-",
            "syspath",
            "/sys/class/block/sda1",
            "dump",
            "syspath",
            "/sys/class/misc/cciss!c0d0",
            "dump",
            "syspath",
            "/sys/class/misc/1234",
            "dump",
            "syspath",
            "/sys/bus/pci/drivers/ahci",
            "dump",
            "syspath",
            "/sys/class/net/eth0",
            "dump",
        ],
    ));
}

#[test]
fn fake_enumerate() {
    for (name, args) in [
        ("fake-enum-all", &["enum", "e-scan", "e-dump"][..]),
        ("fake-enum-init", &["enum", "e-init", "e-scan", "e-list"]),
        ("fake-enum-sub", &["enum", "e-sub", "block", "e-sub", "mi?c", "e-scan", "e-list"]),
        ("fake-enum-nosub", &["enum", "e-nosub", "block", "e-scan", "e-list"]),
        ("fake-enum-name", &["enum", "e-name", "sd*", "e-name", "eth0", "e-scan", "e-list"]),
        ("fake-enum-attr", &["enum", "e-attr", "size", "1000", "e-scan", "e-list"]),
        ("fake-enum-attr-glob", &["enum", "e-attr", "size", "1*", "e-attr", "size", "2*", "e-scan", "e-list"]),
        ("fake-enum-attr-any", &["enum", "e-attr", "partition", "-", "e-scan", "e-list"]),
        ("fake-enum-attr-clear", &["enum", "e-attr", "size", "9", "e-attr", "size", "-", "e-scan", "e-list"]),
        ("fake-enum-noattr", &["enum", "e-sub", "block", "e-noattr", "partition", "-", "e-scan", "e-list"]),
        ("fake-enum-prop", &["enum", "e-prop", "DEVTYPE", "disk", "e-prop", "PARTN", "*", "e-scan", "e-list"]),
        ("fake-enum-prop-null", &["enum", "e-prop", "ID_FS_TYPE", "-", "e-scan", "e-list"]),
        ("fake-enum-tag", &["enum", "e-tag", "systemd", "e-scan", "e-dump"]),
        ("fake-enum-tags", &["enum", "e-tag", "systemd", "e-tag", "old", "e-scan", "e-list"]),
        ("fake-enum-tag-sub", &["enum", "e-tag", "systemd", "e-sub", "block", "e-scan", "e-list"]),
        ("fake-enum-tag-none", &["enum", "e-tag", "none", "e-scan", "e-list"]),
        ("fake-enum-parent", &["syspath", "/sys/bus/pci/devices/0000:00:1f.2", "enum", "e-parent", "e-scan", "e-list"]),
        (
            "fake-enum-parent-sub",
            &[
                "syspath",
                "/sys/devices/pci0000:00",
                "enum",
                "e-parent",
                "e-sub",
                "block",
                "e-name",
                "sd*",
                "e-scan",
                "e-list",
            ],
        ),
        ("fake-enum-parent-null", &["null", "enum", "e-parent", "e-scan", "e-list"]),
        (
            "fake-enum-parents2",
            &[
                "syspath",
                "/sys/class/block/sda",
                "enum",
                "e-parent",
                "syspath",
                "/sys/class/net/eth0",
                "e-parent",
                "e-scan",
                "e-list",
            ],
        ),
        ("fake-enum-subsystems", &["enum", "e-scansub", "e-dump-attrs"]),
        ("fake-enum-subsystems-drivers", &["enum", "e-sub", "drivers", "e-scansub", "e-list"]),
        ("fake-enum-subsystems-module", &["enum", "e-sub", "module", "e-scansub", "e-list"]),
        (
            "fake-enum-paths",
            &[
                "enum",
                "e-path",
                "/sys/class/net/eth0",
                "e-path",
                "/sys/class/misc/nouevent",
                "e-path",
                "-",
                "e-list",
                "e-scan",
                "e-list",
            ],
        ),
        (
            "fake-enum-rescan",
            &[
                "enum",
                "e-scan",
                "e-list",
                "e-sub",
                "net",
                "e-list",
                "e-scan",
                "e-list",
                "e-scansub",
                "e-list",
                "e-scan",
                "e-list",
            ],
        ),
        (
            "fake-enum-null-args",
            &[
                "enum", "e-sub", "-", "e-nosub", "-", "e-attr", "-", "x", "e-noattr", "-", "x", "e-prop", "-", "x",
                "e-tag", "-", "e-name", "-", "e-scan", "e-list", "e-udev",
            ],
        ),
        ("fake-enum-noscan", &["enum", "e-list", "e-path", "/sys/class/net/eth0", "e-list"]),
    ] {
        let mut a = vec!["log", "7"];
        a.extend_from_slice(args);
        both(fake(name, &a));
    }
}

#[test]
fn fake_environment() {
    both(fake(
        "fake-env",
        &[
            "log",
            "7",
            "env",
            "clearenv",
            "putenv",
            "ACTION=add",
            "putenv",
            "DEVPATH=/devices/virtual/net/eth0",
            "env",
            "putenv",
            "SUBSYSTEM=net",
            "env",
            "putenv",
            "SEQNUM=42",
            "putenv",
            "IFINDEX=2",
            "putenv",
            "INTERFACE=eth0",
            "putenv",
            "DEVLINKS=/dev/a /dev/b\\x20c b",
            "putenv",
            "TAGS=:systemd::seat:",
            "putenv",
            "CURRENT_TAGS=:seat:",
            "putenv",
            "USEC_INITIALIZED=100",
            "putenv",
            "ID_X=1",
            "putenv",
            "bad-key=1",
            "putenv",
            "DEVMODE=0600",
            "putenv",
            "DEVUID=0",
            "putenv",
            "DEVGID=5",
            "putenv",
            "UDEV_DATABASE_VERSION=1",
            "putenv",
            "DISKSEQ=3",
            "putenv",
            "DRIVER=e1000",
            "putenv",
            "DEVTYPE=wlan",
            "env",
            "dump",
            "tag",
            "systemd",
            "ctag",
            "systemd",
            "attr",
            "address",
            "putenv",
            "ACTION=bogus",
            "env",
            "putenv",
            "ACTION=change",
            "putenv",
            "SEQNUM=0",
            "env",
            "putenv",
            "SEQNUM=x",
            "env",
            "putenv",
            "SEQNUM=7",
            "putenv",
            "MAJOR=8",
            "putenv",
            "MINOR=1x",
            "env",
            "putenv",
            "MINOR=1",
            "putenv",
            "DEVNAME=sda1",
            "env",
            "dump",
            "putenv",
            "SUBSYSTEM=drivers",
            "putenv",
            "DEVPATH=/bus/pci/drivers/ahci",
            "env",
            "dump",
            "putenv",
            "DEVPATH=/devices/x",
            "env",
            "putenv",
            "DEVPATH=x",
            "env",
            "putenv",
            "TAGS=:bad/tag:",
            "env",
            "putenv",
            "TAGS=",
            "putenv",
            "DEVLINKS=/etc/x",
            "env",
            "putenv",
            "DEVLINKS=",
            "putenv",
            "IFINDEX=-1",
            "env",
            "putenv",
            "IFINDEX=2",
            "putenv",
            "USEC_INITIALIZED=x",
            "env",
        ],
    ));
    // With no environment at all (environ is NULL), C asserts and aborts.
    both(fake("fake-env-none", &["log", "7", "clearenv", "env", "dump"]));
}

#[test]
fn lists() {
    both(fake(
        "lists",
        &[
            "syspath",
            "/sys/class/block/sda",
            "props",
            "list-name",
            "ID_FS_TYPE",
            "list-name",
            "nope",
            "list-first",
            "list-next",
            "attrs",
            "list-name",
            "size",
            "list-next",
            "enum",
            "e-sub",
            "block",
            "e-scan",
            "e-list",
            "list-name",
            "/sys/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda",
            "list-next",
            "hwdb",
            "usb:v1D6Bp0002",
            "list-name",
            "ID_VENDOR_FROM_DATABASE",
            "list-next",
        ],
    ));
}

#[test]
fn misc() {
    both(case("nulls", &["log", "7", "nulls", "syspath", "/sys/class/mem/null", "nulls"]));
    both(case("refs", &["log", "7", "syspath", "/sys/class/mem/null", "refs"]));
    both(case(
        "threads",
        &["syspath", "/sys/class/mem/null", "parent", "thread-unref", "syspath", "/sys/class/net/lo", "thread-unref"],
    ));
    both(case(
        "encode",
        &[
            "encode",
            "plain",
            "64",
            "encode",
            "a b/c\\d",
            "64",
            "encode",
            "é€😀",
            "64",
            "encode",
            "\u{1}\u{7f}x",
            "64",
            "encode",
            "abc",
            "3",
            "encode",
            "abc",
            "4",
            "encode",
            "a b",
            "4",
            "encode",
            "a b",
            "5",
            "encode",
            "a b",
            "6",
            "encode",
            "é",
            "2",
            "encode",
            "é",
            "3",
            "encode",
            "",
            "1",
            "encode",
            "",
            "0",
            "encode",
            "-",
            "8",
            "encode",
            "x",
            "0",
            "encode",
            "#+-.:=@_",
            "64",
        ],
    ));
    both(case(
        "log-levels",
        &["log", "0", "log", "7", "log", "-1", "syspath", "/nonexistent", "log", "3", "syspath", "/nonexistent"],
    ));
}

#[test]
fn hwdb() {
    let lookups = [
        "hwdb",
        "usb:v1D6Bp0002",
        "hwdb",
        "usb:v046DpC52B*",
        "hwdb",
        "pci:v00008086d00001234",
        "hwdb",
        "pci:v00008086",
        "hwdb",
        "evdev:input:b0003v046DpC52B",
        "hwdb",
        "nothing:at:all",
        "hwdb",
        "",
        "hwdb",
        "-",
        "hwdb-null",
    ];
    let mut a = vec!["log", "7"];
    a.extend_from_slice(&lookups);
    both(case("hwdb-real", &a));
    // No database at all: /etc/udev is the case's own, and empty.
    both(case("hwdb-none", &["log", "7", "hwdb", "usb:v1D6Bp0002", "hwdb-null"]).etc_own("udev"));
    // A corrupt one.
    both(case("hwdb-corrupt", &["log", "7", "hwdb", "usb:v1D6Bp0002"]).etc_own("udev").file(
        "etc/udev/hwdb.bin",
        b"KSLPHHRH\0\0\0\0\0\0\0\0garbage",
        0o444,
    ));
}

#[test]
fn queue() {
    let q = &["log", "7", "queue"][..];
    both(fake("queue-none", q));
    both(fake("queue-active", q).file("run/udev/control", b"", 0o644));
    both(fake("queue-busy", q).file("run/udev/control", b"", 0o644).file("run/udev/queue", b"", 0o644));
}

// The monitor, in a network namespace of its own, fed crafted messages.

fn mon(name: &str, args: &[&str]) -> Case {
    let mut a = vec!["log", "7"];
    a.extend_from_slice(args);
    fake(name, &a).netns().file("run/udev/control", b"", 0o644)
}

const ADD_SDA: &str = "ACTION=add|DEVPATH=/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda|SUBSYSTEM=block|SEQNUM=100|MAJOR=8|MINOR=0|DEVNAME=sda|DEVTYPE=disk|TAGS=:systemd:|CURRENT_TAGS=:systemd:|DEVLINKS=/dev/disk/by-id/x /dev/disk/by-id/y|ID_FS_TYPE=ext4|USEC_INITIALIZED=99";
const ADD_ETH: &str =
    "ACTION=change|DEVPATH=/devices/virtual/net/eth0|SUBSYSTEM=net|SEQNUM=101|INTERFACE=eth0|IFINDEX=2";

#[test]
fn monitor() {
    for (name, args) in [
        ("mon-names", &["mon", "udev", "m-fd", "mon", "kernel", "m-fd", "mon", "-", "m-fd", "mon", "bogus"][..]),
        (
            "mon-udev",
            &[
                "mon", "udev", "m-enable", "nl-udev", "2", "block", "disk", "systemd", ADD_SDA, "m-recv", "1000",
                "m-recv", "100",
            ],
        ),
        (
            "mon-udev-sub",
            &[
                "mon", "udev", "m-sub", "net", "-", "m-enable", "nl-udev", "2", "block", "disk", "systemd", ADD_SDA,
                "nl-udev", "2", "net", "-", "-", ADD_ETH, "m-recv", "1000", "m-recv", "100",
            ],
        ),
        (
            "mon-udev-devtype",
            &[
                "mon",
                "udev",
                "m-sub",
                "block",
                "partition",
                "m-sub",
                "block",
                "disk",
                "m-enable",
                "nl-udev",
                "2",
                "block",
                "disk",
                "-",
                ADD_SDA,
                "m-recv",
                "1000",
            ],
        ),
        (
            "mon-udev-devtype-miss",
            &[
                "mon",
                "udev",
                "m-sub",
                "block",
                "partition",
                "m-enable",
                "nl-udev",
                "2",
                "block",
                "disk",
                "-",
                ADD_SDA,
                "m-recv",
                "300",
            ],
        ),
        (
            "mon-udev-tag",
            &[
                "mon", "udev", "m-tag", "seat", "m-tag", "systemd", "m-enable", "nl-udev", "2", "net", "-", "-",
                ADD_ETH, "nl-udev", "2", "block", "disk", "systemd", ADD_SDA, "m-recv", "1000", "m-recv", "100",
            ],
        ),
        (
            "mon-udev-tag-userspace",
            &[
                "mon",
                "udev",
                "m-tag",
                "systemd",
                "m-enable",
                "nl-udev",
                "2",
                "block",
                "disk",
                "systemd",
                ACTION_NO_TAG,
                "m-recv",
                "1000",
                "m-recv",
                "100",
            ],
        ),
        (
            "mon-udev-remove",
            &[
                "mon", "udev", "m-sub", "net", "-", "m-enable", "m-remove", "nl-udev", "2", "block", "disk", "systemd",
                ADD_SDA, "m-recv", "1000",
            ],
        ),
        (
            "mon-udev-noupdate",
            &[
                "mon", "udev", "m-sub", "net", "-", "nl-udev", "2", "block", "disk", "systemd", ADD_SDA, "m-recv",
                "1000",
            ],
        ),
        ("mon-udev-sub-null", &["mon", "udev", "m-sub", "-", "x", "m-tag", "-", "m-update"]),
        ("mon-udev-buf", &["mon", "udev", "m-buf", "1048576", "m-buf", "-1"]),
        ("mon-udev-badmagic", &["mon", "udev", "m-enable", "nl-badmagic", "2", "m-recv", "1000"]),
        (
            "mon-udev-garbage",
            &[
                "mon",
                "udev",
                "m-enable",
                "nl-raw",
                "2",
                "short",
                "m-recv",
                "1000",
                "nl-raw",
                "2",
                "no nul at all in this message, still long enough",
                "m-recv",
                "1000",
                "nl-raw",
                "2",
                "no header|ACTION=add|DEVPATH=/x|SUBSYSTEM=x|SEQNUM=1|",
                "m-recv",
                "1000",
            ],
        ),
        (
            "mon-udev-incomplete",
            &[
                "mon",
                "udev",
                "m-enable",
                "nl-udev",
                "2",
                "block",
                "-",
                "-",
                "ACTION=add|SUBSYSTEM=block|SEQNUM=1|DEVNAME=sda|MAJOR=8",
                "m-recv",
                "1000",
                "nl-udev",
                "2",
                "block",
                "-",
                "-",
                "DEVPATH=/devices/x|SUBSYSTEM=block|SEQNUM=1|ACTION=nope",
                "m-recv",
                "1000",
                "nl-udev",
                "2",
                "block",
                "-",
                "-",
                "DEVPATH=/devices/x|SUBSYSTEM=block|SEQNUM=1|ACTION=add|MAJOR=x",
                "m-recv",
                "1000",
                "nl-udev",
                "2",
                "block",
                "-",
                "-",
                "DEVPATH=/devices/x|SUBSYSTEM=block|SEQNUM=1|ACTION=add|BAD KEY=1|NL=a\nb",
                "m-recv",
                "1000",
            ],
        ),
        (
            "mon-udev-unicast",
            &["mon", "udev", "m-enable", "nl-udev", "self", "block", "disk", "systemd", ADD_SDA, "m-recv", "1000"],
        ),
        (
            "mon-udev-from-kernel-group",
            &["mon", "udev", "m-enable", "nl-kernel", "2", "add@/devices/virtual/net/eth0", ADD_ETH, "m-recv", "1000"],
        ),
        (
            "mon-kernel",
            &[
                "mon",
                "kernel",
                "m-enable",
                "nl-kernel",
                "1",
                "add@/devices/virtual/net/eth0",
                ADD_ETH,
                "m-recv",
                "1000",
            ],
        ),
        (
            "mon-kernel-filter",
            &[
                "mon",
                "kernel",
                "m-sub",
                "block",
                "-",
                "m-enable",
                "nl-kernel",
                "self",
                "change@/devices/virtual/net/eth0",
                ADD_ETH,
                "m-recv",
                "1000",
            ],
        ),
        (
            "mon-none",
            &[
                "mon",
                "-",
                "m-enable",
                "nl-udev",
                "2",
                "block",
                "disk",
                "systemd",
                ADD_SDA,
                "m-recv",
                "300",
                "m-recv-now",
            ],
        ),
        ("mon-empty", &["mon", "udev", "m-enable", "m-recv-now", "m-recv-now"]),
    ] {
        both(mon(name, args));
    }
    // Without /run/udev/control, but /dev is devtmpfs: the udev group stays.
    both(
        fake(
            "mon-nocontrol",
            &[
                "log", "7", "mon", "udev", "m-enable", "nl-udev", "2", "block", "disk", "systemd", ADD_SDA, "m-recv",
                "1000",
            ],
        )
        .netns(),
    );
}

const ACTION_NO_TAG: &str = "ACTION=add|DEVPATH=/devices/virtual/net/eth0|SUBSYSTEM=net|SEQNUM=5";

// Real programs

/// Every lsblk column (lsblk 2.41) but the mount ones.
const LSBLK_COLUMNS: &str = "NAME,KNAME,PATH,MAJ:MIN,FSTYPE,FSVER,LABEL,UUID,PTUUID,PTTYPE,PARTTYPE,PARTTYPENAME,\
PARTLABEL,PARTUUID,PARTN,PARTFLAGS,RA,RO,RM,HOTPLUG,MODEL,SERIAL,SIZE,STATE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,\
OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,TYPE,DISC-ALN,DISC-GRAN,DISC-MAX,DISC-ZERO,WSAME,WWN,RAND,PKNAME,HCTL,\
TRAN,SUBSYSTEMS,REV,VENDOR,ZONED,DAX,ID-LINK,ID,DISK-SEQ";

#[test]
fn consumers() {
    let s = setup();
    for (name, args) in [
        // (Not the mount columns: the sandbox's own mounts differ per run.)
        ("lsblk", &["lsblk", "-J", "-o", LSBLK_COLUMNS][..]),
        ("findmnt", &["findmnt", "-o", "SOURCE,FSTYPE,UUID,LABEL,PARTUUID", "/"]),
        ("lsusb", &["lsusb"]),
        ("lsusb-tree", &["lsusb", "-t"]),
        ("lsusb-verbose", &["lsusb", "-v"]),
        ("libinput", &["libinput", "list-devices"]),
    ] {
        if Command::new("sh")
            .args(["-c", &format!("command -v {}", args[0])])
            .output()
            .is_ok_and(|o| !o.status.success())
        {
            eprintln!("skipping {name}: {} not installed", args[0]);
            continue;
        }
        check(&s.consumers, case(&format!("consumer-{name}"), args));
    }
}
