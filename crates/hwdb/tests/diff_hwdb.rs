// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential tests for systemd-hwdb: the C build and the port compile
//! the same `hwdb.d` trees (the `hwdb.bin` files must be byte-identical:
//! the snapshot compares them) and query the results.

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::{Case, Program, check, reference_build};

fn prog() -> Program {
    Program {
        name: "systemd-hwdb",
        c: reference_build().join("systemd-hwdb"),
        rust: PathBuf::from(env!("CARGO_BIN_EXE_systemd-hwdb")),
    }
}

/// A case with `/etc/udev`, `/etc/systemd` and `/usr/lib/udev` (and the
/// `/usr/lib/systemd/hwdb` query path) under T.
fn s(name: &str, args: &[&str]) -> Case {
    Case::new(name, args)
        .etc_own("udev")
        .etc_own("systemd")
        .bind("/usr/lib/udev", "usr/lib/udev")
        .bind("/usr/lib/systemd", "usr/lib/systemd")
        .dir("etc/udev", 0o755)
        .dir("usr/lib/udev/hwdb.d", 0o755)
}

fn c(case: Case) {
    check(&prog(), case);
}

/// The case, then the same case with the debug log.
fn cd(case: Case) {
    let name = format!("{}_debug", case.name);
    let mut d = case.clone().env("SYSTEMD_LOG_LEVEL", "debug");
    d.name = name;
    check(&prog(), case);
    check(&prog(), d);
}

/// Some hwdb.d content.
const BASIC: &str = "\
# comment
usb:v1234p*
 ID_VENDOR_FROM_DATABASE=Example
 ID_MODEL_FROM_DATABASE=Gadget

usb:v1234p5678*
usb:v1234p9999*
 ID_MODEL_FROM_DATABASE=Special Gadget
 ID_EXTRA=1

pci:v00008086d*
 ID_VENDOR_FROM_DATABASE=Intel Corporation

evdev:name:*Keyboard*:*
 KEYBOARD_KEY_70039=leftctrl

dmi:bvn*:svnACME:pn[Rr]oad[Rr]unner*
 ID_CHASSIS=laptop

usb:vAB[12]*
 BRACKET=1

usb:vAB?x*
 QUESTION=1

usb:vABZ*
 PLAIN=1
";

/// `s()` with BASIC in /usr/lib/udev/hwdb.d/20-basic.hwdb.
fn basic(name: &str, args: &[&str]) -> Case {
    s(name, args).conf("usr/lib/udev/hwdb.d/20-basic.hwdb", BASIC)
}

// ---------------------------------------------------------------------------
// command line

#[test]
fn command_line() {
    c(s("help", &["--help"]));
    c(s("help_verb", &["help"]));
    c(s("help_verb_args", &["help", "x", "y"]));
    c(s("help_narrow", &["--help"]).env("COLUMNS", "40"));
    c(s("help_wide", &["--help"]).env("COLUMNS", "200"));
    c(s("version", &["--version"]));
    c(s("introspect", &["--introspect-cli"]));
    c(s("no_verb", &[]));
    c(s("unknown_verb", &["frob"]));
    c(s("unknown_verb_prefix", &["up"]));
    c(s("unknown_verb_far", &["zzzzzzzzzzzz"]));
    c(s("query_no_arg", &["query"]));
    c(s("query_too_many", &["query", "a", "b"]));
    c(s("update_too_many", &["update", "x"]));
    c(s("bad_option", &["--frobnicate"]));
    c(s("bad_short", &["-x"]));
    c(s("root_missing_arg", &["update", "--root"]));
    c(s("options_after_verb", &["update", "--strict", "-r", "@T@"]));
}

// ---------------------------------------------------------------------------
// update

#[test]
fn update() {
    cd(basic("update", &["update"]));
    cd(basic("update_root", &["update", "--root=@T@"]));
    cd(basic("update_root_slash", &["update", "--root=/"]));
    cd(basic("update_root_empty", &["update", "--root="]));
    cd(basic("update_root_relative", &["update", "-r", "img"]).conf("img/etc/udev/hwdb.d/a.hwdb", BASIC));
    cd(basic("update_usr", &["update", "--usr"]));
    cd(basic("update_strict", &["update", "--strict"]));
    cd(basic("update_replace", &["update"]).file("etc/udev/hwdb.bin", b"old", 0o644));
    cd(basic("update_bypass", &["update"]).env("SYSTEMD_HWDB_UPDATE_BYPASS", "1"));
    cd(basic("update_bypass_bad", &["update"]).env("SYSTEMD_HWDB_UPDATE_BYPASS", "maybe"));
    cd(s("update_none", &["update"]));
    cd(s("update_none_remove", &["update"]).file("etc/udev/hwdb.bin", b"old", 0o644));
    cd(s("update_none_dir", &["update"]).dir("etc/udev/hwdb.bin", 0o755).file("etc/udev/hwdb.bin/x", b"", 0o644));
    cd(basic("update_no_etc_udev", &["update", "--root=@T@/img"]).conf("img/usr/lib/udev/hwdb.d/a.hwdb", BASIC));
    cd(basic("update_readonly", &["update"]).read_only("/etc/udev"));
    cd(basic("update_parent_is_file", &["update", "--root=@T@/img"])
        .conf("img/usr/lib/udev/hwdb.d/a.hwdb", BASIC)
        .file("img/etc", b"", 0o644));
}

#[test]
fn update_files() {
    // /etc overrides /usr/lib by name; later files win for the same key;
    // masking by an empty file or a /dev/null symlink; non-.hwdb ignored.
    cd(s("files_order", &["update"])
        .conf("usr/lib/udev/hwdb.d/10-a.hwdb", "usb:v1*\n KEY=a\n K2=a\n")
        .conf("usr/lib/udev/hwdb.d/20-b.hwdb", "usb:v1*\n KEY=b\n")
        .conf("etc/udev/hwdb.d/20-b.hwdb", "usb:v1*\n KEY=etc\n")
        .conf("usr/lib/udev/hwdb.d/30-masked.hwdb", "usb:v1*\n KEY=masked\n")
        .conf("etc/udev/hwdb.d/30-masked.hwdb", "")
        .conf("usr/lib/udev/hwdb.d/40-null.hwdb", "usb:v1*\n KEY=null\n")
        .symlink("etc/udev/hwdb.d/40-null.hwdb", "/dev/null")
        .conf("usr/lib/udev/hwdb.d/50-other.txt", "usb:v1*\n KEY=txt\n")
        .conf("usr/lib/udev/hwdb.d/05-first.hwdb", "usb:v1*\n KEY=first\n"));
    cd(s("files_symlink", &["update"])
        .conf("usr/lib/udev/hwdb.d/real.data", "usb:v2*\n KEY=link\n")
        .symlink("usr/lib/udev/hwdb.d/60-link.hwdb", "real.data"));
    cd(s("files_dir_named_hwdb", &["update"])
        .dir("usr/lib/udev/hwdb.d/70-dir.hwdb", 0o755)
        .conf("usr/lib/udev/hwdb.d/80-ok.hwdb", "usb:v3*\n KEY=ok\n"));
    cd(s("files_unreadable", &["update", "--strict"])
        .file("usr/lib/udev/hwdb.d/90-secret.hwdb", b"usb:v4*\n KEY=x\n", 0o000)
        .run_as(common::ALICE)
        .dir_owned("etc/udev", 0o755, 1001, 1001));
}

#[test]
fn update_parsing() {
    for (name, text) in [
        ("indented_first", " KEY=value\nusb:v1*\n KEY=x\n"),
        ("no_properties", "usb:v1*\n\nusb:v2*\n KEY=x\n"),
        ("no_properties_eof", "usb:v1*\n KEY=x\n\nusb:v2*\n"),
        ("no_equals", "usb:v1*\n KEY\n OTHER=1\n"),
        ("empty_key", "usb:v1*\n =value\n    =value\n OK=1\n"),
        ("empty_value", "usb:v1*\n KEY=\n"),
        ("multiple_spaces", "usb:v1*\n     KEY=spaces\n \t KEY2=tab\n\tKEY3=tab_first\n"),
        ("match_after_data", "usb:v1*\n KEY=x\nusb:v2*\n KEY=y\n"),
        ("trailing_comment", "usb:v1*  # comment\n KEY=a#b\n KEY2=c # d\n"),
        ("trailing_space", "usb:v1*   \t\n KEY=value   \n"),
        ("crlf", "usb:v1*\r\n KEY=value\r\n\r\nusb:v2*\r\n KEY=v2\r\n"),
        ("cr_only", "usb:v1*\r KEY=value\r"),
        ("nul", "usb:v1*\n KEY=val\0ue\n"),
        ("equals_in_value", "usb:v1*\n KEY=a=b=c\n"),
        ("comment_in_record", "usb:v1*\n# comment\n KEY=x\n#\n KEY2=y\n"),
        ("same_key_twice", "usb:v1*\n KEY=first\n KEY=second\n"),
        ("many_matches", "usb:v1*\nusb:v2*\nusb:v3*\nusb:v1*\n KEY=x\n"),
        ("no_final_newline", "usb:v1*\n KEY=x"),
        ("only_comments", "# a\n# b\n"),
        ("empty_file", ""),
        ("blank_lines", "\n\n\nusb:v1*\n KEY=x\n\n\n"),
        ("long_line", &format!("usb:v1*\n KEY={}\n", "x".repeat(70000))),
        ("utf8", "usb:v1*\n KEY=Grüße 日本\n"),
        ("high_bytes", "usb:v\u{ff}*\n KEY=x\n"),
        ("prefix_split", "abcdef\n K=1\n\nabcxyz\n K=2\n\nabc\n K=3\n\nab\n K=4\n\nabcdefgh\n K=5\n\na*c\n K=6\n"),
        ("shared_tails", "x:foo\n K=same value\ny:foo\n K=same value\nz:afoo\n K=value\n"),
    ] {
        cd(s(&format!("parse_{name}"), &["update"]).conf("usr/lib/udev/hwdb.d/10-t.hwdb", text));
    }
}

// ---------------------------------------------------------------------------
// query

/// A compiled database to query: made with the C build in the case itself
/// would not compare the port's writer, so each run updates first.
fn q(name: &str, modalias: &str) -> Case {
    basic(name, &["query", modalias])
}

#[test]
fn query() {
    // Each query runs on a database compiled by the same implementation
    // (an update step in a sh -c), so both the writer and reader count.
    for (name, m) in [
        ("exact", "usb:v1234p5678"),
        ("glob_star", "usb:v1234p0001"),
        ("two_records", "usb:v1234p9999d0100"),
        ("pci", "pci:v00008086d00001234sv00001028sd000004AAbc06sc04i00"),
        ("no_match", "usb:vFFFFpFFFF"),
        ("empty", ""),
        ("keyboard", "evdev:name:AT Translated Set 2 Keyboard:phys:isa0060"),
        ("bracket", "dmi:bvnX:svnACME:pnroadRunner2000"),
        ("bracket_no", "dmi:bvnX:svnACME:pnxoadRunner"),
        ("glob_in_query", "usb:v1234p*"),
        ("branch_bracket", "usb:vAB1"),
        ("branch_question", "usb:vAB3x"),
        ("branch_plain", "usb:vABZ"),
    ] {
        let script = format!("systemd-hwdb update && exec systemd-hwdb query '{m}'");
        cd(q(&format!("query_{name}"), m).shell(&script));
    }
}

#[test]
fn query_files() {
    // The query paths, in order, and --root.
    let db = |name: &str, args: &[&str], at: &str| {
        let script = format!(
            "systemd-hwdb update --root=@T@/src && mkdir -p @T@/{at} && mv @T@/src/etc/udev/hwdb.bin @T@/{at}/ && exec systemd-hwdb {}",
            args.join(" ")
        );
        s(name, args).conf("src/usr/lib/udev/hwdb.d/a.hwdb", BASIC).shell(&script)
    };
    cd(db("path_etc_systemd", &["query", "usb:v1234p1"], "etc/systemd/hwdb"));
    cd(db("path_etc_udev", &["query", "usb:v1234p1"], "etc/udev"));
    cd(db("path_usr_systemd", &["query", "usb:v1234p1"], "usr/lib/systemd/hwdb"));
    cd(db("path_usr_udev", &["query", "usb:v1234p1"], "usr/lib/udev"));
    cd(db("path_root", &["query", "--root=@T@/img", "usb:v1234p1"], "img/usr/lib/udev"));
    cd(db("path_root_rel", &["query", "-r", "img", "usb:v1234p1"], "img/etc/udev"));
    cd(db("path_root_missing", &["query", "--root=@T@/none", "usb:v1234p1"], "x"));
    cd(s("path_none", &["query", "usb:v1"]));
    cd(s("path_unreadable", &["query", "usb:v1"]).file("etc/systemd/hwdb/hwdb.bin", b"x", 0o000).run_as(common::ALICE));
    // Corrupt databases.
    let bad = |name: &str, data: Vec<u8>| s(name, &["query", "usb:v1234p1"]).file("etc/udev/hwdb.bin", &data, 0o444);
    cd(bad("bad_short", b"KSLPHHRH".to_vec()));
    cd(bad("bad_signature", vec![b'X'; 200]));
    let mut size = b"KSLPHHRH".to_vec();
    size.extend([0u8; 8]);
    size.extend(999u64.to_le_bytes());
    size.resize(120, 0);
    cd(bad("bad_size", size));
    let mut hdr = b"KSLPHHRH".to_vec();
    hdr.extend(262u64.to_le_bytes());
    hdr.extend(120u64.to_le_bytes());
    for v in [80u64, 24, 16, 32, 5000, 0, 0] {
        hdr.extend(v.to_le_bytes());
    }
    hdr.resize(120, 0);
    cd(bad("bad_root_off", hdr.clone()));
    let mut small = hdr.clone();
    small[32..40].copy_from_slice(&8u64.to_le_bytes());
    cd(bad("bad_node_size", small));
}

#[test]
fn priorities() {
    // A key set by several files: the later file (or line) wins, for
    // exact and glob matches alike.
    let case = |name: &str, m: &str| {
        s(name, &["query", m])
            .conf("usr/lib/udev/hwdb.d/10-a.hwdb", "usb:v1*\n KEY=a-glob\n A=1\n\nusb:v1p2\n KEY=a-exact\n")
            .conf("usr/lib/udev/hwdb.d/20-b.hwdb", "usb:v1p*\n KEY=b-glob\n B=1\n")
            .conf("etc/udev/hwdb.d/15-c.hwdb", "usb:v1p2\n KEY=c-exact\n C=1\nusb:v*\n Z=1\n")
            .shell(&format!("systemd-hwdb update && exec systemd-hwdb query '{m}'"))
    };
    cd(case("prio_exact", "usb:v1p2"));
    cd(case("prio_glob", "usb:v1p3"));
    cd(case("prio_other", "usb:v9"));
}

// ---------------------------------------------------------------------------
// the real database

#[test]
fn system_hwdb() {
    // The installed hwdb.d, compiled: the hwdb.bin files must match.
    let full = |name: &str, args: &[&str]| {
        let mut c = s(name, args);
        for e in std::fs::read_dir("/usr/lib/udev/hwdb.d").unwrap().flatten() {
            let data = std::fs::read(e.path()).unwrap();
            let n = e.file_name().into_string().unwrap();
            c = c.file(&format!("usr/lib/udev/hwdb.d/{n}"), &data, 0o644);
        }
        c
    };
    c(full("system_update", &["update"]));
    for (name, m) in [
        ("usb_hub", "usb:v1D6Bp0002d0606dc09dsc00dp01ic09isc00ip00in00"),
        ("usb_logitech", "usb:v046Dp0825d0010dcEFdsc02dp01ic0Eisc01ip00in00"),
        ("pci_intel", "pci:v00008086d00009A49sv00001028sd00000A38bc03sc00i00"),
        ("acpi", "acpi:PNP0C0A:"),
        ("bluetooth", "bluetooth:v004C"),
        ("keyboard", "evdev:atkbd:dmi:bvnLENOVO:bvr1:bd01/01/2020:svnLENOVO:pn2:pvrThinkPadX220Tablet:rvnLENOVO:rn3:"),
        ("mouse", "mouse:usb:v046dpc603:name:Logitech Mouse:"),
        ("sensor", "sensor:modalias:acpi:BOSC0200:BOSC0200:dmi:bvnX:svnAcer:pnSpin:rnAlien_AP:rvr1:"),
    ] {
        cd(full(&format!("system_query_{name}"), &["query", m])
            .shell(&format!("systemd-hwdb update && exec systemd-hwdb query '{m}'")));
    }
}
