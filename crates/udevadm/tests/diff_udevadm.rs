// SPDX-License-Identifier: GPL-2.0-or-later
//! Differential tests for udevadm: help and introspection, `verify` and
//! `cat` on rules trees, `test` on upstream's fake sysfs
//! (`test/sys-script.py`) with upstream's rule sets
//! (`test/test-udev.py`, via `tools/udev-test-rules.py`) and more, and
//! `info` on the fake sysfs and a made-up udev database.

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{Case, Program, check, reference_build, repo_dir};

fn prog() -> Program {
    Program {
        name: "udevadm",
        c: reference_build().join("udevadm"),
        rust: PathBuf::from(env!("CARGO_BIN_EXE_udevadm")),
    }
}

fn source_dir() -> PathBuf {
    reference_build().parent().unwrap().to_path_buf()
}

fn fixture_dir() -> PathBuf {
    repo_dir().join("target/difftest/.udev-fixture")
}

/// The fake sysfs, made once: `<fixture>/sys`.
fn sysfs() -> &'static Path {
    static D: OnceLock<PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let dir = fixture_dir();
        let sys = dir.join("sys");
        if !sys.join("devices").exists() {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let st = std::process::Command::new("python3")
                .arg("-I")
                .arg(source_dir().join("test/sys-script.py"))
                .arg(&dir)
                .current_dir(&dir)
                .status()
                .unwrap();
            assert!(st.success(), "sys-script.py failed");
        }
        sys
    })
}

/// One of upstream's rule sets.
#[derive(Debug, Clone)]
struct RuleSet {
    desc: String,
    rules: String,
    devpaths: Vec<String>,
}

/// Upstream's rule sets, extracted from the reference's test-udev.py.
fn rule_sets() -> &'static [RuleSet] {
    static R: OnceLock<Vec<RuleSet>> = OnceLock::new();
    R.get_or_init(|| {
        let out = std::process::Command::new("python3")
            .arg("-I")
            .arg(repo_dir().join("tools/udev-test-rules.py"))
            .arg(source_dir())
            .arg(sysfs().parent().unwrap())
            .output()
            .unwrap();
        assert!(out.status.success(), "udev-test-rules.py failed");
        parse_rule_sets(&String::from_utf8(out.stdout).unwrap())
    })
}

/// A minimal reader for the JSON the extractor prints.
fn parse_rule_sets(json: &str) -> Vec<RuleSet> {
    let v = Json::parse(json);
    let Json::Arr(sets) = v else { panic!("not an array") };
    sets.into_iter()
        .map(|s| {
            let Json::Obj(o) = s else { panic!("not an object") };
            let get = |k: &str| o.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
            let Json::Str(desc) = get("desc") else { panic!() };
            let Json::Str(rules) = get("rules") else { panic!() };
            let Json::Arr(devs) = get("devices") else { panic!() };
            let devpaths = devs
                .into_iter()
                .map(|d| {
                    let Json::Obj(o) = d else { panic!() };
                    match o.into_iter().find(|(n, _)| n == "devpath").unwrap().1 {
                        Json::Str(p) => p,
                        _ => panic!(),
                    }
                })
                .collect();
            RuleSet { desc, rules, devpaths }
        })
        .collect()
}

#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool,
    Num,
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(s: &str) -> Json {
        let b = s.as_bytes();
        let mut i = 0;
        Json::value(b, &mut i)
    }
    fn ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }
    fn value(b: &[u8], i: &mut usize) -> Json {
        Json::ws(b, i);
        match b[*i] {
            b'{' => {
                *i += 1;
                let mut o = Vec::new();
                loop {
                    Json::ws(b, i);
                    if b[*i] == b'}' {
                        *i += 1;
                        return Json::Obj(o);
                    }
                    let Json::Str(k) = Json::value(b, i) else { panic!("key") };
                    Json::ws(b, i);
                    assert_eq!(b[*i], b':');
                    *i += 1;
                    let v = Json::value(b, i);
                    o.push((k, v));
                    Json::ws(b, i);
                    if b[*i] == b',' {
                        *i += 1;
                    }
                }
            }
            b'[' => {
                *i += 1;
                let mut a = Vec::new();
                loop {
                    Json::ws(b, i);
                    if b[*i] == b']' {
                        *i += 1;
                        return Json::Arr(a);
                    }
                    a.push(Json::value(b, i));
                    Json::ws(b, i);
                    if b[*i] == b',' {
                        *i += 1;
                    }
                }
            }
            b'"' => {
                *i += 1;
                let mut out: Vec<u8> = Vec::new();
                while b[*i] != b'"' {
                    if b[*i] == b'\\' {
                        *i += 1;
                        match b[*i] {
                            b'n' => out.push(b'\n'),
                            b't' => out.push(b'\t'),
                            b'r' => out.push(b'\r'),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'u' => {
                                let h = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                                let c = char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap();
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                                *i += 4;
                            }
                            c => out.push(c),
                        }
                    } else {
                        out.push(b[*i]);
                    }
                    *i += 1;
                }
                *i += 1;
                Json::Str(String::from_utf8(out).unwrap())
            }
            b't' | b'f' => {
                *i += if b[*i] == b't' { 4 } else { 5 };
                Json::Bool
            }
            b'n' => {
                *i += 4;
                Json::Null
            }
            _ => {
                while *i < b.len() && (b[*i] == b'-' || b[*i].is_ascii_digit() || b[*i] == b'.') {
                    *i += 1;
                }
                Json::Num
            }
        }
    }
}

/// Mask what is the same by design but can't match yet: the builtins'
/// init and exit logging (the builtins are phase 7), and initialization
/// timestamps taken from `CLOCK_MONOTONIC`.
fn mask(s: &str) -> String {
    let mut out = String::new();
    let mut in_builtins = false;
    for l in s.split_inclusive('\n') {
        let t = l.trim_end_matches(['\n', '\r']);
        if t.ends_with("Loading builtins...") {
            in_builtins = true;
            out.push_str(l);
            continue;
        }
        if t.ends_with("Loading builtins done.") {
            in_builtins = false;
        }
        // CPUID leaf 1 carries the APIC ID of the CPU we happen to run on.
        // The forked child's own log line races with the parent's.
        if in_builtins
            || t.starts_with("PR_SET_MM_ARG_START failed")
            || t.starts_with("CPUID result ")
            || is_set_element_trace(t)
            || t.ends_with("Unloaded hardware database.")
            || t.ends_with("Unloaded kernel module index.")
            || t.ends_with("Unloaded link configuration context.")
        {
            continue;
        }
        out.push_str(&mask_usec(l));
    }
    sort_sets(&out)
}

/// C keeps devlinks and tags in hash sets whose order changes from run to
/// run; the port keeps them sorted.  Sort them in C's output too: the
/// words of DEVLINKS=, TAGS= and CURRENT_TAGS=, and the lines of the
/// "Device node symlinks:", "Tags:" and "Current Tags:" blocks.
fn sort_sets(s: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut block: Vec<String> = Vec::new();
    let mut in_block = false;
    let mut in_out = false;
    let flush = |out: &mut Vec<String>, block: &mut Vec<String>| {
        block.sort();
        out.append(block);
    };
    for l in s.split_inclusive('\n') {
        let t = l.trim_end_matches(['\n', '\r']);
        if in_block && t.starts_with("  ") && !t.starts_with("   ") {
            block.push(l.to_string());
            continue;
        }
        if in_block {
            flush(&mut out, &mut block);
            in_block = false;
        }
        if is_callout_output(t) {
            // Whether a callout's stdout or stderr is read first is a race,
            // in C too: sort each run of them.
            if !in_out {
                flush(&mut out, &mut block);
                in_out = true;
            }
            block.push(l.to_string());
            continue;
        }
        if in_out {
            flush(&mut out, &mut block);
            in_out = false;
        }
        if t.contains("Device node symlinks:")
            || t.ends_with("Tags:")
            || t.ends_with("Written sysfs attributes:")
            || t.ends_with("Written sysctl entries:")
        {
            in_block = true;
        }
        out.push(sort_words(l));
    }
    flush(&mut out, &mut block);
    out.concat()
}

fn sort_words(l: &str) -> String {
    let mut s = sort_json_arrays(l);
    for (key, sep) in [("DEVLINKS=", ' '), ("CURRENT_TAGS=", ':'), (" TAGS=", ':'), ("\"TAGS=", ':')] {
        let Some(k) = s.find(key) else { continue };
        let start = k + key.len();
        let end = s[start..].find(['\n', '"', '\'']).map(|e| start + e).unwrap_or(s.len());
        let mut words: Vec<&str> = s[start..end].split(sep).collect();
        let (lead, trail) = (words.first() == Some(&""), words.last() == Some(&"") && words.len() > 1);
        words.retain(|w| !w.is_empty());
        words.sort();
        let mut v = String::new();
        if lead {
            v.push(sep);
        }
        v.push_str(&words.join(&sep.to_string()));
        if trail {
            v.push(sep);
        }
        s.replace_range(start..end, &v);
    }
    if let Some(rest) = l.strip_prefix("TAGS=") {
        return sort_words(&format!(" TAGS={rest}"))[1..].to_string();
    }
    s
}

/// The JSON arrays of written attributes and sysctls are in hash order in
/// C too: sort their elements (on one line, as --json=short prints them).
fn sort_json_arrays(l: &str) -> String {
    let mut s = l.to_string();
    for key in ["\"sysfsAttributes\":[", "\"sysctl\":["] {
        let Some(k) = s.find(key) else { continue };
        let start = k + key.len();
        let Some(e) = s[start..].find(']') else { continue };
        let end = start + e;
        let inner = &s[start..end];
        let mut items: Vec<String> =
            inner.trim_start_matches('{').trim_end_matches('}').split("},{").map(|x| format!("{{{x}}}")).collect();
        items.sort();
        let joined = items.join(",");
        s.replace_range(start..end, &joined);
    }
    s
}

/// A forked child logs while its parent does: drop the child's line.
fn mask_child_race(s: &str) -> String {
    s.split_inclusive('\n').filter(|l| !l.starts_with("PR_SET_MM_ARG_START failed")).collect()
}

/// `'CMD'(out) 'LINE'` or `(err)`: a callout's output, logged as read.
fn is_callout_output(t: &str) -> bool {
    t.contains("'(out) '") || t.contains("'(err) '")
}

/// For callouts with a lot of output: how the pipe reads split it, and so
/// the logged lines, depends on timing (in C too).
fn mask_big_output(s: &str) -> String {
    let kept: String = s.split_inclusive('\n').filter(|l| !is_callout_output(l)).collect();
    mask(&kept)
}

/// A trace line of `SYMLINK==`, `TAG==` or `TAGS==` for one element of
/// the set: C walks the set in hash order and stops at the first match,
/// so which of these lines appear varies from run to run.
fn is_set_element_trace(t: &str) -> bool {
    let Some(k) = t.find(": String \"") else { return false };
    if !t.ends_with('.') {
        return false;
    }
    let head = &t[..k];
    let Some(tok) = head.rsplit(' ').next() else { return false };
    ["SYMLINK==", "SYMLINK!=", "TAG==", "TAG!=", "TAGS==", "TAGS!="].iter().any(|p| tok.starts_with(p))
}

fn mask_usec(l: &str) -> String {
    let mut s = l.to_string();
    for key in ["USEC_INITIALIZED=", "\"USEC_INITIALIZED\":\""] {
        let mut from = 0;
        while let Some(k) = s[from..].find(key) {
            let start = from + k + key.len();
            let n = s[start..].bytes().take_while(u8::is_ascii_digit).count();
            if n > 0 {
                s.replace_range(start..start + n, "@USEC@");
            }
            from = start;
        }
    }
    s
}

/// A udevadm case: its own `/etc/udev`, `/run` and `/usr/lib/udev/rules.d`
/// (empty unless the case adds rules), on the real sysfs.
fn u(name: &str, args: &[&str]) -> Case {
    Case::new(name, args)
        .etc_own("udev")
        .bind("/run", "run")
        .bind("/usr/lib/udev/rules.d", "usr/lib/udev/rules.d")
        .bind("/usr/local/lib", "usr/local/lib")
        .dir("etc/udev", 0o755)
        .dir("run/udev", 0o755)
        .mask(mask)
}

/// A udevadm case on the fake sysfs.
fn f(name: &str, args: &[&str]) -> Case {
    u(name, args).bind_host(sysfs().to_str().unwrap(), "/sys").env("SYSTEMD_DEVICE_VERIFY_SYSFS", "0")
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

#[test]
fn help() {
    for (n, a) in [
        ("help_long", &["--help"][..]),
        ("help_short", &["-h"]),
        ("help_verb", &["help"]),
        ("help_verb_args", &["help", "foo", "bar"]),
        ("version_long", &["--version"]),
        ("version_short", &["-V"]),
        ("version_verb", &["version"]),
        ("version_verb_args", &["version", "x"]),
        ("introspect", &["--introspect-cli"]),
        ("no_verb", &[]),
        ("unknown_verb", &["frobnicate"]),
        ("close_verb", &["infoo"]),
        ("prefix_verb", &["inf"]),
        ("unknown_option", &["--frobnicate"]),
        ("unknown_short", &["-z"]),
        ("debug_then_verb", &["-d", "version"]),
        ("verb_after_args", &["--debug", "--", "version"]),
    ] {
        c(u(n, a));
    }
    for verb in [
        "info",
        "trigger",
        "settle",
        "control",
        "monitor",
        "test",
        "test-builtin",
        "verify",
        "cat",
        "wait",
        "lock",
        "hwdb",
    ] {
        c(u(&format!("help_{verb}"), &[verb, "--help"]));
        c(u(&format!("help_{verb}_h"), &[verb, "-h"]));
        c(u(&format!("version_{verb}"), &[verb, "-V"]));
        c(u(&format!("introspect_{verb}"), &[verb, "--introspect-cli"]));
        c(u(&format!("unknown_option_{verb}"), &[verb, "--frobnicate"]));
    }
    c(u("help_pty", &["--help"]).pty(40, 100));
    c(u("help_info_pty", &["info", "--help"]).pty(40, 60));
    c(u("help_narrow", &["--help"]).env("COLUMNS", "60"));
    c(u("introspect_test_json", &["test", "--json=short", "--introspect-cli"]));
    c(u("introspect_info_json", &["info", "--json=pretty", "--introspect-cli"]));
}

/// Rules files with something to say about each check of `verify`.
const VERIFY_FILES: &[(&str, &str)] = &[
    (
        "good.rules",
        "# comment\nACTION==\"add\", SUBSYSTEM==\"block\", SYMLINK+=\"disk/%k\"\n\nKERNEL==\"sd*\", GOTO=\"end\"\nENV{FOO}=\"bar\"\nLABEL=\"end\"\n",
    ),
    (
        "style.rules",
        "ACTION==\"add\",SUBSYSTEM==\"block\" ,SYMLINK+=\"x\"\n, KERNEL==\"a\", TAG+=\"t\",\nKERNEL==\"b\" TAG+=\"t\"\nKERNEL==\"c\",, TAG+=\"t\"\nKERNEL==\"d\"  ,  TAG+=\"t\"\nLABEL=\"unused\"\n",
    ),
    (
        "errors.rules",
        "FOO==\"bar\"\nKERNEL=\"x\"\nACTION{x}==\"add\"\nKERNEL==\"sda\", SYMLINK+=\"%z\"\nKERNEL==\"sda\", ATTR{}==\"x\"\nKERNEL==\"a\", GOTO=\"nowhere\"\nKERNEL==\"a\" GOTO=\"x\", GOTO=\"y\"\nLABEL=\"x\"\nLABEL=\"y\"\nKERNEL==\"a\nKERNEL==\"a\", TAG+=\"t\", \\\nTAG+=\"u\"\nKERNEL=\"a\\\n",
    ),
    (
        "conflicts.rules",
        "KERNEL==\"sda\", KERNEL!=\"sda\", TAG+=\"x\"\nKERNEL==\"sda\", KERNEL==\"sda\", TAG+=\"x\"\nKERNEL==\"sd*\", KERNEL==\"hd*\", TAG+=\"x\"\nKERNEL==\"sda|sdb\", KERNEL==\"sdc\", TAG+=\"x\"\nKERNEL==\"sda|sdb\", KERNEL==\"sdb|sdc\", TAG+=\"x\"\nATTR{a}==\"1\", ATTR{a}!=\"1\", TAG+=\"x\"\nENV{A}==\"1\", ENV{B}==\"1\", TAG+=\"x\"\nKERNEL==\"\", KERNEL!=\"\", TAG+=\"x\"\nSUBSYSTEM==\"subsystem\", SUBSYSTEM==\"bus\", TAG+=\"x\"\nKERNEL==\"?*\", KERNEL==\"\", TAG+=\"x\"\nKERNEL==i\"SDA\", KERNEL==i\"sda\", TAG+=\"x\"\n",
    ),
    (
        "ops.rules",
        "NAME+=\"x\"\nENV{A}:=\"1\"\nTAG:=\"t\"\nATTR{x}+=\"1\"\nSYSCTL{a.b}:=\"1\"\nOWNER+=\"root\"\nGROUP+=\"root\"\nMODE+=\"0600\"\nSECLABEL{selinux}:=\"x\"\nNAME-=\"x\"\nPROGRAM-=\"x\"\nIMPORT{file}-=\"x\"\nRUN==\"x\"\nOPTIONS==\"dump\"\nOPTIONS-=\"dump\"\nGOTO+=\"x\"\nLABEL==\"x\"\nKERNEL=\"x\"\nKERNEL==e\"x\", KERNEL==\"y\", TAG=i\"x\"\nPROGRAM==i\"x\"\nTEST==i\"x\"\nIMPORT{file}==i\"x\"\n",
    ),
    (
        "values.rules",
        "NAME=\"%k\"\nNAME=\"\"\nKERNEL==\"a\", ENV{ACTION}=\"x\"\nKERNEL==\"a\", ENV{SYNTH_ARG_X}=\"x\"\nKERNEL==\"a\", CONST{arch}==\"x86-64\", TAG+=\"t\"\nKERNEL==\"a\", CONST{foo}==\"x\", TAG+=\"t\"\nSUBSYSTEM==\"bus\", TAG+=\"t\"\nSUBSYSTEM==\"class\", TAG+=\"t\"\nATTRS{device/vendor}==\"x\", TAG+=\"t\"\nATTRS{../x}==\"x\", TAG+=\"t\"\nTEST{0644}==\"x\", TAG+=\"t\"\nTEST{bad}==\"x\", TAG+=\"t\"\nTEST==\"\", TAG+=\"t\"\nPROGRAM==\"\", TAG+=\"t\"\nIMPORT{foo}==\"x\"\nIMPORT{builtin}==\"nosuch\"\nIMPORT{program}==\"path_id\"\nIMPORT{program}==\"/bin/true\"\nRUN{builtin}+=\"nosuch\"\nRUN{builtin}+=\"kmod load\"\nRUN{foo}+=\"x\"\nOPTIONS+=\"bogus\"\nOPTIONS+=\"link_priority=x\"\nOPTIONS+=\"log_level=loud\"\nOPTIONS+=\"log_level=reset\"\nOPTIONS+=\"log_level=debug\"\nOPTIONS+=\"link_priority=-5\"\nOPTIONS+=\"static_node=tty1\"\nOPTIONS+=\"watch\"\nOPTIONS+=\"nowatch\"\nOPTIONS+=\"db_persist\"\nOPTIONS+=\"string_escape=none\"\nOPTIONS+=\"string_escape=replace\"\nOPTIONS+=\"dump-json\"\nKERNEL==\"a\", OWNER=\"root\", GROUP=\"nobody\", MODE=\"0640\"\nKERNEL==\"a\", OWNER=\"alice\"\nKERNEL==\"a\", GROUP=\"users\"\nKERNEL==\"a\", OWNER=\"nosuchuser\"\nKERNEL==\"a\", GROUP=\"nosuchgroup\"\nKERNEL==\"a\", OWNER=\"1001\", GROUP=\"100\"\nKERNEL==\"a\", OWNER=\"%k\", GROUP=\"$env{G}\", MODE=\"$env{M}\"\nKERNEL==\"a\", MODE=\"0999\"\nKERNEL==\"a\", ENV{X}=\"$attr{}\"\nKERNEL==\"a\", ENV{X}=\"%c{x}\"\nKERNEL==\"a\", ENV{X}=\"%c{2+}\"\nKERNEL==\"a\", ENV{X}=\"$$ %% $kernel %k $nosuch\"\nKERNEL==\"a\", RESULT==\"x\", PROGRAM==\"/bin/echo\", TAG+=\"t\"\nKERNEL==\"a\", SECLABEL{}=\"x\"\nKERNEL==\"a\", ENV{}=\"x\"\nKERNEL==\"a\", SYSCTL{}=\"x\"\nKERNEL==\"a\", ATTR{$bad}=\"x\"\n",
    ),
    (
        "long.rules",
        "KERNEL==\"a\", \\\n  TAG+=\"t1\", \\\n# comment inside\n  TAG+=\"t2\"\n\n  \t  KERNEL==\"b\", TAG+=\"x\"\nKERNEL==e\"a\\x41\\n\", TAG+=\"t\"\nKERNEL==e\"a\\q\", TAG+=\"t\"\nKERNEL==ie\"a\", TAG+=\"t\"\nKERNEL==ii\"a\", TAG+=\"t\"\nKERNEL==\"a\\\"b\", TAG+=\"t\"\nKERNEL    ==    \"a\"  ,  TAG  +=  \"t\"\nKERNEL==\"a\" TAG+=\"t\"\n",
    ),
];

fn with_files(mut case: Case, dir: &str, files: &[(&str, &str)]) -> Case {
    for (n, body) in files {
        case = case.file(&format!("{dir}/{n}"), body.as_bytes(), 0o644);
    }
    case
}

#[test]
fn verify() {
    cd(with_files(u("verify_all", &["verify"]), "etc/udev/rules.d", VERIFY_FILES));
    for (n, _) in VERIFY_FILES {
        let stem = n.trim_end_matches(".rules");
        cd(with_files(u(&format!("verify_{stem}"), &["verify", n]), "etc/udev/rules.d", VERIFY_FILES));
        c(with_files(
            u(&format!("verify_{stem}_nostyle"), &["verify", "--no-style", n]),
            "etc/udev/rules.d",
            VERIFY_FILES,
        ));
        c(with_files(
            u(&format!("verify_{stem}_nosummary"), &["verify", "--no-summary", stem]),
            "etc/udev/rules.d",
            VERIFY_FILES,
        ));
    }
    c(u("verify_none", &["verify"]));
    c(u("verify_root_none", &["verify", "--root=@T@/nothing"]).dir("nothing", 0o755));
    cd(with_files(u("verify_root", &["verify", "--root=@T@/r"]), "r/etc/udev/rules.d", VERIFY_FILES));
    c(with_files(u("verify_root_slash", &["verify", "--root=/"]), "etc/udev/rules.d", VERIFY_FILES));
    c(with_files(u("verify_path", &["verify", "@T@/x/good.rules", "@T@/x/style.rules"]), "x", VERIFY_FILES));
    c(with_files(u("verify_dir", &["verify", "@T@/x"]), "x", VERIFY_FILES));
    c(with_files(u("verify_relative", &["verify", "x/good.rules"]), "x", VERIFY_FILES));
    c(u("verify_missing", &["verify", "@T@/nosuch.rules"]));
    c(u("verify_missing_name", &["verify", "nosuch"]));
    c(with_files(u("verify_twice", &["verify", "good", "good.rules"]), "etc/udev/rules.d", VERIFY_FILES));
    c(u("verify_mask", &["verify", "masked"]).symlink("etc/udev/rules.d/masked.rules", "/dev/null"));
    c(u("verify_mask_empty", &["verify", "empty"]).file("etc/udev/rules.d/empty.rules", b"", 0o644));
    c(u("verify_override", &["verify"])
        .file("etc/udev/rules.d/a.rules", b"KERNEL==\"a\", TAG+=\"x\"\n", 0o644)
        .file("usr/lib/udev/rules.d/a.rules", b"FOO==\"x\"\n", 0o644)
        .file("usr/lib/udev/rules.d/b.rules", b"KERNEL==\"b\" TAG+=\"x\"\n", 0o644)
        .file("run/udev/rules.d/c.rules", b"KERNEL==\"c\", TAG+=\"x\"\n", 0o644));
    c(u("verify_resolve_never", &["verify", "-N", "never", "values"]).file(
        "etc/udev/rules.d/values.rules",
        VERIFY_FILES.iter().find(|x| x.0 == "values.rules").unwrap().1.as_bytes(),
        0o644,
    ));
    c(u("verify_resolve_late", &["verify", "--resolve-names=late", "values"]).file(
        "etc/udev/rules.d/values.rules",
        VERIFY_FILES.iter().find(|x| x.0 == "values.rules").unwrap().1.as_bytes(),
        0o644,
    ));
    c(u("verify_resolve_bad", &["verify", "-N", "sometimes"]));
    c(u("verify_resolve_help", &["verify", "-N", "help"]));
    c(u("verify_perms", &["verify"]).file("etc/udev/rules.d/x.rules", b"KERNEL==\"a\", TAG+=\"x\"\n", 0o777));
    c(u("verify_long_line", &["verify", "x"]).file(
        "etc/udev/rules.d/x.rules",
        format!("KERNEL==\"a\", TAG+=\"{}\"\nKERNEL==\"b\", TAG+=\"y\"\n", "x".repeat(20000)).as_bytes(),
        0o644,
    ));
    c(u("verify_long_continuation", &["verify", "x"]).file(
        "etc/udev/rules.d/x.rules",
        format!("KERNEL==\"a\", \\\n{}TAG+=\"x\"\nKERNEL==\"b\", TAG+=\"y\"\n", "TAG+=\"t\", \\\n".repeat(1600))
            .as_bytes(),
        0o644,
    ));
    c(u("verify_color", &["verify", "errors"]).pty(40, 100).file(
        "etc/udev/rules.d/errors.rules",
        VERIFY_FILES.iter().find(|x| x.0 == "errors.rules").unwrap().1.as_bytes(),
        0o644,
    ));
    // The installed rules (the sandbox shows the real /usr/lib/udev).
    c(Case::new("verify_installed", &["verify"]).etc_own("udev").dir("etc/udev", 0o755).mask(mask));
}

#[test]
fn cat() {
    let files: &[(&str, &str)] = &[
        ("10-a.rules", "# a comment\nKERNEL==\"a\", TAG+=\"x\"\n\n  # indented\nKERNEL==\"b\", \\\n  TAG+=\"y\"\n"),
        ("20-b.rules", "KERNEL==\"c\", TAG+=\"z\"\n"),
    ];
    c(with_files(u("cat_all", &["cat"]), "etc/udev/rules.d", files));
    c(with_files(u("cat_tldr", &["cat", "--tldr"]), "etc/udev/rules.d", files));
    c(with_files(u("cat_one", &["cat", "10-a"]), "etc/udev/rules.d", files));
    c(with_files(u("cat_two", &["cat", "20-b.rules", "10-a"]), "etc/udev/rules.d", files));
    c(with_files(u("cat_path", &["cat", "@T@/x/10-a.rules"]), "x", files));
    c(with_files(u("cat_dir", &["cat", "@T@/x"]), "x", files));
    c(u("cat_missing", &["cat", "nosuch"]));
    c(u("cat_none", &["cat"]));
    c(u("cat_mask", &["cat", "m"]).symlink("etc/udev/rules.d/m.rules", "/dev/null"));
    c(with_files(u("cat_root", &["cat", "--root=@T@/r"]), "r/usr/lib/udev/rules.d", files));
    c(with_files(u("cat_pty", &["cat"]), "etc/udev/rules.d", files).pty(40, 100));
    c(u("cat_config_none", &["cat", "--config"]));
    c(u("cat_config", &["cat", "--config"])
        .file("etc/udev/udev.conf", b"# conf\nudev_log=info\n", 0o644)
        .file("etc/udev/udev.conf.d/10-x.conf", b"children_max=4\n", 0o644)
        .file("run/udev/udev.conf.d/20-y.conf", b"[Section]\nexec_delay=1\n", 0o644));
    c(u("cat_config_tldr", &["cat", "--config", "--tldr"]).file(
        "etc/udev/udev.conf",
        b"# conf\n\nudev_log=info\n",
        0o644,
    ));
    c(u("cat_config_files", &["cat", "--config", "x"]));
    c(u("cat_config_root", &["cat", "--config", "--root=@T@/r"]).file(
        "r/etc/udev/udev.conf",
        b"udev_log=debug\n",
        0o644,
    ));
    c(Case::new("cat_installed", &["cat", "50-udev-default"]).etc_own("udev").dir("etc/udev", 0o755).mask(mask));
}

#[test]
fn config() {
    cd(u("conf_debug", &["verify", "--no-summary"]).file("etc/udev/udev.conf", b"udev_log=debug\n", 0o644));
    c(u("conf_info", &["cat", "nosuch"]).file("etc/udev/udev.conf", b"udev_log = info\nchildren_max=1\n", 0o644));
    c(u("conf_bad", &["version"]).file(
        "etc/udev/udev.conf",
        b"udev_log=loud\nfoo=bar\nX-ok=1\n=x\nnoequals\n[sec]\nudev_log=debug\n\xff=1\n",
        0o644,
    ));
    c(u("conf_dropins", &["verify", "nosuch"])
        .file("etc/udev/udev.conf", b"udev_log=err\n", 0o644)
        .file("usr/lib/udev/udev.conf.d/50-a.conf", b"udev_log=debug\n", 0o644)
        .file("etc/udev/udev.conf.d/60-b.conf", b"udev_log=notice\n", 0o644));
    c(u("conf_continuation", &["verify", "nosuch"]).file("etc/udev/udev.conf", b"udev_log=\\\ndebug\n", 0o644));
    c(u("conf_perms", &["version"]).file("etc/udev/udev.conf", b"udev_log=info\n", 0o777));
    c(u("conf_cli_overrides", &["-d", "verify", "nosuch"]).file("etc/udev/udev.conf", b"udev_log=err\n", 0o644));
}

/// `udevadm test` on each device of a rule set, with and without -v.
fn rule_set_case(i: usize, rs: &RuleSet) -> Case {
    let mut script = String::new();
    for d in &rs.devpaths {
        script +=
            &format!("udevadm test -v '{d}'; echo \"rc=$?\"; udevadm test '{d}' >/dev/null 2>&1; echo \"rc=$?\";\n");
    }
    // Short names: the sandbox's socket paths must fit in sun_path.
    let slug: String = rs.desc.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).take(16).collect();
    let name = format!("rules_{i:03}_{slug}");
    f(&name, &[]).shell(&script).file("etc/udev/rules.d/udev-test.rules", rs.rules.as_bytes(), 0o644)
}

/// Whether a rule set runs a builtin: those are phase 7.
fn uses_builtin(rs: &RuleSet) -> bool {
    const NAMES: &[&str] = &[
        "blkid",
        "btrfs",
        "dissect_image",
        "factory_reset",
        "hwdb",
        "input_id",
        "keyboard",
        "kmod",
        "net_driver",
        "net_id",
        "net_setup_link",
        "path_id",
        "uaccess",
        "usb_id",
    ];
    rs.rules.lines().any(|l| {
        (l.contains("IMPORT{builtin}") || l.contains("RUN{builtin}") || l.contains("IMPORT{program}"))
            && NAMES.iter().any(|n| l.contains(&format!("\"{n}")))
    })
}

fn rule_sets_part(part: usize, parts: usize) {
    for (i, rs) in rule_sets().iter().enumerate() {
        if i % parts == part && !uses_builtin(rs) {
            c(rule_set_case(i, rs));
        }
    }
}

#[test]
fn rules_0() {
    rule_sets_part(0, 6);
}
#[test]
fn rules_1() {
    rule_sets_part(1, 6);
}
#[test]
fn rules_2() {
    rule_sets_part(2, 6);
}
#[test]
fn rules_3() {
    rule_sets_part(3, 6);
}
#[test]
fn rules_4() {
    rule_sets_part(4, 6);
}
#[test]
fn rules_5() {
    rule_sets_part(5, 6);
}

const SDA: &str = "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda";
const SDA1: &str = "/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda/sda1";
const ETH0: &str = "/devices/pci0000:00/0000:00:1c.0/0000:02:00.0/net/eth0";
const NULL: &str = "/devices/virtual/mem/null";
const TTY1: &str = "/devices/virtual/tty/tty1";

/// Rules that use a bit of everything `udevadm test` can show.
const FEATURES: &str = r#"
ACTION=="remove", GOTO="end"
SUBSYSTEM=="block", ENV{DEVTYPE}=="partition", IMPORT{parent}="ID_*"
SUBSYSTEM=="block", IMPORT{db}="DB_PROP", IMPORT{db}="NO_SUCH_PROP"
SUBSYSTEM=="block", IMPORT{cmdline}="foo", IMPORT{cmdline}="bar.baz", IMPORT{cmdline}="nosuch"
SUBSYSTEM=="block", IMPORT{file}="/etc/udev/props", IMPORT{file}="/etc/udev/nosuch"
KERNEL=="sda", PROGRAM="ata_id --export $devnode", RESULT=="ID_ATA=1*", ENV{ATA_RESULT}="%c", ENV{FIRST}="%c{1}", ENV{REST}="%c{2+}"
KERNEL=="sda", IMPORT{program}="scsi_id --export --whitelisted -d $devnode"
KERNEL=="sda", PROGRAM="cdrom_id $devnode", ENV{CDROM}="yes"
KERNEL=="sda", PROGRAM="/bin/echo not run in test mode", ENV{ECHO}="%c"
KERNEL=="sda", TEST=="size", TEST{0444}=="size", TEST!="nosuch", TEST=="[block/sda]/range", TEST=="/etc/udev/props", ENV{TESTS}="ok"
KERNEL=="sda", TEST=="queue/*/x", ENV{GLOBTEST}="no"
KERNEL=="sda", SYSCTL{kernel/ostype}=="Linux", SYSCTL{kernel.nosuch}=="", ENV{SYSCTL}="ok"
KERNEL=="sda", SYSCTL{kernel/hostname}="example", SYSCTL{vm.nosuch}="1"
KERNEL=="sda", ATTR{ro}="1", ATTR{removable}="5", ATTR{nosuch}="1", ATTR{[block/sda1]start}="9"
KERNEL=="sda", ATTR{ro}=="1", ATTR{removable}=="5", ENV{ATTRS_CACHED}="yes"
KERNEL=="sda", ATTR{size}=="?*", ATTR{size}=="*[0-9]", ATTR{[block/sda]size}=="?*", ENV{SIZE}="$attr{size}", ENV{SDA1START}="$attr{[block/sda1]start}"
KERNEL=="sda*", SUBSYSTEMS=="scsi", ATTRS{vendor}=="ATA*", ATTRS{model}=="?*", ENV{VENDOR}="$attr{vendor}", ENV{DRV}="%d", ENV{ID}="%b"
KERNEL=="sda*", KERNELS=="0:0:0:0", DRIVERS=="sd", ENV{PARENT_OK}="1"
KERNEL=="sda*", OWNER="root", GROUP="disk", MODE="0640", SECLABEL{selinux}="a", SECLABEL{smack}+="b", SECLABEL{other}+="c"
KERNEL=="sda*", OWNER="%E{OWNER_NAME}", GROUP="$env{GROUP_NAME}", MODE="$env{MODE}"
KERNEL=="sda1", OWNER:="alice", OWNER="bob", MODE:="0600", MODE="0666", GROUP:="users", GROUP="root"
KERNEL=="sda1", SYMLINK+="disk/by-test/%k %N_x", SYMLINK+="a\tb", OPTIONS+="link_priority=7", OPTIONS+="string_escape=replace", SYMLINK+="r e/p"
KERNEL=="sda1", SYMLINK:="final/%k", SYMLINK+="ignored", SYMLINK-="final/%k"
KERNEL=="sda", TAG+="t1", TAG+="t2", TAG-="t1", TAG="t3", TAG+="t4", TAG+="bad tag"
KERNEL=="sda", RUN+="/bin/true %k", RUN+="kmod load foo", RUN{builtin}+="kmod load bar", RUN+="/bin/true %k", RUN{builtin}+="/bin/true %k"
KERNEL=="sda1", RUN:="/bin/final", RUN+="/bin/ignored"
KERNEL=="sda", OPTIONS+="watch", OPTIONS:="nowatch", OPTIONS+="watch", OPTIONS+="db_persist", OPTIONS+="log_level=info", OPTIONS+="log_level=reset"
KERNEL=="sda", ENV{A}="1", ENV{A}+="2", ENV{A}+="3", ENV{B}="x", ENV{B}="", ENV{C}+="", ENV{SPACE}=" padded  "
KERNEL=="sda", ENV{ESC}="%k$$%%", OPTIONS+="string_escape=replace", ENV{REPL}="a b/c?d"
KERNEL=="eth0", NAME="new%n", NAME+="ignored"
KERNEL=="eth0", NAME:="final0", NAME="notused"
KERNEL=="null", NAME="nope", SYMLINK+="nullink"
KERNEL=="tty1", SYMLINK+="mytty", ENV{LINKS}="%L $links", ENV{DEVNODE}="$devnode $tempnode %N", ENV{ROOT}="%r %S $root $sys"
KERNEL=="tty1", ENV{MM}="%M:%m $major:$minor", ENV{NUM}="%n $number", ENV{PARENT}="%P $parent", ENV{NAMEVAR}="%D $name", ENV{PATHVAR}="%p $devpath"
KERNEL=="tty1", ENV{BAD}="%z $nosuch %", ENV{UNTERM}="$attr{dev", ENV{EMPTYATTR}="$env{NOSUCH}x"
KERNEL=="tty1", CONST{arch}=="x86-64", ENV{ARCH}="1"
KERNEL=="tty1", OPTIONS="dump"
KERNEL=="null", OPTIONS="dump-json"
LABEL="end"
ACTION=="remove", ENV{REMOVED}="1", TAG+="removed"
"#;

/// The database entries the cases see.
fn with_db(case: Case) -> Case {
    case.file(
        "run/udev/data/b8:0",
        b"S:disk/by-id/old-link\nS:disk/by-id/other-old\nL:3\nI:1234567\nE:DB_PROP=from-db\nE:ID_SERIAL=SER123\nE:ID_MODEL=Model X\nG:oldtag\nQ:oldtag\nV:1\n",
        0o644,
    )
    .file("run/udev/data/b8:1", b"I:7654321\nE:OLD=1\nG:t3\nV:1\n", 0o644)
    .file("run/udev/data/n2", b"I:42\nE:ID_NET=1\nV:1\n", 0o644)
}

/// Callout stand-ins: `$FOO_ID_PATH` overrides `foo_id`.
fn with_callouts(case: Case) -> Case {
    case.env("ATA_ID_PATH", "@T@/bin/ata_id")
        .env("SCSI_ID_PATH", "@T@/bin/scsi_id")
        .env("CDROM_ID_PATH", "@T@/bin/cdrom_id")
        .file(
            "bin/ata_id",
            b"#!/bin/sh\necho \"ID_ATA=1 second  third\"\necho \"ata_id: $*\" >&2\nexit 0\n",
            0o755,
        )
        .file(
            "bin/scsi_id",
            b"#!/bin/sh\nprintf 'ID_SCSI=1\\nID_VENDOR=\"quoted\"\\nID_BAD\\n# comment\\nID_EMPTY=\\nID_SQ='\"'\"'sq'\"'\"'\\n'\n",
            0o755,
        )
        .file("bin/cdrom_id", b"#!/bin/sh\necho no cdrom >&2\nexit 3\n", 0o755)
        .env("SYSTEMD_PROC_CMDLINE", "foo bar.baz=1 bar-baz=2 rd.qux=3")
        .env("OWNER_NAME", "root")
        .env("GROUP_NAME", "disk")
        .env("MODE", "0600")
        .file("etc/udev/props", b"# props\nFILE_A=1\n  FILE_B = 'two' \nFILE_C=\"three\"\nnoequals\nFILE_D=\"x'\n=v\n\n", 0o644)
}

fn features(name: &str, args: &[&str]) -> Case {
    with_callouts(with_db(f(name, args))).file("etc/udev/rules.d/50-features.rules", FEATURES.as_bytes(), 0o644)
}

#[test]
fn test_verb() {
    for (n, dev) in [("sda", SDA), ("sda1", SDA1), ("eth0", ETH0), ("null", NULL), ("tty1", TTY1)] {
        c(features(&format!("test_{n}"), &["test", dev]));
        c(features(&format!("test_{n}_v"), &["test", "-v", dev]));
        c(features(&format!("test_{n}_json"), &["test", "--json=short", dev]));
        // sda writes several attributes, which C lists in hash order;
        // the one-line JSON is sorted by the mask, this isn't.
        if n != "sda" {
            c(features(&format!("test_{n}_pretty"), &["test", "--json=pretty", "--verbose", dev]));
        }
        c(features(&format!("test_{n}_remove"), &["test", "-a", "remove", dev]));
    }
    for a in ["change", "move", "online", "offline", "bind", "unbind", "help", "frob"] {
        c(features(&format!("test_action_{a}"), &["test", "--action", a, SDA]));
    }
    for n in ["never", "late", "early", "help", "x"] {
        c(features(&format!("test_names_{n}"), &["test", "-N", n, SDA1]));
    }
    for j in ["off", "help", "x"] {
        c(features(&format!("test_json_{j}"), &["test", &format!("--json={j}"), SDA]));
    }
    c(features("test_pty", &["test", "-v", SDA1]).pty(60, 120));
    c(features("test_quiet", &["test", SDA]).env("SYSTEMD_LOG_LEVEL", "notice"));
    c(features("test_console_target", &["test", SDA]).env("SYSTEMD_LOG_TARGET", "console-prefixed"));
    c(features("test_no_syspath", &["test"]));
    c(features("test_two_paths", &["test", SDA, SDA1]));
    c(features("test_bad_path", &["test", "/devices/nosuch"]));
    c(features("test_sys_prefix", &["test", &format!("/sys{SDA}")]));
    c(features("test_device_id", &["test", "b8:1"]));
    c(features("test_devname", &["test", "/dev/sda"]));
    c(features("test_unit", &["test", "dev-sda.device"]));
    c(features("test_unit_bad", &["test", "dev-sda.service"]));
    c(features("test_extra_dir", &["test", "-D", "@T@/extra", "--extra-rules-dir=extra2", "-v", SDA])
        .file("extra/00-first.rules", b"KERNEL==\"sda\", ENV{EXTRA}=\"1\"\n", 0o644)
        .file("extra2/99-last.rules", b"KERNEL==\"sda\", ENV{EXTRA2}=\"1\"\n", 0o644)
        .file("extra/50-features.rules", b"KERNEL==\"sda\", ENV{SHADOWED}=\"1\"\n", 0o644));
    c(features("test_overrides", &["test", SDA])
        .file("run/udev/rules.d/50-features.rules", b"KERNEL==\"sda\", ENV{RUN_WINS}=\"1\"\n", 0o644)
        .file("usr/lib/udev/rules.d/10-early.rules", b"KERNEL==\"sda\", ENV{EARLY}=\"1\"\n", 0o644)
        .symlink("etc/udev/rules.d/10-early.rules", "/dev/null"));
    c(f("test_non_utf8_json", &["test", "--json=short", SDA]).file(
        "etc/udev/rules.d/x.rules",
        b"KERNEL==\"sda\", ENV{X}=e\"\\xff\"\n",
        0o644,
    ));
    c(f("test_non_utf8_text", &["test", SDA]).file(
        "etc/udev/rules.d/x.rules",
        b"KERNEL==\"sda\", ENV{X}=e\"\\xff\"\n",
        0o644,
    ));
    c(f("test_conf_log", &["test", SDA]).file("etc/udev/udev.conf", b"udev_log=err\n", 0o644));
    c(f("test_cli_debug", &["-d", "test", SDA]).file("etc/udev/udev.conf", b"udev_log=err\n", 0o644));
    c(f("test_no_rules", &["test", "-v", TTY1]));
    c(f("test_installed_rules", &["test", TTY1]).bind_host("/usr/lib/udev/rules.d", "/usr/lib/udev/rules.d"));
}

/// A made-up udev database for the fake sysfs.
fn info_db(case: Case) -> Case {
    case.file(
        "run/udev/data/b8:0",
        b"S:disk/by-id/ata-DISK\nL:5\nI:1000001\nE:ID_MODEL=Disk Model\nE:ID_SERIAL=SER\nE:ID_PATH=pci-0000:00:1f.2-ata-1\nG:systemd\nQ:systemd\nV:1\n",
        0o644,
    )
    .file("run/udev/data/b8:1", b"S:disk/by-uuid/1234\nI:1000002\nE:ID_FS_TYPE=ext4\nE:ID_PROCESSING=1\nG:systemd\nV:1\n", 0o644)
    .file("run/udev/data/n2", b"I:1000003\nE:ID_NET_NAME_PATH=enp2s0\nE:ID_BAD=\xff\xfe\nV:1\n", 0o644)
    .file("run/udev/data/c4:1", b"I:1000004\nE:ID_TTY=1\nG:seat\nQ:seat\nV:1\n", 0o1644)
    .file("run/udev/data/+input:input0", b"I:1000005\nE:ID_INPUT=1\nV:1\n", 0o644)
    .file("run/udev/tags/systemd/b8:0", b"", 0o444)
    .file("run/udev/tags/systemd/b8:1", b"", 0o444)
    .file("run/udev/tags/seat/c4:1", b"", 0o444)
    .file("run/udev/tags/stale/b8:99", b"", 0o444)
    .symlink("run/udev/links/disk\\x2fby-id\\x2fata-DISK/b8:0", "5:/dev/sda")
    .symlink("run/udev/links/stale/b8:99", "0:/dev/nosuch")
    .file("run/udev/static_node-tags/uaccess/snd\\x2fseq", b"", 0o644)
    .file("run/udev/watch/1", b"", 0o644)
}

fn i(name: &str, args: &[&str]) -> Case {
    info_db(f(name, args))
}

#[test]
fn info() {
    for (n, dev) in [("sda", SDA), ("sda1", SDA1), ("eth0", ETH0), ("tty1", TTY1), ("null", NULL)] {
        let sys = format!("/sys{dev}");
        c(i(&format!("info_{n}"), &["info", &sys]));
        c(i(&format!("info_{n}_json"), &["info", "--json=short", &sys]));
        c(i(&format!("info_{n}_devpath"), &["info", dev]));
        c(i(&format!("info_{n}_pretty"), &["info", "--json=pretty", &sys]));
        c(i(&format!("info_{n}_walk"), &["info", "-a", &sys]));
        c(i(&format!("info_{n}_walk_json"), &["info", "-a", "--json=short", &sys]));
        c(i(&format!("info_{n}_tree"), &["info", "-t", &sys]));
        for q in ["name", "symlink", "path", "property", "all", "env"] {
            c(i(&format!("info_{n}_q_{q}"), &["info", "-q", q, &sys]));
        }
    }
    let sda = format!("/sys{SDA}");
    let sda = sda.as_str();
    c(i("info_root", &["info", "-r", "-q", "name", sda]));
    c(i("info_root_links", &["info", "--root", "--query=symlink", sda]));
    c(i("info_value_links", &["info", "--value", "-q", "symlink", sda]));
    c(i(
        "info_props",
        &["info", "-q", "property", "--property=ID_MODEL,DEVNAME", "--property", "ID_SERIAL,DEVNAME", sda],
    ));
    c(i("info_props_empty", &["info", "-q", "property", "--property=", sda]));
    c(i("info_props_value", &["info", "-q", "property", "--value", "--property=DEVNAME", sda]));
    c(i("info_export", &["info", "-x", "-q", "property", sda]));
    c(i("info_export_prefix", &["info", "-P", "UDEV_", "-q", "property", sda]));
    c(i("info_export_value", &["info", "-x", "--value", sda]));
    c(i("info_q_bad", &["info", "-q", "bogus", sda]));
    c(i("info_by_name", &["info", "-n", "sda"]));
    c(i("info_by_name_dev", &["info", "--name=/dev/sda1"]));
    c(i("info_by_path", &["info", "-p", "devices/virtual/mem/null"]));
    c(i("info_by_path_sys", &["info", "-p", &format!("/sys{NULL}")]));
    c(i("info_by_id", &["info", "b8:1"]));
    c(i("info_by_id_net", &["info", "n2"]));
    c(i("info_by_id_plus", &["info", "+input:input0"]));
    c(i("info_by_unit", &["info", "sys-devices-virtual-mem-null.device"]));
    c(i("info_by_unit_bad", &["info", "x-y.mount"]));
    c(i("info_several", &["info", sda, "nosuch", "/nosuch", &format!("/sys{TTY1}"), "dev-nosuch.device"]));
    c(i("info_none", &["info"]));
    c(i("info_walk_two", &["info", "-a", sda, &format!("/sys{SDA1}")]));
    c(i("info_devid_file", &["info", "-d", "/etc/passwd"]));
    c(i("info_devid_export", &["info", "-x", "-d", "/etc/passwd"]));
    c(i("info_devid_prefix", &["info", "-P", "X_", "-d", "/etc/passwd"]));
    c(i("info_devid_missing", &["info", "-d", "/nosuch"]));
    c(i("info_devid_with_device", &["info", "-d", "/etc/passwd", sda]));
    c(i("info_export_db", &["info", "-e"]));
    c(i("info_export_db_json", &["info", "--export-db", "--json=short"]));
    for (n, m) in [
        ("subsystem", &["--subsystem-match=block"][..]),
        ("subsystem_no", &["--subsystem-nomatch=block", "--subsystem-nomatch=tty"]),
        ("attr", &["--attr-match=removable=0"]),
        ("attr_any", &["--attr-match=ro"]),
        ("attr_no", &["--attr-nomatch=dev"]),
        ("property", &["--property-match=ID_FS_TYPE=ext*"]),
        ("property_bad", &["--property-match=ID_FS_TYPE"]),
        ("tag", &["--tag-match=systemd"]),
        ("sysname", &["--sysname-match=sd*"]),
        ("name", &["--name-match=/dev/sda"]),
        ("name_bad", &["--name-match=nosuch"]),
        ("parent", &["--parent-match=/sys/devices/pci0000:00/0000:00:1f.2"]),
        ("parent_two", &["--parent-match=/sys/devices/virtual/mem", "--parent-match=/sys/devices/virtual/tty"]),
        ("initialized", &["--initialized-match", "--subsystem-match=block"]),
        ("uninitialized", &["--initialized-nomatch", "--subsystem-match=mem"]),
        ("key_bad", &["--attr-match=a/b=1"]),
    ] {
        let mut args = vec!["info", "-e"];
        args.extend_from_slice(m);
        c(i(&format!("info_export_{n}"), &args));
    }
    c(i("info_tree", &["info", "-t"]));
    c(i("info_tree_pty", &["info", "--tree", "/sys/devices/virtual/mem"]).pty(40, 100));
    c(i("info_pty", &["info", sda]).pty(60, 120));
    c(i("info_pty_nopager", &["info", "--no-pager", "-e", "--subsystem-match=mem"]).pty(60, 120));
    c(i("info_cleanup", &["info", "-c"]));
    c(i("info_cleanup_device", &["info", "-c", sda]));
    c(f("info_cleanup_empty", &["info", "--cleanup-db"]));
    c(i("info_wait_ready", &["info", "-w", &format!("/sys{SDA}")]));
    c(i("info_wait_timeout_ready", &["info", "--wait-for-initialization=1", &format!("/sys{TTY1}")]));
    c(i("info_wait_processing", &["info", "--wait-for-initialization=0.2", &format!("/sys{SDA1}")]).netns());
    c(i("info_wait_uninitialized", &["info", "--wait-for-initialization=0.2", &format!("/sys{NULL}")]).netns());
    c(i("info_wait_bad", &["info", "-w5x", sda]));
    c(i("info_json_help", &["info", "--json=help"]));
    c(i("info_json_bad", &["info", "--json=xml", sda]));
    c(i("info_debug", &["info", "-q", "all", sda]).env("SYSTEMD_LOG_LEVEL", "debug"));
}

fn h(name: &str, args: &[&str]) -> Case {
    Case::new(name, args)
        .etc_own("udev")
        .etc_own("systemd")
        .bind("/usr/lib/udev", "usr/lib/udev")
        .bind("/usr/lib/systemd", "usr/lib/systemd")
        .dir("etc/udev", 0o755)
        .file(
            "usr/lib/udev/hwdb.d/20-test.hwdb",
            b"usb:v1234p*\n ID_VENDOR_FROM_DATABASE=Example\n\nusb:v1234p5678*\n ID_MODEL_FROM_DATABASE=Gadget\n",
            0o644,
        )
}

#[test]
fn hwdb() {
    c(h("hwdb_none", &["hwdb"]));
    cd(h("hwdb_update", &["hwdb", "--update"]));
    c(h("hwdb_update_usr", &["hwdb", "-u", "--usr"]));
    c(h("hwdb_update_root", &["hwdb", "-u", "-r", "@T@/r"]).file(
        "r/usr/lib/udev/hwdb.d/x.hwdb",
        b"pci:v*\n A=1\n",
        0o644,
    ));
    c(h("hwdb_strict", &["hwdb", "-u", "-s"]).file("etc/udev/hwdb.d/bad.hwdb", b" A=1\nnot a match\n", 0o644));
    c(h("hwdb_update_test", &["hwdb", "--update", "--test=usb:v1234p5678d0001"]));
    c(h("hwdb_test_none", &["hwdb", "-t", "usb:v1234p5678"]));
    c(h("hwdb_bypass", &["hwdb", "-u"]).env("SYSTEMD_HWDB_UPDATE_BYPASS", "1"));
}

fn runner() -> Program {
    Program {
        name: "test-udev-rule-runner",
        c: reference_build().join("test-udev-rule-runner"),
        rust: PathBuf::from(env!("CARGO_BIN_EXE_test-udev-rule-runner")),
    }
}

/// A small sysfs of devices without device nodes (the sandbox can't
/// make those), as the runner wants it: `./tmpfs/sys`, with `./tmpfs/dev`
/// and `./run`.
fn rr(name: &str, script: &str, rules: &str) -> Case {
    Case::new(name, &[])
        .shell(script)
        .mask(mask_child_race)
        .etc_own("udev")
        .dir("etc/udev/rules.d", 0o755)
        .file("tmpfs/dev/null", b"", 0o666)
        .bind_host("/dev/null", &format!("{}/tmpfs/dev/null", common::fixed_root().display()))
        .dir("tmpfs/sys/class/net", 0o755)
        .dir("tmpfs/sys/class/thing", 0o755)
        .file("tmpfs/sys/devices/virtual/net/eth9/uevent", b"INTERFACE=eth9\nIFINDEX=9\n", 0o644)
        .file("tmpfs/sys/devices/virtual/net/eth9/mtu", b"1500\n", 0o644)
        .file("tmpfs/sys/devices/virtual/net/eth9/ifalias", b"\n", 0o644)
        .symlink("tmpfs/sys/devices/virtual/net/eth9/subsystem", "../../../../class/net")
        .symlink("tmpfs/sys/class/net/eth9", "../../devices/virtual/net/eth9")
        .file("tmpfs/sys/devices/virtual/thing/t1/uevent", b"FOO=bar\n", 0o644)
        .file("tmpfs/sys/devices/virtual/thing/t1/value", b"42\n", 0o644)
        .file("tmpfs/sys/devices/virtual/thing/t1/ro", b"x\n", 0o444)
        .symlink("tmpfs/sys/devices/virtual/thing/t1/subsystem", "../../../../class/thing")
        .symlink("tmpfs/sys/class/thing/t1", "../../devices/virtual/thing/t1")
        .file("run/udev-test.rules", rules.as_bytes(), 0o644)
        .file("run/udev/data/n9", b"I:111\nE:OLD=1\nG:systemd\nV:1\n", 0o644)
        .file("run/udev/data/+thing:t1", b"I:222\nV:1\n", 0o644)
        .env("SYSTEMD_DEVICE_VERIFY_SYSFS", "0")
        .file("bin/record", b"#!/bin/sh\necho \"$0 $* ACTION=$ACTION FOO=$FOO\" >> /run/record.log\necho out-line\necho err-line >&2\nexit ${EXIT:-0}\n", 0o755)
}

const RUNNER_RULES: &str = r#"
ACTION=="remove", GOTO="remove"
SUBSYSTEM=="net", ENV{NETPROP}="1", TAG+="systemd", OPTIONS+="db_persist"
SUBSYSTEM=="net", IMPORT{db}="OLD", ATTR{mtu}="9000", ATTR{nosuch}="1"
SUBSYSTEM=="net", RUN+="/run/../%S/../bin/record net %k", RUN+="/nosuch/prog", RUN+="kmod load x"
SUBSYSTEM=="net", SYSCTL{net/ipv4/nosuch}="1"
SUBSYSTEM=="thing", ATTR{value}="43", ATTR{ro}="y", ENV{THING}="$attr{value}", TAG="thingtag"
SUBSYSTEM=="thing", PROGRAM="/run/../bin/record program", RESULT=="out-line", ENV{GOT}="%c"
SUBSYSTEM=="thing", IMPORT{program}="/run/../bin/record import", RUN+="/run/../bin/record thing"
SUBSYSTEM=="thing", PROGRAM="/run/../bin/record fail", ENV{NOTREACHED}="1"
SUBSYSTEM=="thing", ENV{EXIT}="3", RUN+="/run/../bin/record exit3"
LABEL="remove"
ACTION=="remove", RUN+="/run/../bin/record removed %k"
"#;

#[test]
fn rule_runner() {
    let rc = |case: Case| {
        check(&runner(), case);
    };
    let rec = |p: &str| p.replace("/run/../", "@T@/");
    let rules = rec(RUNNER_RULES);
    rc(rr("runner_args", "test-udev-rule-runner; echo rc=$?; test-udev-rule-runner a b c d; echo rc=$?", &rules));
    rc(rr("runner_check", "test-udev-rule-runner check; echo rc=$?; test-udev-rule-runner checkx; echo rc=$?", &rules));
    rc(rr(
        "runner_bad",
        "test-udev-rule-runner frob /devices/virtual/thing/t1; echo rc=$?; test-udev-rule-runner add /devices/nosuch; echo rc=$?; test-udev-rule-runner add /x 12x; echo rc=$?",
        &rules,
    ));
    rc(rr(
        "runner_net",
        "test-udev-rule-runner add /devices/virtual/net/eth9; echo rc=$?; test-udev-rule-runner change /devices/virtual/net/eth9 1000; echo rc=$?",
        &rules,
    ));
    rc(rr(
        "runner_net_remove",
        "test-udev-rule-runner add /devices/virtual/net/eth9; test-udev-rule-runner remove /devices/virtual/net/eth9; echo rc=$?",
        &rules,
    ));
    rc(rr("runner_thing", "test-udev-rule-runner add /devices/virtual/thing/t1; echo rc=$?", &rules));
    rc(rr(
        "runner_thing_debug",
        "SYSTEMD_LOG_LEVEL=debug test-udev-rule-runner add /devices/virtual/thing/t1; echo rc=$?",
        &rules,
    ));
    rc(rr("runner_thing_remove", "test-udev-rule-runner remove /devices/virtual/thing/t1; echo rc=$?", &rules));
    rc(rr(
        "runner_no_db",
        "rm -f run/udev/data/n9 run/udev/data/+thing:t1; test-udev-rule-runner remove /devices/virtual/net/eth9; echo rc=$?",
        &rules,
    ));
    rc(rr(
        "runner_run_twice",
        "test-udev-rule-runner add /devices/virtual/thing/t1; echo rc=$?",
        &rec(
            "SUBSYSTEM==\"thing\", RUN+=\"/run/../bin/record twice\"\nSUBSYSTEM==\"thing\", RUN+=\"/run/../bin/record twice\"\n",
        ),
    ));
    rc(rr("runner_empty_rules", "test-udev-rule-runner add /devices/virtual/thing/t1; echo rc=$?", "# nothing\n"));
}

#[test]
fn consts() {
    let rules = "KERNEL==\"tty1\", CONST{arch}==\"x86-64\", ENV{A}=\"1\"\nKERNEL==\"tty1\", CONST{virt}==\"none\", ENV{V}=\"none\"\nKERNEL==\"tty1\", CONST{virt}==\"container-other|kvm|oracle\", ENV{V}=\"other\"\nKERNEL==\"tty1\", CONST{cvm}==\"none\", ENV{C}=\"none\"\nKERNEL==\"tty1\", CONST{arch}==i\"X86*\", ENV{AI}=\"1\"\n";
    c(f("const", &["test", "-v", TTY1]).file("etc/udev/rules.d/c.rules", rules.as_bytes(), 0o644));
    c(f("const_cmdline_env", &["test", "-v", TTY1])
        .file("etc/udev/rules.d/c.rules", rules.as_bytes(), 0o644)
        .env("SYSTEMD_PROC_CMDLINE", "quiet"));
    c(f("const_container_file", &["test", "-v", TTY1])
        .file("etc/udev/rules.d/c.rules", rules.as_bytes(), 0o644)
        .file("run/systemd/container", b"docker\n", 0o644)
        .env("SYSTEMD_PROC_CMDLINE", "quiet"));
    c(f("const_container_mgr", &["test", "-v", TTY1]).file("etc/udev/rules.d/c.rules", rules.as_bytes(), 0o644).file(
        "run/host/container-manager",
        b"oci\n",
        0o644,
    ));
    c(f("cmdline_container", &["test", "-v", TTY1])
        .file(
            "etc/udev/rules.d/c.rules",
            b"KERNEL==\"tty1\", IMPORT{cmdline}=\"BOOT_IMAGE\", IMPORT{cmdline}=\"ro\"\n",
            0o644,
        )
        .file("run/systemd/container", b"lxc\n", 0o644));
}

#[test]
fn quirks() {
    // The labels and commands are keyed by pointer: duplicates are kept.
    c(f("quirk_seclabel", &["test", "-v", TTY1]).file(
        "etc/udev/rules.d/q.rules",
        b"KERNEL==\"tty1\", SECLABEL{selinux}+=\"a\"\nKERNEL==\"tty1\", SECLABEL{selinux}+=\"b\"\nKERNEL==\"tty1\", ENV{AFTER}=\"1\"\n",
        0o644,
    ));
    // The same command, queued as a program, a builtin, and again.
    c(f("quirk_run_twice", &["test", "-v", TTY1]).file(
        "etc/udev/rules.d/q.rules",
        b"KERNEL==\"tty1\", RUN+=\"kmod load x\"\nKERNEL==\"tty1\", RUN{builtin}+=\"kmod load x\"\nKERNEL==\"tty1\", ENV{AFTER}=\"1\"\nKERNEL==\"tty1\", RUN+=\"kmod load x\"\n",
        0o644,
    ));
    // One bad key drops the whole line, the good keys before it too.
    c(f("quirk_line_dropped", &["test", "-v", TTY1]).file(
        "etc/udev/rules.d/q.rules",
        b"KERNEL==\"tty1\", ENV{A}=\"1\", BOGUS=\"x\"\nKERNEL==\"tty1\", ENV{B}=\"1\"\n",
        0o644,
    ));
}

#[test]
fn limits() {
    // A continued line of exactly UDEV_LINE_SIZE bytes is too long; one
    // byte less is not.  ('KERNEL=="tty1", ' is 16 bytes.)
    for (n, len) in [("limit_cont_16383", 16383usize), ("limit_cont_16384", 16384)] {
        let body = format!(
            "KERNEL==\"tty1\", \\\nENV{{X}}=\"{}\"\nKERNEL==\"tty1\", ENV{{Y}}=\"1\"\n",
            "x".repeat(len - 16 - 9)
        );
        c(f(n, &["test", TTY1]).file("etc/udev/rules.d/l.rules", body.as_bytes(), 0o644));
    }
    // Callout output that fills the 16 KiB result: the last line is cut
    // and dropped.
    for (n, size) in [("limit_output_fits", 16000usize), ("limit_output_full", 16383), ("limit_output_over", 20000)] {
        let script = format!(
            "#!/bin/sh\nawk 'BEGIN {{ n = 0; i = 0; while (n < {size}) {{ s = sprintf(\"KEY_%05d=%s\", i, \"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\"); print s; n += length(s) + 1; i++ }} }}'\n"
        );
        c(f(n, &["test", "-v", TTY1])
            .file("etc/udev/rules.d/l.rules", b"KERNEL==\"tty1\", IMPORT{program}=\"ata_id\"\nKERNEL==\"tty1\", PROGRAM=\"ata_id\", ENV{LAST}=\"%c{2000+}\"\n", 0o644)
            .file("bin/ata_id", script.as_bytes(), 0o755)
            .env("ATA_ID_PATH", "@T@/bin/ata_id")
            .mask(mask_big_output));
    }
}
