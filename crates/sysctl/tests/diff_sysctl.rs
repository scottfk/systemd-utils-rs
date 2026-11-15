// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential tests for systemd-sysctl: the C build and the port, run on
//! the same sysctl.d trees and a fake /proc/sys (plain files).

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::{ALICE, Case, Program, check, reference_build};

fn prog() -> Program {
    Program {
        name: "systemd-sysctl",
        c: reference_build().join("systemd-sysctl"),
        rust: PathBuf::from(env!("CARGO_BIN_EXE_systemd-sysctl")),
    }
}

/// A case with the sysctl.d hierarchy and /proc/sys under T, and a small
/// fake /proc/sys tree.
fn s(name: &str, args: &[&str]) -> Case {
    Case::new(name, args)
        .etc_own("sysctl.d")
        .bind("/proc/sys", "proc/sys")
        .bind("/run", "run")
        .bind("/usr/lib/sysctl.d", "usr/lib/sysctl.d")
        .bind("/usr/local/lib", "usr/local/lib")
        .conf("proc/sys/kernel/sysrq", "16\n")
        .conf("proc/sys/kernel/pid_max", "32768\n")
        .conf("proc/sys/kernel/core_pattern", "core\n")
        .conf("proc/sys/fs/protected_symlinks", "0\n")
        .conf("proc/sys/net/ipv4/ip_forward", "0\n")
        .conf("proc/sys/net/ipv4/conf/all/rp_filter", "0\n")
        .conf("proc/sys/net/ipv4/conf/default/rp_filter", "0\n")
        .conf("proc/sys/net/ipv4/conf/eth0/rp_filter", "0\n")
        .conf("proc/sys/net/ipv4/conf/eth0.100/rp_filter", "0\n")
        .conf("proc/sys/net/ipv4/conf/lo/rp_filter", "0\n")
        .conf("proc/sys/net/ipv6/conf/all/forwarding", "0\n")
}

fn c(case: Case) {
    check(&prog(), case);
}

/// The same case with the debug log.
fn cd(case: Case) {
    let name = format!("{}_debug", case.name);
    let mut d = case.clone().env("SYSTEMD_LOG_LEVEL", "debug");
    d.name = name;
    check(&prog(), case);
    check(&prog(), d);
}

// ---------------------------------------------------------------------------
// command line

#[test]
fn help() {
    c(s("help", &["--help"]));
    c(s("help_short", &["-h"]));
    c(s("help_abbrev", &["--he"]));
    c(s("help_narrow", &["--help"]).env("COLUMNS", "30"));
    c(s("help_very_narrow", &["--help"]).env("COLUMNS", "12"));
    c(s("help_wide", &["--help"]).env("COLUMNS", "200"));
    c(s("help_columns_bad", &["--help"]).env("COLUMNS", "0"));
    c(s("help_invoked_as", &["--help"]).env("SYSTEMD_INVOKED_AS", "/usr/bin/other-name"));
    c(s("help_after_args", &["foo", "--help", "bar"]));
}

#[test]
fn version() {
    c(s("version", &["--version"]));
    c(s("introspect", &["--introspect-cli"]));
}

#[test]
fn bad_options() {
    c(s("bad_long", &["--frobnicate"]));
    c(s("bad_short", &["-x"]));
    c(s("bad_short_cluster", &["-hx"]));
    c(s("ambiguous", &["--s"]));
    c(s("empty_long", &["--=foo"]));
    c(s("missing_arg", &["--prefix"]));
    c(s("no_arg_allowed", &["--strict=yes"]));
    c(s("no_arg_allowed_help", &["--help=1"]));
    c(s("double_dash", &["--", "--strict"]));
    c(s("single_dash", &["-"]).stdin(b"kernel.sysrq = 1\n"));
}

#[test]
fn argument_checks() {
    c(s("cat_with_args", &["--cat-config", "foo"]));
    c(s("tldr_with_args", &["--tldr", "foo"]));
    c(s("inline_without_args", &["--inline"]));
    c(s("save_without_args", &["--save=x"]));
    c(s("save_empty", &["--save=", "x"]));
    c(s("save_dot", &["--save=.hidden", "x"]));
    c(s("save_slash", &["--save=a/b", "x"]));
    c(s("save_dotdot", &["--save=..", "x"]));
    c(s("revert_empty", &["--revert="]));
    c(s("revert_slash", &["--revert=../x"]));
    c(s("save_too_long", &["--save", &"x".repeat(252), "x"]));
    c(s("save_long_ok", &["--save", &"x".repeat(250), "--inline", "kernel.sysrq=1"]));
}

// ---------------------------------------------------------------------------
// applying the hierarchy

fn tree(name: &str) -> Case {
    s(name, &[])
        .conf("usr/lib/sysctl.d/50-default.conf", "kernel.sysrq = 16\nfs.protected_symlinks = 1\n")
        .conf("usr/lib/sysctl.d/60-net.conf", "net.ipv4.ip_forward=1\n")
        .conf("usr/local/lib/sysctl.d/55-local.conf", "kernel.pid_max = 65536\n")
        .conf("run/sysctl.d/60-net.conf", "net.ipv4.ip_forward = 0\n")
        .conf("etc/sysctl.d/70-mine.conf", "# comment\n; also comment?\n\nkernel.sysrq = 438\n")
        .conf("etc/sysctl.d/README", "not a config file\n")
        .conf("etc/sysctl.d/.hidden.conf", "kernel.sysrq = 1\n")
        .conf("etc/sysctl.d/80-backup.conf~", "kernel.sysrq = 2\n")
        .conf("etc/sysctl.d/80-new.conf.rpmnew", "kernel.sysrq = 3\n")
}

#[test]
fn hierarchy() {
    cd(tree("hierarchy"));
    cd(tree("hierarchy_mask_symlink").symlink("etc/sysctl.d/50-default.conf", "/dev/null"));
    cd(tree("hierarchy_mask_empty").conf("etc/sysctl.d/50-default.conf", ""));
    cd(tree("hierarchy_dangling").symlink("etc/sysctl.d/40-gone.conf", "/nonexistent.conf"));
    cd(tree("hierarchy_symlink").symlink("etc/sysctl.d/40-link.conf", "/usr/lib/sysctl.d/60-net.conf"));
    cd(tree("hierarchy_dir_named_conf").dir("etc/sysctl.d/30-dir.conf", 0o755));
    cd(tree("hierarchy_unreadable").file("etc/sysctl.d/30-secret.conf", b"kernel.sysrq = 5\n", 0o600).run_as(ALICE));
    cd(tree("hierarchy_etc_symlink_dir")
        .no_node("etc/sysctl.d/70-mine.conf")
        .no_node("etc/sysctl.d/README")
        .no_node("etc/sysctl.d/.hidden.conf")
        .no_node("etc/sysctl.d/80-backup.conf~")
        .no_node("etc/sysctl.d/80-new.conf.rpmnew")
        .symlink("etc/sysctl.d", "/usr/lib/sysctl.d"));
    cd(s("empty_hierarchy", &[]));
}

#[test]
fn values_and_keys() {
    let conf = "\
kernel.sysrq=1
  kernel/pid_max   =   40000
net/ipv4/conf/eth0.100/rp_filter = 2
net.ipv4.conf.eth0/100.rp_filter = 3
fs.protected_symlinks =
kernel..sysrq = 4
/kernel/./core_pattern = |/bin/false %p
=nothing
-
kernel.sysrq
just some words
";
    cd(s("values", &[]).conf("etc/sysctl.d/a.conf", conf));
    cd(s("values_crlf", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 7\r\nkernel.pid_max = 7\r\n"));
    cd(s("values_no_newline", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 8"));
    cd(s("values_nul", &[]).file("etc/sysctl.d/a.conf", b"kernel.sysrq = 9\0kernel.pid_max = 9\n", 0o644));
    cd(s("values_long_line", &[])
        .conf("etc/sysctl.d/a.conf", &format!("kernel.sysrq = {}\nkernel.pid_max = 5\n", "1".repeat(3000))));
    cd(s("values_unicode", &[]).conf("etc/sysctl.d/a.conf", "kernel.core_pattern = ‘core’ ✓\n"));
    cd(s("values_invalid_utf8", &[]).file(
        "etc/sysctl.d/a.conf",
        b"kernel.core_pattern = \xff\xfe\nkernel.\xc3 = 1\n",
        0o644,
    ));
    cd(s("values_nonnormal", &[]).conf("etc/sysctl.d/a.conf", "kernel/../kernel/sysrq = 1\n../etc/passwd = x\n"));
}

#[test]
fn duplicates() {
    let conf = "kernel.sysrq = 1\nkernel/sysrq = 1\n-kernel.sysrq = 1\nkernel.sysrq = 2\nkernel.pid_max = 1\n-kernel.pid_max\n";
    cd(s("duplicates", &[]).conf("etc/sysctl.d/a.conf", conf));
    cd(s("duplicates_across_files", &[])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\nkernel.pid_max = 2\n")
        .conf("etc/sysctl.d/b.conf", "kernel.sysrq = 3\n-kernel.pid_max = 2\n"));
}

#[test]
fn ignore_failure() {
    cd(s("ignore_failure", &[])
        .conf("etc/sysctl.d/a.conf", "-kernel.nonexistent = 1\nkernel.nonexistent2 = 1\n-net.ipv4.nope = 3\n"));
    cd(s("ignore_failure_strict", &["--strict"])
        .conf("etc/sysctl.d/a.conf", "-kernel.nonexistent = 1\nkernel.nonexistent2 = 1\n"));
    cd(s("enoent_strict", &["--strict"]).conf("etc/sysctl.d/a.conf", "kernel.nonexistent = 1\nkernel.sysrq = 1\n"));
    cd(s("eisdir", &[]).conf("etc/sysctl.d/a.conf", "kernel = 1\nkernel.sysrq = 1\n"));
    cd(s("eisdir_ignored", &[]).conf("etc/sysctl.d/a.conf", "-kernel = 1\n"));
    cd(s("enotdir", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq.x = 1\n"));
}

#[test]
fn permissions() {
    cd(s("eacces", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\nkernel.pid_max = 7\n").run_as(ALICE));
    cd(s("eacces_strict", &["--strict"]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n").run_as(ALICE));
    cd(s("eacces_same_value", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 16\n").run_as(ALICE));
    cd(s("erofs", &[])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\nnet.ipv4.ip_forward = 1\n")
        .read_only("/proc/sys/kernel"));
    cd(s("erofs_strict", &["--strict"])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n")
        .read_only("/proc/sys/kernel"));
    cd(s("erofs_same_value", &["--strict"])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 16\n")
        .read_only("/proc/sys/kernel"));
}

#[test]
fn redundant_and_verify() {
    cd(s("unchanged", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 16\nkernel.pid_max=32768   \n"));
    cd(s("unchanged_prefix", &[]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\nkernel.pid_max = 327\n"));
    cd(s("longer_old_value", &[])
        .conf("proc/sys/kernel/sysrq", "123456789\n")
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n"));
    cd(s("verify", &["--verify"])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\nkernel.pid_max = 32768\nkernel.nope = 3\n"));
    cd(s("verify_mismatch", &["--verify"])
        .conf("proc/sys/kernel/sysrq", "123456789\n")
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n"));
    cd(s("verify_eacces", &["--verify"]).conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n").run_as(ALICE));
    cd(s("verify_erofs", &["--verify", "--strict"])
        .conf("etc/sysctl.d/a.conf", "kernel.sysrq = 1\n")
        .read_only("/proc/sys/kernel"));
}

#[test]
fn globs() {
    let conf = "net.ipv4.conf.*.rp_filter = 2\nnet.ipv4.conf.eth0.rp_filter = 1\n-net.ipv4.conf.lo.rp_filter\n";
    cd(s("glob", &[]).conf("etc/sysctl.d/a.conf", conf));
    cd(s("glob_ignore", &[]).conf("etc/sysctl.d/a.conf", "-net.ipv4.conf.*.rp_filter = 2\n"));
    cd(s("glob_nomatch", &[]).conf("etc/sysctl.d/a.conf", "net.ipv4.nomatch.* = 2\nnet.*.x = 1\n"));
    cd(s("glob_strict", &["--strict"]).conf("etc/sysctl.d/a.conf", "net.ipv4.conf.*.rp_filter = 2\n"));
    cd(s("glob_eacces", &[]).conf("etc/sysctl.d/a.conf", "net.ipv4.conf.*.rp_filter = 2\n").run_as(ALICE));
    cd(s("glob_unreadable_dir", &[])
        .conf("etc/sysctl.d/a.conf", "net.ipv4.conf.*.rp_filter = 2\n")
        .dir("proc/sys/net/ipv4/conf", 0o700)
        .run_as(ALICE));
    cd(s("glob_dirs", &[]).conf("etc/sysctl.d/a.conf", "net.ipv4.conf.* = 1\nkernel.* = 2\n"));
    cd(s("glob_brace", &[])
        .conf("etc/sysctl.d/a.conf", "net.ipv4.conf.{all,lo}.rp_filter = 5\nkernel.[sp]* = 6\nkernel.sysr? = 7\n"));
    cd(s("glob_hidden", &[])
        .conf("proc/sys/kernel/.hidden", "0\n")
        .conf("etc/sysctl.d/a.conf", "kernel.* = 9\nkernel..* = 8\n"));
    cd(s("glob_negative_first", &[])
        .conf("etc/sysctl.d/a.conf", "-net.ipv4.conf.eth0.rp_filter\nnet.ipv4.conf.*.rp_filter = 3\n"));
}

#[test]
fn prefixes() {
    let conf =
        "kernel.sysrq = 1\nnet.ipv4.ip_forward = 1\nnet.ipv4.conf.*.rp_filter = 2\nnet.ipv4.conf.eth0.rp_filter = 1\n";
    for (n, p) in [
        ("prefix_net", "net"),
        ("prefix_dotted", "net.ipv4"),
        ("prefix_procsys", "/proc/sys/net/ipv4"),
        ("prefix_conf_eth0", "net.ipv4.conf.eth0"),
        ("prefix_conf_star", "net.ipv4.conf"),
        ("prefix_trailing", "kernel/"),
        ("prefix_partial", "ker"),
        ("prefix_glob", "net.ipv4.conf.*"),
        ("prefix_dotdot", "net/../kernel"),
        ("prefix_empty", ""),
        ("prefix_root", "/"),
    ] {
        cd(s(n, &["--prefix", p]).conf("etc/sysctl.d/a.conf", conf));
    }
    cd(s("prefix_multi", &["--prefix=kernel", "--prefix=net.ipv4.conf.lo"]).conf("etc/sysctl.d/a.conf", conf));
}

#[test]
fn explicit_files() {
    let conf = "kernel.sysrq = 1\n";
    cd(s("file_absolute", &["@T@/x.conf"]).conf("x.conf", conf));
    cd(s("file_relative", &["./x.conf"]).conf("x.conf", conf));
    cd(s("file_search", &["60-net.conf"])
        .conf("usr/lib/sysctl.d/60-net.conf", conf)
        .conf("etc/sysctl.d/60-net.conf", "kernel.sysrq = 2\n"));
    cd(s("file_search_run", &["99-x.conf"]).conf("run/sysctl.d/99-x.conf", conf));
    cd(s("file_missing", &["/nonexistent.conf", "missing.conf"]));
    cd(s("file_missing_abs_then_ok", &["/nonexistent.conf", "@T@/x.conf"]).conf("x.conf", conf));
    cd(s("file_dir", &["@T@/d"]).dir("d", 0o755));
    cd(s("file_unreadable", &["@T@/x.conf"]).file("x.conf", conf.as_bytes(), 0o600).run_as(ALICE));
    cd(s("file_stdin", &["-"]).stdin(b"kernel.sysrq = 3\nbad line\n"));
    cd(s("file_masked_still_read", &["50-default.conf"])
        .symlink("etc/sysctl.d/50-default.conf", "/dev/null")
        .conf("usr/lib/sysctl.d/50-default.conf", conf));
    cd(s("file_search_symlinked_dir", &["z.conf"])
        .symlink("etc/sysctl.d", "/usr/lib/sysctl.d")
        .conf("usr/lib/sysctl.d/z.conf", conf));
    cd(s("file_no_credentials", &["@T@/x.conf"])
        .conf("x.conf", conf)
        .env("CREDENTIALS_DIRECTORY", "@T@/creds")
        .conf("creds/sysctl.extra", "kernel.pid_max = 1\n"));
}

#[test]
fn inline() {
    cd(s(
        "inline",
        &["--inline", "kernel.sysrq=1", "  # comment", "", "  net.ipv4.ip_forward = 1", "bad", "-kernel.nope=1"],
    ));
    cd(s("inline_globs", &["--inline", "net.ipv4.conf.*.rp_filter=4", "-net.ipv4.conf.all.rp_filter"]));
    cd(s("inline_prefix", &["--inline", "--prefix=net", "kernel.sysrq=1", "net.ipv4.ip_forward=1"]));
}

#[test]
fn credentials() {
    cd(tree("credentials")
        .env("CREDENTIALS_DIRECTORY", "@T@/creds")
        .conf("creds/sysctl.extra", "kernel.pid_max = 1234\nbad\n"));
    cd(tree("credentials_missing_file").env("CREDENTIALS_DIRECTORY", "@T@/creds").dir("creds", 0o755));
    cd(tree("credentials_relative").env("CREDENTIALS_DIRECTORY", "creds"));
    cd(tree("credentials_unnormalized").env("CREDENTIALS_DIRECTORY", "@T@/./creds"));
}

#[test]
fn save_and_revert() {
    let conf =
        "kernel.sysrq = 1\n-net.ipv4.conf.*.rp_filter = 2\n-net.ipv4.conf.lo.rp_filter\nnet.ipv4.ip_forward=  \n";
    cd(s("save", &["--save=mine", "@T@/x.conf"]).conf("x.conf", conf));
    cd(s("save_conf_suffix", &["--save=mine.conf", "--inline", "kernel.sysrq=1"]));
    cd(s("save_prefix", &["--save=mine", "--prefix=kernel", "@T@/x.conf"]).conf("x.conf", conf));
    cd(s("save_nothing", &["--save=mine", "--inline", "# nothing"]));
    cd(s(
        "save_unsafe",
        &[
            "--save=mine",
            "--inline",
            "kernel.sysrq='1'",
            "kernel.core_pattern=a\\b",
            "kernel.pid_max=\x07",
            "kernel.x\ty=1",
        ],
    ));
    cd(s("save_same_content", &["--save=mine", "--inline", "kernel.sysrq=1"])
        .conf("run/sysctl.d/mine.conf", "# This is generated by systemd-sysctl.\nkernel.sysrq = 1\n"));
    cd(s("save_replace", &["--save=mine", "--inline", "kernel.sysrq=2"]).file(
        "run/sysctl.d/mine.conf",
        b"old\n",
        0o600,
    ));
    cd(s("save_parse_error", &["--save=mine", "@T@/x.conf", "/nonexistent.conf"]).conf("x.conf", conf));
    cd(s("save_run_unwritable", &["--save=mine", "--inline", "kernel.sysrq=1"]).run_as(ALICE));
    cd(s("save_run_sysctld_file", &["--save=mine", "--inline", "kernel.sysrq=1"]).conf("run/sysctl.d", "x"));
    cd(s("revert", &["--revert=mine"])
        .conf("run/sysctl.d/mine.conf", "kernel.sysrq = 1\n")
        .conf("etc/sysctl.d/a.conf", "kernel.pid_max = 1\n"));
    cd(s("revert_missing", &["--revert=mine.conf"]));
    cd(s("revert_dir", &["--revert=mine"]).dir("run/sysctl.d/mine.conf", 0o755));
    cd(s("revert_and_save", &["--revert=mine", "--save=mine", "--inline", "kernel.sysrq=3"])
        .conf("run/sysctl.d/mine.conf", "x\n"));
}

// ---------------------------------------------------------------------------
// --cat-config and --tldr

fn cat_tree(name: &str, args: &[&str]) -> Case {
    tree(name)
        .conf(
            "usr/lib/sysctl.d/10-comments.conf",
            "# A comment\n  ; another\n\n\\\nkernel.sysrq = 1 \\\nmore\nweird\\\\\n[Section]\nkey=value\n",
        )
        .symlink("etc/sysctl.d/20-masked.conf", "/dev/null")
        .symlink("etc/sysctl.d/30-link.conf", "/usr/lib/sysctl.d/50-default.conf")
        .args_replace(args)
}

trait ArgsReplace {
    fn args_replace(self, args: &[&str]) -> Case;
}

impl ArgsReplace for Case {
    fn args_replace(mut self, args: &[&str]) -> Case {
        self.args = args.iter().map(|s| s.to_string()).collect();
        self
    }
}

#[test]
fn cat_config() {
    cd(cat_tree("cat_config", &["--cat-config"]));
    cd(cat_tree("tldr", &["--tldr"]));
    cd(cat_tree("cat_config_empty_file", &["--cat-config"]).conf("etc/sysctl.d/05-empty.conf", ""));
    cd(cat_tree("cat_config_unreadable", &["--cat-config"])
        .file("etc/sysctl.d/05-secret.conf", b"x\n", 0o600)
        .run_as(ALICE));
    cd(s("cat_config_nothing", &["--cat-config"]));
}

// ---------------------------------------------------------------------------
// terminals, colors and the pager

const PAGER: &str = "#!/bin/sh\n{ echo \"args: $*\"; echo \"LESS=$LESS\"; echo \"LESSCHARSET=$LESSCHARSET\"; echo \"LESSSECURE=$LESSSECURE\"; cat; } > @T@/paged\n";

#[test]
fn tty() {
    for (n, term) in [("xterm", "xterm-256color"), ("dumb", "dumb"), ("linux", "linux")] {
        cd(cat_tree(&format!("tty_cat_{n}"), &["--cat-config", "--no-pager"]).pty(24, 80).env("TERM", term));
        cd(s(&format!("tty_help_{n}"), &["--help", "--no-pager"]).pty(24, 80).env("TERM", term));
        c(s(&format!("tty_version_{n}"), &["--version"]).pty(24, 80).env("TERM", term));
        c(s(&format!("tty_introspect_{n}"), &["--introspect-cli"]).pty(24, 80).env("TERM", term));
        c(s(&format!("tty_logs_{n}"), &["--inline", "kernel.nope=1", "bad"]).pty(24, 80).env("TERM", term));
    }
    for (n, k, v) in [
        ("16", "SYSTEMD_COLORS", "16"),
        ("24bit", "COLORTERM", "truecolor"),
        ("auto24", "SYSTEMD_COLORS", "auto-24bit"),
        ("no", "SYSTEMD_COLORS", "no"),
        ("bogus", "SYSTEMD_COLORS", "bogus"),
        ("nocolor", "NO_COLOR", "1"),
    ] {
        c(s(&format!("tty_colors_{n}"), &["--help", "--no-pager", "--inline", "bad"])
            .pty(24, 80)
            .env("TERM", "xterm")
            .env(k, v));
        c(s(&format!("tty_logcolors_{n}"), &["--inline", "kernel.nope=1", "bad"])
            .pty(24, 80)
            .env("TERM", "xterm")
            .env(k, v)
            .env("SYSTEMD_LOG_LEVEL", "debug"));
    }
    c(s("tty_help_narrow", &["--no-pager", "--help"]).pty(24, 33).env("TERM", "xterm"));
    c(s("colors_true_on_file", &["--help"]).env("SYSTEMD_COLORS", "true"));
    c(s("colors_256_on_file", &["--inline", "bad"]).env("SYSTEMD_COLORS", "256"));
    c(s("utf8_off", &["--help", "--cat-config"]).env("SYSTEMD_UTF8", "0").env("SYSTEMD_LOG_LEVEL", "debug"));
}

#[test]
fn pager() {
    let pc = |n: &str, args: &[&str]| {
        cat_tree(n, args)
            .pty(24, 80)
            .env("TERM", "xterm")
            .file("pager", PAGER.as_bytes(), 0o755)
            .env("SYSTEMD_PAGER", "@T@/pager --flag")
            .env("SYSTEMD_PAGERSECURE", "1")
            .sorted()
    };
    cd(pc("pager_cat", &["--cat-config"]));
    cd(pc("pager_help", &["--help"]));
    cd(pc("pager_no_pager", &["--no-pager", "--help"]));
    cd(pc("pager_less_opts", &["--cat-config"]).env("SYSTEMD_LESS", "abc").env("SYSTEMD_LESSCHARSET", "latin1"));
    cd(pc("pager_insecure", &["--cat-config"]).env("SYSTEMD_PAGERSECURE", "0"));
    cd(pc("pager_secure_bad", &["--cat-config"]).env("SYSTEMD_PAGERSECURE", "maybe").env("PATH", "/nonexistent"));
    cd(pc("pager_untrusted_fallback", &["--cat-config"]).no_env("SYSTEMD_PAGERSECURE").env("PATH", "/nonexistent"));
    cd(pc("pager_missing", &["--cat-config"]).env("SYSTEMD_PAGER", "/nonexistent/pager").env("PATH", "/nonexistent"));
    cd(pc("pager_env_pager", &["--cat-config"]).no_env("SYSTEMD_PAGER").env("PAGER", "@T@/pager"));
    cd(pc("pager_cat_disables", &["--cat-config"]).env("SYSTEMD_PAGER", "cat"));
    cd(pc("pager_empty_disables", &["--cat-config"]).env("SYSTEMD_PAGER", "  "));
    cd(pc("pager_dumb", &["--cat-config"]).env("TERM", "dumb"));
    c(pc("pager_not_tty", &["--cat-config"]).args_replace(&["--cat-config"]).no_pty());
}

trait NoPty {
    fn no_pty(self) -> Case;
}

impl NoPty for Case {
    fn no_pty(mut self) -> Case {
        self.pty = None;
        self
    }
}

// ---------------------------------------------------------------------------
// logging

#[test]
fn log_settings() {
    let base = |n: &str| s(n, &["--inline", "kernel.nope=1", "bad", "kernel.sysrq=1"]);
    for (n, k, v) in [
        ("level_debug", "SYSTEMD_LOG_LEVEL", "debug"),
        ("level_err", "SYSTEMD_LOG_LEVEL", "err"),
        ("level_number", "SYSTEMD_LOG_LEVEL", "4"),
        ("level_bad", "SYSTEMD_LOG_LEVEL", "loud"),
        ("level_bad_number", "SYSTEMD_LOG_LEVEL", "8"),
        ("level_targets", "SYSTEMD_LOG_LEVEL", "debug,console:warning"),
        ("level_target_bad", "SYSTEMD_LOG_LEVEL", "syslog:debug,bogus:info"),
        ("level_target_auto", "SYSTEMD_LOG_LEVEL", "auto:info"),
        ("target_null", "SYSTEMD_LOG_TARGET", "null"),
        ("target_console_prefixed", "SYSTEMD_LOG_TARGET", "console-prefixed"),
        ("target_bad", "SYSTEMD_LOG_TARGET", "elsewhere"),
        ("target_syslog", "SYSTEMD_LOG_TARGET", "syslog"),
        ("target_kmsg", "SYSTEMD_LOG_TARGET", "kmsg"),
        ("target_syslog_or_kmsg", "SYSTEMD_LOG_TARGET", "syslog-or-kmsg"),
        ("target_journal_missing", "SYSTEMD_LOG_TARGET", "journal"),
        ("target_journal_or_kmsg", "SYSTEMD_LOG_TARGET", "journal-or-kmsg"),
        ("time", "SYSTEMD_LOG_TIME", "1"),
        ("tid", "SYSTEMD_LOG_TID", "yes"),
        ("color_on_file", "SYSTEMD_LOG_COLOR", "on"),
        ("color_bad", "SYSTEMD_LOG_COLOR", "rainbow"),
        ("location_bad", "SYSTEMD_LOG_LOCATION", "where"),
        ("debug_invocation", "DEBUG_INVOCATION", "1"),
        ("debug_invocation_bad", "DEBUG_INVOCATION", "sure"),
        ("ratelimit_bad", "SYSTEMD_LOG_RATELIMIT_KMSG", "x"),
    ] {
        c(base(n).env(k, v));
    }
    c(base("time_tid_prefixed")
        .env("SYSTEMD_LOG_TIME", "1")
        .env("SYSTEMD_LOG_TID", "1")
        .env("SYSTEMD_LOG_TARGET", "console-prefixed"));
    c(base("time_tz").env("SYSTEMD_LOG_TIME", "1").env("TZ", "Europe/Berlin"));
    c(base("kmsg_debug").env("SYSTEMD_LOG_TARGET", "kmsg").env("SYSTEMD_LOG_LEVEL", "debug"));
    c(base("syslog_debug")
        .env("SYSTEMD_LOG_TARGET", "syslog")
        .env("SYSTEMD_LOG_LEVEL", "debug")
        .env("TZ", "Europe/Berlin"));
    c(base("journal").env("SYSTEMD_LOG_TARGET", "journal").journal());
    c(base("journal_debug").env("SYSTEMD_LOG_TARGET", "journal").env("SYSTEMD_LOG_LEVEL", "debug").journal());
    c(base("journal_auto_stream").env("JOURNAL_STREAM", "0:0").journal());
    c(base("exec_pid_star")
        .env("SYSTEMD_EXEC_PID", "*")
        .env("SYSTEMD_PROC_CMDLINE", "systemd.log_level=debug systemd.log-target=console-prefixed rd.x quiet"));
    c(base("exec_pid_cmdline_bad").env("SYSTEMD_EXEC_PID", "*").env(
        "SYSTEMD_PROC_CMDLINE",
        "systemd.log_level systemd.log_target=x systemd.log_color=x systemd.log_time systemd.log_tid=0",
    ));
    c(base("exec_pid_debug")
        .env("SYSTEMD_EXEC_PID", "*")
        .env("SYSTEMD_PROC_CMDLINE", "debug \"systemd.log_level=warning\""));
    c(base("exec_pid_other").env("SYSTEMD_EXEC_PID", "1").env("SYSTEMD_PROC_CMDLINE", "debug"));
    c(base("exec_pid_bad").env("SYSTEMD_EXEC_PID", "abc").env("SYSTEMD_LOG_LEVEL", "debug"));
    c(base("exec_pid_initrd")
        .env("SYSTEMD_EXEC_PID", "*")
        .env("SYSTEMD_IN_INITRD", "1")
        .env("SYSTEMD_PROC_CMDLINE", "rd.systemd.log_level=debug"));
}

#[test]
fn notify() {
    c(s("notify_missing_socket", &["--inline", "kernel.nope=1"]).env("NOTIFY_SOCKET", "@T@/nope"));
    c(s("notify_bad_address", &["--inline", "bad"]).env("NOTIFY_SOCKET", "relative"));
}
