// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential tests for systemd-tmpfiles: the C build and the port, run
//! on the same trees with the same configuration.  Targets live under
//! `@T@/w`; configuration is `@T@/t.conf` unless a case says otherwise.

#[path = "../../../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::{ALICE, BOB, Case, Program, check, reference_build};

fn prog() -> Program {
    Program {
        name: "systemd-tmpfiles",
        c: reference_build().join("systemd-tmpfiles"),
        rust: PathBuf::from(env!("CARGO_BIN_EXE_systemd-tmpfiles")),
    }
}

/// 2033-05-18: well after any real ctime or btime, for clean tests.
const FUTURE: i64 = 2_000_000_000;
/// A day before FUTURE.
const OLD: i64 = FUTURE - 86_400 * 3;
/// A minute before FUTURE.
const NEW: i64 = FUTURE - 60;

/// A case with the tmpfiles.d hierarchy under T and an empty `w`, on a
/// root of the sandbox's own (so CHASE_SAFE accepts the path down to T).
fn s(name: &str, args: &[&str]) -> Case {
    Case::new(name, args)
        .own_root()
        .etc_own("tmpfiles.d")
        .bind("/run", "run")
        .bind("/usr/lib/tmpfiles.d", "usr/lib/tmpfiles.d")
        .bind("/usr/local/lib", "usr/local/lib")
        .dir("w", 0o755)
}

/// `s()` running `ops` on `@T@/t.conf`, which holds `conf`.
fn t(name: &str, ops: &[&str], conf: &str) -> Case {
    let mut args = ops.to_vec();
    args.push("@T@/t.conf");
    s(name, &args).conf("t.conf", conf)
}

/// `t()` with --create.
fn cr(name: &str, conf: &str) -> Case {
    t(name, &["--create"], conf)
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

/// The case, with the debug log, and with --dry-run (plus debug).
fn cdn(case: Case) {
    let mut n = case.clone();
    n.name = format!("{}_dry", case.name);
    let pos = n.args.iter().position(|a| a.starts_with("--")).unwrap_or(0);
    n.args.insert(pos, "--dry-run".into());
    cd(case);
    cd(n);
}

// ---------------------------------------------------------------------------
// command line

#[test]
fn help() {
    c(s("help", &["--help"]));
    c(s("help_short", &["-h"]));
    c(s("help_narrow", &["--help"]).env("COLUMNS", "40"));
    c(s("help_wide", &["--help"]).env("COLUMNS", "200"));
    c(s("version", &["--version"]));
    c(s("introspect", &["--introspect-cli"]));
}

#[test]
fn bad_options() {
    c(s("no_operation", &[]));
    c(s("no_operation_args", &["@T@/t.conf"]));
    c(s("bad_long", &["--frobnicate"]));
    c(s("bad_short", &["-x"]));
    c(s("missing_arg", &["--create", "--root"]));
    c(s("purge_no_config", &["--purge"]));
    c(s("replace_relative", &["--create", "--replace=x.conf", "a"]));
    c(s("replace_no_conf", &["--create", "--replace=/etc/tmpfiles.d/x", "a"]));
    c(s("replace_no_args", &["--create", "--replace=/etc/tmpfiles.d/x.conf"]));
    c(s("replace_cat", &["--cat-config", "--replace=/etc/tmpfiles.d/x.conf", "a"]));
    c(s("inline_cat", &["--cat-config", "--inline"]));
    c(s("user_root", &["--create", "--user", "--root=/"]));
    c(s("image_root", &["--create", "--image=/x.img", "--root=/x"]));
    c(s("root_empty", &["--create", "--root=", "--inline", "d @T@/w/a"]));
}

// ---------------------------------------------------------------------------
// configuration discovery

/// A hierarchy of tmpfiles.d directories.
fn tree(name: &str, args: &[&str]) -> Case {
    s(name, args)
        .conf("etc/tmpfiles.d/10-etc.conf", "d @T@/w/etc 0700\n")
        .conf("etc/tmpfiles.d/20-masked.conf", "")
        .conf("run/tmpfiles.d/20-masked.conf", "d @T@/w/masked\n")
        .conf("run/tmpfiles.d/30-run.conf", "d @T@/w/run\n")
        .conf("usr/lib/tmpfiles.d/30-run.conf", "d @T@/w/shadowed\n")
        .conf("usr/lib/tmpfiles.d/40-lib.conf", "f @T@/w/lib 0640 - - - lib\n")
        .conf("usr/local/lib/tmpfiles.d/50-local.conf", "L @T@/w/local - - - - lib\n")
        .conf("usr/lib/tmpfiles.d/notconf.txt", "d @T@/w/txt\n")
}

#[test]
fn hierarchy() {
    cd(tree("tree_create", &["--create"]));
    cd(tree("tree_cat", &["--cat-config", "--no-pager"]));
    c(tree("tree_tldr", &["--tldr", "--no-pager"]));
    cd(tree("tree_replace", &["--create", "--replace=/etc/tmpfiles.d/30-run.conf", "--inline", "d @T@/w/replaced"]));
    cd(tree("tree_replace_new", &["--create", "--replace=/etc/tmpfiles.d/35-new.conf", "--inline", "d @T@/w/new"]));
    cd(tree("tree_replace_lower", &["--create", "--replace=/usr/lib/tmpfiles.d/10-etc.conf", "--inline", "d @T@/w/x"]));
    cd(tree("tree_by_name", &["--create", "40-lib.conf"]));
    cd(tree("tree_by_name_missing", &["--create", "99-none.conf"]));
    cd(tree("tree_prefix", &["--create", "--prefix=@T@/w/run", "--prefix=@T@/w/lib"]));
    cd(tree("tree_exclude", &["--create", "--exclude-prefix=@T@/w/run"]));
    cd(tree("tree_e", &["--create", "-E"]));
    cd(tree("tree_stdin", &["--create", "-"]).stdin(b"d @T@/w/stdin\n"));
    c(tree("tree_bypass", &["--create"]).env("SYSTEMD_TMPFILES_BYPASS", "1"));
    c(tree("tree_bypass_bad", &["--create"]).env("SYSTEMD_TMPFILES_BYPASS", "maybe").env("SYSTEMD_LOG_LEVEL", "debug"));
    cd(tree("tree_relative", &["--create", "t.conf"]));
    cd(tree("tree_missing_path", &["--create", "@T@/none.conf"]));
    cd(tree("tree_dir_as_conf", &["--create", "@T@/w"]));
}

#[test]
fn credentials() {
    cd(s("cred_extra", &["--create"])
        .conf("creds/tmpfiles.extra", "d @T@/w/fromcred 0711\n")
        .env("CREDENTIALS_DIRECTORY", "@T@/creds"));
    cd(s("cred_dir_bad", &["--create"]).env("CREDENTIALS_DIRECTORY", "relative"));
    cd(s("cred_dir_missing", &["--create"]).env("CREDENTIALS_DIRECTORY", "@T@/nocreds"));
    cd(cr("cred_line", "f^ @T@/w/secret 0600 - - - mysecret\n")
        .conf("creds/mysecret", "s3cr3t\0binary\n")
        .env("CREDENTIALS_DIRECTORY", "@T@/creds"));
    cd(cr("cred_line_missing", "f^ @T@/w/secret 0600 - - - nope\n").env("CREDENTIALS_DIRECTORY", "@T@/creds"));
    cd(cr("cred_line_unset", "f^ @T@/w/secret 0600 - - - nope\n"));
    cd(cr("cred_line_noname", "f^ @T@/w/secret\n"));
    cd(cr("cred_line_badname", "f^ @T@/w/secret - - - - a:b\n"));
    cd(cr("cred_line_b64", "w^~ @T@/w/f - - - - b64\n")
        .file("w/f", b"old\n", 0o644)
        .conf("creds/b64", "aGVsbG8gd29ybGQK")
        .env("CREDENTIALS_DIRECTORY", "@T@/creds"));
}

// ---------------------------------------------------------------------------
// parsing

#[test]
fn parse_errors() {
    for (name, line) in [
        ("syntax", "d"),
        ("bad_quote", "d \"@T@/w/a"),
        ("unknown_type", "y @T@/w/a"),
        ("unknown_modifier", "d% @T@/w/a"),
        ("double_modifier", "d-- @T@/w/a"),
        ("relative", "d w/a"),
        ("argument_not_allowed", "d @T@/w/a - - - - arg"),
        ("w_no_arg", "w @T@/w/a"),
        ("c_no_arg", "c @T@/w/a"),
        ("c_bad_devnum", "c @T@/w/a - - - - 1-3"),
        ("c_b64", "c~ @T@/w/a - - - - 1:3"),
        ("L_b64", "L~ @T@/w/a - - - - x"),
        ("C_b64", "C~ @T@/w/a - - - - /etc"),
        ("t_no_arg", "t @T@/w/a"),
        ("t_b64", "t~ @T@/w/a - - - - user.a=b"),
        ("a_no_arg", "a @T@/w/a"),
        ("a_b64", "a~ @T@/w/a - - - - u::rw"),
        ("k_no_arg", "k @T@/w/a"),
        ("k_b64", "k~ @T@/w/a - - - - cap_chown=ep"),
        ("h_no_arg", "h @T@/w/a"),
        ("h_b64", "h~ @T@/w/a - - - - +i"),
        ("h_no_spec", "h @T@/w/a - - - - +"),
        ("h_unknown_attr", "h @T@/w/a - - - - +Z"),
        ("purge_bad_type", "x$ @T@/w/a"),
        ("question_bad_type", "d? @T@/w/a"),
        ("bad_mode", "d @T@/w/a 999"),
        ("bad_mode_text", "d @T@/w/a rwx"),
        ("bad_user", "d @T@/w/a - nosuchuser"),
        ("bad_group", "d @T@/w/a - - nosuchgroup"),
        ("bad_uid", "d @T@/w/a - 4294967295"),
        ("bad_age", "d @T@/w/a - - - 5x"),
        ("bad_age_by", "d @T@/w/a - - - q:5d"),
        ("empty_age_by", "d @T@/w/a - - - :5d"),
        ("tilde_age_r", "r @T@/w/a - - - ~5d"),
        ("bad_specifier", "d @T@/w/%y"),
        ("bad_specifier_arg", "f @T@/w/a - - - - %y"),
        ("C_relative_src", "C @T@/w/a - - - - etc"),
        ("bad_b64", "f~ @T@/w/a - - - - !!!"),
        ("bad_escape", "f @T@/w/a - - - - \\x"),
        ("long_path", &format!("d @T@/w/{}", "x".repeat(5000))),
    ] {
        cd(cr(&format!("parse_{name}"), &format!("{line}\n")));
    }
    // Errors on several lines, and a good line after them: all reported,
    // the good one still applied, exit status 65.
    cd(cr("parse_mixed", "y @T@/w/a\nd @T@/w/good\nd w/rel\n# comment\n\n   \nd @T@/w/good2 0700\n"));
    // An inline error: (argument):N.
    cd(s("parse_inline", &["--create", "--inline", "d @T@/w/a", "y @T@/w/b", "d @T@/w/c"]));
    // Errors that are not configuration errors: exit status 73.
    cd(cr("create_failure_status", "d @T@/w/nodir/x\nf @T@/w/f\n").file("w/nodir", b"", 0o644));
}

#[test]
fn parse_fields() {
    cdn(cr(
        "fields",
        "d   @T@/w/a   0700   -   -   -\n\
         d\t@T@/w/b\t-\t-\t-\t-\n\
         d \"@T@/w/with space\" 0711\n\
         d '@T@/w/quoted' 0711\n\
         d @T@/w/esc\\x41pe 0711\n\
         d @T@/w//double//slash/ 0711\n\
         d @T@/w/./dot/../dotdot 0711\n\
         f @T@/w/argsp - - - - two  spaces  kept\n\
         f @T@/w/argdash - - - - -\n\
         f @T@/w/argesc - - - - tab\\there\\nnewline\n\
         f @T@/w/argquote - - - - \"quoted arg\"\n",
    ));
    cd(cr("var_run", "d /var/run/x 0700\nd /var/run 0755\n").env("SYSTEMD_LOG_LEVEL", "notice"));
    cd(cr("boot_skip", "d! @T@/w/boot\nd @T@/w/always\n"));
    cd(t("boot_run", &["--create", "--boot"], "d! @T@/w/boot\nd @T@/w/always\n"));
    cd(cr("modes", "d @T@/w/a 1777\nd @T@/w/b :0700\nd @T@/w/c ~0777\nf @T@/w/f 4755\nf @T@/w/g 0\n"));
    cd(cr("default_modes", "d @T@/w/d\nf @T@/w/f\np @T@/w/p\nv @T@/w/v\n"));
    cd(cr("owners", "d @T@/w/a - alice bob\nd @T@/w/b - 1001 100\nd @T@/w/c - :alice :users\nd @T@/w/d - root root\n"));
    cd(t("graceful", &["--create", "--graceful"], "d @T@/w/a 4755 nosuchuser nosuchgroup\nd @T@/w/b - nosuchuser\n"));
    cd(cr(
        "ages",
        "d @T@/w/a - - - 10d\nd @T@/w/b - - - ~1h\nd @T@/w/c - - - aBm:1w\nd @T@/w/d - - - 0\nd @T@/w/e - - - infinity\n",
    ));
}

#[test]
fn specifiers() {
    cd(cr(
        "specifiers",
        "f @T@/w/spec - - - - m=%m b=%b H=%H l=%l q=%q v=%v a=%a o=%o w=%w B=%B W=%W A=%A M=%M\n\
         f @T@/w/creds - - - - u=%u U=%U g=%g G=%G h=%h T=%T V=%V\n\
         f @T@/w/dirs - - - - t=%t S=%S C=%C L=%L D=%D %%=%% end%\n\
         d @T@/w/%m\n",
    ));
    cd(cr("specifiers_user", "f @T@/w/u - - - - u=%u h=%h t=%t\n").run_as(ALICE).dir_owned("w", 0o755, 1001, 1001));
    cd(cr("specifier_tmp_env", "f @T@/w/t - - - - T=%T V=%V\n").env("TMPDIR", "@T@/tmp").env("TMP", "/x"));
    cd(cr("specifier_xattr", "f @T@/w/f\nt @T@/w/f - - - - user.%m=%H\n").meta());
}

#[test]
fn duplicates() {
    cd(cr("dup_same", "d @T@/w/a 0700\nd @T@/w/a 0700\n"));
    cd(cr("dup_conflict", "d @T@/w/a 0700\nd @T@/w/a 0711\n"));
    cd(cr("dup_compatible", "d @T@/w/a 0700\nz @T@/w/a 0711\n"));
    cd(cr("dup_w_plus", "f @T@/w/f\nw+ @T@/w/f - - - - one\nw+ @T@/w/f - - - - two\n"));
    cd(cr("dup_w", "f @T@/w/f\nw @T@/w/f - - - - one\nw @T@/w/f - - - - two\n"));
    cd(cr("order_by_type", "z @T@/w/a 0711\nd @T@/w/a 0700\nm @T@/w/a 0755\n"));
    cd(cr("x_inherits_age", "d @T@/w/a - - - 1d\nX @T@/w/a/*\nd @T@/w/b - - - 2d\nX @T@/w/b\n"));
}

// ---------------------------------------------------------------------------
// creating

#[test]
fn files() {
    cdn(cr("f_new", "f @T@/w/f 0640 alice users - hello\\n\n"));
    cdn(cr("f_exists", "f @T@/w/f 0640 alice users - new\n").file("w/f", b"old\n", 0o600));
    cdn(cr("f_exists_only_create", "f @T@/w/f :0640 :alice :users - new\n").file("w/f", b"old\n", 0o600));
    cdn(cr("f_dir", "f @T@/w/d\n").dir("w/d", 0o755));
    cdn(cr("f_symlink", "f @T@/w/l\n").symlink("w/l", "target"));
    cdn(cr("f_plus", "f+ @T@/w/f 0600 - - - new\n").file("w/f", b"old contents\n", 0o644));
    cdn(cr("f_plus_new", "f+ @T@/w/f 0600 - - - new\n"));
    cdn(cr("f_plus_empty", "f+ @T@/w/f 0600\n").file("w/f", b"", 0o644));
    cdn(cr("F_trunc", "F @T@/w/f 0600 - - - x\n").file("w/f", b"old contents\n", 0o644));
    cdn(cr("F_not_regular", "F @T@/w/p\n").fifo("w/p", 0o644));
    cdn(cr("f_parents", "f @T@/w/a/b/c 0600\n"));
    cdn(cr("f_parent_is_file", "f @T@/w/a/b 0600\n").file("w/a", b"", 0o644));
    cdn(cr("f_b64", "f~ @T@/w/f - - - - aGVsbG8K\n"));
    cdn(cr("f_hardlink", "f @T@/w/f 0600 alice\nz @T@/w/h 0600 alice\n")
        .file("w/g", b"x", 0o644)
        .hardlink("w/f", "w/g")
        .hardlink("w/h", "w/g"));
    // With fs.protected_hardlinks off, changing a hard-linked file is refused.
    cdn(cr(
        "hardlink_unprotected",
        "z @T@/w/h 0600 alice\na @T@/w/h - - - - u:bob:r\nk @T@/w/h - - - - cap_chown=ep\n",
    )
    .file("w/g", b"x", 0o644)
    .hardlink("w/h", "w/g")
    .bind("/proc/sys/fs", "fakeproc/fs")
    .conf("fakeproc/fs/protected_hardlinks", "0\n"));
    cdn(cr("hardlink_sysctl_bad", "z @T@/w/h 0600 alice\n")
        .file("w/g", b"x", 0o644)
        .hardlink("w/h", "w/g")
        .bind("/proc/sys/fs", "fakeproc/fs")
        .conf("fakeproc/fs/protected_hardlinks", "maybe\n"));
    cdn(cr("hardlink_sysctl_missing", "z @T@/w/h 0600 alice\n")
        .file("w/g", b"x", 0o644)
        .hardlink("w/h", "w/g")
        .bind("/proc/sys/fs", "fakeproc/fs"));
    cd(cr("f_ro", "f @T@/w/ro/f 0600\nF @T@/w/ro/g 0600\nF @T@/w/ro/e 0644\n")
        .dir("w/ro", 0o755)
        .file("w/ro/g", b"data", 0o644)
        .file("w/ro/e", b"", 0o644)
        .read_only("@T@/w/ro"));
    cdn(cr("w_write", "w @T@/w/f - - - - new\n").file("w/f", b"old\n", 0o644));
    cdn(cr("w_append", "w+ @T@/w/f - - - - new\n").file("w/f", b"old\n", 0o644));
    cdn(cr("w_missing", "w @T@/w/f - - - - new\n"));
    cdn(cr("w_glob", "w @T@/w/*.txt 0600 - - - glob\n")
        .file("w/a.txt", b"", 0o644)
        .file("w/b.txt", b"", 0o644)
        .file("w/c.dat", b"", 0o644));
    cdn(cr("w_dir", "w @T@/w/d - - - - x\n").dir("w/d", 0o755));
    cdn(cr("w_fifo_minus", "w- @T@/w/p - - - - x\n").dir("w/p", 0o755));
    cdn(cr("w_mode", "w @T@/w/f 0600 bob - - new\n").file("w/f", b"old\n", 0o644));
}

#[test]
fn directories() {
    cdn(cr("d_new", "d @T@/w/d 0750 alice users\n"));
    cdn(cr("d_exists", "d @T@/w/d 0750 alice users\n").dir("w/d", 0o700));
    cdn(cr("d_exists_only_create", "d @T@/w/d :0750 :alice :users\n").dir("w/d", 0o700));
    cdn(cr("d_is_file", "d @T@/w/d\n").file("w/d", b"", 0o644));
    cdn(cr("d_is_symlink_dir", "d @T@/w/d\n").dir("w/real", 0o755).symlink("w/d", "real"));
    cdn(cr("d_minus_fail", "d- @T@/w/nodir/d\n").file("w/nodir", b"", 0o644));
    cdn(cr("d_replace", "d= @T@/w/a/b/c 0700\n").file("w/a/b", b"file", 0o644));
    cdn(cr("d_replace_dir", "f= @T@/w/a/d 0700\n").dir("w/a/d/sub", 0o755).file("w/a/d/sub/x", b"x", 0o644));
    cdn(cr("d_replace_symlink", "d= @T@/w/a/b 0700\n").symlink("w/a/b", "/nonexistent"));
    cdn(cr("d_mask", "d @T@/w/d ~0777\n").dir("w/d", 0o750));
    cdn(cr("D_create", "D @T@/w/d 0700\n"));
    cdn(cr("e_existing", "e @T@/w/d 0700 alice\ne @T@/w/missing 0700\ne @T@/w/f 0700\n")
        .dir("w/d", 0o755)
        .file("w/f", b"", 0o644));
    cdn(cr("e_glob", "e @T@/w/d* 0711\n").dir("w/d1", 0o755).dir("w/d2", 0o755));
    cdn(cr("v_subvol", "v @T@/w/v 0700\n"));
    cdn(cr("v_exists", "v @T@/w/v 0700\n").dir("w/v", 0o755));
    cdn(cr("q_subvol", "q @T@/w/q 0700\nQ @T@/w/Q 0700\n"));
    cd(cr("v_force_env", "v @T@/w/v 0700\n").env("SYSTEMD_TMPFILES_FORCE_SUBVOL", "0"));
    cd(cr("v_force_env_bad", "v @T@/w/v 0700\n").env("SYSTEMD_TMPFILES_FORCE_SUBVOL", "x"));
}

#[test]
fn nodes() {
    cdn(cr("p_new", "p @T@/w/p 0600 alice\n"));
    cdn(cr("p_exists", "p @T@/w/p 0600\n").fifo("w/p", 0o644));
    cdn(cr("p_wrong", "p @T@/w/p\n").file("w/p", b"", 0o644));
    cdn(cr("p_force", "p+ @T@/w/p 0640\n").file("w/p", b"", 0o644));
    cdn(cr("p_force_dir", "p+ @T@/w/p 0640\n").dir("w/p/sub", 0o755).file("w/p/sub/f", b"", 0o644));
    cdn(cr("c_node", "c @T@/w/null 0666 - - - 1:3\nb @T@/w/blk 0660 - - - 8:0\n"));
    cdn(cr("c_node_plus", "c+ @T@/w/null 0666 - - - 1:3\n").file("w/null", b"", 0o644));
}

#[test]
fn symlinks() {
    cdn(cr("L_new", "L @T@/w/l - - - - target\n"));
    cdn(cr("L_correct", "L @T@/w/l - - - - target\n").symlink("w/l", "target"));
    cdn(cr("L_wrong", "L @T@/w/l - - - - target\n").symlink("w/l", "other"));
    cdn(cr("L_force", "L+ @T@/w/l - - - - target\n").symlink("w/l", "other"));
    cdn(cr("L_force_file", "L+ @T@/w/l - - - - target\n").file("w/l", b"", 0o644));
    cdn(cr("L_force_dir", "L+ @T@/w/l - - - - target\n").dir("w/l/x", 0o755).file("w/l/x/y", b"", 0o644));
    cdn(cr("L_default_target", "L @T@/w/l\n"));
    cdn(cr("L_owner", "L @T@/w/l - alice users - target\n"));
    cdn(cr("L_question_missing", "L? @T@/w/l - - - - missing\nL? @T@/w/m - - - - @T@/w/missing\n"));
    cdn(cr("L_question_present", "L? @T@/w/l - - - - there\nL? @T@/w/m - - - - @T@/w/there\n")
        .file("w/there", b"", 0o644));
    cdn(cr("L_parents", "L @T@/w/a/b/l - - - - t\n"));
    cdn(cr("L_replace_parent", "L= @T@/w/a/l - - - - t\n").file("w/a", b"", 0o644));
}

#[test]
fn copies() {
    let src = |c: Case| {
        c.dir("src/tree/sub", 0o750)
            .file("src/tree/a", b"aaa\n", 0o640)
            .file("src/tree/sub/b", b"bbb\n", 0o600)
            .symlink("src/tree/link", "a")
            .fifo("src/tree/fifo", 0o600)
            .file("src/file", b"single\n", 0o604)
    };
    cdn(src(cr("C_tree", "C @T@/w/tree - - - - @T@/src/tree\n")));
    cdn(src(cr("C_file", "C @T@/w/file - - - - @T@/src/file\n")));
    cdn(src(cr("C_owner", "C @T@/w/tree - alice users - @T@/src/tree\n")));
    cdn(src(cr("C_exists_empty", "C @T@/w/tree - - - - @T@/src/tree\n")).dir("w/tree", 0o700));
    cdn(src(cr("C_exists_full", "C @T@/w/tree - - - - @T@/src/tree\n")).file("w/tree/keep", b"k", 0o644));
    cdn(src(cr("C_merge", "C+ @T@/w/tree - - - - @T@/src/tree\n"))
        .file("w/tree/keep", b"k", 0o644)
        .file("w/tree/a", b"mine", 0o644));
    cdn(src(cr("C_exists_file", "C @T@/w/file - - - - @T@/src/file\n")).file("w/file", b"mine", 0o644));
    cdn(src(cr("C_wrong_type", "C @T@/w/tree - - - - @T@/src/tree\n")).file("w/tree", b"mine", 0o644));
    cdn(src(cr("C_missing_src", "C @T@/w/x - - - - @T@/src/none\n")));
    cdn(src(cr("C_default_src", "C @T@/w/x\n")));
    cdn(src(cr("C_bang", "C! @T@/w/tree - - - - @T@/src/tree\n")));
    cd(src(cr("C_hardlinks", "C @T@/w/tree - - - - @T@/src/tree\n"))
        .file("src/tree/h1", b"hard\n", 0o644)
        .hardlink("src/tree/sub/h2", "src/tree/h1")
        .hardlink("src/tree/h3", "src/tree/h1")
        .meta());
    cd(src(cr("C_xattr", "t @T@/src/file - - - - user.k=v\nC @T@/w/file - - - - @T@/src/file\n")).meta());
}

#[test]
fn adjust() {
    let tr = |c: Case| {
        c.dir("w/d/sub", 0o700)
            .file("w/d/a", b"", 0o600)
            .file("w/d/sub/b", b"", 0o644)
            .symlink("w/d/l", "a")
            .file("w/x.conf", b"", 0o644)
            .file("w/y.conf", b"", 0o600)
    };
    cdn(tr(cr("z_mode", "z @T@/w/d 0755 alice users\n")));
    cdn(tr(cr("z_glob", "z @T@/w/*.conf 0640 bob\n")));
    cdn(tr(cr("z_missing", "z @T@/w/none 0640\nz @T@/w/no*ne 0640\n")));
    cdn(tr(cr("Z_recursive", "Z @T@/w/d 0750 alice users\n")));
    cdn(tr(cr("Z_mask", "Z @T@/w/d ~0775\n")));
    // ~ keeps only the permission classes already set, and drops
    // suid/sgid/sticky except on directories.
    cdn(tr(cr("z_mask_suid", "z @T@/w/x.conf ~6755\nz @T@/w/d ~7777\nz @T@/w/y.conf ~4777\n")));
    cdn(tr(cr("m_legacy", "m @T@/w/x.conf 0600 alice\n")));
    cdn(tr(cr("z_owner_only", "z @T@/w/d - alice\nz @T@/w/x.conf - - users\n")));
    cdn(tr(cr("z_minus", "z- @T@/w/none 0640\n")));
    cdn(tr(cr("z_unsafe", "z @T@/w/u/link 0600\n"))
        .dir_owned("w/u", 0o755, 1001, 1001)
        .symlink("w/u/link", "../x.conf"));
    cdn(tr(cr("z_dotdot_glob", "z @T@/w/d/* 0700\n")));
}

#[test]
fn xattrs_acls_attrs() {
    let tr = |c: Case| c.dir("w/d/sub", 0o755).file("w/d/f", b"", 0o644).file("w/f", b"", 0o644).meta();
    cdn(tr(cr("t_set", "t @T@/w/f - - - - user.a=1 \"user.b=two words\" user.c\n")));
    cdn(tr(cr("t_bad", "t @T@/w/f - - - - user.a= =x noeq\n")));
    cdn(tr(cr("t_trusted", "t @T@/w/f - - - - trusted.a=1\n")));
    cdn(tr(cr("T_recursive", "T @T@/w/d - - - - user.r=1\n")));
    cdn(tr(cr("a_set", "a @T@/w/f - - - - u:alice:rw,g:users:r\n")));
    cdn(tr(cr("a_plus", "a+ @T@/w/f - - - - u:bob:r\n")));
    cdn(tr(cr("a_default", "a @T@/w/d - - - - d:u:alice:rwx,u:bob:r\n")));
    cdn(tr(cr("A_recursive", "A @T@/w/d - - - - u:alice:rX\n")));
    cdn(tr(cr("A_recursive_plus", "A+ @T@/w/d - - - - u:alice:rX\n")));
    cdn(tr(cr("a_bad", "a @T@/w/f - - - - u:nosuch:rw\n")));
    cdn(tr(t("a_bad_graceful", &["--create", "--graceful"], "a @T@/w/f - - - - u:nosuch:rw\n")));
    cdn(tr(cr("a_garbage", "a @T@/w/f - - - - garbage\n")));
    cdn(tr(cr("a_mask", "a @T@/w/f - - - - u:alice:rwx,m::r\n")));
    cdn(tr(cr("a_hardlink", "a @T@/w/f - - - - u:alice:r\n")).hardlink("w/f2", "w/f"));
    cdn(tr(cr("h_set", "h @T@/w/f - - - - +A\nh @T@/w/d - - - - =A\n")));
    cdn(tr(cr("h_unset", "h @T@/w/f - - - - -A\n")));
    cdn(tr(cr("H_recursive", "H @T@/w/d - - - - +d\n")));
    cdn(tr(cr("h_dirsync", "h @T@/w/f - - - - +D\nh @T@/w/d - - - - +D\n")));
    cdn(tr(cr("h_immutable", "h @T@/w/f - - - - +i\n")));
    cdn(tr(cr("h_fifo", "h @T@/w/p - - - - +A\n")).fifo("w/p", 0o644));
    cdn(tr(cr("h_set_empty", "h @T@/w/f - - - - =\n")));
    cdn(tr(cr("k_caps", "k @T@/w/f - - - - cap_net_raw+ep\n")));
    cdn(tr(cr("k_caps_more", "k @T@/w/f - - - - cap_chown,cap_kill=ep cap_kill-e rootuid=1001\n")));
    cdn(tr(cr("k_caps_all", "k @T@/w/f - - - - all=p\n")));
    cdn(tr(cr("k_caps_numbers", "k @T@/w/f - - - - 0,1,62=i\n")));
    cdn(tr(cr("k_caps_bad", "k @T@/w/f - - - - cap_nope=ep\nk @T@/w/d/f - - - - =x\nk @T@/w/f - - - - noop\n")));
    cdn(tr(cr("k_caps_inconsistent", "k @T@/w/f - - - - cap_chown=e\n")));
    cdn(tr(cr("k_caps_dir", "k @T@/w/d - - - - cap_chown=ep\n")));
    cdn(tr(cr("K_caps", "K @T@/w/d - - - - cap_chown=ep\n")));
    cdn(tr(cr("k_caps_append", "k @T@/w/f - - - - cap_chown=ep\nk+ @T@/w/d/f - - - - cap_kill+p\n")));
}

#[test]
fn users() {
    cdn(cr("as_alice", "d @T@/w/a/d 0700\nf @T@/w/a/f 0600 - - - x\nd @T@/w/root\nz @T@/w/a 0700 bob\n")
        .run_as(ALICE)
        .dir_owned("w/a", 0o755, 1001, 1001));
    cdn(cr("unsafe_parent", "f @T@/w/a/l/f 0600\nd @T@/w/a/l/d\n")
        .dir_owned("w/a", 0o755, 1001, 1001)
        .dir("w/target", 0o755)
        .symlink("w/a/l", "../target"));
    cdn(cr("safe_parent", "f @T@/w/a/l/f 0600\n")
        .dir_owned("w/a", 0o755, 1001, 1001)
        .dir_owned("w/target", 0o755, 1001, 1001)
        .symlink("w/a/l", "../target"));
    cdn(cr("bob_dir", "d @T@/w/b/sub 0700 alice\n").run_as(BOB).dir_owned("w/b", 0o755, 1002, 1002));
}

// ---------------------------------------------------------------------------
// removing, cleaning, purging

/// A tree to remove or clean, with times set: old files and a new one.
fn junk(c: Case) -> Case {
    c.dir("w/d/sub/deep", 0o755)
        .file("w/d/old", b"", 0o644)
        .file("w/d/new", b"", 0o644)
        .file("w/d/sub/old", b"", 0o644)
        .file("w/d/sub/deep/old", b"", 0o644)
        .file("w/d/.hidden", b"", 0o644)
        .file("w/d/sticky", b"", 0o1644)
        .symlink("w/d/link", "old")
        .fifo("w/d/fifo", 0o644)
        .touch("w/d/old", OLD)
        .touch("w/d/new", NEW)
        .touch("w/d/sub/old", OLD)
        .touch("w/d/sub/deep/old", OLD)
        .touch("w/d/.hidden", OLD)
        .touch("w/d/sticky", OLD)
        .touch("w/d/link", OLD)
        .touch("w/d/fifo", OLD)
        .touch("w/d/sub/deep", OLD)
        .touch("w/d/sub", OLD)
        .touch("w/d", OLD)
        .time(FUTURE)
        .meta()
}

#[test]
fn removing() {
    cdn(junk(t("r_file", &["--remove"], "r @T@/w/d/old\nr @T@/w/d/sub\nr @T@/w/none\n")));
    cdn(junk(t("r_glob", &["--remove"], "r @T@/w/d/*ld\n")));
    cdn(junk(t("R_dir", &["--remove"], "R @T@/w/d/sub\nR @T@/w/d/old\nR @T@/w/none\n")));
    cdn(junk(t("R_glob", &["--remove"], "R @T@/w/d*\n")));
    cdn(junk(t("D_remove", &["--remove"], "D @T@/w/d\n")));
    cdn(junk(t("D_remove_create", &["--remove", "--create"], "D @T@/w/d 0700\n")));
    // Children are processed in C's hash order, which changes from run to
    // run: compare the log sorted.
    cdn(junk(t("D_remove_excluded", &["--remove"], "D @T@/w/d\nx @T@/w/d/sub\nX @T@/w/d/old\nd @T@/w/d/new\n"))
        .sorted());
    cdn(junk(t("remove_no_op_types", &["--remove"], "d @T@/w/d\nf @T@/w/d/old\nx @T@/w/d\n")));
    cdn(junk(t("r_create_only", &["--create"], "r @T@/w/d/old\nR @T@/w/d/sub\n")));
    cdn(junk(t("R_root_child", &["--remove"], "R @T@/w/d/sub/deep/old/x\n")));
}

#[test]
fn cleaning() {
    cdn(junk(t("clean_d", &["--clean"], "d @T@/w/d - - - 1d\n")));
    cdn(junk(t("clean_d_noage", &["--clean"], "d @T@/w/d\n")));
    cdn(junk(t("clean_d_keep_first", &["--clean"], "d @T@/w/d - - - ~1d\n")));
    cdn(junk(t("clean_d_zero", &["--clean"], "d @T@/w/d - - - 0\n")));
    cdn(junk(t("clean_d_long", &["--clean"], "d @T@/w/d - - - 10d\n")));
    cdn(junk(t("clean_ageby_m", &["--clean"], "d @T@/w/d - - - m:1d\n")));
    cdn(junk(t("clean_ageby_c", &["--clean"], "d @T@/w/d - - - c:1d\n")));
    cdn(junk(t("clean_ageby_dirs", &["--clean"], "d @T@/w/d - - - aM:1d\n")));
    cdn(junk(t("clean_excluded", &["--clean"], "d @T@/w/d - - - 1d\nx @T@/w/d/sub\nx @T@/w/d/old\n")).sorted());
    cdn(junk(t("clean_excluded_glob", &["--clean"], "d @T@/w/d - - - 1d\nx @T@/w/d/*ld\n")));
    cdn(junk(t("clean_X", &["--clean"], "d @T@/w/d - - - 1d\nX @T@/w/d/sub\n")));
    cdn(junk(t("clean_x_age", &["--clean"], "x @T@/w/d - - - 1d\nX @T@/w/d/s* - - - 1d\n")));
    cdn(junk(t("clean_e", &["--clean"], "e @T@/w/d - - - 1d\n")));
    cdn(junk(t("clean_e_glob", &["--clean"], "e @T@/w/d* - - - 1d\n")));
    cdn(junk(t(
        "clean_r_age",
        &["--clean"],
        "r @T@/w/d/old - - - 1d\nr @T@/w/d/new - - - 1d\nr @T@/w/d/sub/deep - - - 1d\n",
    )));
    cdn(junk(t("clean_R_age", &["--clean"], "R @T@/w/d/sub - - - 1d\nR @T@/w/d/old - - - 1d\n")));
    cdn(junk(t("clean_R_age_keep", &["--clean"], "R @T@/w/d - - - ~1d\n")));
    cdn(junk(t("clean_v", &["--clean"], "v @T@/w/d - - - 1d\nq @T@/w/d - - - 1d\n")));
    cdn(junk(t("clean_C", &["--clean"], "C @T@/w/d - - - 1d @T@/src\n")).dir("src", 0o755));
    cdn(junk(t("clean_missing", &["--clean"], "d @T@/w/none - - - 1d\nd @T@/w/d/old - - - 1d\n")));
    cdn(junk(t("clean_then_create", &["--clean", "--create"], "d @T@/w/d 0700 - - 1d\nf @T@/w/d/old2\n")));
    cdn(junk(t("clean_nested_items", &["--clean"], "d @T@/w/d - - - 1d\nd @T@/w/d/sub - - - 2h\n")));
    cdn(junk(t("clean_r_remove_both", &["--clean", "--remove"], "R @T@/w/d/sub - - - 1d\nr @T@/w/d/old\n")));
    cdn(junk(t("clean_future_age", &["--clean"], "d @T@/w/d - - - 100y\n")));
    // /proc/net/unix lists live sockets by path: "live" and "live2" are
    // kept, "dead" is removed.
    let unix = "Num       RefCount Protocol Flags    Type St Inode Path\n\
                0000000000000000: 00000002 00000000 00010000 0001 01 12345 @T@/w/d/live\n\
                0000000000000000: 00000002 00000000 00010000 0001 01 12346 @T@//w/d/./live2\n\
                0000000000000000: 00000002 00000000 00010000 0001 01 12347 short\n\
                0000000000000000: 00000003 00000000 00000000 0001 03 12348\n";
    let sockets = |c: Case| {
        c.socket("w/d/live")
            .socket("w/d/live2")
            .socket("w/d/dead")
            .touch("w/d/live", OLD)
            .touch("w/d/live2", OLD)
            .touch("w/d/dead", OLD)
            .touch("w/d", OLD)
    };
    let clean = |n: &str| junk(t(n, &["--clean"], "d @T@/w/d - - - 1d\n")).bind("/proc/net", "fakeproc/net");
    cdn(sockets(clean("clean_socket")).conf("fakeproc/net/unix", unix));
    cdn(sockets(clean("clean_socket_noproc")));
    cdn(sockets(clean("clean_socket_empty")).conf("fakeproc/net/unix", ""));
    // Exactly at the cutoff is too new; a second older is not.
    cdn(t("clean_boundary", &["--clean"], "d @T@/w/b - - - 1d\n")
        .file("w/b/at", b"", 0o644)
        .file("w/b/before", b"", 0o644)
        .file("w/b/after", b"", 0o644)
        .touch("w/b/at", FUTURE - 86_400)
        .touch("w/b/before", FUTURE - 86_401)
        .touch("w/b/after", FUTURE - 86_399)
        .touch("w/b", OLD)
        .time(FUTURE)
        .meta());
    cdn(junk(t("clean_lost_found", &["--clean"], "d @T@/w/d - - - 1d\n"))
        .dir("w/d/lost+found", 0o700)
        .touch("w/d/lost+found", OLD));
}

#[test]
fn purging() {
    cdn(junk(t("purge", &["--purge"], "d$ @T@/w/d\nf$ @T@/w/f\nL$ @T@/w/l\nd @T@/w/keep\n"))
        .file("w/f", b"", 0o644)
        .symlink("w/l", "x")
        .dir("w/keep", 0o755));
    cdn(junk(t("purge_glob", &["--purge"], "w$ @T@/w/d/*ld - - - - x\n")));
    cdn(junk(t("purge_create", &["--purge", "--create"], "d$ @T@/w/d 0700\n")));
    cdn(junk(t("purge_nothing", &["--purge"], "d @T@/w/d\n")));
}

// ---------------------------------------------------------------------------
// --root and --user

#[test]
fn root() {
    let r = |c: Case| {
        c.dir("img/etc", 0o755)
            .conf(
                "img/etc/passwd",
                "root:x:0:0::/root:/bin/sh\ncarol:x:2001:2001::/home/carol:/bin/sh\ncarol:x:2002:2002::/x:/bin/sh\n",
            )
            .conf("img/etc/group", "root:x:0:\ncarols:x:2005:\n")
            .conf("img/usr/lib/passwd", "dave:x:2003:2003::/:/bin/sh\n")
            .conf("img/etc/tmpfiles.d/a.conf", "d /var/lib/a 0700 carol carols\nf /etc/hostname - - - - img\n")
            .conf("img/usr/lib/tmpfiles.d/b.conf", "L /etc/link - - - - target\nC /copy - - - - /src\n")
            .file("img/src", b"from the image\n", 0o640)
            .conf("img/etc/machine-id", "0123456789abcdef0123456789abcdef\n")
    };
    cdn(r(s("root_create", &["--create", "--root=@T@/img"])));
    cdn(r(s(
        "root_users",
        &[
            "--create",
            "--root=@T@/img",
            "--inline",
            "d /x - dave carols",
            "d /y - nobody",
            "d /z - root root",
            "d /n - 2001 2005",
        ],
    )));
    cdn(r(s("root_unknown_user", &["--create", "--root=@T@/img", "--inline", "d /x - nobody"])));
    cdn(r(s("root_specifiers", &["--create", "--root=@T@/img", "--inline", "f /s - - - - m=%m T=%T V=%V"])));
    cdn(r(s("root_no_machine_id", &["--create", "--root=@T@/img", "--inline", "d /%m"])).no_node("img/etc/machine-id"));
    cdn(r(s("root_cat", &["--cat-config", "--root=@T@/img", "--no-pager"])));
    cdn(
        r(s("root_symlink_escape", &["--create", "--root=@T@/img", "--inline", "f /esc/f"]).symlink("img/esc", "/etc")),
    );
    cdn(r(s("root_relative", &["--create", "--root=img", "--inline", "d /rel"])));
}

#[test]
fn user_mode() {
    let u = |c: Case| {
        c.run_as(ALICE)
            .dir_owned("home", 0o755, 1001, 1001)
            .conf(
                "home/.config/user-tmpfiles.d/a.conf",
                "d %h/made 0700\nf %t/run 0600\nd %C/cache\nd %S/state\nd %L/log\n",
            )
            .conf("xdgdata/user-tmpfiles.d/b.conf", "f %h/fromdata\n")
            .dir_owned("home/.config", 0o755, 1001, 1001)
            .dir_owned("rt", 0o700, 1001, 1001)
            .env("HOME", "@T@/home")
            .env("XDG_RUNTIME_DIR", "@T@/rt")
            .env("XDG_DATA_DIRS", "@T@/xdgdata")
    };
    cdn(u(s("user_create", &["--create", "--user"])));
    cdn(u(s("user_cat", &["--cat-config", "--user", "--no-pager"])));
    cdn(u(s("user_no_runtime", &["--create", "--user"])).no_env("XDG_RUNTIME_DIR"));
    cdn(u(s("user_config_home", &["--create", "--user"]))
        .env("XDG_CONFIG_HOME", "@T@/cfg")
        .conf("cfg/user-tmpfiles.d/c.conf", "d %h/cfghome\n"));
}

// ---------------------------------------------------------------------------
// logging

#[test]
fn logging() {
    let base = |n: &str| cr(n, "d @T@/w/a 0700\ny @T@/w/b\nf @T@/w/nodir/f\n").file("w/nodir", b"", 0o644);
    c(base("log_syslog").env("SYSTEMD_LOG_TARGET", "syslog").env("SYSTEMD_LOG_LEVEL", "debug"));
    c(base("log_journal").env("SYSTEMD_LOG_TARGET", "journal").journal());
    c(base("log_kmsg").env("SYSTEMD_LOG_TARGET", "kmsg").env("SYSTEMD_LOG_LEVEL", "debug"));
    c(base("log_color").env("SYSTEMD_LOG_COLOR", "1").env("SYSTEMD_LOG_LEVEL", "debug"));
    c(base("log_location").env("SYSTEMD_LOG_LOCATION", "0").env("SYSTEMD_LOG_TIME", "1"));
    c(base("log_pty").pty(24, 80).env("SYSTEMD_LOG_LEVEL", "info"));
}
