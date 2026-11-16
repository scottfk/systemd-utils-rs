// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-sysctl`: apply `sysctl.d` settings to /proc/sys.  A port of
//! systemd's `src/sysctl/sysctl.c` (v262).

use shared::conf_files::{CONF_FILES_WARN, conf_file_read, conf_files_list_strv, conf_paths};
use shared::errno::{is_neg_fs_write_refused, is_privilege, ret_gather, strerror, synthetic};
use shared::glob::glob_extend;
use shared::options::{Command, Opt, OptionParser, command_print_help, common, introspect_cli};
use shared::pager::{PAGER_DISABLE, pager_open};
use shared::path::{filename_is_valid, path_glob_can_match, path_join, path_startswith, path_startswith_strv};
use shared::pretty_print::{CAT_CONFIG_OFF, CAT_CONFIG_ON, CAT_TLDR, cat_files};
use shared::string::{
    STRING_ALLOW_BACKSLASHES, STRING_ALLOW_EMPTY, STRING_ALLOW_GLOBS, STRING_ALLOW_QUOTES, skip_leading_chars,
    string_is_glob, string_is_safe, strstrip,
};
use shared::sysctl_util::{sysctl_normalize, sysctl_write, sysctl_write_verify};
use shared::{bcat, log_debug, log_error_errno, log_info, log_syntax, log_warning_errno, sys};

const OPT_HELP: i32 = 0x100;
const OPT_VERSION: i32 = 0x101;
const OPT_CAT_CONFIG: i32 = 0x102;
const OPT_TLDR: i32 = 0x103;
const OPT_PREFIX: i32 = 0x104;
const OPT_NO_PAGER: i32 = 0x105;
const OPT_STRICT: i32 = 0x106;
const OPT_VERIFY: i32 = 0x107;
const OPT_INLINE: i32 = 0x108;
const OPT_SAVE: i32 = 0x109;
const OPT_REVERT: i32 = 0x10a;
const OPT_INTROSPECT_CLI: i32 = 0x10b;

/// The `OPTION()` table of `parse_argv()`, in source order.
const OPTIONS: &[Opt] = &[
    Opt::group("Commands"),
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    common::cat_config(OPT_CAT_CONFIG),
    common::tldr(OPT_TLDR),
    Opt::group("Options"),
    Opt::long(OPT_PREFIX, "prefix", Some("PATH"), Some("Only apply rules with the specified prefix")),
    common::no_pager(OPT_NO_PAGER),
    Opt::long(OPT_STRICT, "strict", None, Some("Fail on any kind of failures")),
    Opt::long(OPT_VERIFY, "verify", None, Some("Verify sysctl values after write")),
    Opt::long(OPT_INLINE, "inline", None, Some("Treat arguments as configuration lines")),
    Opt::long(OPT_SAVE, "save", Some("FILENAME"), Some("Write loaded settings to the specified file")),
    Opt::long(OPT_REVERT, "revert", Some("FILENAME"), Some("Remove the specified file from /run/sysctl.d/")),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["systemd-sysctl"],
    abstract_: "Apply kernel sysctl settings.",
    argspec: &["[CONFIGURATION FILE…]"],
    footer: None,
    man_pages: &["systemd-sysctl.service(8)"],
    verbs: &[],
};

#[derive(Debug, Default)]
struct Args {
    prefixes: Vec<Vec<u8>>,
    cat_flags: u32,
    strict: bool,
    verify: bool,
    inline: bool,
    pager_flags: u32,
    save_file: Option<Vec<u8>>,
    revert_file: Option<Vec<u8>>,
}

/// `SysctlOption`.
#[derive(Debug, Clone)]
struct SysctlOption {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    ignore_failure: bool,
}

/// The `OrderedHashmap` of options: insertion order, keyed by name.
#[derive(Debug, Default)]
struct Options(Vec<SysctlOption>);

impl Options {
    fn get(&self, key: &[u8]) -> Option<usize> {
        self.0.iter().position(|o| o.key == key)
    }
    fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }
}

/// `test_prefix()`.
fn test_prefix(a: &Args, p: &[u8]) -> bool {
    a.prefixes.is_empty() || path_startswith_strv(p, &a.prefixes).is_some()
}

/// `sysctl_write_or_warn()`.
fn sysctl_write_or_warn(a: &Args, key: &[u8], value: &[u8], ignore_failure: bool, ignore_enoent: bool) -> i32 {
    let r = if a.verify { sysctl_write_verify(key, value) } else { sysctl_write(key, value) };
    if let Err(r) = r {
        if ignore_failure || (!a.strict && is_neg_fs_write_refused(r)) {
            shared::log_debug_errno!(r, "Couldn't write '", value, "' to '", key, "', ignoring: ", strerror(r));
        } else if ignore_enoent && r == -libc::ENOENT {
            log_warning_errno!(r, "Couldn't write '", value, "' to '", key, "', ignoring: ", strerror(r));
        } else {
            return log_error_errno!(r, "Couldn't write '", value, "' to '", key, "': ", strerror(r));
        }
    }
    0
}

/// `apply_glob_option_with_prefix()`.
fn apply_glob_option_with_prefix(a: &Args, opts: &Options, option: &SysctlOption, prefix: Option<&[u8]>) -> i32 {
    let value = option.value.as_deref().unwrap_or_default();
    let pattern = if let Some(prefix) = prefix {
        let key = match path_glob_can_match(&option.key, prefix) {
            Err(r) => {
                return log_error_errno!(
                    r,
                    "Failed to check if the glob '",
                    option.key,
                    "' matches prefix '",
                    prefix,
                    "': ",
                    strerror(r)
                );
            }
            Ok(None) => {
                log_debug!("The glob '", option.key, "' does not match prefix '", prefix, "'.");
                return 0;
            }
            Ok(Some(k)) => k,
        };
        log_debug!("The glob '", option.key, "' is prefixed with '", prefix, "': '", key, "'");
        if !string_is_glob(&key) {
            if opts.contains(&key) {
                log_debug!("Not setting ", key, " (explicit setting exists).");
                return 0;
            }
            return sysctl_write_or_warn(a, &key, value, option.ignore_failure, true);
        }
        path_join(&[b"/proc/sys", &key])
    } else {
        path_join(&[b"/proc/sys", &option.key])
    };

    let mut paths = Vec::new();
    if let Err(r) = glob_extend(&mut paths, &pattern, libc::GLOB_NOCHECK) {
        if r == -libc::ENOENT {
            log_debug!("No match for glob: ", option.key);
            return 0;
        }
        if option.ignore_failure || is_privilege(r) {
            shared::log_debug_errno!(r, "Failed to resolve glob '", option.key, "', ignoring: ", strerror(r));
            return 0;
        }
        return log_error_errno!(r, "Couldn't resolve glob '", option.key, "': ", strerror(r));
    }
    let mut r = 0;
    for s in &paths {
        let key = path_startswith(s, b"/proc/sys").expect("glob results are under /proc/sys");
        if opts.contains(key) {
            log_debug!("Not setting ", key, " (explicit setting exists).");
            continue;
        }
        ret_gather(&mut r, sysctl_write_or_warn(a, key, value, option.ignore_failure, !a.strict));
    }
    r
}

/// `apply_glob_option()`.
fn apply_glob_option(a: &Args, opts: &Options, option: &SysctlOption) -> i32 {
    if a.prefixes.is_empty() {
        return apply_glob_option_with_prefix(a, opts, option, None);
    }
    let mut r = 0;
    for p in &a.prefixes {
        ret_gather(&mut r, apply_glob_option_with_prefix(a, opts, option, Some(p)));
    }
    r
}

/// `apply_all()`.
fn apply_all(a: &Args, opts: &Options) -> i32 {
    let mut r = 0;
    for option in &opts.0 {
        let Some(value) = &option.value else { continue };
        let k = if string_is_glob(&option.key) {
            apply_glob_option(a, opts, option)
        } else {
            sysctl_write_or_warn(a, &option.key, value, option.ignore_failure, !a.strict)
        };
        ret_gather(&mut r, k);
    }
    r
}

/// `filter_sysctl_options()`.
fn filter_sysctl_options(a: &Args, opts: &mut Options) {
    opts.0.retain(|o| string_is_glob(&o.key) || test_prefix(a, &o.key));
}

/// `parse_line()`.
fn parse_line(a: &Args, opts: &mut Options, fname: &[u8], line: u32, buffer: &[u8]) -> i32 {
    let mut buffer = buffer;
    let mut ignore_failure = false;
    let (k, v) = match buffer.iter().position(|&b| b == b'=') {
        Some(eq) => {
            if buffer[0] == b'-' {
                ignore_failure = true;
                buffer = &buffer[1..];
            }
            let eq = eq - ignore_failure as usize;
            (buffer[..eq].to_vec(), Some(buffer[eq + 1..].to_vec()))
        }
        None => {
            if buffer[0] == b'-' {
                buffer = &buffer[1..];
            } else {
                return log_syntax!(
                    libc::LOG_WARNING,
                    Some(fname),
                    line,
                    synthetic(libc::EINVAL),
                    "Line is not an assignment, ignoring: ",
                    buffer
                );
            }
            (buffer.to_vec(), None)
        }
    };
    let key = sysctl_normalize(strstrip(&k));
    let value = v.as_deref().map(|v| strstrip(v).to_vec());

    if a.save_file.is_some() {
        let kf = STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS;
        if !string_is_safe(&key, kf) || value.as_deref().is_some_and(|v| !string_is_safe(v, kf | STRING_ALLOW_EMPTY)) {
            return log_syntax!(
                libc::LOG_WARNING,
                Some(fname),
                line,
                synthetic(libc::EINVAL),
                "Ignoring unsafe key and/or value for '",
                key,
                "'."
            );
        }
    } else if !string_is_glob(&key) && !test_prefix(a, &key) {
        return 0;
    }

    if let Some(i) = opts.get(&key) {
        if opts.0[i].value == value {
            opts.0[i].ignore_failure = opts.0[i].ignore_failure || ignore_failure;
            return 0;
        }
        log_syntax!(libc::LOG_DEBUG, Some(fname), line, 0, "Overwriting earlier assignment of '", key, "'.");
        opts.0.remove(i);
    }
    opts.0.push(SysctlOption { key, value, ignore_failure });
    0
}

/// `parse_file()`.
fn parse_file(a: &Args, opts: &mut Options, path: &[u8], ignore_enoent: bool) -> i32 {
    conf_file_read(
        None,
        &conf_paths("sysctl.d"),
        path,
        &mut |f, l, b, _| parse_line(a, opts, f, l, b),
        ignore_enoent,
        None,
    )
}

/// `read_credential_lines()`.
fn read_credential_lines(a: &Args, opts: &mut Options) -> i32 {
    let d = match shared::creds::get_credentials_dir() {
        Err(r) if r == -libc::ENXIO => return 0,
        Err(r) => return log_error_errno!(r, "Failed to get credentials directory: ", strerror(r)),
        Ok(d) => d,
    };
    let j = path_join(&[&d, b"sysctl.extra"]);
    parse_file(a, opts, &j, true)
}

/// `save_sysctl_options()`.
fn save_sysctl_options(opts: &Options, filename: &[u8]) -> i32 {
    if opts.0.is_empty() {
        log_info!("No sysctl settings loaded, not creating '", filename, "'.");
        return 0;
    }
    if let Err(r) = shared::fs::mkdir_p(b"/run/sysctl.d/", 0o755) {
        return log_error_errno!(r, "Failed to create directory '/run/sysctl.d/': ", strerror(r));
    }
    let path = path_join(&[b"/run/sysctl.d/", filename]);
    let (fd, temp_path) = match shared::fs::fopen_temporary(&path) {
        Ok(x) => x,
        Err(r) => return log_error_errno!(r, "Failed to open a temporary file for '", path, "': ", strerror(r)),
    };
    // unlink_and_freep: remove the temporary file on every failure path.
    let fail = |r: i32| -> i32 {
        let _ = sys::unlink(&temp_path);
        r
    };
    if let Err(e) = sys::fchmod(fd.raw(), 0o644) {
        return fail(log_error_errno!(e, "Failed to chmod '", temp_path, "': ", strerror(e)));
    }
    let mut data = b"# This is generated by systemd-sysctl.\n".to_vec();
    for o in &opts.0 {
        data.extend(bcat!(
            if o.ignore_failure || o.value.is_none() { "-" } else { "" },
            o.key,
            if o.value.is_some() { " = " } else { "" },
            o.value.as_deref().unwrap_or_default(),
            "\n"
        ));
    }
    if let Err(r) = sys::write_all(fd.raw(), &data) {
        return fail(log_error_errno!(r, "Failed to flush '", temp_path, "': ", strerror(r)));
    }
    drop(fd);
    if let Err(r) = shared::fs::conservative_rename(&temp_path, &path) {
        return fail(log_error_errno!(r, "Failed to rename '", temp_path, "' to '", path, "': ", strerror(r)));
    }
    0
}

/// `parse_conf_filename()`.
fn parse_conf_filename(src: &[u8], option: &str) -> Result<Vec<u8>, i32> {
    if src.is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Cannot use an empty filename for ", option, "."));
    }
    if src.starts_with(b".") {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Dot-prefixed filenames are not allowed for ",
            option,
            "."
        ));
    }
    let name = if src.ends_with(b".conf") { src.to_vec() } else { bcat!(src, ".conf") };
    if !filename_is_valid(&name) {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Invalid file name '",
            name,
            "' specified for ",
            option,
            "."
        ));
    }
    Ok(name)
}

/// `parse_argv()`: `Ok(Some(args))` to go on, `Ok(None)` to exit successfully.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(Args, Vec<Vec<u8>>)>, i32> {
    let mut a = Args { cat_flags: CAT_CONFIG_OFF, ..Default::default() };
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            OPT_HELP => {
                let r = command_print_help(&COMMAND, OPTIONS, Some(a.pager_flags));
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            OPT_VERSION => {
                shared::build::version();
                return Ok(None);
            }
            OPT_CAT_CONFIG => a.cat_flags = CAT_CONFIG_ON,
            OPT_TLDR => a.cat_flags = CAT_TLDR,
            OPT_PREFIX => {
                let normalized = sysctl_normalize(&arg);
                let s = path_startswith(&normalized, b"/proc/sys").map(|s| s.to_vec());
                a.prefixes.push(s.unwrap_or(normalized));
            }
            OPT_NO_PAGER => a.pager_flags |= PAGER_DISABLE,
            OPT_STRICT => a.strict = true,
            OPT_VERIFY => a.verify = true,
            OPT_INLINE => a.inline = true,
            OPT_SAVE => a.save_file = Some(parse_conf_filename(&arg, "--save=")?),
            OPT_REVERT => a.revert_file = Some(parse_conf_filename(&arg, "--revert=")?),
            OPT_INTROSPECT_CLI => {
                let r = introspect_cli(&COMMAND, OPTIONS, shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            _ => unreachable!("option id {c}"),
        }
    }
    let args = opts.args().to_vec();
    if a.cat_flags != CAT_CONFIG_OFF && !args.is_empty() {
        return Err(log_error_errno!(
            synthetic(libc::EINVAL),
            "Positional arguments are not allowed with --cat-config/--tldr."
        ));
    }
    if a.inline && args.is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "--inline requires positional arguments."));
    }
    if a.save_file.is_some() && args.is_empty() {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "--save= requires positional arguments."));
    }
    Ok(Some((a, args)))
}

/// `run()`.
fn run(argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_setup();
    let (a, args) = match parse_argv(argv) {
        Ok(Some(x)) => x,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    sys::umask(0o022);

    if let Some(rf) = &a.revert_file {
        let path = path_join(&[b"/run/sysctl.d/", rf]);
        if let Err(e) = sys::unlink(&path)
            && e != -libc::ENOENT
        {
            return log_error_errno!(e, "Failed to remove '", path, "': ", strerror(e));
        }
    }

    let mut opts = Options::default();
    let mut r = 0;
    if !args.is_empty() {
        let mut pos = 0u32;
        for arg in &args {
            if a.inline {
                pos += 1;
                let s = skip_leading_chars(arg, None);
                if s.is_empty() || s[0] == b'#' {
                    continue;
                }
                let k = parse_line(&a, &mut opts, b"(argument)", pos, s);
                ret_gather(&mut r, k);
            } else {
                let k = parse_file(&a, &mut opts, arg, false);
                ret_gather(&mut r, k);
            }
        }
        if let Some(sf) = &a.save_file {
            let k = save_sysctl_options(&opts, sf);
            if k < 0 {
                return k;
            }
            // QUIRK: the result of saving replaces the parse result, so a
            // failed parse_file() no longer makes the run fail.
            r = k;
            filter_sysctl_options(&a, &mut opts);
        }
    } else {
        let files = match conf_files_list_strv(Some(b".conf"), None, CONF_FILES_WARN, &conf_paths("sysctl.d")) {
            Ok(f) => f,
            Err(e) => return log_error_errno!(e, "Failed to enumerate sysctl.d files: ", strerror(e)),
        };
        if a.cat_flags != CAT_CONFIG_OFF {
            pager_open(a.pager_flags);
            return cat_files(None, &files, a.cat_flags);
        }
        for f in &files {
            let k = parse_file(&a, &mut opts, f, true);
            ret_gather(&mut r, k);
        }
        let k = read_credential_lines(&a, &mut opts);
        ret_gather(&mut r, k);
    }
    let k = apply_all(&a, &opts);
    ret_gather(&mut r, k);
    r
}

fn main() {
    shared::main_func::main_with(run)
}
