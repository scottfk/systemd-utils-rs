// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-tmpfiles`: create, delete, and clean up files and directories.
//! A port of systemd's `src/tmpfiles/tmpfiles.c` (v262).

mod fcaps;
mod item;
mod offline;
mod ops;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use shared::chase::{CHASE_PREFIX_ROOT, chase};
use shared::conf_files::{conf_file_read, conf_files_list_with_replacement, conf_paths};
use shared::errno::{strerror, synthetic};
use shared::locale::{Glyph, glyph};
use shared::options::{Command, Opt, OptionParser, command_print_help, common, introspect_cli};
use shared::pager::{PAGER_DISABLE, pager_open};
use shared::path::{path_equal, path_is_absolute, path_join, path_make_absolute_cwd, path_simplify, path_startswith};
use shared::pretty_print::{CAT_CONFIG_OFF, CAT_CONFIG_ON, CAT_TLDR, cat_files};
use shared::specifier::RuntimeScope;
use shared::string::endswith;
use shared::{log_debug, log_debug_errno, log_error_errno, sys};

use item::*;

const OPT_CREATE: i32 = 0x100;
const OPT_CLEAN: i32 = 0x101;
const OPT_REMOVE: i32 = 0x102;
const OPT_PURGE: i32 = 0x103;
const OPT_CAT_CONFIG: i32 = 0x104;
const OPT_TLDR: i32 = 0x105;
const OPT_HELP: i32 = 0x106;
const OPT_VERSION: i32 = 0x107;
const OPT_USER: i32 = 0x108;
const OPT_BOOT: i32 = 0x109;
const OPT_GRACEFUL: i32 = 0x10a;
const OPT_PREFIX: i32 = 0x10b;
const OPT_EXCLUDE_PREFIX: i32 = 0x10c;
const OPT_E: i32 = 0x10d;
const OPT_ROOT: i32 = 0x10e;
const OPT_IMAGE: i32 = 0x10f;
const OPT_IMAGE_POLICY: i32 = 0x110;
const OPT_REPLACE: i32 = 0x111;
const OPT_DRY_RUN: i32 = 0x112;
const OPT_INLINE: i32 = 0x113;
const OPT_NO_PAGER: i32 = 0x114;
const OPT_INTROSPECT_CLI: i32 = 0x115;

/// The `OPTION()` table of `parse_argv()`, in source order.
const OPTIONS: &[Opt] = &[
    Opt::group("Commands"),
    Opt::long(OPT_CREATE, "create", None, Some("Create and adjust files and directories")),
    Opt::long(OPT_CLEAN, "clean", None, Some("Clean up files and directories")),
    Opt::long(OPT_REMOVE, "remove", None, Some("Remove files and directories marked for removal")),
    Opt::long(
        OPT_PURGE,
        "purge",
        None,
        Some("Delete files and directories marked for creation in specified configuration files (careful!)"),
    ),
    common::cat_config(OPT_CAT_CONFIG),
    common::tldr(OPT_TLDR),
    common::help(OPT_HELP),
    common::version(OPT_VERSION),
    Opt::group("Options"),
    Opt::long(OPT_USER, "user", None, Some("Execute user configuration")),
    Opt::long(OPT_BOOT, "boot", None, Some("Execute actions only safe at boot")),
    Opt::long(OPT_GRACEFUL, "graceful", None, Some("Quietly ignore unknown users or groups")),
    Opt::long(OPT_PREFIX, "prefix", Some("PATH"), Some("Only apply rules with the specified prefix")),
    Opt::long(OPT_EXCLUDE_PREFIX, "exclude-prefix", Some("PATH"), Some("Ignore rules with the specified prefix")),
    Opt::new(OPT_E, b'E', None, None, Some("Ignore rules prefixed with /dev, /proc, /run, /sys")),
    Opt::long(OPT_ROOT, "root", Some("PATH"), Some("Operate on an alternate filesystem root")),
    Opt::long(OPT_IMAGE, "image", Some("PATH"), Some("Operate on disk image as filesystem root")),
    Opt::long(OPT_IMAGE_POLICY, "image-policy", Some("POLICY"), Some("Specify disk image dissection policy")),
    Opt::long(OPT_REPLACE, "replace", Some("PATH"), Some("Treat arguments as replacement for PATH")),
    Opt::new(OPT_DRY_RUN, b'n', Some("dry-run"), None, Some("Just print what would be done")),
    Opt::long(OPT_INLINE, "inline", None, Some("Treat arguments as configuration lines")),
    common::no_pager(OPT_NO_PAGER),
    common::introspect_cli(OPT_INTROSPECT_CLI),
];

const COMMAND: Command = Command {
    names: &["systemd-tmpfiles"],
    abstract_: "Create, delete, and clean up files and directories.",
    argspec: &["[CONFIGURATION FILE…]"],
    footer: None,
    man_pages: &["systemd-tmpfiles(8)"],
    verbs: &[],
};

/// The `arg_*` globals.
#[derive(Debug)]
pub struct Args {
    pub cat_flags: u32,
    pub dry_run: bool,
    pub inline: bool,
    pub runtime_scope: RuntimeScope,
    pub operation: u32,
    pub boot: bool,
    pub graceful: bool,
    pub pager_flags: u32,
    pub include_prefixes: Vec<Vec<u8>>,
    pub exclude_prefixes: Vec<Vec<u8>>,
    pub root: Option<Vec<u8>>,
    pub image: Option<Vec<u8>>,
    pub replace: Option<Vec<u8>>,
}

static ARGS: OnceLock<Args> = OnceLock::new();

/// The parsed command line.
pub fn args() -> &'static Args {
    ARGS.get().expect("parse_argv() ran")
}

/// `Context`: the item arrays live in `arrays`; `items` and `globs` are the
/// two ordered hashmaps of C, as a key → index map plus insertion order.
#[derive(Debug, Default)]
pub struct Context {
    pub arrays: Vec<ItemArray>,
    pub items: HashMap<Vec<u8>, usize>,
    pub items_order: Vec<usize>,
    pub globs: HashMap<Vec<u8>, usize>,
    pub globs_order: Vec<usize>,
    /// The sockets in /proc/net/unix, once loaded.
    pub unix_sockets: RefCell<Option<HashSet<Vec<u8>>>>,
    pub uid_cache: Option<HashMap<Vec<u8>, u32>>,
    pub gid_cache: Option<HashMap<Vec<u8>, u32>>,
}

/// `log_action(would, doing, fmt, ...)`: INFO with --dry-run, else DEBUG;
/// the first piece is the verb.
#[macro_export]
macro_rules! log_action {
    ($would:expr, $doing:expr, $($e:expr),* $(,)?) => {{
        let dry = $crate::args().dry_run;
        shared::log_full!(
            if dry { libc::LOG_INFO } else { libc::LOG_DEBUG },
            if dry { $would } else { $doing },
            $($e),*
        )
    }};
}

/// `running_in_chroot()` (`virt.c`).
pub fn running_in_chroot() -> i32 {
    match shared::env::getenv_bool("SYSTEMD_IN_CHROOT") {
        Ok(b) => return b as i32,
        Err(r) if r != -libc::ENXIO => {
            log_debug_errno!(r, "Failed to parse $SYSTEMD_IN_CHROOT, ignoring: ", strerror(r));
        }
        Err(_) => {}
    }
    if shared::env::getenv_bool("SYSTEMD_IGNORE_CHROOT") == Ok(true) {
        return 0;
    }
    match shared::stat_util::inode_same_at(libc::AT_FDCWD, Some(b"/proc/1/root"), libc::AT_FDCWD, Some(b"/"), 0) {
        Err(r) if r == -libc::ENOENT => match shared::fs::proc_mounted_full() {
            Ok(false) => {
                if sys::getpid() == 1 {
                    return 0;
                }
                log_debug!("/proc/ is not mounted, assuming we're in a chroot.");
                1
            }
            Ok(true) => -libc::ENOSYS,
            Err(_) => log_debug_errno!(r, "Failed to check if /proc/1/root and / are the same inode: ", strerror(r)),
        },
        Err(r) => log_debug_errno!(r, "Failed to check if /proc/1/root and / are the same inode: ", strerror(r)),
        Ok(same) => !same as i32,
    }
}

/// `user_config_paths()`.
fn user_config_paths() -> Result<Vec<Vec<u8>>, i32> {
    let (mut config_dirs, data_dirs) = shared::sd_path::user_search_dirs(b"/user-tmpfiles.d");
    match shared::sd_path::sd_path_lookup(shared::sd_path::SdPath::UserRuntime, Some(b"/user-tmpfiles.d")) {
        Ok(p) => config_dirs.push(p),
        Err(r) if errno_is_neg_noinfo(r) => {}
        Err(r) => return Err(r),
    }
    for d in data_dirs {
        if !config_dirs.contains(&d) {
            config_dirs.push(d);
        }
    }
    config_dirs.iter().map(|d| path_make_absolute_cwd(d)).collect()
}

/// `exclude_default_prefixes()`.
fn exclude_default_prefixes(a: &mut Args) {
    for p in [&b"/dev"[..], b"/proc", b"/run", b"/sys"] {
        a.exclude_prefixes.push(p.to_vec());
    }
    // strv_uniq()
    let mut seen: Vec<Vec<u8>> = Vec::new();
    a.exclude_prefixes.retain(|p| {
        if seen.contains(p) {
            false
        } else {
            seen.push(p.clone());
            true
        }
    });
}

/// `parse_path_argument(path, suppress_root=false, &arg)`.
fn parse_path_argument(path: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    if path.is_empty() {
        return Ok(None);
    }
    match path_make_absolute_cwd(path) {
        Ok(p) => Ok(Some(path_simplify(&p))),
        Err(r) => Err(log_error_errno!(r, "Failed to parse path \"", path, "\" and make it absolute: ", strerror(r))),
    }
}

/// `parse_argv()`: `Ok(Some(args))` to go on, `Ok(None)` to exit successfully.
fn parse_argv(argv: Vec<Vec<u8>>) -> Result<Option<(Args, Vec<Vec<u8>>)>, i32> {
    let mut a = Args {
        cat_flags: CAT_CONFIG_OFF,
        dry_run: false,
        inline: false,
        runtime_scope: RuntimeScope::System,
        operation: 0,
        boot: false,
        graceful: false,
        pager_flags: 0,
        include_prefixes: Vec::new(),
        exclude_prefixes: Vec::new(),
        root: None,
        image: None,
        replace: None,
    };
    let mut opts = OptionParser::new(argv, OPTIONS);
    while let Some(c) = opts.next()? {
        let arg = opts.arg.clone().unwrap_or_default();
        match c {
            OPT_CREATE => a.operation |= OPERATION_CREATE,
            OPT_CLEAN => a.operation |= OPERATION_CLEAN,
            OPT_REMOVE => a.operation |= OPERATION_REMOVE,
            OPT_PURGE => a.operation |= OPERATION_PURGE,
            OPT_CAT_CONFIG => a.cat_flags = CAT_CONFIG_ON,
            OPT_TLDR => a.cat_flags = CAT_TLDR,
            OPT_HELP => {
                let r = command_print_help(&COMMAND, OPTIONS, Some(a.pager_flags));
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            OPT_VERSION => {
                shared::build::version();
                return Ok(None);
            }
            OPT_USER => a.runtime_scope = RuntimeScope::User,
            OPT_BOOT => a.boot = true,
            OPT_GRACEFUL => a.graceful = true,
            OPT_PREFIX => a.include_prefixes.push(arg),
            OPT_EXCLUDE_PREFIX => a.exclude_prefixes.push(arg),
            OPT_E => exclude_default_prefixes(&mut a),
            OPT_ROOT => a.root = parse_path_argument(&arg)?,
            OPT_IMAGE => {
                a.image = parse_path_argument(&arg)?;
                exclude_default_prefixes(&mut a);
            }
            // Images are not supported (see README), so the policy is
            // accepted without being parsed.
            OPT_IMAGE_POLICY => {}
            OPT_REPLACE => {
                if !path_is_absolute(&arg) {
                    return Err(log_error_errno!(
                        synthetic(libc::EINVAL),
                        "The argument to --replace= must be an absolute path."
                    ));
                }
                if !endswith(&arg, b".conf") {
                    return Err(log_error_errno!(
                        synthetic(libc::EINVAL),
                        "The argument to --replace= must have the extension '.conf'."
                    ));
                }
                a.replace = Some(arg);
            }
            OPT_DRY_RUN => a.dry_run = true,
            OPT_INLINE => a.inline = true,
            OPT_NO_PAGER => a.pager_flags |= PAGER_DISABLE,
            OPT_INTROSPECT_CLI => {
                let r = introspect_cli(&COMMAND, OPTIONS, shared::json::SD_JSON_FORMAT_OFF);
                return if r < 0 { Err(r) } else { Ok(None) };
            }
            _ => unreachable!("option id {c}"),
        }
    }
    let args = opts.args().to_vec();
    let bad = |msg: &str| Err(log_error_errno!(synthetic(libc::EINVAL), msg));
    if a.operation == 0 && a.cat_flags == CAT_CONFIG_OFF {
        return bad("You need to specify at least one of --clean, --create, --remove, or --purge.");
    }
    if a.operation & OPERATION_PURGE != 0 && args.is_empty() {
        return bad("Refusing --purge without specification of a configuration file.");
    }
    if a.replace.is_some() && a.cat_flags != CAT_CONFIG_OFF {
        return bad("Option --replace= is not supported with --cat-config/--tldr.");
    }
    if a.inline && a.cat_flags != CAT_CONFIG_OFF {
        return bad("Option --inline is not supported with --cat-config/--tldr.");
    }
    if a.replace.is_some() && args.is_empty() {
        return bad("When --replace= is given, some configuration items must be specified.");
    }
    if a.root.is_some() && a.runtime_scope == RuntimeScope::User {
        return bad("Combination of --user and --root= is not supported.");
    }
    if a.image.is_some() && a.root.is_some() {
        return bad("Please specify either --root= or --image=, the combination of both is not supported.");
    }
    Ok(Some((a, args)))
}

/// `read_config_file(c, config_dirs, fn, ignore_enoent, &invalid_config)`.
fn read_config_file(
    c: &mut Context,
    config_dirs: &[Vec<u8>],
    path: &[u8],
    ignore_enoent: bool,
    invalid_config: &mut bool,
) -> i32 {
    let r = conf_file_read(
        args().root.as_deref(),
        config_dirs,
        path,
        &mut |f, l, b, inv| parse_line(c, f, l, b, inv),
        ignore_enoent,
        Some(invalid_config),
    );
    if r <= 0 {
        return r;
    }

    // Determine the age parameter for each entry of type X.
    for gi in c.globs_order.clone() {
        for ii in 0..c.arrays[gi].items.len() {
            if c.arrays[gi].items[ii].ty != IGNORE_DIRECTORY_PATH {
                continue;
            }
            let ipath = c.arrays[gi].items[ii].path.clone();
            let mut candidate: Option<(usize, usize)> = None;
            'outer: for &ja in &c.items_order {
                for (jj, j) in c.arrays[ja].items.iter().enumerate() {
                    if !matches!(
                        j.ty,
                        CREATE_DIRECTORY
                            | TRUNCATE_DIRECTORY
                            | CREATE_SUBVOLUME
                            | CREATE_SUBVOLUME_INHERIT_QUOTA
                            | CREATE_SUBVOLUME_NEW_QUOTA
                    ) {
                        continue;
                    }
                    if path_equal(&j.path, &ipath) {
                        candidate = Some((ja, jj));
                        // C breaks out of the inner loop only, and keeps
                        // looking in the following arrays.
                        continue 'outer;
                    }
                    let better = match candidate {
                        Some((ca, ci)) => {
                            path_startswith(&j.path, &c.arrays[ca].items[ci].path).is_some()
                                && sys::fnmatch(&ipath, &j.path, libc::FNM_PATHNAME | libc::FNM_PERIOD) == 0
                        }
                        None => path_startswith(&ipath, &j.path).is_some(),
                    };
                    if better {
                        candidate = Some((ja, jj));
                    }
                }
            }
            if let Some((ca, ci)) = candidate {
                let cand = &c.arrays[ca].items[ci];
                if cand.age_set {
                    let (age, abf, abd) = (cand.age, cand.age_by_file, cand.age_by_dir);
                    let i = &mut c.arrays[gi].items[ii];
                    i.age = age;
                    i.age_set = true;
                    i.age_by_file = abf;
                    i.age_by_dir = abd;
                }
            }
        }
    }
    r
}

/// `parse_arguments()`.
fn parse_arguments(c: &mut Context, config_dirs: &[Vec<u8>], argv: &[Vec<u8>], invalid_config: &mut bool) -> i32 {
    for (pos, arg) in (1u32..).zip(argv) {
        if args().inline {
            let mut invalid_arg = false;
            let r = parse_line(c, b"(argument)", pos, arg, &mut invalid_arg);
            if invalid_arg {
                *invalid_config = true;
            } else if r < 0 {
                return r;
            }
        } else {
            let r = read_config_file(c, config_dirs, arg, false, invalid_config);
            if r < 0 {
                return r;
            }
        }
    }
    0
}

/// `read_config_files()`.
fn read_config_files(c: &mut Context, config_dirs: &[Vec<u8>], argv: &[Vec<u8>], invalid_config: &mut bool) -> i32 {
    let (files, p) =
        match conf_files_list_with_replacement(args().root.as_deref(), config_dirs, args().replace.as_deref()) {
            Ok(x) => x,
            Err(r) => return r,
        };
    for f in &files {
        if let Some(p) = &p
            && path_equal(f, p)
        {
            log_debug!("Parsing arguments at position \"", f, "\"", glyph(Glyph::Ellipsis));
            let r = parse_arguments(c, config_dirs, argv, invalid_config);
            if r < 0 {
                return r;
            }
        } else {
            let _ = read_config_file(c, config_dirs, f, true, invalid_config);
        }
    }
    0
}

/// `read_credential_lines()`.
fn read_credential_lines(c: &mut Context, invalid_config: &mut bool) -> i32 {
    let d = match shared::creds::get_credentials_dir() {
        Err(r) if r == -libc::ENXIO => return 0,
        Err(r) => return log_error_errno!(r, "Failed to get credentials directory: ", strerror(r)),
        Ok(d) => d,
    };
    let j = path_join(&[&d, b"tmpfiles.extra"]);
    let _ = read_config_file(c, &[], &j, true, invalid_config);
    0
}

/// `link_parent()`: register the closest parent array of `a`.
fn link_parent(c: &mut Context, a: usize) {
    let Some(first) = c.arrays[a].items.first() else { return };
    let path = first.path.clone();
    // PATH_FOREACH_PREFIX(): every proper prefix, longest first, ending with "".
    let mut prefix = path_simplify(&path);
    if prefix == b"/" {
        return;
    }
    loop {
        match prefix.iter().rposition(|&b| b == b'/') {
            Some(slash) => prefix.truncate(slash),
            None => break,
        }
        let j = c.items.get(&prefix).or_else(|| c.globs.get(&prefix)).copied();
        if let Some(j) = j {
            if !c.arrays[j].children.contains(&a) {
                c.arrays[j].children.push(a);
            }
            c.arrays[a].parent = Some(j);
            return;
        }
        if prefix.is_empty() {
            break;
        }
    }
}

/// `cat_config()`.
fn cat_config(config_dirs: &[Vec<u8>]) -> i32 {
    let files = match conf_files_list_with_replacement(args().root.as_deref(), config_dirs, args().replace.as_deref()) {
        Ok((f, _)) => f,
        Err(r) => return r,
    };
    pager_open(args().pager_flags);
    cat_files(None, &files, args().cat_flags)
}

/// `rlimit_nofile_bump(HIGH_RLIMIT_NOFILE)`.
fn rlimit_nofile_bump() {
    const HIGH_RLIMIT_NOFILE: u64 = 512 * 1024;
    let r = match sys::setrlimit_nofile(HIGH_RLIMIT_NOFILE, HIGH_RLIMIT_NOFILE) {
        Ok(()) => return,
        Err(e) if e != -libc::EPERM => e,
        Err(e) => match sys::getrlimit_nofile() {
            Err(g) => g,
            Ok((_, max)) if max == libc::RLIM_INFINITY => e,
            Ok((cur, max)) => {
                let fixed = (HIGH_RLIMIT_NOFILE.min(max), HIGH_RLIMIT_NOFILE.min(max));
                if fixed == (cur, max) {
                    return;
                }
                log_debug!(
                    "Failed at setting rlimit ",
                    HIGH_RLIMIT_NOFILE.to_string(),
                    " for resource RLIMIT_NOFILE. Will attempt setting value ",
                    fixed.1.to_string(),
                    " instead."
                );
                match sys::setrlimit_nofile(fixed.0, fixed.1) {
                    Ok(()) => return,
                    Err(e) => e,
                }
            }
        },
    };
    log_debug_errno!(r, "Failed to set RLIMIT_NOFILE: ", strerror(r));
}

/// `ERRNO_IS_NEG_RESOURCE()`.
fn errno_is_neg_resource(r: i32) -> bool {
    [-libc::ENOMEM, -libc::EMFILE, -libc::ENFILE].contains(&r)
}

/// `run()`.
fn run(argv: Vec<Vec<u8>>) -> i32 {
    let (a, positional) = match parse_argv(argv) {
        Ok(Some(x)) => x,
        Ok(None) => return 0,
        Err(r) => return r,
    };
    ARGS.set(a).expect("set once");
    shared::log::log_setup();

    if !shared::fs::proc_mounted() {
        return log_error_errno!(
            synthetic(libc::ENOSYS),
            "/proc/ is not mounted, but required for successful operation of systemd-tmpfiles. Please mount /proc/. Alternatively, consider using the --root= or --image= switches."
        );
    }

    rlimit_nofile_bump();

    let config_dirs = match args().runtime_scope {
        RuntimeScope::User => match user_config_paths() {
            Ok(d) => d,
            Err(r) => return log_error_errno!(r, "Failed to initialize configuration directory list: ", strerror(r)),
        },
        RuntimeScope::System => conf_paths("tmpfiles.d"),
    };

    if shared::log::enabled(libc::LOG_DEBUG) {
        let mut t = Vec::new();
        for i in &config_dirs {
            t.extend_from_slice(b"\n\t");
            t.extend(path_join(&[args().root.as_deref().unwrap_or_default(), i]));
        }
        log_debug!("Looking for configuration files in (higher priority first):", t);
    }

    if args().cat_flags != CAT_CONFIG_OFF {
        return cat_config(&config_dirs);
    }

    if shared::options::should_bypass("SYSTEMD_TMPFILES") {
        return 0;
    }

    sys::umask(0o022);

    if let Some(image) = &args().image {
        return log_error_errno!(
            synthetic(libc::EOPNOTSUPP),
            "Operating on disk image '",
            image,
            "' is not supported."
        );
    }

    let mut c = Context::default();
    let mut invalid_config = false;

    let r = if args().replace.is_some() || positional.is_empty() {
        read_config_files(&mut c, &config_dirs, &positional, &mut invalid_config)
    } else {
        parse_arguments(&mut c, &config_dirs, &positional, &mut invalid_config)
    };
    if r < 0 {
        return r;
    }

    let r = read_credential_lines(&mut c, &mut invalid_config);
    if r < 0 {
        return r;
    }

    // Link up all child/parent relationships.
    for a in c.items_order.clone() {
        link_parent(&mut c, a);
    }
    for a in c.globs_order.clone() {
        link_parent(&mut c, a);
    }

    // First purge, then remove/clean, and only then create, i.e. first
    // clean out the platform we then build on.
    let mut r = 0;
    for op in [OPERATION_PURGE, OPERATION_REMOVE | OPERATION_CLEAN, OPERATION_CREATE] {
        let op = args().operation & op;
        if op == 0 {
            continue;
        }
        // The non-globbing ones usually create things, hence we apply
        // them first; the globbing ones usually alter things.
        for &a in c.items_order.iter().chain(c.globs_order.iter()) {
            let k = ops::process_item_array(&c, a, op);
            shared::errno::ret_gather(&mut r, k);
        }
    }

    if errno_is_neg_resource(r) {
        return r;
    }
    if invalid_config {
        return 65; // EX_DATAERR
    }
    if r < 0 {
        return 73; // EX_CANTCREAT
    }
    0
}

fn main() {
    shared::main_func::main_with_positive_failure(run)
}

// Used by `find_uid()`/`find_gid()` with --root=.
pub(crate) fn chase_prefix_root(path: &[u8], root: Option<&[u8]>) -> Result<shared::chase::Chased, i32> {
    chase(path, root, CHASE_PREFIX_ROOT, true, true)
}
