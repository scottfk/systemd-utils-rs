// SPDX-License-Identifier: LGPL-2.1-or-later
//! `options.c` and the command help/introspection parts of `verbs.c`:
//! systemd 262's table-driven option parser.
//!
//! In C the table is assembled by the linker from `OPTION()` macros in
//! `parse_argv()`; here each program passes a slice of [`Opt`] in the same
//! order.

use crate::errno::synthetic;
use crate::json::{Json, SD_JSON_FORMAT_OFF, SD_JSON_FORMAT_PRETTY_AUTO, dump};
use crate::log::{LOG_ERR, program_name};
use crate::stdio::out;
use crate::string::{strv_rebreak_lines, strv_split};
use crate::table::{Cell, Table, sync_all_column_widths};
use crate::terminal::{ansi, columns};
use crate::{bcat, log_error_errno, log_full_errno, printo};

pub const OPTION_OPTIONAL_ARG: u32 = 1 << 0;
pub const OPTION_POSITIONAL_ENTRY: u32 = 1 << 1;
pub const OPTION_STOPS_PARSING: u32 = 1 << 2;
pub const OPTION_NAMESPACE_MARKER: u32 = 1 << 3;
pub const OPTION_GROUP_MARKER: u32 = 1 << 4;
pub const OPTION_HELP_ENTRY: u32 = 1 << 5;
pub const OPTION_HELP_ENTRY_VERBATIM: u32 = 1 << 6;

/// One `Option` entry.  `id` is what `option_parse()` returns.
#[derive(Debug, Clone, Copy)]
pub struct Opt {
    pub id: i32,
    pub flags: u32,
    pub short: u8,
    pub long: Option<&'static str>,
    pub metavar: Option<&'static str>,
    pub help: Option<&'static str>,
}

impl Opt {
    /// `OPTION(sc, lc, mv, h)`.
    pub const fn new(
        id: i32,
        short: u8,
        long: Option<&'static str>,
        metavar: Option<&'static str>,
        help: Option<&'static str>,
    ) -> Opt {
        Opt { id, flags: 0, short, long, metavar, help }
    }
    /// `OPTION_LONG(lc, mv, h)`.
    pub const fn long(id: i32, long: &'static str, metavar: Option<&'static str>, help: Option<&'static str>) -> Opt {
        Opt { id, flags: 0, short: 0, long: Some(long), metavar, help }
    }
    /// `OPTION_GROUP(gr)`.
    pub const fn group(name: &'static str) -> Opt {
        Opt { id: 0, flags: OPTION_GROUP_MARKER, short: 0, long: Some(name), metavar: None, help: None }
    }
    pub const fn with_flags(mut self, flags: u32) -> Opt {
        self.flags |= flags;
        self
    }

    fn takes_arg(&self) -> bool {
        self.metavar.is_some()
    }
    fn arg_optional(&self) -> bool {
        self.takes_arg() && self.flags & OPTION_OPTIONAL_ARG != 0
    }
    fn arg_required(&self) -> bool {
        self.takes_arg() && self.flags & OPTION_OPTIONAL_ARG == 0
    }
    fn is_metadata(&self) -> bool {
        self.flags
            & (OPTION_NAMESPACE_MARKER
                | OPTION_GROUP_MARKER
                | OPTION_POSITIONAL_ENTRY
                | OPTION_HELP_ENTRY
                | OPTION_HELP_ENTRY_VERBATIM)
            != 0
    }
}

/// The common options (`OPTION_COMMON_*`).
pub mod common {
    use super::Opt;
    pub const fn help(id: i32) -> Opt {
        Opt::new(id, b'h', Some("help"), None, Some("Show this help"))
    }
    pub const fn version(id: i32) -> Opt {
        Opt::long(id, "version", None, Some("Show package version"))
    }
    pub const fn version_with_v(id: i32) -> Opt {
        Opt::new(id, b'V', Some("version"), None, Some("Show package version"))
    }
    pub const fn introspect_cli(id: i32) -> Opt {
        Opt::long(id, "introspect-cli", None, None)
    }
    pub const fn no_pager(id: i32) -> Opt {
        Opt::long(id, "no-pager", None, Some("Do not start a pager"))
    }
    pub const fn no_legend(id: i32) -> Opt {
        Opt::long(id, "no-legend", None, Some("Do not show headers and footers"))
    }
    pub const fn cat_config(id: i32) -> Opt {
        Opt::long(id, "cat-config", None, Some("Show configuration files"))
    }
    pub const fn tldr(id: i32) -> Opt {
        Opt::long(id, "tldr", None, Some("Show non-comment parts of configuration"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserMode {
    Normal,
    StopAtFirstNonoption,
    ReturnPositionalArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    Running,
    Stopping,
    Done,
    Failed,
}

/// `OptionParser`.
#[derive(Debug)]
pub struct OptionParser<'a> {
    pub argv: Vec<Vec<u8>>,
    pub mode: ParserMode,
    options: &'a [Opt],
    state: State,
    optind: usize,
    short_option_offset: usize,
    positional_offset: usize,
    /// The argument of the last matched option.
    pub arg: Option<Vec<u8>>,
}

impl<'a> OptionParser<'a> {
    pub fn new(argv: Vec<Vec<u8>>, options: &'a [Opt]) -> OptionParser<'a> {
        OptionParser {
            argv,
            mode: ParserMode::Normal,
            options,
            state: State::Init,
            optind: 0,
            short_option_offset: 0,
            positional_offset: 0,
            arg: None,
        }
    }

    /// `shift_arg()`: move argv[source] before argv[target].
    fn shift_arg(&mut self, target: usize, source: usize) {
        let saved = self.argv.remove(source);
        self.argv.insert(target, saved);
    }

    fn fail(&mut self, r: i32) -> Result<Option<i32>, i32> {
        self.state = State::Failed;
        Err(r)
    }

    /// `partial_match_error()`.
    fn partial_match_error(&mut self, optname: &[u8]) -> i32 {
        let s: Vec<Vec<u8>> = self
            .options
            .iter()
            .filter(|o| !o.is_metadata() && o.long.is_some_and(|l| l.as_bytes().starts_with(&optname[2..])))
            .map(|o| bcat!("--", o.long.unwrap_or_default()))
            .collect();
        let p = crate::string::strv_join(&s, b", ");
        log_full_errno!(
            LOG_ERR,
            synthetic(libc::EINVAL),
            program_name(),
            ": option '",
            optname,
            "' is ambiguous; possibilities: ",
            p
        )
    }

    /// `option_parse()`: `Ok(Some(id))` per option, `Ok(None)` when done.
    pub fn next(&mut self) -> Result<Option<i32>, i32> {
        match self.state {
            State::Init => {
                if self.argv.is_empty() {
                    let r = log_full_errno!(LOG_ERR, synthetic(libc::EUCLEAN), "argv cannot be empty");
                    return self.fail(r);
                }
                self.optind = 1;
                self.positional_offset = 1;
                self.state = State::Running;
            }
            State::Running | State::Stopping => {}
            State::Done => return Ok(self.done()),
            State::Failed => {
                return Err(log_full_errno!(
                    LOG_ERR,
                    synthetic(libc::ESTALE),
                    "Option parser failed before, refusing."
                ));
            }
        }
        let argc = self.argv.len();
        let mut option: Option<Opt> = None;
        let mut optname: Vec<u8> = Vec::new();
        let mut optval: Option<Vec<u8>> = None;
        let mut separate_optval = false;
        let mut handling_positional_arg = false;

        if self.short_option_offset == 0 {
            loop {
                if self.optind == argc {
                    return Ok(self.done());
                }
                if self.argv[self.optind] == b"--" {
                    let (t, s) = (self.positional_offset, self.optind);
                    self.shift_arg(t, s);
                    self.positional_offset += 1;
                    self.optind += 1;
                    return Ok(self.done());
                }
                if self.state == State::Stopping {
                    return Ok(self.done());
                }
                let a = &self.argv[self.optind];
                if a.first() == Some(&b'-') && a.len() > 1 {
                    break;
                }
                if self.mode == ParserMode::StopAtFirstNonoption {
                    return Ok(self.done());
                }
                if self.mode == ParserMode::ReturnPositionalArgs {
                    handling_positional_arg = true;
                    optval = Some(a.clone());
                    break;
                }
                self.optind += 1;
            }

            if handling_positional_arg {
                option = self.options.iter().find(|o| o.flags & OPTION_POSITIONAL_ENTRY != 0).copied();
                assert!(option.is_some(), "OPTION_POSITIONAL is required");
            } else if self.argv[self.optind].get(1) == Some(&b'-') {
                let a = self.argv[self.optind].clone();
                if let Some(eq) = a.iter().position(|&b| b == b'=') {
                    optname = a[..eq].to_vec();
                    optval = Some(a[eq + 1..].to_vec());
                } else {
                    optname = a;
                }
                if optname.len() == 2 {
                    let r = log_full_errno!(
                        LOG_ERR,
                        synthetic(libc::EINVAL),
                        program_name(),
                        ": unrecognized option '",
                        optname,
                        "'"
                    );
                    return self.fail(r);
                }
                let name = &optname[2..];
                let mut last_partial = None;
                let mut n_partial = 0;
                let mut exact = None;
                for o in self.options {
                    if o.is_metadata() {
                        continue;
                    }
                    let Some(l) = o.long else { continue };
                    let Some(rest) = l.as_bytes().strip_prefix(name) else { continue };
                    if rest.is_empty() {
                        exact = Some(*o);
                        break;
                    }
                    last_partial = Some(*o);
                    n_partial += 1;
                }
                option = match exact {
                    Some(o) => Some(o),
                    None => {
                        if n_partial == 0 {
                            let r = log_full_errno!(
                                LOG_ERR,
                                synthetic(libc::EINVAL),
                                program_name(),
                                ": unrecognized option '",
                                optname,
                                "'"
                            );
                            return self.fail(r);
                        }
                        if n_partial > 1 {
                            let r = self.partial_match_error(&optname);
                            return self.fail(r);
                        }
                        last_partial
                    }
                };
            } else {
                self.short_option_offset = 1;
            }
        }

        if self.short_option_offset > 0 {
            let a = self.argv[self.optind].clone();
            let optchar = a[self.short_option_offset];
            optname = vec![b'-', optchar];
            let Some(o) = self.options.iter().find(|o| !o.is_metadata() && o.short == optchar).copied() else {
                let r = log_full_errno!(
                    LOG_ERR,
                    synthetic(libc::EINVAL),
                    program_name(),
                    ": unrecognized option '",
                    optname,
                    "'"
                );
                return self.fail(r);
            };
            let rest = &a[self.short_option_offset + 1..];
            if o.takes_arg() && !rest.is_empty() {
                optval = Some(rest.to_vec());
                self.short_option_offset = 0;
            } else if rest.is_empty() {
                self.short_option_offset = 0;
            } else {
                self.short_option_offset += 1;
            }
            option = Some(o);
        }

        let o = option.expect("matched above");
        if !handling_positional_arg && optval.is_some() && !o.takes_arg() {
            let r = log_full_errno!(
                LOG_ERR,
                synthetic(libc::EINVAL),
                program_name(),
                ": option '",
                optname,
                "' doesn't allow an argument"
            );
            return self.fail(r);
        }
        if !handling_positional_arg && optval.is_none() && o.arg_required() {
            if self.optind + 1 >= argc {
                let r = log_full_errno!(
                    LOG_ERR,
                    synthetic(libc::EINVAL),
                    program_name(),
                    ": option '",
                    optname,
                    "' requires an argument"
                );
                return self.fail(r);
            }
            optval = Some(self.argv[self.optind + 1].clone());
            separate_optval = true;
        }
        if self.short_option_offset == 0 {
            let (t, s) = (self.positional_offset, self.optind);
            self.shift_arg(t, s);
            self.positional_offset += 1;
            self.optind += 1;
            if separate_optval {
                let (t, s) = (self.positional_offset, self.optind);
                self.shift_arg(t, s);
                self.positional_offset += 1;
                self.optind += 1;
            }
        }
        if o.flags & OPTION_STOPS_PARSING != 0 {
            self.state = State::Stopping;
        }
        self.arg = optval;
        Ok(Some(o.id))
    }

    fn done(&mut self) -> Option<i32> {
        self.state = State::Done;
        self.arg = None;
        None
    }

    /// `option_parser_get_args()`.
    pub fn args(&self) -> &[Vec<u8>] {
        &self.argv[self.positional_offset..]
    }
}

/// `option_get_synopsis(opt, joiner, show_metavar)`.
pub fn option_get_synopsis(opt: &Opt, joiner: Option<&str>, show_metavar: bool) -> Vec<u8> {
    if opt.flags & (OPTION_HELP_ENTRY_VERBATIM | OPTION_POSITIONAL_ENTRY) != 0 {
        return opt.long.unwrap_or_default().as_bytes().to_vec();
    }
    let sc: Vec<u8> = if opt.short != 0 { vec![b'-', opt.short] } else { Vec::new() };
    let joiner = if show_metavar && opt.metavar.is_some() && opt.long.is_none() {
        " "
    } else if opt.short == 0 || opt.long.is_none() {
        ""
    } else {
        joiner.unwrap_or(" ")
    };
    let need_eq = opt.takes_arg() && opt.long.is_some();
    let long = opt.long.unwrap_or_default();
    let dashes = if opt.long.is_some() { "--" } else { "" };
    if !show_metavar {
        return bcat!(sc, joiner, dashes, long, if need_eq { "=" } else { "" });
    }
    let need_quote = opt.metavar.is_some_and(|m| m.contains(' '));
    let q = if need_quote { "'" } else { "" };
    let (ob, cb) = if opt.arg_optional() { ("[", "]") } else { ("", "") };
    bcat!(sc, joiner, dashes, long, ob, if need_eq { "=" } else { "" }, q, opt.metavar.unwrap_or_default(), q, cb)
}

/// `options_get_help_table_group()`: (table, group name, entries consumed).
fn help_table_group(options: &[Opt]) -> (Table, Option<&'static str>, usize) {
    let group_marker = options[0].flags & OPTION_GROUP_MARKER != 0;
    let group = if group_marker { options[0].long } else { None };
    let mut table = Table::new(&["names", "help"]);
    let mut i = group_marker as usize;
    while i < options.len() {
        let opt = &options[i];
        if opt.flags & (OPTION_NAMESPACE_MARKER | OPTION_GROUP_MARKER) != 0 {
            break;
        }
        i += 1;
        let Some(help) = opt.help else { continue };
        let s = option_get_synopsis(opt, Some(" "), true);
        let shift_left = opt.short != 0 || opt.flags & OPTION_HELP_ENTRY_VERBATIM != 0;
        table.add(Cell::String(bcat!(if shift_left { "  " } else { "     " }, s)));
        table.add(Cell::StrvWrapped(strv_split(help.as_bytes(), crate::string::WHITESPACE)));
    }
    table.set_header(false);
    (table, group, i)
}

/// `CommandDescription`.
#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub names: &'static [&'static str],
    pub abstract_: &'static str,
    pub argspec: &'static [&'static str],
    pub footer: Option<&'static str>,
    pub man_pages: &'static [&'static str],
}

/// `help_cmdline()`.
fn help_cmdline(arguments: &[u8]) {
    let invoked = crate::env::secure_getenv("SYSTEMD_INVOKED_AS");
    let progname = match invoked.as_deref().map(crate::path::last_path_component) {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => program_name(),
    };
    printo!(ansi::grey(), ">", ansi::normal(), " ", progname, " ", arguments, "\n");
}

/// `help_section()`.
pub fn help_section(title: &str) {
    printo!("\n", ansi::underline(), title, ":", ansi::normal(), "\n");
}

/// `print_wrapped()`.
fn print_wrapped(text: Option<&str>, ansi_seq: Option<&str>) -> i32 {
    let Some(text) = text else { return 0 };
    let width = (columns() as usize).min(80);
    let lines = match crate::extract::strv_split_full(
        text.as_bytes(),
        Some(b"\n"),
        crate::extract::EXTRACT_DONT_COALESCE_SEPARATORS,
    ) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let lines2 = match strv_rebreak_lines(&lines, width) {
        Ok(l) => l,
        Err(r) => return r,
    };
    out(b"\n");
    for l in &lines2 {
        match ansi_seq {
            Some(seq) => printo!(seq, l, ansi::normal(), "\n"),
            None => printo!(l, "\n"),
        }
    }
    0
}

/// `_command_print_help_full(..., name=NULL, footer_ansi_seq=NULL)` for a
/// command without verbs.
pub fn command_print_help(cmd: &Command, options: &[Opt], pager_flags: Option<u32>) -> i32 {
    if let Some(f) = pager_flags {
        crate::pager::pager_open(f);
    }
    if !cmd.argspec.is_empty() {
        for spec in cmd.argspec {
            help_cmdline(&bcat!("[OPTION…] ", spec));
        }
    } else {
        help_cmdline(b"[OPTION\xe2\x80\xa6]");
    }
    let seq = format!("{}{}", ansi::highlight(), ansi::add_italics());
    let r = print_wrapped(Some(cmd.abstract_), Some(&seq));
    if r < 0 {
        return r;
    }

    // print_verb_option_help(): no verbs, so only the option groups.
    let mut tables: Vec<(Table, &'static str)> = Vec::new();
    let mut i = 0;
    while i < options.len() {
        if options[i].flags & OPTION_NAMESPACE_MARKER != 0 {
            break;
        }
        let (t, group, n) = help_table_group(&options[i..]);
        tables.push((t, group.unwrap_or("Options")));
        i += n;
    }
    {
        let mut refs: Vec<&mut Table> = tables.iter_mut().map(|(t, _)| t).collect();
        sync_all_column_widths(0, &mut refs);
    }
    for (t, g) in tables.iter_mut() {
        if t.is_empty() {
            continue;
        }
        help_section(g);
        out(&t.format());
        let r = crate::stdio::fflush_and_check_stdout();
        if r < 0 {
            let r = log_error_errno!(r, "Failed to print table: ", crate::errno::strerror(r));
            return log_error_errno!(r, "Failed to print verb&option help: ", crate::errno::strerror(r));
        }
    }

    let r = print_wrapped(cmd.footer, None);
    if r < 0 {
        return r;
    }
    for page in cmd.man_pages {
        let link = crate::pretty_print::terminal_urlify_man(page.as_bytes(), None);
        printo!("\nSee the ", link, " for details.\n");
    }
    0
}

/// `options_build_json()`.
fn options_build_json(options: &[Opt]) -> Option<Json> {
    let mut array = Vec::new();
    let mut group: Option<&str> = None;
    for opt in options {
        if opt.flags & OPTION_NAMESPACE_MARKER != 0 {
            break;
        }
        if opt.flags & OPTION_GROUP_MARKER != 0 {
            group = opt.long;
            continue;
        }
        if opt.is_metadata() {
            continue;
        }
        let mut names = Vec::new();
        if opt.short != 0 {
            names.push(Json::String(vec![b'-', opt.short]));
        }
        if let Some(l) = opt.long {
            names.push(Json::str(format!("--{l}")));
        }
        let argtype = if opt.arg_required() {
            "required_argument"
        } else if opt.arg_optional() {
            "optional_argument"
        } else {
            "no_argument"
        };
        let mut o = vec![(b"names".to_vec(), Json::Array(names)), (b"argument".to_vec(), Json::str(argtype))];
        if let Some(m) = opt.metavar {
            o.push((b"metavar".to_vec(), Json::str(m)));
        }
        if let Some(h) = opt.help {
            o.push((b"help".to_vec(), Json::str(h)));
        }
        if let Some(g) = group {
            o.push((b"group".to_vec(), Json::strv(&[g])));
        }
        array.push(Json::Object(o));
    }
    if array.is_empty() { None } else { Some(Json::Array(array)) }
}

/// `_introspect_cli(..., flags)` for one command without verbs.
pub fn introspect_cli(cmd: &Command, options: &[Opt], mut flags: u32) -> i32 {
    if flags == SD_JSON_FORMAT_OFF {
        flags = SD_JSON_FORMAT_PRETTY_AUTO;
    }
    let mut c = vec![
        (b"names".to_vec(), Json::strv(cmd.names)),
        (b"project".to_vec(), Json::str("systemd")),
        (b"version".to_vec(), Json::str(crate::build::PROJECT_VERSION_FULL)),
        (b"features".to_vec(), Json::Array(crate::build::SYSTEMD_FEATURES.split(' ').map(Json::str).collect())),
        (b"abstract".to_vec(), Json::strv(&[cmd.abstract_])),
    ];
    if let Some(f) = cmd.footer {
        c.push((b"postscript".to_vec(), Json::strv(&[f])));
    }
    if let Some(o) = options_build_json(options) {
        c.push((b"options".to_vec(), o));
    }
    let w = Json::Object(vec![
        (b"mediaType".to_vec(), Json::str("application/vnd.io.systemd.cli-introspection-0")),
        (b"commands".to_vec(), Json::Array(vec![Json::Object(c)])),
    ]);
    out(&dump(&w, flags));
    0
}
