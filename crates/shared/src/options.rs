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

/// `CommandDescription`, with the command's `VERB()` table (in source
/// order; empty for a command without verbs).
#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub names: &'static [&'static str],
    pub abstract_: &'static str,
    pub argspec: &'static [&'static str],
    pub footer: Option<&'static str>,
    pub man_pages: &'static [&'static str],
    pub verbs: &'static [Verb],
}

/// `VERB_ANY`.
pub const VERB_ANY: u32 = u32::MAX;
pub const VERB_DEFAULT: u32 = 1 << 0;
pub const VERB_ONLINE_ONLY: u32 = 1 << 1;
pub const VERB_OPTION_REQUIRED: u32 = 1 << 2;
pub const VERB_GROUP_MARKER: u32 = 1 << 4;
pub const VERB_DEPRECATED: u32 = 1 << 5;

/// One `VERB()` entry (or a `VERB_GROUP()` marker, whose `verb` is the
/// group's name).
#[derive(Debug, Clone, Copy)]
pub struct Verb {
    pub verb: &'static str,
    pub min_args: u32,
    pub max_args: u32,
    pub flags: u32,
    pub argspec: &'static [&'static str],
    pub help: Option<&'static str>,
}

impl Verb {
    /// `VERB(d, v, a, amin, amax, f, h)`.
    pub const fn new(
        verb: &'static str,
        argspec: &'static [&'static str],
        min_args: u32,
        max_args: u32,
        flags: u32,
        help: Option<&'static str>,
    ) -> Verb {
        Verb { verb, min_args, max_args, flags, argspec, help }
    }
    /// `VERB_NOARG(d, v, h)`.
    pub const fn noarg(verb: &'static str, help: &'static str) -> Verb {
        Verb::new(verb, &[], VERB_ANY, 1, 0, Some(help))
    }
    /// `VERB_COMMON_HELP_AUTO_HIDDEN()`.
    pub const fn help_hidden() -> Verb {
        Verb::new("help", &[], VERB_ANY, VERB_ANY, 0, None)
    }
    /// `VERB_GROUP(gr)`.
    pub const fn group(name: &'static str) -> Verb {
        Verb::new(name, &[], 0, 0, VERB_GROUP_MARKER, None)
    }
    fn is_group(&self) -> bool {
        self.flags & VERB_GROUP_MARKER != 0
    }
}

/// `strlevenshtein()`.
pub fn strlevenshtein(x: &[u8], y: &[u8]) -> usize {
    if x == y {
        return 0;
    }
    if x.is_empty() {
        return y.len();
    }
    if y.is_empty() {
        return x.len();
    }
    let yl = y.len();
    let mut t0 = vec![0usize; yl + 1];
    let mut t1: Vec<usize> = (0..=yl).collect();
    let mut t2 = vec![0usize; yl + 1];
    for i in 0..x.len() {
        t2[0] = i + 1;
        for j in 0..yl {
            t2[j + 1] = t1[j] + (x[i] != y[j]) as usize;
            if i > 0 && j > 0 && x[i - 1] == y[j] && x[i] == y[j - 1] && t2[j + 1] > t0[j - 1] + 1 {
                t2[j + 1] = t0[j - 1] + 1;
            }
            if t2[j + 1] > t1[j + 1] + 1 {
                t2[j + 1] = t1[j + 1] + 1;
            }
            if t2[j + 1] > t2[j] + 1 {
                t2[j + 1] = t2[j] + 1;
            }
        }
        std::mem::swap(&mut t0, &mut t1);
        std::mem::swap(&mut t1, &mut t2);
    }
    t1[yl]
}

/// `strv_find_closest()`: the shortest completion of name, else the
/// closest within a Levenshtein distance of 5.
pub fn strv_find_closest<'a>(l: &[&'a str], name: &[u8]) -> Option<&'a str> {
    let mut best: Option<(usize, &str)> = None;
    for s in l {
        if let Some(e) = s.as_bytes().strip_prefix(name)
            && best.is_none_or(|(d, _)| e.len() < d)
        {
            best = Some((e.len(), s));
        }
    }
    if let Some((_, s)) = best {
        return Some(s);
    }
    for s in l {
        let d = strlevenshtein(s.as_bytes(), name);
        if d > 5 {
            continue;
        }
        if best.is_none_or(|(bd, _)| d < bd) {
            best = Some((d, s));
        }
    }
    best.map(|(_, s)| s)
}

/// `_dispatch_verb(args, ...)`: which verb to run, and its argv (the verb
/// alone if none was given and a default verb runs).
pub fn dispatch_verb(args: &[Vec<u8>], verbs: &'static [Verb]) -> Result<(&'static Verb, Vec<Vec<u8>>), i32> {
    let name = args.first();
    let mut left = args.len();
    let verb = verbs.iter().find(|v| {
        !v.is_group()
            && match name {
                Some(n) => n == v.verb.as_bytes(),
                None => v.flags & VERB_DEFAULT != 0,
            }
    });
    let Some(verb) = verb else {
        let names: Vec<&str> = verbs.iter().filter(|v| !v.is_group()).map(|v| v.verb).collect();
        if let Some(n) = name {
            if let Some(found) = strv_find_closest(&names, n) {
                return Err(log_error_errno!(
                    synthetic(libc::EINVAL),
                    "Unknown command verb '",
                    n,
                    "', did you mean '",
                    found,
                    "'?"
                ));
            }
            return Err(log_error_errno!(synthetic(libc::EINVAL), "Unknown command verb '", n, "'."));
        }
        if names.len() >= 2 {
            return Err(log_error_errno!(
                synthetic(libc::EINVAL),
                "Command verb required (one of ",
                names.join(", "),
                ")."
            ));
        }
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Command verb '", names[0], "' required."));
    };
    if name.is_none() {
        left = 1;
    }
    if verb.min_args != VERB_ANY && left < verb.min_args as usize {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Too few arguments."));
    }
    if verb.max_args != VERB_ANY && left > verb.max_args as usize {
        return Err(log_error_errno!(synthetic(libc::EINVAL), "Too many arguments."));
    }
    // VERB_ONLINE_ONLY is not used by the programs ported so far.
    debug_assert!(verb.flags & VERB_ONLINE_ONLY == 0);
    if name.is_none() {
        return Ok((verb, vec![verb.verb.as_bytes().to_vec()]));
    }
    Ok((verb, args.to_vec()))
}

const VERB_SYNOPSIS_WIDTH_SANE: usize = 25;

/// `find_point_to_break()`: where the part after the break starts.
fn find_point_to_break(s: &[u8], max_width: usize) -> Option<usize> {
    if s.len() <= max_width {
        return None;
    }
    let p = s[max_width..]
        .iter()
        .position(|&c| c == b' ')
        .map(|k| k + max_width)
        .or_else(|| s.iter().rposition(|&c| c == b' '));
    p.map(|k| k + 1)
}

/// `verb_add_help_one()`.
fn verb_add_help_one(table: &mut Table, verb: &Verb) {
    let is_default = verb.flags & VERB_DEFAULT != 0;
    let specs: Vec<Option<&str>> = if verb.argspec.is_empty() || verb.argspec[0].is_empty() {
        vec![None]
    } else {
        verb.argspec.iter().map(|s| Some(*s)).collect()
    };
    let mut cell: Vec<u8> = Vec::new();
    for spec in specs {
        let s = bcat!(
            "  ",
            if is_default { "[" } else { "" },
            verb.verb,
            if spec.is_some() { " " } else { "" },
            spec.unwrap_or_default(),
            if is_default { "]" } else { "" },
            if verb.flags & VERB_OPTION_REQUIRED != 0 { " OPTION" } else { "" }
        );
        let mut ss: Option<Vec<u8>> = None;
        if (columns() as usize) < VERB_SYNOPSIS_WIDTH_SANE * 4
            && let Some(p) = find_point_to_break(&s, VERB_SYNOPSIS_WIDTH_SANE)
        {
            let s1 = &s[..p];
            let rest = &s[p..];
            ss = Some(match find_point_to_break(rest, VERB_SYNOPSIS_WIDTH_SANE - 4) {
                Some(p2) => bcat!(s1, "\n    ", &rest[..p2], "\n    ", &rest[p2..]),
                None => bcat!(s1, "\n    ", rest),
            });
        }
        if !cell.is_empty() {
            cell.push(b'\n');
        }
        cell.extend(ss.unwrap_or(s));
    }
    table.add(Cell::String(cell));
    table.add(Cell::StrvWrapped(strv_split(verb.help.unwrap_or_default().as_bytes(), crate::string::WHITESPACE)));
}

/// `verbs_get_help_table(verbs, group)`: (table, entries consumed).
fn verbs_help_table(verbs: &[Verb], group: Option<&str>) -> (Table, usize) {
    let mut table = Table::new(&["verb", "help"]);
    let mut in_group = group.is_none();
    let mut i = 0;
    while i < verbs.len() {
        let v = &verbs[i];
        if !in_group {
            in_group = v.is_group() && Some(v.verb) == group;
            i += 1;
            continue;
        }
        if v.is_group() {
            break;
        }
        i += 1;
        if v.flags & VERB_DEPRECATED != 0 || v.help.is_none() {
            continue;
        }
        verb_add_help_one(&mut table, v);
    }
    table.set_header(false);
    (table, i)
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
    } else if cmd.verbs.iter().any(|v| v.help.is_some()) {
        help_cmdline("[OPTION…] COMMAND …".as_bytes());
    } else {
        help_cmdline(b"[OPTION\xe2\x80\xa6]");
    }
    let seq = format!("{}{}", ansi::highlight(), ansi::add_italics());
    let r = print_wrapped(Some(cmd.abstract_), Some(&seq));
    if r < 0 {
        return r;
    }

    // print_verb_option_help(): the verb groups, then the option groups.
    let mut tables: Vec<(Table, &'static str)> = Vec::new();
    let mut i = 0;
    while i < cmd.verbs.len() {
        let group = if cmd.verbs[i].is_group() { Some(cmd.verbs[i].verb) } else { None };
        let (t, n) = verbs_help_table(&cmd.verbs[i..], group);
        tables.push((t, group.unwrap_or("Commands")));
        i += n;
    }
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
    let verbs: Vec<Json> = cmd
        .verbs
        .iter()
        .filter(|v| !v.is_group())
        .map(|v| {
            let mut o = vec![(b"names".to_vec(), Json::strv(&[v.verb]))];
            if let Some(h) = v.help {
                o.push((b"abstract".to_vec(), Json::strv(&[h])));
            }
            if v.min_args != VERB_ANY {
                o.push((b"minArguments".to_vec(), Json::Unsigned(v.min_args as u64)));
            }
            if v.max_args != VERB_ANY {
                o.push((b"maxArguments".to_vec(), Json::Unsigned(v.max_args as u64)));
            }
            for (flag, name) in
                [(VERB_DEFAULT, "isDefault"), (VERB_DEPRECATED, "isDeprecated"), (VERB_ONLINE_ONLY, "isOnlineOnly")]
            {
                if v.flags & flag != 0 {
                    o.push((name.as_bytes().to_vec(), Json::Bool(true)));
                }
            }
            Json::Object(o)
        })
        .collect();
    if !verbs.is_empty() {
        c.push((b"verbs".to_vec(), Json::Array(verbs)));
    }
    let w = Json::Object(vec![
        (b"mediaType".to_vec(), Json::str("application/vnd.io.systemd.cli-introspection-0")),
        (b"commands".to_vec(), Json::Array(vec![Json::Object(c)])),
    ]);
    out(&dump(&w, flags));
    0
}

/// `should_bypass(env_prefix)` (`verbs.c`).
pub fn should_bypass(env_prefix: &str) -> bool {
    let env = format!("{env_prefix}_BYPASS");
    match crate::env::getenv_bool(&env) {
        Err(r) if r != -libc::ENXIO => {
            crate::log_debug_errno!(r, "Failed to parse $", env, ", assuming no: ", crate::errno::strerror(r));
            false
        }
        Ok(true) => {
            crate::log_debug!("$", env, " is enabled, skipping execution.");
            true
        }
        _ => false,
    }
}
