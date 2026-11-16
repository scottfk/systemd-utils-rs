// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-rules.c`: the rule types and token parsing; `load` reads the
//! files, `apply` runs them on events.

mod apply;
mod load;

pub use load::udev_rules_load;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use shared::conf_files::{
    CONF_FILES_FILTER_MASKED, CONF_FILES_REGULAR, ConfFile, conf_files_list_strv_full, conf_paths,
};
use shared::errno::{strerror, synthetic};
use shared::fileio::{CReader, read_line};
use shared::log::{LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING};
use shared::sd_device::{Dev, Device, log_device_full};
use shared::string::{DIGITS, GLOB_CHARS, WHITESPACE, in_charset, skip_leading_chars, string_is_glob};
use shared::{bcat, log_debug, log_debug_errno, log_warning_errno};

use super::builtin::{BuiltinCommand, udev_builtin_lookup};
use super::def::{MODE_INVALID, ResolveNameTiming, UDEV_LINE_SIZE};
use super::format::udev_check_format;

/// `UdevRuleOperatorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Match,
    Nomatch,
    Add,
    Remove,
    Assign,
    AssignFinal,
}

// `UdevRuleMatchType`.
pub(super) const MATCH_TYPE_EMPTY: u8 = 0;
pub(super) const MATCH_TYPE_PLAIN: u8 = 1;
pub(super) const MATCH_TYPE_PLAIN_WITH_EMPTY: u8 = 2;
pub(super) const MATCH_TYPE_GLOB: u8 = 3;
pub(super) const MATCH_TYPE_GLOB_WITH_EMPTY: u8 = 4;
pub(super) const MATCH_TYPE_SUBSYSTEM: u8 = 5;
pub(super) const MATCH_TYPE_MASK: u8 = (1 << 5) - 1;
pub(super) const MATCH_REMOVE_TRAILING_WHITESPACE: u8 = 1 << 5;
pub(super) const MATCH_CASE_INSENSITIVE: u8 = 1 << 6;
/// `_MATCH_TYPE_INVALID` with the case flag cleared, in an 8-bit field.
pub(super) const MATCH_TYPE_INVALID: u8 = 0xAA;

/// `UdevRuleSubstituteType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubstType {
    Plain,
    Format,
    Subsys,
    Invalid,
}

/// `UdevRuleTokenType`, in its order (`sort_tokens()` sorts by it).
pub(super) mod tk {
    pub const M_ACTION: u8 = 0;
    pub const M_DEVPATH: u8 = 1;
    pub const M_KERNEL: u8 = 2;
    pub const M_DEVLINK: u8 = 3;
    pub const M_NAME: u8 = 4;
    pub const M_ENV: u8 = 5;
    pub const M_CONST: u8 = 6;
    pub const M_TAG: u8 = 7;
    pub const M_SUBSYSTEM: u8 = 8;
    pub const M_DRIVER: u8 = 9;
    pub const M_ATTR: u8 = 10;
    pub const M_SYSCTL: u8 = 11;
    pub const M_PARENTS_KERNEL: u8 = 12;
    pub const M_PARENTS_SUBSYSTEM: u8 = 13;
    pub const M_PARENTS_DRIVER: u8 = 14;
    pub const M_PARENTS_ATTR: u8 = 15;
    pub const M_PARENTS_TAG: u8 = 16;
    pub const M_TEST: u8 = 17;
    pub const M_PROGRAM: u8 = 18;
    pub const M_IMPORT_FILE: u8 = 19;
    pub const M_IMPORT_PROGRAM: u8 = 20;
    pub const M_IMPORT_BUILTIN: u8 = 21;
    pub const M_IMPORT_DB: u8 = 22;
    pub const M_IMPORT_CMDLINE: u8 = 23;
    pub const M_IMPORT_PARENT: u8 = 24;
    pub const M_RESULT: u8 = 25;
    pub const M_MAX: u8 = 26;
    pub const A_OPTIONS_DUMP: u8 = 26;
    pub const A_OPTIONS_STRING_ESCAPE_NONE: u8 = 27;
    pub const A_OPTIONS_STRING_ESCAPE_REPLACE: u8 = 28;
    pub const A_OPTIONS_DB_PERSIST: u8 = 29;
    pub const A_OPTIONS_INOTIFY_WATCH: u8 = 30;
    pub const A_OPTIONS_DEVLINK_PRIORITY: u8 = 31;
    pub const A_OPTIONS_LOG_LEVEL: u8 = 32;
    pub const A_OWNER: u8 = 33;
    pub const A_GROUP: u8 = 34;
    pub const A_MODE: u8 = 35;
    pub const A_OWNER_ID: u8 = 36;
    pub const A_GROUP_ID: u8 = 37;
    pub const A_MODE_ID: u8 = 38;
    pub const A_TAG: u8 = 39;
    pub const A_OPTIONS_STATIC_NODE: u8 = 40;
    pub const A_SECLABEL: u8 = 41;
    pub const A_ENV: u8 = 42;
    pub const A_NAME: u8 = 43;
    pub const A_DEVLINK: u8 = 44;
    pub const A_ATTR: u8 = 45;
    pub const A_SYSCTL: u8 = 46;
    pub const A_RUN_BUILTIN: u8 = 47;
    pub const A_RUN_PROGRAM: u8 = 48;
}

// `UdevRuleLineType`.
const LINE_HAS_NAME: u32 = 1 << 0;
const LINE_HAS_DEVLINK: u32 = 1 << 1;
const LINE_HAS_STATIC_NODE: u32 = 1 << 2;
const LINE_HAS_GOTO: u32 = 1 << 3;
const LINE_HAS_LABEL: u32 = 1 << 4;
const LINE_UPDATE_SOMETHING: u32 = 1 << 5;
const LINE_IS_REFERENCED: u32 = 1 << 6;

/// A token's `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Data {
    None,
    /// The attribute (`ENV{x}`, `ATTR{x}`, ...).
    Str(Vec<u8>),
    Mode(u32),
    Id(u32),
    Int(i32),
    Builtin(BuiltinCommand),
    JsonFlags(u32),
}

impl Data {
    pub(super) fn str(&self) -> &[u8] {
        match self {
            Data::Str(s) => s,
            _ => panic!("token data is not a string"),
        }
    }
}

/// `UdevRuleToken`.
#[derive(Debug, Clone)]
pub(super) struct Token {
    pub ty: u8,
    pub op: Op,
    pub match_type: u8,
    pub attr_subst_type: SubstType,
    /// The value; `None` for the options without one.
    pub value: Option<Vec<u8>>,
    /// The alternatives (`"a|b"`) of the match types that have them
    /// (`type_has_nulstr_value()`): C's nulstr.
    pub alts: Vec<Vec<u8>>,
    pub data: Data,
    /// The token as written, for logging.
    pub token_str: Vec<u8>,
}

impl Token {
    /// `token_is_for_parents()`.
    pub fn is_for_parents(&self) -> bool {
        (tk::M_PARENTS_KERNEL..=tk::M_PARENTS_TAG).contains(&self.ty)
    }
    /// The value as C's `token->value` reads as a string: the first
    /// alternative for nulstr values.
    pub fn value_str(&self) -> &[u8] {
        if type_has_nulstr_value(self.ty) {
            self.alts.first().map(|v| &v[..]).unwrap_or_default()
        } else {
            self.value.as_deref().unwrap_or_default()
        }
    }
}

/// `UdevRuleLine`.
#[derive(Debug)]
pub(super) struct Line {
    pub line_number: u32,
    pub ty: u32,
    pub label: Option<Vec<u8>>,
    pub goto_label: Option<Vec<u8>>,
    /// The index of the `GOTO=` target in the file's lines.
    pub goto_line: Option<usize>,
    pub tokens: Vec<Token>,
}

/// `UdevRuleFile`.
#[derive(Debug)]
pub struct RuleFile {
    pub filename: Vec<u8>,
    /// Used by "udevadm verify": a bit per log level seen while parsing.
    pub issues: Cell<u32>,
    pub(super) lines: Vec<Line>,
}

/// `UdevRules`.
#[derive(Debug)]
pub struct Rules {
    pub resolve_name_timing: ResolveNameTiming,
    known_users: RefCell<HashMap<Vec<u8>, u32>>,
    known_groups: RefCell<HashMap<Vec<u8>, u32>>,
    /// `stats_by_path`, for `udev_rules_should_reload()`.
    pub stats_by_path: Vec<(Vec<u8>, shared::sys::Stat)>,
    pub files: Vec<RuleFile>,
}

/// `type_has_nulstr_value()`.
fn type_has_nulstr_value(ty: u8) -> bool {
    ty < tk::M_TEST || ty == tk::M_RESULT
}

/// `log_udev_rule_file_full(device, file, line_nr, level, error, ...)`.
pub(super) fn log_rule_file(
    dev: Option<&Device>,
    file: Option<&RuleFile>,
    line_nr: u32,
    level: i32,
    error: i32,
    msg: Vec<u8>,
) -> i32 {
    if dev.is_none()
        && let Some(f) = file
    {
        f.issues.set(f.issues.get() | (1u32 << level));
    }
    let name: &[u8] = file.map(|f| &f.filename[..]).unwrap_or(b"n/a");
    log_device_full(dev, level, error, bcat!(name, ":", line_nr.to_string(), " ", msg))
}

/// The rule line being parsed, for `log_line_*()`.
struct LineCtx<'a> {
    file: &'a RuleFile,
    line_number: u32,
}

impl LineCtx<'_> {
    fn log(&self, level: i32, error: i32, msg: Vec<u8>) -> i32 {
        log_rule_file(None, Some(self.file), self.line_number, level, error, msg)
    }
    fn error(&self, error: i32, msg: Vec<u8>) -> i32 {
        self.log(LOG_ERR, error, msg)
    }
    fn warning(&self, msg: Vec<u8>) {
        self.log(LOG_WARNING, 0, msg);
    }
    fn notice(&self, msg: Vec<u8>) {
        self.log(LOG_NOTICE, 0, msg);
    }
    fn debug(&self, msg: Vec<u8>) {
        self.log(LOG_DEBUG, 0, msg);
    }
    /// `_log_line_invalid_token(line, key, type)`.
    fn invalid(&self, key: &[u8], what: &str) -> i32 {
        self.error(synthetic(libc::EINVAL), bcat!("Invalid ", what, " for ", key, "."))
    }
    fn invalid_op(&self, key: &[u8]) -> i32 {
        self.invalid(key, "operator")
    }
    fn invalid_attr(&self, key: &[u8]) -> i32 {
        self.invalid(key, "attribute")
    }
    fn invalid_prefix(&self, key: &[u8]) -> i32 {
        self.invalid(key, "prefix 'i'")
    }
}

/// A line while it's parsed: what `rule_line_add_token()` fills.
struct NewLine {
    ty: u32,
    label: Option<Vec<u8>>,
    goto_label: Option<Vec<u8>>,
    tokens: Vec<Token>,
}

/// `rule_get_substitution_type()`.
fn rule_get_substitution_type(s: &[u8]) -> SubstType {
    if s.first() == Some(&b'[') {
        return SubstType::Subsys;
    }
    if s.contains(&b'%') || s.contains(&b'$') {
        return SubstType::Format;
    }
    SubstType::Plain
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `rule_line_add_token()`.
fn rule_line_add_token(
    nl: &mut NewLine,
    ty: u8,
    mut op: Op,
    value: Option<Vec<u8>>,
    data: Data,
    is_case_insensitive: bool,
    token_str: &[u8],
) {
    let mut match_type = MATCH_TYPE_INVALID;
    let mut subst_type = SubstType::Invalid;
    let mut alts = Vec::new();
    if ty < tk::M_MAX {
        let v = value.as_deref().expect("matches have a value");
        if ty == tk::M_SUBSYSTEM && matches!(v, b"subsystem" | b"bus" | b"class") {
            match_type = MATCH_TYPE_SUBSYSTEM;
        } else if v.is_empty() {
            match_type = MATCH_TYPE_EMPTY;
        } else if v == b"?*" {
            // Convert KEY=="?*" -> KEY!=""
            match_type = MATCH_TYPE_EMPTY;
            op = if op == Op::Match { Op::Nomatch } else { Op::Match };
        } else if string_is_glob(v) {
            match_type = MATCH_TYPE_GLOB;
        } else {
            match_type = MATCH_TYPE_PLAIN;
        }
        if type_has_nulstr_value(ty) {
            // Convert the value to a nulstr of alternatives.
            let mut bar = true;
            let mut empty = false;
            let mut cur: Vec<u8> = Vec::new();
            for &c in v {
                if c != b'|' {
                    cur.push(c);
                    bar = false;
                } else {
                    if bar {
                        empty = true;
                    } else {
                        alts.push(std::mem::take(&mut cur));
                    }
                    bar = true;
                }
            }
            if !cur.is_empty() {
                alts.push(cur);
            }
            if bar {
                empty = true;
            }
            if empty {
                if match_type == MATCH_TYPE_GLOB {
                    match_type = MATCH_TYPE_GLOB_WITH_EMPTY;
                }
                if match_type == MATCH_TYPE_PLAIN {
                    match_type = MATCH_TYPE_PLAIN_WITH_EMPTY;
                }
            }
        }
    }
    if ty == tk::M_ATTR || ty == tk::M_PARENTS_ATTR {
        let v = value.as_deref().expect("matches have a value");
        if let Some(&last) = v.last()
            && !isspace(last)
        {
            match_type |= MATCH_REMOVE_TRAILING_WHITESPACE;
        }
        subst_type = rule_get_substitution_type(data.str());
    }
    if is_case_insensitive {
        match_type |= MATCH_CASE_INSENSITIVE;
    } else {
        match_type &= !MATCH_CASE_INSENSITIVE;
    }
    let token = Token {
        ty,
        op,
        match_type,
        attr_subst_type: subst_type,
        value: if type_has_nulstr_value(ty) { None } else { value },
        alts,
        data,
        token_str: token_str.to_vec(),
    };
    nl.tokens.push(token);
    if ty == tk::A_NAME {
        nl.ty |= LINE_HAS_NAME;
    } else if matches!(
        ty,
        tk::A_DEVLINK | tk::A_OWNER | tk::A_GROUP | tk::A_MODE | tk::A_OWNER_ID | tk::A_GROUP_ID | tk::A_MODE_ID
    ) {
        nl.ty |= LINE_HAS_DEVLINK;
    } else if ty == tk::A_OPTIONS_STATIC_NODE {
        nl.ty |= LINE_HAS_STATIC_NODE;
    } else if ty >= tk::M_MAX
        || matches!(
            ty,
            tk::M_PROGRAM
                | tk::M_IMPORT_FILE
                | tk::M_IMPORT_PROGRAM
                | tk::M_IMPORT_BUILTIN
                | tk::M_IMPORT_DB
                | tk::M_IMPORT_CMDLINE
                | tk::M_IMPORT_PARENT
        )
    {
        nl.ty |= LINE_UPDATE_SOMETHING;
    }
}

/// `log_line_invalid_value()`.
fn log_invalid_value(lc: &LineCtx, key: &[u8], value: &[u8], offset: usize, hint: &str) {
    lc.error(
        synthetic(libc::EINVAL),
        bcat!("Invalid value \"", value, "\" for ", key, " (char ", offset.to_string(), ": ", hint, "), ignoring."),
    );
}

/// `check_value_format_and_warn()`.
fn check_value_format_and_warn(lc: &LineCtx, key: &[u8], value: &[u8], nonempty: bool) {
    if nonempty && value.is_empty() {
        log_invalid_value(lc, key, value, 0, "empty value");
    } else if let Err((offset, hint)) = udev_check_format(value) {
        log_invalid_value(lc, key, value, offset + 1, hint);
    }
}

/// `check_attr_format_and_warn()`.
fn check_attr_format_and_warn(lc: &LineCtx, key: &[u8], attr: Option<&[u8]>) -> Result<(), i32> {
    let a = attr.unwrap_or_default();
    if a.is_empty() {
        return Err(lc.invalid_attr(key));
    }
    if let Err((offset, hint)) = udev_check_format(a) {
        lc.error(
            synthetic(libc::EINVAL),
            bcat!(
                "Invalid attribute \"",
                a,
                "\" for ",
                key,
                " (char ",
                (offset + 1).to_string(),
                ": ",
                hint,
                "), ignoring."
            ),
        );
    }
    Ok(())
}

/// `device_property_can_set()`.
fn device_property_can_set(p: &[u8]) -> bool {
    const NO: &[&[u8]] = &[
        b"ACTION",
        b"SEQNUM",
        b"SYNTH_UUID",
        b"DEVPATH",
        b"DEVPATH_OLD",
        b"SUBSYSTEM",
        b"DEVTYPE",
        b"DRIVER",
        b"MODALIAS",
        b"DEVNAME",
        b"DEVMODE",
        b"DEVUID",
        b"DEVGID",
        b"MAJOR",
        b"MINOR",
        b"DISKSEQ",
        b"PARTN",
        b"IFINDEX",
        b"INTERFACE",
        b"INTERFACE_OLD",
        b"DEVLINKS",
        b"TAGS",
        b"CURRENT_TAGS",
        b"USEC_INITIALIZED",
        b"UDEV_DATABASE_VERSION",
    ];
    !NO.contains(&p) && !p.starts_with(b"SYNTH_ARG_")
}

/// `SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR`.
pub(super) const MESSAGE_SYSTEM_ACCOUNT_REQUIRED: &str = "MESSAGE_ID=3405205d368e49feb5ab3925fee13874";

impl Rules {
    /// `udev_rules_new(resolve_name_timing)`.
    pub fn new(resolve_name_timing: ResolveNameTiming) -> Rules {
        Rules {
            resolve_name_timing,
            known_users: RefCell::new(HashMap::new()),
            known_groups: RefCell::new(HashMap::new()),
            stats_by_path: Vec::new(),
            files: Vec::new(),
        }
    }

    /// `rule_resolve_user()` / `rule_resolve_group()`.
    fn rule_resolve_id(&self, lc: &LineCtx, name: &[u8], group: bool) -> Result<u32, i32> {
        let cache = if group { &self.known_groups } else { &self.known_users };
        if let Some(&id) = cache.borrow().get(name) {
            return Ok(id);
        }
        let what = if group { "group" } else { "user" };
        let r =
            if group { shared::userdb::groupdb_gid_by_name(name) } else { shared::userdb::userdb_uid_by_name(name) };
        let id = match r {
            Ok(id) => id,
            Err(r) => {
                return Err(lc.error(
                    r,
                    bcat!(
                        "Failed to resolve ",
                        what,
                        " '",
                        name,
                        "', ignoring: ",
                        shared::user::strerror_account(r, what)
                    ),
                ));
            }
        };
        if !shared::userdb::id_is_system(id) {
            let (w, ws) = if group { ("Group", "group") } else { ("User", "user") };
            shared::log::log_struct_full(
                LOG_WARNING,
                0,
                shared::log::Loc { file: file!(), line: line!(), func: "" },
                &[],
                &bcat!(
                    lc.file.filename,
                    ":",
                    lc.line_number.to_string(),
                    " ",
                    w,
                    " ",
                    name,
                    " configured to own a device node is not a system ",
                    ws,
                    ". Support for device node ownership by non-system accounts is deprecated and will be removed in the future."
                ),
                &[MESSAGE_SYSTEM_ACCOUNT_REQUIRED.as_bytes().to_vec()],
            );
        }
        cache.borrow_mut().insert(name.to_vec(), id);
        Ok(id)
    }

    /// `parse_token()`: Ok(()) whether a token was added or the key
    /// ignored; Err(r) drops the line.
    fn parse_token(
        &self,
        lc: &LineCtx,
        nl: &mut NewLine,
        key: &[u8],
        attr: Option<&[u8]>,
        mut op: Op,
        value: Vec<u8>,
        is_case_insensitive: bool,
        token_str: &[u8],
    ) -> Result<(), i32> {
        let resolve_name_timing = self.resolve_name_timing;
        let is_match = matches!(op, Op::Match | Op::Nomatch);
        if !is_match && is_case_insensitive {
            return Err(lc.error(
                synthetic(libc::EINVAL),
                bcat!(
                    "Invalid prefix 'i' for '",
                    key,
                    "'. The 'i' prefix can be specified only for '==' or '!=' operator."
                ),
            ));
        }
        let attr_s = || Data::Str(attr.unwrap_or_default().to_vec());
        let ci = is_case_insensitive;
        macro_rules! add {
            ($ty:expr, $op:expr, $value:expr, $data:expr, $ci:expr) => {
                rule_line_add_token(nl, $ty, $op, $value, $data, $ci, token_str)
            };
        }
        // The keys that take no attribute and only match.
        let simple_match = |nl: &mut NewLine, ty: u8, op: Op| -> Result<(), i32> {
            if attr.is_some() {
                return Err(lc.invalid_attr(key));
            }
            if !is_match {
                return Err(lc.invalid_op(key));
            }
            rule_line_add_token(nl, ty, op, Some(value.clone()), Data::None, ci, token_str);
            Ok(())
        };
        match key {
            b"ACTION" => simple_match(nl, tk::M_ACTION, op)?,
            b"DEVPATH" => simple_match(nl, tk::M_DEVPATH, op)?,
            b"KERNEL" => simple_match(nl, tk::M_KERNEL, op)?,
            b"SYMLINK" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if !is_match {
                    check_value_format_and_warn(lc, key, &value, false);
                    add!(tk::A_DEVLINK, op, Some(value), Data::None, false);
                } else {
                    add!(tk::M_DEVLINK, op, Some(value), Data::None, ci);
                }
            }
            b"NAME" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::Add {
                    lc.warning(bcat!(key, " key takes '==', '!=', '=', or ':=' operator, assuming '='."));
                    op = Op::Assign;
                }
                if !is_match {
                    if value == b"%k" {
                        return Err(lc.error(
                            synthetic(libc::EINVAL),
                            b"Ignoring NAME=\"%k\", as it will take no effect.".to_vec(),
                        ));
                    }
                    if value.is_empty() {
                        return Err(lc.error(
                            synthetic(libc::EINVAL),
                            b"Ignoring NAME=\"\", as udev will not delete any network interfaces.".to_vec(),
                        ));
                    }
                    check_value_format_and_warn(lc, key, &value, false);
                    add!(tk::A_NAME, op, Some(value), Data::None, false);
                } else {
                    add!(tk::M_NAME, op, Some(value), Data::None, ci);
                }
            }
            b"ENV" => {
                if attr.is_none_or(|a| a.is_empty()) {
                    return Err(lc.invalid_attr(key));
                }
                if op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::AssignFinal {
                    lc.warning(bcat!(key, " key takes '==', '!=', '=', or '+=' operator, assuming '='."));
                    op = Op::Assign;
                }
                if !is_match {
                    let a = attr.unwrap_or_default();
                    if !device_property_can_set(a) {
                        return Err(
                            lc.error(synthetic(libc::EINVAL), bcat!("Invalid ENV attribute. '", a, "' cannot be set."))
                        );
                    }
                    check_value_format_and_warn(lc, key, &value, false);
                    add!(tk::A_ENV, op, Some(value), attr_s(), false);
                } else {
                    add!(tk::M_ENV, op, Some(value), attr_s(), ci);
                }
            }
            b"CONST" => {
                if !matches!(attr, Some(b"arch") | Some(b"virt") | Some(b"cvm")) {
                    return Err(lc.invalid_attr(key));
                }
                if !is_match {
                    return Err(lc.invalid_op(key));
                }
                add!(tk::M_CONST, op, Some(value), attr_s(), ci);
            }
            b"TAG" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if op == Op::AssignFinal {
                    lc.warning(bcat!(key, " key takes '==', '!=', '=', or '+=' operator, assuming '='."));
                    op = Op::Assign;
                }
                if !is_match {
                    check_value_format_and_warn(lc, key, &value, true);
                    add!(tk::A_TAG, op, Some(value), Data::None, false);
                } else {
                    add!(tk::M_TAG, op, Some(value), Data::None, ci);
                }
            }
            b"SUBSYSTEM" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if !is_match {
                    return Err(lc.invalid_op(key));
                }
                if value == b"bus" || value == b"class" {
                    lc.warning(bcat!("\"", value, "\" must be specified as \"subsystem\"."));
                }
                add!(tk::M_SUBSYSTEM, op, Some(value), Data::None, ci);
            }
            b"DRIVER" => simple_match(nl, tk::M_DRIVER, op)?,
            b"ATTR" | b"SYSCTL" => {
                check_attr_format_and_warn(lc, key, attr)?;
                if op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if matches!(op, Op::Add | Op::AssignFinal) {
                    lc.warning(bcat!(key, " key takes '==', '!=', or '=' operator, assuming '='."));
                    op = Op::Assign;
                }
                let (a, m) = if key == b"ATTR" { (tk::A_ATTR, tk::M_ATTR) } else { (tk::A_SYSCTL, tk::M_SYSCTL) };
                if !is_match {
                    check_value_format_and_warn(lc, key, &value, false);
                    add!(a, op, Some(value), attr_s(), false);
                } else {
                    add!(m, op, Some(value), attr_s(), ci);
                }
            }
            b"KERNELS" => simple_match(nl, tk::M_PARENTS_KERNEL, op)?,
            b"SUBSYSTEMS" => simple_match(nl, tk::M_PARENTS_SUBSYSTEM, op)?,
            b"DRIVERS" => simple_match(nl, tk::M_PARENTS_DRIVER, op)?,
            b"ATTRS" => {
                check_attr_format_and_warn(lc, key, attr)?;
                if !is_match {
                    return Err(lc.invalid_op(key));
                }
                let a = attr.unwrap_or_default();
                if a.starts_with(b"device/") {
                    lc.warning(b"'device' link may not be available in future kernels.".to_vec());
                }
                if a.windows(3).any(|w| w == b"../") {
                    lc.warning(b"Direct reference to parent sysfs directory, may break in future kernels.".to_vec());
                }
                add!(tk::M_PARENTS_ATTR, op, Some(value), attr_s(), ci);
            }
            b"TAGS" => simple_match(nl, tk::M_PARENTS_TAG, op)?,
            b"TEST" => {
                let mut mode = MODE_INVALID;
                if let Some(a) = attr.filter(|a| !a.is_empty()) {
                    match shared::parse::parse_mode(a) {
                        Ok(m) => mode = m,
                        Err(r) => {
                            return Err(lc.error(r, bcat!("Failed to parse mode '", a, "': ", strerror(r))));
                        }
                    }
                }
                check_value_format_and_warn(lc, key, &value, true);
                if !is_match {
                    return Err(lc.invalid_op(key));
                }
                if is_case_insensitive {
                    return Err(lc.invalid_prefix(key));
                }
                add!(tk::M_TEST, op, Some(value), Data::Mode(mode), ci);
            }
            b"PROGRAM" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                check_value_format_and_warn(lc, key, &value, true);
                if op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if !is_match {
                    op = Op::Match;
                }
                if is_case_insensitive {
                    return Err(lc.invalid_prefix(key));
                }
                add!(tk::M_PROGRAM, op, Some(value), Data::None, false);
            }
            b"IMPORT" => {
                if attr.is_none_or(|a| a.is_empty()) {
                    return Err(lc.invalid_attr(key));
                }
                check_value_format_and_warn(lc, key, &value, true);
                if op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if !is_match {
                    op = Op::Match;
                }
                if is_case_insensitive {
                    return Err(lc.invalid_prefix(key));
                }
                match attr.unwrap_or_default() {
                    b"file" => add!(tk::M_IMPORT_FILE, op, Some(value), Data::None, false),
                    b"program" => match udev_builtin_lookup(&value) {
                        Some(cmd) => {
                            lc.debug(bcat!("Found builtin command '", value, "' for ", key, ", replacing attribute."));
                            add!(tk::M_IMPORT_BUILTIN, op, Some(value), Data::Builtin(cmd), false);
                        }
                        None => add!(tk::M_IMPORT_PROGRAM, op, Some(value), Data::None, false),
                    },
                    b"builtin" => match udev_builtin_lookup(&value) {
                        Some(cmd) => add!(tk::M_IMPORT_BUILTIN, op, Some(value), Data::Builtin(cmd), false),
                        None => {
                            return Err(lc.error(synthetic(libc::EINVAL), bcat!("Unknown builtin command: ", value)));
                        }
                    },
                    b"db" => add!(tk::M_IMPORT_DB, op, Some(value), Data::None, false),
                    b"cmdline" => add!(tk::M_IMPORT_CMDLINE, op, Some(value), Data::None, false),
                    b"parent" => add!(tk::M_IMPORT_PARENT, op, Some(value), Data::None, false),
                    _ => return Err(lc.invalid_attr(key)),
                }
            }
            b"RESULT" => simple_match(nl, tk::M_RESULT, op)?,
            b"OPTIONS" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if is_match || op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::Add {
                    op = Op::Assign;
                }
                let v = &value[..];
                if v == b"dump" {
                    add!(tk::A_OPTIONS_DUMP, op, None, Data::JsonFlags(shared::json::SD_JSON_FORMAT_OFF), false);
                } else if v == b"dump-json" {
                    add!(tk::A_OPTIONS_DUMP, op, None, Data::JsonFlags(shared::json::SD_JSON_FORMAT_NEWLINE), false);
                } else if v == b"string_escape=none" {
                    add!(tk::A_OPTIONS_STRING_ESCAPE_NONE, op, None, Data::None, false);
                } else if v == b"string_escape=replace" {
                    add!(tk::A_OPTIONS_STRING_ESCAPE_REPLACE, op, None, Data::None, false);
                } else if v == b"db_persist" {
                    add!(tk::A_OPTIONS_DB_PERSIST, op, None, Data::None, false);
                } else if v == b"watch" {
                    add!(tk::A_OPTIONS_INOTIFY_WATCH, op, None, Data::Int(1), false);
                } else if v == b"nowatch" {
                    add!(tk::A_OPTIONS_INOTIFY_WATCH, op, None, Data::Int(0), false);
                } else if let Some(tmp) = v.strip_prefix(b"static_node=") {
                    add!(tk::A_OPTIONS_STATIC_NODE, op, Some(tmp.to_vec()), Data::None, false);
                } else if let Some(tmp) = v.strip_prefix(b"link_priority=") {
                    match shared::parse::safe_atoi(tmp) {
                        Ok(prio) => add!(tk::A_OPTIONS_DEVLINK_PRIORITY, op, None, Data::Int(prio), false),
                        Err(r) => {
                            return Err(lc.error(r, bcat!("Failed to parse link priority '", tmp, "': ", strerror(r))));
                        }
                    }
                } else if let Some(tmp) = v.strip_prefix(b"log_level=") {
                    let level = if tmp == b"reset" {
                        -1
                    } else {
                        match shared::log::log_level_from_string(tmp) {
                            Ok(l) => l,
                            Err(r) => {
                                return Err(lc.error(r, bcat!("Failed to parse log level '", tmp, "': ", strerror(r))));
                            }
                        }
                    };
                    add!(tk::A_OPTIONS_LOG_LEVEL, op, None, Data::Int(level), false);
                } else {
                    lc.warning(bcat!("Invalid value for OPTIONS key, ignoring: '", v, "'"));
                    return Ok(());
                }
            }
            b"OWNER" | b"GROUP" => {
                let group = key == b"GROUP";
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if is_match || op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::Add {
                    lc.warning(bcat!(key, " key takes '=' or ':=' operator, assuming '='."));
                    op = Op::Assign;
                }
                if in_charset(&value, DIGITS)
                    || (resolve_name_timing == ResolveNameTiming::Early
                        && rule_get_substitution_type(&value) == SubstType::Plain)
                {
                    let id = self.rule_resolve_id(lc, &value, group)?;
                    add!(if group { tk::A_GROUP_ID } else { tk::A_OWNER_ID }, op, None, Data::Id(id), false);
                } else if resolve_name_timing != ResolveNameTiming::Never {
                    check_value_format_and_warn(lc, key, &value, true);
                    add!(if group { tk::A_GROUP } else { tk::A_OWNER }, op, Some(value), Data::None, false);
                } else {
                    if group {
                        lc.debug(bcat!("Resolving group name is disabled, ignoring GROUP=\"", value, "\"."));
                    } else {
                        lc.debug(bcat!("User name resolution is disabled, ignoring ", key, "=\"", value, "\"."));
                    }
                    return Ok(());
                }
            }
            b"MODE" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if is_match || op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::Add {
                    lc.warning(bcat!(key, " key takes '=' or ':=' operator, assuming '='."));
                    op = Op::Assign;
                }
                match shared::parse::parse_mode(&value) {
                    Ok(mode) => add!(tk::A_MODE_ID, op, None, Data::Mode(mode), false),
                    Err(_) => {
                        check_value_format_and_warn(lc, key, &value, true);
                        add!(tk::A_MODE, op, Some(value), Data::None, false);
                    }
                }
            }
            b"SECLABEL" => {
                if attr.is_none_or(|a| a.is_empty()) {
                    return Err(lc.invalid_attr(key));
                }
                check_value_format_and_warn(lc, key, &value, true);
                if is_match || op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                if op == Op::AssignFinal {
                    lc.warning(bcat!(key, " key takes '=' or '+=' operator, assuming '='."));
                    op = Op::Assign;
                }
                add!(tk::A_SECLABEL, op, Some(value), attr_s(), false);
            }
            b"RUN" => {
                if is_match || op == Op::Remove {
                    return Err(lc.invalid_op(key));
                }
                check_value_format_and_warn(lc, key, &value, true);
                match attr {
                    None | Some(b"program") => add!(tk::A_RUN_PROGRAM, op, Some(value), Data::None, false),
                    Some(b"builtin") => match udev_builtin_lookup(&value) {
                        Some(cmd) => add!(tk::A_RUN_BUILTIN, op, Some(value), Data::Builtin(cmd), false),
                        None => {
                            return Err(lc.error(
                                synthetic(libc::EINVAL),
                                bcat!("Unknown builtin command '", value, "', ignoring."),
                            ));
                        }
                    },
                    _ => return Err(lc.invalid_attr(key)),
                }
            }
            b"GOTO" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if op != Op::Assign {
                    return Err(lc.invalid_op(key));
                }
                if nl.ty & LINE_HAS_GOTO != 0 {
                    lc.warning(bcat!("Contains multiple GOTO keys, ignoring GOTO=\"", value, "\"."));
                    return Ok(());
                }
                nl.goto_label = Some(value);
                nl.ty |= LINE_HAS_GOTO;
            }
            b"LABEL" => {
                if attr.is_some() {
                    return Err(lc.invalid_attr(key));
                }
                if op != Op::Assign {
                    return Err(lc.invalid_op(key));
                }
                if nl.ty & LINE_HAS_LABEL != 0 {
                    lc.warning(bcat!(
                        "Contains multiple LABEL keys, ignoring LABEL=\"",
                        nl.label.as_deref().unwrap_or_default(),
                        "\"."
                    ));
                }
                nl.label = Some(value);
                nl.ty |= LINE_HAS_LABEL;
            }
            _ => return Err(lc.error(synthetic(libc::EINVAL), bcat!("Invalid key '", key, "'."))),
        }
        Ok(())
    }
}

/// `parse_operator()`.
fn parse_operator(op: &[u8]) -> Option<Op> {
    if op.starts_with(b"==") {
        Some(Op::Match)
    } else if op.starts_with(b"!=") {
        Some(Op::Nomatch)
    } else if op.starts_with(b"+=") {
        Some(Op::Add)
    } else if op.starts_with(b"-=") {
        Some(Op::Remove)
    } else if op.starts_with(b"=") {
        Some(Op::Assign)
    } else if op.starts_with(b":=") {
        Some(Op::AssignFinal)
    } else {
        None
    }
}

/// `check_token_delimiters(rule_line, line + pos)`.
fn check_token_delimiters(lc: &LineCtx, line: &[u8], pos: usize) {
    let mut n_comma = 0;
    let mut ws_before_comma = false;
    let mut ws_after_comma = false;
    let mut p = pos;
    while p < line.len() {
        let c = line[p];
        if c == b',' {
            n_comma += 1;
        } else if WHITESPACE.contains(&c) {
            if n_comma > 0 {
                ws_after_comma = true;
            } else {
                ws_before_comma = true;
            }
        } else {
            break;
        }
        p += 1;
    }
    if pos == 0 {
        if n_comma > 0 {
            lc.notice(b"style: stray leading comma.".to_vec());
        }
    } else if p >= line.len() {
        if n_comma > 0 {
            lc.notice(b"style: stray trailing comma.".to_vec());
        }
    } else {
        if n_comma == 0 {
            lc.notice(b"style: a comma between tokens is expected.".to_vec());
        } else if n_comma > 1 {
            lc.notice(b"style: more than one comma between tokens.".to_vec());
        }
        if n_comma > 0 {
            if ws_before_comma {
                lc.notice(b"style: stray whitespace before comma.".to_vec());
            }
            if !ws_after_comma {
                lc.notice(b"style: whitespace after comma is expected.".to_vec());
            }
        } else if !ws_before_comma && !ws_after_comma {
            lc.notice(b"style: whitespace between tokens is expected.".to_vec());
        }
    }
}

/// `udev_rule_parse_value(str)`: (value, end position, case
/// insensitive), positions relative to `s`.
pub fn udev_rule_parse_value(s: &[u8]) -> Result<(Vec<u8>, usize, bool), i32> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut is_escaped = false;
    let mut is_case_insensitive = false;
    let mut k = 0;
    while at(k) != b'"' && k < 2 {
        let c = at(k);
        if c == b'e' && !is_escaped {
            is_escaped = true;
        } else if c == b'i' && !is_case_insensitive {
            is_case_insensitive = true;
        } else {
            return Err(-libc::EINVAL);
        }
        k += 1;
    }
    let start = is_escaped as usize + is_case_insensitive as usize;
    if at(start) != b'"' {
        return Err(-libc::EINVAL);
    }
    let mut value = Vec::new();
    let mut i = start + 1;
    if !is_escaped {
        // unescape double quotation '\"'->'"'
        while at(i) != b'"' {
            if at(i) == 0 {
                return Err(-libc::EINVAL);
            }
            if at(i) == b'\\' && at(i + 1) == b'"' {
                i += 1;
            }
            value.push(at(i));
            i += 1;
        }
    } else {
        while at(i) != b'"' {
            if at(i) == b'\\' {
                i += 1;
            }
            if at(i) == 0 {
                return Err(-libc::EINVAL);
            }
            i += 1;
        }
        value = shared::extract::cunescape(&s[start + 1..i])?;
        // cunescape() stops at an escaped NUL, as C's string does.
        if let Some(n) = value.iter().position(|&b| b == 0) {
            value.truncate(n);
        }
    }
    Ok((value, i + 1, is_case_insensitive))
}

/// What `parse_line()` found.
struct KeyValue {
    key: Vec<u8>,
    attr: Option<Vec<u8>>,
    op: Op,
    value: Vec<u8>,
    is_case_insensitive: bool,
    key_begin: usize,
    end: usize,
}

/// `parse_line(&line, ...)` at `pos`: Ok(None) at the end of the line.
fn parse_line(line: &[u8], pos: usize) -> Result<Option<KeyValue>, i32> {
    let at = |i: usize| line.get(i).copied().unwrap_or(0);
    let mut key_begin = pos;
    while key_begin < line.len() && (WHITESPACE.contains(&line[key_begin]) || line[key_begin] == b',') {
        key_begin += 1;
    }
    if key_begin >= line.len() {
        return Ok(None);
    }
    let mut key_end = key_begin;
    loop {
        let c = at(key_end);
        if c == 0 {
            return Err(-libc::EINVAL);
        }
        if b" \t\n\r={".contains(&c) {
            break;
        }
        if b"+-!:".contains(&c) && at(key_end + 1) == b'=' {
            break;
        }
        key_end += 1;
    }
    let (attr, mut tmp) = if at(key_end) == b'{' {
        let a = key_end + 1;
        let Some(close) = line[a..].iter().position(|&b| b == b'}') else {
            return Err(-libc::EINVAL);
        };
        (Some(line[a..a + close].to_vec()), a + close + 1)
    } else {
        (None, key_end)
    };
    while tmp < line.len() && WHITESPACE.contains(&line[tmp]) {
        tmp += 1;
    }
    let op = parse_operator(&line[tmp.min(line.len())..]).ok_or(-libc::EINVAL)?;
    tmp += if op == Op::Assign { 1 } else { 2 };
    while tmp < line.len() && WHITESPACE.contains(&line[tmp]) {
        tmp += 1;
    }
    let (value, end, ci) = udev_rule_parse_value(&line[tmp.min(line.len())..])?;
    Ok(Some(KeyValue {
        key: line[key_begin..key_end].to_vec(),
        attr,
        op,
        value,
        is_case_insensitive: ci,
        key_begin,
        end: tmp + end,
    }))
}

/// `check_tokens_order()`.
fn check_tokens_order(lc: &LineCtx, tokens: &[Token]) {
    let mut has_result = false;
    for t in tokens {
        if t.ty == tk::M_RESULT {
            has_result = true;
        } else if has_result && t.ty == tk::M_PROGRAM {
            lc.warning(b"Reordering RESULT check after PROGRAM assignment.".to_vec());
            break;
        }
    }
}
