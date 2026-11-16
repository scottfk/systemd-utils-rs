// SPDX-License-Identifier: GPL-2.0-or-later
//! Reading `.rules` files: `rule_add_line()`, `rule_resolve_goto()`, the
//! `udevadm verify` checks, `udev_rules_parse_file()` and
//! `udev_rules_load()`.

use super::*;

/// `strcspn(s, GLOB_CHARS)`.
fn strcspn_glob(s: &[u8]) -> usize {
    s.iter().position(|c| GLOB_CHARS.contains(c)).unwrap_or(s.len())
}

/// `nulstr_eq()`.
fn nulstr_eq(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.iter().all(|i| b.contains(i)) && b.iter().all(|i| a.contains(i))
}

/// `token_data_is_string()`.
fn token_data_is_string(ty: u8) -> bool {
    matches!(
        ty,
        tk::M_ENV
            | tk::M_CONST
            | tk::M_ATTR
            | tk::M_SYSCTL
            | tk::M_PARENTS_ATTR
            | tk::A_SECLABEL
            | tk::A_ENV
            | tk::A_ATTR
            | tk::A_SYSCTL
    )
}

/// `token_type_and_data_eq()`.
fn token_type_and_data_eq(a: &Token, b: &Token) -> bool {
    // Strings compare by value, the rest as C compares the data pointers;
    // with Data both are ==.
    let _ = token_data_is_string(a.ty);
    a.ty == b.ty && a.data == b.data
}

/// `token_type_and_value_eq()`.
fn token_type_and_value_eq(a: &Token, b: &Token) -> bool {
    if a.ty != b.ty || a.match_type != b.match_type {
        return false;
    }
    if a.match_type == MATCH_TYPE_EMPTY || a.match_type == MATCH_TYPE_SUBSYSTEM {
        return true;
    }
    if type_has_nulstr_value(a.ty) { nulstr_eq(&a.alts, &b.alts) } else { a.value == b.value }
}

/// `conflicting_op()`.
fn conflicting_op(a: Op, b: Op) -> bool {
    (a == Op::Match && b == Op::Nomatch) || (a == Op::Nomatch && b == Op::Match)
}

/// `tokens_eq()`.
fn tokens_eq(a: &Token, b: &Token) -> bool {
    a.attr_subst_type == b.attr_subst_type && token_type_and_value_eq(a, b) && token_type_and_data_eq(a, b)
}

/// `nulstr_tokens_conflict()`.
fn nulstr_tokens_conflict(a: &Token, b: &Token) -> bool {
    if !(a.ty == b.ty
        && type_has_nulstr_value(a.ty)
        && a.op == b.op
        && a.op == Op::Match
        && a.match_type == b.match_type
        && a.attr_subst_type == b.attr_subst_type
        && token_type_and_data_eq(a, b))
    {
        return false;
    }
    if a.match_type == MATCH_TYPE_PLAIN {
        return !a.alts.iter().any(|i| b.alts.contains(i));
    }
    if a.match_type == MATCH_TYPE_GLOB {
        for i in &a.alts {
            let i_n = strcspn_glob(i);
            if i_n == 0 {
                return false;
            }
            for j in &b.alts {
                let j_n = strcspn_glob(j);
                let n = i_n.min(j_n);
                if j_n == 0 || i[..n] == j[..n] {
                    return false;
                }
            }
        }
        return true;
    }
    false
}

/// `udev_check_rule_line()`: unused labels, conflicts and duplicates.
fn udev_check_rule_line(lc: &LineCtx, line: &Line) {
    if line.ty & LINE_HAS_LABEL != 0 && line.ty & LINE_IS_REFERENCED == 0 {
        lc.notice(bcat!("style: LABEL=\"", line.label.as_deref().unwrap_or_default(), "\" is unused."));
    }
    let mut conflicts = false;
    let mut duplicates = false;
    for (n, token) in line.tokens.iter().enumerate() {
        for i in &line.tokens[n + 1..] {
            let mut new_conflicts = false;
            let mut new_duplicates = false;
            if tokens_eq(token, i) {
                if !duplicates && token.op == i.op {
                    new_duplicates = true;
                }
                if !conflicts && conflicting_op(token.op, i.op) {
                    new_conflicts = true;
                }
            } else if !conflicts && nulstr_tokens_conflict(token, i) {
                new_conflicts = true;
            } else {
                continue;
            }
            if new_duplicates {
                duplicates = true;
                lc.warning(b"duplicate expressions.".to_vec());
            }
            if new_conflicts {
                conflicts = true;
                lc.log(LOG_ERR, 0, b"conflicting match expressions, the line has no effect.".to_vec());
            }
            if conflicts && duplicates {
                return;
            }
        }
    }
}

impl Rules {
    /// `rule_add_line()`.
    fn rule_add_line(&self, file: &RuleFile, lines: &mut Vec<Line>, line: &[u8], line_nr: u32, extra_checks: bool) {
        if line.is_empty() {
            return;
        }
        let lc = LineCtx { file, line_number: line_nr };
        let mut nl = NewLine { ty: 0, label: None, goto_label: None, tokens: Vec::new() };
        let mut p = 0;
        while p < line.len() {
            if extra_checks {
                check_token_delimiters(&lc, line, p);
            }
            let kv = match parse_line(line, p) {
                Err(r) => {
                    lc.error(r, b"Invalid key/value pair, ignoring.".to_vec());
                    return;
                }
                Ok(None) => break,
                Ok(Some(kv)) => kv,
            };
            let token_str = &line[kv.key_begin..kv.end];
            if self
                .parse_token(
                    &lc,
                    &mut nl,
                    &kv.key,
                    kv.attr.as_deref(),
                    kv.op,
                    kv.value,
                    kv.is_case_insensitive,
                    token_str,
                )
                .is_err()
            {
                return;
            }
            p = kv.end;
        }
        if nl.ty == 0 {
            lc.warning(b"The line has no effect, ignoring.".to_vec());
            return;
        }
        if extra_checks {
            check_tokens_order(&lc, &nl.tokens);
        }
        // sort_tokens(): a stable sort by type.
        nl.tokens.sort_by_key(|t| t.ty);
        lines.push(Line {
            line_number: line_nr,
            ty: nl.ty,
            label: nl.label,
            goto_label: nl.goto_label,
            goto_line: None,
            tokens: nl.tokens,
        });
    }

    /// `udev_rules_parse_file(rules, c, extra_checks, &file)`: the index
    /// of the file in `self.files`.
    pub fn parse_file(&mut self, c: &ConfFile, extra_checks: bool) -> Result<usize, i32> {
        let mut f = match shared::fileio::fopen_re(&shared::fd::proc_fd_path(c.fd.raw())) {
            Ok(f) => f,
            Err(r) => {
                if extra_checks {
                    return Err(r);
                }
                return Err(log_warning_errno!(r, "Failed to open ", c.original_path, ", ignoring: ", strerror(r)));
            }
        };
        if self.stats_by_path.iter().any(|(p, _)| shared::path::path_equal(p, &c.original_path)) {
            let r = -libc::EEXIST;
            return Err(log_warning_errno!(
                r,
                "Failed to save stat for ",
                c.original_path,
                ", ignoring: ",
                strerror(r)
            ));
        }
        self.stats_by_path.push((c.original_path.clone(), c.st));
        shared::conf_parser::stat_warn_permissions(&c.original_path, &c.st);
        log_debug!("Reading rules file: ", c.original_path);
        let file = RuleFile { filename: c.original_path.clone(), issues: Cell::new(0), lines: Vec::new() };
        let mut lines = self.read_rules(&file, &mut f, extra_checks)?;
        rule_resolve_goto(&file, &mut lines);
        if extra_checks {
            for l in &lines {
                udev_check_rule_line(&LineCtx { file: &file, line_number: l.line_number }, l);
            }
        }
        let mut file = file;
        file.lines = lines;
        self.files.push(file);
        Ok(self.files.len() - 1)
    }

    /// The line loop of `udev_rules_parse_file()`.
    fn read_rules(&self, file: &RuleFile, f: &mut CReader, extra_checks: bool) -> Result<Vec<Line>, i32> {
        let mut lines = Vec::new();
        let mut continuation: Option<Vec<u8>> = None;
        let mut line_nr = 0u32;
        let mut current_line_nr = 0u32;
        let mut ignore_line = false;
        loop {
            let buf = match read_line(f, UDEV_LINE_SIZE)? {
                (0, _) => break,
                (_, b) => b,
            };
            current_line_nr += 1;
            if continuation.is_none() {
                line_nr = current_line_nr;
            }
            let physical = skip_leading_chars(&buf, None);
            // Lines beginning with '#' are ignored regardless of line continuation.
            if physical.first() == Some(&b'#') {
                continue;
            }
            let mut use_continuation = false;
            if let Some(c) = continuation.as_mut()
                && !ignore_line
            {
                if c.len() + physical.len() >= UDEV_LINE_SIZE {
                    ignore_line = true;
                }
                c.extend_from_slice(physical);
                use_continuation = !ignore_line;
            }
            let line: Vec<u8> = if use_continuation { continuation.clone().expect("set") } else { physical.to_vec() };
            if line.last() == Some(&b'\\') {
                if ignore_line {
                    continue;
                }
                let stripped = &line[..line.len() - 1];
                match continuation.as_mut() {
                    Some(c) => {
                        // line is the continuation: strip its backslash.
                        c.pop();
                    }
                    None => continuation = Some(stripped.to_vec()),
                }
                continue;
            }
            if ignore_line {
                log_rule_file(None, Some(file), line_nr, LOG_ERR, 0, b"Line is too long, ignored.".to_vec());
            } else if !line.is_empty() {
                self.rule_add_line(file, &mut lines, &line, line_nr, extra_checks);
            }
            continuation = None;
            ignore_line = false;
        }
        if continuation.is_some() {
            log_rule_file(
                None,
                Some(file),
                line_nr,
                LOG_ERR,
                0,
                b"Unexpected EOF after line continuation, line ignored.".to_vec(),
            );
        }
        Ok(lines)
    }
}

/// `rule_resolve_goto()`: link GOTOs to LABEL lines in this file.
fn rule_resolve_goto(file: &RuleFile, lines: &mut Vec<Line>) {
    let mut removed = vec![false; lines.len()];
    for i in 0..lines.len() {
        if lines[i].ty & LINE_HAS_GOTO == 0 {
            continue;
        }
        let target = (i + 1..lines.len()).find(|&j| lines[j].label.is_some() && lines[j].label == lines[i].goto_label);
        if let Some(j) = target {
            lines[i].goto_line = Some(j);
            lines[j].ty |= LINE_IS_REFERENCED;
            continue;
        }
        let lc = LineCtx { file, line_number: lines[i].line_number };
        lc.log(
            LOG_ERR,
            0,
            bcat!("GOTO=\"", lines[i].goto_label.as_deref().unwrap_or_default(), "\" has no matching label, ignoring."),
        );
        lines[i].ty &= !LINE_HAS_GOTO;
        lines[i].goto_label = None;
        if lines[i].ty & !(LINE_HAS_LABEL | LINE_IS_REFERENCED) == 0 {
            lc.warning(b"The line has no effect any more, dropping.".to_vec());
            if lines[i].ty & LINE_HAS_LABEL != 0 {
                lines[i].tokens.clear();
            } else {
                removed[i] = true;
            }
        }
    }
    if removed.iter().any(|&r| r) {
        let mut map = vec![0usize; lines.len()];
        let mut n = 0;
        for (i, r) in removed.iter().enumerate() {
            map[i] = n;
            if !r {
                n += 1;
            }
        }
        let old = std::mem::take(lines);
        for (i, mut l) in old.into_iter().enumerate() {
            if removed[i] {
                continue;
            }
            l.goto_line = l.goto_line.map(|g| map[g]);
            lines.push(l);
        }
    }
}

/// `udev_rules_load(&rules, resolve_name_timing, extra)`.
pub fn udev_rules_load(resolve_name_timing: ResolveNameTiming, extra: &[Vec<u8>]) -> Result<Rules, i32> {
    let mut rules = Rules::new(resolve_name_timing);
    let mut directories: Vec<Vec<u8>> = extra.to_vec();
    directories.extend(conf_paths("udev/rules.d"));
    let files = match conf_files_list_strv_full(
        Some(b".rules"),
        None,
        CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
        &directories,
    ) {
        Ok(f) => f,
        Err(r) => return Err(log_debug_errno!(r, "Failed to enumerate rules files: ", strerror(r))),
    };
    for c in &files {
        if let Err(r) = rules.parse_file(c, false) {
            log_debug_errno!(r, "Failed to read rules file '", c.original_path, "', ignoring: ", strerror(r));
        }
    }
    Ok(rules)
}

impl Rules {
    /// `udev_rule_file_get_issues(file)`.
    pub fn file_issues(&self, index: usize) -> u32 {
        self.files[index].issues.get()
    }
}
