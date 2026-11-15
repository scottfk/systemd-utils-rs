// SPDX-License-Identifier: LGPL-2.1-or-later
//! `format-table.c`: the subset `--help` uses (string, header and
//! wrapped-strv cells), with C's two-pass width allocation and its
//! per-cell format cache, which decides when a cell counts as "soft".

use crate::locale::{Glyph, glyph};
use crate::string::ellipsize;
use crate::terminal::{ansi, colors_enabled, columns, isatty_safe, underline_enabled};
use crate::utf8::{console_width, encoded_to_unichar, skip_len, unichar_iswide};

const DEFAULT_WEIGHT: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Empty,
    String(Vec<u8>),
    Header(Vec<u8>),
    StrvWrapped(Vec<Vec<u8>>),
}

#[derive(Debug, Clone)]
struct TableData {
    cell: Cell,
    minimum_width: usize,
    maximum_width: usize,
    weight: u64,
    align_percent: u32,
    ellipsize_percent: u32,
    formatted: Option<Vec<u8>>,
    formatted_for_width: usize,
}

/// `Table`.
#[derive(Debug)]
pub struct Table {
    n_columns: usize,
    header: bool,
    width: usize,
    cell_height_max: usize,
    data: Vec<TableData>,
}

impl Table {
    /// `table_new(header...)`.
    pub fn new(headers: &[&str]) -> Table {
        let mut t = Table {
            n_columns: headers.len(),
            header: true,
            width: usize::MAX,
            cell_height_max: usize::MAX,
            data: Vec::new(),
        };
        for h in headers {
            t.add(Cell::Header(h.as_bytes().to_vec()));
        }
        t
    }

    /// `table_add_cell()` with the formatting parameters copied from the row above.
    pub fn add(&mut self, cell: Cell) {
        let p =
            if self.data.len() >= self.n_columns { Some(&self.data[self.data.len() - self.n_columns]) } else { None };
        let d = TableData {
            cell,
            minimum_width: p.map(|p| p.minimum_width).unwrap_or(1),
            maximum_width: usize::MAX,
            weight: p.map(|p| p.weight).unwrap_or(DEFAULT_WEIGHT),
            align_percent: p.map(|p| p.align_percent).unwrap_or(0),
            ellipsize_percent: p.map(|p| p.ellipsize_percent).unwrap_or(100),
            formatted: None,
            formatted_for_width: 0,
        };
        self.data.push(d);
    }

    /// `table_set_header()`.
    pub fn set_header(&mut self, b: bool) {
        self.header = b;
    }

    /// `table_isempty()`: only the header row.
    pub fn is_empty(&self) -> bool {
        self.data.len() <= self.n_columns
    }

    fn rows(&self) -> usize {
        self.data.len() / self.n_columns
    }

    /// `table_data_requested_width()` for one column.
    fn column_requested_width(&mut self, column: usize) -> usize {
        let mut width = 0;
        for row in 0..self.rows() {
            let i = row * self.n_columns + column;
            let (w, _) = requested_width_height(&mut self.data[i], usize::MAX, &mut None, self.cell_height_max);
            width = width.max(w);
        }
        width
    }

    /// `table_set_column_width()`.
    fn set_column_width(&mut self, column: usize, width: usize) {
        for row in 0..self.rows() {
            let i = row * self.n_columns + column;
            self.data[i].minimum_width = if width == usize::MAX { 1 } else { width };
        }
    }

    /// `table_print_full(t, stdout, flush=true)`: the output bytes.
    pub fn format(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let n_rows = self.rows();
        let nc = self.n_columns;
        let mut minimum_width = vec![1usize; nc];
        let mut maximum_width = vec![usize::MAX; nc];
        let mut requested_width = vec![usize::MAX; nc];
        let mut column_weight = vec![0u64; nc];
        let mut width: Option<Vec<usize>> = None;
        let first_row = if self.header { 0 } else { 1 };

        for pass in 0..2 {
            requested_width.iter_mut().for_each(|w| *w = usize::MAX);
            let mut any_soft = Some(false);
            for i in first_row..n_rows {
                for j in 0..nc {
                    let avail = width.as_ref().map(|w| w[j]).unwrap_or(usize::MAX);
                    let chm = self.cell_height_max;
                    let d = &mut self.data[i * nc + j];
                    let (req_width, _) = requested_width_height(d, avail, &mut any_soft, chm);
                    if requested_width[j] == usize::MAX || requested_width[j] < req_width {
                        requested_width[j] = req_width;
                    }
                    if minimum_width[j] < d.minimum_width {
                        minimum_width[j] = d.minimum_width;
                    }
                    if d.maximum_width != usize::MAX
                        && (maximum_width[j] == usize::MAX || maximum_width[j] > d.maximum_width)
                    {
                        maximum_width[j] = d.maximum_width;
                    }
                    column_weight[j] += d.weight;
                }
            }
            let any_soft = any_soft.unwrap_or(false);
            let mut table_requested = nc - 1;
            let mut table_minimum = nc - 1;
            let mut table_maximum = nc - 1;
            let mut weight_sum = 0u64;
            for j in 0..nc {
                weight_sum += column_weight[j];
                table_minimum += minimum_width[j];
                if maximum_width[j] == usize::MAX {
                    table_maximum = usize::MAX;
                } else if table_maximum != usize::MAX {
                    table_maximum += maximum_width[j];
                }
                table_requested = table_requested.saturating_add(requested_width[j]);
            }
            let mut effective = if self.width != 0 && self.width != usize::MAX {
                self.width
            } else if self.width == 0 || ((pass > 0 || !any_soft) && (crate::pager::pager_have() || !isatty_safe(1))) {
                table_requested
            } else {
                table_requested.min(columns() as usize)
            };
            if table_maximum != usize::MAX && effective > table_maximum {
                effective = table_maximum;
            }
            if effective < table_minimum {
                effective = table_minimum;
            }
            let w = width.get_or_insert_with(|| vec![0; nc]);
            if effective >= table_requested {
                let mut extra = effective - table_requested;
                for j in 0..nc {
                    w[j] = if weight_sum == 0 {
                        requested_width[j] + extra / (nc - j)
                    } else {
                        requested_width[j] + ((extra as u64 * column_weight[j]) / weight_sum) as usize
                    };
                    if maximum_width[j] != usize::MAX && w[j] > maximum_width[j] {
                        w[j] = maximum_width[j];
                    }
                    if w[j] < minimum_width[j] {
                        w[j] = minimum_width[j];
                    }
                    let delta = w[j].saturating_sub(requested_width[j]);
                    extra = extra.saturating_sub(delta);
                    weight_sum -= column_weight[j];
                }
                break;
            } else {
                let mut finalize = false;
                let mut extra = effective - table_minimum;
                w.iter_mut().for_each(|x| *x = usize::MAX);
                loop {
                    let mut restart = false;
                    for j in 0..nc {
                        if w[j] != usize::MAX {
                            continue;
                        }
                        let mut ww = if weight_sum == 0 {
                            minimum_width[j] + extra / (nc - j)
                        } else {
                            minimum_width[j] + ((extra as u64 * column_weight[j]) / weight_sum) as usize
                        };
                        if ww >= requested_width[j] {
                            ww = requested_width[j];
                            restart = true;
                        } else if !finalize {
                            continue;
                        }
                        w[j] = ww;
                        extra -= ww - minimum_width[j];
                        weight_sum -= column_weight[j];
                        if restart && !finalize {
                            break;
                        }
                    }
                    if finalize {
                        break;
                    }
                    if !restart {
                        finalize = true;
                    }
                }
                if !any_soft {
                    break;
                }
            }
        }
        let width = width.expect("computed above");

        for i in first_row..n_rows {
            let mut n_subline = 0usize;
            loop {
                let mut more_sublines = false;
                for j in 0..nc {
                    let d = &mut self.data[i * nc + j];
                    let field_full = table_data_format(d, width[j], &mut None);
                    let (line, more) = string_extract_line(&field_full, n_subline);
                    let mut lines_truncated = false;
                    if more {
                        if self.cell_height_max == usize::MAX || n_subline + 1 < self.cell_height_max {
                            more_sublines = true;
                        } else {
                            lines_truncated = true;
                        }
                    }
                    let mut field = line;
                    let mut l = console_width(&field);
                    if l > width[j] {
                        field = ellipsize(&field, width[j], if lines_truncated { 100 } else { d.ellipsize_percent })
                            .unwrap_or_default();
                    } else {
                        if lines_truncated {
                            let mut padded = field.clone();
                            padded.extend_from_slice(glyph(Glyph::Ellipsis));
                            field = ellipsize(&padded, width[j], 100).unwrap_or_default();
                            l = console_width(&field);
                        }
                        if l < width[j] {
                            let mut aligned = align_string(&field, width[j], d.align_percent);
                            if j == nc - 1
                                && (!colors_enabled() || data_color(d).is_none())
                                && (!underline_enabled() || data_underline(d).is_none())
                            {
                                let n = aligned
                                    .iter()
                                    .rposition(|b| !crate::string::WHITESPACE.contains(b))
                                    .map(|p| p + 1)
                                    .unwrap_or(0);
                                aligned.truncate(n);
                            }
                            field = aligned;
                        }
                    }
                    if j > 0 {
                        out.push(b' ');
                    }
                    let mut color = None;
                    if colors_enabled() {
                        color = data_color(d);
                        if let Some(c) = color {
                            out.extend_from_slice(c.as_bytes());
                        }
                    }
                    let mut underline = None;
                    if underline_enabled() {
                        underline = data_underline(d);
                        if let Some(u) = underline {
                            out.extend_from_slice(u.as_bytes());
                        }
                    }
                    out.extend_from_slice(&field);
                    if color.is_some() || underline.is_some() {
                        out.extend_from_slice(ansi::NORMAL.as_bytes());
                    }
                }
                out.push(b'\n');
                n_subline += 1;
                if !more_sublines {
                    break;
                }
            }
        }
        out
    }
}

/// `table_sync_all_column_widths(column, tables)`.
pub fn sync_all_column_widths(column: usize, tables: &mut [&mut Table]) {
    let mut max = 0;
    for t in tables.iter_mut() {
        max = max.max(t.column_requested_width(column));
    }
    for t in tables.iter_mut() {
        t.set_column_width(column, max);
    }
}

fn is_empty_cell(d: &TableData) -> bool {
    match &d.cell {
        Cell::Empty => true,
        Cell::StrvWrapped(v) => v.is_empty(),
        _ => false,
    }
}

/// `table_data_color()`.
fn data_color(d: &TableData) -> Option<&'static str> {
    if is_empty_cell(d) { Some(ansi::grey()) } else { None }
}

/// `table_data_underline()`.
fn data_underline(d: &TableData) -> Option<&'static str> {
    if matches!(d.cell, Cell::Header(_)) { Some(ansi::add_underline()) } else { None }
}

/// `format_strv_width()`.
fn format_strv_width(strv: &[Vec<u8>], column_width: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut position = 0usize;
    for p in strv {
        let our_len = console_width(p);
        if position == 0 {
            out.extend_from_slice(p);
            position = our_len;
        } else if position.saturating_add(1).saturating_add(our_len) <= column_width {
            out.push(b' ');
            out.extend_from_slice(p);
            position = position.saturating_add(1).saturating_add(our_len);
        } else {
            out.push(b'\n');
            out.extend_from_slice(p);
            position = our_len;
        }
    }
    out
}

/// `table_data_format()`: `have_soft` is only set when a wrapped cell is
/// (re)formatted, not when its cached text is reused, exactly as in C.
fn table_data_format(d: &mut TableData, column_width: usize, have_soft: &mut Option<bool>) -> Vec<u8> {
    if let Some(f) = &d.formatted
        && (!matches!(d.cell, Cell::StrvWrapped(_)) || d.formatted_for_width == column_width)
    {
        return f.clone();
    }
    d.formatted = None;
    match &d.cell {
        Cell::Empty => Vec::new(),
        Cell::String(s) => s.clone(),
        Cell::Header(s) => {
            let up: Vec<u8> = s.iter().map(|b| b.to_ascii_uppercase()).collect();
            d.formatted = Some(up.clone());
            up
        }
        Cell::StrvWrapped(v) => {
            if v.is_empty() {
                return Vec::new();
            }
            let f = format_strv_width(v, column_width);
            d.formatted = Some(f.clone());
            d.formatted_for_width = column_width;
            if let Some(h) = have_soft {
                *h = true;
            }
            f
        }
    }
}

/// `table_data_requested_width_height()`.
fn requested_width_height(
    d: &mut TableData,
    available: usize,
    have_soft: &mut Option<bool>,
    _cell_height_max: usize,
) -> (usize, usize) {
    let mut soft = Some(false);
    let t = table_data_format(d, available, &mut soft);
    let mut max_width = 0;
    let mut height = 0;
    for line in t.split(|&b| b == b'\n') {
        max_width = max_width.max(console_width(line));
        height += 1;
    }
    if t.ends_with(b"\n") && height > 1 {
        height -= 1;
    }
    let mut width = max_width;
    if d.maximum_width != usize::MAX && width > d.maximum_width {
        width = d.maximum_width;
    }
    if width < d.minimum_width {
        width = d.minimum_width;
    }
    if soft == Some(true)
        && let Some(h) = have_soft
    {
        *h = true;
    }
    (width, height)
}

/// `string_extract_line(s, i)`: (line, more lines follow).
fn string_extract_line(s: &[u8], i: usize) -> (Vec<u8>, bool) {
    let mut p = 0usize;
    let mut c = 0usize;
    loop {
        let q = s[p..].iter().position(|&b| b == b'\n').map(|x| x + p);
        if i == c {
            return match q {
                Some(q) => (s[p..q].to_vec(), q + 1 < s.len()),
                None => (s[p..].to_vec(), false),
            };
        }
        match q {
            None => return (Vec::new(), false),
            Some(q) => p = q + 1,
        }
        c += 1;
    }
}

/// `align_string_mem(str, url=NULL, new_length, percent)`.
fn align_string(s: &[u8], new_length: usize, percent: u32) -> Vec<u8> {
    let mut w = 0usize;
    let mut p = 0usize;
    while p < s.len() {
        match encoded_to_unichar(&s[p..]) {
            Err(_) => {
                p += 1;
                w += 1;
                continue;
            }
            Ok((c, _)) => {
                p += skip_len(s[p]);
                w += if unichar_iswide(c) { 2 } else { 1 };
            }
        }
    }
    if w >= new_length {
        return s.to_vec();
    }
    let space = new_length - w;
    let lspace = space * percent as usize / 100;
    let mut out = vec![b' '; lspace];
    out.extend_from_slice(s);
    out.resize(out.len() + space - lspace, b' ');
    out
}
