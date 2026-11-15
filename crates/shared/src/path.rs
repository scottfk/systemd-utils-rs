// SPDX-License-Identifier: LGPL-2.1-or-later
//! `path-util.c`: path parsing, joining and comparing, on byte strings.

use std::cmp::Ordering;

use crate::string::string_is_glob;
use crate::sys;

pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;

/// `path_is_absolute()`.
pub fn path_is_absolute(p: &[u8]) -> bool {
    p.first() == Some(&b'/')
}

/// `is_path()`: contains a slash.
pub fn is_path(p: &[u8]) -> bool {
    p.contains(&b'/')
}

/// `dot_or_dot_dot()`.
pub fn dot_or_dot_dot(p: &[u8]) -> bool {
    p == b"." || p == b".."
}

/// `skip_slash_or_dot()`.
fn skip_slash_or_dot(p: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < p.len() {
        if p[i] == b'/' {
            i += 1;
            continue;
        }
        if p[i..].starts_with(b"./") {
            i += 2;
            continue;
        }
        break;
    }
    &p[i..]
}

/// `path_find_first_component(&p, accept_dot_dot, &ret)`: the length of the
/// first component (0 if none) and the component itself; `p` moves past it.
pub fn path_find_first_component<'a>(p: &mut &'a [u8], accept_dot_dot: bool) -> Result<(usize, &'a [u8]), i32> {
    let first = skip_slash_or_dot(p);
    if first.is_empty() {
        *p = first;
        return Ok((0, &[]));
    }
    if first == b"." {
        *p = &first[1..];
        return Ok((0, &[]));
    }
    let len = first.iter().position(|&b| b == b'/').unwrap_or(first.len());
    if len > NAME_MAX {
        return Err(-libc::EINVAL);
    }
    if !accept_dot_dot && &first[..len] == b".." {
        return Err(-libc::EINVAL);
    }
    let next = skip_slash_or_dot(&first[len..]);
    *p = if next == b"." { &next[1..] } else { next };
    Ok((len, first))
}

/// `skip_slash_or_dot_backward(path, q)`: index, or None.
fn skip_slash_or_dot_backward(path: &[u8], mut q: Option<usize>) -> Option<usize> {
    while let Some(i) = q {
        if path[i] == b'/' {
            q = i.checked_sub(1);
            continue;
        }
        if i > 0 && &path[i - 1..i + 1] == b"/." {
            q = i.checked_sub(1);
            continue;
        }
        if i == 0 && path[i] == b'.' {
            q = None;
            continue;
        }
        break;
    }
    q
}

/// `path_find_last_component(path, accept_dot_dot, &next, &ret)`, for the
/// first call (`*next == NULL`): (len, start of the last component, `next`).
pub fn path_find_last_component(path: &[u8], accept_dot_dot: bool) -> Result<(usize, usize, usize), i32> {
    if path.is_empty() {
        return Ok((0, 0, 0));
    }
    let Some(q) = skip_slash_or_dot_backward(path, Some(path.len() - 1)) else {
        return Ok((0, 0, 0));
    };
    let last_end = q + 1;
    let mut q = Some(q);
    while let Some(i) = q {
        if path[i] == b'/' {
            break;
        }
        q = i.checked_sub(1);
    }
    let last_begin = q.map(|i| i + 1).unwrap_or(0);
    let len = last_end - last_begin;
    if len > NAME_MAX {
        return Err(-libc::EINVAL);
    }
    if !accept_dot_dot && &path[last_begin..last_end] == b".." {
        return Err(-libc::EINVAL);
    }
    let next = skip_slash_or_dot_backward(path, q).map(|i| i + 1).unwrap_or(0);
    Ok((len, last_begin, next))
}

/// `path_is_valid_full()`.
pub fn path_is_valid_full(p: &[u8], accept_dot_dot: bool) -> bool {
    if p.is_empty() {
        return false;
    }
    let mut e = p;
    loop {
        if path_find_first_component(&mut e, accept_dot_dot).is_err() {
            return false;
        }
        if p.len() - e.len() >= PATH_MAX {
            return false;
        }
        if e.is_empty() {
            return true;
        }
    }
}

/// `path_is_valid()`.
pub fn path_is_valid(p: &[u8]) -> bool {
    path_is_valid_full(p, true)
}

/// `path_is_safe()`.
pub fn path_is_safe(p: &[u8]) -> bool {
    path_is_valid_full(p, false)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `path_is_normalized()`.
pub fn path_is_normalized(p: &[u8]) -> bool {
    if !path_is_safe(p) {
        return false;
    }
    if p == b"." || p.starts_with(b"./") || p.ends_with(b"/.") || contains(p, b"/./") {
        return false;
    }
    !contains(p, b"//")
}

/// `filename_part_is_valid()`.
pub fn filename_part_is_valid(p: &[u8]) -> bool {
    !p.contains(&b'/') && p.len() <= NAME_MAX
}

/// `filename_is_valid()`.
pub fn filename_is_valid(p: &[u8]) -> bool {
    !p.is_empty() && !dot_or_dot_dot(p) && filename_part_is_valid(p)
}

/// `path_simplify_full(path, 0)`.
pub fn path_simplify(path: &[u8]) -> Vec<u8> {
    path_simplify_full(path, false)
}

/// `path_simplify_full(path, flags)`.
pub fn path_simplify_full(path: &[u8], keep_trailing_slash: bool) -> Vec<u8> {
    if path.is_empty() {
        return Vec::new();
    }
    let keep_trailing_slash = keep_trailing_slash && path.ends_with(b"/");
    let absolute = path_is_absolute(path);
    let mut out: Vec<u8> = if absolute { b"/".to_vec() } else { Vec::new() };
    let mut p = &path[absolute as usize..];
    let mut add_slash = false;
    let mut beginning = true;
    loop {
        let before = p;
        match path_find_first_component(&mut p, true) {
            Ok((0, _)) => break,
            Ok((r, e)) => {
                if absolute && beginning && &e[..r] == b".." {
                    continue;
                }
                beginning = false;
                if add_slash {
                    out.push(b'/');
                }
                out.extend_from_slice(&e[..r]);
                add_slash = true;
            }
            Err(_) => {
                // Invalid: copy the rest as it is.
                if add_slash {
                    out.push(b'/');
                }
                out.extend_from_slice(before);
                return out;
            }
        }
    }
    if out.is_empty() {
        out.push(b'.');
    }
    if out.last() != Some(&b'/') && keep_trailing_slash {
        out.push(b'/');
    }
    out
}

/// `path_startswith_full(path, prefix, 0)`: the rest after the prefix.
pub fn path_startswith<'a>(original: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if path_is_absolute(original) != path_is_absolute(prefix) {
        return None;
    }
    let mut path = original;
    let mut prefix = prefix;
    loop {
        let (m, p) = path_find_first_component(&mut path, true).ok()?;
        let (n, q) = path_find_first_component(&mut prefix, true).ok()?;
        if n == 0 {
            // C returns p if set, else path: the start of the next component.
            return Some(if m > 0 { p } else { path });
        }
        if m != n || p[..m] != q[..n] {
            return None;
        }
    }
}

/// `path_startswith_strv(p, strv)`.
pub fn path_startswith_strv<'a>(p: &'a [u8], strv: &[Vec<u8>]) -> Option<&'a [u8]> {
    strv.iter().find_map(|s| path_startswith(p, s))
}

/// `path_compare(a, b)`.
pub fn path_compare(a: &[u8], b: &[u8]) -> Ordering {
    let r = path_is_absolute(a).cmp(&path_is_absolute(b));
    if r != Ordering::Equal {
        return r;
    }
    let (mut a, mut b) = (a, b);
    loop {
        let j = path_find_first_component(&mut a, true);
        let k = path_find_first_component(&mut b, true);
        let (j, aa, k, bb) = match (j, k) {
            (Ok((j, aa)), Ok((k, bb))) => (j, aa, k, bb),
            (j, k) => {
                let r = j.is_err().cmp(&k.is_err());
                if r != Ordering::Equal {
                    return r;
                }
                return a.cmp(b);
            }
        };
        if j == 0 {
            return if k == 0 { Ordering::Equal } else { Ordering::Less };
        }
        if k == 0 {
            return Ordering::Greater;
        }
        let r = aa[..j.min(k)].cmp(&bb[..j.min(k)]);
        if r != Ordering::Equal {
            return r;
        }
        let r = j.cmp(&k);
        if r != Ordering::Equal {
            return r;
        }
    }
}

/// `path_equal(a, b)`.
pub fn path_equal(a: &[u8], b: &[u8]) -> bool {
    path_compare(a, b) == Ordering::Equal
}

/// `empty_or_root()`.
pub fn empty_or_root(p: Option<&[u8]>) -> bool {
    match p {
        None => true,
        Some(p) => p.is_empty() || path_equal(p, b"/"),
    }
}

/// `path_join(...)`: join with single slashes; empty parts are skipped.
pub fn path_join(parts: &[&[u8]]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut slash = true;
    for p in parts {
        if p.is_empty() {
            continue;
        }
        if !slash && p[0] != b'/' {
            out.push(b'/');
        }
        out.extend_from_slice(p);
        slash = p.ends_with(b"/");
    }
    out
}

/// `last_path_component()`.
pub fn last_path_component(path: &[u8]) -> &[u8] {
    let l = path.len();
    if l == 0 {
        return path;
    }
    let mut k = l;
    while k > 0 && path[k - 1] == b'/' {
        k -= 1;
    }
    if k == 0 {
        return &path[l - 1..];
    }
    while k > 0 && path[k - 1] != b'/' {
        k -= 1;
    }
    &path[k..]
}

/// `skip_leading_slash()`.
pub fn skip_leading_slash(p: &[u8]) -> &[u8] {
    let n = p.iter().take_while(|&&b| b == b'/').count();
    &p[n..]
}

/// `path_split_prefix_filename()`: (dir, filename, has trailing slash).
pub fn path_split_prefix_filename(
    path: &[u8],
    want_dir: bool,
    want_filename: bool,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, bool), i32> {
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    let (r, c, next) = path_find_last_component(path, false)?;
    if r == 0 {
        return Err(-libc::EADDRNOTAVAIL);
    }
    let mut d = None;
    if want_dir {
        if next == 0 {
            if path[0] != b'/' {
                if !want_filename {
                    return Err(-libc::EDESTADDRREQ);
                }
            } else {
                d = Some(b"/".to_vec());
            }
        } else {
            let s = path_simplify(&path[..next]);
            if !path_is_valid(&s) {
                return Err(-libc::EINVAL);
            }
            d = Some(s);
        }
    } else if !path_is_valid(path) {
        return Err(-libc::EINVAL);
    }
    let f = if want_filename { Some(path[c..c + r].to_vec()) } else { None };
    Ok((d, f, path.len() - c > r))
}

/// `path_extract_filename()`.
pub fn path_extract_filename(path: &[u8]) -> Result<Vec<u8>, i32> {
    Ok(path_split_prefix_filename(path, false, true)?.1.expect("requested"))
}

/// `path_extract_directory()`: `Err(-EDESTADDRREQ)` for a bare filename.
pub fn path_extract_directory(path: &[u8]) -> Result<Vec<u8>, i32> {
    Ok(path_split_prefix_filename(path, true, false)?.0.expect("requested"))
}

/// `safe_getcwd()`.
pub fn safe_getcwd() -> Result<Vec<u8>, i32> {
    let cwd = sys::getcwd()?;
    if cwd.first() != Some(&b'/') {
        return Err(-libc::ENOMEDIUM);
    }
    Ok(cwd)
}

/// `path_make_absolute_cwd()`.
pub fn path_make_absolute_cwd(p: &[u8]) -> Result<Vec<u8>, i32> {
    if path_is_absolute(p) {
        return Ok(p.to_vec());
    }
    let cwd = safe_getcwd()?;
    Ok(path_join(&[&cwd, p]))
}

/// `path_glob_can_match(pattern, prefix, &ret)`.
pub fn path_glob_can_match(pattern: &[u8], prefix: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    let (mut a, mut b) = (pattern, prefix);
    loop {
        let (r, p) = path_find_first_component(&mut a, false)?;
        let (s, q) = path_find_first_component(&mut b, false)?;
        if s == 0 {
            // C passes p, the rest of the pattern from this component on.
            return Ok(Some(path_join(&[prefix, if r == 0 { &[] } else { p }])));
        }
        if r == 0 {
            break;
        }
        if r == s && p[..r] == q[..s] {
            continue;
        }
        let g = &p[..r];
        if !string_is_glob(g) {
            break;
        }
        let rr = sys::fnmatch(g, &q[..s], 0);
        if rr == libc::FNM_NOMATCH {
            break;
        }
        if rr != 0 {
            return Err(-libc::EINVAL);
        }
    }
    Ok(None)
}
