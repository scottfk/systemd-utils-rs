// SPDX-License-Identifier: LGPL-2.1-or-later
//! `sd-path.c`: the directories tmpfiles' `%C %D %L %S %t` specifiers use,
//! plus `get_home_dir()` and the tmp directories (`fs-util.c`).

use crate::path::{path_is_absolute, path_is_normalized, path_is_valid, path_join, path_simplify, path_simplify_full};
use crate::sys;

#[derive(Debug, Clone, Copy)]
pub enum SdPath {
    SystemRuntime,
    SystemStatePrivate,
    SystemStateCache,
    SystemStateLogs,
    SystemShared,
    UserRuntime,
    UserStatePrivate,
    UserStateCache,
    UserShared,
    UserConfiguration,
}

/// `get_home_dir()`.
pub fn get_home_dir() -> Result<Vec<u8>, i32> {
    if let Some(e) = sys::secure_getenv("HOME")
        && path_is_valid(&e)
        && path_is_absolute(&e)
    {
        return Ok(path_simplify(&e));
    }
    let u = sys::getuid();
    if u == 0 {
        return Ok(b"/root".to_vec());
    }
    if u == 65534 && sys::stat(b"/etc/systemd/dont-synthesize-nobody").is_err() {
        return Ok(b"/".to_vec());
    }
    let e = sys::getpwuid_dir(u).ok_or(-libc::ESRCH)?;
    if !path_is_valid(&e) || !path_is_absolute(&e) {
        return Err(-libc::EINVAL);
    }
    Ok(path_simplify(&e))
}

fn from_environment(env: &str) -> Result<Vec<u8>, i32> {
    match sys::secure_getenv(env) {
        Some(e) if path_is_absolute(&e) => Ok(e),
        _ => Err(-libc::ENXIO),
    }
}

fn from_home_dir(env: &str, suffix: &[u8]) -> Result<Vec<u8>, i32> {
    if let Some(e) = sys::secure_getenv(env)
        && path_is_absolute(&e)
    {
        return Ok(e);
    }
    Ok(path_join(&[&get_home_dir()?, suffix]))
}

/// `sd_path_lookup(type, suffix, &ret)`.
pub fn sd_path_lookup(t: SdPath, suffix: Option<&[u8]>) -> Result<Vec<u8>, i32> {
    let p = match t {
        SdPath::SystemRuntime => b"/run".to_vec(),
        SdPath::SystemStatePrivate => b"/var/lib".to_vec(),
        SdPath::SystemStateCache => b"/var/cache".to_vec(),
        SdPath::SystemStateLogs => b"/var/log".to_vec(),
        SdPath::SystemShared => b"/usr/share".to_vec(),
        SdPath::UserRuntime => from_environment("XDG_RUNTIME_DIR")?,
        SdPath::UserStatePrivate => from_home_dir("XDG_STATE_HOME", b".local/state")?,
        SdPath::UserStateCache => from_home_dir("XDG_CACHE_HOME", b".cache")?,
        SdPath::UserShared => from_home_dir("XDG_DATA_HOME", b".local/share")?,
        SdPath::UserConfiguration => from_home_dir("XDG_CONFIG_HOME", b".config")?,
    };
    match suffix {
        Some(s) if !s.is_empty() => Ok(path_simplify_full(&path_join(&[&p, s]), true)),
        _ => Ok(p),
    }
}

/// `getenv_tmp_dir()`: Ok(Some) if one of $TMPDIR/$TEMP/$TMP is usable,
/// Ok(None) if none is set, Err with the first problem otherwise.
fn getenv_tmp_dir() -> Result<Option<Vec<u8>>, i32> {
    let mut ret = 0;
    for n in ["TMPDIR", "TEMP", "TMP"] {
        let Some(e) = sys::secure_getenv(n) else { continue };
        let r = if !path_is_absolute(&e) {
            -libc::ENOTDIR
        } else if !path_is_normalized(&e) {
            -libc::EPERM
        } else {
            match crate::fs::is_dir_at(libc::AT_FDCWD, &e, true) {
                Ok(true) => return Ok(Some(e)),
                Ok(false) => -libc::ENOTDIR,
                Err(r) => r,
            }
        };
        if ret >= 0 {
            ret = r;
        }
    }
    if ret < 0 { Err(ret) } else { Ok(None) }
}

/// `tmp_dir_internal(def)`.
fn tmp_dir_internal(def: &[u8]) -> Result<Vec<u8>, i32> {
    let r = getenv_tmp_dir();
    if let Ok(Some(e)) = r {
        return Ok(e);
    }
    let k = match crate::fs::is_dir_at(libc::AT_FDCWD, def, true) {
        Ok(true) => 0,
        Ok(false) => -libc::ENOTDIR,
        Err(e) => e,
    };
    if k < 0 {
        // RET_GATHER(r, k): the env error wins if there was one.
        return Err(match r {
            Err(e) => e,
            _ => k,
        });
    }
    Ok(def.to_vec())
}

/// `tmp_dir()`.
pub fn tmp_dir() -> Result<Vec<u8>, i32> {
    tmp_dir_internal(b"/tmp")
}

/// `var_tmp_dir()`.
pub fn var_tmp_dir() -> Result<Vec<u8>, i32> {
    tmp_dir_internal(b"/var/tmp")
}

/// `search_from_environment()`: $env_search split at ':' (else the
/// defaults), with $env_home (else $HOME/home_suffix) prepended.
fn search_from_environment(env_home: &str, home_suffix: &[u8], env_search: &str, defaults: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut l: Vec<Vec<u8>> = match sys::secure_getenv(env_search) {
        Some(e) => crate::string::strv_split(&e, b":"),
        None => defaults.iter().map(|d| d.to_vec()).collect(),
    };
    let h = match sys::secure_getenv(env_home) {
        Some(e) if path_is_absolute(&e) => Some(e),
        _ => match sys::secure_getenv("HOME") {
            Some(e) if path_is_absolute(&e) => Some(path_join(&[&e, home_suffix])),
            _ => None,
        },
    };
    if let Some(h) = h {
        l.insert(0, h);
    }
    l
}

/// `user_search_dirs(suffix, &config_dirs, &data_dirs)`.
pub fn user_search_dirs(suffix: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let add = |l: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
        l.into_iter().map(|i| path_simplify_full(&path_join(&[&i, suffix]), true)).collect()
    };
    let config = search_from_environment("XDG_CONFIG_HOME", b".config", "XDG_CONFIG_DIRS", &[b"/etc"]);
    let data = search_from_environment(
        "XDG_DATA_HOME",
        b".local/share",
        "XDG_DATA_DIRS",
        &[b"/usr/local/share", b"/usr/share"],
    );
    (add(config), add(data))
}
