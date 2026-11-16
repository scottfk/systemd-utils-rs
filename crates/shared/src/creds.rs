// SPDX-License-Identifier: LGPL-2.1-or-later
//! `creds-util.c`: the credentials directory.

use crate::errno::strerror;
use crate::path::{path_is_absolute, path_is_normalized};

/// `get_credentials_dir()`: `Err(-ENXIO)` if $CREDENTIALS_DIRECTORY is unset.
pub fn get_credentials_dir() -> Result<Vec<u8>, i32> {
    let e = crate::sys::secure_getenv("CREDENTIALS_DIRECTORY").ok_or(-libc::ENXIO)?;
    if !path_is_absolute(&e) || !path_is_normalized(&e) {
        return Err(-libc::EINVAL);
    }
    Ok(e)
}

/// `fdname_is_valid()`: printable ASCII except ':', at most 255 bytes.
pub fn fdname_is_valid(s: &[u8]) -> bool {
    s.iter().all(|&c| (b' '..127).contains(&c) && c != b':') && s.len() <= 255
}

/// `credential_name_valid()`.
pub fn credential_name_valid(s: &[u8]) -> bool {
    crate::path::filename_is_valid(s) && fdname_is_valid(s)
}

/// `read_credential(name, &data, &size)`.
pub fn read_credential(name: &[u8]) -> Result<Vec<u8>, i32> {
    if !credential_name_valid(name) {
        return Err(-libc::EINVAL);
    }
    let d = get_credentials_dir()?;
    let mut f = crate::fileio::fopen_re(&crate::path::path_join(&[&d, name]))?;
    f.read_to_end()
}

/// `PickUpCredential`: (credential prefix, target directory, filename suffix).
pub type PickUpCredential = (&'static str, &'static str, &'static str);

/// `pick_up_credential_one()`.
fn pick_up_credential_one(dir_fd: i32, name: &[u8], t: &PickUpCredential) -> i32 {
    let Some(e) = name.strip_prefix(t.0.as_bytes()) else { return 0 };
    let f = crate::bcat!(e, t.2);
    if !crate::path::filename_is_valid(&f) {
        return crate::log_warning_errno!(
            crate::errno::synthetic(libc::EINVAL),
            "Passed credential '",
            name,
            "' would result in invalid filename '",
            &f[..],
            "'."
        );
    }
    if let Err(r) = crate::fs::mkdir_p(t.1.as_bytes(), 0o755) {
        return crate::log_warning_errno!(r, "Failed to create '", t.1, "': ", strerror(r));
    }
    let target = crate::path::path_join(&[t.1.as_bytes(), &f]);
    if let Err(r) = crate::copy::copy_file_at(dir_fd, name, libc::AT_FDCWD, &target, 0o644) {
        return crate::log_warning_errno!(
            r,
            "Failed to copy credential ",
            name,
            " ",
            crate::locale::glyph(crate::locale::Glyph::ArrowRight),
            " file ",
            &target[..],
            ": ",
            strerror(r)
        );
    }
    crate::log_info!("Installed ", &target[..], " from credential.");
    1
}

/// `pick_up_credentials(table, n)`.
pub fn pick_up_credentials(table: &[PickUpCredential]) -> i32 {
    let fd = match get_credentials_dir()
        .and_then(|d| crate::sys::open(&d, libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_RDONLY, 0))
    {
        Err(r) if r == -libc::ENXIO || r == -libc::ENOENT => {
            crate::log_debug!("No credentials found.");
            return 0;
        }
        Err(r) => return crate::log_error_errno!(r, "Failed to open credentials directory: ", strerror(r)),
        Ok(fd) => crate::sys::OwnedFd::new(fd),
    };
    // readdir_all(RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_MUST_BE_REGULAR)
    let mut names = Vec::new();
    let r = (|| -> Result<(), i32> {
        let mut d = crate::sys::fdopendir_dup(fd.raw())?;
        while let Some((n, t)) = crate::conf_files::foreach_dirent_all(&mut d)? {
            if n.starts_with(b".") {
                continue;
            }
            let regular = if t == libc::DT_UNKNOWN {
                crate::sys::fstatat(fd.raw(), &n, libc::AT_SYMLINK_NOFOLLOW)
                    .is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
            } else {
                t == libc::DT_REG
            };
            if regular {
                names.push(n);
            }
        }
        Ok(())
    })();
    if let Err(r) = r {
        return crate::log_error_errno!(r, "Failed to enumerate credentials: ", strerror(r));
    }
    names.sort();
    let mut ret = 0;
    for n in &names {
        for t in table {
            let r = pick_up_credential_one(fd.raw(), n, t);
            if r != 0 {
                crate::errno::ret_gather(&mut ret, r);
                break;
            }
        }
    }
    ret
}
