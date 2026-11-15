// SPDX-License-Identifier: LGPL-2.1-or-later
//! `argv-util.c`: `save_argc_argv()` and `rename_process()`.

use std::sync::Mutex;

use crate::errno::{is_neg_privilege, strerror, synthetic};
use crate::{log_debug_errno, sys};

const CAP_SYS_RESOURCE: u32 = 24;

/// The lengths of argv[1..] as saved by `save_argc_argv()`.
static SAVED_ARGV_LENS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
/// `update_argv()`'s state: can_do (-1 unknown) and the mapping.
static MM: Mutex<(i8, usize, usize)> = Mutex::new((-1, 0, 0));

/// `save_argc_argv()`.
pub fn save_argc_argv(argv: &[Vec<u8>]) {
    *SAVED_ARGV_LENS.lock().unwrap() = argv.iter().skip(1).map(|a| a.len()).collect();
}

/// `update_argv()`: point the kernel's argv at a fresh copy of `name`.
fn update_argv(name: &[u8]) -> i32 {
    let mut mm = MM.lock().unwrap();
    if mm.0 == 0 {
        return 0;
    }
    mm.0 = 0;
    let l = name.len();
    match sys::have_effective_cap(CAP_SYS_RESOURCE) {
        Err(r) => return log_debug_errno!(r, "Failed to check if we have enough privileges: ", strerror(r)),
        Ok(false) => {
            return log_debug_errno!(synthetic(libc::EPERM), "Skipping PR_SET_MM, as we don't have privileges.");
        }
        Ok(true) => {}
    }
    if mm.2 < l + 1 {
        let (nn, nn_size) = match sys::mmap_name(name) {
            Ok(x) => x,
            Err(e) => return log_debug_errno!(e, "mmap() failed: ", strerror(e)),
        };
        match sys::prctl_set_mm(libc::PR_SET_MM_ARG_START, nn) {
            Err(r) if is_neg_privilege(r) => return log_debug_errno!(r, "PR_SET_MM_ARG_START failed: ", strerror(r)),
            Err(r) => {
                log_debug_errno!(r, "PR_SET_MM_ARG_START failed, attempting PR_SET_MM_ARG_END hack: ", strerror(r));
                if let Err(r) = sys::prctl_set_mm(libc::PR_SET_MM_ARG_END, nn + l + 1) {
                    log_debug_errno!(r, "PR_SET_MM_ARG_END hack failed, proceeding without: ", strerror(r));
                    sys::munmap(nn, nn_size);
                    return r;
                }
                if let Err(r) = sys::prctl_set_mm(libc::PR_SET_MM_ARG_START, nn) {
                    return log_debug_errno!(r, "PR_SET_MM_ARG_START still failed, proceeding without: ", strerror(r));
                }
            }
            Ok(()) => {
                if let Err(r) = sys::prctl_set_mm(libc::PR_SET_MM_ARG_END, nn + l + 1) {
                    log_debug_errno!(r, "PR_SET_MM_ARG_END failed, proceeding without: ", strerror(r));
                }
            }
        }
        if mm.1 != 0 {
            sys::munmap(mm.1, mm.2);
        }
        mm.1 = nn;
        mm.2 = nn_size;
    } else {
        // Not reached by the ported programs: they rename at most once.
        if let Err(r) = sys::prctl_set_mm(libc::PR_SET_MM_ARG_END, mm.1 + l + 1) {
            log_debug_errno!(r, "PR_SET_MM_ARG_END failed, proceeding without: ", strerror(r));
        }
    }
    mm.0 = 1;
    0
}

/// `rename_process(name)` (= `rename_process_full(name, NULL)`).
pub fn rename_process(comm: &[u8]) -> i32 {
    if comm.is_empty() {
        return -libc::EINVAL;
    }
    if !crate::locale::is_main_thread() {
        return -libc::EPERM;
    }
    if let Err(r) = sys::try_set_comm(comm) {
        log_debug_errno!(r, "PR_SET_NAME failed: ", strerror(r));
    }
    let mut truncated = comm.len() >= 16;
    let k = sys::invocation_name().len();
    if comm.len() > k {
        truncated = true;
    }
    // Steps two and four of C: program_invocation_name is argv[0], so one
    // strncpy() covers both (the zeroing of argv[1..] moves before step
    // three, which nothing can observe).
    let lens = SAVED_ARGV_LENS.lock().unwrap().clone();
    let new0 = sys::rewrite_argv(comm, &lens);
    let short = match new0.iter().rposition(|&b| b == b'/') {
        Some(i) => &new0[i + 1..],
        None => &new0[..],
    };
    crate::log::set_short_name(short);
    let _ = update_argv(comm);
    if truncated { 0 } else { 1 }
}
