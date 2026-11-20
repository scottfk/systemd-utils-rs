// SPDX-License-Identifier: GPL-2.0-or-later
//! `udev-builtin-dissect_image.c`: probe the boot disk's partitions (the
//! "probe" verb) and copy the results to its partitions ("copy").

use std::cell::RefCell;

use shared::dissect::{self, ImageFilter, VeritySettings};
use shared::errno::{strerror, synthetic};
use shared::gpt::{self, Designator};
use shared::image_policy::{self as ip, ImagePolicy};
use shared::{log_debug, log_device_debug, log_device_debug_errno, log_device_warning_errno, log_error_errno};

use super::super::builtin::udev_builtin_add_property;
use super::super::event::Event;

#[derive(Default)]
struct Args {
    policy: Option<ImagePolicy>,
    verity: VeritySettings,
    filter: Option<ImageFilter>,
}

thread_local! {
    static ARGS: RefCell<Args> = RefCell::new(Args::default());
}

/// `proc_cmdline_get_key(key, 0, &value)`.
fn cmdline_value(key: &[u8]) -> Result<Option<Vec<u8>>, i32> {
    shared::proc_cmdline::proc_cmdline_get_key(key, false).map(|v| v.flatten())
}

/// `acquire_image_policy()`.
fn acquire_image_policy() -> Result<Option<ImagePolicy>, i32> {
    let Some(value) = cmdline_value(b"systemd.image_policy").map_err(|r| {
        log_error_errno!(r, "Failed to read systemd.image_policy= kernel command line switch: ", strerror(r))
    })?
    else {
        return Ok(None);
    };
    let p = ip::image_policy_from_string(&value)
        .map_err(|r| log_error_errno!(r, "Failed to parse image policy '", &value[..], "': ", strerror(r)))?;
    if shared::log::debug_logging() {
        log_debug!("Loaded image policy: ", p.to_string(true));
    }
    Ok(Some(p))
}

/// `acquire_verity_settings()`.
fn acquire_verity_settings() -> Result<VeritySettings, i32> {
    let mut v = VeritySettings::default();
    let mut h = cmdline_value(b"roothash")
        .map_err(|r| log_error_errno!(r, "Failed to read roothash= kernel command line switch: ", strerror(r)))?;
    if h.is_some() {
        v.designator = Some(Designator::Root);
    }
    let uh = cmdline_value(b"usrhash")
        .map_err(|r| log_error_errno!(r, "Failed to read usrhash= kernel command line switch: ", strerror(r)))?;
    if let Some(uh) = uh {
        if h.is_some() {
            return Err(log_error_errno!(synthetic(libc::EINVAL), "Both roothash= and usrhash= specified, refusing."));
        }
        h = Some(uh);
        v.designator = Some(Designator::Usr);
    }
    if let Some(h) = h {
        v.root_hash = shared::hexdecoct::unhexmem(&h).map_err(|r| {
            log_error_errno!(r, "Failed to parse root hash from kernel command line switch: ", strerror(r))
        })?;
    }
    Ok(v)
}

/// `acquire_image_filter()`.
fn acquire_image_filter() -> Result<Option<ImageFilter>, i32> {
    let Some(value) = cmdline_value(b"systemd.image_filter").map_err(|r| {
        log_error_errno!(r, "Failed to read systemd.image_filter= kernel command line switch: ", strerror(r))
    })?
    else {
        return Ok(None);
    };
    dissect::image_filter_parse(&value)
        .map_err(|r| log_error_errno!(r, "Failed to parse image filter '", &value[..], "': ", strerror(r)))
}

/// `verb_probe()`.
fn verb_probe(event: &mut Event) -> Result<(), i32> {
    let dev = event.dev.clone();
    let devnode = dev
        .get_devname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r)))?
        .bytes()
        .to_vec();
    if shared::blockdev::block_device_is_whole_disk(&dev) != Ok(true) {
        log_device_debug!(dev, "Must be invoked on whole block device (was invoked in '", &devnode[..], "), ignoring.");
        return Ok(());
    }
    let diskseq = dev
        .get_diskseq()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get diskseq of '", &devnode[..], "': ", strerror(r)))?;
    match shared::blockdev::blockdev_partscan_enabled(&dev) {
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to determine if block device '",
                &devnode[..],
                "' supports partitions: ",
                strerror(r)
            ));
        }
        Ok(false) => {
            log_device_debug!(
                dev,
                "Invoked on block device '",
                &devnode[..],
                "' that lacks partition scanning, ignoring."
            );
            return Ok(());
        }
        Ok(true) => {}
    }
    let lp = match dissect::loop_device_open(&dev, libc::O_RDONLY, libc::LOCK_SH) {
        Err(r) if shared::sd_device::errno_is_neg_device_absent(r) => {
            log_device_debug!(dev, "Device absent while opening block device '", &devnode[..], "', ignoring.");
            return Ok(());
        }
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to open block device '",
                &devnode[..],
                ": ",
                strerror(r)
            ));
        }
        Ok(l) => l,
    };
    let (policy, mut verity, filter) = ARGS.with(|a| {
        let a = a.borrow();
        (a.policy.clone().unwrap_or_else(ip::image_policy_host), a.verity.clone(), a.filter.clone())
    });
    let mut r = dissect::dissect_loop_device(&lp, &verity, &policy, filter.as_ref());
    if r.as_ref().err() == Some(&-libc::ERFKILL) && !shared::proc_cmdline::in_initrd() {
        let mangled = policy.ignore_designators(&[
            Designator::Root,
            Designator::RootVerity,
            Designator::RootVeritySig,
            Designator::Usr,
            Designator::UsrVerity,
            Designator::UsrVeritySig,
        ]);
        if mangled != policy {
            if shared::log::debug_logging() {
                log_device_debug_errno!(
                    dev,
                    synthetic(libc::ERFKILL),
                    "Couldn't dissect block device with regular policy '",
                    policy.to_string(false),
                    "', retrying with policy where root/usr are set to ignore '",
                    mangled.to_string(false),
                    "'."
                );
            }
            r = dissect::dissect_loop_device(&lp, &verity, &mangled, filter.as_ref());
        }
    }
    let mut image = match r {
        Err(r) if [-libc::ENOPKG, -libc::ENOMSG, -libc::ENXIO, -libc::ENOTUNIQ].contains(&r) => {
            log_device_debug_errno!(
                dev,
                r,
                "Device does not carry a GPT disk label with suitable partitions, ignoring."
            );
            return Ok(());
        }
        Err(r) if r == -libc::ERFKILL => {
            log_device_debug_errno!(
                dev,
                r,
                "Device carries GPT disk label that doesn't match our image policy, ignoring."
            );
            return Ok(());
        }
        Err(r) => return Err(log_device_debug_errno!(dev, r, "Failed to dissect disk image: ", strerror(r))),
        Ok(m) => m,
    };
    dissect::load_verity_sig_partition(&mut image, lp.fd.raw(), &mut verity).map_err(|r| {
        log_device_debug_errno!(dev, r, "Failed to load verity signature data from image: ", strerror(r))
    })?;
    dissect::guess_verity_roothash(&mut image, &mut verity);
    let add = |k: &str, v: &[u8]| {
        let _ = udev_builtin_add_property(event, k.as_bytes(), Some(v));
    };
    add("ID_DISSECT_IMAGE", b"1");
    if let Some(a) = image.architecture() {
        add("ID_DISSECT_IMAGE_ARCHITECTURE", a.as_bytes());
    }
    for d in gpt::ALL {
        let p = &image.partitions[d.index()];
        if !p.found {
            continue;
        }
        let n = p.partno;
        add(&format!("ID_DISSECT_PART{n}_DESIGNATOR"), d.as_str().as_bytes());
        if let Some(a) = p.architecture {
            add(&format!("ID_DISSECT_PART{n}_ARCHITECTURE"), a.as_bytes());
        }
        if let Some(dv) = d.verity_hash_of()
            && image.partitions[dv.index()].found
        {
            add(&format!("ID_DISSECT_PART{n}_HAS_VERITY"), b"1");
            add(
                &format!("ID_DISSECT_PART{n}_VERITY_DEVICE"),
                format!("/dev/disk/by-diskseq/{diskseq}-part{}", image.partitions[dv.index()].partno).as_bytes(),
            );
        }
        if let Some(ds) = d.verity_sig_of()
            && image.partitions[ds.index()].found
        {
            add(&format!("ID_DISSECT_PART{n}_HAS_VERITY_SIG"), b"1");
            add(
                &format!("ID_DISSECT_PART{n}_VERITY_SIG_DEVICE"),
                format!("/dev/disk/by-diskseq/{diskseq}-part{}", image.partitions[ds.index()].partno).as_bytes(),
            );
        }
        if Some(d) == verity.designator {
            if !verity.root_hash.is_empty() {
                add(&format!("ID_DISSECT_PART{n}_ROOTHASH"), &shared::hexdecoct::hexmem(&verity.root_hash));
            }
            if !verity.root_hash_sig.is_empty() {
                add(&format!("ID_DISSECT_PART{n}_ROOTHASH_SIG"), &shared::hexdecoct::base64mem(&verity.root_hash_sig));
            }
        }
    }
    Ok(())
}

/// `verb_copy()`.
fn verb_copy(event: &mut Event) -> Result<(), i32> {
    let dev = event.dev.clone();
    let devnode = dev
        .get_devname()
        .map_err(|r| log_device_debug_errno!(dev, r, "Failed to get device node: ", strerror(r)))?
        .bytes()
        .to_vec();
    match dev.is_subsystem_devtype(Some(b"block"), Some(b"partition")) {
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to check if the device '",
                &devnode[..],
                "' is a partition, refusing: ",
                strerror(r)
            ));
        }
        Ok(false) => {
            return Err(log_device_debug_errno!(
                dev,
                synthetic(libc::EINVAL),
                "Invoked on non-partition device '",
                &devnode[..],
                "', refusing."
            ));
        }
        Ok(true) => {}
    }
    let parent = dev
        .get_parent()
        .map_err(|r| log_error_errno!(r, "Failed to get parent of device '", &devnode[..], "': ", strerror(r)))?;
    match parent.is_subsystem_devtype(Some(b"block"), Some(b"disk")) {
        Err(r) => {
            return Err(log_device_debug_errno!(
                dev,
                r,
                "Failed to check if the parent of block device '",
                &devnode[..],
                "' is a whole block device, refusing: ",
                strerror(r)
            ));
        }
        Ok(false) => {
            return Err(log_device_debug_errno!(
                dev,
                synthetic(libc::EINVAL),
                "Parent of block device '",
                &devnode[..],
                "' is not a whole block device, refusing."
            ));
        }
        Ok(true) => {}
    }
    let partn = dev
        .get_property_value(b"PARTN")
        .map_err(|r| {
            log_device_debug_errno!(
                dev,
                r,
                "Failed to get partition number of partition block device '",
                &devnode[..],
                "': ",
                strerror(r)
            )
        })?
        .bytes()
        .to_vec();
    for f in [
        "_DESIGNATOR",
        "_ARCHITECTURE",
        "_HAS_VERITY",
        "_HAS_VERITY_SIG",
        "_ROOTHASH",
        "_ROOTHASH_SIG",
        "_VERITY_DEVICE",
        "_VERITY_SIG_DEVICE",
    ] {
        let p = shared::bcat!("ID_DISSECT_PART", &partn[..], f);
        let v = match parent.get_property_value(&p) {
            Err(r) if r == -libc::ENOENT => continue,
            Err(r) => {
                return Err(log_device_debug_errno!(
                    dev,
                    r,
                    "Failed to get '",
                    &p[..],
                    "' property of parent of '",
                    &devnode[..],
                    "': ",
                    strerror(r)
                ));
            }
            Ok(v) => v.bytes().to_vec(),
        };
        let _ = udev_builtin_add_property(event, shared::bcat!("ID_DISSECT_PART", f).as_slice(), Some(&v));
    }
    Ok(())
}

/// `builtin_dissect_image()`.
pub fn run(event: &mut Event, argv: &[Vec<u8>]) -> Result<(), i32> {
    let dev = event.dev.clone();
    if argv.len() != 2 {
        return Err(log_device_warning_errno!(
            dev,
            synthetic(libc::EINVAL),
            &argv[0][..],
            ": expected single argument."
        ));
    }
    match &argv[1][..] {
        b"probe" => verb_probe(event),
        b"copy" => verb_copy(event),
        v => Err(log_device_warning_errno!(dev, synthetic(libc::EINVAL), &argv[0][..], ": unknown verb '", v, "'")),
    }
}

/// `builtin_dissect_image_init()`.
pub fn init() {
    let policy = match acquire_image_policy() {
        Ok(p) => p,
        Err(_) => return,
    };
    ARGS.with(|a| a.borrow_mut().policy = policy);
    let verity = match acquire_verity_settings() {
        Ok(v) => v,
        Err(_) => return,
    };
    ARGS.with(|a| a.borrow_mut().verity = verity);
    if let Ok(f) = acquire_image_filter() {
        ARGS.with(|a| a.borrow_mut().filter = f);
    }
}

/// `builtin_dissect_image_exit()`.
pub fn exit() {
    ARGS.with(|a| *a.borrow_mut() = Args::default());
}
