// SPDX-License-Identifier: LGPL-2.1-or-later
//! `iocost`: set up the iocost model and QoS solutions the hwdb knows for
//! block devices.  A port of systemd's `src/udev/iocost/iocost.c` (v262).

use std::cell::RefCell;

use shared::conf_parser::{Assign, CONFIG_PARSE_WARN, config_parse_path};
use shared::errno::{strerror, synthetic};
use shared::log::{LOG_DEBUG, LOG_ERR, LOG_INFO};
use shared::options::{Command, OptionParser, Verb, command_print_help, dispatch_verb};
use shared::sd_device::{Dev, Device};
use shared::{log_debug, log_device_debug, log_device_debug_errno, log_device_error_errno, log_device_full_errno};
use shared::{log_device_info, log_error_errno, log_info};
use udev_helpers::{COMMON_OPTIONS, common_option};

const VERBS: &[Verb] = &[
    Verb::help_hidden(),
    Verb::new("query", &["PATH"], 2, 2, 0, Some("Query the known solution for the device")),
    Verb::new(
        "apply",
        &["PATH [SOLUTION]"],
        2,
        3,
        0,
        Some("Apply solution for the device if found, do nothing otherwise"),
    ),
];

const COMMAND: Command = Command {
    names: &["iocost"],
    abstract_: "Set up iocost model and qos solutions for block devices.",
    argspec: &[],
    footer: None,
    man_pages: &["iocost.conf(5)"],
    verbs: VERBS,
};

thread_local! {
    static TARGET_SOLUTION: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn target() -> Vec<u8> {
    TARGET_SOLUTION.with(|t| t.borrow().clone())
}

/// `parse_config()`.
fn parse_config() -> i32 {
    let mut target: Option<Vec<u8>> = None;
    let mut lookup = |a: &Assign| -> Option<i32> {
        if a.section == Some(b"IOCost") && a.lvalue == b"TargetSolution" {
            target = if a.rvalue.is_empty() { None } else { Some(a.rvalue.to_vec()) };
            return Some(1);
        }
        None
    };
    let r = config_parse_path(b"/etc/udev/iocost.conf", Some(&["IOCost"]), CONFIG_PARSE_WARN, &mut lookup);
    if r < 0 {
        return r;
    }
    let t = target.unwrap_or_else(|| b"naive".to_vec());
    log_debug!("Target solution: ", &t[..]);
    TARGET_SOLUTION.with(|s| *s.borrow_mut() = t);
    0
}

/// `get_known_solutions()`: (solutions, selected index).
fn get_known_solutions(device: &Device, log_level: i32) -> Result<(Vec<Vec<u8>>, usize), i32> {
    let value = match device.get_property_value(b"IOCOST_SOLUTIONS") {
        Err(r) if r == -libc::ENOENT => {
            return Err(log_device_full_errno!(device, log_level, r, "No iocost solution found for device."));
        }
        Err(r) => {
            return Err(log_device_error_errno!(device, r, "Failed to query solutions from device: ", strerror(r)));
        }
        Ok(v) => v.bytes().to_vec(),
    };
    let s = shared::string::strv_split(&value, shared::string::WHITESPACE);
    if s.is_empty() {
        return Err(log_device_error_errno!(
            device,
            synthetic(libc::EINVAL),
            "IOCOST_SOLUTIONS exists in hwdb but is empty."
        ));
    }
    let t = target();
    let selected = match s.iter().position(|x| *x == t) {
        Some(i) => {
            log_device_debug!(device, "Selected solution based on target solution: ", &s[i][..]);
            i
        }
        None => {
            log_device_debug!(device, "Selected first available solution: ", &s[0][..]);
            0
        }
    };
    Ok((s, selected))
}

/// `query_named_solution()`: (model, qos).
fn query_named_solution(device: &Device, name: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let upper: Vec<u8> = name.iter().map(|c| if *c == b'-' { b'_' } else { c.to_ascii_uppercase() }).collect();
    let qos_key = shared::bcat!("IOCOST_QOS_", &upper[..]);
    let model_key = shared::bcat!("IOCOST_MODEL_", &upper[..]);
    let qos = match device.get_property_value(&qos_key) {
        Err(r) if r == -libc::ENOENT => {
            return Err(log_device_debug_errno!(
                device,
                r,
                "No value found for key ",
                &qos_key[..],
                ", skipping iocost logic."
            ));
        }
        Err(r) => {
            return Err(log_device_error_errno!(
                device,
                r,
                "Failed to obtain QoS for iocost solution from device: ",
                strerror(r)
            ));
        }
        Ok(v) => v.bytes().to_vec(),
    };
    let model = match device.get_property_value(&model_key) {
        Err(r) if r == -libc::ENOENT => {
            return Err(log_device_debug_errno!(
                device,
                r,
                "No value found for key ",
                &model_key[..],
                ", skipping iocost logic."
            ));
        }
        Err(r) => {
            return Err(log_device_error_errno!(
                device,
                r,
                "Failed to obtain model for iocost solution from device: ",
                strerror(r)
            ));
        }
        Ok(v) => v.bytes().to_vec(),
    };
    Ok((model, qos))
}

fn device_from_path(path: &[u8]) -> Result<Dev, i32> {
    Device::new_from_path(path).map_err(|r| log_error_errno!(r, "Error looking up device: ", strerror(r)))
}

/// `cg_set_attribute(NULL, attribute, value)`.
fn cg_set_attribute(attribute: &str, value: &[u8]) -> Result<(), i32> {
    use shared::fileio::{WRITE_STRING_FILE_DISABLE_BUFFER, WRITE_STRING_FILE_OPEN_NONBLOCKING};
    let p = shared::bcat!("/sys/fs/cgroup/", attribute);
    shared::fileio::write_string_file(&p, value, WRITE_STRING_FILE_DISABLE_BUFFER | WRITE_STRING_FILE_OPEN_NONBLOCKING)
}

/// `apply_solution_for_path()`.
fn apply_solution_for_path(path: &[u8], name: Option<&[u8]>) -> i32 {
    let device = match device_from_path(path) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let devnum = match device.get_devnum() {
        Ok(d) => d,
        Err(r) => return log_device_error_errno!(device, r, "Error getting devnum: ", strerror(r)),
    };
    let name = match name {
        Some(n) => n.to_vec(),
        None => match get_known_solutions(&device, LOG_DEBUG) {
            Err(r) if r == -libc::ENOENT => return 0,
            Err(r) => return r,
            Ok((s, i)) => s[i].clone(),
        },
    };
    let (model_params, qos_params) = match query_named_solution(&device, &name) {
        Err(r) if r == -libc::ENOENT => return 0,
        Err(r) => return r,
        Ok(x) => x,
    };
    let dn = shared::sd_device::devnum_format(devnum);
    let qos = shared::bcat!(&dn[..], " enable=1 ctrl=user ", &qos_params[..]);
    let model = shared::bcat!(&dn[..], " model=linear ctrl=user ", &model_params[..]);
    log_debug!(
        "Applying iocost parameters to ",
        path,
        " using solution '",
        &name[..],
        "'\n\tio.cost.qos: ",
        &qos[..],
        "\n\tio.cost.model: ",
        &model[..],
        "\n"
    );
    for (attr, v) in [("io.cost.qos", &qos), ("io.cost.model", &model)] {
        if let Err(r) = cg_set_attribute(attr, v) {
            log_device_full_errno!(
                device,
                if r == -libc::ENOENT { LOG_DEBUG } else { LOG_ERR },
                r,
                "Failed to set ",
                attr,
                ": ",
                strerror(r)
            );
            return if r == -libc::ENOENT { 0 } else { r };
        }
    }
    0
}

/// `query_solutions_for_path()`.
fn query_solutions_for_path(path: &[u8]) -> i32 {
    let device = match device_from_path(path) {
        Ok(d) => d,
        Err(r) => return r,
    };
    // device_get_model_string()
    let model_name = match ["ID_MODEL_FROM_DATABASE", "ID_MODEL"]
        .iter()
        .map(|f| device.get_property_value(f.as_bytes()))
        .find(|r| r.as_ref().err() != Some(&-libc::ENOENT))
    {
        None => {
            log_device_info!(device, "Device model not found");
            return 0;
        }
        Some(Err(r)) => {
            return log_device_error_errno!(device, r, "Model name for device ", path, " is unknown");
        }
        Some(Ok(m)) => m.bytes().to_vec(),
    };
    let (solutions, selected) = match get_known_solutions(&device, LOG_INFO) {
        Err(r) if r == -libc::ENOENT => return 0,
        Err(r) => return r,
        Ok(x) => x,
    };
    log_info!(
        "Known solutions for ",
        path,
        " model name: \"",
        &model_name[..],
        "\"\nPreferred solution: ",
        target(),
        "\nSolution that would be applied: ",
        &solutions[selected][..]
    );
    for s in &solutions {
        let Ok((model, qos)) = query_named_solution(&device, s) else { continue };
        log_info!(&s[..], ": io.cost.qos: ", &qos[..], "\n", &s[..], ": io.cost.model: ", &model[..]);
    }
    0
}

fn run(argv: Vec<Vec<u8>>) -> i32 {
    shared::log::log_setup();
    let mut opts = OptionParser::new(argv, COMMON_OPTIONS);
    loop {
        match opts.next() {
            Err(r) => return r,
            Ok(None) => break,
            Ok(Some(c)) => {
                if let Some(r) = common_option(c, &COMMAND, COMMON_OPTIONS) {
                    return r.min(0);
                }
            }
        }
    }
    let args = opts.args().to_vec();
    let r = parse_config();
    if r < 0 {
        return r;
    }
    let (verb, vargs) = match dispatch_verb(&args, VERBS) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match verb.verb {
        "query" => query_solutions_for_path(&vargs[1]),
        "apply" => apply_solution_for_path(&vargs[1], vargs.get(2).map(|v| &v[..])),
        _ => command_print_help(&COMMAND, COMMON_OPTIONS, None),
    }
}

fn main() {
    shared::main_func::main_with(run)
}
