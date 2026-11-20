// SPDX-License-Identifier: LGPL-2.1-or-later
//! The IRQ affinity part of `link-config.c`: `IRQAffinityPolicy=single`
//! and `spread`, over the CPU topology.

use shared::cpu_set::CpuSet;
use shared::errno::strerror;
use shared::log::{LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_WARNING};
use shared::sd_device::Device;
use shared::{log_debug_errno, log_device_debug_errno, log_interface};

use super::link::Link;

macro_rules! log_link {
    ($link:expr, $level:expr, $err:expr, $($e:expr),* $(,)?) => {
        log_interface!(Some(&$link.ifname[..]), $level, $err, $($e),*)
    };
}

/// A `CPUTopology`.
#[derive(Debug, Clone, Copy)]
struct CpuTopology {
    cpu: u32,
    #[allow(dead_code)] // C keeps it too, unused by the selection
    numa_node: u32,
    package_id: u32,
    die_id: u32,
    core_id: u32,
    is_first_thread: bool,
}

/// `cpu_topology_get_first_thread()`.
fn first_thread(cpu_node: &Device) -> Result<u32, i32> {
    let c = cpu_node.get_sysattr_value(b"topology/thread_siblings_list")?.bytes().to_vec();
    let end = c.iter().position(|b| b == &b',' || b == &b'-').unwrap_or(c.len());
    shared::parse::safe_atou(&c[..end])
}

/// `assign_sequential_die_ids()`.
fn assign_sequential_die_ids(cpus: &mut [CpuTopology]) -> Result<(), i32> {
    cpus.sort_by_key(|c| c.cpu);
    let mut groups: Vec<Vec<u8>> = Vec::new();
    for cpu in cpus.iter_mut() {
        let node = Device::new_from_syspath(format!("/sys/devices/system/cpu/cpu{}", cpu.cpu).as_bytes())?;
        let Ok(l3) = node.get_sysattr_value(b"cache/index3/shared_cpu_list") else {
            cpu.die_id = cpu.package_id;
            continue;
        };
        let l3 = l3.bytes().to_vec();
        match groups.iter().position(|g| *g == l3) {
            Some(i) => cpu.die_id = i as u32,
            None => {
                cpu.die_id = groups.len() as u32;
                groups.push(l3);
            }
        }
    }
    Ok(())
}

/// `discover_cpu_topology()`.
fn discover_cpu_topology() -> Result<Vec<CpuTopology>, i32> {
    let parent = Device::new_from_syspath(b"/sys/devices/system/cpu")?;
    let mut cpus: Vec<CpuTopology> = Vec::new();
    let mut child = parent.get_child_first();
    while let Some((node, name)) = child {
        child = parent.get_child_next();
        let Some(n) = name.strip_prefix(b"cpu") else { continue };
        let cpu = match shared::parse::safe_atou(n) {
            Ok(c) => c,
            Err(r) => {
                log_debug_errno!(r, "Failed to convert ", n, " to unsigned, skipping: ", strerror(r));
                continue;
            }
        };
        match node.get_sysattr_unsigned_full(b"online", 0) {
            Err(r) if r == -libc::ENOENT => {}
            Err(_) | Ok(0) => continue,
            Ok(_) => {}
        }
        let topo = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
        if let Err(r) = shared::sys_net::access(topo.as_bytes(), libc::F_OK) {
            log_debug_errno!(r, "Failed to access ", &topo[..], ", ignoring: ", strerror(r));
            continue;
        }
        let numa_node = shared::cpu_set::numa_get_node_from_cpu(cpu).unwrap_or_else(|r| {
            log_debug_errno!(r, format!("Failed to get NUMA node for CPU {cpu}, assuming NUMA node 0: "), strerror(r));
            0
        });
        let package_id = node.get_sysattr_unsigned_full(b"topology/physical_package_id", 0).unwrap_or_else(|r| {
            log_device_debug_errno!(node, r, "Failed to get physical_package_id, assuming package ID 0: ", strerror(r));
            0
        });
        let core_id = node.get_sysattr_unsigned_full(b"topology/core_id", 0).unwrap_or_else(|r| {
            log_device_debug_errno!(node, r, format!("Failed to get core_id, assuming core ID {cpu}: "), strerror(r));
            cpu
        });
        let is_first_thread = first_thread(&node).map_or(true, |f| f == cpu);
        cpus.push(CpuTopology { cpu, numa_node, package_id, die_id: 0, core_id, is_first_thread });
    }
    if cpus.is_empty() {
        return Err(-libc::ENOENT);
    }
    assign_sequential_die_ids(&mut cpus)?;
    cpus.sort_by_key(|c| (c.die_id, c.core_id, c.cpu));
    Ok(cpus)
}

/// `equidist_permute()`.
fn equidist_permute(indices: &mut [usize]) {
    let n = indices.len();
    if n <= 1 {
        return;
    }
    let left_count = n.div_ceil(2);
    let mut left = indices[..left_count].to_vec();
    let mut right = indices[left_count..].to_vec();
    equidist_permute(&mut left);
    equidist_permute(&mut right);
    let (mut li, mut ri, mut ti) = (0, 0, 0);
    for i in 0..n {
        if i % 2 == 0 && li < left.len() {
            indices[ti] = left[li];
            li += 1;
        } else if ri < right.len() {
            indices[ti] = right[ri];
            ri += 1;
        } else if li < left.len() {
            indices[ti] = left[li];
            li += 1;
        } else {
            continue;
        }
        ti += 1;
    }
}

/// A `DieInfo`.
#[derive(Debug)]
struct DieInfo {
    die_id: u32,
    cpus: Vec<u32>,
    next_idx: usize,
}

/// `build_die_info()`.
fn build_die_info(topology: &[CpuTopology]) -> Vec<DieInfo> {
    let mut dies: Vec<DieInfo> = Vec::new();
    for t in topology.iter().filter(|t| t.is_first_thread) {
        match dies.iter_mut().find(|d| d.die_id == t.die_id) {
            Some(d) => d.cpus.push(t.cpu),
            None => dies.push(DieInfo { die_id: t.die_id, cpus: vec![t.cpu], next_idx: 0 }),
        }
    }
    for d in &mut dies {
        let mut idx: Vec<usize> = (0..d.cpus.len()).collect();
        equidist_permute(&mut idx);
        d.cpus = idx.iter().map(|&i| d.cpus[i]).collect();
    }
    dies
}

/// `select_spread_cpus()`.
fn select_spread_cpus(topology: &[CpuTopology], n_irqs: usize) -> Result<Vec<u32>, i32> {
    let mut dies = build_die_info(topology);
    if dies.is_empty() {
        return Err(-libc::ENOENT);
    }
    let mut order: Vec<usize> = (0..dies.len()).collect();
    equidist_permute(&mut order);
    let mut selected: Vec<u32> = Vec::new();
    let mut exhausted = 0;
    while selected.len() < n_irqs {
        let mut progress = false;
        for &o in &order {
            if selected.len() >= n_irqs {
                break;
            }
            let d = &mut dies[o];
            if d.next_idx >= d.cpus.len() {
                continue;
            }
            selected.push(d.cpus[d.next_idx]);
            d.next_idx += 1;
            progress = true;
            if d.next_idx >= d.cpus.len() {
                exhausted += 1;
            }
        }
        if progress {
            continue;
        }
        if exhausted < dies.len() {
            break;
        }
        for d in &mut dies {
            d.next_idx = 0;
        }
        exhausted = 0;
    }
    Ok(selected)
}

/// `set_irq_affinity()`.
fn set_irq_affinity(link: &Link, irq: u32, cpu: u32) {
    let path = format!("/proc/irq/{irq}/smp_affinity");
    let mut mask = format!("{:x}", 1u32 << (cpu % 32));
    for _ in 0..cpu / 32 {
        mask.push_str(",00000000");
    }
    match shared::fileio::write_string_file(
        path.as_bytes(),
        mask.as_bytes(),
        shared::fileio::WRITE_STRING_FILE_DISABLE_BUFFER,
    ) {
        Err(r) => {
            log_link!(link, LOG_WARNING, r, format!("Failed to set IRQ {irq} affinity to CPU {cpu}: "), strerror(r));
        }
        Ok(()) => {
            log_link!(link, LOG_DEBUG, 0, format!("Set IRQ {irq} affinity to CPU {cpu}."));
        }
    }
}

/// The IRQs in `device/msi_irqs`: None (after logging) to skip.
fn msi_irqs(link: &Link, dev: &Device, each: &mut dyn FnMut(u32)) -> Result<bool, i32> {
    let mut dir = match dev.opendir(Some(b"device/msi_irqs")) {
        Ok(d) => d,
        Err(r) => {
            if r != -libc::ENOENT {
                return Err(log_link!(link, LOG_ERR, r, "Failed to open device/msi_irqs: ", strerror(r)));
            }
            log_link!(link, LOG_DEBUG, r, "No MSI IRQs found, skipping IRQ affinity configuration: ", strerror(r));
            return Ok(false);
        }
    };
    loop {
        match shared::conf_files::foreach_dirent(&mut dir) {
            Err(r) => {
                return Err(log_link!(link, LOG_ERR, r, "Failed to read directory device/msi_irqs: ", strerror(r)));
            }
            Ok(None) => break,
            Ok(Some((name, _))) => match shared::parse::safe_atou(&name) {
                Err(r) => {
                    return Err(log_link!(link, LOG_ERR, r, "Failed to convert parse IRQ number: ", &name[..]));
                }
                Ok(irq) => each(irq),
            },
        }
    }
    Ok(true)
}

/// `link_apply_irq_affinity_spread()`.
pub fn apply_spread(link: &Link, dev: &Device, allowed: Option<&CpuSet>) -> Result<(), i32> {
    let mut irqs: Vec<u32> = Vec::new();
    if !msi_irqs(link, dev, &mut |i| irqs.push(i))? {
        return Ok(());
    }
    if irqs.is_empty() {
        log_link!(link, LOG_DEBUG, 0, "No IRQs found, skipping spread.");
        return Ok(());
    }
    irqs.sort_unstable();
    let mut topology = discover_cpu_topology()
        .map_err(|r| log_link!(link, LOG_ERR, r, "Failed to discover CPU topology: ", strerror(r)))?;
    if let Some(a) = allowed.filter(|a| a.is_set()) {
        let all = topology.len();
        let filtered: Vec<CpuTopology> = topology.iter().copied().filter(|t| a.contains(t.cpu as usize)).collect();
        if filtered.is_empty() {
            log_link!(link, LOG_WARNING, 0, "IRQAffinity= filter excludes all CPUs, skipping spread.");
            return Ok(());
        }
        log_link!(
            link,
            LOG_DEBUG,
            0,
            format!("Filtered to {} CPUs (from {all}) based on IRQAffinity=.", filtered.len())
        );
        topology = filtered;
    }
    log_link!(link, LOG_DEBUG, 0, format!("Spreading {} IRQs across {} CPUs.", irqs.len(), topology.len()));
    let spread = select_spread_cpus(&topology, irqs.len())
        .map_err(|r| log_link!(link, LOG_ERR, r, "Failed to select spread CPUs: ", strerror(r)))?;
    for (i, cpu) in spread.iter().enumerate() {
        set_irq_affinity(link, irqs[i], *cpu);
    }
    log_link!(
        link,
        LOG_INFO,
        0,
        format!(
            "Applied IRQ affinity policy 'spread' across {} CPUs for {} IRQs.",
            topology.len().min(irqs.len()),
            irqs.len()
        )
    );
    Ok(())
}

/// `link_apply_irq_affinity_single()`.
pub fn apply_single(link: &Link, dev: &Device, allowed: Option<&CpuSet>) -> Result<(), i32> {
    let mut target = 0u32;
    if let Some(a) = allowed.filter(|a| a.is_set()) {
        match (0..a.allocated() * 8).find(|&c| a.contains(c)) {
            Some(c) => target = c as u32,
            None => {
                log_link!(link, LOG_WARNING, 0, "IRQAffinity= filter excludes all CPUs, skipping single.");
                return Ok(());
            }
        }
    }
    if !msi_irqs(link, dev, &mut |irq| set_irq_affinity(link, irq, target))? {
        return Ok(());
    }
    log_link!(link, LOG_INFO, 0, format!("Applied IRQ affinity policy 'single' (pinning to CPU {target})."));
    Ok(())
}
