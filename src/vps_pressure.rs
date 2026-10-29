//! VPS pressure collector.
//!
//! The host-metric *collection* (PSI parsing, /proc/stat steal+iowait deltas,
//! busiest-device disk deltas, virtualization detection) now lives in the shared
//! `w-hostmetrics` crate — this file is the W-Monitor **shim** that samples
//! through that crate, keeps the per-interval counter cache, and maps the typed
//! samples onto the exact `schema_version: 2` JSON the dashboard already
//! consumes. Keeping `build_vps_pressure_report` here means the wire contract is
//! owned by w-monitor and cannot drift when the collection logic is shared.

use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use sysinfo::System;

use w_hostmetrics::{cpu, disk, loadavg, pressure, round2, virt};

#[derive(Debug, Clone)]
struct VpsPressureInput {
    logical_cores: usize,
    load: Option<loadavg::LoadAvg>,
    cpu_delta: Option<cpu::CpuDelta>,
    cpu_pressure: Option<pressure::PressureStall>,
    memory_pressure: Option<pressure::PressureStall>,
    io_pressure: Option<pressure::PressureStall>,
    disk_delta: disk::DiskDelta,
    memory_available_percent: Option<f64>,
    swap_usage_percent: Option<f64>,
    virtualization: virt::Virtualization,
}

#[derive(Debug, Clone)]
struct CachedCounters {
    collected_at: Instant,
    cpu: Option<cpu::CpuTotals>,
    disks: HashMap<String, disk::DiskIoTotals>,
}

static COUNTER_CACHE: OnceLock<Mutex<Option<CachedCounters>>> = OnceLock::new();
static VIRTUALIZATION_CACHE: OnceLock<virt::Virtualization> = OnceLock::new();

pub fn collect_vps_pressure(sys: &Arc<Mutex<System>>) -> Value {
    let now = Instant::now();
    let cpu_totals = cpu::read_cpu_totals();
    let disks = read_disk_totals();
    let (cpu_delta, disk_delta) = sample_deltas(cpu_totals, disks, now);
    let (logical_cores, memory_available_percent, swap_usage_percent) = {
        let s = sys.lock();
        let total = s.total_memory();
        let available = s.available_memory();
        let swap_total = s.total_swap();
        let swap_used = s.used_swap();
        (
            s.cpus().len().max(1),
            if total > 0 {
                Some(round2(available as f64 / total as f64 * 100.0))
            } else {
                None
            },
            if swap_total > 0 {
                Some(round2(swap_used as f64 / swap_total as f64 * 100.0))
            } else {
                None
            },
        )
    };

    build_vps_pressure_report(VpsPressureInput {
        logical_cores,
        load: loadavg::read_loadavg().or_else(|| {
            let load = System::load_average();
            Some(loadavg::LoadAvg {
                one: load.one,
                five: load.five,
                fifteen: load.fifteen,
                running: 0,
                total_threads: 0,
            })
        }),
        cpu_delta,
        cpu_pressure: pressure::read_pressure("/proc/pressure/cpu"),
        memory_pressure: pressure::read_pressure("/proc/pressure/memory"),
        io_pressure: pressure::read_pressure("/proc/pressure/io"),
        disk_delta,
        memory_available_percent,
        swap_usage_percent,
        virtualization: VIRTUALIZATION_CACHE
            .get_or_init(virt::detect_virtualization)
            .clone(),
    })
}

/// Read /proc/diskstats into the shared typed totals (loop/ram/fd/sr skipped).
fn read_disk_totals() -> HashMap<String, disk::DiskIoTotals> {
    match std::fs::read_to_string("/proc/diskstats") {
        Ok(content) => disk::parse_diskstats(&content),
        Err(_) => HashMap::new(),
    }
}

fn sample_deltas(
    cpu_totals: Option<cpu::CpuTotals>,
    disks: HashMap<String, disk::DiskIoTotals>,
    now: Instant,
) -> (Option<cpu::CpuDelta>, disk::DiskDelta) {
    let cache = COUNTER_CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock();
    let previous = guard.take();

    let result = if let Some(prev) = previous {
        (
            prev.cpu
                .as_ref()
                .zip(cpu_totals.as_ref())
                .and_then(|(a, b)| cpu::calculate_cpu_delta(a, b)),
            disk::calculate_disk_delta(&prev.disks, &disks, now.duration_since(prev.collected_at)),
        )
    } else {
        (
            None,
            disk::DiskDelta {
                max_io_in_progress: disks.values().map(|d| d.io_in_progress).max().unwrap_or(0),
                ..disk::DiskDelta::default()
            },
        )
    };

    *guard = Some(CachedCounters {
        collected_at: now,
        cpu: cpu_totals,
        disks,
    });
    result
}

/// Canonical machine class for fleet filtering / badges.
///
/// Precedence: container runtime markers win over bare hypervisor signals so a
/// container-on-VM host is still classified as `container` (the visible guest
/// boundary for this agent). Pure VMs report `vm`. Everything else is
/// `physical` (including hosts where DMI is absent and no hypervisor flag is
/// set — common for bare metal and some ARM boards).
pub(crate) fn classify_machine_kind(virt: &virt::Virtualization) -> &'static str {
    if virt.container
        || virt
            .detected
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("container"))
    {
        "container"
    } else if virt.hypervisor_flag || virt.detected.is_some() {
        "vm"
    } else {
        "physical"
    }
}

fn collector_note_for_kind(kind: &str) -> &'static str {
    match kind {
        "physical" => {
            "Bare-metal host metrics. Steal/PSI still apply under cgroup or power limits; no oversell verdict."
        }
        "container" => {
            "Container-scoped metrics only; host oversell and sibling guests are not visible. No oversell verdict."
        }
        _ => {
            "VM-internal metrics only; host oversell ratio is not readable from the guest. No oversell verdict."
        }
    }
}

fn build_vps_pressure_report(input: VpsPressureInput) -> Value {
    let cores = input.logical_cores.max(1) as f64;
    let load_per_core_1m = input.load.map(|l| round2(l.one / cores));
    let run_queue_per_core = input
        .load
        .and_then(|l| (l.running > 0).then(|| round2(l.running as f64 / cores)));
    let cpu_psi_some_avg10 = input
        .cpu_pressure
        .and_then(|p| p.some)
        .map(|line| round2(line.avg10));
    let cpu_psi_full_avg10 = input
        .cpu_pressure
        .and_then(|p| p.full)
        .map(|line| round2(line.avg10));
    let memory_psi_some_avg10 = input
        .memory_pressure
        .and_then(|p| p.some)
        .map(|line| round2(line.avg10));
    let memory_psi_full_avg10 = input
        .memory_pressure
        .and_then(|p| p.full)
        .map(|line| round2(line.avg10));
    let io_psi_some_avg10 = input
        .io_pressure
        .and_then(|p| p.some)
        .map(|line| round2(line.avg10));
    let io_psi_full_avg10 = input
        .io_pressure
        .and_then(|p| p.full)
        .map(|line| round2(line.avg10));
    let cpu_steal_percent = input.cpu_delta.map(|d| d.steal_percent);
    let cpu_iowait_percent = input.cpu_delta.map(|d| d.iowait_percent);
    let machine_kind = classify_machine_kind(&input.virtualization);
    let platform = input.virtualization.detected.clone();
    let is_virtual = input.virtualization.is_virtual();
    let container_label = input.virtualization.container_kind.clone().or_else(|| {
        input
            .virtualization
            .container
            .then(|| "container".to_string())
    });

    json!({
        "schema_version": 2,
        // First-class class for fleet list / filters (physical | vm | container).
        "machine_kind": machine_kind,
        "sample": {
            "logical_cores": input.logical_cores,
            "cpu_steal_percent": cpu_steal_percent,
            "cpu_iowait_percent": cpu_iowait_percent,
            "cpu_psi_some_avg10": cpu_psi_some_avg10,
            "cpu_psi_full_avg10": cpu_psi_full_avg10,
            "memory_psi_some_avg10": memory_psi_some_avg10,
            "memory_psi_full_avg10": memory_psi_full_avg10,
            "io_psi_some_avg10": io_psi_some_avg10,
            "io_psi_full_avg10": io_psi_full_avg10,
            "load_per_core_1m": load_per_core_1m,
            "run_queue_per_core": run_queue_per_core,
            "load_avg": input.load.map(|l| json!({
                "one": round2(l.one),
                "five": round2(l.five),
                "fifteen": round2(l.fifteen),
                "running": l.running,
                "total_threads": l.total_threads,
            })),
            "disk_busy_percent": input.disk_delta.max_busy_percent,
            "disk_weighted_io_ms_per_sec": input.disk_delta.max_weighted_io_ms_per_sec,
            "disk_max_io_in_progress": input.disk_delta.max_io_in_progress,
            "memory_available_percent": input.memory_available_percent,
            "swap_usage_percent": input.swap_usage_percent,
        },
        // Canonical probe result from w-hostmetrics (string platform name in `detected`).
        "virtualization": {
            "detected": platform,
            "hypervisor_flag": input.virtualization.hypervisor_flag,
            "container": input.virtualization.container,
            "container_kind": input.virtualization.container_kind,
            "sys_vendor": input.virtualization.sys_vendor,
            "product_name": input.virtualization.product_name,
            "product_version": input.virtualization.product_version,
            "machine_kind": machine_kind,
        },
        // Legacy SPA shape (boolean `detected` + `hypervisor` string). Keep both so
        // older dashboards and the current Metrics tab stay correct.
        "virt": {
            "detected": is_virtual,
            "hypervisor": input.virtualization.detected,
            "container": container_label,
            "sys_vendor": input.virtualization.sys_vendor,
            "product_name": input.virtualization.product_name,
            "machine_kind": machine_kind,
        },
        "collector_note": collector_note_for_kind(machine_kind),
    })
}
