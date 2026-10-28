//! # w-hostmetrics
//!
//! Canonical host/system metrics collection for the W fleet.
//!
//! Every product that watches a host re-implements the same `/proc` parsers,
//! CPU/disk delta math, PSI pressure reading, virtualization detection,
//! `nvidia-smi` scraping and network-rate counters. W-Monitor's agent had the
//! most battle-tested versions (timeout guards, counter-wraparound protection,
//! `statvfs` inode accounting) — this crate is that logic, extracted as the one
//! source of truth and exposed as **typed samples** instead of ad-hoc
//! `serde_json::Value`. Consumers map the structs onto whatever wire shape they
//! already emit.
//!
//! The crate is dependency-light on purpose (`std` + `libc` on unix, optional
//! `serde`): CLIs, agents, Tauri surfaces and axum servers can all depend on it
//! without dragging in tokio/axum.
//!
//! ## Modules
//! - [`cpu`] — `/proc/stat` totals; steal/iowait/usage/idle deltas.
//! - [`cpuinfo`] — static CPU identity (model/vendor/MHz/flags) from `/proc/cpuinfo`.
//! - [`memory`] — `/proc/meminfo` (typed bytes, open KiB map, commit/dirty); `SysMem` (feature `sysinfo`).
//! - [`pressure`] — `/proc/pressure/*` PSI some/full lines (tolerant + strict parsers).
//! - [`loadavg`] — `/proc/loadavg` including the runnable/total entity counts.
//! - [`disk`] — `/proc/diskstats` IO totals + full throughput, busy% deltas,
//!   `statvfs` space + inodes; `list_mounts` (feature `sysinfo-disks`).
//! - [`virt`] — virtualization / cloud-vendor detection (DMI table + optional
//!   `systemd-detect-virt`, configurable via [`virt::VirtOptions`]).
//! - [`gpu`] — `nvidia-smi` runtime CSV; compute-apps; static props ([`gpu::props`], feature `gpu-props`).
//! - [`net`] — per-interface byte-counter → bytes/sec with reset protection.
//! - [`host`] — static host identity (hostname/uptime/os/kernel/arch).
//!
//! ## Features
//! `serde` (default), `sysinfo` (live `SysMem`/host info), `sysinfo-disks`
//! (mount enumeration), `sampling` (blocking CPU sampler), `gpu-props`.

pub mod cpu;
pub mod cpuinfo;
pub mod disk;
pub mod gpu;
pub mod host;
pub mod loadavg;
pub mod memory;
pub mod net;
pub mod pressure;
pub mod virt;

/// Round a float to two decimals — the fleet-wide convention for percentages.
#[inline]
pub fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Round a float to one decimal — used for temperatures and GPU memory percent.
#[inline]
pub fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}
