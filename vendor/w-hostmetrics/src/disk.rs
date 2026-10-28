//! `/proc/diskstats` IO totals + busy/weighted-IO deltas, and `statvfs` inodes.

use crate::round2;
use std::collections::HashMap;
use std::time::Duration;

/// The three `/proc/diskstats` counters used for saturation signals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiskIoTotals {
    /// IOs currently in progress (field 9 / column 12).
    pub io_in_progress: u64,
    /// Milliseconds spent doing IO (field 10 / column 13).
    pub io_time_ms: u64,
    /// Weighted milliseconds spent doing IO (field 11 / column 14).
    pub weighted_io_time_ms: u64,
}

/// Busiest-device deltas across a sampling interval.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiskDelta {
    pub max_busy_percent: Option<f64>,
    pub max_weighted_io_ms_per_sec: Option<f64>,
    pub max_io_in_progress: u64,
}

/// Whether a `/proc/diskstats` device name should be ignored (virtual/removable
/// pseudo-devices that aren't real backing storage).
pub fn skip_disk_device(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("fd")
        || name.starts_with("sr")
}

/// Parse `/proc/diskstats` into per-device IO totals, skipping pseudo-devices.
pub fn parse_diskstats(content: &str) -> HashMap<String, DiskIoTotals> {
    let mut disks = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let name = parts[2];
        if skip_disk_device(name) {
            continue;
        }
        disks.insert(
            name.to_string(),
            DiskIoTotals {
                io_in_progress: parts[11].parse().unwrap_or(0),
                io_time_ms: parts[12].parse().unwrap_or(0),
                weighted_io_time_ms: parts[13].parse().unwrap_or(0),
            },
        );
    }
    disks
}

/// Busiest-device busy% and weighted-IO/sec between two samples taken `elapsed`
/// apart. `max_io_in_progress` always reflects the latest sample. Counter resets
/// are absorbed by saturating subtraction; a non-positive interval yields only
/// the queue depth.
pub fn calculate_disk_delta(
    prev: &HashMap<String, DiskIoTotals>,
    next: &HashMap<String, DiskIoTotals>,
    elapsed: Duration,
) -> DiskDelta {
    let mut delta = DiskDelta {
        max_io_in_progress: next.values().map(|d| d.io_in_progress).max().unwrap_or(0),
        ..DiskDelta::default()
    };
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_ms <= 0.0 || elapsed_secs <= 0.0 {
        return delta;
    }
    for (name, cur) in next {
        let Some(old) = prev.get(name) else {
            continue;
        };
        let busy = cur.io_time_ms.saturating_sub(old.io_time_ms) as f64 / elapsed_ms * 100.0;
        let weighted = cur
            .weighted_io_time_ms
            .saturating_sub(old.weighted_io_time_ms) as f64
            / elapsed_secs;
        delta.max_busy_percent = Some(
            delta
                .max_busy_percent
                .map(|v| v.max(round2(busy)))
                .unwrap_or_else(|| round2(busy)),
        );
        delta.max_weighted_io_ms_per_sec = Some(
            delta
                .max_weighted_io_ms_per_sec
                .map(|v| v.max(round2(weighted)))
                .unwrap_or_else(|| round2(weighted)),
        );
    }
    delta
}

/// Inode accounting for one filesystem.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Inodes {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub usage_percent: f64,
}

/// Build inode usage from raw `statvfs` counts (`f_files`, `f_ffree`).
/// `None` when the filesystem reports no inodes (e.g. many FUSE/network FSes).
pub fn inodes_from_counts(f_files: u64, f_ffree: u64) -> Option<Inodes> {
    if f_files == 0 {
        return None;
    }
    let used = f_files.saturating_sub(f_ffree);
    Some(Inodes {
        total: f_files,
        used,
        free: f_ffree,
        usage_percent: round2(used as f64 / f_files as f64 * 100.0),
    })
}

/// Live inode usage for a mount point via `statvfs(3)`.
#[cfg(unix)]
pub fn inode_usage(mount_point: &str) -> Option<Inodes> {
    statvfs_raw(mount_point).and_then(|s| inodes_from_counts(s.f_files, s.f_ffree))
}

// ─── 0.2.0 superset additions ───────────────────────────────────────────────

/// Bytes per disk sector reported by `/proc/diskstats` (always 512, regardless
/// of physical sector size).
pub const SECTOR_BYTES: u64 = 512;

/// Convert a `/proc/diskstats` sector count to bytes.
pub fn sectors_to_bytes(sectors: u64) -> u64 {
    sectors.saturating_mul(SECTOR_BYTES)
}

/// Which `/proc/diskstats` devices to skip. `pseudo` = loop/ram/fd/sr;
/// `dm` = device-mapper (`dm-*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSkip {
    pub pseudo: bool,
    pub dm: bool,
}

impl Default for DeviceSkip {
    fn default() -> Self {
        DeviceSkip {
            pseudo: true,
            dm: false,
        }
    }
}

impl DeviceSkip {
    fn skips(&self, name: &str) -> bool {
        (self.pseudo && skip_disk_device(name)) || (self.dm && name.starts_with("dm-"))
    }
}

/// Full per-device counters from `/proc/diskstats` (read/write completions +
/// sectors, in-flight, IO time). Superset of [`DiskIoTotals`] for consumers that
/// want throughput, not just saturation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiskRawStats {
    pub reads_completed: u64,
    pub reads_sectors: u64,
    pub writes_completed: u64,
    pub writes_sectors: u64,
    pub io_in_progress: u64,
    pub io_time_ms: u64,
    pub weighted_io_time_ms: u64,
}

impl DiskRawStats {
    pub fn read_bytes(&self) -> u64 {
        sectors_to_bytes(self.reads_sectors)
    }
    pub fn write_bytes(&self) -> u64 {
        sectors_to_bytes(self.writes_sectors)
    }
}

/// Parse `/proc/diskstats` into full per-device counters, honouring `skip`.
pub fn parse_diskstats_full(content: &str, skip: DeviceSkip) -> HashMap<String, DiskRawStats> {
    let mut disks = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let name = parts[2];
        if skip.skips(name) {
            continue;
        }
        disks.insert(
            name.to_string(),
            DiskRawStats {
                reads_completed: parts[3].parse().unwrap_or(0),
                reads_sectors: parts[5].parse().unwrap_or(0),
                writes_completed: parts[7].parse().unwrap_or(0),
                writes_sectors: parts[9].parse().unwrap_or(0),
                io_in_progress: parts[11].parse().unwrap_or(0),
                io_time_ms: parts[12].parse().unwrap_or(0),
                weighted_io_time_ms: parts[13].parse().unwrap_or(0),
            },
        );
    }
    disks
}

/// Raw `statvfs(3)` counts (all `u64`). One syscall feeds both space and inode
/// views — call [`statvfs_raw`] once and derive both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StatvfsRaw {
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_frsize: u64,
    pub f_files: u64,
    pub f_ffree: u64,
}

/// One `statvfs(3)` call for a mount point.
#[cfg(unix)]
pub fn statvfs_raw(mount_point: &str) -> Option<StatvfsRaw> {
    let cpath = std::ffi::CString::new(mount_point.as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some(StatvfsRaw {
        f_blocks: s.f_blocks as u64,
        f_bfree: s.f_bfree as u64,
        f_bavail: s.f_bavail as u64,
        f_frsize: s.f_frsize as u64,
        f_files: s.f_files as u64,
        f_ffree: s.f_ffree as u64,
    })
}

/// Space usage for a filesystem, in bytes. `used = total − available` (the
/// non-root-reserved `f_bavail` view that matches `df`'s Avail column).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpaceUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

/// Build [`SpaceUsage`] from raw statvfs counts.
pub fn space_from_statvfs(s: &StatvfsRaw) -> SpaceUsage {
    let total = s.f_blocks.saturating_mul(s.f_frsize);
    let available = s.f_bavail.saturating_mul(s.f_frsize);
    let used = total.saturating_sub(available);
    let usage_percent = if total > 0 {
        round2(used as f64 / total as f64 * 100.0)
    } else {
        0.0
    };
    SpaceUsage {
        total_bytes: total,
        used_bytes: used,
        available_bytes: available,
        usage_percent,
    }
}

/// Both space and inode usage for a mount point from a single `statvfs` call.
#[cfg(unix)]
pub fn mount_metrics(mount_point: &str) -> Option<(SpaceUsage, Option<Inodes>)> {
    let s = statvfs_raw(mount_point)?;
    Some((
        space_from_statvfs(&s),
        inodes_from_counts(s.f_files, s.f_ffree),
    ))
}

/// Live space usage for one mount point.
#[cfg(unix)]
pub fn space_usage(mount_point: &str) -> Option<SpaceUsage> {
    statvfs_raw(mount_point).map(|s| space_from_statvfs(&s))
}

/// `(available_bytes, total_bytes)` for a path — the figures disk-guard /
/// retention loops want. Terminates the inline statvfs re-implementations in
/// disk_guard.rs / ingest.rs / omni-nvr storage routes.
#[cfg(unix)]
pub fn free_space_bytes(path: &str) -> Option<(u64, u64)> {
    space_usage(path).map(|u| (u.available_bytes, u.total_bytes))
}

// ─── live mount enumeration (feature `sysinfo-disks`) ───────────────────────

/// One real mounted filesystem.
#[cfg(feature = "sysinfo-disks")]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MountEntry {
    pub mount_point: String,
    pub name: String,
    pub fs_type: String,
    pub space: SpaceUsage,
    pub inodes: Option<Inodes>,
    pub is_removable: bool,
}

/// Which mounts to keep when enumerating. Defaults reproduce W-Monitor's
/// `collect_disk` filter: drop overlay/snap/pseudo filesystems, sub-gigabyte
/// mounts, and zero-size devices.
#[cfg(feature = "sysinfo-disks")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountFilter {
    pub min_bytes: u64,
    pub exclude_pseudo_fs: bool,
    pub exclude_path_prefixes: Vec<String>,
}

#[cfg(feature = "sysinfo-disks")]
impl Default for MountFilter {
    fn default() -> Self {
        MountFilter {
            min_bytes: 1_073_741_824, // 1 GiB
            exclude_pseudo_fs: true,
            exclude_path_prefixes: vec!["/snap/".into(), "/docker/overlay2/".into()],
        }
    }
}

#[cfg(feature = "sysinfo-disks")]
impl MountFilter {
    fn keep(&self, mount: &str, fs: &str, name: &str, total: u64) -> bool {
        if total < self.min_bytes || name == "overlay" {
            return false;
        }
        if self.exclude_pseudo_fs
            && (fs.contains("tmpfs")
                || fs.contains("devtmpfs")
                || fs.contains("proc")
                || fs.contains("sysfs"))
        {
            return false;
        }
        !self
            .exclude_path_prefixes
            .iter()
            .any(|p| mount.starts_with(p.as_str()))
    }
}

/// Enumerate real mounted filesystems via `sysinfo::Disks`, deriving space from
/// `sysinfo` totals and inodes from `statvfs`. De-duplicates by mount point.
#[cfg(feature = "sysinfo-disks")]
pub fn list_mounts(filter: &MountFilter) -> Vec<MountEntry> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for disk in disks.list() {
        let mount = disk.mount_point().to_string_lossy().to_string();
        let name = disk.name().to_string_lossy().to_string();
        let fs = format!("{:?}", disk.file_system());
        let total = disk.total_space();
        if !filter.keep(&mount, &fs, &name, total) || !seen.insert(mount.clone()) {
            continue;
        }
        let available = disk.available_space();
        let used = total.saturating_sub(available);
        let usage_percent = if total > 0 {
            round2(used as f64 / total as f64 * 100.0)
        } else {
            0.0
        };
        out.push(MountEntry {
            inodes: inode_usage(&mount),
            space: SpaceUsage {
                total_bytes: total,
                used_bytes: used,
                available_bytes: available,
                usage_percent,
            },
            mount_point: mount,
            name,
            fs_type: fs,
            is_removable: disk.is_removable(),
        });
    }
    out
}

/// Sum a set of mounts into one space figure.
#[cfg(feature = "sysinfo-disks")]
pub fn aggregate(entries: &[MountEntry]) -> SpaceUsage {
    let total: u64 = entries.iter().map(|e| e.space.total_bytes).sum();
    let available: u64 = entries.iter().map(|e| e.space.available_bytes).sum();
    let used = total.saturating_sub(available);
    SpaceUsage {
        total_bytes: total,
        used_bytes: used,
        available_bytes: available,
        usage_percent: if total > 0 {
            round2(used as f64 / total as f64 * 100.0)
        } else {
            0.0
        },
    }
}
