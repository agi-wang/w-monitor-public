//! `/proc/meminfo` — memory and swap accounting.
//!
//! `sysinfo` covers totals on a live host, but products that want the raw kernel
//! numbers (or run where they only have `/proc`) re-parse `/proc/meminfo` by
//! hand. The kB→byte conversion and the `used = total - available` convention
//! are the bits everyone gets subtly different. Three shapes are offered so
//! every consumer adopts without changing its wire:
//! - [`MemInfo`] — typed bytes (the common case, incl. commit/dirty extras),
//! - [`MemInfoRaw`] — open key→KiB map (for consumers that emit `*_kib`),
//! - [`SysMem`] (feature `sysinfo`) — sysinfo's `used_memory()` semantics.

use crate::round2;
use std::collections::HashMap;

/// Memory and swap figures from `/proc/meminfo`, in **bytes**. The four
/// `Option` fields (commit/dirty/writeback) are `None` when the kernel didn't
/// report them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub commit_limit_bytes: Option<u64>,
    pub committed_as_bytes: Option<u64>,
    pub dirty_bytes: Option<u64>,
    pub writeback_bytes: Option<u64>,
}

impl MemInfo {
    /// Used = total − available (excluding reclaimable buffers/cache).
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }

    /// Used memory as a percentage of total, two decimals; `0.0` if total is 0.
    pub fn usage_percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        round2(self.used_bytes() as f64 / self.total_bytes as f64 * 100.0)
    }

    /// Used swap = swap total − swap free.
    pub fn swap_used_bytes(&self) -> u64 {
        self.swap_total_bytes.saturating_sub(self.swap_free_bytes)
    }

    /// Used swap as a percentage of swap total, two decimals; `0.0` if no swap.
    pub fn swap_usage_percent(&self) -> f64 {
        if self.swap_total_bytes == 0 {
            return 0.0;
        }
        round2(self.swap_used_bytes() as f64 / self.swap_total_bytes as f64 * 100.0)
    }

    /// Committed_AS / CommitLimit — overcommit pressure. `None` unless both
    /// fields were present and CommitLimit > 0.
    pub fn commit_ratio(&self) -> Option<f64> {
        match (self.committed_as_bytes, self.commit_limit_bytes) {
            (Some(c), Some(l)) if l > 0 => Some(round2(c as f64 / l as f64 * 100.0)),
            _ => None,
        }
    }
}

/// Parse `/proc/meminfo`. Returns `None` if `MemTotal` is missing. Lines are
/// `Key:   <number> kB`; the trailing `kB` unit is converted to bytes.
pub fn parse_meminfo(content: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut seen_total = false;
    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value_kb: u64 = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let bytes = value_kb.saturating_mul(1024);
        match key.trim() {
            "MemTotal" => {
                m.total_bytes = bytes;
                seen_total = true;
            }
            "MemFree" => m.free_bytes = bytes,
            "MemAvailable" => m.available_bytes = bytes,
            "Buffers" => m.buffers_bytes = bytes,
            "Cached" => m.cached_bytes = bytes,
            "SwapTotal" => m.swap_total_bytes = bytes,
            "SwapFree" => m.swap_free_bytes = bytes,
            "CommitLimit" => m.commit_limit_bytes = Some(bytes),
            "Committed_AS" => m.committed_as_bytes = Some(bytes),
            "Dirty" => m.dirty_bytes = Some(bytes),
            "Writeback" => m.writeback_bytes = Some(bytes),
            _ => {}
        }
    }
    seen_total.then_some(m)
}

/// Read and parse the live `/proc/meminfo`.
pub fn read_meminfo() -> Option<MemInfo> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|c| parse_meminfo(&c))
}

/// Every `/proc/meminfo` key → its raw **KiB** value (NOT multiplied by 1024).
/// For consumers that keep an open key set and emit `*_kib` wire fields, doing
/// the ×1024 only at render time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemInfoRaw(pub HashMap<String, u64>);

impl MemInfoRaw {
    /// Raw KiB for a key (e.g. `"MemTotal"`, `"Committed_AS"`).
    pub fn get_kib(&self, key: &str) -> Option<u64> {
        self.0.get(key).copied()
    }
    /// Bytes for a key (KiB × 1024).
    pub fn get_bytes(&self, key: &str) -> Option<u64> {
        self.get_kib(key).map(|k| k.saturating_mul(1024))
    }
    pub fn total_kib(&self) -> Option<u64> {
        self.get_kib("MemTotal")
    }
    pub fn available_kib(&self) -> Option<u64> {
        self.get_kib("MemAvailable")
    }
    pub fn committed_as_kib(&self) -> Option<u64> {
        self.get_kib("Committed_AS")
    }
    pub fn dirty_kib(&self) -> Option<u64> {
        self.get_kib("Dirty")
    }
}

/// Parse every `Key: <n> kB` line into an open KiB map.
pub fn parse_meminfo_raw(content: &str) -> MemInfoRaw {
    let mut map = HashMap::new();
    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some(v) = rest.split_whitespace().next().and_then(|v| v.parse().ok()) {
            map.insert(key.trim().to_string(), v);
        }
    }
    MemInfoRaw(map)
}

/// Read and parse the live `/proc/meminfo` as an open KiB map.
pub fn read_meminfo_raw() -> Option<MemInfoRaw> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|c| parse_meminfo_raw(&c))
}

/// Memory totals with `sysinfo`'s `used_memory()` semantics (NOT `total −
/// available`). Use this to preserve the numbers products already emit from
/// `sysinfo`. Requires the `sysinfo` feature.
#[cfg(feature = "sysinfo")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SysMem {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_free_bytes: u64,
}

#[cfg(feature = "sysinfo")]
impl SysMem {
    /// Build from a refreshed `sysinfo::System` (bytes throughout).
    pub fn from_sysinfo(sys: &sysinfo::System) -> Self {
        SysMem {
            total_bytes: sys.total_memory(),
            used_bytes: sys.used_memory(),
            available_bytes: sys.available_memory(),
            free_bytes: sys.free_memory(),
            swap_total_bytes: sys.total_swap(),
            swap_used_bytes: sys.used_swap(),
            swap_free_bytes: sys.free_swap(),
        }
    }

    /// Alternative "used = total − available" figure for consumers that prefer
    /// the canonical convention over sysinfo's `used_memory()`.
    pub fn used_from_available(&self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }
}
