//! `/proc/stat` aggregate CPU totals and steal/iowait deltas.

use crate::round2;

/// The ten jiffy counters from the aggregate `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuTotals {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

impl CpuTotals {
    /// Sum of all jiffy counters — the denominator for delta percentages.
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
            + self.guest
            + self.guest_nice
    }
}

/// Percentages computed between two `/proc/stat` samples. steal%/iowait% reveal
/// a noisy-neighbour / oversold VM; usage%/idle% are the headline busy figures.
/// `usage = (total - idle - iowait) / total` (iowait is excluded from busy, so
/// the four fields do NOT sum to 100) — matching the fleet's convention.
///
/// Note: 0.2.0 added `usage_percent`/`idle_percent`. Construct with
/// `..Default::default()` if you build it by literal (kept literal-constructible
/// on purpose so consumers can still make one in tests).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuDelta {
    pub steal_percent: f64,
    pub iowait_percent: f64,
    pub usage_percent: f64,
    pub idle_percent: f64,
}

/// Parse the aggregate `cpu` line out of full `/proc/stat` contents.
/// `iowait`/`irq`/`softirq`/`steal` are tolerated as missing on old kernels.
pub fn parse_proc_stat(content: &str) -> Option<CpuTotals> {
    let line = content
        .lines()
        .find(|l| l.split_whitespace().next() == Some("cpu"))?;
    let mut parts = line.split_whitespace();
    parts.next(); // consume the "cpu" label
    Some(CpuTotals {
        user: parts.next()?.parse().ok()?,
        nice: parts.next()?.parse().ok()?,
        system: parts.next()?.parse().ok()?,
        idle: parts.next()?.parse().ok()?,
        iowait: parts.next().unwrap_or("0").parse().ok()?,
        irq: parts.next().unwrap_or("0").parse().ok()?,
        softirq: parts.next().unwrap_or("0").parse().ok()?,
        steal: parts.next().unwrap_or("0").parse().ok()?,
        guest: parts.next().unwrap_or("0").parse().unwrap_or(0),
        guest_nice: parts.next().unwrap_or("0").parse().unwrap_or(0),
    })
}

fn cpu_delta_core(prev: &CpuTotals, next: &CpuTotals) -> Option<CpuDelta> {
    let total_delta = next.total().checked_sub(prev.total())?;
    if total_delta == 0 {
        return None;
    }
    let td = total_delta as f64;
    let idle_delta = next.idle.saturating_sub(prev.idle);
    let iowait_delta = next.iowait.saturating_sub(prev.iowait);
    let steal_delta = next.steal.saturating_sub(prev.steal);
    let busy_delta = total_delta
        .saturating_sub(idle_delta)
        .saturating_sub(iowait_delta);
    Some(CpuDelta {
        steal_percent: steal_delta as f64 / td * 100.0,
        iowait_percent: iowait_delta as f64 / td * 100.0,
        usage_percent: busy_delta as f64 / td * 100.0,
        idle_percent: idle_delta as f64 / td * 100.0,
    })
}

/// steal%/iowait%/usage%/idle% between two samples, each rounded to two decimals
/// (the fleet wire convention). `None` when the interval has no elapsed jiffies,
/// or when the counters went backwards (reboot / counter reset).
pub fn calculate_cpu_delta(prev: &CpuTotals, next: &CpuTotals) -> Option<CpuDelta> {
    cpu_delta_core(prev, next).map(|d| CpuDelta {
        steal_percent: round2(d.steal_percent),
        iowait_percent: round2(d.iowait_percent),
        usage_percent: round2(d.usage_percent),
        idle_percent: round2(d.idle_percent),
    })
}

/// Same as [`calculate_cpu_delta`] but UN-rounded — for consumers (e.g.
/// obscura-inspector) that do their own formatting and need byte-identical
/// numbers to their previous hand-rolled math.
pub fn calculate_cpu_delta_raw(prev: &CpuTotals, next: &CpuTotals) -> Option<CpuDelta> {
    cpu_delta_core(prev, next)
}

/// Read `/proc/stat`, sleep `window` (capped at 10s), read again, return the
/// UN-rounded delta. Convenience for one-shot samplers that don't keep a
/// cross-tick counter cache. Requires the `sampling` feature.
#[cfg(feature = "sampling")]
pub fn sample_cpu_delta(window: std::time::Duration) -> Option<CpuDelta> {
    let prev = read_cpu_totals()?;
    std::thread::sleep(window.min(std::time::Duration::from_secs(10)));
    let next = read_cpu_totals()?;
    calculate_cpu_delta_raw(&prev, &next)
}

/// Read and parse the live `/proc/stat`.
pub fn read_cpu_totals() -> Option<CpuTotals> {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|c| parse_proc_stat(&c))
}
