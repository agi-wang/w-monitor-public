//! Static host identity — hostname, uptime, OS/kernel, architecture.
//!
//! Named `host` (not `sysinfo`) to avoid clashing with the `sysinfo` crate.
//! `arch` and `uptime` are available with no extra deps; hostname/OS/kernel
//! need the `sysinfo` feature.

/// Static facts about the host. `hostname`/`os_*`/`kernel_version` are `None`
/// unless populated via the `sysinfo` feature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HostInfo {
    pub hostname: Option<String>,
    pub uptime_seconds: u64,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub arch: String,
}

/// Parse `/proc/uptime` ("12345.67 6789.01") → whole seconds of uptime.
pub fn parse_uptime(content: &str) -> Option<u64> {
    content
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|secs| secs as u64)
}

/// Read `/proc/uptime` → whole seconds.
pub fn read_uptime() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|c| parse_uptime(&c))
}

/// Host info without any extra deps: `arch` + `uptime` only.
pub fn collect_host_info_basic() -> HostInfo {
    HostInfo {
        uptime_seconds: read_uptime().unwrap_or(0),
        arch: std::env::consts::ARCH.to_string(),
        ..Default::default()
    }
}

/// Full host info via `sysinfo` (hostname/OS/kernel) + `/proc/uptime` + arch.
#[cfg(feature = "sysinfo")]
pub fn collect_host_info() -> HostInfo {
    HostInfo {
        hostname: sysinfo::System::host_name(),
        uptime_seconds: sysinfo::System::uptime(),
        os_name: sysinfo::System::name(),
        os_version: sysinfo::System::os_version(),
        kernel_version: sysinfo::System::kernel_version(),
        arch: std::env::consts::ARCH.to_string(),
    }
}
