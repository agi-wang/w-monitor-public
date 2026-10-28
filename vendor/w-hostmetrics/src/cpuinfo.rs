//! Static CPU identity from `/proc/cpuinfo` — model, vendor, core count, MHz,
//! notable feature flags. This is a *different concern* from the `/proc/stat`
//! usage deltas in [`crate::cpu`]: this answers "what CPU is this", not "how
//! busy is it". The `procfs` parse is pure/testable; richer brand/frequency
//! data comes from the `sysinfo` feature.

/// Feature flags products commonly surface (virtualization / crypto / SIMD).
pub const IMPORTANT_FLAGS: &[&str] = &[
    "aes", "avx", "avx2", "avx512f", "fma", "sse4_2", "vmx", "svm", "sha_ni", "rdrand",
];

/// Static CPU facts parseable from `/proc/cpuinfo`.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuStaticInfo {
    pub model: Option<String>,
    pub vendor: Option<String>,
    /// Number of `processor:` entries (logical CPUs).
    pub logical_cpus: usize,
    /// `cpu MHz` of the first core (per-core current frequency, may fluctuate).
    pub cpu_mhz: Option<f64>,
    /// Architecture (compile-time target).
    pub architecture: String,
    /// Subset of `flags` intersected with [`IMPORTANT_FLAGS`].
    pub important_flags: Vec<String>,
}

/// Keep only the wanted flags present in a `/proc/cpuinfo` `flags` line,
/// preserving `wanted` order.
pub fn filter_important_flags(flags_line: &str, wanted: &[&str]) -> Vec<String> {
    let present: std::collections::HashSet<&str> = flags_line.split_whitespace().collect();
    wanted
        .iter()
        .filter(|w| present.contains(**w))
        .map(|w| (*w).to_string())
        .collect()
}

/// Parse `/proc/cpuinfo` for static CPU identity. Reads `model name`,
/// `vendor_id`, counts `processor` entries, takes the first `cpu MHz` and the
/// first `flags`/`Features` line.
pub fn parse_cpuinfo(content: &str) -> CpuStaticInfo {
    let mut info = CpuStaticInfo {
        architecture: std::env::consts::ARCH.to_string(),
        ..Default::default()
    };
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "processor" => info.logical_cpus += 1,
            "model name" if info.model.is_none() => info.model = Some(value.to_string()),
            "vendor_id" if info.vendor.is_none() => info.vendor = Some(value.to_string()),
            "cpu MHz" if info.cpu_mhz.is_none() => info.cpu_mhz = value.parse().ok(),
            // x86 uses `flags`, aarch64 uses `Features`.
            "flags" | "Features" if info.important_flags.is_empty() => {
                info.important_flags = filter_important_flags(value, IMPORTANT_FLAGS);
            }
            _ => {}
        }
    }
    info
}

/// Read and parse the live `/proc/cpuinfo`.
pub fn read_cpu_static() -> CpuStaticInfo {
    parse_cpuinfo(&std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default())
}
