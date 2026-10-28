//! `nvidia-smi` parsing — **runtime** metrics (this module) and **static**
//! properties ([`props`], behind `gpu-props`).
//!
//! Running `nvidia-smi` (with a hard timeout — it can hang on a driver reset)
//! is the host's job; this is the CSV row → typed parse that products otherwise
//! hand-roll. MiB→bytes and the memory-percent rounding are the fiddly parts.

use crate::round1;

const MIB: f64 = 1_048_576.0;

/// One GPU's RUNTIME metrics as reported by `nvidia-smi`. The four `Option`
/// fields (0.2.0) are filled only by extended queries / NVML; the canonical
/// 11-field CSV leaves them `None`.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GpuDevice {
    pub index: u32,
    pub name: String,
    pub temperature_c: f64,
    pub utilization_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub memory_percent: f64,
    pub fan_speed_percent: f64,
    pub power_draw_w: f64,
    pub power_limit_w: f64,
    pub driver_version: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub memory_free_bytes: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub utilization_memory_percent: Option<f64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub clock_sm_mhz: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub clock_mem_mhz: Option<u64>,
}

/// A process holding GPU memory (`nvidia-smi --query-compute-apps`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GpuProcess {
    pub pid: u32,
    pub name: String,
    pub gpu_memory_bytes: u64,
}

/// Parse the CSV produced by
/// `nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,fan.speed,power.draw,power.limit,driver_version --format=csv,noheader,nounits`.
/// Rows with fewer than 10 fields are skipped (partial/old driver output).
pub fn parse_nvidia_smi_csv(output: &str) -> Vec<GpuDevice> {
    let mut devices = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() < 10 {
            continue;
        }
        let mem_used_mib: f64 = parts[4].parse().unwrap_or(0.0);
        let mem_total_mib: f64 = parts[5].parse().unwrap_or(0.0);
        let memory_percent = if mem_total_mib > 0.0 {
            round1(mem_used_mib / mem_total_mib * 100.0)
        } else {
            0.0
        };
        devices.push(GpuDevice {
            index: parts[0].parse().unwrap_or(0),
            name: parts[1].to_string(),
            temperature_c: parts[2].parse().unwrap_or(0.0),
            utilization_percent: parts[3].parse().unwrap_or(0.0),
            memory_used_bytes: (mem_used_mib * MIB) as u64,
            memory_total_bytes: (mem_total_mib * MIB) as u64,
            memory_percent,
            fan_speed_percent: parts[6].parse().unwrap_or(0.0),
            power_draw_w: parts[7].parse().unwrap_or(0.0),
            power_limit_w: parts[8].parse().unwrap_or(0.0),
            driver_version: parts[9].to_string(),
            ..Default::default()
        });
    }
    devices
}

/// Parse `nvidia-smi --query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory
/// --format=csv,noheader,nounits` (used GPU memory in MiB → bytes).
pub fn parse_nvidia_smi_compute_apps(output: &str) -> Vec<GpuProcess> {
    let mut procs = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() < 4 {
            continue;
        }
        let mem_mib: f64 = parts[3].parse().unwrap_or(0.0);
        procs.push(GpuProcess {
            pid: parts[1].parse().unwrap_or(0),
            name: parts[2].to_string(),
            gpu_memory_bytes: (mem_mib * MIB) as u64,
        });
    }
    procs
}

/// The driver version reported by the first device (all devices share one).
pub fn top_level_driver_version(devices: &[GpuDevice]) -> Option<String> {
    devices
        .iter()
        .map(|d| d.driver_version.as_str())
        .find(|v| !v.is_empty())
        .map(|v| v.to_string())
}

/// Static GPU **properties** (model/VRAM/driver/compute-cap/pcie) — a different
/// concern from runtime metrics, behind the `gpu-props` feature. This is the
/// `nvidia-smi --query-gpu=name,memory.total,driver_version,compute_cap,pcie.link.gen.current,pcie.link.width.current`
/// query that benchmark/inventory tools use.
#[cfg(feature = "gpu-props")]
pub mod props {
    /// Static, slow-changing GPU device properties.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct NvidiaProps {
        pub name: String,
        pub vram_bytes: u64,
        pub driver_version: String,
        pub compute_capability: String,
        pub pcie_gen: String,
        pub pcie_width: String,
    }

    const MIB: f64 = 1_048_576.0;

    /// Parse the static-properties CSV (6 fields per row, MiB VRAM → bytes).
    pub fn parse_nvidia_smi_props_csv(output: &str) -> Vec<NvidiaProps> {
        let mut out = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() < 6 {
                continue;
            }
            let vram_mib: f64 = parts[1].parse().unwrap_or(0.0);
            out.push(NvidiaProps {
                name: parts[0].to_string(),
                vram_bytes: (vram_mib * MIB) as u64,
                driver_version: parts[2].to_string(),
                compute_capability: parts[3].to_string(),
                pcie_gen: parts[4].to_string(),
                pcie_width: parts[5].to_string(),
            });
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_static_props_row() {
            let p = parse_nvidia_smi_props_csv("NVIDIA RTX 5090, 24564, 570.1, 8.9, 5, 16\n");
            assert_eq!(p.len(), 1);
            assert_eq!(p[0].name, "NVIDIA RTX 5090");
            assert_eq!(p[0].vram_bytes, 24564 * 1_048_576);
            assert_eq!(p[0].compute_capability, "8.9");
            assert_eq!(p[0].pcie_gen, "5");
        }
    }
}
