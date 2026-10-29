use super::*;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use sysinfo::{Components, Disks, Networks, System};

#[derive(Default)]
pub struct NetworkRateCache {
    samples: HashMap<String, NetworkRateSample>,
}

struct NetworkRateSample {
    received_bytes: u64,
    transmitted_bytes: u64,
    timestamp: Instant,
}

const DISK_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_DISK_REFRESH_GATES: usize = 64;
const MAX_DISK_INODE_CACHE_ENTRIES: usize = 256;

/// Disk capacity and inode counters do not need the one-second cadence used by
/// realtime CPU/network charts. Regular and realtime collectors share this
/// gate so concurrent report loops cannot duplicate filesystem scans.
pub(crate) fn refresh_disks_throttled(disks: &Arc<Mutex<Disks>>) {
    static LAST_REFRESH: OnceLock<Mutex<HashMap<usize, Instant>>> = OnceLock::new();
    let now = Instant::now();
    let cache_key = Arc::as_ptr(disks) as usize;
    let mut last_refresh = LAST_REFRESH
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock();
    if last_refresh
        .get(&cache_key)
        .is_some_and(|last| now.saturating_duration_since(*last) < DISK_REFRESH_INTERVAL)
    {
        return;
    }
    disks.lock().refresh(true);
    if !last_refresh.contains_key(&cache_key) && last_refresh.len() >= MAX_DISK_REFRESH_GATES {
        if let Some(oldest) = last_refresh
            .iter()
            .min_by_key(|(_, refreshed_at)| *refreshed_at)
            .map(|(key, _)| *key)
        {
            last_refresh.remove(&oldest);
        }
    }
    last_refresh.insert(cache_key, now);
}

impl NetworkRateCache {
    pub fn new() -> Self {
        Self {
            samples: HashMap::new(),
        }
    }

    fn calculate(
        &mut self,
        iface: &str,
        received_bytes: u64,
        transmitted_bytes: u64,
        timestamp: Instant,
    ) -> (f64, f64) {
        let speeds = self
            .samples
            .get(iface)
            .and_then(|prev| {
                let elapsed = timestamp.duration_since(prev.timestamp).as_secs_f64();
                if elapsed <= 0.0
                    || received_bytes < prev.received_bytes
                    || transmitted_bytes < prev.transmitted_bytes
                {
                    return None;
                }
                Some((
                    (received_bytes - prev.received_bytes) as f64 / elapsed,
                    (transmitted_bytes - prev.transmitted_bytes) as f64 / elapsed,
                ))
            })
            .unwrap_or((0.0, 0.0));

        self.samples.insert(
            iface.to_string(),
            NetworkRateSample {
                received_bytes,
                transmitted_bytes,
                timestamp,
            },
        );

        speeds
    }
}

pub(crate) fn collect_cpu(sys: &Arc<Mutex<System>>) -> serde_json::Value {
    let s = sys.lock();
    let cpus = s.cpus();
    let global_usage = s.global_cpu_usage();

    let per_core: Vec<serde_json::Value> = cpus
        .iter()
        .enumerate()
        .map(|(i, cpu)| {
            serde_json::json!({
                "core": i,
                "usage_percent": (cpu.cpu_usage() * 100.0).round() / 100.0,
                "frequency_mhz": (cpu.frequency() > 0).then(|| cpu.frequency()),
            })
        })
        .collect();

    let frequencies: Vec<u64> = cpus
        .iter()
        .map(|cpu| cpu.frequency())
        .filter(|mhz| *mhz > 0)
        .collect();
    let frequency_mhz = (!frequencies.is_empty())
        .then(|| frequencies.iter().sum::<u64>() as f64 / frequencies.len() as f64);
    let load_avg = System::load_average();

    serde_json::json!({
        "usage_percent": (global_usage * 100.0).round() / 100.0,
        "cores": cpus.len(),
        "frequency_mhz": frequency_mhz,
        "frequency_min_mhz": frequencies.iter().min(),
        "frequency_max_mhz": frequencies.iter().max(),
        "per_core": per_core,
        "load_avg": {
            "one": load_avg.one,
            "five": load_avg.five,
            "fifteen": load_avg.fifteen,
        },
        "brand": cpus.first().map(|c| c.brand().to_string()).unwrap_or_default(),
    })
}

pub(crate) fn collect_memory(sys: &Arc<Mutex<System>>) -> serde_json::Value {
    let s = sys.lock();
    let total = s.total_memory();
    let used = s.used_memory();
    let available = s.available_memory();
    let swap_total = s.total_swap();
    let swap_used = s.used_swap();

    serde_json::json!({
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": available,
        "usage_percent": if total > 0 { (used as f64 / total as f64 * 10000.0).round() / 100.0 } else { 0.0 },
        "swap_total_bytes": swap_total,
        "swap_used_bytes": swap_used,
        "swap_usage_percent": if swap_total > 0 { (swap_used as f64 / swap_total as f64 * 10000.0).round() / 100.0 } else { 0.0 },
    })
}

pub(crate) fn collect_disk(disks: &Arc<Mutex<Disks>>) -> serde_json::Value {
    let d = disks.lock();
    let real_disks: Vec<&sysinfo::Disk> = d
        .iter()
        .filter(|disk| {
            let mount = disk.mount_point().to_string_lossy();
            let name = disk.name().to_string_lossy();
            let fs = format!("{:?}", disk.file_system());

            if mount.contains("/docker/overlay2/") {
                return false;
            }
            if mount.starts_with("/snap/") {
                return false;
            }
            if fs.contains("tmpfs")
                || fs.contains("devtmpfs")
                || fs.contains("proc")
                || fs.contains("sysfs")
            {
                return false;
            }
            if disk.total_space() == 0 {
                return false;
            }
            if name == "overlay" {
                return false;
            }
            true
        })
        .collect();

    let disk_list: Vec<serde_json::Value> = real_disks
        .iter()
        .map(|disk| {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);

            let inode_info = collect_inode_info_cached(disk.mount_point());

            serde_json::json!({
                "mount_point": disk.mount_point().to_string_lossy(),
                "name": disk.name().to_string_lossy(),
                "fs_type": format!("{:?}", disk.file_system()),
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "usage_percent": if total > 0 { (used as f64 / total as f64 * 10000.0).round() / 100.0 } else { 0.0 },
                "is_removable": disk.is_removable(),
                "inodes": inode_info,
            })
        })
        .collect();

    let mut seen_devices: HashSet<(String, u64)> = HashSet::new();
    let mut seen_mounts: HashSet<String> = HashSet::new();
    let mut seen_sizes: HashSet<(u64, u64)> = HashSet::new();
    let mut total_space: u64 = 0;
    let mut total_avail: u64 = 0;
    for disk in &real_disks {
        let dev_key = disk.name().to_string_lossy().to_string();
        let mount = disk.mount_point().to_string_lossy().to_string();
        let total = disk.total_space();
        let avail = disk.available_space();
        if total < 1_073_741_824 {
            continue;
        }
        if !seen_mounts.insert(mount) {
            continue;
        }
        if !seen_devices.insert((dev_key, total)) {
            continue;
        }
        if !seen_sizes.insert((total, avail)) {
            continue;
        }
        total_space += total;
        total_avail += avail;
    }
    let total_used = total_space.saturating_sub(total_avail);

    serde_json::json!({
        "total_bytes": total_space,
        "used_bytes": total_used,
        "available_bytes": total_avail,
        "usage_percent": if total_space > 0 { (total_used as f64 / total_space as f64 * 10000.0).round() / 100.0 } else { 0.0 },
        "disks": disk_list,
    })
}

fn collect_inode_info_cached(path: &std::path::Path) -> serde_json::Value {
    static CACHE: OnceLock<Mutex<HashMap<std::path::PathBuf, (Instant, serde_json::Value)>>> =
        OnceLock::new();
    let now = Instant::now();
    let mut cache = CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock();
    if let Some((updated_at, value)) = cache.get(path) {
        if now.saturating_duration_since(*updated_at) < DISK_REFRESH_INTERVAL {
            return value.clone();
        }
    }

    let value = std::ffi::CString::new(path.to_string_lossy().as_bytes().to_vec())
        .ok()
        .and_then(|cpath| {
            let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) } == 0 && stat.f_files > 0 {
                let used = stat.f_files - stat.f_ffree;
                Some(serde_json::json!({
                    "total": stat.f_files,
                    "used": used,
                    "free": stat.f_ffree,
                    "usage_percent": (used as f64 / stat.f_files as f64 * 10000.0).round() / 100.0,
                }))
            } else {
                None
            }
        })
        .unwrap_or(serde_json::Value::Null);
    if !cache.contains_key(path) && cache.len() >= MAX_DISK_INODE_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (updated_at, _))| *updated_at)
            .map(|(cached_path, _)| cached_path.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(path.to_path_buf(), (now, value.clone()));
    value
}

// Match kernel device names across reordering; unavailable/reset counters have no rate.
pub(crate) fn add_disk_io_rates(
    previous: Option<&serde_json::Value>,
    current: &mut serde_json::Value,
    elapsed: Option<f64>,
) {
    let previous = previous.and_then(|value| value["devices"].as_array());
    let Some(devices) = current["devices"].as_array_mut() else {
        return;
    };
    for device in devices {
        let old =
            previous.and_then(|devices| devices.iter().find(|old| old["name"] == device["name"]));
        for (counter, rate) in [
            ("read_bytes", "read_bytes_per_sec"),
            ("write_bytes", "write_bytes_per_sec"),
        ] {
            let value = old.and_then(|old| {
                let elapsed = elapsed.filter(|elapsed| elapsed.is_finite() && *elapsed > 0.0)?;
                let delta = device[counter]
                    .as_u64()?
                    .checked_sub(old[counter].as_u64()?)?;
                Some(round_f64_two_decimals(delta as f64 / elapsed))
            });
            device[rate] = serde_json::json!(value);
        }
    }
}

pub(crate) fn collect_disk_io() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        use std::io::BufRead;
        if let Ok(file) = std::fs::File::open("/proc/diskstats") {
            let reader = std::io::BufReader::new(file);
            let mut devices = Vec::new();
            for line in reader.lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 14 {
                    continue;
                }
                let name = parts[2];
                if name.starts_with("loop") || name.starts_with("dm-") || name.starts_with("ram") {
                    continue;
                }
                let reads_completed: u64 = parts[3].parse().unwrap_or(0);
                let reads_sectors: u64 = parts[5].parse().unwrap_or(0);
                let writes_completed: u64 = parts[7].parse().unwrap_or(0);
                let writes_sectors: u64 = parts[9].parse().unwrap_or(0);
                let io_in_progress: u64 = parts[11].parse().unwrap_or(0);
                let read_bytes = reads_sectors * 512;
                let write_bytes = writes_sectors * 512;
                devices.push(serde_json::json!({
                    "name": name,
                    "reads_completed": reads_completed,
                    "writes_completed": writes_completed,
                    "read_bytes": read_bytes,
                    "write_bytes": write_bytes,
                    "io_in_progress": io_in_progress,
                }));
            }
            return serde_json::json!({ "devices": devices });
        }
    }
    serde_json::json!({ "devices": [] })
}

fn default_network_routes() -> Option<HashSet<String>> {
    #[cfg(target_os = "linux")]
    {
        let mut routes = HashSet::new();
        let mut available = false;
        for (path, ipv6) in [("/proc/net/route", false), ("/proc/net/ipv6_route", true)] {
            let Ok(raw) = std::fs::read_to_string(path) else {
                continue;
            };
            available = true;
            let mut minimum = u64::MAX;
            let mut family = HashSet::new();
            for line in raw.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                let parsed = if ipv6
                    && fields.len() >= 10
                    && fields[0] == "00000000000000000000000000000000"
                    && fields[1] == "00"
                    && fields[2] == "00000000000000000000000000000000"
                    && fields[3] == "00"
                {
                    u64::from_str_radix(fields[8], 16)
                        .ok()
                        .zip(u64::from_str_radix(fields[5], 16).ok())
                        .map(|(flags, metric)| (fields[9], flags, metric))
                } else if !ipv6
                    && fields.len() >= 8
                    && fields[1] == "00000000"
                    && fields[7] == "00000000"
                {
                    u64::from_str_radix(fields[3], 16)
                        .ok()
                        .zip(fields[6].parse::<u64>().ok())
                        .map(|(flags, metric)| (fields[0], flags, metric))
                } else {
                    None
                };
                let Some((name, flags, metric)) = parsed else {
                    continue;
                };
                if flags & 1 == 0 || flags & 0x200 != 0 || name.is_empty() || name.contains('/') {
                    continue;
                }
                if metric < minimum {
                    family.clear();
                    minimum = metric;
                }
                if metric == minimum {
                    family.insert(name.to_owned());
                }
            }
            routes.extend(family);
        }
        // A bridge/bond and its enslaved interface must not both be counted.
        let selected = routes.clone();
        routes.retain(|name| {
            let mut current = name.clone();
            for _ in 0..8 {
                let Ok(master) = std::fs::read_link(format!("/sys/class/net/{current}/master"))
                else {
                    break;
                };
                let Some(parent) = master.file_name().and_then(|value| value.to_str()) else {
                    break;
                };
                if selected.contains(parent) {
                    return false;
                }
                current = parent.to_owned();
            }
            !selected.iter().any(|parent| {
                parent != name
                    && std::path::Path::new(&format!("/sys/class/net/{parent}/lower_{name}"))
                        .exists()
            })
        });
        available.then_some(routes)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

fn network_traffic_class(name: &str, routes: Option<&HashSet<String>>) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "lo" | "lo0") || lower.starts_with("loopback") {
        return "loopback";
    }
    if [
        "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "ifb",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return "container";
    }
    if [
        "tun",
        "tap",
        "utun",
        "wg",
        "tailscale",
        "zt",
        "easytier",
        "ppp",
        "gre",
        "ip6tnl",
        "sit",
        "vxlan",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return "tunnel";
    }
    #[cfg(target_os = "linux")]
    if std::path::Path::new(&format!("/sys/class/net/{name}/tun_flags")).exists()
        || std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .is_some_and(|kind| matches!(kind, 768 | 769 | 776 | 778 | 65534))
    {
        return "tunnel";
    }
    if routes.is_some_and(|routes| routes.contains(name)) {
        return "egress";
    }
    #[cfg(target_os = "linux")]
    if ["bridge", "brport"]
        .iter()
        .any(|kind| std::path::Path::new(&format!("/sys/class/net/{name}/{kind}")).exists())
    {
        return "container";
    }
    if routes.is_some() {
        "lan"
    } else {
        "unknown"
    }
}

pub(crate) fn collect_network(
    networks: &Arc<Mutex<Networks>>,
    network_rate_cache: &Arc<Mutex<NetworkRateCache>>,
) -> serde_json::Value {
    let n = networks.lock();
    let now = Instant::now();
    let mut rate_cache = network_rate_cache.lock();
    let routes = default_network_routes();
    let mut groups = serde_json::Map::new();
    for class in [
        "egress",
        "lan",
        "loopback",
        "container",
        "tunnel",
        "unknown",
    ] {
        groups.insert(class.to_owned(), serde_json::json!({"received_bytes":0_u64,"transmitted_bytes":0_u64,"received_bytes_per_sec":0.0,"transmitted_bytes_per_sec":0.0,"interface_count":0}));
    }
    let mut default_interfaces = Vec::new();
    let interfaces: Vec<_> = n.iter().map(|(name, data)| {
        let class = network_traffic_class(name, routes.as_ref());
        let received = data.total_received();
        let transmitted = data.total_transmitted();
        let (rx, tx) = rate_cache.calculate(name, received, transmitted, now);
        let group = groups.get_mut(class).unwrap();
        group["received_bytes"] = serde_json::json!(group["received_bytes"].as_u64().unwrap().saturating_add(received));
        group["transmitted_bytes"] = serde_json::json!(group["transmitted_bytes"].as_u64().unwrap().saturating_add(transmitted));
        group["received_bytes_per_sec"] = serde_json::json!(group["received_bytes_per_sec"].as_f64().unwrap() + rx);
        group["transmitted_bytes_per_sec"] = serde_json::json!(group["transmitted_bytes_per_sec"].as_f64().unwrap() + tx);
        group["interface_count"] = serde_json::json!(group["interface_count"].as_u64().unwrap() + 1);
        if class == "egress" { default_interfaces.push(name.clone()); }
        serde_json::json!({
            "name":name,"traffic_class":class,
            "ip_addresses":data.ip_networks().iter().map(|ip|ip.addr.to_string()).collect::<Vec<_>>(),
            "mac_address":data.mac_address().to_string(),
            "received_bytes":received,"transmitted_bytes":transmitted,
            "received_bytes_per_sec":rx,"transmitted_bytes_per_sec":tx,
            "received_packets":data.total_packets_received(),"transmitted_packets":data.total_packets_transmitted(),
            "received_errors":data.total_errors_on_received(),"transmitted_errors":data.total_errors_on_transmitted(),
        })
    }).collect();
    default_interfaces.sort();
    let available = !default_interfaces.is_empty();
    let egress = &groups["egress"];
    serde_json::json!({
        "accounting_version":2,"accounting_scope":if available {"default_route_interfaces"} else {"unavailable"},
        "default_route_interfaces":default_interfaces,
        "total_received_bytes":if available {egress["received_bytes"].clone()} else {serde_json::Value::Null},
        "total_transmitted_bytes":if available {egress["transmitted_bytes"].clone()} else {serde_json::Value::Null},
        "total_received_bytes_per_sec":if available {egress["received_bytes_per_sec"].clone()} else {serde_json::Value::Null},
        "total_transmitted_bytes_per_sec":if available {egress["transmitted_bytes_per_sec"].clone()} else {serde_json::Value::Null},
        "traffic_groups":groups,"interfaces":interfaces,
    })
}

pub(crate) fn collect_gpu() -> serde_json::Value {
    let query_fields = "index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,fan.speed,power.draw,power.limit,driver_version";

    // nvidia-smi can hang (driver crash, GPU reset, exclusive-process mode).
    // Hard-limit to 10 seconds; return empty on timeout/error.
    let output = match run_cmd_with_timeout(
        "nvidia-smi",
        &["--query-gpu", query_fields, "--format=csv,noheader,nounits"],
        Duration::from_secs(10),
    ) {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            return serde_json::json!({
                "devices": [],
                "count": 0,
            });
        }
    };

    let mut devices = Vec::new();
    let mut driver_ver = String::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() < 10 {
            continue;
        }

        let index: u32 = parts[0].parse().unwrap_or(0);
        let name = parts[1].to_string();
        let temp: f64 = parts[2].parse().unwrap_or(0.0);
        let util: f64 = parts[3].parse().unwrap_or(0.0);
        let mem_used_mib: f64 = parts[4].parse().unwrap_or(0.0);
        let mem_total_mib: f64 = parts[5].parse().unwrap_or(0.0);
        let fan: f64 = parts[6].parse().unwrap_or(0.0);
        let power_draw: f64 = parts[7].parse().unwrap_or(0.0);
        let power_limit: f64 = parts[8].parse().unwrap_or(0.0);
        driver_ver = parts[9].to_string();

        let mem_used_bytes = (mem_used_mib * 1048576.0) as u64;
        let mem_total_bytes = (mem_total_mib * 1048576.0) as u64;
        let mem_percent = if mem_total_mib > 0.0 {
            (mem_used_mib / mem_total_mib * 1000.0).round() / 10.0
        } else {
            0.0
        };

        devices.push(serde_json::json!({
            "index": index,
            "name": name,
            "temperature_c": temp,
            "utilization_percent": util,
            "memory_used_bytes": mem_used_bytes,
            "memory_total_bytes": mem_total_bytes,
            "memory_percent": mem_percent,
            "fan_speed_percent": fan,
            "power_draw_w": power_draw,
            "power_limit_w": power_limit,
            "driver_version": driver_ver,
        }));
    }

    let mut processes = Vec::new();
    if let Some(proc_output) = run_cmd_with_timeout(
        "nvidia-smi",
        &[
            "--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ],
        Duration::from_secs(10),
    ) {
        if proc_output.status.success() {
            let proc_str = String::from_utf8_lossy(&proc_output.stdout);
            for line in proc_str.lines() {
                let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    let pid: u32 = parts[1].parse().unwrap_or(0);
                    let name = parts[2].to_string();
                    let mem_mib: f64 = parts[3].parse().unwrap_or(0.0);
                    processes.push(serde_json::json!({
                        "pid": pid,
                        "name": name,
                        "gpu_memory_mib": mem_mib,
                    }));
                }
            }
        }
    }

    serde_json::json!({
        "devices": devices,
        "count": devices.len(),
        "driver_version": driver_ver,
        "processes": processes,
    })
}

pub(crate) fn collect_system_info(sys: &Arc<Mutex<System>>) -> serde_json::Value {
    struct StaticSystemInfo {
        os_name: String,
        os_version: String,
        kernel_version: String,
    }

    static STATIC_SYSTEM_INFO: OnceLock<StaticSystemInfo> = OnceLock::new();
    let static_info = STATIC_SYSTEM_INFO.get_or_init(|| StaticSystemInfo {
        os_name: System::name().unwrap_or_else(|| std::env::consts::OS.to_string()),
        os_version: System::os_version().unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
    });
    // Hostname and uptime remain live because W-Monitor can change the former
    // without restarting the agent. OS and kernel identity are process-static
    // and no longer re-read /proc and os-release on every fast report.
    let hostname = System::host_name().unwrap_or_default();
    let uptime_seconds = System::uptime();
    let (cpu_count, total_memory) = {
        let s = sys.lock();
        (s.cpus().len(), s.total_memory())
    };

    serde_json::json!({
        "hostname": hostname,
        "os_name": static_info.os_name.as_str(),
        "os_version": static_info.os_version.as_str(),
        "kernel_version": static_info.kernel_version.as_str(),
        "architecture": std::env::consts::ARCH,
        "uptime_seconds": uptime_seconds,
        "cpu_count": cpu_count,
        "total_memory_bytes": total_memory,
    })
}

/// Refresh the one shared process table used by both the process summary and
/// security posture collectors. The sysinfo default also reads disk counters,
/// command lines, environments and every task/thread; none of those fields are
/// part of either report and they become costly on large hosts.
pub(crate) fn refresh_process_snapshot(sys: &Arc<Mutex<System>>) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

    sys.lock().refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .without_tasks(),
    );
}

pub(crate) fn collect_processes(sys: &Arc<Mutex<System>>) -> serde_json::Value {
    use std::collections::HashMap;

    let s = sys.lock();

    let total_mem = s.total_memory();
    let processes = s.processes();
    let total_processes = processes.len();
    let running_processes = processes
        .values()
        .filter(|p| matches!(p.status(), sysinfo::ProcessStatus::Run))
        .count();

    struct ProcAgg {
        pid: u32,
        name: String,
        cpu_usage: f32,
        memory: u64,
        status: String,
    }

    let mut agg: HashMap<String, ProcAgg> = HashMap::new();
    for p in processes.values() {
        let name = p.name().to_string_lossy().to_string();
        agg.entry(name)
            .and_modify(|a| {
                a.cpu_usage += p.cpu_usage();
                if p.memory() > a.memory {
                    a.memory = p.memory();
                }
                if p.pid().as_u32() < a.pid {
                    a.pid = p.pid().as_u32();
                    a.status = format!("{:?}", p.status());
                }
            })
            .or_insert_with_key(|name| ProcAgg {
                pid: p.pid().as_u32(),
                name: name.clone(),
                cpu_usage: p.cpu_usage(),
                memory: p.memory(),
                status: format!("{:?}", p.status()),
            });
    }
    let unique_procs: Vec<ProcAgg> = agg.into_values().collect();

    let mem_pct = |mem: u64| -> f64 {
        if total_mem > 0 {
            let pct = (mem as f64 / total_mem as f64 * 10000.0).round() / 100.0;
            if pct > 100.0 {
                100.0
            } else {
                pct
            }
        } else {
            0.0
        }
    };

    let mut by_cpu: Vec<&ProcAgg> = unique_procs.iter().filter(|p| p.cpu_usage > 0.0).collect();
    retain_top_processes(&mut by_cpu, |a, b| {
        b.cpu_usage
            .total_cmp(&a.cpu_usage)
            .then_with(|| a.pid.cmp(&b.pid))
    });
    let top_cpu: Vec<serde_json::Value> = by_cpu
        .iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "name": p.name,
                "cpu_percent": (p.cpu_usage as f64 * 100.0).round() / 100.0,
                "memory_bytes": p.memory,
                "memory_percent": mem_pct(p.memory),
                "status": p.status,
            })
        })
        .collect();

    let mut by_mem: Vec<&ProcAgg> = unique_procs.iter().filter(|p| p.memory > 0).collect();
    retain_top_processes(&mut by_mem, |a, b| {
        b.memory.cmp(&a.memory).then_with(|| a.pid.cmp(&b.pid))
    });
    let top_memory: Vec<serde_json::Value> = by_mem
        .iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "name": p.name,
                "cpu_percent": (p.cpu_usage as f64 * 100.0).round() / 100.0,
                "memory_bytes": p.memory,
                "memory_percent": mem_pct(p.memory),
                "status": p.status,
            })
        })
        .collect();

    serde_json::json!({
        "total_processes": total_processes,
        "running_processes": running_processes,
        "top_cpu": top_cpu,
        "top_memory": top_memory,
    })
}

// Select in linear time, then sort only the ten displayed entries. Sorting
// the whole host process table twice gets costly on large worker nodes.
fn retain_top_processes<T>(
    processes: &mut Vec<T>,
    mut compare: impl FnMut(&T, &T) -> std::cmp::Ordering,
) {
    const LIMIT: usize = 10;
    if processes.len() > LIMIT {
        processes.select_nth_unstable_by(LIMIT, &mut compare);
        processes.truncate(LIMIT);
    }
    processes.sort_unstable_by(compare);
}

#[cfg(target_os = "linux")]
fn collect_linux_sensors(root: &std::path::Path) -> Option<serde_json::Value> {
    use sha2::{Digest, Sha256};
    let mut temperatures = Vec::new();
    let mut truncated = false;
    for (index, hwmon) in std::fs::read_dir(root)
        .ok()?
        .flatten()
        .take(129)
        .enumerate()
    {
        if index == 128 {
            truncated = true;
            break;
        }
        let path = hwmon.path();
        let canonical = std::fs::canonicalize(&path).ok();
        let parent = canonical.as_deref().and_then(std::path::Path::parent);
        let device = parent.map(|path| {
            if path.file_name().is_some_and(|name| name == "hwmon") {
                path.parent().unwrap_or(path)
            } else {
                path
            }
        });
        let identity = device.unwrap_or(&path).to_string_lossy();
        let digest: String = Sha256::digest(identity.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let chip = std::fs::read_to_string(path.join("name")).unwrap_or_else(|_| "sensor".into());
        let device_label = device
            .and_then(std::path::Path::file_name)
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for (index, entry) in entries.flatten().take(4097).enumerate() {
            if index == 4096 {
                truncated = true;
                break;
            }
            let filename = entry.file_name().to_string_lossy().into_owned();
            let Some(channel) = filename
                .strip_suffix("_input")
                .filter(|name| name.starts_with("temp") && name[4..].parse::<u32>().is_ok())
            else {
                continue;
            };
            if temperatures.len() == 256 {
                truncated = true;
                continue;
            }
            let read = |suffix: &str| {
                std::fs::read_to_string(path.join(format!("{channel}_{suffix}")))
                    .ok()
                    .and_then(|value| value.trim().parse::<f64>().ok())
                    .map(|value| value / 1000.0)
                    .filter(|value| value.is_finite() && *value >= -273.15 && *value <= 500.0)
            };
            let label = std::fs::read_to_string(path.join(format!("{channel}_label")))
                .unwrap_or_else(|_| channel.into());
            temperatures.push(serde_json::json!({
                "id":format!("hwmon:{}:{channel}",&digest[..16]),
                "label":format!("{} {} · {}",chip.trim(),label.trim(),device_label),
                "temperature_celsius":read("input").map(round_f64_two_decimals),
                "max_celsius":read("highest").map(round_f64_two_decimals),
                "critical_celsius":read("crit").map(round_f64_two_decimals),
            }));
        }
    }
    if temperatures.is_empty() {
        return None;
    }
    temperatures.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Some(
        serde_json::json!({"count":temperatures.len(),"temperatures":temperatures,"truncated":truncated}),
    )
}

pub(crate) fn collect_sensors() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    if let Some(sensors) = collect_linux_sensors(std::path::Path::new("/sys/class/hwmon")) {
        return sensors;
    }

    let components = Components::new_with_refreshed_list();
    let temperatures: Vec<serde_json::Value> = components
        .iter()
        .map(|c| {
            serde_json::json!({
                "label": c.label(),
                "temperature_celsius": c.temperature().map(round_f32_one_decimal),
                "max_celsius": c.max().map(round_f32_one_decimal),
                "critical_celsius": c.critical().map(|v| (v as f64 * 10.0).round() / 10.0),
            })
        })
        .collect();

    serde_json::json!({
        "temperatures": temperatures,
        "count": temperatures.len(),
    })
}

fn round_f32_one_decimal(value: f32) -> f64 {
    (value as f64 * 10.0).round() / 10.0
}

pub(crate) fn round_f64_two_decimals(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
