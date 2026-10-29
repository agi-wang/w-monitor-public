mod diting;
mod project_status;
mod security;
mod web_hosts;

use w_monitor_collectors::{hardware, mount_health, traffic};

pub use hardware::NetworkRateCache;
pub use traffic::{PingCache, TracerouteCache};

use crate::cache_scan::CacheScanCache;
use crate::vps_pressure::collect_vps_pressure;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, System};
use w_monitor_sdk::{TransportRuntimeState, COMPACT_STICKY_COLLECTORS_KEY};

const MAX_COLLECTOR_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COLLECTOR_STDERR_BYTES: usize = 256 * 1024;

// Re-export cross-submodule symbols at the parent level so each submodule's
// `use super::*;` can resolve helpers/types defined in sibling submodules
// (e.g. project_status uses security::SecurityListener; security uses
// traffic's ss parsers and hardware's rounding helper).
pub(crate) use diting::collect_diting_audit;
pub(crate) use hardware::{
    collect_cpu, collect_disk, collect_disk_io, collect_gpu, collect_memory, collect_network,
    collect_processes, collect_sensors, collect_system_info, refresh_disks_throttled,
    refresh_process_snapshot, round_f64_two_decimals,
};
pub(crate) use project_status::{
    collect_docker, collect_easytier, collect_project_status, docker_ps_inventory_cached,
};
pub(crate) use security::{
    build_security_listeners_from_ss, collect_login_accounts, collect_security_posture_with_ss,
    SecurityListener,
};
pub(crate) use traffic::{
    collect_connections, collect_traffic_flows_with_ss, looks_like_endpoint, parse_endpoint,
    parse_process_info, parse_ss_flow_line, traffic_flow_direction, traffic_flow_scope,
};
pub(crate) use web_hosts::collect_web_hosts;

pub(crate) fn run_ss_tunp_cached() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = run_cmd_with_timeout("ss", &["-H", "-tunp"], Duration::from_secs(2))?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub(crate) fn run_ss_listeners_cached() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = run_cmd_with_timeout("ss", &["-H", "-tulnp"], Duration::from_secs(2))?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Run a subprocess with a hard timeout.
///
/// Spawns the command, drains its output concurrently, and waits up to
/// `timeout` for it to finish. If the deadline passes its process group is killed and `None` is
/// returned.  This prevents hanging sub-commands (docker stats, nvidia-smi,
/// easytier-cli, …) from freezing the entire collection cycle.
pub(crate) fn run_cmd_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<std::process::Output> {
    run_command_with_timeout(std::process::Command::new(program).args(args), timeout)
}

pub(crate) fn run_command_with_timeout(
    command: &mut std::process::Command,
    timeout: Duration,
) -> Option<std::process::Output> {
    use std::process::Stdio;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take().map(|pipe| {
        std::thread::spawn(move || read_bounded_and_drain(pipe, MAX_COLLECTOR_STDOUT_BYTES))
    });
    let stderr = child.stderr.take().map(|pipe| {
        std::thread::spawn(move || read_bounded_and_drain(pipe, MAX_COLLECTOR_STDERR_BYTES))
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                #[cfg(unix)]
                unsafe {
                    // The child starts its own process group, so helpers it
                    // spawned cannot outlive the collector timeout.
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    status.map(|status| std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded_and_drain(mut reader: impl std::io::Read, max_bytes: usize) -> Vec<u8> {
    let mut captured = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let remaining = max_bytes.saturating_sub(captured.len());
        captured.extend_from_slice(&chunk[..count.min(remaining)]);
        // Continue draining after the capture limit. Closing a full pipe early
        // would SIGPIPE an otherwise healthy collector and distort its status.
    }
    captured
}

/// Deduplicate a list of paths while preserving first-seen order.
pub(crate) fn dedupe_paths(paths: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    deduped
}

const HEAVY_COLLECT_INTERVAL: Duration = Duration::from_secs(60);

/// Keeps expensive command/file collectors on a stable cadence even when the
/// server requests high-frequency TCP reports. Fast host metrics are refreshed
/// every cycle; cached heavy slices preserve the complete wire schema.
pub struct CollectorScheduler {
    heavy_keys: Vec<String>,
    heavy_collected_at: Option<Instant>,
    heavy_interval: Duration,
    hardware_collected_at: Option<Instant>,
    sensor_cache: Option<serde_json::Value>,
    disk_io_cache: Option<serde_json::Value>,
    restricted: bool,
}

impl CollectorScheduler {
    pub fn new(restricted: bool) -> Self {
        Self {
            heavy_keys: Vec::new(),
            heavy_collected_at: None,
            heavy_interval: HEAVY_COLLECT_INTERVAL,
            hardware_collected_at: None,
            sensor_cache: None,
            disk_io_cache: None,
            restricted,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn collect(
        &mut self,
        sys: &Arc<Mutex<System>>,
        networks: &Arc<Mutex<Networks>>,
        disks: &Arc<Mutex<Disks>>,
        ping_cache: &Arc<Mutex<PingCache>>,
        traceroute_cache: &Arc<Mutex<TracerouteCache>>,
        cache_scan_cache: &Arc<Mutex<CacheScanCache>>,
        network_rate_cache: &Arc<Mutex<NetworkRateCache>>,
        transport_runtime_state: &Arc<TransportRuntimeState>,
    ) -> HashMap<String, serde_json::Value> {
        let now = Instant::now();
        if heavy_refresh_due(self.hardware_collected_at, now, Duration::from_secs(5)) {
            sys.lock()
                .refresh_cpu_specifics(sysinfo::CpuRefreshKind::nothing().with_frequency());
            self.sensor_cache = Some(collect_sensors());
            let mut disk_io = collect_disk_io();
            hardware::add_disk_io_rates(
                self.disk_io_cache.as_ref(),
                &mut disk_io,
                self.hardware_collected_at
                    .map(|at| now.saturating_duration_since(at).as_secs_f64()),
            );
            self.disk_io_cache = Some(disk_io);
            self.hardware_collected_at = Some(now);
        }
        let mut map = collect_realtime_metrics(
            sys,
            networks,
            disks,
            network_rate_cache,
            transport_runtime_state,
            self.restricted,
        );
        if let Some(sensor) = &self.sensor_cache {
            map.insert("sensor".to_string(), sensor.clone());
        }
        if let Some(disk_io) = &self.disk_io_cache {
            map.insert("disk_io".to_string(), disk_io.clone());
        }
        let now = Instant::now();
        let heavy_fresh = heavy_refresh_due(self.heavy_collected_at, now, self.heavy_interval);
        if heavy_fresh {
            let heavy = collect_heavy_metrics(
                sys,
                ping_cache,
                traceroute_cache,
                cache_scan_cache,
                self.restricted,
            );
            self.heavy_keys = heavy.keys().cloned().collect();
            self.heavy_keys.sort_unstable();
            map.extend(heavy);
            self.heavy_collected_at = Some(Instant::now());
        }
        map.insert(
            COMPACT_STICKY_COLLECTORS_KEY.to_string(),
            serde_json::json!({
                "fresh": heavy_fresh,
                "keys": &self.heavy_keys,
            }),
        );
        map
    }
}

fn heavy_refresh_due(last: Option<Instant>, now: Instant, interval: Duration) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= interval)
}

pub fn collect_realtime_metrics(
    sys: &Arc<Mutex<System>>,
    networks: &Arc<Mutex<Networks>>,
    disks: &Arc<Mutex<Disks>>,
    network_rate_cache: &Arc<Mutex<NetworkRateCache>>,
    transport_runtime_state: &Arc<TransportRuntimeState>,
    restricted: bool,
) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    {
        let mut system = sys.lock();
        // The scheduler refreshes CPU frequency and sensors every five seconds;
        // usage remains sampled on each report cycle.
        system.refresh_cpu_usage();
        system.refresh_memory();
    }
    networks.lock().refresh(true);
    refresh_disks_throttled(disks);

    map.insert("cpu".to_string(), collect_cpu(sys));
    map.insert("memory".to_string(), collect_memory(sys));
    map.insert("vps_pressure".to_string(), collect_vps_pressure(sys));
    map.insert("disk".to_string(), collect_disk(disks));
    map.insert(
        "network".to_string(),
        collect_network(networks, network_rate_cache),
    );
    map.insert("system".to_string(), collect_system_info(sys));
    map.insert(
        "runtime_access".to_string(),
        runtime_access_collector(restricted),
    );
    map.insert(
        "transport_runtime".to_string(),
        serde_json::to_value(transport_runtime_state.snapshot()).unwrap_or_else(|_| {
            serde_json::json!({
                "active_transport": "http",
                "tcp_connected": false,
                "active_tcp_endpoint": null,
                "tcp_candidates": [],
                "http_endpoint": "",
            })
        }),
    );
    map
}

fn runtime_access_collector(restricted: bool) -> serde_json::Value {
    if restricted {
        serde_json::json!({
            "level": "restricted",
            "privileged": false,
            "reason": "insufficient_permissions",
        })
    } else {
        serde_json::json!({
            "level": "privileged",
            "privileged": true,
            "reason": null,
        })
    }
}

fn collect_heavy_metrics(
    sys: &Arc<Mutex<System>>,
    ping_cache: &Arc<Mutex<PingCache>>,
    traceroute_cache: &Arc<Mutex<TracerouteCache>>,
    cache_scan_cache: &Arc<Mutex<CacheScanCache>>,
    restricted: bool,
) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    refresh_process_snapshot(sys);
    let login_accounts = collect_login_accounts();
    map.insert("process".to_string(), collect_processes(sys));
    map.insert("ping".to_string(), ping_cache.lock().results.clone());
    {
        let traceroute = traceroute_cache.lock();
        if traceroute.last_updated.is_some() {
            map.insert("traceroute".to_string(), traceroute.results.clone());
        }
    }
    map.insert(
        "mount_health".to_string(),
        mount_health::collect_mount_health(),
    );
    map.insert("connections".to_string(), collect_connections());
    if restricted {
        let reason = "insufficient_permissions";
        map.insert(
            "gpu".to_string(),
            serde_json::json!({"available": false, "devices": [], "reason": reason}),
        );
        map.insert(
            "docker".to_string(),
            serde_json::json!({"available": false, "containers": [], "count": 0, "reason": reason}),
        );
        let traffic_flows = collect_traffic_flows_with_ss(&None);
        map.insert("traffic_flows".to_string(), traffic_flows);
        map.insert(
            "security_posture".to_string(),
            serde_json::json!({"available": false, "findings": [], "reason": reason}),
        );
        map.insert(
            "diting_audit".to_string(),
            serde_json::json!({"available": false, "reason": reason}),
        );
        map.insert(
            "easytier".to_string(),
            serde_json::json!({"installed": false, "running": false, "peers": [], "reason": reason}),
        );
        map.insert(
            "web_hosts".to_string(),
            serde_json::json!({"available": false, "sites": [], "reason": reason}),
        );
        map.insert(
            "project_status".to_string(),
            serde_json::json!({"available": false, "reason": reason}),
        );
        map.insert("login_accounts".to_string(), login_accounts);
        return map;
    }
    map.insert("gpu".to_string(), collect_gpu());
    map.insert("docker".to_string(), collect_docker());
    let ss_output = run_ss_tunp_cached();
    let listener_output = run_ss_listeners_cached();
    // Project status needs the total count to distinguish a partial inventory
    // from confirmed absence. Apply each report's limit after parsing.
    let listeners = listener_output
        .as_deref()
        .map(build_security_listeners_from_ss)
        .unwrap_or_default();
    let traffic_flows = collect_traffic_flows_with_ss(&ss_output);
    let security_posture = collect_security_posture_with_ss(
        sys,
        &ss_output,
        &login_accounts,
        &listeners[..listeners.len().min(120)],
    );
    map.insert(
        "diting_audit".to_string(),
        collect_diting_audit(&security_posture, &traffic_flows),
    );
    map.insert("traffic_flows".to_string(), traffic_flows);
    map.insert("security_posture".to_string(), security_posture);
    map.insert("easytier".to_string(), collect_easytier());
    let web_hosts = collect_web_hosts();
    let project_status = collect_project_status(&listeners, &web_hosts);
    map.insert("login_accounts".to_string(), login_accounts);
    map.insert("web_hosts".to_string(), web_hosts);
    map.insert("project_status".to_string(), project_status);
    if let Some(results) = cache_scan_cache.lock().results.clone() {
        map.insert("cache_scan".to_string(), results);
    }
    map
}
