use crate::collectors::{PingCache, TracerouteCache};
use futures_util::StreamExt;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

const MAX_PEERS_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_DIAGNOSTIC_PEERS: usize = 256;
const MAX_PEER_RECORDS_SCANNED: usize = 1024;
const MAX_SERVER_PRESETS_SCANNED: usize = 64;
const MAX_DIAGNOSTIC_PRESETS: usize = 16;
const MAX_PING_TARGETS_PER_CYCLE: usize = 16;
const MAX_TRACEROUTE_TARGETS_PER_CYCLE: usize = 8;
const PING_CYCLE_BUDGET: Duration = Duration::from_secs(45);
const PING_PROBE_TIMEOUT: Duration = Duration::from_secs(7);
const TRACEROUTE_CYCLE_BUDGET: Duration = Duration::from_secs(75);
const TRACEROUTE_PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const TRACEROUTE_MAX_HOPS: usize = 12;

const MAX_AGENT_ID_CHARS: usize = 128;
const MAX_HOSTNAME_CHARS: usize = 256;
const MAX_PRESET_LABEL_CHARS: usize = 128;
const PING_START_JITTER_MAX_SECS: u64 = 5 * 60;
const TRACEROUTE_START_JITTER_MAX_SECS: u64 = 60 * 60;
const TRACEROUTE_PEER_CACHE_RETRY: Duration = Duration::from_secs(60);
const TRACEROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiagnosticPeer {
    agent_id: String,
    hostname: String,
    ip: IpAddr,
}

#[derive(Clone, Debug, Default)]
struct DiagnosticPeerInventory {
    peers: Vec<DiagnosticPeer>,
    source_rows_scanned: Option<u64>,
    source_scan_truncated: Option<bool>,
    source_targets_truncated: Option<bool>,
    local_records_truncated: bool,
}

impl DiagnosticPeerInventory {
    fn source_inventory_exact(&self) -> bool {
        self.source_rows_scanned.is_some_and(|rows| {
            rows <= MAX_PEER_RECORDS_SCANNED as u64 && rows >= self.peers.len() as u64
        }) && self.source_scan_truncated == Some(false)
            && self.source_targets_truncated == Some(false)
            && !self.local_records_truncated
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PingTarget {
    Preset { ip: IpAddr, label: String },
    Peer(DiagnosticPeer),
}

pub fn spawn_ping_collector(
    cache: Arc<Mutex<PingCache>>,
    endpoint_url: String,
    auth_token: Arc<Mutex<String>>,
    agent_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start_delay = Duration::from_secs(30)
            + diagnostic_start_jitter(&agent_id, b"ping", PING_START_JITTER_MAX_SECS);
        tokio::time::sleep(start_delay).await;
        let base_url = endpoint_url
            .trim_end_matches('/')
            .trim_end_matches("/api/v1/report")
            .to_string();
        let mut target_cursor = 0usize;

        loop {
            let needs_refresh = { cache.lock().peers_stale() };
            if needs_refresh {
                info!("Refreshing peers list from server...");
                let token = auth_token.lock().clone();
                match fetch_peers(&base_url, &token, &agent_id).await {
                    Ok(resp) => {
                        let mut c = cache.lock();
                        c.cached_peers = Some(resp);
                        c.peers_fetched_at = Some(Instant::now());
                        info!("Peers list refreshed, next refresh in 1 hour");
                    }
                    Err(e) => warn!("Failed to fetch peers: {}", e),
                }
            }

            let cached = { cache.lock().cached_peers.clone() };
            info!("Running ping collector...");
            let result = run_ping_cycle_with_cache(cached, &mut target_cursor).await;
            {
                let mut c = cache.lock();
                c.results = result;
                c.last_updated = Some(Instant::now());
            }
            info!("Ping collector done, next run in 10 minutes");
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    })
}

pub fn spawn_traceroute_collector(
    traceroute_cache: Arc<Mutex<TracerouteCache>>,
    ping_cache: Arc<Mutex<PingCache>>,
    agent_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start_delay = Duration::from_secs(60)
            + diagnostic_start_jitter(&agent_id, b"traceroute", TRACEROUTE_START_JITTER_MAX_SECS);
        tokio::time::sleep(start_delay).await;
        let mut target_cursor = 0usize;
        loop {
            let cached_peers = { ping_cache.lock().cached_peers.clone() };
            if let Some(retry_delay) = traceroute_peer_cache_retry(cached_peers.as_ref()) {
                info!(
                    "Traceroute collector waiting for the bounded peer inventory; retrying in {:?}",
                    retry_delay
                );
                tokio::time::sleep(retry_delay).await;
                continue;
            }
            info!("Running traceroute collector...");
            let result = run_traceroute_cycle(cached_peers, &mut target_cursor).await;
            {
                let mut c = traceroute_cache.lock();
                c.results = result;
                c.last_updated = Some(Instant::now());
            }
            info!("Traceroute collector done, next run in 24 hours");
            tokio::time::sleep(TRACEROUTE_REFRESH_INTERVAL).await;
        }
    })
}

fn traceroute_peer_cache_retry(cached_peers: Option<&serde_json::Value>) -> Option<Duration> {
    cached_peers
        .is_none()
        .then_some(TRACEROUTE_PEER_CACHE_RETRY)
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

/// Deterministically spread fleet diagnostics after coordinated restarts.
/// A stable local hash avoids RNG state and keeps each Agent's schedule
/// predictable while preventing every node from probing at the same second.
fn diagnostic_start_jitter(agent_id: &str, namespace: &[u8], max_secs: u64) -> Duration {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in namespace.iter().chain(agent_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Duration::from_secs(hash % max_secs.saturating_add(1))
}

/// Generic diagnostics deliberately operate on external/underlay addresses.
/// Private and local addresses are excluded so the EasyTier overlay is never
/// re-probed by this legacy collector; the dedicated SD-WAN topology owns it.
fn is_external_diagnostic_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            !ipv4.is_private()
                && !ipv4.is_loopback()
                && !ipv4.is_link_local()
                && !ipv4.is_multicast()
                && !ipv4.is_unspecified()
                && !ipv4.is_broadcast()
                && octets[0] != 0
                && octets[0] < 224
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                && !(octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
                && !(octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                && !(octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(ipv6) => {
            if let Some(mapped) = ipv6.to_ipv4_mapped() {
                return is_external_diagnostic_ip(IpAddr::V4(mapped));
            }
            let segments = ipv6.segments();
            !ipv6.is_loopback()
                && !ipv6.is_unspecified()
                && !ipv6.is_multicast()
                && !ipv6.is_unique_local()
                && !ipv6.is_unicast_link_local()
                && segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn parse_diagnostic_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 64 {
        return None;
    }
    raw.parse::<IpAddr>()
        .ok()
        .filter(|ip| is_external_diagnostic_ip(*ip))
}

fn diagnostic_peers(response: Option<&serde_json::Value>) -> DiagnosticPeerInventory {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let source_rows_scanned = response
        .and_then(|value| value.get("rows_scanned"))
        .and_then(serde_json::Value::as_u64);
    let source_scan_truncated = response
        .and_then(|value| value.get("scan_truncated"))
        .and_then(serde_json::Value::as_bool);
    let source_targets_truncated = response
        .and_then(|value| value.get("targets_truncated"))
        .and_then(serde_json::Value::as_bool);
    let Some(peers) = response
        .and_then(|value| value.get("peers"))
        .and_then(serde_json::Value::as_array)
    else {
        return DiagnosticPeerInventory {
            peers: result,
            source_rows_scanned,
            source_scan_truncated,
            source_targets_truncated,
            local_records_truncated: false,
        };
    };
    let mut local_records_truncated = peers.len() > MAX_PEER_RECORDS_SCANNED;

    for peer in peers.iter().take(MAX_PEER_RECORDS_SCANNED) {
        let target = ["ipv4", "ipv6", "ip"].iter().find_map(|field| {
            peer.get(*field)
                .and_then(serde_json::Value::as_str)
                .and_then(parse_diagnostic_ip)
        });
        let Some(ip) = target else {
            continue;
        };
        if !seen.insert(ip) {
            continue;
        }

        let agent_id = bounded_text(
            peer.get("agent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            MAX_AGENT_ID_CHARS,
        );
        let hostname = bounded_text(
            peer.get("hostname")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
            MAX_HOSTNAME_CHARS,
        );
        let normalized = DiagnosticPeer {
            agent_id,
            hostname: if hostname.is_empty() {
                "unknown".to_string()
            } else {
                hostname
            },
            ip,
        };
        if result.len() < MAX_DIAGNOSTIC_PEERS {
            result.push(normalized);
        } else {
            local_records_truncated = true;
        }
    }
    DiagnosticPeerInventory {
        peers: result,
        source_rows_scanned,
        source_scan_truncated,
        source_targets_truncated,
        local_records_truncated,
    }
}

fn default_presets() -> Vec<(IpAddr, String)> {
    [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Public DNS 1.1.1.1"),
        ("223.5.5.5", "Aliyun DNS"),
    ]
    .into_iter()
    .map(|(host, label)| {
        (
            host.parse().expect("built-in diagnostic IP must be valid"),
            label.to_string(),
        )
    })
    .collect()
}

fn diagnostic_presets(response: Option<&serde_json::Value>) -> Vec<(IpAddr, String)> {
    let Some(values) = response
        .and_then(|value| value.get("presets"))
        .and_then(serde_json::Value::as_array)
    else {
        return default_presets();
    };
    let mut seen = HashSet::new();
    let mut parsed = Vec::new();
    for value in values.iter().take(MAX_SERVER_PRESETS_SCANNED) {
        let Some(ip) = value
            .get("host")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_diagnostic_ip)
        else {
            continue;
        };
        if !seen.insert(ip) {
            continue;
        }
        let label = bounded_text(
            value
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            MAX_PRESET_LABEL_CHARS,
        );
        parsed.push((ip, label));
        if parsed.len() == MAX_DIAGNOSTIC_PRESETS {
            break;
        }
    }
    if parsed.is_empty() {
        default_presets()
    } else {
        parsed
    }
}

fn ping_targets(
    response: Option<&serde_json::Value>,
) -> (Vec<PingTarget>, DiagnosticPeerInventory) {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for (ip, label) in diagnostic_presets(response) {
        if seen.insert(ip) {
            targets.push(PingTarget::Preset { ip, label });
        }
    }
    let peer_inventory = diagnostic_peers(response);
    for peer in peer_inventory.peers.iter().cloned() {
        if seen.insert(peer.ip) {
            targets.push(PingTarget::Peer(peer));
        }
    }
    (targets, peer_inventory)
}

fn rotating_window<T: Clone>(values: &[T], cursor: usize, limit: usize) -> Vec<T> {
    if values.is_empty() || limit == 0 {
        return Vec::new();
    }
    let start = cursor % values.len();
    let count = values.len().min(limit);
    (0..count)
        .map(|offset| values[(start + offset) % values.len()].clone())
        .collect()
}

async fn run_ping_cycle_with_cache(
    cached_peers: Option<serde_json::Value>,
    target_cursor: &mut usize,
) -> serde_json::Value {
    run_ping_cycle_with_budget(cached_peers, target_cursor, PING_CYCLE_BUDGET).await
}

async fn run_ping_cycle_with_budget(
    cached_peers: Option<serde_json::Value>,
    target_cursor: &mut usize,
    cycle_budget: Duration,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + cycle_budget;
    let (targets, peer_inventory) = ping_targets(cached_peers.as_ref());
    let selection_start = if targets.is_empty() {
        0
    } else {
        *target_cursor % targets.len()
    };
    let selected = rotating_window(
        targets.as_slice(),
        selection_start,
        MAX_PING_TARGETS_PER_CYCLE,
    );
    let selected_count = selected.len();
    let mut peers_data = Vec::new();
    let mut preset_results = Vec::new();
    let mut probed = 0usize;
    let mut deadline_exceeded = false;

    for target in selected {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            deadline_exceeded = true;
            break;
        }
        let probe_timeout = remaining.min(PING_PROBE_TIMEOUT);
        match target {
            PingTarget::Preset { ip, label } => {
                let result = ping_host(ip, probe_timeout).await;
                preset_results.push(serde_json::json!({
                    "host": ip.to_string(),
                    "label": label,
                    "latency_ms": result.0,
                    "packet_loss": result.1,
                    "status": result.2,
                }));
            }
            PingTarget::Peer(peer) => {
                let result = ping_host(peer.ip, probe_timeout).await;
                peers_data.push(serde_json::json!({
                    "agent_id": peer.agent_id,
                    "hostname": peer.hostname,
                    "ip": peer.ip.to_string(),
                    "af": if peer.ip.is_ipv4() { "ipv4" } else { "ipv6" },
                    "latency_ms": result.0,
                    "packet_loss": result.1,
                    "status": result.2,
                }));
            }
        }
        probed += 1;
    }
    *target_cursor = if targets.is_empty() {
        0
    } else {
        (selection_start + probed) % targets.len()
    };
    deadline_exceeded |= tokio::time::Instant::now() >= deadline;

    serde_json::json!({
        "scope": "underlay_external",
        "presets": preset_results,
        "peers": peers_data,
        "targets_total": targets.len(),
        "targets_total_exact": peer_inventory.source_inventory_exact(),
        "peer_targets_retained": peer_inventory.peers.len(),
        "source_rows_scanned": peer_inventory.source_rows_scanned,
        "source_scan_truncated": peer_inventory.source_scan_truncated,
        "source_targets_truncated": peer_inventory.source_targets_truncated,
        "local_peer_records_truncated": peer_inventory.local_records_truncated,
        "targets_selected": selected_count,
        "targets_probed": probed,
        "rotated": targets.len() > selected_count,
        "deadline_exceeded": deadline_exceeded,
    })
}

async fn run_traceroute_cycle(
    cached_peers: Option<serde_json::Value>,
    target_cursor: &mut usize,
) -> serde_json::Value {
    run_traceroute_cycle_with_budget(cached_peers, target_cursor, TRACEROUTE_CYCLE_BUDGET).await
}

async fn run_traceroute_cycle_with_budget(
    cached_peers: Option<serde_json::Value>,
    target_cursor: &mut usize,
    cycle_budget: Duration,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + cycle_budget;
    let peer_inventory = diagnostic_peers(cached_peers.as_ref());
    let peers = &peer_inventory.peers;
    let selection_start = if peers.is_empty() {
        0
    } else {
        *target_cursor % peers.len()
    };
    let selected = rotating_window(
        peers.as_slice(),
        selection_start,
        MAX_TRACEROUTE_TARGETS_PER_CYCLE,
    );
    let selected_count = selected.len();
    let mut traces = Vec::new();
    let mut deadline_exceeded = false;

    for peer in selected {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            deadline_exceeded = true;
            break;
        }
        info!("Traceroute to {} ({})...", peer.hostname, peer.ip);
        let hops = traceroute_host(peer.ip, remaining.min(TRACEROUTE_PROBE_TIMEOUT)).await;
        let total_hops = hops.len();
        let status = if hops.is_empty() {
            "failed"
        } else {
            "completed"
        };

        traces.push(serde_json::json!({
            "agent_id": peer.agent_id,
            "hostname": peer.hostname,
            "target_ip": peer.ip.to_string(),
            "hops": hops,
            "total_hops": total_hops,
            "status": status,
        }));
    }

    let probed = traces.len();
    *target_cursor = if peers.is_empty() {
        0
    } else {
        (selection_start + probed) % peers.len()
    };
    deadline_exceeded |= tokio::time::Instant::now() >= deadline;
    serde_json::json!({
        "scope": "underlay_external",
        "traces": traces,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "targets_total": peers.len(),
        "targets_total_exact": peer_inventory.source_inventory_exact(),
        "peer_targets_retained": peers.len(),
        "source_rows_scanned": peer_inventory.source_rows_scanned,
        "source_scan_truncated": peer_inventory.source_scan_truncated,
        "source_targets_truncated": peer_inventory.source_targets_truncated,
        "local_peer_records_truncated": peer_inventory.local_records_truncated,
        "targets_selected": selected_count,
        "targets_probed": probed,
        "rotated": peers.len() > selected_count,
        "deadline_exceeded": deadline_exceeded,
    })
}

fn traceroute_command(host: IpAddr) -> tokio::process::Command {
    let target = host.to_string();
    let mut command = tokio::process::Command::new("traceroute");
    command
        .args([
            "-n",
            "-m",
            "12",
            "-q",
            "1",
            "-w",
            "1",
            "--",
            target.as_str(),
        ])
        .kill_on_drop(true);
    command
}

async fn traceroute_host(host: IpAddr, timeout: Duration) -> Vec<serde_json::Value> {
    let output = tokio::time::timeout(timeout, traceroute_command(host).output()).await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut hops: Vec<serde_json::Value> = Vec::new();

            for line in stdout.lines().skip(1).take(TRACEROUTE_MAX_HOPS) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let hop_num: u32 = match parts[0].parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                if parts.len() >= 2 && parts[1] == "*" {
                    hops.push(serde_json::json!({
                        "hop": hop_num,
                        "ip": null,
                        "rtt_ms": null,
                        "timeout": true,
                    }));
                } else if parts.len() >= 3 {
                    let Some(ip) = parts[1].parse::<IpAddr>().ok() else {
                        continue;
                    };
                    let mut rtt: Option<f64> = None;
                    for p in &parts[2..] {
                        if let Ok(val) = p.parse::<f64>() {
                            rtt = Some(val);
                            break;
                        }
                    }
                    hops.push(serde_json::json!({
                        "hop": hop_num,
                        "ip": ip.to_string(),
                        "rtt_ms": rtt,
                        "timeout": false,
                    }));
                }
            }
            hops
        }
        Ok(Err(e)) => {
            error!("Traceroute command failed for {}: {}", host, e);
            Vec::new()
        }
        Err(_) => {
            warn!("Traceroute command timed out for {}", host);
            Vec::new()
        }
    }
}

async fn fetch_peers(
    base_url: &str,
    auth_token: &str,
    agent_id: &str,
) -> Result<serde_json::Value, String> {
    let mut url = reqwest::Url::parse(&format!("{}/api/v1/peers", base_url))
        .map_err(|e| format!("Peers URL error: {e}"))?;
    url.query_pairs_mut().append_pair("agent_id", agent_id);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {}", auth_token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Server returned {}", resp.status()));
    }

    if resp
        .content_length()
        .is_some_and(|length| length > MAX_PEERS_RESPONSE_BYTES as u64)
    {
        return Err("Peers response exceeds 1 MiB".to_string());
    }
    let mut body = Vec::with_capacity(
        resp.content_length()
            .unwrap_or_default()
            .min(MAX_PEERS_RESPONSE_BYTES as u64) as usize,
    );
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Response body error: {e}"))?;
        append_bounded_response_chunk(&mut body, chunk.as_ref())?;
    }
    serde_json::from_slice::<serde_json::Value>(&body).map_err(|e| format!("Parse error: {e}"))
}

fn append_bounded_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if chunk.len() > MAX_PEERS_RESPONSE_BYTES.saturating_sub(body.len()) {
        return Err("Peers response exceeds 1 MiB".to_string());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn ping_command(host: IpAddr) -> tokio::process::Command {
    let target = host.to_string();
    let mut command = tokio::process::Command::new("ping");
    command
        .args(["-n", "-c", "3", "-W", "2", "--", target.as_str()])
        .kill_on_drop(true);
    command
}

async fn ping_host(host: IpAddr, timeout: Duration) -> (Option<f64>, f64, &'static str) {
    let output = tokio::time::timeout(timeout, ping_command(host).output()).await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let packet_loss = stdout
                .lines()
                .find(|l| l.contains("packet loss"))
                .and_then(|l| {
                    l.split_whitespace()
                        .find(|w| w.ends_with('%'))
                        .and_then(|w| w.trim_end_matches('%').parse::<f64>().ok())
                })
                .unwrap_or(100.0);

            let latency = stdout
                .lines()
                .find(|l| l.contains("min/avg/max"))
                .and_then(|l| {
                    l.split('=')
                        .next_back()
                        .and_then(|vals| vals.trim().split('/').nth(1))
                        .and_then(|avg| avg.trim().parse::<f64>().ok())
                });

            if packet_loss >= 100.0 {
                (None, 100.0, "timeout")
            } else {
                (latency, packet_loss, "ok")
            }
        }
        Ok(Err(e)) => {
            error!("Ping command failed for {}: {}", host, e);
            (None, 100.0, "error")
        }
        Err(_) => {
            warn!("Ping command timed out for {}", host);
            (None, 100.0, "timeout")
        }
    }
}
