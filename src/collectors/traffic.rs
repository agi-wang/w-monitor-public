use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Shared ping results cache — updated by background task every 10 minutes.
/// Peers list is cached separately and refreshed every 1 hour.
pub struct PingCache {
    pub results: serde_json::Value,
    pub last_updated: Option<Instant>,
    /// Cached peers response from server (refreshed every 1 hour)
    pub cached_peers: Option<serde_json::Value>,
    pub peers_fetched_at: Option<Instant>,
}

impl PingCache {
    pub fn new() -> Self {
        Self {
            results: serde_json::json!({ "presets": [], "peers": [] }),
            last_updated: None,
            cached_peers: None,
            peers_fetched_at: None,
        }
    }

    pub fn peers_stale(&self) -> bool {
        match self.peers_fetched_at {
            None => true,
            Some(t) => t.elapsed() > Duration::from_secs(3600),
        }
    }
}

/// Shared traceroute results cache — updated by background task every 24 hours.
pub struct TracerouteCache {
    pub results: serde_json::Value,
    pub last_updated: Option<Instant>,
}

impl TracerouteCache {
    pub fn new() -> Self {
        Self {
            results: serde_json::json!({ "traces": [] }),
            last_updated: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrafficFlowEntry {
    pub(crate) protocol: String,
    pub(crate) state: String,
    pub(crate) local_ip: String,
    pub(crate) local_port: String,
    pub(crate) remote_ip: String,
    pub(crate) remote_port: String,
    pub(crate) process: String,
    pub(crate) pid: Option<u32>,
    pub(crate) connections: u32,
}

pub(crate) fn collect_connections() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        use std::io::BufRead;
        let mut established = 0u32;
        let mut listen = 0u32;
        let mut time_wait = 0u32;
        let mut close_wait = 0u32;
        let mut total = 0u32;

        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(file) = std::fs::File::open(path) {
                let reader = std::io::BufReader::new(file);
                for (i, line) in reader.lines().map_while(Result::ok).enumerate() {
                    if i == 0 {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 4 {
                        continue;
                    }
                    total += 1;
                    match parts[3] {
                        "01" => established += 1,
                        "0A" => listen += 1,
                        "06" => time_wait += 1,
                        "08" => close_wait += 1,
                        _ => {}
                    }
                }
            }
        }

        serde_json::json!({
            "total": total,
            "established": established,
            "listen": listen,
            "time_wait": time_wait,
            "close_wait": close_wait,
        })
    }

    #[cfg(not(target_os = "linux"))]
    serde_json::json!({
        "total": 0,
        "established": 0,
        "listen": 0,
        "time_wait": 0,
        "close_wait": 0,
    })
}

pub(crate) fn collect_traffic_flows_with_ss(ss_output: &Option<String>) -> serde_json::Value {
    match ss_output {
        Some(stdout) => build_traffic_flows_report_from_ss(stdout, 80),
        None => serde_json::json!({
            "available": false,
            "sampler": "ss",
            "error": "ss command unavailable or timed out",
            "flows": [],
        }),
    }
}

fn build_traffic_flows_report_from_ss(output: &str, limit: usize) -> serde_json::Value {
    let mut total_connections = 0u32;
    let mut internal_connections = 0u32;
    let mut external_connections = 0u32;
    let mut grouped: HashMap<String, TrafficFlowEntry> = HashMap::new();

    for line in output.lines() {
        if line.split_whitespace().count() >= 5 {
            total_connections += 1;
        }
        let Some(flow) = parse_ss_flow_line(line) else {
            continue;
        };
        let scope = traffic_flow_scope(&flow);
        if scope == "internal" {
            internal_connections += 1;
        } else {
            external_connections += 1;
        }
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            scope,
            flow.protocol,
            flow.state,
            flow.local_ip,
            flow.remote_ip,
            service_port_for_flow(&flow),
            flow.process,
            flow.pid.map(|v| v.to_string()).unwrap_or_default()
        );
        grouped
            .entry(key)
            .and_modify(|entry| entry.connections += 1)
            .or_insert(flow);
    }

    let mut flows: Vec<TrafficFlowEntry> = grouped.into_values().collect();
    flows.sort_by(|a, b| {
        b.connections
            .cmp(&a.connections)
            .then_with(|| a.local_ip.cmp(&b.local_ip))
            .then_with(|| a.remote_ip.cmp(&b.remote_ip))
    });
    let truncated = flows.len() > limit;
    flows.truncate(limit);

    let flow_values: Vec<serde_json::Value> = flows
        .into_iter()
        .map(|f| {
            let scope = traffic_flow_scope(&f);
            serde_json::json!({
                "protocol": f.protocol,
                "state": f.state,
                "local_ip": f.local_ip,
                "local_port": f.local_port,
                "remote_ip": f.remote_ip,
                "remote_port": f.remote_port,
                "service_port": service_port_for_flow(&f),
                "process": f.process,
                "pid": f.pid,
                "connections": f.connections,
                "scope": scope,
                "direction": traffic_flow_direction(&f),
            })
        })
        .collect();

    serde_json::json!({
        "available": true,
        "sampler": "ss",
        "total_connections": total_connections,
        "internal_connections": internal_connections,
        "external_connections": external_connections,
        "truncated": truncated,
        "flows": flow_values,
        "note": "connection-level bandwidth requires eBPF; this snapshot reports active internal and external connections",
    })
}

pub(crate) fn parse_ss_flow_line(line: &str) -> Option<TrafficFlowEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }

    let (local_raw, remote_raw, process_raw) = if looks_like_endpoint(parts[4])
        && looks_like_endpoint(parts[5])
    {
        (parts[4], parts[5], parts.get(6).copied().unwrap_or(""))
    } else if parts.len() >= 5 && looks_like_endpoint(parts[3]) && looks_like_endpoint(parts[4]) {
        (parts[3], parts[4], parts.get(5).copied().unwrap_or(""))
    } else {
        return None;
    };

    let (local_ip, local_port) = parse_endpoint(local_raw)?;
    let (remote_ip, remote_port) = parse_endpoint(remote_raw)?;
    if is_wildcard_endpoint(&local_ip, &local_port)
        || is_wildcard_endpoint(&remote_ip, &remote_port)
    {
        return None;
    }
    let (process, pid) = parse_process_info(process_raw);

    Some(TrafficFlowEntry {
        protocol: parts[0].to_ascii_lowercase(),
        state: parts[1].to_string(),
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        process,
        pid,
        connections: 1,
    })
}

pub(crate) fn looks_like_endpoint(value: &str) -> bool {
    value.contains(':') || value == "*" || value.starts_with('[')
}

pub(crate) fn parse_endpoint(raw: &str) -> Option<(String, String)> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':').unwrap_or("*");
        return Some((ip.to_string(), port.to_string()));
    }
    let idx = value.rfind(':')?;
    let ip = &value[..idx];
    let port = &value[idx + 1..];
    Some((ip.to_string(), port.to_string()))
}

pub(crate) fn parse_process_info(raw: &str) -> (String, Option<u32>) {
    let process = raw
        .split("((\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let pid = raw
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<u32>().ok());
    (process, pid)
}

fn service_port_for_flow(flow: &TrafficFlowEntry) -> String {
    let local = flow.local_port.parse::<u16>().ok();
    let remote = flow.remote_port.parse::<u16>().ok();
    match (local, remote) {
        (Some(lp), _) if lp < 32768 => flow.local_port.clone(),
        (_, Some(rp)) if rp < 32768 => flow.remote_port.clone(),
        _ => flow.remote_port.clone(),
    }
}

pub(crate) fn traffic_flow_scope(flow: &TrafficFlowEntry) -> &'static str {
    if is_internal_ip(&flow.local_ip) && is_internal_ip(&flow.remote_ip) {
        "internal"
    } else {
        "external"
    }
}

pub(crate) fn traffic_flow_direction(flow: &TrafficFlowEntry) -> &'static str {
    let local_port = flow.local_port.parse::<u16>().ok();
    let remote_port = flow.remote_port.parse::<u16>().ok();
    match (local_port, remote_port) {
        (Some(lp), Some(rp)) if lp >= 32768 && rp < 32768 => "outbound",
        (Some(lp), Some(rp)) if lp < 32768 && rp >= 32768 => "inbound",
        _ => "unknown",
    }
}

fn is_wildcard_endpoint(ip: &str, port: &str) -> bool {
    ip == "*" || ip == "0.0.0.0" || ip == "::" || port == "*"
}

fn is_internal_ip(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(second) = ip
        .strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|v| v.parse::<u8>().ok())
    {
        return (16..=31).contains(&second);
    }
    if let Some(second) = ip
        .strip_prefix("100.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|v| v.parse::<u8>().ok())
    {
        return (64..=127).contains(&second);
    }
    let lower = ip.to_ascii_lowercase();
    lower == "::1" || lower.starts_with("fc") || lower.starts_with("fd")
}
