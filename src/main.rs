//! Full permitted read-only collection over outbound HTTP(S), with no control
//! transport, command interpreter, file manager, or self-updater in this tree.
#![allow(dead_code)] // Shared read-only collectors include optional diagnostics.
#[cfg(not(target_os = "linux"))]
compile_error!("W-Monitor Lite currently supports Linux only");
mod cache_scan;
mod collectors;
mod network_diag;
mod runtime_paths;
mod security_advisories;
mod software_inventory;
mod vps_pressure;

use anyhow::{bail, Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{CpuRefreshKind, Disks, Networks, System};
use tracing::{info, warn};
use w_monitor_sdk::{
    SystemInfo, SystemReport, TransportRuntimeState, COMPACT_STICKY_COLLECTORS_KEY,
};

const MAX_REPORT: usize = 8 * 1024 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Parser)]
#[command(
    version,
    about = "Read-only Linux monitoring; updates require a local operator"
)]
struct Args {
    /// Owner-only JSON config; contains endpoint_url, auth_token and optional agent_id/interval.
    #[arg(long, default_value_os_t = default_config_path())]
    config: PathBuf,
    /// Fixed receiver URL. Used with --key to configure this device.
    #[arg(long, default_value = "https://monitor.20290708.xyz/api/v1/report")]
    endpoint: String,
    /// Registration credential; saved privately before starting collection.
    #[arg(long)]
    key: Option<String>,
    /// Explicitly permit loopback HTTP for local development only.
    #[arg(long)]
    allow_local_http: bool,
}

fn default_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/w-monitor-public/agent.json")
}

fn read_config(path: &Path) -> Result<Value> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > 64 * 1024
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("Config must be a regular file owned by the current user, at most 64 KiB, with mode 0600");
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("Config exceeds 64 KiB");
    }
    let value: Value = serde_json::from_slice(&bytes).context("Invalid JSON configuration")?;
    if !value.is_object() {
        bail!("Config must be a JSON object");
    }
    Ok(value)
}

fn persist_config(path: &Path, expected: &str, next: &str, id: &str) -> Result<()> {
    let mut value = read_config(path)?;
    if value["auth_token"].as_str() != Some(expected) {
        bail!("Config changed; refusing to overwrite credentials");
    }
    value["auth_token"] = json!(next);
    value["agent_id"] = json!(id);
    write_config(path, &value)
}

fn write_config(path: &Path, value: &Value) -> Result<()> {
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        file.write_all(&serde_json::to_vec_pretty(&value)?)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

async fn post_report(
    client: &reqwest::Client,
    endpoint: &url::Url,
    token: &str,
    body: &[u8],
    compressed: bool,
) -> Result<Value> {
    // No redirect can forward a credential. The configured origin is the only
    // telemetry destination, and every request has a whole-request deadline.
    let request = client
        .post(endpoint.clone())
        .bearer_auth(token)
        .header("Content-Type", "application/json");
    let request = if compressed {
        request.header("Content-Encoding", "gzip")
    } else {
        request
    };
    let response = request.body(body.to_vec()).send().await?;
    if !response.status().is_success() {
        bail!("Report rejected: HTTP {}", response.status().as_u16());
    }
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_RESPONSE as u64)
    {
        bail!("Response exceeds limit");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            bail!("Response exceeds limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let parent = args
        .config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Some(key) = &args.key {
        if key.is_empty() || key.len() > 512 || key.chars().any(char::is_control) {
            bail!("Invalid registration key");
        }
        let endpoint = url::Url::parse(&args.endpoint)?;
        let local_http = args.allow_local_http
            && endpoint.scheme() == "http"
            && matches!(
                endpoint.host_str(),
                Some("127.0.0.1" | "[::1]" | "localhost")
            );
        if !(endpoint.scheme() == "https" || local_http)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!("Endpoint requires HTTPS without credentials, query or fragment");
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            bail!("Config directory must be owned by the current user with mode 0700");
        }
        let mut value = match std::fs::symlink_metadata(&args.config) {
            Ok(_) => read_config(&args.config)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(error) => return Err(error.into()),
        };
        value["endpoint_url"] = json!(args.endpoint);
        value["auth_token"] = json!(key);
        value["compress_reports"] = json!(true);
        write_config(&args.config, &value)?;
        // Remove the registration key from the long-running process arguments.
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.arg("--config").arg(&args.config);
        if args.allow_local_http {
            command.arg("--allow-local-http");
        }
        return Err(command.exec().into());
    }
    let parent_metadata = std::fs::metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("Config directory must be owned by the current user and not writable by group or others");
    }
    let config = read_config(&args.config)?;
    let endpoint_text = config["endpoint_url"]
        .as_str()
        .context("endpoint_url is required")?;
    let mut endpoint = url::Url::parse(endpoint_text)?;
    let local_http = args.allow_local_http
        && endpoint.scheme() == "http"
        && matches!(
            endpoint.host_str(),
            Some("127.0.0.1" | "[::1]" | "localhost")
        );
    if !(endpoint.scheme() == "https" || local_http)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("Endpoint requires HTTPS, without credentials, query or fragment; loopback HTTP needs --allow-local-http");
    }
    if endpoint.path() == "/" {
        endpoint.set_path("/api/v1/report");
    }
    let mut token = config["auth_token"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
        .context("auth_token is required (up to 512 bytes)")?
        .to_owned();
    let mut identity = SystemInfo::detect();
    if let Some(id) = config["agent_id"].as_str().filter(|id| !id.is_empty()) {
        if id.len() > 255 || id.trim() != id || id.chars().any(char::is_control) {
            bail!("Invalid agent_id");
        }
        identity.agent_id = id.to_owned();
    }
    persist_config(&args.config, &token, &token, &identity.agent_id)?;
    let mut interval_ms = config["interval"]
        .as_u64()
        .unwrap_or(60_000)
        .clamp(10_000, 1_800_000);
    // Enabled by Public configurations; existing receiver configurations retain
    // their transport until a local operator explicitly enables compression.
    let compress_reports = config["compress_reports"].as_bool().unwrap_or(false);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("w-monitor-lite/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let restricted = runtime_paths::is_unprivileged();
    // Use a dedicated user-owned cache, never the standard Agent's update state.
    let data_dir = args
        .config
        .parent()
        .unwrap_or(Path::new("."))
        .join("lite-state");
    match std::fs::DirBuilder::new().mode(0o700).create(&data_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let state_metadata = std::fs::symlink_metadata(&data_dir)?;
    if !state_metadata.is_dir()
        || state_metadata.uid() != unsafe { libc::geteuid() }
        || state_metadata.mode() & 0o077 != 0
    {
        bail!("Lite state must be a real directory owned by the current user with mode 0700");
    }
    let sys = Arc::new(Mutex::new(System::new()));
    sys.lock().refresh_cpu_list(CpuRefreshKind::everything());
    let networks = Arc::new(Mutex::new(Networks::new_with_refreshed_list()));
    let disks = Arc::new(Mutex::new(Disks::new_with_refreshed_list()));
    let ping = Arc::new(Mutex::new(collectors::PingCache::new()));
    let traceroute = Arc::new(Mutex::new(collectors::TracerouteCache::new()));
    let cache_state = data_dir.join("cache-scan-state.json");
    let scan = Arc::new(Mutex::new(if restricted {
        cache_scan::CacheScanCache::new()
    } else {
        cache_scan::CacheScanCache::load(&cache_state)
    }));
    let rates = Arc::new(Mutex::new(collectors::NetworkRateCache::new()));
    let transport = Arc::new(TransportRuntimeState::new(endpoint.to_string()));
    let shared_token = Arc::new(Mutex::new(token.clone()));
    let mut tasks = Vec::new();
    if !restricted {
        tasks.push(network_diag::spawn_ping_collector(
            ping.clone(),
            endpoint.to_string(),
            shared_token.clone(),
            identity.agent_id.clone(),
        ));
        tasks.push(network_diag::spawn_traceroute_collector(
            traceroute.clone(),
            ping.clone(),
            identity.agent_id.clone(),
        ));
        tasks.push(cache_scan::spawn_cache_scan_collector(
            scan.clone(),
            cache_state,
        ));
    }
    let (catalog_tx, assessment_tx, security, inventory) =
        security_advisories::start(&data_dir, endpoint.as_str());
    let scheduler = Arc::new(Mutex::new(collectors::CollectorScheduler::new(restricted)));
    let mut latest = HashMap::new();
    let mut heavy_keys = Vec::<String>::new();
    info!(
        "Lite started: full permitted read-only collection; no remote control or automatic updates"
    );
    loop {
        if tasks.iter().any(tokio::task::JoinHandle::is_finished) {
            bail!("A diagnostic collector exited; restart the Agent");
        }
        let (sys, networks, disks, ping, traceroute, scan, rates, transport, scheduler) = (
            sys.clone(),
            networks.clone(),
            disks.clone(),
            ping.clone(),
            traceroute.clone(),
            scan.clone(),
            rates.clone(),
            transport.clone(),
            scheduler.clone(),
        );
        let mut snapshot = tokio::task::spawn_blocking(move || {
            scheduler.lock().collect(
                &sys,
                &networks,
                &disks,
                &ping,
                &traceroute,
                &scan,
                &rates,
                &transport,
            )
        })
        .await?;
        let sticky = snapshot
            .remove(COMPACT_STICKY_COLLECTORS_KEY)
            .unwrap_or(Value::Null);
        if sticky["fresh"].as_bool() == Some(true) {
            let keys: Vec<String> =
                serde_json::from_value(sticky["keys"].clone()).unwrap_or_default();
            for old in &heavy_keys {
                if !keys.contains(old) {
                    latest.remove(old);
                }
            }
            heavy_keys = keys;
        }
        latest.extend(snapshot);
        latest.insert("security_advisories".into(), security.lock().clone());
        latest.insert("software_inventory".into(), inventory.lock().clone());
        if let Some(access) = latest.get_mut("runtime_access") {
            access["lite_mode"] = json!(true);
        }
        let mut report = SystemReport::build(&identity, latest.clone(), interval_ms);
        report.metadata.agent_version = env!("CARGO_PKG_VERSION").to_owned();
        report.apply_runtime_access(true);
        report.metadata.capabilities["agent.lite"] = json!(true);
        report.metadata.capabilities["security.inventory"] = json!("osv-v1");
        report.metadata.capabilities["security.advisories"] = json!("dpkg-v1");
        let bytes = serde_json::to_vec(&report)?;
        if bytes.len() > MAX_REPORT {
            bail!("Collected report exceeds 8 MiB; refusing an unbounded upload");
        }
        let (bytes, compressed) = if compress_reports && bytes.len() >= 4096 {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&bytes)?;
            let encoded = encoder.finish()?;
            if encoded.len() < bytes.len() {
                (encoded, true)
            } else {
                (bytes, false)
            }
        } else {
            (bytes, false)
        };
        let mut response = None;
        for attempt in 0..=2 {
            match post_report(&client, &endpoint, &token, &bytes, compressed).await {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                // reqwest errors contain URLs but never the Authorization header;
                // print only the failure class to keep endpoint details private.
                Err(_) => warn!(attempt, "Report delivery failed"),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        }
        if let Some(value) = response {
            if value["status"] == "ok" {
                if let Some(next) = value["agent_token"].as_str().filter(|v| {
                    v.starts_with("sat_")
                        && v.len() == 36
                        && v[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
                }) {
                    if next != token {
                        persist_config(&args.config, &token, next, &identity.agent_id)?;
                        token = next.to_owned();
                        *shared_token.lock() = token.clone();
                    }
                }
                if let Some(ms) = value["report_interval_ms"].as_u64() {
                    interval_ms = ms.clamp(10_000, 1_800_000);
                }
                if let Ok(catalog) = serde_json::from_value::<
                    w_monitor_sdk::security_advisories::Catalog,
                >(value["security_advisories"].clone())
                {
                    if catalog.validate().is_ok() {
                        catalog_tx.send_replace(Some(catalog));
                    }
                }
                if let Ok(assessment) = serde_json::from_value::<
                    w_monitor_sdk::software_inventory::Assessment,
                >(value["security_assessment"].clone())
                {
                    if assessment.validate().is_ok() {
                        assessment_tx.send_replace(Some(assessment));
                    }
                }
                info!(
                    collectors = report.collectors.len(),
                    "Read-only report delivered"
                );
            }
            // All other fields, including commands, terminal payloads,
            // tcp_endpoints and update_version, are deliberately ignored.
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(interval_ms)) => {},
        }
    }
    for task in tasks {
        task.abort();
    }
    Ok(())
}
