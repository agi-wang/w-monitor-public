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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    /// Create an anonymous space and public page on this HTTPS origin.
    #[arg(long, conflicts_with = "key")]
    public: Option<String>,
    #[arg(long, default_value = "en", value_parser = ["en", "zh-CN"])]
    language: String,
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

fn prepare_config_directory(parent: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .with_context(|| format!("Cannot open config directory {} safely", parent.display()))?;
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "Config directory {} must belong to the current user",
            parent.display()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        if default_config_path().parent() == Some(parent) {
            directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        } else {
            bail!(
                "Config directory {} must have mode 0700; current mode is {:04o}",
                parent.display(),
                metadata.mode() & 0o777
            );
        }
    }
    Ok(())
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
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

async fn interactive_setup(endpoint: &str, language: &str) -> Result<(String, Option<String>)> {
    let mut url = url::Url::parse(endpoint)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("Setup endpoint requires HTTPS without credentials, query or fragment");
    }
    url.set_path("/api/regions");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()?;
    let catalog = response_json(
        client
            .get(url)
            .header("Accept-Language", language)
            .send()
            .await?,
    )
    .await?;
    let regions = catalog["regions"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 16)
        .context("No available regions")?;
    let mut terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")
        .context("Interactive setup needs a terminal; use --public URL or --endpoint URL --key KEY for unattended setup")?;
    writeln!(
        terminal,
        "{}",
        if language == "zh-CN" {
            "请选择数据存储地区："
        } else {
            "Choose a data region:"
        }
    )?;
    for (index, region) in regions.iter().enumerate() {
        let name = region["name"]
            .as_str()
            .filter(|v| v.len() <= 120 && !v.chars().any(char::is_control))
            .context("Invalid region name")?;
        writeln!(terminal, "{}: {}", index + 1, name)?;
    }
    write!(
        terminal,
        "{} [1]: ",
        if language == "zh-CN" {
            "地区"
        } else {
            "Region"
        }
    )?;
    terminal.flush()?;
    let mut reader = std::io::BufReader::new(terminal.try_clone()?);
    let mut answer = String::new();
    use std::io::BufRead;
    reader.read_line(&mut answer)?;
    let index = if answer.trim().is_empty() {
        0
    } else {
        answer
            .trim()
            .parse::<usize>()?
            .checked_sub(1)
            .context("Invalid region")?
    };
    let origin = regions
        .get(index)
        .and_then(|v| v["origin"].as_str())
        .context("Invalid region")?;
    let parsed = url::Url::parse(origin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("Invalid region origin");
    }
    write!(
        terminal,
        "{}: ",
        if language == "zh-CN" {
            "已有接入 Key（留空创建匿名空间）"
        } else {
            "Existing key (leave empty to create an anonymous space)"
        }
    )?;
    terminal.flush()?;
    answer.clear();
    reader.read_line(&mut answer)?;
    let key = answer.trim();
    Ok((
        origin.trim_end_matches('/').to_owned(),
        if key.is_empty() {
            None
        } else {
            Some(key.to_owned())
        },
    ))
}

async fn public_setup(origin: &str, language: &str) -> Result<Value> {
    let url = url::Url::parse(origin)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("Anonymous setup requires a fixed HTTPS origin");
    }
    let origin = origin.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .get(format!("{origin}/api/session"))
        .header("Accept-Language", language)
        .send()
        .await?;
    let cookie = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.split(';')
                .next()
                .filter(|v| v.starts_with("__Host-wm_public=wms_"))
                .map(str::to_owned)
        })
        .context("Missing setup session cookie")?;
    let session = response_json(response).await?;
    let csrf = session["csrf"]
        .as_str()
        .context("Missing setup CSRF token")?;
    // Creating a space is never retried automatically: a lost response may
    // already have created ownership that only its recovery key can restore.
    let response = client.post(format!("{origin}/api/spaces/create"))
        .header("Origin", origin).header("Cookie", cookie).header("X-CSRF-Token", csrf)
        .header("Accept-Language", language)
        .json(&json!({"title": SystemInfo::detect().hostname.chars().take(80).collect::<String>(), "auto_public_page": true}))
        .send().await?;
    let result = response_json(response).await?;
    for (field, prefix, size) in [("recovery", "wmr_", 64), ("bootstrap_key", "wmb_", 64)] {
        let value = result[field].as_str().context("Missing setup credential")?;
        if !value.starts_with(prefix)
            || value.len() != prefix.len() + size
            || !value[prefix.len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("Invalid setup credential");
        }
    }
    for (field, path) in [
        ("manage_url", "/manage/wm1_"),
        ("status_url", "/status/wm1_"),
    ] {
        let value = result[field].as_str().context("Missing setup link")?;
        let link = url::Url::parse(value)?;
        if link.origin() != url.origin()
            || !link.path().starts_with(path)
            || !link.username().is_empty()
            || link.password().is_some()
            || link.query().is_some()
            || link.fragment().is_some()
        {
            bail!("Invalid setup link");
        }
    }
    if result["ingest_url"].as_str() != Some(format!("{origin}/api/v1/report").as_str()) {
        bail!("Invalid report endpoint");
    }
    let labels = if language == "zh-CN" {
        ["私密恢复口令（请保存）", "管理地址", "公开页面"]
    } else {
        [
            "Private recovery key (save securely)",
            "Management URL",
            "Public status URL",
        ]
    };
    for (label, field) in labels
        .into_iter()
        .zip(["recovery", "manage_url", "status_url"])
    {
        println!("{}: {}", label, result[field].as_str().unwrap());
    }
    std::io::stdout().flush()?;
    Ok(
        json!({"endpoint_url": result["ingest_url"], "auth_token": result["bootstrap_key"], "interval": 60000, "compress_reports": true}),
    )
}

async fn post_report(
    client: &reqwest::Client,
    endpoint: &url::Url,
    token: &str,
    body: &[u8],
    compressed: bool,
    metrics: bool,
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
    let request = if metrics {
        request.header("X-WM-Report-Kind", "metrics")
    } else {
        request
    };
    let response = request.body(body.to_vec()).send().await?;
    if !response.status().is_success() {
        bail!("Report rejected: HTTP {}", response.status().as_u16());
    }
    response_json(response).await
}

async fn response_json(response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success() {
        bail!(
            "Receiver rejected request: HTTP {}",
            response.status().as_u16()
        );
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
    let mut args = Args::parse();
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
    if args.key.is_none() && args.public.is_none() && !args.config.exists() {
        let (origin, key) = interactive_setup(&args.endpoint, &args.language).await?;
        if let Some(key) = key {
            args.endpoint = format!("{origin}/api/v1/report");
            args.key = Some(key);
        } else {
            args.public = Some(origin);
        }
    }
    if let Some(origin) = &args.public {
        prepare_config_directory(parent)?;
        // Reserve before making any remote writes; an existing device config
        // must never silently create a second anonymous space.
        let reservation = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&args.config)?;
        let setup = public_setup(origin, &args.language).await;
        drop(reservation);
        match setup {
            Ok(value) => write_config(&args.config, &value)?,
            Err(_) => {
                std::fs::remove_file(&args.config)?;
                bail!("Anonymous setup failed. Keep any recovery key printed above; setup was not retried.");
            }
        }
    }
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
        prepare_config_directory(parent)?;
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
        .clamp(5_000, 1_800_000);
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
    let mut metrics_ms = None;
    let mut full_due = Instant::now();
    info!(
        "Lite started: full permitted read-only collection; no remote control or automatic updates"
    );
    loop {
        let cycle_started = Instant::now();
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
        let full = metrics_ms.is_none() || Instant::now() >= full_due || !token.starts_with("sat_");
        let mut snapshot = tokio::task::spawn_blocking(move || {
            if !full {
                return collectors::collect_realtime_metrics(
                    &sys, &networks, &disks, &rates, &transport, restricted,
                );
            }
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
        if full {
            latest.insert("security_advisories".into(), security.lock().clone());
            latest.insert("software_inventory".into(), inventory.lock().clone());
        }
        if let Some(access) = latest.get_mut("runtime_access") {
            access["lite_mode"] = json!(true);
        }
        let outgoing = if full {
            latest.clone()
        } else {
            latest
                .iter()
                .filter(|(key, _)| matches!(key.as_str(), "cpu" | "memory" | "disk" | "network"))
                .map(|(key, value)| {
                    let data = value.get("data").unwrap_or(value);
                    let fields: &[&str] = if key == "network" {
                        &[
                            "total_received_bytes_per_sec",
                            "total_transmitted_bytes_per_sec",
                            "total_received_bytes",
                            "total_transmitted_bytes",
                        ]
                    } else {
                        &[
                            "usage_percent",
                            "usage",
                            "total_bytes",
                            "used_bytes",
                            "available_bytes",
                        ]
                    };
                    let compact: serde_json::Map<String, Value> = fields
                        .iter()
                        .filter_map(|field| {
                            data.get(*field)
                                .map(|value| ((*field).to_owned(), value.clone()))
                        })
                        .collect();
                    (key.clone(), Value::Object(compact))
                })
                .collect()
        };
        let mut report = SystemReport::build(&identity, outgoing, interval_ms);
        report.metadata.agent_version = env!("CARGO_PKG_VERSION").to_owned();
        report.apply_runtime_access(true);
        report.metadata.capabilities["agent.lite"] = json!(true);
        report.metadata.capabilities["telemetry.metrics"] = json!(true);
        report.metadata.capabilities["security.inventory"] = json!("osv-v1");
        report.metadata.capabilities["security.advisories"] = json!("dpkg-v1");
        let bytes = if full {
            serde_json::to_vec(&report)?
        } else {
            let mut wire = serde_json::to_value(&report)?;
            wire["report_kind"] = json!("metrics");
            serde_json::to_vec(&wire)?
        };
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
            match post_report(&client, &endpoint, &token, &bytes, compressed, !full).await {
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
                    interval_ms = ms.clamp(5_000, 1_800_000);
                }
                metrics_ms = value["metrics_interval_ms"]
                    .as_u64()
                    .map(|ms| ms.clamp(1000, 60000));
                if full {
                    full_due = Instant::now() + Duration::from_millis(interval_ms);
                }
                if value["request_full_report"].as_bool() == Some(true) {
                    full_due = Instant::now();
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
            _ = tokio::time::sleep(Duration::from_millis(metrics_ms.unwrap_or(interval_ms)).saturating_sub(cycle_started.elapsed())) => {},
        }
    }
    for task in tasks {
        task.abort();
    }
    Ok(())
}
