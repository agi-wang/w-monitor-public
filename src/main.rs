//! Full permitted read-only collection over outbound HTTP(S), with no control
//! transport, command interpreter, file manager, or self-updater in this tree.
#![allow(dead_code)] // Shared read-only collectors include optional diagnostics.
#[cfg(not(target_os = "linux"))]
compile_error!("W-Monitor Lite currently supports Linux only");
mod cache_scan;
mod collectors;
mod keys;
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

#[derive(Debug)]
struct HtmlReceiverResponse(String);

impl std::fmt::Display for HtmlReceiverResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "接收端 {} 返回了 HTML 防护或代理页面，无法上报 JSON。请选择其他节点或联系主机商豁免该域名。 / Receiver returned HTML instead of JSON; select another node or ask the hosting provider to exempt this domain.", self.0)
    }
}

impl std::error::Error for HtmlReceiverResponse {}

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
    /// Disable lightweight realtime samples; retain the full report cadence.
    #[arg(long)]
    no_realtime: bool,
    /// Send reports without gzip compression.
    #[arg(long)]
    no_compression: bool,
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
        });
    let session = response_json(response).await?;
    let cookie = cookie.context("Missing setup session cookie")?;
    let csrf = session["csrf"]
        .as_str()
        .context("Missing setup CSRF token")?;
    let (space_key, space_seed) = keys::SigningKey::generate()?;
    let public_key = space_key.public();
    let response = client
        .post(format!("{origin}/api/keys/challenge"))
        .header("Origin", origin)
        .header("Cookie", &cookie)
        .header("X-CSRF-Token", csrf)
        .json(&json!({"purpose":"create","public_key":public_key}))
        .send()
        .await?;
    let challenge = response_json(response).await?;
    let challenge_value = challenge["challenge"]
        .as_str()
        .context("Missing space challenge")?;
    let message = format!("wm-space-v1\n{origin}\ncreate\n{challenge_value}");
    // Creating a space is never retried automatically: a lost response may
    // already have created ownership that only its recovery key can restore.
    let response = client.post(format!("{origin}/api/spaces/create"))
        .header("Origin", origin).header("Cookie", &cookie).header("X-CSRF-Token", csrf)
        .header("Accept-Language", language)
        .json(&json!({"title": SystemInfo::detect().hostname.chars().take(80).collect::<String>(), "auto_public_page": true,"key_proof":{"public_key":public_key,"challenge":challenge_value,"signature":space_key.sign(&message)}}))
        .send().await?;
    let mut result = response_json(response).await?;
    if result["key_public"].as_str() != Some(public_key.as_str()) {
        bail!("Server did not bind the space public key");
    }
    result["recovery"] = json!(format!("wmr2_{space_seed}"));
    for (field, prefix, size) in [("recovery", "wmr2_", 64), ("bootstrap_key", "wmb_", 64)] {
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
    result["manage_url"] = json!(format!(
        "{}#recovery={}",
        result["manage_url"].as_str().unwrap(),
        result["recovery"].as_str().unwrap()
    ));
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
    signing_key: &keys::SigningKey,
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
    let mut request = request;
    for (name, value) in signing_key.headers(endpoint, token, body, compressed, metrics)? {
        request = request.header(name, value);
    }
    let response = request.body(body.to_vec()).send().await?;
    response_json(response).await
}

async fn response_json(response: reqwest::Response) -> Result<Value> {
    let origin = response.url().origin().ascii_serialization();
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
    {
        return Err(HtmlReceiverResponse(origin).into());
    }
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
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'<') {
        return Err(HtmlReceiverResponse(origin).into());
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
        let mut value = match std::fs::symlink_metadata(&args.config) {
            Ok(_) => {
                let value = read_config(&args.config)?;
                if value["endpoint_url"].as_str()
                    != Some(format!("{}/api/v1/report", origin.trim_end_matches('/')).as_str())
                {
                    let target = url::Url::parse(origin)?;
                    let receiver = target.origin().ascii_serialization();
                    let existing = value["endpoint_url"]
                        .as_str()
                        .and_then(|s| url::Url::parse(s).ok())
                        .map(|url| url.origin().ascii_serialization())
                        .unwrap_or_else(|| "(invalid endpoint_url)".to_owned());
                    let host = target.host_str().unwrap_or("receiver").replace(':', "_");
                    let suffix = target.port().map(|p| format!("-{p}")).unwrap_or_default();
                    let separate = parent
                        .join("receivers")
                        .join(format!("{host}{suffix}"))
                        .join("agent.json");
                    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
                    let mut command = format!(
                        "{} --public {} --config {} --language {}",
                        quote(&std::env::current_exe()?.to_string_lossy()),
                        quote(origin),
                        quote(&separate.to_string_lossy()),
                        quote(&args.language)
                    );
                    for (enabled, flag) in [
                        (args.no_realtime, "--no-realtime"),
                        (args.no_compression, "--no-compression"),
                    ] {
                        if enabled {
                            command.push(' ');
                            command.push_str(flag);
                        }
                    }
                    if args.language == "zh-CN" {
                        bail!("此配置已绑定其他接收端，原设备凭据已保留。\n配置文件 (--config): {:?}\n当前接收端: {existing}\n请求接收端 (--public): {receiver}\n接入新节点请使用独立配置文件，执行：\n{command}", args.config);
                    }
                    bail!("Existing device belongs to another receiver; its credentials were preserved.\nConfig file (--config): {:?}\nCurrent receiver: {existing}\nRequested receiver (--public): {receiver}\nUse a separate config to join this node:\n{command}", args.config);
                }
                value
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Reserve before any remote write. Another setup must never
                // silently create a second anonymous space for this config.
                let reservation = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&args.config)?;
                let setup = public_setup(origin, &args.language).await;
                drop(reservation);
                match setup {
                    Ok(value) => value,
                    Err(error) => {
                        std::fs::remove_file(&args.config)?;
                        if error.is::<HtmlReceiverResponse>() {
                            return Err(error);
                        }
                        bail!("Anonymous setup failed. Keep any recovery key printed above; setup was not retried.");
                    }
                }
            }
            Err(error) => return Err(error.into()),
        };
        value["realtime_metrics"] = json!(!args.no_realtime);
        value
            .as_object_mut()
            .unwrap()
            .remove("remote_config_revision");
        value["compress_reports"] = json!(!args.no_compression);
        write_config(&args.config, &value)?;
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
        value["compress_reports"] = json!(!args.no_compression);
        value["realtime_metrics"] = json!(!args.no_realtime);
        value
            .as_object_mut()
            .unwrap()
            .remove("remote_config_revision");
        write_config(&args.config, &value)?;
        // Remove the registration key from the long-running process arguments.
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.arg("--config").arg(&args.config);
        command.arg("--language").arg(&args.language);
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
    let signing_key = if let Some(seed) = config["device_private_key"].as_str() {
        keys::SigningKey::from_seed(seed)?
    } else {
        let (key, seed) = keys::SigningKey::generate()?;
        let mut saved = read_config(&args.config)?;
        if saved["auth_token"].as_str() != Some(token.as_str()) {
            bail!("Config changed during device key creation");
        }
        saved["device_private_key"] = json!(seed);
        write_config(&args.config, &saved)?;
        key
    };
    let mut interval_ms = config["interval"]
        .as_u64()
        .unwrap_or(60_000)
        .clamp(5_000, 1_800_000);
    // Enabled by Public configurations; existing receiver configurations retain
    // their transport until a local operator explicitly enables compression.
    let mut compress_reports =
        config["compress_reports"].as_bool().unwrap_or(false) && !args.no_compression;
    let mut realtime_metrics =
        config["realtime_metrics"].as_bool().unwrap_or(true) && !args.no_realtime;
    if args.language == "zh-CN" {
        println!("配置文件 (--config): {:?}\n上报地址 (--endpoint / --public): {endpoint}\n设备 ID: {}\n完整报告间隔 (interval): {interval_ms} ms\n实时采样 (realtime_metrics / --no-realtime): {realtime_metrics}\n压缩 (compress_reports / --no-compression): {compress_reports}\n运行模式: 只读采集；更新须在本机手动执行", args.config, identity.agent_id);
    } else {
        println!("Config file (--config): {:?}\nReport URL (--endpoint / --public): {endpoint}\nDevice ID: {}\nFull report interval (interval): {interval_ms} ms\nRealtime samples (realtime_metrics / --no-realtime): {realtime_metrics}\nCompression (compress_reports / --no-compression): {compress_reports}\nMode: read-only collection; updates require a local operator", args.config, identity.agent_id);
    }
    let mut applied_revision = config["remote_config_revision"].as_str().map(str::to_owned);
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
                            "accounting_version",
                            "accounting_scope",
                            "default_route_interfaces",
                            "traffic_groups",
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
        report.metadata.capabilities["telemetry.metrics"] = json!(realtime_metrics);
        report.metadata.capabilities["telemetry.compression"] = json!(compress_reports);
        report.metadata.capabilities["telemetry.settings"] = json!(1);
        report.metadata.capabilities["telemetry.config_revision"] = json!(applied_revision);
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
        let mut receiver_html = false;
        for attempt in 0..=2 {
            match post_report(
                &client,
                &endpoint,
                &token,
                &bytes,
                compressed,
                !full,
                &signing_key,
            )
            .await
            {
                Ok(value) => {
                    response = Some(value);
                    break;
                }
                // reqwest errors contain URLs but never the Authorization header;
                // print only the failure class to keep endpoint details private.
                Err(error) if error.is::<HtmlReceiverResponse>() => {
                    warn!("{error} Retrying the same receiver in at least 60 seconds; credentials remain unchanged.");
                    receiver_html = true;
                    break;
                }
                Err(_) => warn!(attempt, "Report delivery failed"),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        }
        let mut config_changed = false;
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
                let configuration = &value["agent_config"];
                if configuration["version"].as_u64() == Some(1)
                    && configuration["settings"]
                        .as_object()
                        .is_some_and(|settings| settings.len() == 2)
                {
                    if let (Some(revision), Some(realtime), Some(compression)) = (
                        configuration["revision"].as_str().filter(|revision| {
                            revision.len() == 16
                                && revision.bytes().all(|byte| {
                                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                })
                        }),
                        configuration["settings"]["realtime_metrics"].as_bool(),
                        configuration["settings"]["compress_reports"].as_bool(),
                    ) {
                        if applied_revision.as_deref() != Some(revision)
                            || realtime_metrics != realtime
                            || compress_reports != compression
                        {
                            let mut saved = read_config(&args.config)?;
                            if saved["auth_token"].as_str() != Some(token.as_str()) {
                                bail!("Config changed; refusing to overwrite local credentials");
                            }
                            saved["realtime_metrics"] = json!(realtime);
                            saved["compress_reports"] = json!(compression);
                            saved["remote_config_revision"] = json!(revision);
                            write_config(&args.config, &saved)?;
                            realtime_metrics = realtime;
                            compress_reports = compression;
                            applied_revision = Some(revision.to_owned());
                            config_changed = true;
                        }
                    }
                }
                metrics_ms = value["metrics_interval_ms"]
                    .as_u64()
                    .filter(|_| realtime_metrics)
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
                    full_report_interval_ms = interval_ms,
                    realtime_metrics,
                    realtime_interval_ms = metrics_ms,
                    compress_reports,
                    "Read-only report delivered"
                );
            }
            // All other fields, including commands, terminal payloads,
            // tcp_endpoints and update_version, are deliberately ignored.
        }
        if config_changed {
            full_due = Instant::now();
            continue;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(if receiver_html { interval_ms.max(60_000) } else { metrics_ms.unwrap_or(interval_ms) }).saturating_sub(cycle_started.elapsed())) => {},
        }
    }
    for task in tasks {
        task.abort();
    }
    Ok(())
}
