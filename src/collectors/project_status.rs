use super::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn collect_project_status(
    listeners: &[SecurityListener],
    web_hosts: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "collected_at": chrono::Utc::now().to_rfc3339(),
        "project_metadata": collect_project_metadata_files(),
        "systemd": collect_project_systemd(),
        "docker": collect_project_docker(),
        "listeners": project_status_listeners_json(listeners),
        "web_hosts": web_hosts,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SystemdUnitSummary {
    unit: String,
    load: String,
    active: String,
    sub: String,
    description: String,
}

fn collect_project_systemd() -> serde_json::Value {
    let Some(output) = run_cmd_with_timeout(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        Duration::from_secs(4),
    ) else {
        return serde_json::json!({
            "available": false,
            "units": [],
            "details": [],
            "error": "systemctl list-units timed out or could not start",
        });
    };
    if !output.status.success() {
        return serde_json::json!({
            "available": false,
            "units": [],
            "details": [],
            "error": short_stderr(&output.stderr),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let units = parse_systemd_list_units(&stdout, 200);
    let detail_units: Vec<String> = units
        .iter()
        .filter(|unit| systemd_unit_should_show(unit))
        .take(120)
        .map(|unit| unit.unit.clone())
        .collect();
    let details = collect_systemd_show_details(&detail_units);
    serde_json::json!({
        "available": true,
        "count": units.len(),
        "details_count": details.len(),
        "units": units.iter().map(|unit| serde_json::json!({
            "unit": unit.unit,
            "load": unit.load,
            "active": unit.active,
            "sub": unit.sub,
            "description": unit.description,
        })).collect::<Vec<_>>(),
        "details": details,
    })
}

fn parse_systemd_list_units(output: &str, limit: usize) -> Vec<SystemdUnitSummary> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let mut unit = parts.next()?.trim();
            // Without --plain, systemctl prefixes failed/not-found rows with a
            // single-character status marker (● ○ ×) as its own token; real
            // unit names are never one character.
            if unit.chars().count() == 1 {
                unit = parts.next()?.trim();
            }
            let load = parts.next().unwrap_or("").trim();
            let active = parts.next().unwrap_or("").trim();
            let sub = parts.next().unwrap_or("").trim();
            let description = parts.collect::<Vec<_>>().join(" ");
            if unit.is_empty() {
                return None;
            }
            Some(SystemdUnitSummary {
                unit: unit.to_string(),
                load: load.to_string(),
                active: active.to_string(),
                sub: sub.to_string(),
                description,
            })
        })
        .take(limit)
        .collect()
}

fn systemd_unit_should_show(unit: &SystemdUnitSummary) -> bool {
    if unit.active == "active" || unit.sub == "running" || unit.active == "failed" {
        return true;
    }
    let haystack = format!(
        "{} {}",
        unit.unit.to_ascii_lowercase(),
        unit.description.to_ascii_lowercase()
    );
    [
        "obscura", "radar", "monitor", "caddy", "nginx", "apache", "docker", "postgres", "redis",
        "gitea", "api", "server",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn collect_systemd_show_details(units: &[String]) -> Vec<serde_json::Value> {
    if units.is_empty() {
        return Vec::new();
    }
    let mut args = vec![
        "show".to_string(),
        "--no-pager".to_string(),
        "--property=Id,Names,LoadState,ActiveState,SubState,Description,FragmentPath,ExecStart,WorkingDirectory,Environment,EnvironmentFiles,MainPID".to_string(),
    ];
    args.extend(units.iter().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(output) = run_cmd_with_timeout("systemctl", &arg_refs, Duration::from_secs(8)) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_systemd_show_output(&stdout, &AtomicUsize::new(MAX_ENV_FILE_READS_PER_CYCLE))
}

fn parse_systemd_show_output(
    output: &str,
    env_file_budget: &AtomicUsize,
) -> Vec<serde_json::Value> {
    let mut details = Vec::new();
    let mut block: HashMap<String, String> = HashMap::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            push_systemd_show_block(&mut details, &mut block, env_file_budget);
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            block.insert(key.to_string(), value.to_string());
        }
    }
    push_systemd_show_block(&mut details, &mut block, env_file_budget);
    details
}

fn push_systemd_show_block(
    details: &mut Vec<serde_json::Value>,
    block: &mut HashMap<String, String>,
    env_file_budget: &AtomicUsize,
) {
    if block.is_empty() {
        return;
    }
    let id = block
        .get("Id")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .or_else(|| block.get("Names").cloned())
        .unwrap_or_default();
    if id.is_empty() {
        block.clear();
        return;
    }
    let environment_files = parse_systemd_environment_files(
        block
            .get("EnvironmentFiles")
            .map(String::as_str)
            .unwrap_or(""),
    );
    // EnvironmentFile values land first so `Environment=` keeps systemd's
    // precedence. Only project-identity keys are ever extracted — secret
    // material in env files is never read into the report.
    let mut env = extract_project_env_from_environment_files(&environment_files, env_file_budget);
    for (key, value) in
        extract_project_env_from_systemd(block.get("Environment").map(String::as_str))
    {
        env.insert(key, value);
    }
    let project_id = env
        .get("OBSCURA_PROJECT_ID")
        .or_else(|| env.get("W_RADAR_PROJECT_ID"))
        .or_else(|| env.get("PROJECT_ID"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    details.push(serde_json::json!({
        "unit": id,
        "names": split_systemd_names(block.get("Names").map(String::as_str).unwrap_or("")),
        "load": block.get("LoadState").cloned(),
        "active": block.get("ActiveState").cloned(),
        "sub": block.get("SubState").cloned(),
        "description": block.get("Description").cloned(),
        "fragment_path": block.get("FragmentPath").filter(|value| !value.is_empty()).cloned(),
        "working_directory": block.get("WorkingDirectory").filter(|value| !value.is_empty()).cloned(),
        "environment_files": environment_files,
        "env": env,
        "project_id": project_id,
        "main_pid": block.get("MainPID").and_then(|value| value.parse::<u64>().ok()).filter(|pid| *pid > 0),
        "exec_start": block.get("ExecStart").map(|value| redact_sensitive_command(value)),
    }));
    block.clear();
}

fn split_systemd_names(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .take(10)
        .map(str::to_string)
        .collect()
}

fn parse_systemd_environment_files(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|token| token.trim().trim_start_matches('-'))
        .filter(|token| token.starts_with('/'))
        .map(|token| {
            token
                .split_once(';')
                .map(|(path, _)| path)
                .unwrap_or(token)
                .to_string()
        })
        .take(20)
        .collect()
}

/// Read project-identity keys out of a unit's `EnvironmentFile=` list.
/// `systemctl show` reports file paths but not their contents, and the
/// `Environment=` property alone misses services whose env lives entirely
/// in a file — the common W deployment shape. Reads are bounded: at most
/// `MAX_ENV_FILE_BYTES` per file and `MAX_ENV_FILE_READS_PER_CYCLE` files
/// per collection cycle; unreadable files are skipped silently.
const MAX_ENV_FILE_BYTES: usize = 64 * 1024;
const MAX_ENV_FILE_READS_PER_CYCLE: usize = 200;

fn extract_project_env_from_environment_files(
    paths: &[String],
    budget: &AtomicUsize,
) -> serde_json::Map<String, serde_json::Value> {
    let mut env = serde_json::Map::new();
    for path in paths.iter().take(20) {
        if budget
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |left| left.checked_sub(1),
            )
            .is_err()
        {
            break;
        }
        let Ok(content) = std::fs::read(path) else {
            continue;
        };
        let content = &content[..content.len().min(MAX_ENV_FILE_BYTES)];
        let text = String::from_utf8_lossy(content);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, raw_value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if is_project_identity_env_key(key) {
                env.insert(
                    key.to_string(),
                    serde_json::json!(trim_env_quotes(raw_value.trim())),
                );
            }
        }
    }
    env
}

fn extract_project_env_from_systemd(
    value: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut env = serde_json::Map::new();
    let Some(value) = value else {
        return env;
    };
    for token in value.split_whitespace() {
        if let Some((key, raw_value)) = token.split_once('=') {
            if is_project_identity_env_key(key) {
                env.insert(
                    key.to_string(),
                    serde_json::json!(trim_env_quotes(raw_value)),
                );
            }
        }
    }
    env
}

fn is_project_identity_env_key(key: &str) -> bool {
    matches!(
        key,
        "OBSCURA_PROJECT_ID"
            | "W_RADAR_PROJECT_ID"
            | "PROJECT_ID"
            | "SERVICE_NAME"
            | "APP_ENV"
            | "APP_RELEASE"
            | "APP_VERSION"
    )
}

fn trim_env_quotes(value: &str) -> String {
    value.trim_matches('"').trim_matches('\'').to_string()
}

fn redact_sensitive_command(value: &str) -> String {
    fn sensitive_name(value: &str) -> bool {
        let compact = value
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        [
            "secret",
            "password",
            "passwd",
            "token",
            "apikey",
            "accesskey",
            "privatekey",
            "credential",
        ]
        .iter()
        .any(|marker| compact.contains(marker))
    }

    fn exact_credential_flag(value: &str) -> bool {
        matches!(
            value,
            "-u" | "--user" | "--userpwd" | "--proxy-user" | "--proxy-userpwd" | "--oauth2-bearer"
        )
    }

    let mut redacted = Vec::new();
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RedactionState {
        None,
        SecretValue,
        AuthorizationScheme,
        AuthorizationCredential,
    }

    let mut state = RedactionState::None;
    for token in value.split_whitespace().take(80) {
        let lower = token
            .trim_matches(['\'', '"', '[', ']', '{', '}', ','])
            .to_ascii_lowercase();
        match state {
            RedactionState::SecretValue | RedactionState::AuthorizationCredential => {
                redacted.push("<redacted>".to_string());
                state = RedactionState::None;
                continue;
            }
            RedactionState::AuthorizationScheme => {
                if matches!(lower.trim_matches([':', ';']), "bearer" | "basic" | "token") {
                    redacted.push("<auth-scheme>".to_string());
                    state = RedactionState::AuthorizationCredential;
                } else {
                    redacted.push("<redacted>".to_string());
                    state = RedactionState::None;
                }
                continue;
            }
            RedactionState::None => {}
        }

        if !lower.starts_with("--")
            && lower
                .strip_prefix("-u")
                .is_some_and(|value| !value.is_empty())
        {
            redacted.push("-u<redacted>".to_string());
            continue;
        }

        if let Some((flag, _)) = lower.split_once('=') {
            if exact_credential_flag(flag) {
                let original_flag = token.split_once('=').map(|(flag, _)| flag).unwrap_or(flag);
                redacted.push(format!("{original_flag}=<redacted>"));
                continue;
            }
        }

        if matches!(
            lower.as_str(),
            "--password"
                | "--passwd"
                | "--token"
                | "--auth-token"
                | "--bearer-token"
                | "--secret"
                | "--network-secret"
                | "--client-secret"
                | "--api-key"
                | "--apikey"
                | "--access-key"
                | "--secret-access-key"
                | "--aws-access-key-id"
                | "--aws-secret-access-key"
                | "--private-key"
        ) || exact_credential_flag(&lower)
        {
            redacted.push(token.to_string());
            state = RedactionState::SecretValue;
            continue;
        }
        if lower.contains("authorization:") {
            let auth_tail = lower
                .split_once("authorization:")
                .map(|(_, tail)| tail.trim_matches(['\'', '"', ':', ';']))
                .unwrap_or_default();
            redacted.push("<redacted-authorization>".to_string());
            state = if auth_tail.is_empty() {
                RedactionState::AuthorizationScheme
            } else if matches!(auth_tail, "bearer" | "basic" | "token") {
                RedactionState::AuthorizationCredential
            } else {
                RedactionState::None
            };
            continue;
        }
        if let Some((header_name, header_value)) = lower.split_once(':') {
            if sensitive_name(header_name) {
                redacted.push("<redacted-sensitive-header>".to_string());
                if header_value.trim_matches(['\'', '"']).is_empty() {
                    state = RedactionState::SecretValue;
                }
                continue;
            }
        }
        if lower.starts_with("postgres://")
            || lower.starts_with("mysql://")
            || lower.starts_with("redis://")
            || (lower.contains("://") && lower.contains('@'))
        {
            redacted.push("<redacted-url>".to_string());
            continue;
        }
        if sensitive_name(&lower) {
            if let Some((key, _)) = token.split_once('=') {
                redacted.push(format!("{key}=<redacted>"));
            } else if lower.starts_with('-') {
                redacted.push(token.to_string());
                state = RedactionState::SecretValue;
            } else {
                redacted.push("<redacted>".to_string());
            }
            continue;
        }
        redacted.push(token.to_string());
    }
    redacted.join(" ").chars().take(1000).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DockerContainerSummary {
    id: String,
    name: String,
    image: String,
    status: String,
    ports: String,
}

/// One non-secret Docker inventory is shared by all heavy collectors in a
/// cycle. Each consumer still performs its own narrowly formatted `inspect`
/// so consolidating process calls does not broaden secret-bearing output.
pub(crate) fn docker_ps_inventory_cached() -> Option<Arc<str>> {
    const TTL: Duration = Duration::from_secs(30);
    static CACHE: parking_lot::Mutex<Option<(std::time::Instant, Option<Arc<str>>)>> =
        parking_lot::Mutex::new(None);

    let now = std::time::Instant::now();
    let mut cache = CACHE.lock();
    if let Some((updated_at, value)) = cache.as_ref() {
        if now.saturating_duration_since(*updated_at) < TTL {
            return value.clone();
        }
    }

    let value = run_cmd_with_timeout(
        "docker",
        &[
            "ps",
            "--no-trunc",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Labels}}",
        ],
        Duration::from_secs(4),
    )
    .filter(|output| output.status.success())
    .map(|output| Arc::<str>::from(String::from_utf8_lossy(&output.stdout).into_owned()));
    *cache = Some((now, value.clone()));
    value
}

fn collect_project_docker() -> serde_json::Value {
    let Some(stdout) = docker_ps_inventory_cached() else {
        return serde_json::json!({
            "available": false,
            "containers": [],
            "error": "docker ps timed out or could not start",
        });
    };
    let containers = parse_project_docker_ps(&stdout, 120);
    let ids: Vec<String> = containers
        .iter()
        .map(|container| container.id.clone())
        .collect();
    let inspect = collect_docker_project_inspect(&ids);
    let out = containers
        .iter()
        .map(|container| {
            let mut item = serde_json::json!({
                "id": short_container_id(&container.id),
                "full_id": container.id,
                "name": container.name,
                "image": container.image,
                "status": container.status,
                "ports": container.ports,
            });
            if let Some(extra) = inspect
                .get(&container.id)
                .or_else(|| inspect.get(&short_container_id(&container.id)))
            {
                merge_json_objects(&mut item, extra);
            }
            item
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "available": true,
        "count": out.len(),
        "containers": out,
    })
}

fn parse_project_docker_ps(output: &str, limit: usize) -> Vec<DockerContainerSummary> {
    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 4 {
                return None;
            }
            Some(DockerContainerSummary {
                id: parts[0].trim().to_string(),
                name: parts[1].trim().to_string(),
                image: parts[2].trim().to_string(),
                status: parts[3].trim().to_string(),
                ports: parts.get(4).copied().unwrap_or("").trim().to_string(),
            })
        })
        .take(limit)
        .collect()
}

fn collect_docker_project_inspect(ids: &[String]) -> HashMap<String, serde_json::Value> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let mut args = vec![
        "inspect".to_string(),
        "--format".to_string(),
        "{{.Id}}\t{{.Name}}\t{{json .Config.Env}}\t{{json .Config.Labels}}".to_string(),
    ];
    args.extend(ids.iter().take(120).cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(output) = run_cmd_with_timeout("docker", &arg_refs, Duration::from_secs(8)) else {
        return HashMap::new();
    };
    if !output.status.success() {
        return HashMap::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_docker_project_inspect(&stdout)
}

fn parse_docker_project_inspect(output: &str) -> HashMap<String, serde_json::Value> {
    let mut by_id = HashMap::new();
    for line in output.lines().take(120) {
        let mut parts = line.splitn(4, '\t');
        let id = parts.next().unwrap_or("").trim();
        if id.is_empty() {
            continue;
        }
        let name = parts.next().unwrap_or("").trim().trim_start_matches('/');
        let env_json = parts.next().unwrap_or("[]").trim();
        let labels_json = parts.next().unwrap_or("{}").trim();
        let env = parse_docker_env_project_identity(env_json);
        let labels = parse_docker_label_project_identity(labels_json);
        let project_id = env
            .get("OBSCURA_PROJECT_ID")
            .or_else(|| env.get("W_RADAR_PROJECT_ID"))
            .or_else(|| labels.get("com.obscura.project_id"))
            .or_else(|| labels.get("obscura.project_id"))
            .or_else(|| labels.get("radar.project_id"))
            .or_else(|| labels.get("com.docker.compose.project"))
            .and_then(|value| value.as_str())
            .map(str::to_string);
        by_id.insert(
            id.to_string(),
            serde_json::json!({
                "inspect_name": name,
                "env": env,
                "labels": labels,
                "project_id": project_id,
            }),
        );
    }
    by_id
}

fn parse_docker_env_project_identity(env_json: &str) -> serde_json::Map<String, serde_json::Value> {
    let envs = serde_json::from_str::<Vec<String>>(env_json).unwrap_or_default();
    let mut out = serde_json::Map::new();
    for env in envs {
        let Some((key, value)) = env.split_once('=') else {
            continue;
        };
        if is_project_identity_env_key(key) {
            out.insert(key.to_string(), serde_json::json!(value));
        }
    }
    out
}

fn parse_docker_label_project_identity(
    labels_json: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let labels = serde_json::from_str::<HashMap<String, String>>(labels_json).unwrap_or_default();
    let mut out = serde_json::Map::new();
    for key in [
        "com.obscura.project_id",
        "obscura.project_id",
        "radar.project_id",
        "com.docker.compose.project",
        "com.docker.compose.service",
        "org.opencontainers.image.title",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.source",
    ] {
        if let Some(value) = labels.get(key).filter(|value| !value.trim().is_empty()) {
            out.insert(key.to_string(), serde_json::json!(value));
        }
    }
    out
}

fn short_container_id(id: &str) -> String {
    id.chars().take(12).collect()
}

fn merge_json_objects(target: &mut serde_json::Value, extra: &serde_json::Value) {
    let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) else {
        return;
    };
    for (key, value) in extra {
        target.insert(key.clone(), value.clone());
    }
}

fn project_status_listeners_json(listeners: &[SecurityListener]) -> serde_json::Value {
    serde_json::json!({
        "available": true,
        "count": listeners.len(),
        "services": listeners.iter().take(160).map(|listener| serde_json::json!({
            "protocol": listener.protocol,
            "local_ip": listener.local_ip,
            "local_port": listener.local_port,
            "process": listener.process,
            "pid": listener.pid,
            "scope": listener.scope,
        })).collect::<Vec<_>>(),
    })
}

const PROJECT_METADATA_FILE_SCAN_LIMIT: usize = 180;
const PROJECT_METADATA_FILES_PER_DIR_LIMIT: usize = 80;
const PROJECT_METADATA_DIR_LIMIT: usize = 16;
const PROJECT_METADATA_ID_MAX_CHARS: usize = 256;
const PROJECT_METADATA_PATH_MAX_CHARS: usize = 512;
const PROJECT_METADATA_ENTRY_MAX_BYTES: usize = 16 * 1024;
const PROJECT_METADATA_TOTAL_MAX_BYTES: usize = 512 * 1024;

fn collect_project_metadata_files() -> serde_json::Value {
    let mut entries = Vec::new();
    let (candidate_dirs, candidate_dirs_truncated) = project_metadata_candidate_dirs();
    let (candidate_files, mut truncated) = project_metadata_candidate_files(&candidate_dirs);
    let candidate_count_lower_bound = candidate_files.len();
    truncated |= candidate_files.len() > PROJECT_METADATA_FILE_SCAN_LIMIT;
    let mut retained_bytes = 0usize;
    let mut oversized_entry_count = 0usize;
    for path in candidate_files
        .into_iter()
        .take(PROJECT_METADATA_FILE_SCAN_LIMIT)
    {
        let Some(entry) = read_project_metadata_file(&path) else {
            continue;
        };
        let Ok(encoded) = serde_json::to_vec(&entry) else {
            truncated = true;
            continue;
        };
        if encoded.len() > PROJECT_METADATA_ENTRY_MAX_BYTES {
            oversized_entry_count += 1;
            truncated = true;
            continue;
        }
        if retained_bytes.saturating_add(encoded.len()) > PROJECT_METADATA_TOTAL_MAX_BYTES {
            truncated = true;
            break;
        }
        retained_bytes += encoded.len();
        entries.push(entry);
    }
    serde_json::json!({
        "available": !entries.is_empty(),
        "count": entries.len(),
        "count_semantics": if truncated || candidate_dirs_truncated { "lower_bound" } else { "exact" },
        "candidate_count_lower_bound": candidate_count_lower_bound,
        "truncated": truncated || candidate_dirs_truncated,
        "candidate_dirs_truncated": candidate_dirs_truncated,
        "oversized_entry_count": oversized_entry_count,
        "retained_json_bytes": retained_bytes,
        "max_retained_json_bytes": PROJECT_METADATA_TOTAL_MAX_BYTES,
        "files": entries,
        "candidate_dirs": candidate_dirs.iter().map(|path| path.to_string_lossy().chars().take(PROJECT_METADATA_PATH_MAX_CHARS).collect::<String>()).collect::<Vec<_>>(),
    })
}

fn project_metadata_candidate_files(
    candidate_dirs: &[std::path::PathBuf],
) -> (Vec<std::path::PathBuf>, bool) {
    let mut files = Vec::new();
    let mut truncated = false;
    for path in [
        "/opt/obscura/project.json",
        "/etc/obscura/project.json",
        "/var/cache/obscura/project.json",
    ] {
        let path = std::path::PathBuf::from(path);
        let is_regular = std::fs::symlink_metadata(&path)
            .ok()
            .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink());
        if is_regular {
            files.push(path);
        }
    }
    for dir in candidate_dirs {
        truncated |=
            collect_project_metadata_dir(dir, &mut files, PROJECT_METADATA_FILES_PER_DIR_LIMIT);
    }
    (dedupe_paths(files), truncated)
}

fn project_metadata_candidate_dirs() -> (Vec<std::path::PathBuf>, bool) {
    let mut dirs = Vec::new();
    let mut truncated = false;
    if let Ok(value) = std::env::var("OBSCURA_PROJECT_METADATA_DIR") {
        for raw in value.split(':') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if dirs.len() >= PROJECT_METADATA_DIR_LIMIT.saturating_sub(3) {
                truncated = true;
                break;
            }
            if raw.chars().count() > PROJECT_METADATA_PATH_MAX_CHARS {
                truncated = true;
                continue;
            }
            let path = std::path::PathBuf::from(raw);
            let under_managed_root = [
                "/var/cache/obscura",
                "/etc/obscura",
                "/var/lib/obscura",
                "/opt/obscura",
            ]
            .iter()
            .any(|root| path.starts_with(root));
            if !path.is_absolute() || !under_managed_root {
                truncated = true;
                continue;
            }
            dirs.push(path);
        }
    }
    dirs.extend([
        std::path::PathBuf::from("/var/cache/obscura/projects"),
        std::path::PathBuf::from("/etc/obscura/projects"),
        std::path::PathBuf::from("/var/lib/obscura/projects"),
    ]);
    let mut dirs = dedupe_paths(dirs);
    if dirs.len() > PROJECT_METADATA_DIR_LIMIT {
        dirs.truncate(PROJECT_METADATA_DIR_LIMIT);
        truncated = true;
    }
    (dirs, truncated)
}

fn collect_project_metadata_dir(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
    limit: usize,
) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut retained = 0usize;
    for entry in entries.flatten() {
        if retained >= limit {
            return true;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let is_json = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if is_json {
            files.push(path);
            retained += 1;
        }
    }
    false
}

fn read_project_metadata_file(path: &std::path::Path) -> Option<serde_json::Value> {
    use std::io::Read;

    const MAX_BYTES: usize = 128 * 1024;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Project metadata can live below writable cache directories. Open
        // the checked object itself without following a replacement symlink,
        // and never block the collector on a FIFO/device.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_BYTES {
        return None;
    }
    let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    project_metadata_entry_from_json(path, &value)
}

fn project_metadata_entry_from_json(
    path: &std::path::Path,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let obj = value.as_object()?;
    let filename_project_id = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| *name == "projects")
        .and_then(|_| path.file_stem())
        .and_then(|stem| stem.to_str())
        .filter(|value| value.chars().count() <= PROJECT_METADATA_ID_MAX_CHARS)
        .map(str::to_string);
    let project_id = project_metadata_string(obj, &["project_id", "id", "radar_project_id"])
        .or(filename_project_id)?;
    if project_id.trim().is_empty() || project_id == "project" {
        return None;
    }

    let mut out = serde_json::Map::new();
    let bounded_path = path
        .to_string_lossy()
        .chars()
        .take(PROJECT_METADATA_PATH_MAX_CHARS)
        .collect::<String>();
    out.insert("path".to_string(), serde_json::json!(bounded_path));
    out.insert("project_id".to_string(), serde_json::json!(project_id));
    for key in [
        "name",
        "service",
        "runtime",
        "domain",
        "public_url",
        "bind",
        "workspace_id",
        "environment",
    ] {
        if let Some(value) = obj
            .get(key)
            .filter(|value| project_metadata_value_allowed(value))
        {
            out.insert(key.to_string(), value.clone());
        }
    }
    Some(serde_json::Value::Object(out))
}

fn project_metadata_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .filter_map(|key| obj.get(*key))
        .filter_map(|value| value.as_str())
        .map(str::trim)
        .find(|value| !value.is_empty() && value.chars().count() <= PROJECT_METADATA_ID_MAX_CHARS)
        .map(str::to_string)
}

fn project_metadata_value_allowed(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.len() <= 512 && !looks_sensitive_value(s),
        serde_json::Value::Array(values) => {
            values.len() <= 20
                && values.iter().all(|value| {
                    value
                        .as_str()
                        .is_some_and(|s| s.len() <= 512 && !looks_sensitive_value(s))
                })
        }
        _ => false,
    }
}

fn looks_sensitive_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("postgres://")
        || lower.starts_with("mysql://")
        || lower.starts_with("redis://")
    {
        return true;
    }
    let sensitive_name = |name: &str| {
        let compact = name
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        [
            "password",
            "passwd",
            "token",
            "secret",
            "apikey",
            "accesskey",
            "privatekey",
            "credential",
            "authorization",
            "signature",
        ]
        .iter()
        .any(|marker| compact.contains(marker))
            || compact == "sig"
    };
    if let Ok(url) = reqwest::Url::parse(value) {
        return !url.username().is_empty()
            || url.password().is_some()
            || url.query_pairs().any(|(key, _)| sensitive_name(&key))
            || url.fragment().is_some_and(|fragment| {
                fragment
                    .split(['&', ';'])
                    .filter_map(|part| part.split_once('=').map(|(key, _)| key))
                    .any(sensitive_name)
            });
    }
    lower.contains("://")
        && (lower.contains('@')
            || lower
                .split(['?', '&', ';', '#'])
                .filter_map(|part| part.split_once('=').map(|(key, _)| key))
                .any(sensitive_name))
}

fn short_stderr(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .trim()
        .chars()
        .take(240)
        .collect()
}

pub(crate) fn collect_docker() -> serde_json::Value {
    let Some(output) = docker_ps_inventory_cached() else {
        return serde_json::json!({ "available": false, "containers": [], "count": 0 });
    };

    let mut containers = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }
        containers.push(serde_json::json!({
            "id": &parts[0][..12.min(parts[0].len())],
            "name": parts[1],
            "image": parts[2],
            "status": parts[3],
            "ports": if parts.len() > 4 { parts[4] } else { "" },
        }));
    }

    if !containers.is_empty() {
        // The outer collector scheduler already limits this expensive probe to
        // the heavy cadence, so call-count throttling is unnecessary here.
        if let Some(stats_out) = run_cmd_with_timeout(
            "docker",
            &[
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}",
            ],
            Duration::from_secs(10),
        ) {
            if stats_out.status.success() {
                let stats_str = String::from_utf8_lossy(&stats_out.stdout);
                let mut stats_map: HashMap<String, (String, String)> = HashMap::new();
                for line in stats_str.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 3 {
                        stats_map.insert(
                            parts[0].to_string(),
                            (parts[1].to_string(), parts[2].to_string()),
                        );
                    }
                }
                for c in containers.iter_mut() {
                    if let Some(name) = c.get("name").and_then(|n| n.as_str()) {
                        if let Some((cpu, mem)) = stats_map.get(name) {
                            if let Some(o) = c.as_object_mut() {
                                o.insert("cpu".to_string(), serde_json::json!(cpu));
                                o.insert("mem".to_string(), serde_json::json!(mem));
                            }
                        }
                    }
                }
            }
        }
    }

    serde_json::json!({
        "available": true,
        "count": containers.len(),
        "containers": containers,
    })
}

fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn resolve_easytier_binary_from_paths(
    fixed: &std::path::Path,
    binary_name: &str,
    paths: impl IntoIterator<Item = std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if is_executable_file(fixed) {
        return Some(fixed.to_path_buf());
    }
    paths
        .into_iter()
        .map(|directory| directory.join(binary_name))
        .find(|candidate| is_executable_file(candidate))
}

fn resolve_easytier_cli_from_paths(
    fixed: &std::path::Path,
    paths: impl IntoIterator<Item = std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    resolve_easytier_binary_from_paths(fixed, "easytier-cli", paths)
}

fn resolve_easytier_cli() -> Option<std::path::PathBuf> {
    let fixed = std::path::Path::new("/usr/local/bin/easytier-cli");
    let paths = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>());
    resolve_easytier_cli_from_paths(fixed, paths)
}

fn resolve_easytier_core() -> Option<std::path::PathBuf> {
    let fixed = std::path::Path::new("/usr/local/bin/easytier-core");
    let paths = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>());
    resolve_easytier_binary_from_paths(fixed, "easytier-core", paths)
}

#[cfg(unix)]
fn running_easytier_core_matches_disk(main_pid: u32) -> bool {
    running_easytier_process_contract_at(
        main_pid,
        std::path::Path::new("/proc"),
        std::path::Path::new("/usr/local/bin/easytier-core"),
    )
}

#[cfg(not(unix))]
fn running_easytier_core_matches_disk(_main_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn running_easytier_process_contract_at(
    main_pid: u32,
    proc_root: &std::path::Path,
    core_path: &std::path::Path,
) -> bool {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    const MAX_PROC_METADATA_BYTES: u64 = 1024 * 1024;
    const CANONICAL_CMDLINE: &[u8] = b"/usr/local/bin/easytier-core\0--disable-env-parsing\0--console-log-level\0warn\0-c\0/etc/easytier/easytier.toml\0";
    let process_root = proc_root.join(main_pid.to_string());
    let Ok(disk) = std::fs::metadata(core_path) else {
        return false;
    };
    let Ok(running) = std::fs::metadata(process_root.join("exe")) else {
        return false;
    };
    if disk.dev() != running.dev() || disk.ino() != running.ino() {
        return false;
    }

    let read_bounded = |path: &std::path::Path| -> Option<Vec<u8>> {
        let mut file = std::fs::File::open(path).ok()?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_PROC_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() as u64 <= MAX_PROC_METADATA_BYTES).then_some(bytes)
    };
    let Some(cmdline) = read_bounded(&process_root.join("cmdline")) else {
        return false;
    };
    if cmdline != CANONICAL_CMDLINE {
        return false;
    }
    let Some(environment) = read_bounded(&process_root.join("environ")) else {
        return false;
    };
    !environment
        .split(|byte| *byte == 0)
        .any(|entry| entry.starts_with(b"ET_NETWORK_SECRET="))
}

pub(crate) fn collect_easytier() -> serde_json::Value {
    let Some(easytier_core) = resolve_easytier_core() else {
        return serde_json::json!({ "installed": false });
    };
    let easytier_cli = resolve_easytier_cli();

    // Read the managed configuration before considering any live RPC. A fixed
    // address is configuration identity, not proof that the interface has it.
    let static_state = collect_easytier_static_cached(&easytier_core);
    let service_instance = collect_easytier_service_instance();
    let running = service_instance.is_some();
    let config_contract = static_state
        .service_config
        .config_contract
        .as_deref()
        .filter(|_| {
            service_instance.as_ref().is_some_and(|instance| {
                instance.runtime_contract_ok
                    && running_easytier_core_matches_disk(instance.main_pid)
            })
        })
        .unwrap_or("legacy");

    let observed_ip = collect_easytier_virtual_ip_cached(
        service_instance.as_ref(),
        &static_state.service_config,
        &static_state.config_fingerprint,
        easytier_cli.as_deref(),
    );

    let peer_telemetry =
        collect_easytier_peers_cached(service_instance.as_ref(), easytier_cli.as_deref());

    serde_json::json!({
        "installed": true,
        "running": running,
        "virtual_ip": observed_ip.as_ref().map(|observed| observed.ip.as_str()),
        "virtual_ip_verified": observed_ip.is_some(),
        "virtual_ip_source": observed_ip.as_ref().map(|observed| observed.source.as_str()),
        "network_name": static_state.service_config.network_name.as_deref(),
        "mode": static_state.service_config.mode.as_deref(),
        "configured_ip": static_state.service_config.configured_ip.as_deref(),
        "configured_ip_valid": static_state.service_config.configured_ip.as_deref().and_then(normalize_easytier_configured_ip).is_some(),
        "config_contract": config_contract,
        "listeners": &static_state.service_config.listeners,
        "mapped_listeners": &static_state.service_config.mapped_listeners,
        "version": static_state.version,
        "peer_count": peer_telemetry.peers.len(),
        // Keep the established Server topology fields while making their
        // truth conditions explicit: a binary on disk is not telemetry.
        "peer_telemetry_available": peer_telemetry.probe_succeeded,
        "peer_probe_succeeded": peer_telemetry.probe_succeeded,
        "peer_data_truncated": peer_telemetry.truncated,
        "peer_data_stale": peer_telemetry.stale,
        "peers": peer_telemetry.peers,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EasyTierServiceInstance {
    main_pid: u32,
    active_enter_timestamp_monotonic: u64,
    runtime_contract_ok: bool,
}

fn collect_easytier_service_instance() -> Option<EasyTierServiceInstance> {
    collect_easytier_service_instance_with(|program, args, timeout| {
        run_cmd_with_timeout(program, args, timeout).map(|output| {
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        })
    })
}

fn collect_easytier_service_instance_with<Run>(mut run: Run) -> Option<EasyTierServiceInstance>
where
    Run: FnMut(&str, &[&str], Duration) -> Option<(bool, String)>,
{
    let (command_succeeded, stdout) = run(
        "systemctl",
        &[
            "show",
            "easytier",
            "--no-pager",
            "--property=ActiveState,MainPID,ActiveEnterTimestampMonotonic,FragmentPath,DropInPaths,EnvironmentFiles,Environment,ExecStart,ExecStartPre,ExecStartPost,PassEnvironment",
        ],
        Duration::from_secs(2),
    )?;
    parse_easytier_service_instance(command_succeeded, stdout.as_bytes())
}

fn parse_easytier_service_instance(
    command_succeeded: bool,
    stdout: &[u8],
) -> Option<EasyTierServiceInstance> {
    if !command_succeeded {
        return None;
    }

    let output = String::from_utf8_lossy(stdout);
    let mut active_state = None;
    let mut main_pid = None;
    let mut active_enter_timestamp_monotonic = None;
    let mut fragment_path = None;
    // `systemctl show` omits list properties whose value is empty, so a missing
    // line already means empty; only a printed value can disqualify the contract.
    let mut drop_in_paths = Some("");
    let mut environment_files = Some("");
    let mut environment = None;
    let mut exec_start = None;
    let mut exec_start_pre = Some("");
    let mut exec_start_post = Some("");
    let mut pass_environment = Some("");
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key {
            "ActiveState" => active_state = Some(value),
            "MainPID" => main_pid = value.parse::<u32>().ok(),
            "ActiveEnterTimestampMonotonic" => {
                active_enter_timestamp_monotonic = value.parse::<u64>().ok()
            }
            "FragmentPath" => fragment_path = Some(value),
            "DropInPaths" => drop_in_paths = Some(value),
            "EnvironmentFiles" => environment_files = Some(value),
            "Environment" => environment = Some(value),
            "ExecStart" => exec_start = Some(value),
            "ExecStartPre" => exec_start_pre = Some(value),
            "ExecStartPost" => exec_start_post = Some(value),
            "PassEnvironment" => pass_environment = Some(value),
            _ => {}
        }
    }

    let main_pid = main_pid.filter(|pid| *pid > 0)?;
    let active_enter_timestamp_monotonic =
        active_enter_timestamp_monotonic.filter(|timestamp| *timestamp > 0)?;
    const CANONICAL_EXEC_ARGV: &str = "/usr/local/bin/easytier-core --disable-env-parsing --console-log-level warn -c /etc/easytier/easytier.toml";
    let runtime_contract_ok = fragment_path == Some("/etc/systemd/system/easytier.service")
        && drop_in_paths == Some("")
        && environment_files == Some("")
        && environment == Some("RUST_LOG=warn")
        && exec_start_pre == Some("")
        && exec_start_post == Some("")
        && pass_environment == Some("")
        && exec_start.is_some_and(|value| {
            value.contains("path=/usr/local/bin/easytier-core ;")
                && value.contains(&format!("argv[]={CANONICAL_EXEC_ARGV} ;"))
                && value.matches("path=").count() == 1
                && value.matches("argv[]=").count() == 1
                && !value.contains("--network-secret")
                && !value.contains("ET_NETWORK_SECRET")
        });
    (active_state == Some("active")).then_some(EasyTierServiceInstance {
        main_pid,
        active_enter_timestamp_monotonic,
        runtime_contract_ok,
    })
}

const EASYTIER_DYNAMIC_IP_POSITIVE_TTL: Duration = Duration::from_secs(240);
const EASYTIER_DYNAMIC_IP_NEGATIVE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EasyTierObservedIpSource {
    CliNode,
    Tun0,
}

impl EasyTierObservedIpSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::CliNode => "easytier_cli_node",
            Self::Tun0 => "tun0",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EasyTierObservedIp {
    ip: String,
    source: EasyTierObservedIpSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EasyTierDynamicIpCacheKey {
    config_fingerprint: EasyTierConfigFingerprint,
    service_instance: EasyTierServiceInstance,
    cli_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
struct EasyTierDynamicIpCache {
    key: EasyTierDynamicIpCacheKey,
    updated_at: std::time::Instant,
    observed_ip: Option<EasyTierObservedIp>,
}

static EASYTIER_DYNAMIC_IP_CACHE: std::sync::Mutex<Option<EasyTierDynamicIpCache>> =
    std::sync::Mutex::new(None);

fn collect_easytier_virtual_ip_cached(
    service_instance: Option<&EasyTierServiceInstance>,
    service_config: &EasyTierServiceConfig,
    config_fingerprint: &EasyTierConfigFingerprint,
    easytier_cli: Option<&std::path::Path>,
) -> Option<EasyTierObservedIp> {
    collect_easytier_virtual_ip_with(
        service_instance,
        service_config,
        config_fingerprint,
        easytier_cli,
        &EASYTIER_DYNAMIC_IP_CACHE,
        std::time::Instant::now(),
        |program, args, timeout| {
            run_cmd_with_timeout(program, args, timeout).map(|output| {
                (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                )
            })
        },
    )
}

/// Resolve the live EasyTier address while keeping inactive and fixed-mode
/// collection free of CLI and interface-enumeration subprocesses.
///
/// Dynamic (DHCP or legacy auto-address) results are cached for four minutes;
/// negative probes use a shorter one-minute cache so daemon startup recovery is
/// visible promptly. Cache locks are held only for lookup/store, never while a
/// subprocess is running.
fn collect_easytier_virtual_ip_with<Run>(
    service_instance: Option<&EasyTierServiceInstance>,
    service_config: &EasyTierServiceConfig,
    config_fingerprint: &EasyTierConfigFingerprint,
    easytier_cli: Option<&std::path::Path>,
    cache: &std::sync::Mutex<Option<EasyTierDynamicIpCache>>,
    now: std::time::Instant,
    mut run: Run,
) -> Option<EasyTierObservedIp>
where
    Run: FnMut(&str, &[&str], Duration) -> Option<(bool, String)>,
{
    let Some(service_instance) = service_instance else {
        clear_easytier_dynamic_ip_cache(cache);
        return None;
    };

    if easytier_config_is_fixed(service_config) {
        // configured_ip remains available as identity, but it is not an
        // observed interface address and therefore must not populate virtual_ip.
        clear_easytier_dynamic_ip_cache(cache);
        return None;
    }

    let key = EasyTierDynamicIpCacheKey {
        config_fingerprint: config_fingerprint.clone(),
        service_instance: service_instance.clone(),
        cli_path: easytier_cli.map(std::path::Path::to_path_buf),
    };
    if let Some(cached) = lookup_easytier_dynamic_ip_cache(cache, &key, now) {
        return cached;
    }

    let observed_ip = probe_easytier_dynamic_ip(easytier_cli, &mut run);
    store_easytier_dynamic_ip_cache(cache, key, now, observed_ip.clone());
    observed_ip
}

fn easytier_config_is_fixed(service_config: &EasyTierServiceConfig) -> bool {
    service_config.mode.as_deref() == Some("fixed") || service_config.configured_ip.is_some()
}

fn clear_easytier_dynamic_ip_cache(cache: &std::sync::Mutex<Option<EasyTierDynamicIpCache>>) {
    *cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// `Some(None)` is a valid negative cache hit; outer `None` means miss.
fn lookup_easytier_dynamic_ip_cache(
    cache: &std::sync::Mutex<Option<EasyTierDynamicIpCache>>,
    key: &EasyTierDynamicIpCacheKey,
    now: std::time::Instant,
) -> Option<Option<EasyTierObservedIp>> {
    let cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cached = cache.as_ref().filter(|cached| &cached.key == key)?;
    let ttl = if cached.observed_ip.is_some() {
        EASYTIER_DYNAMIC_IP_POSITIVE_TTL
    } else {
        EASYTIER_DYNAMIC_IP_NEGATIVE_TTL
    };
    (now.saturating_duration_since(cached.updated_at) < ttl).then(|| cached.observed_ip.clone())
}

fn store_easytier_dynamic_ip_cache(
    cache: &std::sync::Mutex<Option<EasyTierDynamicIpCache>>,
    key: EasyTierDynamicIpCacheKey,
    now: std::time::Instant,
    observed_ip: Option<EasyTierObservedIp>,
) {
    *cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(EasyTierDynamicIpCache {
        key,
        updated_at: now,
        observed_ip,
    });
}

fn normalize_easytier_configured_ip(value: &str) -> Option<String> {
    let value = value.trim();
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    if prefix.is_some_and(|prefix| prefix.parse::<u8>().ok().is_none_or(|prefix| prefix > 32)) {
        return None;
    }
    address
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|address| address.to_string())
}

fn probe_easytier_dynamic_ip<Run>(
    easytier_cli: Option<&std::path::Path>,
    run: &mut Run,
) -> Option<EasyTierObservedIp>
where
    Run: FnMut(&str, &[&str], Duration) -> Option<(bool, String)>,
{
    // easytier-cli node can block while the daemon is unreachable (Unix socket
    // accept timeout). Apply a five-second hard limit, and only trust successful
    // command output.
    let from_cli = easytier_cli
        .and_then(|cli| run(&cli.to_string_lossy(), &["node"], Duration::from_secs(5)))
        .filter(|(success, _)| *success)
        .and_then(|(_, stdout)| parse_easytier_node_ip(&stdout))
        .map(|ip| EasyTierObservedIp {
            ip,
            source: EasyTierObservedIpSource::CliNode,
        });
    if from_cli.is_some() {
        return from_cli;
    }

    run(
        "ip",
        &["-4", "addr", "show", "dev", "tun0"],
        Duration::from_secs(2),
    )
    .filter(|(success, _)| *success)
    .and_then(|(_, stdout)| parse_easytier_tun_ip(&stdout))
    .map(|ip| EasyTierObservedIp {
        ip,
        source: EasyTierObservedIpSource::Tun0,
    })
}

fn parse_easytier_node_ip(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("ipv4") || line.contains("virtual_ip") {
            let ip = line
                .split(|character: char| !character.is_ascii_digit() && character != '.')
                .filter_map(parse_rfc1918_ipv4)
                .next();
            if ip.is_some() {
                return ip;
            }
        }
    }
    None
}

fn parse_easytier_tun_ip(output: &str) -> Option<String> {
    let mut current_is_tun0 = false;
    for line in output.lines() {
        if !line.starts_with(' ') {
            current_is_tun0 = line
                .split(':')
                .nth(1)
                .is_some_and(|interface| interface.trim() == "tun0");
        } else if current_is_tun0 {
            let mut fields = line.split_whitespace();
            while let Some(field) = fields.next() {
                if field == "inet" {
                    if let Some(ip) = fields
                        .next()
                        .and_then(|value| value.split('/').next())
                        .and_then(parse_observed_ipv4)
                    {
                        return Some(ip);
                    }
                    break;
                }
            }
        }
    }
    None
}

fn parse_rfc1918_ipv4(value: &str) -> Option<String> {
    let address = value.parse::<std::net::Ipv4Addr>().ok()?;
    address.is_private().then(|| address.to_string())
}

fn parse_observed_ipv4(value: &str) -> Option<String> {
    let address = value.parse::<std::net::Ipv4Addr>().ok()?;
    (!address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast())
    .then(|| address.to_string())
}

const EASYTIER_MAX_PEERS: usize = 256;
const EASYTIER_PEERS_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default, PartialEq)]
struct EasyTierPeerSample {
    peers: Vec<serde_json::Value>,
    truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct EasyTierPeerTelemetry {
    probe_succeeded: bool,
    peers: Vec<serde_json::Value>,
    truncated: bool,
    stale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EasyTierPeerCacheKey {
    service_instance: EasyTierServiceInstance,
    cli_path: std::path::PathBuf,
}

#[derive(Debug, Clone)]
struct EasyTierPeerCache {
    key: EasyTierPeerCacheKey,
    attempted_at: std::time::Instant,
    probe_succeeded: bool,
    last_success: Option<EasyTierPeerSample>,
}

static EASYTIER_PEER_CACHE: std::sync::Mutex<Option<EasyTierPeerCache>> =
    std::sync::Mutex::new(None);

/// Remote mesh peers via `easytier-cli peer`, TTL-cached.
///
/// This runs on both the report cycle and the realtime WS tick (500 ms), so
/// the subprocess result is cached: peer topology changes on the order of
/// minutes, not seconds. Failed refreshes retain the last successful sample
/// and mark it stale rather than falsely reporting an observed zero-peer mesh.
fn collect_easytier_peers_cached(
    service_instance: Option<&EasyTierServiceInstance>,
    cli: Option<&std::path::Path>,
) -> EasyTierPeerTelemetry {
    collect_easytier_peers_with_cache(
        service_instance,
        cli,
        &EASYTIER_PEER_CACHE,
        std::time::Instant::now(),
        fetch_easytier_peers,
    )
}

fn collect_easytier_peers_with_cache<Fetch>(
    service_instance: Option<&EasyTierServiceInstance>,
    cli: Option<&std::path::Path>,
    cache: &std::sync::Mutex<Option<EasyTierPeerCache>>,
    now: std::time::Instant,
    mut fetch: Fetch,
) -> EasyTierPeerTelemetry
where
    Fetch: FnMut(&std::path::Path) -> Option<EasyTierPeerSample>,
{
    let (Some(service_instance), Some(cli)) = (service_instance, cli) else {
        *cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        return EasyTierPeerTelemetry::default();
    };
    let key = EasyTierPeerCacheKey {
        service_instance: service_instance.clone(),
        cli_path: cli.to_path_buf(),
    };

    {
        let cache = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = cache.as_ref().filter(|cached| cached.key == key) {
            if now.saturating_duration_since(cached.attempted_at) < EASYTIER_PEERS_TTL {
                return easytier_peer_telemetry_from_cache(cached);
            }
        }
    }

    // Never hold the cache lock while the EasyTier RPC subprocess is running.
    let probe = fetch(cli);
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous_success = cache
        .as_ref()
        .filter(|cached| cached.key == key)
        .and_then(|cached| cached.last_success.clone());
    *cache = Some(EasyTierPeerCache {
        key,
        attempted_at: now,
        probe_succeeded: probe.is_some(),
        last_success: probe.or(previous_success),
    });
    easytier_peer_telemetry_from_cache(cache.as_ref().expect("peer cache was just populated"))
}

fn easytier_peer_telemetry_from_cache(cache: &EasyTierPeerCache) -> EasyTierPeerTelemetry {
    let Some(sample) = cache.last_success.as_ref() else {
        return EasyTierPeerTelemetry::default();
    };
    EasyTierPeerTelemetry {
        probe_succeeded: cache.probe_succeeded,
        peers: sample.peers.clone(),
        truncated: sample.truncated,
        stale: !cache.probe_succeeded,
    }
}

fn fetch_easytier_peers(cli: &std::path::Path) -> Option<EasyTierPeerSample> {
    use std::sync::atomic::AtomicU8;

    // Whether this host's easytier-cli supports `-o json`: 0 unknown, 1 yes,
    // 2 no.  Memoized so old CLIs don't pay for a doomed attempt every call.
    static JSON_SUPPORT: AtomicU8 = AtomicU8::new(0);

    fetch_easytier_peers_with(cli, &JSON_SUPPORT, |program, args, timeout| {
        run_cmd_with_timeout(program, args, timeout).map(|output| {
            (
                output.status.success(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        })
    })
}

fn fetch_easytier_peers_with<Run>(
    cli: &std::path::Path,
    json_support: &std::sync::atomic::AtomicU8,
    mut run: Run,
) -> Option<EasyTierPeerSample>
where
    Run: FnMut(&str, &[&str], Duration) -> Option<(bool, String)>,
{
    use std::sync::atomic::Ordering;

    const TIMEOUT: Duration = Duration::from_secs(3);

    let cli = cli.to_string_lossy();

    if json_support.load(Ordering::Relaxed) != 2 {
        match run(&cli, &["-o", "json", "peer"], TIMEOUT) {
            Some((true, stdout)) => {
                if let Ok(serde_json::Value::Array(rows)) =
                    serde_json::from_str::<serde_json::Value>(&stdout)
                {
                    if let Some(sample) = normalize_peer_rows_checked(rows) {
                        json_support.store(1, Ordering::Relaxed);
                        return Some(sample);
                    }
                }
                json_support.store(2, Ordering::Relaxed);
            }
            // Exited non-zero: CLI predates `-o json`; fall through to the
            // table format below and never try JSON again.
            Some((false, _)) => json_support.store(2, Ordering::Relaxed),
            // Timeout / spawn failure: the easytier RPC is likely wedged or
            // the CLI is absent — the table call would hang the same way.
            None => return None,
        }
    }

    let (succeeded, stdout) = run(&cli, &["peer"], TIMEOUT)?;
    if !succeeded {
        return None;
    }
    let rows = parse_easytier_peer_table_checked(&stdout)?;
    normalize_peer_rows_checked(rows)
}

/// Normalizes peer rows from either easytier-cli output format into one fixed
/// schema and drops the local node's own row (cost `Local`):
/// `{"ipv4": "10.0.0.2", "hostname": "…", "cost": "p2p", "lat_ms": 235.5,
///   "nat_type": "PortRestricted", "version": "2.6.4-8428a89d"}`
/// `lat_ms` is a number or null; `ipv4` has any `/prefix` stripped.
#[cfg(test)]
fn normalize_peer_rows(rows: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    normalize_peer_rows_checked(rows)
        .map(|sample| sample.peers)
        .unwrap_or_default()
}

fn normalize_peer_rows_checked(rows: Vec<serde_json::Value>) -> Option<EasyTierPeerSample> {
    let mut peers = Vec::new();
    let mut truncated = false;
    for row in rows {
        let row = row.as_object()?;
        if ![
            "ipv4",
            "cidr",
            "hostname",
            "cost",
            "nat_type",
            "nat",
            "protocol",
            "tunnel_proto",
            "tunnel",
            "version",
        ]
        .iter()
        .any(|key| {
            row.get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        }) {
            return None;
        }
        let get = |keys: &[&str], limit: usize| -> String {
            keys.iter()
                .find_map(|key| row.get(*key).and_then(serde_json::Value::as_str))
                .unwrap_or("")
                .chars()
                .take(limit)
                .collect()
        };
        let cost = get(&["cost"], 64);
        if cost.eq_ignore_ascii_case("local") {
            continue;
        }
        if peers.len() == EASYTIER_MAX_PEERS {
            truncated = true;
            continue;
        }
        let ipv4 = get(&["ipv4", "cidr"], 64)
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let numeric = |keys: &[&str], suffix: char| {
            keys.iter().find_map(|key| row.get(*key)).and_then(|value| {
                value.as_f64().or_else(|| {
                    value
                        .as_str()?
                        .trim()
                        .trim_end_matches(suffix)
                        .trim()
                        .parse()
                        .ok()
                })
            })
        };
        let lat_ms = numeric(&["lat_ms", "latency_ms"], ' ');
        let loss_percent = numeric(&["loss_percent", "loss_rate", "loss"], '%');
        peers.push(serde_json::json!({
            "ipv4": ipv4,
            "hostname": get(&["hostname"], 255),
            "cost": cost,
            "lat_ms": lat_ms,
            "loss_percent": loss_percent,
            "rx": get(&["rx", "rx_bytes"], 64),
            "tx": get(&["tx", "tx_bytes"], 64),
            "protocol": get(&["protocol", "tunnel_proto", "tunnel"], 64),
            "nat_type": get(&["nat_type", "nat"], 64),
            "version": get(&["version"], 128),
        }));
    }
    Some(EasyTierPeerSample { peers, truncated })
}

/// Parses easytier-cli's peer table into one JSON object per row, keyed by
/// the normalized header cells.  Handles both the markdown-style `|` table
/// (2.6.x) and the older unicode box-drawing `│` table.
#[cfg(test)]
fn parse_easytier_peer_table(output: &str) -> Vec<serde_json::Value> {
    parse_easytier_peer_table_checked(output).unwrap_or_default()
}

fn parse_easytier_peer_table_checked(output: &str) -> Option<Vec<serde_json::Value>> {
    let mut header: Option<Vec<String>> = None;
    let mut peers = Vec::new();

    for line in output.lines() {
        let bar = if line.contains('│') {
            '│'
        } else if line.contains('|') {
            '|'
        } else {
            continue; // pure box-drawing border row (┌─┬┐ ├─┼┤ └─┴┘)
        };
        let mut cells: Vec<&str> = line.split(bar).collect();
        if cells.len() < 3 {
            continue;
        }
        // split() yields empty fragments before the first and after the last bar.
        cells.remove(0);
        cells.pop();
        let cells: Vec<String> = cells.iter().map(|c| c.trim().to_string()).collect();

        // Markdown separator row: |---|---|
        if cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }

        match &header {
            None => {
                header = Some(cells.iter().map(|c| normalize_header_key(c)).collect());
            }
            Some(keys) => {
                let mut obj = serde_json::Map::new();
                for (key, value) in keys.iter().zip(cells.iter()) {
                    if !key.is_empty() {
                        obj.insert(key.clone(), serde_json::Value::String(value.clone()));
                    }
                }
                if !obj.is_empty() {
                    peers.push(serde_json::Value::Object(obj));
                }
            }
        }
    }

    let header = header?;
    // A successful command with a real EasyTier header and zero remote rows is
    // a valid empty observation. Arbitrary stdout must not masquerade as one.
    let recognized = header.iter().any(|key| key == "ipv4" || key == "cidr")
        && header.iter().any(|key| key == "hostname" || key == "cost");
    recognized.then_some(peers)
}

/// `"lat(ms)"` → `lat_ms`, `"NAT"` → `nat`: lowercase, non-alphanumerics
/// collapse to single underscores, trimmed at both ends.
fn normalize_header_key(cell: &str) -> String {
    let mut key = String::new();
    for ch in cell.chars() {
        if ch.is_ascii_alphanumeric() {
            key.push(ch.to_ascii_lowercase());
        } else if !key.ends_with('_') && !key.is_empty() {
            key.push('_');
        }
    }
    key.trim_end_matches('_').to_string()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EasyTierServiceConfig {
    network_name: Option<String>,
    mode: Option<String>,
    configured_ip: Option<String>,
    config_contract: Option<String>,
    listeners: Vec<String>,
    mapped_listeners: Vec<String>,
}

const MANAGED_EASYTIER_EXEC_START: &str =
    "/usr/local/bin/easytier-core --disable-env-parsing --console-log-level warn -c /etc/easytier/easytier.toml";
const MANAGED_EASYTIER_LISTENERS: &str = "[\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]";
const MANAGED_EASYTIER_LISTENERS_WITH_WS: &str =
    "[\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\", \"ws://127.0.0.1:11012/\"]";
const MANAGED_EASYTIER_UNIT: &str = "[Unit]\n\
Description=EasyTier Core Service\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
Environment=RUST_LOG=warn\n\
ExecStart=/usr/local/bin/easytier-core --disable-env-parsing --console-log-level warn -c /etc/easytier/easytier.toml\n\
Restart=on-failure\n\
RestartSec=5s\n\
UMask=0077\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

fn file_fingerprint(path: &str) -> Option<FileFingerprint> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Some(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        mode: metadata.mode(),
        #[cfg(unix)]
        uid: metadata.uid(),
        #[cfg(unix)]
        gid: metadata.gid(),
    })
}

#[cfg(unix)]
fn root_owned_regular_file_with_mode(path: &str, expected_mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == expected_mode
    })
}

#[cfg(not(unix))]
fn root_owned_regular_file_with_mode(_path: &str, _expected_mode: u32) -> bool {
    false
}

#[cfg(unix)]
fn root_owned_directory_with_mode(path: &str, expected_mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == expected_mode
    })
}

#[cfg(not(unix))]
fn root_owned_directory_with_mode(_path: &str, _expected_mode: u32) -> bool {
    false
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EasyTierConfigFingerprint {
    service: Option<FileFingerprint>,
    configuration: Option<FileFingerprint>,
}

#[derive(Debug, Clone, Default)]
struct EasyTierStaticCache {
    service_fingerprint: Option<FileFingerprint>,
    env_fingerprint: Option<FileFingerprint>,
    legacy_env_fingerprint: Option<FileFingerprint>,
    managed_files_secure: bool,
    binary_fingerprint: Option<FileFingerprint>,
    cli_fingerprint: Option<FileFingerprint>,
    desired_hash_fingerprint: Option<FileFingerprint>,
    integrity_binary_fingerprint: Option<FileFingerprint>,
    integrity_cli_fingerprint: Option<FileFingerprint>,
    integrity_config_fingerprint: Option<FileFingerprint>,
    integrity_desired_hash_fingerprint: Option<FileFingerprint>,
    binary_hashes_match: bool,
    desired_config_hash_matches: bool,
    service_config: EasyTierServiceConfig,
    version: String,
}

#[derive(Debug, Clone)]
struct EasyTierStaticInputs {
    service_fingerprint: Option<FileFingerprint>,
    env_fingerprint: Option<FileFingerprint>,
    legacy_env_fingerprint: Option<FileFingerprint>,
    managed_files_secure: bool,
    binary_fingerprint: Option<FileFingerprint>,
    cli_fingerprint: Option<FileFingerprint>,
    desired_hash_fingerprint: Option<FileFingerprint>,
}

#[derive(Debug, Clone)]
struct EasyTierStaticState {
    service_config: EasyTierServiceConfig,
    version: String,
    config_fingerprint: EasyTierConfigFingerprint,
}

fn refresh_easytier_static_cache<
    LoadBinaryIntegrity,
    LoadConfigIntegrity,
    LoadConfig,
    LoadVersion,
>(
    cache: &mut Option<EasyTierStaticCache>,
    inputs: EasyTierStaticInputs,
    load_binary_integrity: LoadBinaryIntegrity,
    load_config_integrity: LoadConfigIntegrity,
    load_config: LoadConfig,
    load_version: LoadVersion,
) -> (EasyTierServiceConfig, String)
where
    LoadBinaryIntegrity: FnOnce() -> bool,
    LoadConfigIntegrity: FnOnce() -> bool,
    LoadConfig: FnOnce(bool, bool) -> Option<EasyTierServiceConfig>,
    LoadVersion: FnOnce() -> Option<String>,
{
    let config_is_current = cache.as_ref().is_some_and(|cached| {
        cached.service_fingerprint == inputs.service_fingerprint
            && cached.env_fingerprint == inputs.env_fingerprint
            && cached.legacy_env_fingerprint == inputs.legacy_env_fingerprint
            && cached.managed_files_secure == inputs.managed_files_secure
            && cached.binary_fingerprint == inputs.binary_fingerprint
            && cached.cli_fingerprint == inputs.cli_fingerprint
            && cached.desired_hash_fingerprint == inputs.desired_hash_fingerprint
    });
    let version_is_current = cache.as_ref().is_some_and(|cached| {
        cached.binary_fingerprint == inputs.binary_fingerprint && !cached.version.is_empty()
    });
    let mut next = cache.clone().unwrap_or_default();
    let binary_integrity_is_current = cache.as_ref().is_some_and(|cached| {
        cached.integrity_binary_fingerprint == inputs.binary_fingerprint
            && cached.integrity_cli_fingerprint == inputs.cli_fingerprint
    });
    if !binary_integrity_is_current {
        next.binary_hashes_match = load_binary_integrity();
        next.integrity_binary_fingerprint = inputs.binary_fingerprint.clone();
        next.integrity_cli_fingerprint = inputs.cli_fingerprint.clone();
    }
    let config_integrity_is_current = cache.as_ref().is_some_and(|cached| {
        cached.integrity_config_fingerprint == inputs.env_fingerprint
            && cached.integrity_desired_hash_fingerprint == inputs.desired_hash_fingerprint
    });
    if !config_integrity_is_current {
        next.desired_config_hash_matches = load_config_integrity();
        next.integrity_config_fingerprint = inputs.env_fingerprint.clone();
        next.integrity_desired_hash_fingerprint = inputs.desired_hash_fingerprint.clone();
    }

    if !config_is_current {
        // A metadata/read race or a transient permissions error must not turn
        // into a permanent negative cache. Keep the previous value and its old
        // fingerprint so the next heavy cycle retries the read.
        if let Some(service_config) =
            load_config(next.binary_hashes_match, next.desired_config_hash_matches)
        {
            next.service_fingerprint = inputs.service_fingerprint.clone();
            next.env_fingerprint = inputs.env_fingerprint.clone();
            next.legacy_env_fingerprint = inputs.legacy_env_fingerprint.clone();
            next.managed_files_secure = inputs.managed_files_secure;
            next.binary_fingerprint = inputs.binary_fingerprint.clone();
            next.cli_fingerprint = inputs.cli_fingerprint.clone();
            next.desired_hash_fingerprint = inputs.desired_hash_fingerprint.clone();
            next.service_config = service_config;
        }
    }
    if !version_is_current {
        // Likewise, cache only a successful non-empty version probe. A timeout
        // should be retried on the next heavy cycle even if the binary itself
        // did not change.
        if let Some(version) = load_version().filter(|version| !version.is_empty()) {
            next.binary_fingerprint = inputs.binary_fingerprint;
            next.version = version;
        }
    }

    let result = (next.service_config.clone(), next.version.clone());
    *cache = Some(next);
    result
}

fn read_fingerprinted_text(path: &str, fingerprint: &Option<FileFingerprint>) -> Option<String> {
    match fingerprint {
        Some(_) => std::fs::read_to_string(path).ok(),
        None => Some(String::new()),
    }
}

fn sha256_file_bounded(path: &str, max_bytes: u64) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(hex::encode(digest.finalize()))
}

fn managed_easytier_binary_hashes_match(core_path: &str, cli_path: &str) -> bool {
    let expected: &[(&str, &str)] = match std::env::consts::ARCH {
        "x86_64" => &[(
            "35b854e0c5853c02733870488c977200f6aa06d09c08d5dc7f9f9e150e7be8d5",
            "8da66644ec50dcf618fccf76780991f52dfbe2939797abc0efe0ef4d4c4d3383",
        )],
        "aarch64" => &[(
            "7bd504e87cad52edacb9ea84ece7397d0afb911101de623a3dfc4a4dbd9e6bb6",
            "11cd0c957e41057a49e2580ce6490d7bef8bde0a04602e5bd80a4b17cb30b984",
        )],
        "arm" => &[
            (
                "7f1040fec526ded3990663aa19dabb028fea52a6c6b06ddc1de32668829934b9",
                "46a8ef74596271f98976383b46f4032f1f1aaa9259d443381f2698fc9da9dadf",
            ),
            (
                "085e99ed005b3b7126b734e4ee32e2bdd05831305c0c95f93875be56e88c64fa",
                "8a11a9d43978559a97e26bab8f1ffd25e8c679f14acbd17def7493d69fb27742",
            ),
        ],
        _ => return false,
    };
    let core_hash = sha256_file_bounded(core_path, 128 * 1024 * 1024);
    let cli_hash = sha256_file_bounded(cli_path, 128 * 1024 * 1024);
    expected
        .iter()
        .any(|(core, cli)| core_hash.as_deref() == Some(*core) && cli_hash.as_deref() == Some(*cli))
}

fn desired_easytier_config_hash_matches(config_path: &str, hash_path: &str) -> bool {
    let Ok(stored) = std::fs::read_to_string(hash_path) else {
        return false;
    };
    let Some(expected) = stored.strip_suffix('\n') else {
        return false;
    };
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    sha256_file_bounded(config_path, 1024 * 1024).as_deref() == Some(expected)
}

fn normalize_easytier_version_output(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find_map(|candidate| {
            let mut components = candidate.split('.');
            let (Some(major), Some(minor), Some(patch), None) = (
                components.next(),
                components.next(),
                components.next(),
                components.next(),
            ) else {
                return None;
            };
            (!major.is_empty()
                && !minor.is_empty()
                && !patch.is_empty()
                && [major, minor, patch]
                    .into_iter()
                    .all(|part| part.chars().all(|character| character.is_ascii_digit())))
            .then(|| format!("{major}.{minor}.{patch}"))
        })
}

/// Service configuration and binary version change only when their underlying
/// files change. Fingerprint-based invalidation avoids spawning the relatively
/// expensive EasyTier binary once per telemetry cycle while still refreshing
/// immediately after an atomic managed upgrade.
fn collect_easytier_static_cached(core_binary: &std::path::Path) -> EasyTierStaticState {
    use std::sync::Mutex;

    const SERVICE_PATH: &str = "/etc/systemd/system/easytier.service";
    const CONFIG_DIR: &str = "/etc/easytier";
    const CONFIG_PATH: &str = "/etc/easytier/easytier.toml";
    const LEGACY_ENV_PATH: &str = "/etc/easytier/easytier.env";
    const CORE_PATH: &str = "/usr/local/bin/easytier-core";
    const CLI_PATH: &str = "/usr/local/bin/easytier-cli";
    const STATE_DIR: &str = "/var/lib/w-monitor-easytier";
    const DESIRED_HASH_PATH: &str = "/var/lib/w-monitor-easytier/desired-config.sha256";
    static CACHE: Mutex<Option<EasyTierStaticCache>> = Mutex::new(None);

    let service_fingerprint = file_fingerprint(SERVICE_PATH);
    let (config_path, config_fingerprint) = match file_fingerprint(CONFIG_PATH) {
        Some(fingerprint) => (CONFIG_PATH, Some(fingerprint)),
        None => (LEGACY_ENV_PATH, file_fingerprint(LEGACY_ENV_PATH)),
    };
    let binary_fingerprint = file_fingerprint(CORE_PATH);
    let cli_fingerprint = file_fingerprint(CLI_PATH);
    let desired_hash_fingerprint = file_fingerprint(DESIRED_HASH_PATH);
    let legacy_env_fingerprint = file_fingerprint(LEGACY_ENV_PATH);
    let managed_files_secure = root_owned_regular_file_with_mode(SERVICE_PATH, 0o644)
        && root_owned_directory_with_mode(CONFIG_DIR, 0o700)
        && root_owned_regular_file_with_mode(CONFIG_PATH, 0o600)
        && root_owned_regular_file_with_mode(CORE_PATH, 0o755)
        && root_owned_regular_file_with_mode(CLI_PATH, 0o755)
        && root_owned_directory_with_mode(STATE_DIR, 0o700)
        && root_owned_regular_file_with_mode(DESIRED_HASH_PATH, 0o600);
    let config_service_fingerprint = service_fingerprint.clone();
    let public_config_fingerprint = config_fingerprint.clone();
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (service_config, version) = refresh_easytier_static_cache(
        &mut cache,
        EasyTierStaticInputs {
            service_fingerprint,
            env_fingerprint: config_fingerprint,
            legacy_env_fingerprint: legacy_env_fingerprint.clone(),
            managed_files_secure,
            binary_fingerprint,
            cli_fingerprint,
            desired_hash_fingerprint,
        },
        || managed_easytier_binary_hashes_match(CORE_PATH, CLI_PATH),
        || desired_easytier_config_hash_matches(CONFIG_PATH, DESIRED_HASH_PATH),
        |binary_hashes_match, desired_config_hash_matches| {
            let service = read_fingerprinted_text(SERVICE_PATH, &config_service_fingerprint)?;
            let configuration = read_fingerprinted_text(config_path, &public_config_fingerprint)?;
            let managed_content_secure =
                managed_files_secure && binary_hashes_match && desired_config_hash_matches;
            Some(parse_easytier_service_config_with_source(
                &service,
                &configuration,
                config_path == CONFIG_PATH,
                legacy_env_fingerprint.is_some(),
                managed_content_secure,
            ))
        },
        || {
            run_cmd_with_timeout(
                &core_binary.to_string_lossy(),
                &["--version"],
                Duration::from_secs(3),
            )
            .filter(|output| output.status.success())
            .and_then(|output| normalize_easytier_version_output(&output.stdout))
        },
    );
    let config_fingerprint = cache
        .as_ref()
        .map(|cached| EasyTierConfigFingerprint {
            service: cached.service_fingerprint.clone(),
            configuration: cached.env_fingerprint.clone(),
        })
        .unwrap_or_default();
    EasyTierStaticState {
        service_config,
        version,
        config_fingerprint,
    }
}

#[cfg(test)]
fn parse_easytier_service_config(content: &str) -> EasyTierServiceConfig {
    parse_easytier_service_config_with_config(content, "")
}

#[cfg(test)]
fn parse_easytier_service_config_with_config(
    content: &str,
    configuration: &str,
) -> EasyTierServiceConfig {
    parse_easytier_service_config_with_source(content, configuration, true, false, true)
}

fn parse_easytier_service_config_with_source(
    content: &str,
    configuration: &str,
    managed_toml_present: bool,
    legacy_env_present: bool,
    managed_files_secure: bool,
) -> EasyTierServiceConfig {
    let exec = content
        .lines()
        .find(|line| line.trim_start().starts_with("ExecStart="))
        .map(|line| line.trim_start().trim_start_matches("ExecStart="))
        .unwrap_or(content);
    let parts: Vec<&str> = exec.split_whitespace().collect();

    // Explicit argv wins when reading transitional/legacy units. Managed v2
    // units keep identity in an owner-only TOML file; only the non-secret
    // network name is projected into telemetry.
    let network_name = value_after(&parts, "--network-name")
        .map(str::to_string)
        .or_else(|| toml_value(configuration, Some("network_identity"), "network_name"))
        .or_else(|| environment_value(configuration, "ET_NETWORK_NAME"));
    let configured_ip = value_after(&parts, "-i")
        .or_else(|| value_after(&parts, "--ipv4"))
        .map(str::to_string)
        .or_else(|| toml_value(configuration, None, "ipv4"));
    let mode = if configured_ip.is_some() {
        Some("fixed".to_string())
    } else if parts.iter().any(|part| *part == "-d" || *part == "--dhcp")
        || toml_value(configuration, None, "dhcp").as_deref() == Some("true")
    {
        Some("dhcp".to_string())
    } else {
        None
    };
    let fixed_ips = toml_raw_assignment_values(configuration, None, "ipv4");
    let network_names =
        toml_raw_assignment_values(configuration, Some("network_identity"), "network_name");
    let network_secrets =
        toml_raw_assignment_values(configuration, Some("network_identity"), "network_secret");
    let dhcp_values = toml_raw_assignment_values(configuration, None, "dhcp");
    let listeners = toml_raw_assignment_values(configuration, None, "listeners");
    let parsed_listeners = listeners
        .first()
        .and_then(|raw| toml_string_array(raw))
        .unwrap_or_default();
    let mapped_listeners = toml_raw_assignment_values(configuration, None, "mapped_listeners")
        .first()
        .and_then(|raw| toml_string_array(raw))
        .unwrap_or_default();
    let ws_ingress = listeners == [MANAGED_EASYTIER_LISTENERS_WITH_WS];
    let managed_listeners_contract = listeners == [MANAGED_EASYTIER_LISTENERS] || ws_ingress;
    // The public wss advertisement and its loopback ingress are one feature:
    // a managed TOML may carry neither or both, and every mapped URI must be
    // an explicit-port wss:// endpoint.
    let managed_mapped_listeners_contract = mapped_listeners
        .iter()
        .all(|uri| managed_wss_uri_is_valid(uri))
        && mapped_listeners.is_empty() != ws_ingress;
    let managed_toml_contract = fixed_ips.len() == 1
        && canonical_toml_string(fixed_ips[0]).is_some_and(managed_fixed_ipv4_is_valid)
        && network_names.len() == 1
        && canonical_toml_string(network_names[0]).is_some_and(|value| !value.is_empty())
        && network_secrets.len() == 1
        && canonical_toml_string(network_secrets[0]).is_some_and(|value| !value.is_empty())
        && dhcp_values.is_empty()
        && managed_listeners_contract
        && managed_mapped_listeners_contract;
    let config_contract = (managed_toml_present
        && !legacy_env_present
        && managed_files_secure
        && managed_toml_contract
        && content == MANAGED_EASYTIER_UNIT
        && exec.trim() == MANAGED_EASYTIER_EXEC_START)
        .then(|| "w-monitor-toml-v1".to_string())
        .or_else(|| Some("legacy".to_string()));

    EasyTierServiceConfig {
        network_name,
        mode,
        configured_ip,
        config_contract,
        listeners: parsed_listeners,
        mapped_listeners,
    }
}

fn toml_value(content: &str, section: Option<&str>, key: &str) -> Option<String> {
    toml_assignment_values(content, section, key)
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn toml_assignment_values<'a>(content: &'a str, section: Option<&str>, key: &str) -> Vec<&'a str> {
    toml_raw_assignment_values(content, section, key)
        .into_iter()
        .map(toml_scalar_value)
        .collect()
}

fn toml_raw_assignment_values<'a>(
    content: &'a str,
    section: Option<&str>,
    key: &str,
) -> Vec<&'a str> {
    let mut current_section = None;
    let mut values = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
                .map(str::trim);
            continue;
        }
        if current_section != section {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        values.push(value.trim());
    }
    values
}

fn canonical_toml_string(value: &str) -> Option<&str> {
    let value = value.trim();
    let unquoted = value.strip_prefix('"')?.strip_suffix('"')?;
    (!unquoted.contains(['"', '\\', '\r', '\n'])).then_some(unquoted)
}

/// Parse a TOML basic-string array (`["a", "b"]`). Every entry must be a
/// canonical string, so malformed syntax fails closed instead of producing
/// half-parsed telemetry.
fn toml_string_array(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    inner
        .split(',')
        .map(|item| canonical_toml_string(item).map(str::to_string))
        .collect()
}

/// Mapped listeners must be public wss:// endpoints carrying an explicit
/// numeric port and path (e.g. `wss://edge.example.com:443/etws/`): EasyTier
/// rejects mapped listeners that omit the port on a non-IP scheme, so a
/// TOML carrying one is treated as drift rather than a valid managed config.
fn managed_wss_uri_is_valid(uri: &str) -> bool {
    uri.strip_prefix("wss://").is_some_and(|rest| {
        rest.split_once('/').is_some_and(|(authority, path)| {
            !path.is_empty()
                && authority.rsplit_once(':').is_some_and(|(host, port)| {
                    !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                })
        })
    })
}

fn toml_scalar_value(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn managed_fixed_ipv4_is_valid(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    !address.contains('/')
        && prefix == "16"
        && address.parse::<std::net::Ipv4Addr>().is_ok_and(|address| {
            address != std::net::Ipv4Addr::UNSPECIFIED
                && address != std::net::Ipv4Addr::BROADCAST
                && address.octets()[..2] == [10, 0]
                && !matches!(address.octets()[3], 0 | 255)
        })
}

fn environment_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        let value = value.trim().trim_matches(['"', '\'']);
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn value_after<'a>(parts: &'a [&str], flag: &str) -> Option<&'a str> {
    parts
        .iter()
        .position(|part| *part == flag)
        .and_then(|idx| parts.get(idx + 1))
        .copied()
}
