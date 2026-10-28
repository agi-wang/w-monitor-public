use super::*;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebHostSite {
    server: String,
    domains: Vec<String>,
    listen: Vec<String>,
    tls: bool,
    upstreams: Vec<String>,
    roots: Vec<String>,
    certificate_paths: Vec<String>,
    config_path: String,
    source: String,
    probe_eligible: bool,
}

impl WebHostSite {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "server": self.server,
            "domains": self.domains,
            "listen": self.listen,
            "tls": self.tls,
            "upstreams": self.upstreams,
            "roots": self.roots,
            "certificate_paths": self.certificate_paths,
            "config_path": self.config_path,
            "source": self.source,
            "probe_eligible": self.probe_eligible,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebHostFileState {
    path: std::path::PathBuf,
    len: u64,
    modified_nanos: Option<u128>,
}

#[derive(Debug, Default)]
struct WebHostScanCache {
    result: Option<serde_json::Value>,
    files: Vec<WebHostFileState>,
    full_scanned_at: Option<Instant>,
    checked_at: Option<Instant>,
}

const WEB_HOST_RECENT_CACHE_SECS: u64 = 300;
const WEB_HOST_FULL_RESCAN_SECS: u64 = 3600;

pub(crate) fn collect_web_hosts() -> serde_json::Value {
    static WEB_HOST_CACHE: std::sync::OnceLock<Mutex<WebHostScanCache>> =
        std::sync::OnceLock::new();
    let cache = WEB_HOST_CACHE.get_or_init(|| Mutex::new(WebHostScanCache::default()));
    let mut cache = cache.lock();
    collect_web_hosts_cached(
        &mut cache,
        Instant::now(),
        web_host_candidate_files,
        web_host_file_state,
        |path| {
            let state = web_host_file_state(path)?;
            let content = read_small_text_file(path, 512 * 1024)?;
            Ok((state, content, path.to_string_lossy().to_string()))
        },
        web_host_include_files,
        collect_docker_web_hosts,
    )
}

fn collect_web_hosts_cached<Discover, Stat, Read, Include, Extra>(
    cache: &mut WebHostScanCache,
    now: Instant,
    discover: Discover,
    mut stat: Stat,
    mut read: Read,
    mut include: Include,
    mut extra_sites: Extra,
) -> serde_json::Value
where
    Discover: FnOnce() -> Vec<std::path::PathBuf>,
    Stat: FnMut(&std::path::Path) -> Result<WebHostFileState, String>,
    Read: FnMut(&std::path::Path) -> Result<(WebHostFileState, String, String), String>,
    Include: FnMut(&std::path::Path, &str, &str) -> Vec<std::path::PathBuf>,
    Extra: FnMut() -> Vec<WebHostSite>,
{
    if let Some(result) = cache.result.as_ref() {
        if cache
            .checked_at
            .and_then(|checked| now.checked_duration_since(checked))
            .map(|elapsed| elapsed < Duration::from_secs(WEB_HOST_RECENT_CACHE_SECS))
            .unwrap_or(false)
        {
            return web_host_result_with_cache_state(result, "fresh");
        }
        if cache
            .full_scanned_at
            .and_then(|scanned| now.checked_duration_since(scanned))
            .map(|elapsed| elapsed < Duration::from_secs(WEB_HOST_FULL_RESCAN_SECS))
            .unwrap_or(false)
        {
            let current_states: Result<Vec<_>, _> =
                cache.files.iter().map(|file| stat(&file.path)).collect();
            if let Ok(current_states) = current_states {
                if current_states == cache.files {
                    cache.checked_at = Some(now);
                    return web_host_result_with_cache_state(result, "verified");
                }
            }
        }
    }

    let mut sites = Vec::new();
    let mut warnings = Vec::new();
    let mut scanned_files = 0usize;
    let mut file_states = Vec::new();
    let mut queued = discover();
    let mut seen_paths = HashSet::new();

    while let Some(path) = queued.pop() {
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        match read(&path) {
            Ok((state, content, path_str)) => {
                scanned_files += 1;
                let kind = web_host_config_kind(&path_str);
                let parsed = match kind {
                    "caddy" => parse_caddy_web_hosts(&content, &path_str),
                    "apache" => parse_apache_web_hosts(&content, &path_str),
                    _ => parse_nginx_web_hosts(&content, &path_str),
                };
                for include_path in include(&path, &content, kind) {
                    if seen_paths.len() + queued.len() >= 200 {
                        warnings.push("web host include scan limit reached".to_string());
                        break;
                    }
                    if !seen_paths.contains(&include_path) {
                        queued.push(include_path);
                    }
                }
                file_states.push(state);
                sites.extend(parsed);
            }
            Err(err) => warnings.push(format!("{}: {}", path.display(), err)),
        }
    }
    sites.extend(extra_sites());

    let mut seen_domains = HashSet::new();
    for site in &sites {
        for domain in &site.domains {
            seen_domains.insert(domain.clone());
        }
    }

    let result = serde_json::json!({
        "available": scanned_files > 0,
        "site_count": sites.len(),
        "domain_count": seen_domains.len(),
        "sites": sites.iter().map(WebHostSite::to_json).collect::<Vec<_>>(),
        "warnings": warnings,
        "cache": {
            "state": "refreshed",
            "file_count": file_states.len(),
            "full_rescan_secs": WEB_HOST_FULL_RESCAN_SECS,
            "recent_cache_secs": WEB_HOST_RECENT_CACHE_SECS,
        },
    });
    cache.result = Some(result.clone());
    cache.files = file_states;
    cache.full_scanned_at = Some(now);
    cache.checked_at = Some(now);
    result
}

fn web_host_result_with_cache_state(result: &serde_json::Value, state: &str) -> serde_json::Value {
    let mut next = result.clone();
    if let Some(obj) = next.as_object_mut() {
        let cache = obj
            .entry("cache")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut();
        if let Some(cache) = cache {
            cache.insert("state".to_string(), serde_json::json!(state));
        }
    }
    next
}

fn web_host_candidate_files() -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for path in web_host_static_candidate_files() {
        let p = std::path::PathBuf::from(path);
        if p.is_file() {
            files.push(p);
        }
    }
    for dir in [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/usr/local/openresty/nginx/conf/conf.d",
        "/usr/local/nginx/conf/conf.d",
        "/www/server/panel/vhost/nginx",
        "/www/server/nginx/conf/conf.d",
        "/opt/1panel/apps/openresty/openresty/conf/conf.d",
        "/opt/1panel/apps/openresty/openresty/www/sites",
        "/etc/caddy/conf.d",
        "/etc/caddy/sites",
        "/etc/caddy/sites-enabled",
        "/etc/apache2/sites-enabled",
        "/etc/apache2/conf-enabled",
        "/etc/httpd/conf.d",
        "/www/server/panel/vhost/apache",
    ] {
        collect_web_host_dir_files(std::path::Path::new(dir), &mut files, 80);
    }
    files.extend(web_host_systemd_config_files());
    dedupe_paths(files)
}

fn web_host_static_candidate_files() -> &'static [&'static str] {
    &[
        "/etc/nginx/nginx.conf",
        "/usr/local/openresty/nginx/conf/nginx.conf",
        "/usr/local/nginx/conf/nginx.conf",
        "/www/server/nginx/conf/nginx.conf",
        "/opt/1panel/apps/openresty/openresty/conf/nginx.conf",
        "/etc/caddy/Caddyfile",
        "/usr/local/etc/caddy/Caddyfile",
        "/etc/caddy/caddy.json",
        "/usr/local/etc/caddy/caddy.json",
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
    ]
}

fn web_host_systemd_config_files() -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for service in ["nginx", "openresty", "caddy", "apache2", "httpd"] {
        let Some(output) = run_cmd_with_timeout(
            "systemctl",
            &["show", service, "--property=ExecStart", "--value"],
            Duration::from_secs(2),
        ) else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        files.extend(parse_systemd_web_host_config_paths(&stdout));
    }
    dedupe_paths(files)
        .into_iter()
        .filter(|path| path.is_file())
        .collect()
}

fn parse_systemd_web_host_config_paths(output: &str) -> Vec<std::path::PathBuf> {
    let tokens: Vec<&str> = output
        .split(|ch: char| ch.is_whitespace() || ch == ';')
        .filter(|token| !token.is_empty())
        .collect();
    let mut paths = Vec::new();
    for (idx, token) in tokens.iter().enumerate() {
        let value = if matches!(*token, "-c" | "-f" | "--config" | "--conf") {
            tokens.get(idx + 1).copied()
        } else {
            token
                .strip_prefix("--config=")
                .or_else(|| token.strip_prefix("--conf="))
                .or_else(|| token.strip_prefix("--config.file="))
        };
        let Some(value) = value.map(clean_config_value) else {
            continue;
        };
        if value.starts_with('/') {
            let path = std::path::PathBuf::from(value);
            if !paths.iter().any(|p| p == &path) {
                paths.push(path);
            }
        }
    }
    paths
}

fn web_host_config_kind(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.contains("caddy") || lower.ends_with("caddyfile") {
        "caddy"
    } else if lower.contains("apache2")
        || lower.contains("httpd")
        || lower.contains("/apache/")
        || lower.contains("\\apache\\")
    {
        "apache"
    } else {
        "nginx"
    }
}

fn collect_web_host_dir_files(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
    limit: usize,
) {
    if files.len() >= limit || !dir.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= limit {
            break;
        }
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
}

fn web_host_file_state(path: &std::path::Path) -> Result<WebHostFileState, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let modified_nanos = meta
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    Ok(WebHostFileState {
        path: path.to_path_buf(),
        len: meta.len(),
        modified_nanos,
    })
}

fn web_host_include_files(
    path: &std::path::Path,
    content: &str,
    kind: &str,
) -> Vec<std::path::PathBuf> {
    let base_dir = path.parent().unwrap_or_else(|| std::path::Path::new("/"));
    let mut includes = Vec::new();
    let patterns = match kind {
        "caddy" => caddy_import_patterns(content),
        "apache" => apache_include_patterns(content),
        _ => nginx_include_patterns(content),
    };
    for pattern in patterns {
        for include in expand_web_host_include_pattern(base_dir, &pattern) {
            if includes.len() >= 80 {
                return includes;
            }
            if !includes.iter().any(|p| p == &include) {
                includes.push(include);
            }
        }
    }
    includes
}

fn nginx_include_patterns(content: &str) -> Vec<String> {
    normalized_nginx_directives(content)
        .into_iter()
        .filter_map(|line| {
            line.strip_prefix("include ")
                .map(clean_config_value)
                .map(str::to_string)
        })
        .collect()
}

fn caddy_import_patterns(content: &str) -> Vec<String> {
    normalized_config_lines(content)
        .into_iter()
        .filter_map(|line| {
            line.strip_prefix("import ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(clean_config_value)
                .filter(|value| !value.starts_with('{') && !value.starts_with('('))
                .map(str::to_string)
        })
        .collect()
}

fn apache_include_patterns(content: &str) -> Vec<String> {
    normalized_config_lines(content)
        .into_iter()
        .filter_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("include ") || lower.starts_with("includeoptional ") {
                line.split_whitespace()
                    .nth(1)
                    .map(clean_config_value)
                    .map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

fn expand_web_host_include_pattern(
    base_dir: &std::path::Path,
    pattern: &str,
) -> Vec<std::path::PathBuf> {
    let cleaned = clean_config_value(pattern);
    if cleaned.is_empty() {
        return Vec::new();
    }
    let raw_path = std::path::Path::new(cleaned);
    let full = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        base_dir.join(raw_path)
    };
    let full_str = full.to_string_lossy();
    if !full_str.contains('*') {
        return if full.is_file() {
            vec![full]
        } else {
            Vec::new()
        };
    }
    let Some(parent) = full.parent() else {
        return Vec::new();
    };
    let Some(file_pattern) = full.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if simple_wildcard_match(file_pattern, name) {
            matches.push(path);
        }
    }
    matches.sort();
    matches
}

fn simple_wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }
    if !value.starts_with(parts[0]) {
        return false;
    }
    if let Some(last) = parts.last() {
        if !last.is_empty() && !value.ends_with(last) {
            return false;
        }
    }
    let mut cursor = parts[0].len();
    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        if part.is_empty() {
            continue;
        }
        let Some(found) = value[cursor..].find(part) else {
            return false;
        };
        cursor += found + part.len();
    }
    true
}

fn collect_docker_web_hosts() -> Vec<WebHostSite> {
    let mut sites = Vec::new();
    let Some(inventory) = docker_ps_inventory_cached() else {
        return Vec::new();
    };
    sites.extend(parse_docker_inventory_label_web_host_sites(&inventory));
    sites.extend(collect_docker_env_web_hosts(&inventory));
    sites
}

fn collect_docker_env_web_hosts(inventory: &str) -> Vec<WebHostSite> {
    let ids: Vec<String> = inventory
        .lines()
        .filter_map(|line| line.split('\t').next().map(str::trim))
        .filter(|id| !id.is_empty())
        .take(80)
        .map(str::to_string)
        .collect();
    if ids.is_empty() {
        return Vec::new();
    }

    let mut args = vec![
        "inspect".to_string(),
        "--format".to_string(),
        "{{.Id}}\t{{.Name}}\t{{json .Config.Env}}".to_string(),
    ];
    args.extend(ids);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(output) = run_cmd_with_timeout("docker", &arg_refs, Duration::from_secs(6)) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_docker_env_web_host_sites(&stdout)
}

fn parse_docker_inventory_label_web_host_sites(output: &str) -> Vec<WebHostSite> {
    let projected = output
        .lines()
        .take(80)
        .filter_map(|line| {
            let parts = line.split('\t').collect::<Vec<_>>();
            let id = parts.first()?.trim();
            let name = parts.get(1).copied().unwrap_or("").trim();
            let labels = parts.get(5).copied().unwrap_or("").trim();
            Some(format!("{id}\t{name}\t{labels}"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    parse_docker_label_web_host_sites(&projected)
}

fn parse_docker_label_web_host_sites(output: &str) -> Vec<WebHostSite> {
    let mut sites = Vec::new();
    for line in output.lines().take(80) {
        let mut parts = line.splitn(3, '\t');
        let container_id = parts.next().unwrap_or("").trim();
        let name = parts.next().unwrap_or("").trim();
        let labels = parts.next().unwrap_or("").trim();
        if labels.is_empty() {
            continue;
        }
        let mut domains = Vec::new();
        extract_traefik_host_rule_domains(labels, &mut domains);
        extract_caddy_label_domains(labels, &mut domains);
        if domains.is_empty() {
            continue;
        }
        let source = if name.is_empty() {
            format!("docker:{}", container_id)
        } else {
            format!("docker:{}", name)
        };
        if let Some(site) = build_web_host_site_with_source(
            "docker",
            domains,
            Vec::new(),
            false,
            Vec::new(),
            &source,
            "docker_label",
        ) {
            sites.push(site);
        }
    }
    sites
}

fn extract_traefik_host_rule_domains(labels: &str, domains: &mut Vec<String>) {
    let mut rest = labels;
    while let Some(idx) = rest.find("Host(") {
        let after = &rest[idx + "Host(".len()..];
        let Some(end) = after.find(')') else {
            break;
        };
        for token in after[..end].split(',') {
            let domain = clean_config_value(token.trim().trim_matches('`'));
            add_unique_domain(domains, domain);
        }
        rest = &after[end + 1..];
    }
}

fn extract_caddy_label_domains(labels: &str, domains: &mut Vec<String>) {
    for part in labels.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key == "caddy" || key.starts_with("caddy.") && key.ends_with(".host") {
            for token in value.split_whitespace() {
                add_unique_domain(domains, token);
            }
        }
    }
}

fn parse_docker_env_web_host_sites(output: &str) -> Vec<WebHostSite> {
    let mut sites = Vec::new();
    for line in output.lines().take(80) {
        let mut parts = line.splitn(3, '\t');
        let container_id = parts.next().unwrap_or("").trim();
        let name = parts.next().unwrap_or("").trim().trim_start_matches('/');
        let env_json = parts.next().unwrap_or("").trim();
        let Ok(envs) = serde_json::from_str::<Vec<String>>(env_json) else {
            continue;
        };

        let mut domains = Vec::new();
        let mut upstreams = Vec::new();
        let mut tls = false;
        for env in envs {
            let Some((key, value)) = env.split_once('=') else {
                continue;
            };
            match key {
                "VIRTUAL_HOST" | "LETSENCRYPT_HOST" | "SERVER_NAME" | "CADDY_HOST" => {
                    for token in value.split(|ch: char| ch == ',' || ch.is_whitespace()) {
                        add_unique_domain(&mut domains, token);
                    }
                    if key == "LETSENCRYPT_HOST" {
                        tls = true;
                    }
                }
                "VIRTUAL_PORT" => {
                    let port = clean_config_value(value);
                    if !port.is_empty() {
                        add_unique_string(&mut upstreams, format!("container:{port}"));
                    }
                }
                "VIRTUAL_PROTO" if value.eq_ignore_ascii_case("https") => {
                    tls = true;
                }
                _ => {}
            }
        }
        if domains.is_empty() {
            continue;
        }

        let source = if name.is_empty() {
            format!("docker:{}", container_id)
        } else {
            format!("docker:{}", name)
        };
        if let Some(site) = build_web_host_site_with_source(
            "docker",
            domains,
            Vec::new(),
            tls,
            upstreams,
            &source,
            "docker_env",
        ) {
            sites.push(site);
        }
    }
    sites
}

fn read_small_text_file(path: &std::path::Path, max_bytes: u64) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > max_bytes {
        return Err(format!("file too large: {} bytes", meta.len()));
    }
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

fn parse_nginx_web_hosts(content: &str, config_path: &str) -> Vec<WebHostSite> {
    extract_named_blocks(content, "server")
        .into_iter()
        .filter_map(|block| {
            let mut domains = Vec::new();
            let mut listen = Vec::new();
            let mut upstreams = Vec::new();
            let mut roots = Vec::new();
            let mut certificate_paths = Vec::new();
            let mut tls = false;

            for line in normalized_nginx_directives(&block) {
                if let Some(rest) = line.strip_prefix("server_name ") {
                    for token in rest.split_whitespace() {
                        add_unique_domain(&mut domains, token);
                    }
                } else if let Some(rest) = line.strip_prefix("listen ") {
                    let value = clean_config_value(rest);
                    if value.contains("443") || value.contains("ssl") {
                        tls = true;
                    }
                    add_unique_string(&mut listen, value);
                } else if let Some(rest) = line.strip_prefix("proxy_pass ") {
                    add_unique_string(&mut upstreams, clean_config_value(rest));
                } else if let Some(rest) = line.strip_prefix("root ") {
                    add_unique_string(&mut roots, clean_config_value(rest));
                } else if let Some(rest) = line.strip_prefix("alias ") {
                    add_unique_string(&mut roots, clean_config_value(rest));
                } else if let Some(rest) = line.strip_prefix("ssl_certificate ") {
                    tls = true;
                    add_unique_string(&mut certificate_paths, clean_config_value(rest));
                } else if let Some(rest) = line.strip_prefix("return ") {
                    add_domains_from_config_text(&mut domains, rest);
                }
            }

            build_web_host_site_with_evidence(
                "nginx",
                domains,
                listen,
                tls,
                upstreams,
                roots,
                certificate_paths,
                config_path,
                "config",
            )
        })
        .collect()
}

fn parse_caddy_web_hosts(content: &str, config_path: &str) -> Vec<WebHostSite> {
    if let Some(sites) = parse_caddy_json_web_hosts(content, config_path) {
        return sites;
    }

    extract_caddy_blocks(content)
        .into_iter()
        .filter_map(|(label, block)| {
            let mut domains = Vec::new();
            let mut listen = Vec::new();
            let mut upstreams = Vec::new();
            let mut roots = Vec::new();
            let mut certificate_paths = Vec::new();
            let mut tls = true;

            for token in label.split(|c: char| c.is_whitespace() || c == ',') {
                let token = clean_config_value(token);
                if token.is_empty() || token.starts_with(':') {
                    continue;
                }
                if let Some(rest) = token.strip_prefix("http://") {
                    tls = false;
                    add_unique_domain(&mut domains, rest);
                } else if let Some(rest) = token.strip_prefix("https://") {
                    add_unique_domain(&mut domains, rest);
                } else {
                    add_unique_domain(&mut domains, token);
                }
            }

            for line in normalized_config_lines(&block) {
                if let Some(rest) = line.strip_prefix("reverse_proxy ") {
                    for token in rest.split_whitespace() {
                        add_unique_string(&mut upstreams, clean_config_value(token));
                    }
                } else if let Some(rest) = line.strip_prefix("root ") {
                    if let Some(path) = caddy_root_path(rest) {
                        add_unique_string(&mut roots, path);
                    }
                } else if let Some(rest) = line.strip_prefix("tls ") {
                    tls = true;
                    if let Some(path) = rest
                        .split_whitespace()
                        .map(clean_config_value)
                        .find(|value| value.starts_with('/'))
                    {
                        add_unique_string(&mut certificate_paths, path);
                    }
                }
            }

            if !domains.is_empty() {
                listen.push(if tls {
                    "443".to_string()
                } else {
                    "80".to_string()
                });
            }
            build_web_host_site_with_evidence(
                "caddy",
                domains,
                listen,
                tls,
                upstreams,
                roots,
                certificate_paths,
                config_path,
                "config",
            )
        })
        .collect()
}

fn parse_caddy_json_web_hosts(content: &str, config_path: &str) -> Option<Vec<WebHostSite>> {
    let root: serde_json::Value = serde_json::from_str(content).ok()?;
    let servers = root.get("apps")?.get("http")?.get("servers")?.as_object()?;
    let mut sites = Vec::new();
    for server in servers.values() {
        let listen = caddy_json_listen_values(server);
        let tls = listen
            .iter()
            .any(|value| value == "443" || value.ends_with(":443"));
        if let Some(routes) = server.get("routes").and_then(|value| value.as_array()) {
            collect_caddy_json_route_sites(routes, &listen, tls, config_path, &mut sites);
        }
    }
    Some(sites)
}

fn caddy_json_listen_values(server: &serde_json::Value) -> Vec<String> {
    server
        .get("listen")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(|value| {
                    clean_config_value(value)
                        .trim_start_matches(':')
                        .to_string()
                })
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn collect_caddy_json_route_sites(
    routes: &[serde_json::Value],
    listen: &[String],
    tls: bool,
    config_path: &str,
    sites: &mut Vec<WebHostSite>,
) {
    for route in routes {
        let domains = caddy_json_route_domains(route);
        if !domains.is_empty() {
            let upstreams = caddy_json_reverse_proxy_upstreams(route);
            if let Some(site) = build_web_host_site(
                "caddy",
                domains,
                listen.to_vec(),
                tls,
                upstreams,
                config_path,
            ) {
                sites.push(site);
            }
        }

        for nested in caddy_json_nested_routes(route) {
            collect_caddy_json_route_sites(nested, listen, tls, config_path, sites);
        }
    }
}

fn caddy_json_route_domains(route: &serde_json::Value) -> Vec<String> {
    let mut domains = Vec::new();
    if let Some(matchers) = route.get("match").and_then(|value| value.as_array()) {
        for matcher in matchers {
            if let Some(hosts) = matcher.get("host").and_then(|value| value.as_array()) {
                for host in hosts.iter().filter_map(|value| value.as_str()) {
                    add_unique_domain(&mut domains, host);
                }
            }
        }
    }
    domains
}

fn caddy_json_reverse_proxy_upstreams(value: &serde_json::Value) -> Vec<String> {
    let mut upstreams = Vec::new();
    collect_caddy_json_reverse_proxy_upstreams(value, &mut upstreams);
    upstreams
}

fn collect_caddy_json_reverse_proxy_upstreams(
    value: &serde_json::Value,
    upstreams: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("handler").and_then(|value| value.as_str()) == Some("reverse_proxy") {
                if let Some(values) = map.get("upstreams").and_then(|value| value.as_array()) {
                    for upstream in values {
                        if let Some(dial) = upstream.get("dial").and_then(|value| value.as_str()) {
                            add_unique_string(upstreams, clean_config_value(dial).to_string());
                        }
                    }
                }
            }
            for nested in map.values() {
                collect_caddy_json_reverse_proxy_upstreams(nested, upstreams);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_caddy_json_reverse_proxy_upstreams(nested, upstreams);
            }
        }
        _ => {}
    }
}

fn caddy_root_path(rest: &str) -> Option<&str> {
    let tokens: Vec<&str> = rest
        .split_whitespace()
        .map(clean_config_value)
        .filter(|token| !token.is_empty())
        .collect();
    match tokens.as_slice() {
        [path] => Some(path),
        [matcher, path, ..] if *matcher == "*" || matcher.starts_with('@') => Some(path),
        [path, ..] => Some(path),
        [] => None,
    }
}

fn caddy_json_nested_routes(route: &serde_json::Value) -> Vec<&[serde_json::Value]> {
    let mut routes = Vec::new();
    if let Some(values) = route.get("routes").and_then(|value| value.as_array()) {
        routes.push(values.as_slice());
    }
    if let Some(handles) = route.get("handle").and_then(|value| value.as_array()) {
        for handle in handles {
            if let Some(values) = handle.get("routes").and_then(|value| value.as_array()) {
                routes.push(values.as_slice());
            }
        }
    }
    routes
}

fn parse_apache_web_hosts(content: &str, config_path: &str) -> Vec<WebHostSite> {
    extract_apache_virtual_hosts(content)
        .into_iter()
        .filter_map(|(label, block)| {
            let mut domains = Vec::new();
            let mut listen = Vec::new();
            let mut upstreams = Vec::new();
            let mut roots = Vec::new();
            let mut certificate_paths = Vec::new();
            let mut tls = false;

            if let Some(port) = label.rsplit(':').next() {
                let port = clean_config_value(port.trim_end_matches('>'));
                if !port.is_empty() {
                    if port == "443" {
                        tls = true;
                    }
                    add_unique_string(&mut listen, port);
                }
            }

            for line in normalized_config_lines(&block) {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("servername ") {
                    if let Some(domain) = line.split_whitespace().nth(1) {
                        add_unique_domain(&mut domains, domain);
                    }
                } else if lower.starts_with("serveralias ") {
                    for token in line.split_whitespace().skip(1) {
                        add_unique_domain(&mut domains, token);
                    }
                } else if lower.starts_with("proxypass ") {
                    if let Some(target) = line.split_whitespace().nth(2) {
                        add_unique_string(&mut upstreams, clean_config_value(target));
                    }
                } else if lower.starts_with("documentroot ") {
                    if let Some(path) = line.split_whitespace().nth(1) {
                        add_unique_string(&mut roots, clean_config_value(path));
                    }
                } else if lower.starts_with("sslcertificatefile ") {
                    tls = true;
                    if let Some(path) = line.split_whitespace().nth(1) {
                        add_unique_string(&mut certificate_paths, clean_config_value(path));
                    }
                } else if lower.starts_with("sslengine on") {
                    tls = true;
                }
            }

            build_web_host_site_with_evidence(
                "apache",
                domains,
                listen,
                tls,
                upstreams,
                roots,
                certificate_paths,
                config_path,
                "config",
            )
        })
        .collect()
}

fn build_web_host_site(
    server: &str,
    domains: Vec<String>,
    listen: Vec<String>,
    tls: bool,
    upstreams: Vec<String>,
    config_path: &str,
) -> Option<WebHostSite> {
    build_web_host_site_with_source(
        server,
        domains,
        listen,
        tls,
        upstreams,
        config_path,
        "config",
    )
}

fn build_web_host_site_with_source(
    server: &str,
    domains: Vec<String>,
    listen: Vec<String>,
    tls: bool,
    upstreams: Vec<String>,
    config_path: &str,
    source: &str,
) -> Option<WebHostSite> {
    build_web_host_site_with_evidence(
        server,
        domains,
        listen,
        tls,
        upstreams,
        Vec::new(),
        Vec::new(),
        config_path,
        source,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_web_host_site_with_evidence(
    server: &str,
    domains: Vec<String>,
    listen: Vec<String>,
    tls: bool,
    upstreams: Vec<String>,
    roots: Vec<String>,
    certificate_paths: Vec<String>,
    config_path: &str,
    source: &str,
) -> Option<WebHostSite> {
    if domains.is_empty() {
        return None;
    }
    let probe_eligible = domains
        .iter()
        .any(|domain| web_host_domain_probe_eligible(domain));
    Some(WebHostSite {
        server: server.to_string(),
        domains,
        listen,
        tls,
        upstreams,
        roots,
        certificate_paths,
        config_path: config_path.to_string(),
        source: source.to_string(),
        probe_eligible,
    })
}

fn extract_named_blocks(content: &str, name: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let marker = format!("{} ", name);
    let mut rest = content;
    while let Some(idx) = rest.find(name) {
        let candidate = &rest[idx..];
        if !(candidate.starts_with(&marker)
            || candidate.starts_with(&format!("{}{{", name))
            || candidate.starts_with(&format!("{} {{", name)))
        {
            rest = &candidate[name.len()..];
            continue;
        }
        let Some(open_rel) = candidate.find('{') else {
            break;
        };
        let after_open = &candidate[open_rel + 1..];
        let Some((block, consumed)) = take_braced_block(after_open) else {
            break;
        };
        blocks.push(block);
        rest = &after_open[consumed..];
    }
    blocks
}

fn extract_caddy_blocks(content: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(open_rel) = content[cursor..].find('{') {
        let open = cursor + open_rel;
        let label = caddy_site_label(content[cursor..open].trim());
        if label.is_empty() || label.starts_with('#') {
            cursor = open + 1;
            continue;
        }
        let after_open = &content[open + 1..];
        if let Some((block, consumed)) = take_braced_block(after_open) {
            blocks.push((label, block));
            cursor = open + 1 + consumed;
        } else {
            break;
        }
    }
    blocks
}

fn caddy_site_label(raw_label: &str) -> String {
    raw_label
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("import ")
                && !line.starts_with('(')
        })
        .unwrap_or("")
        .to_string()
}

fn extract_apache_virtual_hosts(content: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current_label: Option<String> = None;
    let mut current = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.to_ascii_lowercase().starts_with("<virtualhost ") {
            current_label = Some(line.to_string());
            current.clear();
        } else if line.to_ascii_lowercase().starts_with("</virtualhost") {
            if let Some(label) = current_label.take() {
                blocks.push((label, current.join("\n")));
            }
        } else if current_label.is_some() {
            current.push(raw_line.to_string());
        }
    }
    blocks
}

fn take_braced_block(input: &str) -> Option<(String, usize)> {
    let mut depth = 1i32;
    for (idx, ch) in input.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((input[..idx].to_string(), idx + ch.len_utf8()));
                }
            }
            _ => {}
        }
    }
    None
}

fn normalized_config_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.trim_end_matches(';').trim().to_string())
        .collect()
}

fn normalized_nginx_directives(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if current.is_empty() {
            current.push_str(line);
        } else {
            current.push(' ');
            current.push_str(line);
        }
        while let Some(idx) = current.find(';') {
            let directive = current[..idx].trim();
            if !directive.is_empty() {
                lines.push(directive.to_string());
            }
            current = current[idx + 1..].trim().to_string();
        }
        if current.ends_with('{') || current.ends_with('}') {
            lines.push(current.trim().to_string());
            current.clear();
        }
    }
    if !current.is_empty() {
        lines.push(current.trim_end_matches(';').trim().to_string());
    }
    lines
}

fn clean_config_value(value: &str) -> &str {
    value
        .trim()
        .trim_matches(';')
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
}

fn add_unique_domain(domains: &mut Vec<String>, raw: &str) {
    let domain = clean_config_value(raw)
        .trim_end_matches(',')
        .trim_end_matches('.');
    if domain.is_empty() || domain == "_" {
        return;
    }
    if domain.contains('$') || domain.contains('*') || domain.contains('{') || domain.contains('}')
    {
        return;
    }
    add_unique_string(domains, domain.to_ascii_lowercase());
}

fn add_domains_from_config_text(domains: &mut Vec<String>, text: &str) {
    for token in text.split_whitespace() {
        let cleaned = clean_config_value(token);
        let Some(rest) = cleaned
            .strip_prefix("https://")
            .or_else(|| cleaned.strip_prefix("http://"))
        else {
            continue;
        };
        let domain = rest.split(['/', '?', '#', '$']).next().unwrap_or("");
        let domain = domain.split(':').next().unwrap_or(domain);
        add_unique_domain(domains, domain);
    }
}

fn add_unique_string(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() && !values.iter().any(|v| v == &value) {
        values.push(value);
    }
}

fn web_host_domain_probe_eligible(domain: &str) -> bool {
    if domain.contains('$')
        || domain.contains('*')
        || domain == "_"
        || domain.eq_ignore_ascii_case("localhost")
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }
    domain.contains('.') && !domain.contains(':')
}
