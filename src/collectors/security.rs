use super::*;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;

#[derive(Debug, Clone)]
struct SecurityProcess {
    pid: u32,
    name: String,
    exe_path: Option<String>,
    cpu_percent: f64,
    memory_bytes: u64,
}

#[derive(Debug, Clone)]
struct SecurityNetworkFlow {
    process: String,
    pid: Option<u32>,
    remote_ip: String,
    remote_port: String,
    connections: u32,
    direction: String,
}

#[derive(Debug, Clone)]
struct SecurityPersistenceEntry {
    source: String,
    line: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityLoginSource {
    ip: String,
    count: u64,
}

#[derive(Debug, Clone, Default)]
struct SecuritySuccessfulLogin {
    user: String,
    ip: String,
    method: String,
    count: u64,
}

#[derive(Debug, Clone, Default)]
struct SecuritySshTelemetry {
    permit_root_login: Option<String>,
    password_authentication: Option<String>,
    failed_login_count: u64,
    failed_sources: Vec<SecurityLoginSource>,
    successful_login_count: u64,
    successful_logins: Vec<SecuritySuccessfulLogin>,
    log_sources: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct SecuritySshAccessIssue {
    username: String,
    issue: String,
    evidence: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SecurityListener {
    pub(crate) protocol: String,
    pub(crate) local_ip: String,
    pub(crate) local_port: String,
    pub(crate) process: String,
    pub(crate) pid: Option<u32>,
    pub(crate) scope: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityDeletedBinary {
    pid: u32,
    name: String,
    exe_path: String,
}

#[derive(Debug, Clone, Default)]
struct SecuritySuidSgidFile {
    path: String,
    mode: String,
    owner: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityFileTelemetry {
    deleted_binaries: Vec<SecurityDeletedBinary>,
    suspicious_suid_sgid_files: Vec<SecuritySuidSgidFile>,
}

#[derive(Debug, Clone, Default)]
struct SecurityContainerRisk {
    name: String,
    image: String,
    risks: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct SecurityContainerTelemetry {
    available: bool,
    containers: Vec<SecurityContainerRisk>,
}

#[derive(Debug, Clone, Default)]
struct SecurityProcessCommandInput {
    pid: u32,
    process: String,
    exe_path: Option<String>,
    cmdline: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityCommandFinding {
    severity: &'static str,
    title: String,
    pid: Option<u32>,
    process: String,
    evidence: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityProcessBehaviorTelemetry {
    command_findings: Vec<SecurityCommandFinding>,
    truncated_cmdline_count: usize,
}

const SECURITY_PROC_CMDLINE_MAX_BYTES: usize = 16 * 1024;
const SECURITY_LOGIN_DATABASE_MAX_BYTES: usize = 256 * 1024;
const SECURITY_LOGIN_DATABASE_MAX_LINES: usize = 4 * 1024;
const SECURITY_LOGIN_USERS_MAX: usize = 128;
const SECURITY_LOGIN_GROUPS_MAX: usize = 512;
const SECURITY_LOGIN_GROUP_MEMBERS_PER_GROUP_MAX: usize = 128;
const SECURITY_LOGIN_GROUP_MEMBERS_TOTAL_MAX: usize = 4 * 1024;
const SECURITY_LOGIN_GROUPS_PER_USER_MAX: usize = 64;
const SECURITY_LOGIN_USERNAME_MAX_CHARS: usize = 128;
const SECURITY_LOGIN_GROUP_NAME_MAX_CHARS: usize = 128;
const SECURITY_LOGIN_GECOS_MAX_CHARS: usize = 256;
const SECURITY_LOGIN_PATH_MAX_CHARS: usize = 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_USERS: usize = 128;
const SECURITY_AUTHORIZED_KEYS_MAX_BYTES_PER_FILE: usize = 1024 * 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_LINE_BYTES: usize = 16 * 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_LINES_PER_USER: usize = 4 * 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_LINES: usize = 16 * 1024;
const SECURITY_AUTHORIZED_KEYS_MAX_KEYS_PER_USER: usize = 64;
const SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_KEYS: usize = 256;
const SECURITY_AUTHORIZED_KEY_COMMENT_MAX_CHARS: usize = 256;
const SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_RETAINED_JSON_BYTES: usize = 512 * 1024;
const SECURITY_AUTHORIZED_KEYS_SCAN_DEADLINE: Duration = Duration::from_secs(3);
const SECURITY_AUTHORIZED_KEYS_FILE_DEADLINE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Default)]
struct SecurityLoginAccountsScanStats {
    passwd_bytes_read: usize,
    passwd_bytes_retained: usize,
    passwd_input_truncated: bool,
    passwd_unavailable: bool,
    passwd_lines_seen: usize,
    passwd_line_budget_exhausted: bool,
    group_bytes_read: usize,
    group_bytes_retained: usize,
    group_input_truncated: bool,
    group_unavailable: bool,
    group_lines_seen: usize,
    group_line_budget_exhausted: bool,
    groups_seen: usize,
    groups_emitted: usize,
    group_records_truncated: usize,
    group_members_truncated: usize,
    user_group_memberships_truncated: usize,
    users_seen: usize,
    users_emitted: usize,
    user_records_truncated: usize,
}

impl SecurityLoginAccountsScanStats {
    fn users_seen_is_exact(&self) -> bool {
        !self.passwd_unavailable
            && !self.passwd_input_truncated
            && !self.passwd_line_budget_exhausted
    }

    fn groups_seen_is_exact(&self) -> bool {
        !self.group_unavailable && !self.group_input_truncated && !self.group_line_budget_exhausted
    }

    fn users_truncated(&self) -> bool {
        !self.users_seen_is_exact()
            || self.user_records_truncated > 0
            || self.user_group_memberships_truncated > 0
    }

    fn groups_truncated(&self) -> bool {
        !self.groups_seen_is_exact()
            || self.group_records_truncated > 0
            || self.group_members_truncated > 0
    }
}

#[derive(Debug, Clone, Default)]
struct SecurityBoundedLoginInput {
    content: String,
    bytes_read: usize,
    bytes_retained: usize,
    truncated: bool,
    unavailable: bool,
}

#[derive(Debug, Clone, Default)]
struct SecurityAuthorizedKeysScanStats {
    users_seen: usize,
    users_scanned: usize,
    files_scanned: usize,
    bytes_read: usize,
    lines_scanned: usize,
    retained_key_count: usize,
    retained_key_json_bytes: usize,
    truncated_user_count: usize,
    truncated_file_count: usize,
    truncated_line_count: usize,
    unavailable_file_count: usize,
    timed_out_file_count: usize,
    line_budget_exhausted_user_count: usize,
    key_budget_exhausted_user_count: usize,
    output_budget_exhausted_user_count: usize,
}

impl SecurityAuthorizedKeysScanStats {
    fn key_count_is_exact(&self) -> bool {
        self.users_scanned == self.users_seen
            && self.truncated_user_count == 0
            && self.truncated_file_count == 0
            && self.truncated_line_count == 0
            && self.unavailable_file_count == 0
            && self.line_budget_exhausted_user_count == 0
            && self.key_budget_exhausted_user_count == 0
            && self.output_budget_exhausted_user_count == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityBoundedFileError {
    Missing,
    UnsafeOrUnreadable,
    TimedOut,
}

#[derive(Debug, Clone, Default)]
struct SecurityTextSource {
    source: String,
    user: String,
    content: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityUserPersistenceEntry {
    source: String,
    user: String,
    title: String,
    evidence: String,
    severity: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecurityUserPersistenceTelemetry {
    entries: Vec<SecurityUserPersistenceEntry>,
    sudo_nopasswd_entries: Vec<SecurityUserPersistenceEntry>,
    home_profiles_scanned: bool,
}

#[derive(Debug, Clone, Default)]
struct SecurityProxyVariable {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityDnsProxyTelemetry {
    nameservers: Vec<String>,
    proxy_variables: Vec<SecurityProxyVariable>,
    public_proxy_listeners: Vec<SecurityListener>,
}

#[derive(Debug, Clone, Default)]
struct SecurityUid0Account {
    username: String,
    uid: u32,
    home_dir: String,
    shell: String,
}

#[derive(Debug, Clone, Default)]
struct SecurityAccountHardeningTelemetry {
    uid0_accounts: Vec<SecurityUid0Account>,
}

#[derive(Debug, Clone, Default)]
struct SecuritySchedulerEntry {
    source: String,
    title: String,
    evidence: String,
    severity: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecuritySchedulerTelemetry {
    entries: Vec<SecuritySchedulerEntry>,
}

#[derive(Debug, Clone, Default)]
struct SecurityFirewallFinding {
    backend: String,
    title: String,
    evidence: String,
    severity: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecurityFirewallTelemetry {
    observed_backends: Vec<String>,
    findings: Vec<SecurityFirewallFinding>,
}

#[derive(Debug, Clone, Default)]
struct SecurityLoaderEntry {
    source: String,
    title: String,
    evidence: String,
    severity: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecurityLoaderTelemetry {
    entries: Vec<SecurityLoaderEntry>,
}

#[derive(Debug, Clone, Default)]
struct SecurityWritableArtifact {
    path: String,
    title: String,
    mode: String,
    size_bytes: u64,
    modified_age_secs: Option<u64>,
    severity: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecurityWritableArtifactTelemetry {
    artifacts: Vec<SecurityWritableArtifact>,
}

#[derive(Debug, Clone, Default)]
struct SecurityWritableArtifactInput {
    path: String,
    mode: u32,
    size_bytes: u64,
    modified_age_secs: Option<u64>,
    first_line: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SecurityPostureInput {
    processes: Vec<SecurityProcess>,
    network_flows: Vec<SecurityNetworkFlow>,
    persistence_entries: Vec<SecurityPersistenceEntry>,
    login_admin_usernames: Vec<String>,
    authorized_key_count: u64,
    authorized_key_count_exact: bool,
    ssh_telemetry: SecuritySshTelemetry,
    listeners: Vec<SecurityListener>,
    file_telemetry: SecurityFileTelemetry,
    container_telemetry: SecurityContainerTelemetry,
    process_behavior: SecurityProcessBehaviorTelemetry,
    user_persistence: SecurityUserPersistenceTelemetry,
    dns_proxy: SecurityDnsProxyTelemetry,
    account_hardening: SecurityAccountHardeningTelemetry,
    scheduler: SecuritySchedulerTelemetry,
    firewall: SecurityFirewallTelemetry,
    loader: SecurityLoaderTelemetry,
    writable_artifacts: SecurityWritableArtifactTelemetry,
    ssh_access_issues: Vec<SecuritySshAccessIssue>,
}

#[derive(Debug, Clone)]
struct SecurityFinding {
    severity: &'static str,
    category: &'static str,
    title: &'static str,
    evidence: String,
    pid: Option<u32>,
    process: Option<String>,
}

pub(crate) fn collect_security_posture_with_ss(
    sys: &Arc<Mutex<System>>,
    ss_output: &Option<String>,
    login_accounts: &serde_json::Value,
    listeners: &[SecurityListener],
) -> serde_json::Value {
    build_security_posture_report(SecurityPostureInput {
        processes: collect_security_processes(sys),
        network_flows: match ss_output {
            Some(stdout) => build_security_network_flows_from_ss(stdout, 120),
            None => Vec::new(),
        },
        persistence_entries: collect_security_persistence_entries(),
        login_admin_usernames: collect_security_admin_usernames(login_accounts),
        authorized_key_count: collect_security_authorized_key_count(login_accounts),
        authorized_key_count_exact: collect_security_authorized_key_count_exact(login_accounts),
        ssh_telemetry: collect_security_ssh_telemetry(),
        listeners: listeners.to_vec(),
        file_telemetry: collect_security_file_telemetry(),
        container_telemetry: collect_security_container_telemetry(),
        process_behavior: collect_security_process_behavior(),
        user_persistence: collect_security_user_persistence(login_accounts),
        dns_proxy: collect_security_dns_proxy_telemetry(listeners),
        account_hardening: collect_security_account_hardening(),
        scheduler: collect_security_scheduler_telemetry(),
        firewall: collect_security_firewall_telemetry(),
        loader: collect_security_loader_telemetry(),
        writable_artifacts: collect_security_writable_artifacts(),
        ssh_access_issues: collect_security_ssh_access_issues(login_accounts),
    })
}

fn collect_security_processes(sys: &Arc<Mutex<System>>) -> Vec<SecurityProcess> {
    let s = sys.lock();
    s.processes()
        .values()
        .map(|p| SecurityProcess {
            pid: p.pid().as_u32(),
            name: p.name().to_string_lossy().to_string(),
            exe_path: p.exe().and_then(|path| {
                let value = path.to_string_lossy().to_string();
                (!value.is_empty()).then_some(value)
            }),
            cpu_percent: round_f64_two_decimals(p.cpu_usage() as f64),
            memory_bytes: p.memory(),
        })
        .collect()
}

fn build_security_network_flows_from_ss(output: &str, limit: usize) -> Vec<SecurityNetworkFlow> {
    output
        .lines()
        .filter_map(parse_ss_flow_line)
        .filter(|flow| traffic_flow_scope(flow) == "external")
        .filter(|flow| traffic_flow_direction(flow) == "outbound")
        .take(limit)
        .map(|flow| SecurityNetworkFlow {
            process: flow.process,
            pid: flow.pid,
            remote_ip: flow.remote_ip,
            remote_port: flow.remote_port,
            connections: flow.connections,
            direction: "outbound".to_string(),
        })
        .collect()
}

fn collect_security_process_behavior() -> SecurityProcessBehaviorTelemetry {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return SecurityProcessBehaviorTelemetry::default();
        };
        let mut inputs = Vec::new();
        let mut truncated_cmdline_count = 0;
        for entry in entries.flatten() {
            if inputs.len() >= 200 {
                break;
            }
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let (cmdline, truncated) = read_proc_cmdline(entry.path().join("cmdline"));
            truncated_cmdline_count += usize::from(truncated);
            if cmdline.is_empty() {
                continue;
            }
            let process = std::fs::read_to_string(entry.path().join("comm"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            let exe_path = std::fs::read_link(entry.path().join("exe"))
                .ok()
                .map(|path| path.to_string_lossy().to_string());
            inputs.push(SecurityProcessCommandInput {
                pid,
                process,
                exe_path,
                cmdline,
            });
        }
        let mut telemetry = build_security_process_behavior_from_processes(inputs);
        telemetry.truncated_cmdline_count = truncated_cmdline_count;
        telemetry
    }

    #[cfg(not(target_os = "linux"))]
    SecurityProcessBehaviorTelemetry::default()
}

fn read_proc_cmdline(path: std::path::PathBuf) -> (String, bool) {
    use std::io::Read;

    let Ok(file) = std::fs::File::open(path) else {
        return (String::new(), false);
    };
    let read_limit = SECURITY_PROC_CMDLINE_MAX_BYTES + 1;
    let mut bytes = Vec::with_capacity(read_limit);
    if file
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return (String::new(), false);
    }
    let mut truncated = bytes.len() > SECURITY_PROC_CMDLINE_MAX_BYTES;
    bytes.truncate(SECURITY_PROC_CMDLINE_MAX_BYTES);
    let mut command = String::with_capacity(bytes.len());
    let mut parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty());
    for part in parts.by_ref().take(24) {
        if !command.is_empty() {
            command.push(' ');
        }
        command.push_str(&String::from_utf8_lossy(part));
    }
    truncated |= parts.next().is_some();
    if command.is_empty() {
        return (String::new(), truncated);
    }
    truncated |= command.chars().count() > 512 || command.split_whitespace().count() > 40;
    (sanitize_security_command(&command), truncated)
}

fn build_security_process_behavior_from_processes(
    processes: Vec<SecurityProcessCommandInput>,
) -> SecurityProcessBehaviorTelemetry {
    let mut command_findings = Vec::new();
    for process in processes {
        let cmd = sanitize_security_command(&process.cmdline);
        if cmd.is_empty() {
            continue;
        }
        let lower = cmd.to_ascii_lowercase();
        let process_lower = process.process.to_ascii_lowercase();
        let exe_suspicious = process
            .exe_path
            .as_deref()
            .map(path_has_suspicious_exec_prefix)
            .unwrap_or(false);
        let (severity, title) = if command_has_download_execute_marker(&lower) {
            ("high", "Download-and-execute command line")
        } else if command_has_encoded_payload_marker(&lower) {
            ("high", "Encoded payload command line")
        } else if exe_suspicious && command_uses_interpreter(&process_lower, &lower) {
            ("medium", "Interpreter running from writable path")
        } else if process_has_proxy_tunnel_marker(&process_lower) {
            ("medium", "Proxy or tunnel process present")
        } else {
            continue;
        };
        command_findings.push(SecurityCommandFinding {
            severity,
            title: title.to_string(),
            pid: Some(process.pid),
            process: process.process,
            evidence: cmd.chars().take(220).collect(),
        });
        if command_findings.len() >= 20 {
            break;
        }
    }
    SecurityProcessBehaviorTelemetry {
        command_findings,
        truncated_cmdline_count: 0,
    }
}

fn collect_security_user_persistence(
    _login_accounts: &serde_json::Value,
) -> SecurityUserPersistenceTelemetry {
    let mut sources = Vec::new();
    // Login homes may live on autofs/NFS/FUSE. Touching arbitrary paths from
    // passwd can block the entire heavy collector indefinitely, so this
    // bounded posture snapshot deliberately scans only local system-owned
    // persistence surfaces. Process/cmdline and authorized_keys telemetry
    // retain their independent, deadline-isolated coverage.
    collect_security_text_sources(
        std::path::Path::new("/etc/sudoers"),
        "root",
        &mut sources,
        20,
    );
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten().take(40) {
            collect_security_text_sources(&entry.path(), "root", &mut sources, 20);
        }
    }
    let mut telemetry = build_security_user_persistence_from_texts(sources);
    telemetry.home_profiles_scanned = false;
    telemetry
}

fn collect_security_text_sources(
    path: &std::path::Path,
    user: &str,
    sources: &mut Vec<SecurityTextSource>,
    limit: usize,
) {
    if sources.len() >= limit {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    if meta.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten().take(20) {
            collect_security_text_sources(&entry.path(), user, sources, limit);
            if sources.len() >= limit {
                break;
            }
        }
        return;
    }
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return;
    }
    let Some(content) = read_security_text_file(&path.to_string_lossy(), 256 * 1024) else {
        return;
    };
    sources.push(SecurityTextSource {
        source: path.to_string_lossy().to_string(),
        user: user.to_string(),
        content,
    });
}

fn build_security_user_persistence_from_texts(
    sources: Vec<SecurityTextSource>,
) -> SecurityUserPersistenceTelemetry {
    let mut entries = Vec::new();
    let mut sudo_nopasswd_entries = Vec::new();
    for source in sources {
        for line in source.content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.contains("nopasswd") {
                sudo_nopasswd_entries.push(SecurityUserPersistenceEntry {
                    source: source.source.clone(),
                    user: source.user.clone(),
                    title: "NOPASSWD sudo grant".to_string(),
                    evidence: sanitize_security_command(line).chars().take(220).collect(),
                    severity: "medium",
                });
            } else if command_has_download_execute_marker(&lower) {
                entries.push(SecurityUserPersistenceEntry {
                    source: source.source.clone(),
                    user: source.user.clone(),
                    title: "User profile download-and-execute persistence".to_string(),
                    evidence: sanitize_security_command(line).chars().take(220).collect(),
                    severity: "medium",
                });
            } else if line_has_security_marker(line)
                || lower.contains("/dev/tcp/")
                || lower.contains("proxycommand")
            {
                entries.push(SecurityUserPersistenceEntry {
                    source: source.source.clone(),
                    user: source.user.clone(),
                    title: "Suspicious user persistence line".to_string(),
                    evidence: sanitize_security_command(line).chars().take(220).collect(),
                    severity: "medium",
                });
            }
            if entries.len() + sudo_nopasswd_entries.len() >= 20 {
                break;
            }
        }
    }
    entries.truncate(20);
    sudo_nopasswd_entries.truncate(20);
    SecurityUserPersistenceTelemetry {
        entries,
        sudo_nopasswd_entries,
        home_profiles_scanned: false,
    }
}

fn collect_security_dns_proxy_telemetry(
    listeners: &[SecurityListener],
) -> SecurityDnsProxyTelemetry {
    let resolv = read_security_text_file("/etc/resolv.conf", 64 * 1024).unwrap_or_default();
    let environment = read_security_text_file("/etc/environment", 64 * 1024).unwrap_or_default();
    build_security_dns_proxy_telemetry_from_text(&resolv, &environment, listeners.to_vec())
}

fn build_security_dns_proxy_telemetry_from_text(
    resolv_conf: &str,
    environment: &str,
    listeners: Vec<SecurityListener>,
) -> SecurityDnsProxyTelemetry {
    let mut nameservers = Vec::new();
    for line in resolv_conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(value) = parts.next() else {
            continue;
        };
        nameservers.push(value.to_string());
        if nameservers.len() >= 5 {
            break;
        }
    }

    let mut proxy_variables = Vec::new();
    for line in environment.lines() {
        let line = line.trim().trim_matches('"');
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let upper = name.trim().to_ascii_uppercase();
        if !matches!(
            upper.as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "FTP_PROXY"
        ) {
            continue;
        }
        let value = sanitize_security_command(&redact_proxy_value(value.trim().trim_matches('"')));
        if value.is_empty() {
            continue;
        }
        proxy_variables.push(SecurityProxyVariable { name: upper, value });
        if proxy_variables.len() >= 10 {
            break;
        }
    }

    let public_proxy_listeners = listeners
        .into_iter()
        .filter(|listener| {
            listener.scope == "public"
                && SECURITY_PROXY_TOR_PORTS
                    .iter()
                    .any(|port| listener.local_port == *port)
        })
        .take(10)
        .collect();

    SecurityDnsProxyTelemetry {
        nameservers,
        proxy_variables,
        public_proxy_listeners,
    }
}

fn collect_security_account_hardening() -> SecurityAccountHardeningTelemetry {
    let passwd = read_security_text_file("/etc/passwd", 256 * 1024).unwrap_or_default();
    build_security_account_hardening_from_passwd(&passwd)
}

fn build_security_account_hardening_from_passwd(passwd: &str) -> SecurityAccountHardeningTelemetry {
    let mut uid0_accounts = Vec::new();
    for line in passwd.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 7 {
            continue;
        }
        let username = fields[0].trim();
        let uid = fields[2].trim().parse::<u32>().unwrap_or(u32::MAX);
        if uid != 0 || username == "root" || username.is_empty() {
            continue;
        }
        uid0_accounts.push(SecurityUid0Account {
            username: username.to_string(),
            uid,
            home_dir: fields[5].trim().to_string(),
            shell: fields[6].trim().to_string(),
        });
        if uid0_accounts.len() >= 10 {
            break;
        }
    }
    SecurityAccountHardeningTelemetry { uid0_accounts }
}

fn collect_security_scheduler_telemetry() -> SecuritySchedulerTelemetry {
    let mut sources = Vec::new();
    for path in [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/systemd/system",
    ] {
        collect_security_text_sources(std::path::Path::new(path), "root", &mut sources, 80);
        if sources.len() >= 80 {
            break;
        }
    }
    build_security_scheduler_telemetry_from_sources(sources)
}

fn build_security_scheduler_telemetry_from_sources(
    sources: Vec<SecurityTextSource>,
) -> SecuritySchedulerTelemetry {
    let mut entries = Vec::new();
    for source in sources {
        for line in source.content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let title = if command_has_download_execute_marker(&lower) {
                "Scheduled download-and-execute command"
            } else if command_has_encoded_payload_marker(&lower) {
                "Scheduled encoded payload"
            } else if command_has_writable_path_marker(&lower) {
                "Scheduled writable-path execution"
            } else if lower.contains("/dev/tcp/") {
                "Scheduled reverse shell marker"
            } else if line_has_security_marker(line) {
                "Scheduled suspicious command marker"
            } else {
                continue;
            };
            entries.push(SecuritySchedulerEntry {
                source: source.source.clone(),
                title: title.to_string(),
                evidence: sanitize_security_command(line).chars().take(220).collect(),
                severity: "medium",
            });
            if entries.len() >= 20 {
                break;
            }
        }
        if entries.len() >= 20 {
            break;
        }
    }
    SecuritySchedulerTelemetry { entries }
}

fn collect_security_firewall_telemetry() -> SecurityFirewallTelemetry {
    let ufw = collect_security_command_text("ufw", &["status"]);
    let iptables = collect_security_command_text("iptables", &["-S"]);
    let nft = collect_security_command_text("nft", &["list", "ruleset"]);
    build_security_firewall_telemetry_from_outputs(
        ufw.as_deref(),
        iptables.as_deref(),
        nft.as_deref(),
    )
}

fn collect_security_command_text(command: &str, args: &[&str]) -> Option<String> {
    let output = run_cmd_with_timeout(command, args, Duration::from_secs(2))?;
    let mut value = String::new();
    value.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !value.ends_with('\n') {
            value.push('\n');
        }
        value.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Some(value)
}

fn build_security_firewall_telemetry_from_outputs(
    ufw_status: Option<&str>,
    iptables_rules: Option<&str>,
    nft_ruleset: Option<&str>,
) -> SecurityFirewallTelemetry {
    let mut observed_backends = Vec::new();
    let mut findings = Vec::new();

    if let Some(output) = ufw_status {
        observed_backends.push("ufw".to_string());
        if output.to_ascii_lowercase().contains("status: inactive") {
            findings.push(SecurityFirewallFinding {
                backend: "ufw".to_string(),
                title: "UFW firewall inactive".to_string(),
                evidence: first_security_line(output, "Status: inactive"),
                severity: "medium",
            });
        }
    }

    if let Some(output) = iptables_rules {
        observed_backends.push("iptables".to_string());
        for line in output.lines() {
            let line = line.trim();
            if line == "-P INPUT ACCEPT" || line.starts_with("-P INPUT ACCEPT ") {
                findings.push(SecurityFirewallFinding {
                    backend: "iptables".to_string(),
                    title: "iptables INPUT default ACCEPT".to_string(),
                    evidence: line.chars().take(220).collect(),
                    severity: "medium",
                });
                break;
            }
        }
    }

    if let Some(output) = nft_ruleset {
        observed_backends.push("nft".to_string());
        let lower = output.to_ascii_lowercase();
        if !output.trim().is_empty() && !lower.contains("hook input") {
            findings.push(SecurityFirewallFinding {
                backend: "nft".to_string(),
                title: "nftables input hook not observed".to_string(),
                evidence: first_security_line(output, "no input hook"),
                severity: "medium",
            });
        }
    }

    findings.truncate(10);
    SecurityFirewallTelemetry {
        observed_backends,
        findings,
    }
}

fn collect_security_loader_telemetry() -> SecurityLoaderTelemetry {
    let mut sources = Vec::new();
    for path in [
        "/etc/ld.so.preload",
        "/etc/profile",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
    ] {
        collect_security_text_sources(std::path::Path::new(path), "root", &mut sources, 40);
        if sources.len() >= 40 {
            break;
        }
    }
    build_security_loader_telemetry_from_sources(sources)
}

fn build_security_loader_telemetry_from_sources(
    sources: Vec<SecurityTextSource>,
) -> SecurityLoaderTelemetry {
    let mut entries = Vec::new();
    for source in sources {
        let is_ld_preload = source.source.ends_with("ld.so.preload");
        for line in source.content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let (title, severity) = if is_ld_preload {
                if command_has_writable_path_marker(&lower) {
                    ("ld.so preload from writable path", "high")
                } else {
                    ("ld.so preload configured", "medium")
                }
            } else if lower.contains("ld_preload") {
                ("Profile LD_PRELOAD configured", "medium")
            } else if profile_line_has_writable_path_injection(&lower) {
                ("Profile PATH includes writable path", "medium")
            } else if command_has_download_execute_marker(&lower) {
                ("Profile download-and-execute command", "medium")
            } else {
                continue;
            };
            entries.push(SecurityLoaderEntry {
                source: source.source.clone(),
                title: title.to_string(),
                evidence: sanitize_security_command(line).chars().take(220).collect(),
                severity,
            });
            if entries.len() >= 20 {
                break;
            }
        }
        if entries.len() >= 20 {
            break;
        }
    }
    SecurityLoaderTelemetry { entries }
}

fn collect_security_writable_artifacts() -> SecurityWritableArtifactTelemetry {
    #[cfg(target_os = "linux")]
    {
        let mut inputs = Vec::new();
        for path in ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"] {
            collect_security_writable_artifact_inputs(
                std::path::Path::new(path),
                0,
                2,
                &mut inputs,
                160,
            );
            if inputs.len() >= 160 {
                break;
            }
        }
        build_security_writable_artifacts_from_inputs(inputs)
    }

    #[cfg(not(target_os = "linux"))]
    SecurityWritableArtifactTelemetry::default()
}

#[cfg(target_os = "linux")]
fn collect_security_writable_artifact_inputs(
    path: &std::path::Path,
    depth: usize,
    max_depth: usize,
    inputs: &mut Vec<SecurityWritableArtifactInput>,
    limit: usize,
) {
    use std::os::unix::fs::PermissionsExt;

    if inputs.len() >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten().take(80) {
        if inputs.len() >= limit {
            break;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() && depth < max_depth {
            collect_security_writable_artifact_inputs(&path, depth + 1, max_depth, inputs, limit);
            continue;
        }
        if !meta.is_file() || meta.len() > 32 * 1024 * 1024 {
            continue;
        }
        let mode = meta.permissions().mode() & 0o7777;
        let first_line = read_security_first_line(&path, 512);
        let modified_age_secs = meta
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|age| age.as_secs());
        inputs.push(SecurityWritableArtifactInput {
            path: path.to_string_lossy().to_string(),
            mode,
            size_bytes: meta.len(),
            modified_age_secs,
            first_line,
        });
    }
}

fn build_security_writable_artifacts_from_inputs(
    inputs: Vec<SecurityWritableArtifactInput>,
) -> SecurityWritableArtifactTelemetry {
    let mut artifacts = Vec::new();
    for input in inputs {
        let lower_path = input.path.to_ascii_lowercase();
        let executable = input.mode & 0o111 != 0;
        let shebang = input
            .first_line
            .as_deref()
            .map(|line| line.starts_with("#!"))
            .unwrap_or(false);
        let (title, severity) = if process_has_miner_name(&lower_path) {
            ("Writable-path artifact with miner marker", "high")
        } else if executable {
            ("Executable file in writable path", "medium")
        } else if shebang {
            ("Script file in writable path", "medium")
        } else {
            continue;
        };
        artifacts.push(SecurityWritableArtifact {
            path: input.path,
            title: title.to_string(),
            mode: format!("{:04o}", input.mode & 0o7777),
            size_bytes: input.size_bytes,
            modified_age_secs: input.modified_age_secs,
            severity,
        });
        if artifacts.len() >= 20 {
            break;
        }
    }
    SecurityWritableArtifactTelemetry { artifacts }
}

fn open_security_regular_file_nofollow(
    path: &std::path::Path,
) -> Result<std::fs::File, SecurityBoundedFileError> {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            // User-writable directories can replace a checked path with a
            // symlink, FIFO or device. Open non-blocking without following the
            // final symlink, then trust only fstat on the resulting descriptor.
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::File::open(path);

    let file = opened.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SecurityBoundedFileError::Missing
        } else {
            SecurityBoundedFileError::UnsafeOrUnreadable
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| SecurityBoundedFileError::UnsafeOrUnreadable)?;
    if !metadata.is_file() {
        return Err(SecurityBoundedFileError::UnsafeOrUnreadable);
    }
    Ok(file)
}

fn read_security_first_line(path: &std::path::Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;

    let file = open_security_regular_file_nofollow(path).ok()?;
    let read_limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::with_capacity(read_limit);
    file.take(read_limit as u64).read_to_end(&mut bytes).ok()?;
    let prefix = bytes
        .into_iter()
        .take(max_bytes)
        .take_while(|byte| *byte != b'\n' && *byte != 0)
        .collect::<Vec<_>>();
    if prefix.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&prefix).trim().to_string())
}

fn collect_security_ssh_telemetry() -> SecuritySshTelemetry {
    use std::sync::Mutex;
    use std::time::Instant;
    static CACHE: Mutex<Option<(Instant, SecuritySshTelemetry)>> = Mutex::new(None);
    const TTL: Duration = Duration::from_secs(300);

    if let Ok(guard) = CACHE.lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < TTL {
                return cached.clone();
            }
        }
    }

    let sshd_config =
        read_security_text_file("/etc/ssh/sshd_config", 256 * 1024).unwrap_or_default();
    let mut log_sources = Vec::new();
    let mut auth_log = String::new();
    for path in ["/var/log/auth.log", "/var/log/secure"] {
        if let Some(content) = read_security_text_file(path, 512 * 1024) {
            if !content.is_empty() {
                log_sources.push(path.to_string());
                auth_log.push_str(&content);
                auth_log.push('\n');
            }
        }
    }
    let result = build_security_ssh_telemetry_from_text(&sshd_config, &auth_log, log_sources);
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), result.clone()));
    }
    result
}

fn build_security_ssh_telemetry_from_text(
    sshd_config: &str,
    auth_log: &str,
    log_sources: Vec<String>,
) -> SecuritySshTelemetry {
    let mut permit_root_login = None;
    let mut password_authentication = None;
    for line in sshd_config.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let value = parts.next().unwrap_or("").to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        if key == "permitrootlogin" {
            permit_root_login = Some(value);
        } else if key == "passwordauthentication" {
            password_authentication = Some(value);
        }
    }

    let mut failed_by_ip: HashMap<String, u64> = HashMap::new();
    let mut success_by_user_ip_method: HashMap<(String, String, String), u64> = HashMap::new();
    for line in auth_log.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("sshd") {
            continue;
        }
        if lower.contains("failed password") {
            if let Some(ip) = extract_auth_log_ip(line) {
                *failed_by_ip.entry(ip).or_insert(0) += 1;
            }
        } else if let Some(method_start) = lower.find("accepted ") {
            let method = line[method_start + "accepted ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_ascii_lowercase();
            if let (Some(user), Some(ip)) = (
                extract_between(line, " for ", " from "),
                extract_auth_log_ip(line),
            ) {
                *success_by_user_ip_method
                    .entry((user, ip, method))
                    .or_insert(0) += 1;
            }
        }
    }

    let mut failed_sources: Vec<_> = failed_by_ip
        .into_iter()
        .map(|(ip, count)| SecurityLoginSource { ip, count })
        .collect();
    let failed_login_count = failed_sources.iter().map(|s| s.count).sum();
    failed_sources.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
    failed_sources.truncate(5);

    let mut successful_logins: Vec<_> = success_by_user_ip_method
        .into_iter()
        .map(|((user, ip, method), count)| SecuritySuccessfulLogin {
            user,
            ip,
            method,
            count,
        })
        .collect();
    let successful_login_count = successful_logins.iter().map(|s| s.count).sum();
    successful_logins.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.user.cmp(&b.user))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    successful_logins.truncate(5);

    SecuritySshTelemetry {
        permit_root_login,
        password_authentication,
        failed_login_count,
        failed_sources,
        successful_login_count,
        successful_logins,
        log_sources,
    }
}

fn extract_auth_log_ip(line: &str) -> Option<String> {
    extract_between(line, " from ", " ")
}

fn extract_between(line: &str, start: &str, end: &str) -> Option<String> {
    let (_, rest) = line.split_once(start)?;
    let value = rest.split(end).next()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub(crate) fn build_security_listeners_from_ss(output: &str) -> Vec<SecurityListener> {
    output
        .lines()
        .filter_map(parse_security_listener_line)
        .collect()
}

fn parse_security_listener_line(line: &str) -> Option<SecurityListener> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let state = parts.get(1).copied().unwrap_or("").to_ascii_lowercase();
    if state != "listen" && state != "unconn" {
        return None;
    }
    let local_raw = if parts.len() >= 6 && looks_like_endpoint(parts[4]) {
        parts[4]
    } else if looks_like_endpoint(parts[3]) {
        parts[3]
    } else {
        return None;
    };
    let (local_ip, local_port) = parse_endpoint(local_raw)?;
    if local_port == "*" {
        return None;
    }
    let process_raw = parts
        .iter()
        .find(|part| part.contains("users:"))
        .copied()
        .unwrap_or("");
    let (process, pid) = parse_process_info(process_raw);
    let scope = listener_scope(&local_ip);
    Some(SecurityListener {
        protocol: parts[0].to_ascii_lowercase(),
        local_ip,
        local_port,
        process,
        pid,
        scope,
    })
}

fn listener_scope(ip: &str) -> String {
    let lower = ip.trim_matches(['[', ']']).to_ascii_lowercase();
    if lower == "127.0.0.1" || lower == "::1" || lower == "localhost" || lower.starts_with("127.") {
        "loopback".to_string()
    } else {
        "public".to_string()
    }
}

fn collect_security_file_telemetry() -> SecurityFileTelemetry {
    SecurityFileTelemetry {
        deleted_binaries: collect_security_deleted_binaries(),
        suspicious_suid_sgid_files: collect_security_suid_sgid_files(),
    }
}

fn collect_security_deleted_binaries() -> Vec<SecurityDeletedBinary> {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut deleted = Vec::new();
        for entry in entries.flatten() {
            if deleted.len() >= 40 {
                break;
            }
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let exe_link = entry.path().join("exe");
            let Ok(target) = std::fs::read_link(exe_link) else {
                continue;
            };
            let exe_path = target.to_string_lossy().to_string();
            if !exe_path.ends_with(" (deleted)") {
                continue;
            }
            let name = std::fs::read_to_string(entry.path().join("comm"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            deleted.push(SecurityDeletedBinary {
                pid,
                name,
                exe_path,
            });
        }
        deleted
    }

    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

fn collect_security_suid_sgid_files() -> Vec<SecuritySuidSgidFile> {
    #[cfg(target_os = "linux")]
    {
        let dirs: Vec<String> = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]
            .iter()
            .filter(|path| std::path::Path::new(path).is_dir())
            .map(|path| path.to_string())
            .collect();
        if dirs.is_empty() {
            return Vec::new();
        }
        let mut args: Vec<&str> = dirs.iter().map(|s| s.as_str()).collect();
        args.extend([
            "-xdev",
            "-maxdepth",
            "3",
            "-type",
            "f",
            "(",
            "-perm",
            "-4000",
            "-o",
            "-perm",
            "-2000",
            ")",
            "-printf",
            "%m %u %p\n",
        ]);
        let Some(output) = run_cmd_with_timeout("find", &args, Duration::from_secs(2)) else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        build_security_suid_sgid_files_from_find(&stdout, 40)
    }

    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

fn build_security_suid_sgid_files_from_find(
    output: &str,
    limit: usize,
) -> Vec<SecuritySuidSgidFile> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(3, ' ');
            let mode = parts.next()?.trim();
            let owner = parts.next()?.trim();
            let path = parts.next()?.trim();
            if mode.is_empty() || owner.is_empty() || path.is_empty() {
                return None;
            }
            Some(SecuritySuidSgidFile {
                path: path.to_string(),
                mode: mode.to_string(),
                owner: owner.to_string(),
            })
        })
        .take(limit)
        .collect()
}

fn collect_security_container_telemetry() -> SecurityContainerTelemetry {
    let Some(inventory) = docker_ps_inventory_cached() else {
        return SecurityContainerTelemetry::default();
    };
    let ids: Vec<String> = inventory
        .lines()
        .filter_map(|line| line.split('\t').next().map(str::trim))
        .filter(|id| !id.is_empty())
        .take(20)
        .map(str::to_string)
        .collect();
    if ids.is_empty() {
        return SecurityContainerTelemetry {
            available: true,
            containers: Vec::new(),
        };
    }

    let mut args = vec!["inspect"];
    args.extend(ids.iter().map(|id| id.as_str()));
    let Some(inspect_output) = run_cmd_with_timeout("docker", &args, Duration::from_secs(4)) else {
        return SecurityContainerTelemetry {
            available: true,
            containers: Vec::new(),
        };
    };
    if !inspect_output.status.success() {
        return SecurityContainerTelemetry {
            available: true,
            containers: Vec::new(),
        };
    }
    let stdout = String::from_utf8_lossy(&inspect_output.stdout);
    build_security_containers_from_docker_inspect(&stdout, 20)
}

fn build_security_containers_from_docker_inspect(
    output: &str,
    limit: usize,
) -> SecurityContainerTelemetry {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(output) else {
        return SecurityContainerTelemetry {
            available: true,
            containers: Vec::new(),
        };
    };
    let Some(items) = value.as_array() else {
        return SecurityContainerTelemetry {
            available: true,
            containers: Vec::new(),
        };
    };

    let mut containers = Vec::new();
    for item in items.iter().take(limit) {
        let mut risks = Vec::new();
        let host_config = item.get("HostConfig").unwrap_or(&serde_json::Value::Null);
        if host_config
            .get("Privileged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            risks.push("privileged".to_string());
        }
        if host_config
            .get("NetworkMode")
            .and_then(|v| v.as_str())
            .map(|v| v == "host")
            .unwrap_or(false)
        {
            risks.push("host_network".to_string());
        }
        if host_config
            .get("PidMode")
            .and_then(|v| v.as_str())
            .map(|v| v == "host")
            .unwrap_or(false)
        {
            risks.push("host_pid".to_string());
        }
        collect_container_mount_risks(item, &mut risks);
        risks.sort();
        risks.dedup();
        if risks.is_empty() {
            continue;
        }
        let name = item
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .trim_start_matches('/')
            .to_string();
        let image = item
            .get("Config")
            .and_then(|v| v.get("Image"))
            .and_then(|v| v.as_str())
            .or_else(|| item.get("Image").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string();
        containers.push(SecurityContainerRisk { name, image, risks });
    }

    SecurityContainerTelemetry {
        available: true,
        containers,
    }
}

fn collect_container_mount_risks(item: &serde_json::Value, risks: &mut Vec<String>) {
    if let Some(binds) = item
        .get("HostConfig")
        .and_then(|v| v.get("Binds"))
        .and_then(|v| v.as_array())
    {
        for bind in binds.iter().filter_map(|v| v.as_str()) {
            let source = bind.split(':').next().unwrap_or("");
            if source == "/var/run/docker.sock" {
                risks.push("docker_socket_mount".to_string());
            } else if source == "/" {
                risks.push("host_root_mount".to_string());
            }
        }
    }

    if let Some(mounts) = item.get("Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            let source = mount.get("Source").and_then(|v| v.as_str()).unwrap_or("");
            let dest = mount
                .get("Destination")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if source == "/var/run/docker.sock" || dest == "/var/run/docker.sock" {
                risks.push("docker_socket_mount".to_string());
            } else if source == "/" {
                risks.push("host_root_mount".to_string());
            }
        }
    }
}

fn read_security_text_file(path: &str, max_bytes: u64) -> Option<String> {
    use std::io::{Read, Seek};

    let mut file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > max_bytes {
        file.seek(std::io::SeekFrom::Start(meta.len() - max_bytes))
            .ok()?;
    }
    let mut content = Vec::with_capacity(meta.len().min(max_bytes) as usize);
    file.take(max_bytes).read_to_end(&mut content).ok()?;
    Some(String::from_utf8_lossy(&content).to_string())
}

fn collect_security_persistence_entries() -> Vec<SecurityPersistenceEntry> {
    #[cfg(target_os = "linux")]
    {
        let mut entries = Vec::new();
        let paths = [
            "/etc/crontab",
            "/etc/rc.local",
            "/var/spool/cron/root",
            "/var/spool/cron/crontabs/root",
        ];
        for path in paths {
            collect_security_persistence_file(path, &mut entries);
        }
        collect_security_persistence_dir("/etc/cron.d", &mut entries, 40);
        collect_security_persistence_dir("/etc/systemd/system", &mut entries, 80);
        entries.truncate(40);
        entries
    }

    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

#[cfg(target_os = "linux")]
fn collect_security_persistence_dir(
    path: &str,
    entries: &mut Vec<SecurityPersistenceEntry>,
    limit: usize,
) {
    let Ok(read_dir) = std::fs::read_dir(path) else {
        return;
    };
    for entry in read_dir.flatten().take(limit) {
        let path = entry.path();
        if path.is_file() {
            if let Some(path) = path.to_str() {
                collect_security_persistence_file(path, entries);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn collect_security_persistence_file(path: &str, entries: &mut Vec<SecurityPersistenceEntry>) {
    const MAX_BYTES: u64 = 256 * 1024;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line_has_security_marker(line) {
            entries.push(SecurityPersistenceEntry {
                source: path.to_string(),
                line: sanitize_security_command(line).chars().take(240).collect(),
            });
        }
    }
}

fn collect_security_admin_usernames(login_accounts: &serde_json::Value) -> Vec<String> {
    login_accounts
        .get("admin_usernames")
        .and_then(|v| v.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn collect_security_authorized_key_count(login_accounts: &serde_json::Value) -> u64 {
    login_accounts
        .get("users")
        .and_then(|v| v.as_array())
        .map(|users| {
            users
                .iter()
                .filter_map(|user| {
                    user.get("authorized_key_count_lower_bound")
                        .or_else(|| user.get("authorized_key_count"))
                        .and_then(serde_json::Value::as_u64)
                })
                .sum()
        })
        .unwrap_or(0)
}

fn collect_security_authorized_key_count_exact(login_accounts: &serde_json::Value) -> bool {
    login_accounts
        .get("authorized_keys_scan")
        .and_then(|scan| scan.get("key_count_exact"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn collect_security_ssh_access_issues(
    login_accounts: &serde_json::Value,
) -> Vec<SecuritySshAccessIssue> {
    login_accounts
        .get("users")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .flat_map(|user| {
            let username = user
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let Some(health) = user.get("ssh_access") else {
                return Vec::new();
            };
            let strict_ok = health
                .get("strict_modes_path_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if strict_ok {
                return Vec::new();
            }
            let evidence = ssh_access_evidence(health);
            health
                .get("issues")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|issue| {
                    issue.as_str().map(|issue| SecuritySshAccessIssue {
                        username: username.clone(),
                        issue: issue.to_string(),
                        evidence: evidence.clone(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn ssh_access_evidence(health: &serde_json::Value) -> String {
    let home_dir = health
        .get("home_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let authorized_keys_path = health
        .get("authorized_keys_path")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let home_mode = health
        .get("home_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let ssh_dir_mode = health
        .get("ssh_dir_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let authorized_keys_mode = health
        .get("authorized_keys_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    format!(
        "home={} home_mode={} ssh_dir_mode={} authorized_keys={} authorized_keys_mode={}",
        home_dir, home_mode, ssh_dir_mode, authorized_keys_path, authorized_keys_mode
    )
}

fn build_security_posture_report(input: SecurityPostureInput) -> serde_json::Value {
    let mut findings = Vec::new();

    for process in &input.processes {
        if process_has_miner_name(&process.name) {
            findings.push(SecurityFinding {
                severity: "critical",
                category: "process",
                title: "Known miner-like process",
                evidence: format_security_process_evidence(process),
                pid: Some(process.pid),
                process: Some(process.name.clone()),
            });
            continue;
        }

        if process_uses_suspicious_path(process) && process.cpu_percent >= 50.0 {
            findings.push(SecurityFinding {
                severity: "high",
                category: "process",
                title: "High CPU process from suspicious path",
                evidence: format_security_process_evidence(process),
                pid: Some(process.pid),
                process: Some(process.name.clone()),
            });
        } else if process_uses_suspicious_path(process) {
            findings.push(SecurityFinding {
                severity: "medium",
                category: "process",
                title: "Process executing from writable temporary path",
                evidence: format_security_process_evidence(process),
                pid: Some(process.pid),
                process: Some(process.name.clone()),
            });
        }
    }

    for flow in &input.network_flows {
        if flow_has_mining_marker(flow) {
            findings.push(SecurityFinding {
                severity: "medium",
                category: "network",
                title: "Outbound connection to mining pool port",
                evidence: format!(
                    "{} pid={} -> {}:{} connections={} direction={}",
                    flow.process,
                    flow.pid
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    flow.remote_ip,
                    flow.remote_port,
                    flow.connections,
                    flow.direction
                ),
                pid: flow.pid,
                process: Some(flow.process.clone()),
            });
        }
    }

    for entry in &input.persistence_entries {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "persistence",
            title: "Suspicious persistence entry",
            evidence: format!(
                "{}: {}",
                entry.source,
                sanitize_security_command(&entry.line)
            ),
            pid: None,
            process: None,
        });
    }

    if ssh_setting_is_yes(&input.ssh_telemetry.password_authentication) {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "ssh",
            title: "SSH password authentication enabled",
            evidence: "PasswordAuthentication yes".to_string(),
            pid: None,
            process: None,
        });
    }

    if ssh_setting_is_yes(&input.ssh_telemetry.permit_root_login) {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "ssh",
            title: "Root SSH login explicitly enabled",
            evidence: "PermitRootLogin yes".to_string(),
            pid: None,
            process: None,
        });
    }

    if input.ssh_telemetry.failed_login_count >= 20 {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "ssh",
            title: "Burst of failed SSH logins",
            evidence: format!(
                "failed={} top_source={}",
                input.ssh_telemetry.failed_login_count,
                input
                    .ssh_telemetry
                    .failed_sources
                    .first()
                    .map(|source| format!("{} count={}", source.ip, source.count))
                    .unwrap_or_else(|| "-".to_string())
            ),
            pid: None,
            process: None,
        });
    }

    for issue in &input.ssh_access_issues {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "ssh",
            title: "SSH authorized_keys path may be ignored",
            evidence: format!(
                "user={} issue={} {}",
                issue.username, issue.issue, issue.evidence
            ),
            pid: None,
            process: None,
        });
    }

    for listener in &input.listeners {
        let Some((severity, title)) = security_listener_finding(listener) else {
            continue;
        };
        findings.push(SecurityFinding {
            severity,
            category: "listener",
            title,
            evidence: format_security_listener_evidence(listener),
            pid: listener.pid,
            process: Some(listener.process.clone()),
        });
    }

    for binary in &input.file_telemetry.deleted_binaries {
        findings.push(SecurityFinding {
            severity: "high",
            category: "file",
            title: "Deleted executable still running",
            evidence: format!(
                "{} pid={} path={}",
                binary.name, binary.pid, binary.exe_path
            ),
            pid: Some(binary.pid),
            process: Some(binary.name.clone()),
        });
    }

    for file in &input.file_telemetry.suspicious_suid_sgid_files {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "file",
            title: "Suspicious SUID/SGID file in writable path",
            evidence: format!("{} mode={} owner={}", file.path, file.mode, file.owner),
            pid: None,
            process: None,
        });
    }

    for container in &input.container_telemetry.containers {
        findings.push(SecurityFinding {
            severity: "high",
            category: "container",
            title: "Risky container configuration",
            evidence: format!(
                "{} image={} risks={}",
                container.name,
                container.image,
                container.risks.join(",")
            ),
            pid: None,
            process: Some(container.name.clone()),
        });
    }

    for command in &input.process_behavior.command_findings {
        findings.push(SecurityFinding {
            severity: command.severity,
            category: "process_behavior",
            title: security_static_title(&command.title),
            evidence: command.evidence.clone(),
            pid: command.pid,
            process: Some(command.process.clone()),
        });
    }

    for entry in &input.user_persistence.entries {
        findings.push(SecurityFinding {
            severity: entry.severity,
            category: "user_persistence",
            title: security_static_title(&entry.title),
            evidence: format!("{} user={} {}", entry.source, entry.user, entry.evidence),
            pid: None,
            process: None,
        });
    }

    for entry in &input.user_persistence.sudo_nopasswd_entries {
        findings.push(SecurityFinding {
            severity: entry.severity,
            category: "user_persistence",
            title: security_static_title(&entry.title),
            evidence: format!("{} user={} {}", entry.source, entry.user, entry.evidence),
            pid: None,
            process: None,
        });
    }

    for proxy in &input.dns_proxy.proxy_variables {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "dns_proxy",
            title: "Proxy environment variable configured",
            evidence: format!("{}={}", proxy.name, proxy.value),
            pid: None,
            process: None,
        });
    }

    for listener in &input.dns_proxy.public_proxy_listeners {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "dns_proxy",
            title: "Public proxy/Tor listener",
            evidence: format_security_listener_evidence(listener),
            pid: listener.pid,
            process: Some(listener.process.clone()),
        });
    }

    for account in &input.account_hardening.uid0_accounts {
        findings.push(SecurityFinding {
            severity: "high",
            category: "account_hardening",
            title: "Additional UID 0 account",
            evidence: format!(
                "username={} uid={} home={} shell={}",
                account.username, account.uid, account.home_dir, account.shell
            ),
            pid: None,
            process: None,
        });
    }

    for entry in &input.scheduler.entries {
        findings.push(SecurityFinding {
            severity: entry.severity,
            category: "scheduler",
            title: security_static_title(&entry.title),
            evidence: format!("{}: {}", entry.source, entry.evidence),
            pid: None,
            process: None,
        });
    }

    for finding in &input.firewall.findings {
        findings.push(SecurityFinding {
            severity: finding.severity,
            category: "firewall",
            title: security_static_title(&finding.title),
            evidence: format!("{}: {}", finding.backend, finding.evidence),
            pid: None,
            process: None,
        });
    }

    for entry in &input.loader.entries {
        findings.push(SecurityFinding {
            severity: entry.severity,
            category: "loader",
            title: security_static_title(&entry.title),
            evidence: format!("{}: {}", entry.source, entry.evidence),
            pid: None,
            process: None,
        });
    }

    for artifact in &input.writable_artifacts.artifacts {
        findings.push(SecurityFinding {
            severity: artifact.severity,
            category: "writable_artifact",
            title: security_static_title(&artifact.title),
            evidence: format_security_writable_artifact_evidence(artifact),
            pid: None,
            process: None,
        });
    }

    if input.login_admin_usernames.len() > 3 {
        findings.push(SecurityFinding {
            severity: "medium",
            category: "account",
            title: "Many admin-capable login accounts",
            evidence: format!("admin users: {}", input.login_admin_usernames.join(", ")),
            pid: None,
            process: None,
        });
    }

    if input.authorized_key_count > 10 {
        let count_label = if input.authorized_key_count_exact {
            "authorized key count"
        } else {
            "authorized key count lower bound"
        };
        findings.push(SecurityFinding {
            severity: "medium",
            category: "account",
            title: "Many SSH authorized keys",
            evidence: format!("{count_label}: {}", input.authorized_key_count),
            pid: None,
            process: None,
        });
    }

    findings.sort_by(|a, b| {
        security_severity_weight(b.severity)
            .cmp(&security_severity_weight(a.severity))
            .then_with(|| a.category.cmp(b.category))
            .then_with(|| a.title.cmp(b.title))
    });
    findings.truncate(20);

    let critical = count_findings(&findings, "critical");
    let high = count_findings(&findings, "high");
    let medium = count_findings(&findings, "medium");
    let low = count_findings(&findings, "low");
    let score = security_score(&findings);
    let risk_level = if critical > 0 {
        "critical"
    } else if score >= 70 {
        "high"
    } else if score >= 35 {
        "medium"
    } else {
        "low"
    };

    serde_json::json!({
        "schema_version": 1,
        "risk_level": risk_level,
        "score": score,
        "findings": findings.iter().map(security_finding_json).collect::<Vec<_>>(),
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "signals": {
            "process_count": findings.iter().filter(|f| f.category == "process").count(),
            "network_count": findings.iter().filter(|f| f.category == "network").count(),
            "persistence_count": findings.iter().filter(|f| f.category == "persistence").count(),
            "account_count": findings.iter().filter(|f| f.category == "account").count(),
            "ssh_count": findings.iter().filter(|f| f.category == "ssh").count(),
            "listener_count": findings.iter().filter(|f| f.category == "listener").count(),
            "file_count": findings.iter().filter(|f| f.category == "file").count(),
            "container_count": findings.iter().filter(|f| f.category == "container").count(),
            "process_behavior_count": findings.iter().filter(|f| f.category == "process_behavior").count(),
            "user_persistence_count": findings.iter().filter(|f| f.category == "user_persistence").count(),
            "dns_proxy_count": findings.iter().filter(|f| f.category == "dns_proxy").count(),
            "account_hardening_count": findings.iter().filter(|f| f.category == "account_hardening").count(),
            "scheduler_count": findings.iter().filter(|f| f.category == "scheduler").count(),
            "firewall_count": findings.iter().filter(|f| f.category == "firewall").count(),
            "loader_count": findings.iter().filter(|f| f.category == "loader").count(),
            "writable_artifact_count": findings.iter().filter(|f| f.category == "writable_artifact").count(),
        },
        "telemetry": {
            "ssh": security_ssh_telemetry_json(&input.ssh_telemetry),
            "listeners": security_listeners_telemetry_json(&input.listeners),
            "files": security_file_telemetry_json(&input.file_telemetry),
            "containers": security_container_telemetry_json(&input.container_telemetry),
            "process_behavior": security_process_behavior_telemetry_json(&input.process_behavior),
            "user_persistence": security_user_persistence_telemetry_json(&input.user_persistence),
            "dns_proxy": security_dns_proxy_telemetry_json(&input.dns_proxy),
            "account_hardening": security_account_hardening_telemetry_json(&input.account_hardening),
            "scheduler": security_scheduler_telemetry_json(&input.scheduler),
            "firewall": security_firewall_telemetry_json(&input.firewall),
            "loader": security_loader_telemetry_json(&input.loader),
            "writable_artifacts": security_writable_artifacts_telemetry_json(&input.writable_artifacts),
        },
        "collector_note": "Detection only. No automatic remediation was performed.",
    })
}

fn security_ssh_telemetry_json(ssh: &SecuritySshTelemetry) -> serde_json::Value {
    serde_json::json!({
        "permit_root_login": ssh.permit_root_login,
        "password_authentication": ssh.password_authentication,
        "failed_login_count": ssh.failed_login_count,
        "failed_sources": ssh.failed_sources.iter().map(|source| serde_json::json!({
            "ip": source.ip,
            "count": source.count,
        })).collect::<Vec<_>>(),
        "successful_login_count": ssh.successful_login_count,
        "successful_logins": ssh.successful_logins.iter().map(|login| serde_json::json!({
            "user": login.user,
            "ip": login.ip,
            "method": login.method,
            "count": login.count,
        })).collect::<Vec<_>>(),
        "log_sources": ssh.log_sources,
    })
}

fn security_listeners_telemetry_json(listeners: &[SecurityListener]) -> serde_json::Value {
    let public_listening_count = listeners
        .iter()
        .filter(|listener| listener.scope == "public")
        .count();
    let sensitive_public_count = listeners
        .iter()
        .filter(|listener| security_listener_finding(listener).is_some())
        .count();
    serde_json::json!({
        "listening_count": listeners.len(),
        "public_listening_count": public_listening_count,
        "sensitive_public_count": sensitive_public_count,
        "services": listeners.iter().take(20).map(|listener| serde_json::json!({
            "protocol": listener.protocol,
            "local_ip": listener.local_ip,
            "local_port": listener.local_port,
            "process": listener.process,
            "pid": listener.pid,
            "scope": listener.scope,
        })).collect::<Vec<_>>(),
    })
}

fn security_file_telemetry_json(files: &SecurityFileTelemetry) -> serde_json::Value {
    serde_json::json!({
        "deleted_binary_count": files.deleted_binaries.len(),
        "suspicious_suid_sgid_count": files.suspicious_suid_sgid_files.len(),
        "deleted_binaries": files.deleted_binaries.iter().take(10).map(|binary| serde_json::json!({
            "pid": binary.pid,
            "name": binary.name,
            "exe_path": binary.exe_path,
        })).collect::<Vec<_>>(),
        "suspicious_suid_sgid_files": files.suspicious_suid_sgid_files.iter().take(10).map(|file| serde_json::json!({
            "path": file.path,
            "mode": file.mode,
            "owner": file.owner,
        })).collect::<Vec<_>>(),
    })
}

fn security_container_telemetry_json(containers: &SecurityContainerTelemetry) -> serde_json::Value {
    serde_json::json!({
        "available": containers.available,
        "risky_count": containers.containers.len(),
        "containers": containers.containers.iter().take(10).map(|container| serde_json::json!({
            "name": container.name,
            "image": container.image,
            "risks": container.risks,
        })).collect::<Vec<_>>(),
    })
}

fn security_process_behavior_telemetry_json(
    behavior: &SecurityProcessBehaviorTelemetry,
) -> serde_json::Value {
    let proxy_tunnel_process_count = behavior
        .command_findings
        .iter()
        .filter(|finding| finding.title == "Proxy or tunnel process present")
        .count();
    serde_json::json!({
        "suspicious_command_count": behavior.command_findings.len(),
        "proxy_tunnel_process_count": proxy_tunnel_process_count,
        "truncated_cmdline_count": behavior.truncated_cmdline_count,
        "commands": behavior.command_findings.iter().take(10).map(|finding| serde_json::json!({
            "severity": finding.severity,
            "title": finding.title,
            "pid": finding.pid,
            "process": finding.process,
            "evidence": finding.evidence,
        })).collect::<Vec<_>>(),
    })
}

fn security_user_persistence_telemetry_json(
    persistence: &SecurityUserPersistenceTelemetry,
) -> serde_json::Value {
    serde_json::json!({
        "home_profiles_scanned": persistence.home_profiles_scanned,
        "home_profile_scan_status": if persistence.home_profiles_scanned { "complete" } else { "skipped_remote_fs_safety" },
        "entry_count": persistence.entries.len(),
        "sudo_nopasswd_count": persistence.sudo_nopasswd_entries.len(),
        "entries": persistence.entries.iter().take(10).map(security_user_persistence_entry_json).collect::<Vec<_>>(),
        "sudo_nopasswd_entries": persistence.sudo_nopasswd_entries.iter().take(10).map(security_user_persistence_entry_json).collect::<Vec<_>>(),
    })
}

fn security_user_persistence_entry_json(entry: &SecurityUserPersistenceEntry) -> serde_json::Value {
    serde_json::json!({
        "source": entry.source,
        "user": entry.user,
        "title": entry.title,
        "evidence": entry.evidence,
        "severity": entry.severity,
    })
}

fn security_dns_proxy_telemetry_json(dns_proxy: &SecurityDnsProxyTelemetry) -> serde_json::Value {
    serde_json::json!({
        "nameservers": dns_proxy.nameservers,
        "proxy_variable_count": dns_proxy.proxy_variables.len(),
        "proxy_variables": dns_proxy.proxy_variables.iter().take(10).map(|proxy| serde_json::json!({
            "name": proxy.name,
            "value": proxy.value,
        })).collect::<Vec<_>>(),
        "public_proxy_listener_count": dns_proxy.public_proxy_listeners.len(),
        "public_proxy_listeners": dns_proxy.public_proxy_listeners.iter().take(10).map(|listener| serde_json::json!({
            "protocol": listener.protocol,
            "local_ip": listener.local_ip,
            "local_port": listener.local_port,
            "process": listener.process,
            "pid": listener.pid,
            "scope": listener.scope,
        })).collect::<Vec<_>>(),
    })
}

fn security_account_hardening_telemetry_json(
    account_hardening: &SecurityAccountHardeningTelemetry,
) -> serde_json::Value {
    serde_json::json!({
        "uid0_account_count": account_hardening.uid0_accounts.len(),
        "uid0_accounts": account_hardening.uid0_accounts.iter().take(10).map(|account| serde_json::json!({
            "username": account.username,
            "uid": account.uid,
            "home_dir": account.home_dir,
            "shell": account.shell,
        })).collect::<Vec<_>>(),
    })
}

fn security_scheduler_telemetry_json(scheduler: &SecuritySchedulerTelemetry) -> serde_json::Value {
    serde_json::json!({
        "entry_count": scheduler.entries.len(),
        "entries": scheduler.entries.iter().take(10).map(|entry| serde_json::json!({
            "source": entry.source,
            "title": entry.title,
            "evidence": entry.evidence,
            "severity": entry.severity,
        })).collect::<Vec<_>>(),
    })
}

fn security_firewall_telemetry_json(firewall: &SecurityFirewallTelemetry) -> serde_json::Value {
    serde_json::json!({
        "observed_backends": firewall.observed_backends,
        "finding_count": firewall.findings.len(),
        "findings": firewall.findings.iter().take(10).map(|finding| serde_json::json!({
            "backend": finding.backend,
            "title": finding.title,
            "evidence": finding.evidence,
            "severity": finding.severity,
        })).collect::<Vec<_>>(),
    })
}

fn security_loader_telemetry_json(loader: &SecurityLoaderTelemetry) -> serde_json::Value {
    serde_json::json!({
        "entry_count": loader.entries.len(),
        "entries": loader.entries.iter().take(10).map(|entry| serde_json::json!({
            "source": entry.source,
            "title": entry.title,
            "evidence": entry.evidence,
            "severity": entry.severity,
        })).collect::<Vec<_>>(),
    })
}

fn security_writable_artifacts_telemetry_json(
    artifacts: &SecurityWritableArtifactTelemetry,
) -> serde_json::Value {
    serde_json::json!({
        "artifact_count": artifacts.artifacts.len(),
        "artifacts": artifacts.artifacts.iter().take(10).map(|artifact| serde_json::json!({
            "path": artifact.path,
            "title": artifact.title,
            "mode": artifact.mode,
            "size_bytes": artifact.size_bytes,
            "modified_age_secs": artifact.modified_age_secs,
            "severity": artifact.severity,
        })).collect::<Vec<_>>(),
    })
}

fn security_finding_json(finding: &SecurityFinding) -> serde_json::Value {
    serde_json::json!({
        "severity": finding.severity,
        "category": finding.category,
        "title": finding.title,
        "evidence": finding.evidence,
        "pid": finding.pid,
        "process": finding.process,
    })
}

fn count_findings(findings: &[SecurityFinding], severity: &str) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

fn security_score(findings: &[SecurityFinding]) -> u64 {
    let max = findings
        .iter()
        .map(|f| security_severity_weight(f.severity))
        .max()
        .unwrap_or(0);
    let bonus = findings
        .iter()
        .filter(|f| f.severity != "low")
        .count()
        .saturating_sub(1) as u64
        * 5;
    (max as u64 + bonus).min(100)
}

fn security_severity_weight(severity: &str) -> u8 {
    match severity {
        "critical" => 95,
        "high" => 75,
        "medium" => 45,
        "low" => 10,
        _ => 0,
    }
}

fn ssh_setting_is_yes(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

fn security_listener_finding(listener: &SecurityListener) -> Option<(&'static str, &'static str)> {
    if listener.scope != "public" {
        return None;
    }
    if listener.local_port == "2375" {
        return Some(("high", "Public Docker API listener"));
    }
    if SECURITY_SENSITIVE_PUBLIC_PORTS
        .iter()
        .any(|port| listener.local_port == *port)
    {
        return Some(("medium", "Public sensitive service listener"));
    }
    None
}

fn format_security_listener_evidence(listener: &SecurityListener) -> String {
    format!(
        "{} {}:{} process={} pid={} scope={}",
        listener.protocol,
        listener.local_ip,
        listener.local_port,
        listener.process,
        listener
            .pid
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        listener.scope
    )
}

fn security_static_title(title: &str) -> &'static str {
    match title {
        "Download-and-execute command line" => "Download-and-execute command line",
        "Encoded payload command line" => "Encoded payload command line",
        "Interpreter running from writable path" => "Interpreter running from writable path",
        "Proxy or tunnel process present" => "Proxy or tunnel process present",
        "User profile download-and-execute persistence" => {
            "User profile download-and-execute persistence"
        }
        "Suspicious user persistence line" => "Suspicious user persistence line",
        "NOPASSWD sudo grant" => "NOPASSWD sudo grant",
        "Scheduled download-and-execute command" => "Scheduled download-and-execute command",
        "Scheduled encoded payload" => "Scheduled encoded payload",
        "Scheduled writable-path execution" => "Scheduled writable-path execution",
        "Scheduled reverse shell marker" => "Scheduled reverse shell marker",
        "Scheduled suspicious command marker" => "Scheduled suspicious command marker",
        "UFW firewall inactive" => "UFW firewall inactive",
        "iptables INPUT default ACCEPT" => "iptables INPUT default ACCEPT",
        "nftables input hook not observed" => "nftables input hook not observed",
        "ld.so preload from writable path" => "ld.so preload from writable path",
        "ld.so preload configured" => "ld.so preload configured",
        "Profile LD_PRELOAD configured" => "Profile LD_PRELOAD configured",
        "Profile PATH includes writable path" => "Profile PATH includes writable path",
        "Profile download-and-execute command" => "Profile download-and-execute command",
        "Writable-path artifact with miner marker" => "Writable-path artifact with miner marker",
        "Executable file in writable path" => "Executable file in writable path",
        "Script file in writable path" => "Script file in writable path",
        _ => "Security finding",
    }
}

fn sanitize_security_command(value: &str) -> String {
    // Command lines and configuration snippets are evidence, not a secret
    // transport. Remove control characters before applying redaction so an
    // attacker cannot hide a credential boundary from the scanner or the UI.
    let mut sanitized = value
        .chars()
        .take(2048)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    for marker in [
        "password=",
        "passwd=",
        "token=",
        "access_token=",
        "refresh_token=",
        "secret=",
        "client_secret=",
        "apikey=",
        "api_key=",
        "api-key=",
        "authorization=",
        "proxy_authorization=",
        "aws_access_key_id=",
        "aws_secret_access_key=",
        "github_token=",
        "bearer=",
        "basic=",
    ] {
        sanitized = redact_assignment_case_insensitive(&sanitized, marker);
    }
    sanitized = redact_sensitive_adjacent_arguments(&sanitized);
    sanitized = redact_known_token_shapes(&sanitized);
    sanitized = redact_url_credentials(&sanitized);
    sanitized
        .split_whitespace()
        .take(40)
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

fn redact_sensitive_adjacent_arguments(value: &str) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RedactionState {
        None,
        SecretValue,
        AuthorizationScheme,
    }

    fn normalized_argument(value: &str) -> String {
        value
            .trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';'))
            .to_ascii_lowercase()
    }

    fn is_secret_argument(value: &str) -> bool {
        matches!(
            value,
            "--password"
                | "--passwd"
                | "--token"
                | "--access-token"
                | "--refresh-token"
                | "--secret"
                | "--client-secret"
                | "--api-key"
                | "--apikey"
                | "--auth-token"
                | "--bearer-token"
                | "--github-token"
                | "-u"
                | "--user"
                | "--userpwd"
                | "--proxy-user"
                | "--proxy-userpwd"
                | "--oauth2-bearer"
                | "--aws-access-key-id"
                | "--aws-secret-access-key"
                | "aws_access_key_id"
                | "aws_secret_access_key"
                | "github_token"
        ) || (value.starts_with('-')
            && [
                "secret",
                "password",
                "passwd",
                "token",
                "api-key",
                "api_key",
                "apikey",
                "access-key",
                "access_key",
                "private-key",
                "private_key",
            ]
            .iter()
            .any(|marker| value.contains(marker)))
    }

    let mut state = RedactionState::None;
    let mut output = Vec::new();
    for token in value.split_whitespace() {
        let normalized = normalized_argument(token);
        match state {
            RedactionState::SecretValue => {
                output.push("[redacted]".to_string());
                state = RedactionState::None;
                continue;
            }
            RedactionState::AuthorizationScheme => {
                if matches!(normalized.as_str(), "bearer" | "basic" | "token") {
                    output.push(token.to_string());
                    state = RedactionState::SecretValue;
                } else {
                    output.push("[redacted]".to_string());
                    state = RedactionState::None;
                }
                continue;
            }
            RedactionState::None => {}
        }

        let normalized_without_colon = normalized.trim_end_matches(':');
        if !normalized_without_colon.starts_with("--")
            && normalized_without_colon
                .strip_prefix("-u")
                .is_some_and(|value| !value.is_empty())
        {
            output.push("-u[redacted]".to_string());
            continue;
        }
        if let Some((flag, _)) = normalized_without_colon.split_once('=') {
            if is_secret_argument(flag) {
                let original_flag = token.split_once('=').map(|(flag, _)| flag).unwrap_or(flag);
                output.push(format!("{original_flag}=[redacted]"));
                continue;
            }
        }
        if is_secret_argument(normalized_without_colon) {
            output.push(token.to_string());
            state = RedactionState::SecretValue;
        } else if normalized_without_colon == "authorization"
            || normalized_without_colon == "proxy-authorization"
            || normalized_without_colon == "proxy_authorization"
        {
            output.push(token.to_string());
            state = RedactionState::AuthorizationScheme;
        } else if normalized.contains("authorization:bearer")
            || normalized.contains("authorization:basic")
            || normalized.contains("authorization:token")
        {
            // Handles `Authorization:Bearer TOKEN` and header arguments such
            // as `--header=Authorization:Bearer TOKEN`.
            output.push(token.to_string());
            state = RedactionState::SecretValue;
        } else if let Some((header_name, header_value)) = normalized.split_once(':') {
            let compact_name = header_name
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            if [
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
            .any(|marker| compact_name.contains(marker))
            {
                output.push("[redacted-header]".to_string());
                if header_value.trim_matches(['\'', '"']).is_empty() {
                    state = RedactionState::SecretValue;
                }
            } else {
                output.push(token.to_string());
            }
        } else {
            output.push(token.to_string());
        }
    }
    output.join(" ")
}

fn redact_known_token_shapes(value: &str) -> String {
    fn token_end(bytes: &[u8], start: usize) -> usize {
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
        {
            end += 1;
        }
        end
    }

    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len().min(512));
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let remaining = &bytes[cursor..];
        let github_prefix_len = [b"ghp_".as_slice(), b"gho_", b"ghu_", b"ghs_", b"ghr_"]
            .iter()
            .find(|prefix| remaining.starts_with(prefix))
            .map(|prefix| prefix.len())
            .or_else(|| remaining.starts_with(b"github_pat_").then_some(11));
        if let Some(prefix_len) = github_prefix_len {
            let end = token_end(bytes, cursor + prefix_len);
            if end.saturating_sub(cursor) >= prefix_len + 8 {
                output.push_str("[redacted]");
                cursor = end;
                continue;
            }
        }

        if remaining.starts_with(b"AKIA") || remaining.starts_with(b"ASIA") {
            let end = token_end(bytes, cursor + 4);
            let candidate = &bytes[cursor..end];
            if candidate.len() >= 20
                && candidate[..20]
                    .iter()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            {
                output.push_str("[redacted]");
                cursor = end;
                continue;
            }
        }

        let Some(ch) = value[cursor..].chars().next() else {
            break;
        };
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output
}

fn redact_assignment_case_insensitive(value: &str, marker: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let mut result = String::new();
    let mut cursor = 0usize;
    let marker_lower = marker.to_ascii_lowercase();
    while let Some(offset) = lower[cursor..].find(&marker_lower) {
        let start = cursor + offset;
        let value_start = start + marker.len();
        result.push_str(&value[cursor..value_start]);
        result.push_str("[redacted]");
        let rest = &value[value_start..];
        let end_offset = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '&' | ';' | '"' | '\''))
            .unwrap_or(rest.len());
        cursor = value_start + end_offset;
    }
    result.push_str(&value[cursor..]);
    result
}

fn command_has_download_execute_marker(lower: &str) -> bool {
    (lower.contains("curl ") || lower.contains("wget "))
        && (lower.contains("| sh")
            || lower.contains("| bash")
            || lower.contains(" sh ")
            || lower.contains(" bash "))
}

fn command_has_encoded_payload_marker(lower: &str) -> bool {
    (lower.contains("base64") && lower.contains("-d") && lower.contains("|"))
        || (lower.contains("openssl enc") && lower.contains("-d"))
}

fn command_uses_interpreter(process_lower: &str, lower: &str) -> bool {
    SECURITY_INTERPRETER_NAMES
        .iter()
        .any(|name| process_lower.contains(name) || lower.starts_with(name))
}

fn command_has_writable_path_marker(lower: &str) -> bool {
    SECURITY_SUSPICIOUS_PATH_PREFIXES
        .iter()
        .any(|prefix| lower.contains(prefix))
        || lower.contains("/.cache/")
}

fn profile_line_has_writable_path_injection(lower: &str) -> bool {
    lower.contains("path=")
        && [
            "/tmp",
            "/tmp/",
            "/var/tmp",
            "/var/tmp/",
            "/dev/shm",
            "/dev/shm/",
            "/run/shm",
            "/run/shm/",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn process_has_proxy_tunnel_marker(process_lower: &str) -> bool {
    SECURITY_PROXY_TUNNEL_PROCESS_NAMES
        .iter()
        .any(|name| process_lower.contains(name))
}

fn redact_proxy_value(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    let mut cleaned = value.to_string();
    if let Some((scheme, rest)) = value.split_once("://") {
        let rest = rest.rsplit('@').next().unwrap_or(rest);
        cleaned = format!("{}://{}", scheme, rest);
    } else if value.contains('@') {
        cleaned = value.rsplit('@').next().unwrap_or(value).to_string();
    }
    cleaned
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(';')
        .to_string()
}

fn redact_url_credentials(value: &str) -> String {
    let mut result = String::new();
    let mut cursor = 0usize;
    while let Some(offset) = value[cursor..].find("://") {
        let scheme_end = cursor + offset + 3;
        result.push_str(&value[cursor..scheme_end]);
        let rest = &value[scheme_end..];
        let token_end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | ')'))
            .unwrap_or(rest.len());
        let token = &rest[..token_end];
        if let Some(at_index) = token.rfind('@') {
            result.push_str(&token[at_index + 1..]);
        } else {
            result.push_str(token);
        }
        cursor = scheme_end + token_end;
    }
    result.push_str(&value[cursor..]);
    result
}

fn process_has_miner_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECURITY_MINER_NAMES
        .iter()
        .any(|marker| lower.contains(marker))
}

fn process_uses_suspicious_path(process: &SecurityProcess) -> bool {
    process
        .exe_path
        .as_deref()
        .map(path_has_suspicious_exec_prefix)
        .unwrap_or(false)
}

fn path_has_suspicious_exec_prefix(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SECURITY_SUSPICIOUS_PATH_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || lower.contains("/.cache/")
}

fn line_has_security_marker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    SECURITY_MINER_NAMES
        .iter()
        .any(|marker| lower.contains(marker))
        || SECURITY_SUSPICIOUS_PATH_PREFIXES
            .iter()
            .any(|prefix| lower.contains(prefix))
        || lower.contains("stratum+tcp")
        || lower.contains("pool.")
}

fn flow_has_mining_marker(flow: &SecurityNetworkFlow) -> bool {
    let lower_process = flow.process.to_ascii_lowercase();
    let lower_remote = flow.remote_ip.to_ascii_lowercase();
    process_has_miner_name(&lower_process)
        || lower_remote.contains("stratum")
        || SECURITY_MINING_PORTS
            .iter()
            .any(|port| flow.remote_port == *port)
}

fn format_security_process_evidence(process: &SecurityProcess) -> String {
    format!(
        "{} pid={} cpu={:.1}% mem={} path={}",
        process.name,
        process.pid,
        process.cpu_percent,
        process.memory_bytes,
        process.exe_path.as_deref().unwrap_or("-")
    )
}

fn first_security_line(value: &str, fallback: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(fallback)
        .chars()
        .take(220)
        .collect()
}

fn format_security_writable_artifact_evidence(artifact: &SecurityWritableArtifact) -> String {
    format!(
        "{} mode={} size={} modified_age_secs={}",
        artifact.path,
        artifact.mode,
        artifact.size_bytes,
        artifact
            .modified_age_secs
            .map(|age| age.to_string())
            .unwrap_or_else(|| "-".to_string())
    )
}

const SECURITY_MINER_NAMES: &[&str] = &[
    "xmrig",
    "minerd",
    "cpuminer",
    "kinsing",
    "kdevtmpfsi",
    "kthrotlds",
    "watchbog",
    "cryptonight",
];

const SECURITY_MINING_PORTS: &[&str] = &[
    "3333", "3334", "4444", "5555", "7777", "8888", "14444", "14433",
];

const SECURITY_SENSITIVE_PUBLIC_PORTS: &[&str] = &[
    "2375", "2376", "3306", "5432", "6379", "9200", "9300", "11211", "27017", "5900", "3389",
    "5601", "5672", "15672", "8086", "9092",
];

const SECURITY_PROXY_TOR_PORTS: &[&str] = &["9050", "9051", "9150", "1080", "1081", "3128", "8118"];

const SECURITY_PROXY_TUNNEL_PROCESS_NAMES: &[&str] = &[
    "tor",
    "chisel",
    "gost",
    "ngrok",
    "v2ray",
    "xray",
    "sing-box",
    "ss-local",
    "ssserver",
    "shadowsocks",
];

const SECURITY_INTERPRETER_NAMES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "php", "node",
];

const SECURITY_SUSPICIOUS_PATH_PREFIXES: &[&str] =
    &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];

pub(crate) fn collect_login_accounts() -> serde_json::Value {
    let passwd = read_bounded_login_input("/etc/passwd");
    let group = read_bounded_login_input("/etc/group");
    let parsed = parse_login_accounts_bounded(&passwd, &group);
    let mut users = parsed.users;
    let authorized_keys_scan = enrich_authorized_keys(&mut users);
    build_login_accounts_report_from_users(users, parsed.stats, authorized_keys_scan)
}

#[cfg(test)]
fn build_login_accounts_report(passwd: &str, group: &str) -> serde_json::Value {
    let passwd = bounded_login_input_for_text(passwd);
    let group = bounded_login_input_for_text(group);
    let parsed = parse_login_accounts_bounded(&passwd, &group);
    let authorized_keys_scan = SecurityAuthorizedKeysScanStats {
        users_seen: parsed.users.len(),
        truncated_user_count: parsed.users.len(),
        ..Default::default()
    };
    build_login_accounts_report_from_users(parsed.users, parsed.stats, authorized_keys_scan)
}

fn build_login_accounts_report_from_users(
    users: Vec<serde_json::Value>,
    login_scan: SecurityLoginAccountsScanStats,
    authorized_keys_scan: SecurityAuthorizedKeysScanStats,
) -> serde_json::Value {
    let authorized_key_count_exact =
        authorized_keys_scan.key_count_is_exact() && !login_scan.users_truncated();
    let usernames: Vec<serde_json::Value> = users
        .iter()
        .filter_map(|u| u.get("username").cloned())
        .collect();
    let admin_usernames: Vec<serde_json::Value> = users
        .iter()
        .filter(|u| u.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false))
        .filter_map(|u| u.get("username").cloned())
        .collect();

    serde_json::json!({
        "schema_version": 2,
        "count": users.len(),
        "count_semantics": "emitted_sample",
        "admin_count": admin_usernames.len(),
        "usernames": usernames,
        "admin_usernames": admin_usernames,
        "users": users,
        "authorized_keys_scan": {
            "users_seen": authorized_keys_scan.users_seen,
            "users_scanned": authorized_keys_scan.users_scanned,
            "files_scanned": authorized_keys_scan.files_scanned,
            "bytes_read": authorized_keys_scan.bytes_read,
            "lines_scanned": authorized_keys_scan.lines_scanned,
            "retained_key_count": authorized_keys_scan.retained_key_count,
            "retained_key_json_bytes": authorized_keys_scan.retained_key_json_bytes,
            "key_count_lower_bound": authorized_keys_scan.retained_key_count,
            "key_count_exact": authorized_key_count_exact,
            "key_count_semantics": if authorized_key_count_exact { "exact" } else { "lower_bound" },
            "inventory_scope": "emitted_login_users",
            "truncated_user_count": authorized_keys_scan.truncated_user_count,
            "truncated_file_count": authorized_keys_scan.truncated_file_count,
            "truncated_line_count": authorized_keys_scan.truncated_line_count,
            "unavailable_file_count": authorized_keys_scan.unavailable_file_count,
            "timed_out_file_count": authorized_keys_scan.timed_out_file_count,
            "line_budget_exhausted_user_count": authorized_keys_scan.line_budget_exhausted_user_count,
            "key_budget_exhausted_user_count": authorized_keys_scan.key_budget_exhausted_user_count,
            "output_budget_exhausted_user_count": authorized_keys_scan.output_budget_exhausted_user_count,
            "limits": {
                "max_users": SECURITY_AUTHORIZED_KEYS_MAX_USERS,
                "max_bytes_per_file": SECURITY_AUTHORIZED_KEYS_MAX_BYTES_PER_FILE,
                "max_total_bytes": SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_BYTES,
                "max_line_bytes": SECURITY_AUTHORIZED_KEYS_MAX_LINE_BYTES,
                "max_lines_per_user": SECURITY_AUTHORIZED_KEYS_MAX_LINES_PER_USER,
                "max_total_lines": SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_LINES,
                "max_keys_per_user": SECURITY_AUTHORIZED_KEYS_MAX_KEYS_PER_USER,
                "max_total_keys": SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_KEYS,
                "max_comment_chars": SECURITY_AUTHORIZED_KEY_COMMENT_MAX_CHARS,
                "max_total_retained_key_json_bytes": SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_RETAINED_JSON_BYTES,
            },
        },
        "account_scan": {
            "users_seen": login_scan.users_seen,
            "users_emitted": login_scan.users_emitted,
            "users_omitted": login_scan.users_seen.saturating_sub(login_scan.users_emitted),
            "users_seen_exact": login_scan.users_seen_is_exact(),
            "users_truncated": login_scan.users_truncated(),
            "user_records_truncated": login_scan.user_records_truncated,
            "groups_seen": login_scan.groups_seen,
            "groups_emitted": login_scan.groups_emitted,
            "groups_omitted": login_scan.groups_seen.saturating_sub(login_scan.groups_emitted),
            "groups_seen_exact": login_scan.groups_seen_is_exact(),
            "groups_truncated": login_scan.groups_truncated(),
            "group_records_truncated": login_scan.group_records_truncated,
            "group_members_truncated": login_scan.group_members_truncated,
            "user_group_memberships_truncated": login_scan.user_group_memberships_truncated,
            "passwd": {
                "bytes_read": login_scan.passwd_bytes_read,
                "bytes_retained": login_scan.passwd_bytes_retained,
                "input_truncated": login_scan.passwd_input_truncated,
                "unavailable": login_scan.passwd_unavailable,
                "lines_seen": login_scan.passwd_lines_seen,
                "line_budget_exhausted": login_scan.passwd_line_budget_exhausted,
            },
            "group": {
                "bytes_read": login_scan.group_bytes_read,
                "bytes_retained": login_scan.group_bytes_retained,
                "input_truncated": login_scan.group_input_truncated,
                "unavailable": login_scan.group_unavailable,
                "lines_seen": login_scan.group_lines_seen,
                "line_budget_exhausted": login_scan.group_line_budget_exhausted,
            },
            "limits": {
                "max_retained_input_bytes_per_file": SECURITY_LOGIN_DATABASE_MAX_BYTES,
                "max_bytes_read_per_file": SECURITY_LOGIN_DATABASE_MAX_BYTES + 1,
                "max_lines_per_file": SECURITY_LOGIN_DATABASE_MAX_LINES,
                "max_users": SECURITY_LOGIN_USERS_MAX,
                "max_groups": SECURITY_LOGIN_GROUPS_MAX,
                "max_group_members_per_group": SECURITY_LOGIN_GROUP_MEMBERS_PER_GROUP_MAX,
                "max_total_group_members": SECURITY_LOGIN_GROUP_MEMBERS_TOTAL_MAX,
                "max_groups_per_user": SECURITY_LOGIN_GROUPS_PER_USER_MAX,
            },
        },
    })
}

fn read_bounded_login_input(path: &str) -> SecurityBoundedLoginInput {
    use std::io::Read;

    let Ok(file) = std::fs::File::open(path) else {
        return SecurityBoundedLoginInput {
            unavailable: true,
            ..Default::default()
        };
    };
    let mut bytes = Vec::with_capacity(SECURITY_LOGIN_DATABASE_MAX_BYTES + 1);
    if file
        .take((SECURITY_LOGIN_DATABASE_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return SecurityBoundedLoginInput {
            unavailable: true,
            ..Default::default()
        };
    }
    let bytes_read = bytes.len();
    let truncated = bytes.len() > SECURITY_LOGIN_DATABASE_MAX_BYTES;
    bytes.truncate(SECURITY_LOGIN_DATABASE_MAX_BYTES);
    if truncated {
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        bytes.truncate(complete_len);
    }
    SecurityBoundedLoginInput {
        content: String::from_utf8_lossy(&bytes).into_owned(),
        bytes_read,
        bytes_retained: bytes.len(),
        truncated,
        unavailable: false,
    }
}

#[cfg(test)]
fn bounded_login_input_for_text(value: &str) -> SecurityBoundedLoginInput {
    let mut bytes = value.as_bytes().to_vec();
    let truncated = bytes.len() > SECURITY_LOGIN_DATABASE_MAX_BYTES;
    let bytes_read = bytes.len().min(SECURITY_LOGIN_DATABASE_MAX_BYTES + 1);
    bytes.truncate(SECURITY_LOGIN_DATABASE_MAX_BYTES);
    if truncated {
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        bytes.truncate(complete_len);
    }
    SecurityBoundedLoginInput {
        content: String::from_utf8_lossy(&bytes).into_owned(),
        bytes_read,
        bytes_retained: bytes.len(),
        truncated,
        unavailable: false,
    }
}

#[derive(Debug)]
struct SecurityParsedLoginAccounts {
    users: Vec<serde_json::Value>,
    stats: SecurityLoginAccountsScanStats,
}

#[cfg(test)]
fn parse_login_accounts(passwd: &str, group: &str) -> Vec<serde_json::Value> {
    let passwd = bounded_login_input_for_text(passwd);
    let group = bounded_login_input_for_text(group);
    parse_login_accounts_bounded(&passwd, &group).users
}

fn parse_login_accounts_bounded(
    passwd: &SecurityBoundedLoginInput,
    group: &SecurityBoundedLoginInput,
) -> SecurityParsedLoginAccounts {
    let mut stats = SecurityLoginAccountsScanStats {
        passwd_bytes_read: passwd.bytes_read,
        passwd_bytes_retained: passwd.bytes_retained,
        passwd_input_truncated: passwd.truncated,
        passwd_unavailable: passwd.unavailable,
        group_bytes_read: group.bytes_read,
        group_bytes_retained: group.bytes_retained,
        group_input_truncated: group.truncated,
        group_unavailable: group.unavailable,
        ..Default::default()
    };
    let group_index = parse_group_memberships_bounded(group, &mut stats);
    let mut users = Vec::new();

    for line in passwd.content.lines() {
        if stats.passwd_lines_seen >= SECURITY_LOGIN_DATABASE_MAX_LINES {
            stats.passwd_line_budget_exhausted = true;
            break;
        }
        stats.passwd_lines_seen += 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.splitn(7, ':');
        let Some(username_raw) = fields.next() else {
            continue;
        };
        let _password = fields.next();
        let Some(uid_raw) = fields.next() else {
            continue;
        };
        let Some(gid_raw) = fields.next() else {
            continue;
        };
        let Some(gecos_raw) = fields.next() else {
            continue;
        };
        let Some(home_dir_raw) = fields.next() else {
            continue;
        };
        let Some(shell_raw) = fields.next() else {
            continue;
        };

        let username_raw = username_raw.trim();
        let uid = uid_raw.trim().parse::<u32>().unwrap_or(u32::MAX);
        let gid = gid_raw.trim().parse::<u32>().unwrap_or(u32::MAX);
        let shell_raw = shell_raw.trim();
        let login_enabled = is_login_shell(shell_raw);

        if username_raw.is_empty() || !login_enabled || !(uid == 0 || uid >= 1000) {
            continue;
        }
        stats.users_seen += 1;
        if users.len() >= SECURITY_LOGIN_USERS_MAX {
            stats.user_records_truncated += 1;
            continue;
        }

        let username = bounded_login_field(username_raw, SECURITY_LOGIN_USERNAME_MAX_CHARS);
        let gecos = bounded_login_field(gecos_raw.trim(), SECURITY_LOGIN_GECOS_MAX_CHARS);
        let home_dir = bounded_login_field(home_dir_raw.trim(), SECURITY_LOGIN_PATH_MAX_CHARS);
        let shell = bounded_login_field(shell_raw, SECURITY_LOGIN_PATH_MAX_CHARS);

        let matching_groups = group_index
            .iter()
            .filter_map(|g| {
                if g.gid == gid || g.members.iter().any(|m| m == &username) {
                    Some(g.name.clone())
                } else {
                    None
                }
            })
            .take(SECURITY_LOGIN_GROUPS_PER_USER_MAX + 1)
            .collect::<Vec<_>>();
        let group_memberships_truncated =
            matching_groups.len() > SECURITY_LOGIN_GROUPS_PER_USER_MAX;
        stats.user_group_memberships_truncated += usize::from(group_memberships_truncated);
        let mut groups = matching_groups
            .into_iter()
            .take(SECURITY_LOGIN_GROUPS_PER_USER_MAX)
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();

        let is_admin = uid == 0
            || groups
                .iter()
                .any(|g| matches!(g.as_str(), "sudo" | "wheel" | "admin"));

        users.push(serde_json::json!({
            "username": username,
            "uid": uid,
            "gid": gid,
            "gecos": gecos,
            "home_dir": home_dir,
            "shell": shell,
            "login_enabled": login_enabled,
            "groups": groups,
            "is_admin": is_admin,
            "authorized_keys": [],
            "authorized_key_count": 0,
            "authorized_key_sample_count": 0,
            "authorized_key_count_lower_bound": 0,
            "authorized_key_count_exact": false,
            "authorized_key_count_semantics": "lower_bound",
            "authorized_key_count_legacy_semantics": "lower_bound",
            "authorized_keys_scan_status": "not_scanned",
            "authorized_keys_truncated": true,
            // Home directories can be backed by autofs/NFS/FUSE. Filesystem
            // checks are populated by the killable authorized_keys worker;
            // never touch an arbitrary home path on the collector thread.
            "has_home": false,
            "has_home_checked": false,
            "ssh_access": build_unchecked_ssh_access_health(&username, uid, gid, std::path::Path::new(&home_dir), "not_scanned"),
        }));
    }

    stats.users_emitted = users.len();
    SecurityParsedLoginAccounts { users, stats }
}

#[cfg(test)]
fn build_ssh_access_health(
    username: &str,
    uid: u32,
    gid: u32,
    home_dir: &Path,
) -> serde_json::Value {
    let authorized_keys = home_dir.join(".ssh/authorized_keys");
    let scan = read_authorized_keys_scan_with_timeout(
        &authorized_keys,
        0,
        SECURITY_AUTHORIZED_KEYS_FILE_DEADLINE,
        Duration::ZERO,
    );
    scan.snapshot
        .as_ref()
        .map(|snapshot| {
            build_ssh_access_health_from_snapshot(username, uid, gid, home_dir, snapshot)
        })
        .unwrap_or_else(|| {
            build_unchecked_ssh_access_health(username, uid, gid, home_dir, "unavailable")
        })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum SecurityPathKind {
    #[default]
    Missing,
    File,
    Directory,
    Symlink,
    Other,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default)]
struct SecurityPathMetadata {
    kind: SecurityPathKind,
    mode: u32,
    uid: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct SecuritySshPathSnapshot {
    home: SecurityPathMetadata,
    ssh_dir: SecurityPathMetadata,
    authorized_keys: SecurityPathMetadata,
}

fn build_unchecked_ssh_access_health(
    username: &str,
    uid: u32,
    gid: u32,
    home_dir: &Path,
    status: &str,
) -> serde_json::Value {
    let ssh_dir = home_dir.join(".ssh");
    let authorized_keys = ssh_dir.join("authorized_keys");
    serde_json::json!({
        "checked": false,
        "check_status": status,
        "username": username,
        "uid": uid,
        "gid": gid,
        "home_dir": home_dir.display().to_string(),
        "ssh_dir_path": ssh_dir.display().to_string(),
        "authorized_keys_path": authorized_keys.display().to_string(),
        "authorized_keys_exists": false,
        // Preserve the legacy boolean contract without inventing a repairable
        // finding when a bounded check was unavailable.
        "strict_modes_path_ok": true,
        "issues": [],
    })
}

fn build_ssh_access_health_from_snapshot(
    username: &str,
    uid: u32,
    gid: u32,
    home_dir: &Path,
    snapshot: &SecuritySshPathSnapshot,
) -> serde_json::Value {
    let ssh_dir = home_dir.join(".ssh");
    let authorized_keys = ssh_dir.join("authorized_keys");
    let mut issues = Vec::new();
    let check_complete = ![
        snapshot.home.kind,
        snapshot.ssh_dir.kind,
        snapshot.authorized_keys.kind,
    ]
    .contains(&SecurityPathKind::Unavailable);

    if snapshot.home.kind == SecurityPathKind::Missing {
        issues.push("home_missing".to_string());
    } else if snapshot.home.kind != SecurityPathKind::Directory
        && snapshot.home.kind != SecurityPathKind::Unavailable
    {
        issues.push("home_not_directory".to_string());
    }
    if matches!(
        snapshot.home.kind,
        SecurityPathKind::Directory | SecurityPathKind::File
    ) {
        if snapshot.home.mode & 0o022 != 0 {
            issues.push("home_group_or_other_writable".to_string());
        }
        if snapshot.home.uid != 0 && snapshot.home.uid != uid {
            issues.push("home_owner_not_user_or_root".to_string());
        }
    }

    if snapshot.ssh_dir.kind != SecurityPathKind::Missing
        && snapshot.ssh_dir.kind != SecurityPathKind::Unavailable
    {
        if snapshot.ssh_dir.kind != SecurityPathKind::Directory {
            issues.push("ssh_dir_not_directory".to_string());
        }
        if snapshot.ssh_dir.mode & 0o022 != 0 {
            issues.push("ssh_dir_group_or_other_writable".to_string());
        }
        if snapshot.ssh_dir.uid != 0 && snapshot.ssh_dir.uid != uid {
            issues.push("ssh_dir_owner_not_user_or_root".to_string());
        }
    } else if snapshot.ssh_dir.kind == SecurityPathKind::Missing
        && !matches!(
            snapshot.authorized_keys.kind,
            SecurityPathKind::Missing | SecurityPathKind::Unavailable
        )
    {
        issues.push("ssh_dir_missing".to_string());
    }

    if !matches!(
        snapshot.authorized_keys.kind,
        SecurityPathKind::Missing | SecurityPathKind::Unavailable
    ) {
        if snapshot.authorized_keys.kind == SecurityPathKind::Symlink {
            issues.push("authorized_keys_symlink".to_string());
        }
        if snapshot.authorized_keys.kind != SecurityPathKind::File {
            issues.push("authorized_keys_not_file".to_string());
        }
        if snapshot.authorized_keys.mode & 0o022 != 0 {
            issues.push("authorized_keys_group_or_other_writable".to_string());
        }
        if snapshot.authorized_keys.uid != 0 && snapshot.authorized_keys.uid != uid {
            issues.push("authorized_keys_owner_not_user_or_root".to_string());
        }
    }

    let mode = |metadata: SecurityPathMetadata| {
        (!matches!(
            metadata.kind,
            SecurityPathKind::Missing | SecurityPathKind::Unavailable
        ))
        .then(|| format!("{:04o}", metadata.mode & 0o7777))
    };
    let owner = |metadata: SecurityPathMetadata| {
        (!matches!(
            metadata.kind,
            SecurityPathKind::Missing | SecurityPathKind::Unavailable
        ))
        .then_some(metadata.uid)
    };
    serde_json::json!({
        "checked": check_complete,
        "check_status": if check_complete { "complete" } else { "unavailable" },
        "username": username,
        "uid": uid,
        "gid": gid,
        "home_dir": home_dir.display().to_string(),
        "ssh_dir_path": ssh_dir.display().to_string(),
        "authorized_keys_path": authorized_keys.display().to_string(),
        "authorized_keys_exists": matches!(snapshot.authorized_keys.kind, SecurityPathKind::File | SecurityPathKind::Directory | SecurityPathKind::Symlink | SecurityPathKind::Other),
        "home_mode": mode(snapshot.home),
        "home_owner_uid": owner(snapshot.home),
        "ssh_dir_mode": mode(snapshot.ssh_dir),
        "ssh_dir_owner_uid": owner(snapshot.ssh_dir),
        "authorized_keys_mode": mode(snapshot.authorized_keys),
        "authorized_keys_owner_uid": owner(snapshot.authorized_keys),
        "strict_modes_path_ok": issues.is_empty(),
        "issues": issues,
    })
}

fn enrich_authorized_keys(users: &mut [serde_json::Value]) -> SecurityAuthorizedKeysScanStats {
    let scan_deadline = std::time::Instant::now() + SECURITY_AUTHORIZED_KEYS_SCAN_DEADLINE;
    let mut stats = SecurityAuthorizedKeysScanStats {
        users_seen: users.len(),
        truncated_user_count: users
            .len()
            .saturating_sub(SECURITY_AUTHORIZED_KEYS_MAX_USERS),
        ..Default::default()
    };
    let mut total_key_count = 0usize;

    for (index, user) in users.iter_mut().enumerate() {
        if index >= SECURITY_AUTHORIZED_KEYS_MAX_USERS {
            set_authorized_keys_user_result(
                user,
                Vec::new(),
                "not_scanned_user_limit",
                false,
                true,
                0,
                false,
                false,
                false,
            );
            continue;
        }
        stats.users_scanned += 1;
        let Some(home_dir) = user
            .get("home_dir")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
        else {
            stats.unavailable_file_count += 1;
            set_authorized_keys_user_result(
                user,
                Vec::new(),
                "unavailable",
                false,
                true,
                0,
                false,
                false,
                false,
            );
            continue;
        };
        let username = user
            .get("username")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
            .to_string();
        let uid = user
            .get("uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(u32::MAX);
        let gid = user
            .get("gid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(u32::MAX);
        let path = std::path::Path::new(&home_dir).join(".ssh/authorized_keys");
        let key_limit = SECURITY_AUTHORIZED_KEYS_MAX_KEYS_PER_USER
            .min(SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_KEYS.saturating_sub(total_key_count));
        let line_limit = SECURITY_AUTHORIZED_KEYS_MAX_LINES_PER_USER
            .min(SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_LINES.saturating_sub(stats.lines_scanned));
        let output_byte_limit = SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_RETAINED_JSON_BYTES
            .saturating_sub(stats.retained_key_json_bytes);
        let remaining_total_bytes = if key_limit == 0 || line_limit == 0 || output_byte_limit == 0 {
            0
        } else {
            SECURITY_AUTHORIZED_KEYS_MAX_TOTAL_BYTES.saturating_sub(stats.bytes_read)
        };
        let remaining_time = scan_deadline.saturating_duration_since(std::time::Instant::now());
        let per_file_timeout = SECURITY_AUTHORIZED_KEYS_FILE_DEADLINE.min(remaining_time);
        let isolated = read_authorized_keys_scan_with_timeout(
            &path,
            remaining_total_bytes,
            per_file_timeout,
            Duration::ZERO,
        );
        let unavailable_health_status =
            if matches!(&isolated.outcome, Err(SecurityBoundedFileError::TimedOut)) {
                "unavailable_timeout"
            } else {
                "unavailable"
            };
        if let Some(snapshot) = isolated.snapshot.as_ref() {
            if let Some(object) = user.as_object_mut() {
                object.insert(
                    "has_home".to_string(),
                    serde_json::json!(snapshot.home.kind == SecurityPathKind::Directory),
                );
                object.insert("has_home_checked".to_string(), serde_json::json!(true));
                object.insert(
                    "ssh_access".to_string(),
                    build_ssh_access_health_from_snapshot(
                        &username,
                        uid,
                        gid,
                        std::path::Path::new(&home_dir),
                        snapshot,
                    ),
                );
            }
        } else if let Some(object) = user.as_object_mut() {
            object.insert(
                "ssh_access".to_string(),
                build_unchecked_ssh_access_health(
                    &username,
                    uid,
                    gid,
                    std::path::Path::new(&home_dir),
                    unavailable_health_status,
                ),
            );
        }
        let file = match isolated.outcome {
            Ok(file) => file,
            Err(SecurityBoundedFileError::Missing) => {
                set_authorized_keys_user_result(
                    user,
                    Vec::new(),
                    "missing",
                    true,
                    false,
                    0,
                    false,
                    false,
                    false,
                );
                continue;
            }
            Err(SecurityBoundedFileError::UnsafeOrUnreadable) => {
                stats.unavailable_file_count += 1;
                set_authorized_keys_user_result(
                    user,
                    Vec::new(),
                    "unavailable",
                    false,
                    true,
                    0,
                    false,
                    false,
                    false,
                );
                continue;
            }
            Err(SecurityBoundedFileError::TimedOut) => {
                stats.unavailable_file_count += 1;
                stats.timed_out_file_count += 1;
                set_authorized_keys_user_result(
                    user,
                    Vec::new(),
                    "unavailable_timeout",
                    false,
                    true,
                    0,
                    false,
                    false,
                    false,
                );
                continue;
            }
        };
        stats.files_scanned += 1;
        stats.bytes_read += file.bytes_read;
        stats.truncated_file_count += usize::from(file.truncated);

        let mut parsed = parse_authorized_keys_bounded(
            &file.bytes,
            file.truncated,
            key_limit,
            line_limit,
            output_byte_limit,
        );
        if file.truncated && file.bytes.is_empty() {
            parsed.key_budget_exhausted |= key_limit == 0;
            parsed.line_budget_exhausted |= line_limit == 0;
            parsed.output_budget_exhausted |= output_byte_limit == 0;
        }
        stats.lines_scanned += parsed.scanned_line_count;
        stats.truncated_line_count += parsed.truncated_line_count;
        stats.line_budget_exhausted_user_count += usize::from(parsed.line_budget_exhausted);
        stats.key_budget_exhausted_user_count += usize::from(parsed.key_budget_exhausted);
        stats.output_budget_exhausted_user_count += usize::from(parsed.output_budget_exhausted);
        stats.retained_key_json_bytes += parsed.retained_json_bytes;

        let keys = parsed.keys;
        let count = keys.len();
        total_key_count += count;
        stats.retained_key_count += count;
        let count_exact = !file.truncated
            && parsed.truncated_line_count == 0
            && !parsed.line_budget_exhausted
            && !parsed.key_budget_exhausted
            && !parsed.output_budget_exhausted;
        if let Some(obj) = user.as_object_mut() {
            obj.insert("authorized_keys_path".to_string(), serde_json::json!(path));
        }
        set_authorized_keys_user_result(
            user,
            keys,
            if count_exact { "complete" } else { "truncated" },
            count_exact,
            !count_exact,
            parsed.truncated_line_count,
            parsed.line_budget_exhausted,
            parsed.key_budget_exhausted,
            parsed.output_budget_exhausted,
        );
    }

    stats
}

#[allow(clippy::too_many_arguments)]
fn set_authorized_keys_user_result(
    user: &mut serde_json::Value,
    keys: Vec<serde_json::Value>,
    status: &'static str,
    count_exact: bool,
    truncated: bool,
    truncated_line_count: usize,
    line_budget_exhausted: bool,
    key_budget_exhausted: bool,
    output_budget_exhausted: bool,
) {
    let count = keys.len();
    let Some(obj) = user.as_object_mut() else {
        return;
    };
    // Keep the legacy count as the retained sample for compatibility. The
    // adjacent fields make it explicit whether that value is exact or merely a
    // lower bound, so capped scans cannot masquerade as complete inventories.
    obj.insert("authorized_key_count".to_string(), serde_json::json!(count));
    obj.insert(
        "authorized_key_sample_count".to_string(),
        serde_json::json!(count),
    );
    obj.insert(
        "authorized_key_count_lower_bound".to_string(),
        serde_json::json!(count),
    );
    obj.insert(
        "authorized_key_count_exact".to_string(),
        serde_json::json!(count_exact),
    );
    obj.insert(
        "authorized_key_count_semantics".to_string(),
        serde_json::json!(if count_exact { "exact" } else { "lower_bound" }),
    );
    obj.insert(
        "authorized_key_count_legacy_semantics".to_string(),
        serde_json::json!(if count_exact { "exact" } else { "lower_bound" }),
    );
    obj.insert(
        "authorized_keys_scan_status".to_string(),
        serde_json::json!(status),
    );
    obj.insert(
        "authorized_keys_truncated".to_string(),
        serde_json::json!(truncated),
    );
    obj.insert(
        "authorized_key_line_truncated_count".to_string(),
        serde_json::json!(truncated_line_count),
    );
    obj.insert(
        "authorized_key_line_budget_exhausted".to_string(),
        serde_json::json!(line_budget_exhausted),
    );
    obj.insert(
        "authorized_key_budget_exhausted".to_string(),
        serde_json::json!(key_budget_exhausted),
    );
    obj.insert(
        "authorized_key_output_budget_exhausted".to_string(),
        serde_json::json!(output_budget_exhausted),
    );
    obj.insert("authorized_keys".to_string(), serde_json::json!(keys));
}

#[derive(Debug)]
struct SecurityAuthorizedKeysFileRead {
    bytes: Vec<u8>,
    bytes_read: usize,
    truncated: bool,
}

#[derive(Debug)]
struct SecurityAuthorizedKeysIsolatedScan {
    outcome: Result<SecurityAuthorizedKeysFileRead, SecurityBoundedFileError>,
    snapshot: Option<SecuritySshPathSnapshot>,
}

#[cfg(test)]
fn read_authorized_keys_file(
    path: &std::path::Path,
    remaining_total_bytes: usize,
) -> Result<SecurityAuthorizedKeysFileRead, SecurityBoundedFileError> {
    read_authorized_keys_scan_with_timeout(
        path,
        remaining_total_bytes,
        SECURITY_AUTHORIZED_KEYS_FILE_DEADLINE,
        Duration::ZERO,
    )
    .outcome
}

fn read_authorized_keys_scan_with_timeout(
    path: &std::path::Path,
    remaining_total_bytes: usize,
    timeout: Duration,
    child_delay: Duration,
) -> SecurityAuthorizedKeysIsolatedScan {
    if timeout.is_zero() {
        return SecurityAuthorizedKeysIsolatedScan {
            outcome: Err(SecurityBoundedFileError::TimedOut),
            snapshot: None,
        };
    }

    #[cfg(target_os = "linux")]
    {
        read_authorized_keys_scan_linux(path, remaining_total_bytes, timeout, child_delay)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (timeout, child_delay);
        read_authorized_keys_scan_fallback(path, remaining_total_bytes)
    }
}

#[cfg(not(target_os = "linux"))]
fn read_authorized_keys_scan_fallback(
    path: &std::path::Path,
    remaining_total_bytes: usize,
) -> SecurityAuthorizedKeysIsolatedScan {
    use std::io::Read;

    fn path_metadata(path: &Path) -> SecurityPathMetadata {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return SecurityPathMetadata::default();
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_file() {
            SecurityPathKind::File
        } else if file_type.is_dir() {
            SecurityPathKind::Directory
        } else if file_type.is_symlink() {
            SecurityPathKind::Symlink
        } else {
            SecurityPathKind::Other
        };
        SecurityPathMetadata {
            kind,
            mode: 0,
            uid: 0,
        }
    }

    let ssh_dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let home = ssh_dir.parent().unwrap_or_else(|| Path::new("/"));
    let snapshot = SecuritySshPathSnapshot {
        home: path_metadata(home),
        ssh_dir: path_metadata(ssh_dir),
        authorized_keys: path_metadata(path),
    };
    if snapshot.authorized_keys.kind == SecurityPathKind::Missing {
        return SecurityAuthorizedKeysIsolatedScan {
            outcome: Err(SecurityBoundedFileError::Missing),
            snapshot: Some(snapshot),
        };
    }
    let outcome = (|| {
        let file = open_security_regular_file_nofollow(path)?;
        let metadata_len = file
            .metadata()
            .map_err(|_| SecurityBoundedFileError::UnsafeOrUnreadable)?
            .len();
        let content_limit = SECURITY_AUTHORIZED_KEYS_MAX_BYTES_PER_FILE
            .min(remaining_total_bytes.saturating_sub(1));
        let read_limit = content_limit.saturating_add(1).min(remaining_total_bytes);
        let mut bytes = Vec::with_capacity(read_limit);
        file.take(read_limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SecurityBoundedFileError::UnsafeOrUnreadable)?;
        let bytes_read = bytes.len();
        let truncated = bytes.len() > content_limit || metadata_len > content_limit as u64;
        bytes.truncate(content_limit);
        Ok(SecurityAuthorizedKeysFileRead {
            bytes,
            bytes_read,
            truncated,
        })
    })();
    SecurityAuthorizedKeysIsolatedScan {
        outcome,
        snapshot: Some(snapshot),
    }
}

#[cfg(target_os = "linux")]
fn reap_security_child(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: `pid` is a direct child returned by fork and `status` points
        // to initialized writable storage. Blocking is safe only after the
        // worker pipe reached EOF or the whole private process group was
        // killed, so the supervisor cannot remain stuck behind filesystem IO.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return;
        }
        if waited < 0 {
            // SAFETY: Linux exposes thread-local errno through this pointer.
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn read_authorized_keys_scan_linux(
    path: &std::path::Path,
    remaining_total_bytes: usize,
    timeout: Duration,
    child_delay: Duration,
) -> SecurityAuthorizedKeysIsolatedScan {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::time::Instant;

    const HEADER_LEN: usize = 43;
    const FOOTER: u8 = 0x7e;

    fn failure(error: SecurityBoundedFileError) -> SecurityAuthorizedKeysIsolatedScan {
        SecurityAuthorizedKeysIsolatedScan {
            outcome: Err(error),
            snapshot: None,
        }
    }

    fn decode_path_metadata(record: &[u8]) -> Option<SecurityPathMetadata> {
        if record.len() != 10 {
            return None;
        }
        let kind = match record[0] {
            0 => SecurityPathKind::Missing,
            1 => SecurityPathKind::File,
            2 => SecurityPathKind::Directory,
            3 => SecurityPathKind::Symlink,
            4 => SecurityPathKind::Other,
            5 => SecurityPathKind::Unavailable,
            _ => return None,
        };
        let mode = u32::from_le_bytes(record[2..6].try_into().ok()?);
        let uid = u32::from_le_bytes(record[6..10].try_into().ok()?);
        Some(SecurityPathMetadata { kind, mode, uid })
    }

    fn raw_write_all(fd: RawFd, bytes: &[u8]) -> bool {
        let mut offset = 0usize;
        while offset < bytes.len() {
            // SAFETY: the byte slice is valid for the requested range and the
            // descriptor is the worker's private pipe write end.
            let written =
                unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
            if written > 0 {
                offset += written as usize;
                continue;
            }
            // SAFETY: Linux exposes thread-local errno through this pointer.
            let errno = unsafe { *libc::__errno_location() };
            if written < 0 && errno == libc::EINTR {
                continue;
            }
            return false;
        }
        true
    }

    fn raw_path_metadata(path: &CString) -> SecurityPathMetadata {
        // SAFETY: `libc::stat` is plain old data and zero is a valid initial
        // representation before lstat fills every field.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: CString guarantees a NUL-terminated path and `stat` is a
        // valid out pointer for the duration of the call.
        if unsafe { libc::lstat(path.as_ptr(), &mut stat) } != 0 {
            // SAFETY: Linux exposes thread-local errno through this pointer.
            let errno = unsafe { *libc::__errno_location() };
            return SecurityPathMetadata {
                kind: if errno == libc::ENOENT || errno == libc::ENOTDIR {
                    SecurityPathKind::Missing
                } else {
                    SecurityPathKind::Unavailable
                },
                ..Default::default()
            };
        }
        let kind = match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => SecurityPathKind::File,
            libc::S_IFDIR => SecurityPathKind::Directory,
            libc::S_IFLNK => SecurityPathKind::Symlink,
            _ => SecurityPathKind::Other,
        };
        SecurityPathMetadata {
            kind,
            mode: stat.st_mode,
            uid: stat.st_uid,
        }
    }

    fn encode_path_metadata(target: &mut [u8], metadata: SecurityPathMetadata) {
        target[0] = match metadata.kind {
            SecurityPathKind::Missing => 0,
            SecurityPathKind::File => 1,
            SecurityPathKind::Directory => 2,
            SecurityPathKind::Symlink => 3,
            SecurityPathKind::Other => 4,
            SecurityPathKind::Unavailable => 5,
        };
        target[1] = 0;
        target[2..6].copy_from_slice(&metadata.mode.to_le_bytes());
        target[6..10].copy_from_slice(&metadata.uid.to_le_bytes());
    }

    fn worker(
        write_fd: RawFd,
        home: &CString,
        ssh_dir: &CString,
        path: &CString,
        read_limit: usize,
        child_delay: Duration,
    ) -> ! {
        if !child_delay.is_zero() {
            let request = libc::timespec {
                // The test-only delay must fit time_t on 32-bit musl too.
                tv_sec: child_delay.as_secs().min(i32::MAX as u64) as _,
                // subsec_nanos is below 1e9 and fits c_long on 32-bit ARM.
                tv_nsec: child_delay.subsec_nanos() as libc::c_long,
            };
            // SAFETY: both pointers follow nanosleep's contract; a signal may
            // shorten the test-only delay, which is harmless.
            unsafe { libc::nanosleep(&request, std::ptr::null_mut()) };
        }

        let home_metadata = raw_path_metadata(home);
        let ssh_metadata = raw_path_metadata(ssh_dir);
        let mut key_metadata = raw_path_metadata(path);
        let mut outcome = if key_metadata.kind == SecurityPathKind::Missing {
            1u8
        } else if key_metadata.kind == SecurityPathKind::File {
            0u8
        } else {
            2u8
        };
        let mut fd = -1;
        let mut metadata_len = 0u64;
        if outcome == 0 {
            // SAFETY: CString is NUL-terminated and flags prohibit following a
            // replacement symlink or blocking on a FIFO/device.
            fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                // SAFETY: Linux exposes thread-local errno through this pointer.
                let errno = unsafe { *libc::__errno_location() };
                outcome = if errno == libc::ENOENT || errno == libc::ENOTDIR {
                    1
                } else {
                    2
                };
            } else {
                // SAFETY: zeroed stat storage and an open descriptor satisfy
                // fstat's requirements.
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: `fd` is open and `stat` is a valid out pointer.
                if unsafe { libc::fstat(fd, &mut stat) } != 0
                    || stat.st_mode & libc::S_IFMT != libc::S_IFREG
                {
                    outcome = 2;
                } else {
                    metadata_len = stat.st_size.max(0) as u64;
                    key_metadata = SecurityPathMetadata {
                        kind: SecurityPathKind::File,
                        mode: stat.st_mode,
                        uid: stat.st_uid,
                    };
                }
            }
        }

        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(b"WMS2");
        header[4] = outcome;
        encode_path_metadata(&mut header[5..15], home_metadata);
        encode_path_metadata(&mut header[15..25], ssh_metadata);
        encode_path_metadata(&mut header[25..35], key_metadata);
        header[35..43].copy_from_slice(&metadata_len.to_le_bytes());
        if !raw_write_all(write_fd, &header) {
            // SAFETY: descriptors belong to this isolated worker.
            unsafe {
                if fd >= 0 {
                    libc::close(fd);
                }
                libc::_exit(2);
            }
        }

        if outcome == 0 {
            let mut remaining = read_limit;
            let mut buffer = [0u8; 16 * 1024];
            while remaining > 0 {
                // SAFETY: fd is an open regular file and buffer is writable.
                let read = unsafe {
                    libc::read(fd, buffer.as_mut_ptr().cast(), remaining.min(buffer.len()))
                };
                if read == 0 {
                    break;
                }
                if read < 0 {
                    // SAFETY: Linux exposes thread-local errno through this pointer.
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EINTR {
                        continue;
                    }
                    // No footer means the parent reports unavailable rather
                    // than treating a partial key inventory as complete.
                    // SAFETY: descriptors belong to this isolated worker.
                    unsafe {
                        libc::close(fd);
                        libc::_exit(3);
                    }
                }
                let read = read as usize;
                if !raw_write_all(write_fd, &buffer[..read]) {
                    // SAFETY: descriptors belong to this isolated worker.
                    unsafe {
                        libc::close(fd);
                        libc::_exit(4);
                    }
                }
                remaining -= read;
            }
        }
        if !raw_write_all(write_fd, &[FOOTER]) {
            // SAFETY: descriptors belong to this isolated worker.
            unsafe {
                if fd >= 0 {
                    libc::close(fd);
                }
                libc::_exit(5);
            }
        }
        // SAFETY: descriptors belong to this isolated worker and _exit avoids
        // running allocator-backed Rust destructors after fork.
        unsafe {
            if fd >= 0 {
                libc::close(fd);
            }
            libc::close(write_fd);
            libc::_exit(0);
        }
    }

    let content_limit =
        SECURITY_AUTHORIZED_KEYS_MAX_BYTES_PER_FILE.min(remaining_total_bytes.saturating_sub(1));
    let read_limit = content_limit.saturating_add(1).min(remaining_total_bytes);
    let Some(ssh_dir) = path.parent() else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Some(home) = ssh_dir.parent() else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Ok(ssh_c) = CString::new(ssh_dir.as_os_str().as_bytes()) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Ok(home_c) = CString::new(home.as_os_str().as_bytes()) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let mut pipe_fds = [-1; 2];
    // SAFETY: pipe_fds points to two writable integers.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    }
    // SAFETY: fork duplicates the current process. The child branch below
    // uses only async-signal-safe libc calls until _exit.
    let child = unsafe { libc::fork() };
    if child < 0 {
        // SAFETY: these descriptors were created successfully above.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    }
    if child == 0 {
        // SAFETY: the child owns both inherited descriptors.
        unsafe { libc::close(pipe_fds[0]) };
        // A private session gives the parent a process group it can kill even
        // if the filesystem worker is stuck in kernel or FUSE code.
        // SAFETY: the fork child is not a process-group leader.
        if unsafe { libc::setsid() } < 0 {
            // SAFETY: exit immediately without Rust destructors after fork.
            unsafe { libc::_exit(6) };
        }
        // SAFETY: second fork isolates the potentially blocked filesystem
        // worker while the direct child remains a reapable supervisor.
        let worker_pid = unsafe { libc::fork() };
        if worker_pid < 0 {
            // SAFETY: exit immediately without Rust destructors after fork.
            unsafe { libc::_exit(7) };
        }
        if worker_pid == 0 {
            worker(
                pipe_fds[1],
                &home_c,
                &ssh_c,
                &path_c,
                read_limit,
                child_delay,
            );
        }
        // The supervisor must close its copy so EOF reflects only the worker.
        // SAFETY: descriptor belongs to this child.
        unsafe { libc::close(pipe_fds[1]) };
        let mut status = 0;
        loop {
            // SAFETY: worker_pid is this supervisor's direct child.
            let waited = unsafe { libc::waitpid(worker_pid, &mut status, 0) };
            if waited == worker_pid {
                break;
            }
            // SAFETY: Linux exposes thread-local errno through this pointer.
            if waited < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                break;
            }
        }
        // SAFETY: exit immediately without Rust destructors after fork.
        unsafe { libc::_exit(0) };
    }

    // Parent: only retain the read side. The worker and supervisor are in the
    // process group whose id equals the direct child's pid.
    // SAFETY: descriptor belongs to the parent branch.
    unsafe { libc::close(pipe_fds[1]) };
    // SAFETY: ownership of this valid read descriptor transfers to File.
    let mut pipe = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
    let deadline = Instant::now() + timeout;
    let mut response = Vec::with_capacity(HEADER_LEN + read_limit + 1);
    let mut buffer = [0u8; 16 * 1024];
    let mut timed_out = false;
    let mut abort_child = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            break;
        }
        let wait = deadline.saturating_duration_since(now);
        let timeout_ms = wait.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd: pipe_fds[0],
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready == 0 {
            timed_out = true;
            break;
        }
        if ready < 0 {
            // SAFETY: Linux exposes thread-local errno through this pointer.
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            abort_child = true;
            break;
        }
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if response.len().saturating_add(read) > HEADER_LEN + read_limit + 1 {
                    abort_child = true;
                    break;
                }
                response.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                abort_child = true;
                break;
            }
        }
    }
    drop(pipe);
    if timed_out || abort_child {
        // SAFETY: negative pid targets the private session/process group;
        // direct pid is also killed to cover the tiny pre-setsid race.
        unsafe {
            libc::kill(-child, libc::SIGKILL);
            libc::kill(child, libc::SIGKILL);
        }
        reap_security_child(child);
        if abort_child {
            return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
        }
        return failure(SecurityBoundedFileError::TimedOut);
    }
    reap_security_child(child);

    if response.len() < HEADER_LEN + 1
        || &response[..4] != b"WMS2"
        || response.last() != Some(&FOOTER)
    {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    }
    let Some(home_metadata) = decode_path_metadata(&response[5..15]) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Some(ssh_metadata) = decode_path_metadata(&response[15..25]) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let Some(key_metadata) = decode_path_metadata(&response[25..35]) else {
        return failure(SecurityBoundedFileError::UnsafeOrUnreadable);
    };
    let metadata_len = u64::from_le_bytes(response[35..43].try_into().unwrap_or_default());
    let snapshot = SecuritySshPathSnapshot {
        home: home_metadata,
        ssh_dir: ssh_metadata,
        authorized_keys: key_metadata,
    };
    let outcome = match response[4] {
        0 => {
            let mut bytes = response[HEADER_LEN..response.len() - 1].to_vec();
            let bytes_read = bytes.len();
            let truncated = bytes.len() > content_limit || metadata_len > content_limit as u64;
            bytes.truncate(content_limit);
            Ok(SecurityAuthorizedKeysFileRead {
                bytes,
                bytes_read,
                truncated,
            })
        }
        1 => Err(SecurityBoundedFileError::Missing),
        2 => Err(SecurityBoundedFileError::UnsafeOrUnreadable),
        _ => Err(SecurityBoundedFileError::UnsafeOrUnreadable),
    };
    SecurityAuthorizedKeysIsolatedScan {
        outcome,
        snapshot: Some(snapshot),
    }
}

#[derive(Debug, Default)]
struct SecurityParsedAuthorizedKeys {
    keys: Vec<serde_json::Value>,
    retained_json_bytes: usize,
    scanned_line_count: usize,
    truncated_line_count: usize,
    line_budget_exhausted: bool,
    key_budget_exhausted: bool,
    output_budget_exhausted: bool,
}

fn parse_authorized_keys_bounded(
    content: &[u8],
    content_truncated: bool,
    key_limit: usize,
    line_limit: usize,
    output_byte_limit: usize,
) -> SecurityParsedAuthorizedKeys {
    let mut parsed = SecurityParsedAuthorizedKeys::default();
    let mut cursor = 0usize;

    while cursor < content.len() {
        if parsed.scanned_line_count >= line_limit {
            parsed.line_budget_exhausted = true;
            parsed.key_budget_exhausted |= parsed.keys.len() >= key_limit;
            break;
        }
        if parsed.keys.len() >= key_limit {
            parsed.key_budget_exhausted = true;
            break;
        }

        let remaining = &content[cursor..];
        let bounded_line = &remaining[..remaining
            .len()
            .min(SECURITY_AUTHORIZED_KEYS_MAX_LINE_BYTES + 1)];
        let newline_offset = bounded_line.iter().position(|byte| *byte == b'\n');
        let (line, next_cursor, complete) = match newline_offset {
            Some(offset) => (&remaining[..offset], cursor + offset + 1, true),
            None if remaining.len() <= SECURITY_AUTHORIZED_KEYS_MAX_LINE_BYTES => {
                (remaining, content.len(), !content_truncated)
            }
            None => {
                parsed.scanned_line_count += 1;
                parsed.truncated_line_count += 1;
                break;
            }
        };
        cursor = next_cursor;
        parsed.scanned_line_count += 1;

        if !complete {
            parsed.truncated_line_count += 1;
            break;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = String::from_utf8_lossy(line);
        let Some(key) = parse_authorized_key_line(&line) else {
            continue;
        };
        let serialized_len = serde_json::to_vec(&key)
            .map(|encoded| encoded.len())
            .unwrap_or(usize::MAX);
        if parsed
            .retained_json_bytes
            .checked_add(serialized_len)
            .is_none_or(|next| next > output_byte_limit)
        {
            parsed.output_budget_exhausted = true;
            break;
        }
        parsed.retained_json_bytes += serialized_len;
        parsed.keys.push(key);
    }

    parsed
}

#[cfg(test)]
fn parse_authorized_keys(content: &str) -> Vec<serde_json::Value> {
    content
        .lines()
        .filter_map(parse_authorized_key_line)
        .collect()
}

fn parse_authorized_key_line(line: &str) -> Option<serde_json::Value> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    let key_idx = parts.iter().position(|part| is_ssh_public_key_type(part))?;
    let key_type = parts.get(key_idx)?;
    let key_blob = parts.get(key_idx + 1)?;
    let comment = parts
        .get(key_idx + 2..)
        .map(|parts| parts.join(" "))
        .map(|comment| sanitize_authorized_key_comment(&comment))
        .unwrap_or_default();
    let fingerprint = ssh_public_key_fingerprint(key_blob)?;

    Some(serde_json::json!({
        "key_type": key_type,
        "fingerprint_sha256": fingerprint,
        "comment": comment,
    }))
}

fn sanitize_authorized_key_comment(value: &str) -> String {
    let without_controls = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    sanitize_security_command(&without_controls)
        .chars()
        .take(SECURITY_AUTHORIZED_KEY_COMMENT_MAX_CHARS)
        .collect()
}

fn is_ssh_public_key_type(value: &str) -> bool {
    value == "ssh-rsa"
        || value == "ssh-ed25519"
        || value.starts_with("ecdsa-sha2-")
        || value.starts_with("sk-ssh-ed25519@")
        || value.starts_with("sk-ecdsa-sha2-")
}

fn ssh_public_key_fingerprint(key_blob: &str) -> Option<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_blob)
        .ok()
        .filter(|decoded| !decoded.is_empty())?;
    let digest = Sha256::digest(decoded);
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Some(format!("SHA256:{fingerprint}"))
}

struct GroupEntry {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn bounded_login_field(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_chars)
        .collect()
}

fn parse_group_memberships_bounded(
    group: &SecurityBoundedLoginInput,
    stats: &mut SecurityLoginAccountsScanStats,
) -> Vec<GroupEntry> {
    let mut groups = Vec::new();
    let mut total_members = 0usize;

    for line in group.content.lines() {
        if stats.group_lines_seen >= SECURITY_LOGIN_DATABASE_MAX_LINES {
            stats.group_line_budget_exhausted = true;
            break;
        }
        stats.group_lines_seen += 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.splitn(4, ':');
        let Some(name_raw) = fields.next() else {
            continue;
        };
        let _password = fields.next();
        let Some(gid_raw) = fields.next() else {
            continue;
        };
        let Some(members_raw) = fields.next() else {
            continue;
        };
        let name_raw = name_raw.trim();
        if name_raw.is_empty() {
            continue;
        }
        stats.groups_seen += 1;
        if groups.len() >= SECURITY_LOGIN_GROUPS_MAX {
            stats.group_records_truncated += 1;
            continue;
        }

        let mut members = Vec::new();
        for (index, member) in members_raw
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .take(SECURITY_LOGIN_GROUP_MEMBERS_PER_GROUP_MAX + 1)
            .enumerate()
        {
            if index >= SECURITY_LOGIN_GROUP_MEMBERS_PER_GROUP_MAX {
                stats.group_members_truncated += 1;
                break;
            }
            if total_members >= SECURITY_LOGIN_GROUP_MEMBERS_TOTAL_MAX {
                stats.group_members_truncated += 1;
                continue;
            }
            members.push(bounded_login_field(
                member,
                SECURITY_LOGIN_USERNAME_MAX_CHARS,
            ));
            total_members += 1;
        }
        groups.push(GroupEntry {
            name: bounded_login_field(name_raw, SECURITY_LOGIN_GROUP_NAME_MAX_CHARS),
            gid: gid_raw.trim().parse::<u32>().unwrap_or(u32::MAX),
            members,
        });
    }
    stats.groups_emitted = groups.len();
    groups
}

fn is_login_shell(shell: &str) -> bool {
    let shell = shell.trim();
    !shell.is_empty() && !shell.ends_with("/nologin") && !shell.ends_with("/false")
}
