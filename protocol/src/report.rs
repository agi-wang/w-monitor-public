//! Data report types and format specification.
//!
//! This module defines the `SystemReport` — the standardized data envelope
//! that the agent sends to a remote ingestion endpoint. Each report contains
//! a snapshot of all enabled collectors at a given point in time.
//!
//! ## Format Specification (v1.0)
//!
//! ```json
//! {
//!   "version": "1.0",
//!   "agent_id": "uuid-v4",
//!   "hostname": "node-01",
//!   "os": "linux",
//!   "arch": "x86_64",
//!   "timestamp": "2026-02-15T12:00:00Z",
//!   "report_interval_ms": 5000,
//!   "collectors": {
//!     "cpu": { ... },
//!     "memory": { ... }
//!   },
//!   "metadata": {
//!     "agent_version": "0.1.0",
//!     "uptime_secs": 3600,
//!     "report_seq": 42
//!   }
//! }
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

/// Global sequence counter for reports.
static REPORT_SEQ: AtomicU64 = AtomicU64::new(0);

/// System report envelope — the top-level data structure sent to the server.
///
/// Each report contains a full snapshot of all active collectors' latest metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReport {
    /// Report format version (always "1.0")
    pub version: String,

    /// Stable agent identifier (configured by the server or derived per host)
    pub agent_id: String,

    /// Hostname of the reporting machine
    pub hostname: String,

    /// Operating system name ("linux", "macos", "windows")
    pub os: String,

    /// CPU architecture ("x86_64", "aarch64", etc.)
    pub arch: String,

    /// Timestamp when this report was created
    pub timestamp: DateTime<Utc>,

    /// Configured report interval in milliseconds
    pub report_interval_ms: u64,

    /// Collector snapshots, keyed by collector name.
    ///
    /// Each value is the JSON representation of the collector's typed `Output`.
    /// Only collectors that are enabled and successfully collected are included.
    pub collectors: HashMap<String, serde_json::Value>,

    /// Report metadata (agent version, uptime, sequence number)
    pub metadata: ReportMetadata,

    /// Extra fields (command_acks, tunnel_status, etc.)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Metadata about the report itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Agent software version
    pub agent_version: String,

    /// Agent uptime in seconds since startup
    pub uptime_secs: u64,

    /// Monotonically increasing report sequence number
    pub report_seq: u64,

    /// Machine-readable capability manifest for server and MCP policy decisions.
    #[serde(default = "agent_capabilities")]
    pub capabilities: serde_json::Value,
}

/// Static system information, collected once at startup.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Stable agent identifier (UUID-shaped SHA-256 derivation)
    pub agent_id: String,

    /// Hostname
    pub hostname: String,

    /// Operating system name
    pub os: String,

    /// CPU architecture
    pub arch: String,

    /// Time when the agent started (not serialized)
    pub started_at: Instant,
}

impl SystemInfo {
    /// Creates a new `SystemInfo` by detecting the current system.
    pub fn detect() -> Self {
        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        Self {
            agent_id: stable_agent_id(),
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            started_at: Instant::now(),
        }
    }

    /// Returns the agent uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl SystemReport {
    /// Builds a new `SystemReport` from a collector snapshot.
    ///
    /// # Arguments
    /// * `sys_info` — Static system info (agent_id, hostname, os, arch)
    /// * `collectors` — Map of collector_name → latest metric JSON
    /// * `report_interval_ms` — Configured interval in ms
    pub fn build(
        sys_info: &SystemInfo,
        collectors: HashMap<String, serde_json::Value>,
        report_interval_ms: u64,
    ) -> Self {
        let seq = REPORT_SEQ.fetch_add(1, Ordering::Relaxed);

        Self {
            version: "1.0".to_string(),
            agent_id: sys_info.agent_id.clone(),
            // Re-read hostname every report cycle so set_hostname changes take effect immediately
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            os: sys_info.os.clone(),
            arch: sys_info.arch.clone(),
            timestamp: Utc::now(),
            report_interval_ms,
            collectors,
            metadata: ReportMetadata {
                agent_version: crate::VERSION.to_string(),
                uptime_secs: sys_info.uptime_secs(),
                report_seq: seq,
                capabilities: agent_capabilities(),
            },
            extra: HashMap::new(),
        }
    }

    /// Remove privileged operations when the service lacks system access.
    pub fn apply_runtime_access(&mut self, restricted: bool) {
        if restricted {
            for capability in [
                "commands.execute",
                "control.tcp",
                "node.tasks",
                "upgrade",
                "ssh_key.deploy",
                "terminal",
                "file.read",
                "file.write",
            ] {
                self.metadata.capabilities[capability] = serde_json::json!(false);
            }
            self.metadata
                .capabilities
                .as_object_mut()
                .unwrap()
                .remove("easytier.managed_install");
        }
    }
}

pub(crate) fn agent_capabilities() -> serde_json::Value {
    serde_json::json!({
        "agent.lite": true, "telemetry.read": true, "webhosts.probe": true,
        "commands.execute": false, "control.tcp": false, "node.tasks": false,
        "upgrade": false, "ssh_key.deploy": false, "terminal": false,
        "file.read": false, "file.write": false
    })
}

/// Returns the same opaque identifier across service restarts without storing
/// raw host identifiers in reports. A configured server-assigned ID still
/// overrides this value in [`Reporter::new`](crate::reporter::Reporter::new).
pub fn stable_agent_id() -> String {
    static AGENT_ID: OnceLock<String> = OnceLock::new();
    AGENT_ID.get_or_init(detect_stable_agent_id).clone()
}

fn detect_stable_agent_id() -> String {
    let machine_identity = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| read_host_identity(path).map(|value| format!("machine-id:{value}")))
        .or_else(|| {
            read_host_identity("/sys/class/dmi/id/product_uuid")
                .map(|value| format!("dmi-product-uuid:{value}"))
        })
        .or_else(|| {
            normalize_host_identity(&gethostname::gethostname().to_string_lossy())
                .map(|value| format!("hostname:{value}"))
        })
        // Empty hostnames are unusual, but hashing an empty constant would
        // make every such machine collide. Prefer stable interface addresses,
        // then the per-boot kernel UUID, before the last-resort process nonce.
        .or_else(network_interface_identity)
        .or_else(|| {
            read_host_identity("/proc/sys/kernel/random/boot_id")
                .map(|value| format!("boot-id:{value}"))
        })
        .unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!(
                "process-fallback:{}:{}:{nonce}",
                std::env::consts::OS,
                std::process::id()
            )
        });

    stable_agent_id_from_identity(&machine_identity)
}

fn read_host_identity(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|value| normalize_host_identity(&value))
}

fn normalize_host_identity(value: &str) -> Option<String> {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    let is_placeholder = lower == "uninitialized"
        || lower == "none"
        || lower == "not specified"
        || lower == "to be filled by o.e.m."
        || (!compact.is_empty() && compact.chars().all(|ch| ch == '0'))
        || (!compact.is_empty() && compact.chars().all(|ch| ch == 'f'));
    (!value.is_empty() && !is_placeholder).then_some(lower)
}

fn network_interface_identity() -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    let mut addresses = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != "lo")
        .filter_map(|entry| {
            let path = entry.path().join("address");
            std::fs::read_to_string(path)
                .ok()
                .and_then(|value| normalize_host_identity(&value))
        })
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    (!addresses.is_empty()).then(|| format!("mac:{}", addresses.join(",")))
}

fn stable_agent_id_from_identity(identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"w-monitor-agent-id-v1\0");
    hasher.update(identity.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // UUID version/variant bits make the identifier easy to validate while
    // preserving the deterministic, one-way derivation.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}
