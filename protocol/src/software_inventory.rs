//! Read-only software evidence and inventory-bound vulnerability assessments.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_COMPONENTS: usize = 2048;
pub const MAX_INVENTORY_BYTES: usize = 384 * 1024;
pub const MAX_FINDINGS: usize = 128;
pub const MAX_ASSESSMENT_BYTES: usize = 384 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Component {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Local evidence only; never sent to a public vulnerability service.
    pub location: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoftwareInventory {
    pub schema_version: u8,
    pub revision: String,
    pub checked_at: i64,
    pub components: Vec<Component>,
    pub warnings: Vec<String>,
    pub scopes: Vec<String>,
}

fn text_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

pub fn supported_ecosystem(value: &str) -> bool {
    matches!(
        value,
        "npm"
            | "PyPI"
            | "Go"
            | "crates.io"
            | "Maven"
            | "NuGet"
            | "Packagist"
            | "RubyGems"
            | "GIT"
            | "Generic"
    ) || [
        "Ubuntu:",
        "Debian:",
        "Alpine:",
        "AlmaLinux:",
        "Rocky Linux:",
    ]
    .iter()
    .any(|prefix| {
        value.strip_prefix(prefix).is_some_and(|release| {
            !release.is_empty()
                && release
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
        })
    })
}

impl SoftwareInventory {
    pub fn fingerprint(&self) -> String {
        let bytes = serde_json::to_vec(&(&self.components, &self.warnings, &self.scopes))
            .unwrap_or_default();
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.checked_at <= 0
            || self.components.len() > MAX_COMPONENTS
            || self.warnings.len() > 32
            || self.scopes.len() > 64
            || self.warnings.iter().any(|s| !text_ok(s, 240))
            || self.scopes.iter().any(|s| !text_ok(s, 160))
            || self.components.iter().any(|c| {
                (!supported_ecosystem(&c.ecosystem) || c.ecosystem.len() > 80)
                    || !text_ok(&c.name, 200)
                    || !text_ok(&c.version, 160)
                    || !text_ok(&c.location, 240)
                    || !matches!(
                        c.kind.as_str(),
                        "source_package"
                            | "binary_package"
                            | "running_kernel"
                            | "lockfile"
                            | "installed_metadata"
                            | "upstream_binary"
                            | "sbom"
                    )
            })
            || serde_json::to_vec(self)
                .map_err(|_| "invalid inventory")?
                .len()
                > MAX_INVENTORY_BYTES
            || self.revision != self.fingerprint()
        {
            return Err("invalid software inventory or limits");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub package: String,
    pub ecosystem: String,
    pub installed_version: String,
    /// Original affected version retained when current evidence verifies recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_affected_version: Option<String>,
    pub fixed_version: String,
    pub location: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub source_url: String,
    pub cves: Vec<String>,
    pub status: String,
    pub evidence: Vec<Evidence>,
    pub evidence_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assessment {
    pub inventory_revision: String,
    pub checked_at: i64,
    pub complete: bool,
    pub packages_checked: usize,
    pub errors: Vec<String>,
    pub results: Vec<Finding>,
}

impl Assessment {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.inventory_revision.len() != 64
            || !self
                .inventory_revision
                .bytes()
                .all(|c| c.is_ascii_hexdigit())
            || self.checked_at <= 0
            || self.packages_checked > MAX_COMPONENTS
            || self.errors.len() > 32
            || self.errors.iter().any(|s| !text_ok(s, 240))
            || self.results.len() > MAX_FINDINGS
            || self.results.iter().any(|f| {
                !text_ok(&f.id, 100)
                    || !f
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b) || b == b'.')
            })
        {
            return Err("invalid assessment");
        }
        let mut ids = std::collections::HashSet::new();
        for f in &self.results {
            if !ids.insert(&f.id)
                || !text_ok(&f.title, 240)
                || !f.source_url.starts_with("https://")
                || !text_ok(&f.source_url, 512)
                || !matches!(f.severity.as_str(), "low" | "medium" | "high" | "critical")
                || !matches!(f.status.as_str(), "affected" | "not_affected" | "unknown")
                || f.cves.len() > 32
                || f.cves
                    .iter()
                    .any(|c| !text_ok(c, 40) || !c.starts_with("CVE-"))
                || f.evidence.len() > 8
                || f.evidence.iter().any(|e| {
                    !text_ok(&e.package, 200)
                        || !text_ok(&e.ecosystem, 80)
                        || !text_ok(&e.installed_version, 160)
                        || e.previous_affected_version
                            .as_ref()
                            .is_some_and(|v| !text_ok(v, 160))
                        || !text_ok(&e.fixed_version, 240)
                        || !text_ok(&e.location, 240)
                        || !text_ok(&e.kind, 40)
                })
            {
                return Err("invalid finding");
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid assessment")?
            .len()
            > MAX_ASSESSMENT_BYTES
        {
            return Err("assessment too large");
        }
        Ok(())
    }
}
