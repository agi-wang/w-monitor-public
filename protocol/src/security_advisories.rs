//! Declarative, read-only emergency checks shared with the server.
//! No commands, paths or executable expressions are accepted from the catalog.

use serde::{Deserialize, Serialize};

pub const MAX_EVENTS: usize = 128;
// Leaves room for command receipts in the 1 MiB HTTP/TCP response budget.
pub const MAX_CATALOG_BYTES: usize = 512 * 1024;
pub const CATALOG_MAX_AGE_SECS: i64 = 48 * 3600;
pub const SCAN_INTERVAL_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Catalog {
    pub schema_version: u8,
    pub revision: String,
    /// Last successful publication heartbeat for the custom rules.
    pub checked_at: i64,
    pub events: Vec<Advisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub source_url: String,
    pub published_at: i64,
    #[serde(default)]
    pub withdrawn: bool,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub rules: Vec<PackageRule>,
    #[serde(default)]
    pub software_rules: Vec<SoftwareRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoftwareRule {
    pub ecosystem: String,
    pub package: String,
    #[serde(default)]
    pub affected_versions: Vec<String>,
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

impl SoftwareRule {
    #[allow(dead_code)] // Shared Server DTO validates rules; Agent evaluates versions.
    pub fn matches_version(&self, version: &str) -> Option<bool> {
        if !self.affected_versions.is_empty() {
            return Some(self.affected_versions.iter().any(|v| v == version));
        }
        let version = semver::Version::parse(version.strip_prefix('v').unwrap_or(version)).ok()?;
        let lower = self
            .introduced
            .as_deref()
            .map(semver::Version::parse)
            .transpose()
            .ok()?;
        let upper = self
            .fixed
            .as_deref()
            .map(semver::Version::parse)
            .transpose()
            .ok()?;
        Some(
            lower
                .as_ref()
                .is_none_or(|v| version.cmp_precedence(v).is_ge())
                && upper
                    .as_ref()
                    .is_none_or(|v| version.cmp_precedence(v).is_lt()),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageRule {
    pub distro: String,
    pub release: String,
    /// Exact binary package, or source package of the currently running kernel.
    pub package: String,
    pub fixed_version: String,
    pub kind: RuleKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Package,
    RunningKernel,
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-:~".contains(&b))
}

impl Advisory {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !token(&self.id, 80)
            || self.title.is_empty()
            || self.title.len() > 240
            || self.title.chars().any(char::is_control)
            || !matches!(
                self.severity.as_str(),
                "low" | "medium" | "high" | "critical"
            )
            || !self.source_url.starts_with("https://")
            || self.source_url.len() > 512
            || self.source_url.chars().any(char::is_whitespace)
            || self.published_at <= 0
            || self.cves.len() > 2048
            || self
                .cves
                .iter()
                .any(|cve| !cve.starts_with("CVE-") || !token(cve, 40))
            || (self.rules.is_empty() && self.software_rules.is_empty())
            || self.rules.len() > 1024
            || self.software_rules.len() > 64
        {
            return Err("invalid advisory metadata or limits");
        }
        for rule in &self.rules {
            if !matches!(rule.distro.as_str(), "ubuntu" | "debian")
                || !token(&rule.release, 40)
                || !token(&rule.package, 160)
                || !token(&rule.fixed_version, 160)
                || !rule.fixed_version.as_bytes()[0].is_ascii_digit()
            {
                return Err("unsupported or invalid package rule");
            }
        }
        for rule in &self.software_rules {
            if !crate::software_inventory::supported_ecosystem(&rule.ecosystem)
                || rule.ecosystem.len() > 80
                || rule.package.is_empty()
                || rule.package.len() > 200
                || rule.package.chars().any(char::is_control)
                || rule.affected_versions.len() > 128
                || rule.affected_versions.iter().any(|v| !token(v, 160))
                || (rule.affected_versions.is_empty()
                    && rule.introduced.is_none()
                    && rule.fixed.is_none())
                || (!rule.affected_versions.is_empty()
                    && (rule.introduced.is_some() || rule.fixed.is_some()))
                || rule
                    .introduced
                    .iter()
                    .chain(rule.fixed.iter())
                    .any(|v| semver::Version::parse(v).is_err())
                || rule
                    .introduced
                    .as_ref()
                    .zip(rule.fixed.as_ref())
                    .is_some_and(|(lo, hi)| {
                        semver::Version::parse(lo)
                            .ok()
                            .zip(semver::Version::parse(hi).ok())
                            .is_some_and(|(lo, hi)| lo.cmp_precedence(&hi).is_ge())
                    })
            {
                return Err("invalid software version rule");
            }
        }
        Ok(())
    }
}

impl Catalog {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !token(&self.revision, 80)
            || self.checked_at <= 0
            || self.events.len() > MAX_EVENTS
            || serde_json::to_vec(self)
                .map_err(|_| "invalid catalog")?
                .len()
                > MAX_CATALOG_BYTES
        {
            return Err("unsupported catalog or limits exceeded");
        }
        let mut ids = std::collections::HashSet::new();
        for event in &self.events {
            event.validate()?;
            if !ids.insert(&event.id) {
                return Err("duplicate advisory id");
            }
        }
        Ok(())
    }

    pub fn is_stale(&self, now: i64) -> bool {
        self.checked_at > now + 300 || now - self.checked_at > CATALOG_MAX_AGE_SECS
    }
}
