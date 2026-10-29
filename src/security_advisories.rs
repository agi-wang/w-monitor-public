//! Independently scheduled, read-only package checks. Never runs catalog text.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;
use w_monitor_sdk::security_advisories::{
    Advisory, Catalog, RuleKind, MAX_CATALOG_BYTES, SCAN_INTERVAL_SECS,
};
use w_monitor_sdk::software_inventory::{Assessment, SoftwareInventory, MAX_ASSESSMENT_BYTES};

pub type Snapshot = Arc<Mutex<Value>>;

#[derive(Serialize, Deserialize)]
struct Saved {
    endpoint: String,
    catalog: Catalog,
}

#[derive(Debug, Clone)]
struct Package {
    name: String,
    version: String,
    source: String,
    source_version: String,
}

#[derive(Default)]
struct Inventory {
    distro: String,
    release: String,
    packages: Vec<Package>,
    running_kernel: Option<Package>,
    error: Option<String>,
}

fn read_bounded(path: &Path, limit: usize) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes).ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn os_release(raw: &str) -> HashMap<&str, &str> {
    raw.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key, value.trim_matches('"').trim_matches('\'')))
        .collect()
}

fn parse_packages(raw: &str) -> Result<Vec<Package>, &'static str> {
    let mut packages = Vec::new();
    for line in raw.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 6 {
            return Err("incomplete package database output");
        }
        if fields[4] != "installed" {
            continue;
        }
        if fields[0].is_empty() || fields[1].is_empty() {
            return Err("missing package identity");
        }
        let name = fields[0].split(':').next().unwrap_or(fields[0]).to_string();
        let mut package = Package {
            source: if fields[2].is_empty() {
                name.clone()
            } else {
                fields[2].into()
            },
            source_version: if fields[3].is_empty() {
                fields[1].into()
            } else {
                fields[3].into()
            },
            name,
            version: fields[1].into(),
        };
        if package.name.starts_with("linux-image-") && package.source.starts_with("linux-signed") {
            // Signing packages have their own source name/version. Built-Using
            // identifies the actual kernel source, including HWE/cloud variants.
            let mut sources = fields[5].split(',').filter_map(|entry| {
                let (source, relation) = entry.trim().split_once('(')?;
                let source = source.trim();
                let version = relation
                    .trim()
                    .strip_prefix('=')?
                    .trim()
                    .strip_suffix(')')?
                    .trim();
                ((source == "linux" || source.starts_with("linux-"))
                    && !source.starts_with("linux-signed")
                    && !source.starts_with("linux-meta")
                    && debian_version_cmp(version, version).is_some())
                .then_some((source, version))
            });
            if let Some((source, version)) = sources.next().filter(|_| sources.next().is_none()) {
                package.source = source.into();
                package.source_version = version.into();
            } else {
                // Missing/ambiguous provenance cannot establish a clean kernel.
                package.source.clear();
                package.source_version.clear();
            }
        }
        packages.push(package);
    }
    if packages.is_empty() {
        return Err("package inventory is empty");
    }
    Ok(packages)
}

fn running_kernel(packages: &[Package], release: &str) -> Option<Package> {
    packages
        .iter()
        .find(|p| {
            p.name == format!("linux-image-{release}")
                || p.name == format!("linux-image-unsigned-{release}")
        })
        .filter(|p| !p.source.is_empty())
        .cloned()
}

fn inventory() -> Inventory {
    let mut result = Inventory::default();
    let release = read_bounded(Path::new("/etc/os-release"), 16 * 1024).unwrap_or_default();
    let values = os_release(&release);
    result.distro = values.get("ID").copied().unwrap_or_default().into();
    result.release = values
        .get("VERSION_CODENAME")
        .copied()
        .unwrap_or_default()
        .into();
    if !matches!(result.distro.as_str(), "ubuntu" | "debian") || result.release.is_empty() {
        result.error =
            Some("unsupported distribution or missing release; host dpkg checks only".into());
        return result;
    }
    let output = crate::collectors::run_cmd_with_timeout("dpkg-query", &[
        "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\t${Built-Using}\n",
    ], Duration::from_secs(8));
    match output {
        Some(out) if out.status.success() && out.stdout.len() < 16 * 1024 * 1024 => {
            match std::str::from_utf8(&out.stdout)
                .ok()
                .and_then(|s| parse_packages(s).ok())
            {
                Some(packages) => result.packages = packages,
                None => result.error = Some("package database is unreadable or incomplete".into()),
            }
        }
        _ => {
            result.error =
                Some("dpkg-query unavailable, timed out, failed or exceeded output limit".into())
        }
    }
    if let Some(release) = read_bounded(Path::new("/proc/sys/kernel/osrelease"), 512) {
        result.running_kernel = running_kernel(&result.packages, release.trim());
    }
    result
}

// Debian Policy 5.6.12 ordering (epochs, tilde, digit runs and Debian revisions).
// Ordinary semver or lexicographic comparison produces false positives on
// distro backports. Keep this tested against the platform's dpkg comparator.
fn debian_version_cmp(a: &str, b: &str) -> Option<Ordering> {
    fn split(version: &str) -> Option<(&str, &str, &str)> {
        if version.is_empty()
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+:~-".contains(&b))
        {
            return None;
        }
        let (epoch, rest) = version.split_once(':').unwrap_or(("0", version));
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) || rest.is_empty() {
            return None;
        }
        let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
        if upstream.is_empty() || revision.is_empty() || !upstream.as_bytes()[0].is_ascii_digit() {
            return None;
        }
        Some((epoch, upstream, revision))
    }
    fn number(a: &str, b: &str) -> Ordering {
        let a = a.trim_start_matches('0');
        let b = b.trim_start_matches('0');
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }
    fn order(c: Option<u8>) -> i32 {
        match c {
            Some(b'~') => -1,
            None => 0,
            Some(c) if c.is_ascii_digit() => 0,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }
    fn part(a: &str, b: &str) -> Ordering {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let (mut i, mut j) = (0, 0);
        while i < a.len() || j < b.len() {
            while a.get(i).is_some_and(|c| !c.is_ascii_digit())
                || b.get(j).is_some_and(|c| !c.is_ascii_digit())
            {
                let cmp = order(a.get(i).copied()).cmp(&order(b.get(j).copied()));
                if cmp != Ordering::Equal {
                    return cmp;
                }
                i += usize::from(i < a.len());
                j += usize::from(j < b.len());
            }
            while a.get(i) == Some(&b'0') {
                i += 1;
            }
            while b.get(j) == Some(&b'0') {
                j += 1;
            }
            let (ai, bj) = (i, j);
            while a.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            let cmp = (i - ai)
                .cmp(&(j - bj))
                .then_with(|| a[ai..i].cmp(&b[bj..j]));
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
        Ordering::Equal
    }
    let (ae, au, ar) = split(a)?;
    let (be, bu, br) = split(b)?;
    Some(
        number(ae, be)
            .then_with(|| part(au, bu))
            .then_with(|| part(ar, br)),
    )
}

fn check(event: &Advisory, inventory: &Inventory) -> Value {
    let mut result = json!({"id":event.id,"title":event.title,"severity":event.severity,
        "cves":event.cves,"source_url":event.source_url,"status":"not_applicable","evidence":[]});
    if event.withdrawn {
        result["status"] = json!("withdrawn");
        return result;
    }
    let rules: Vec<_> = event
        .rules
        .iter()
        .filter(|r| r.distro == inventory.distro && r.release == inventory.release)
        .collect();
    if rules.is_empty() {
        return result;
    }
    if let Some(error) = &inventory.error {
        result["status"] = json!("unknown");
        result["reason"] = json!(error);
        return result;
    }
    let mut affected = 0;
    let mut unknown = false;
    let mut evidence = Vec::new();
    for rule in rules {
        let packages: Vec<_> = match rule.kind {
            RuleKind::Package => inventory
                .packages
                .iter()
                .filter(|p| p.name == rule.package)
                .collect(),
            RuleKind::RunningKernel => {
                if inventory.running_kernel.is_none() {
                    unknown = true;
                }
                inventory
                    .running_kernel
                    .iter()
                    .filter(|p| p.source == rule.package)
                    .collect()
            }
        };
        for package in packages {
            let version = if rule.kind == RuleKind::RunningKernel {
                &package.source_version
            } else {
                &package.version
            };
            match debian_version_cmp(version, &rule.fixed_version) {
                Some(Ordering::Less) => {
                    affected += 1;
                    if evidence.len() < 8 {
                        evidence.push(json!({"package":package.name,"installed_version":version,
                        "fixed_version":rule.fixed_version,"kind":rule.kind}));
                    }
                }
                None => unknown = true,
                _ => {}
            }
        }
    }
    result["status"] = json!(if affected > 0 {
        "affected"
    } else if unknown {
        "unknown"
    } else {
        "not_affected"
    });
    result["reason"] = json!(if affected > 0 {
        "installed version is below a vendor fix; exploit prerequisites and mitigations require review"
    } else if unknown {
        "running kernel or package version could not be verified"
    } else {
        "no missing fix found among installed distro packages in this event's scope"
    });
    result["evidence"] = json!(evidence);
    result["evidence_truncated"] = json!(affected > evidence.len());
    result
}

// A custom event can combine native vendor rules and software rules. A positive
// wins; missing or incomplete evidence never clears an existing alert.
fn check_software(event: &Advisory, software: &SoftwareInventory, result: &mut Value) {
    if event.withdrawn || event.software_rules.is_empty() {
        return;
    }
    let mut affected = result["status"] == "affected";
    let mut unknown = result["status"] == "unknown" || !software.warnings.is_empty();
    let mut evidence = result["evidence"].as_array().cloned().unwrap_or_default();
    let mut truncated = result["evidence_truncated"] == true;
    for rule in &event.software_rules {
        let mut found = false;
        for component in software
            .components
            .iter()
            .filter(|c| c.ecosystem == rule.ecosystem && c.name == rule.package)
        {
            found = true;
            match rule.matches_version(&component.version) {
                Some(true) => {
                    affected = true;
                    if evidence.len() < 8 {
                        evidence.push(json!({"package":component.name,"ecosystem":component.ecosystem,
                            "installed_version":component.version,"fixed_version":rule.fixed.as_deref().unwrap_or("See advisory"),
                            "kind":component.kind,"location":component.location}));
                    } else {
                        truncated = true;
                    }
                }
                None => unknown = true,
                Some(false) => {}
            }
        }
        // Discovery is bounded: absence is not proof that arbitrary software was removed.
        unknown |= !found;
    }
    result["status"] = json!(if affected {
        "affected"
    } else if unknown {
        "unknown"
    } else {
        "not_affected"
    });
    result["reason"] = json!(if unknown {
        "Software missing from discovered scope, inventory incomplete, or version cannot be compared"
    } else {
        "Compared discovered versions against the published rule"
    });
    result["evidence"] = json!(evidence);
    result["evidence_truncated"] = json!(truncated);
}

fn scan(catalog: &Catalog, inventory: &Inventory, software: &SoftwareInventory, now: i64) -> Value {
    let results: Vec<_> = catalog
        .events
        .iter()
        .map(|event| {
            let mut result = check(event, inventory);
            check_software(event, software, &mut result);
            result
        })
        .collect();
    let count = |status| results.iter().filter(|v| v["status"] == status).count();
    let applicable = count("affected") + count("unknown") + count("not_affected");
    json!({"schema_version":1,"catalog_revision":catalog.revision,"catalog_checked_at":catalog.checked_at,
        "checked_at":now,"catalog_stale":catalog.is_stale(now),
        "status":if inventory.error.is_some() {"unknown"} else if applicable == 0 {"no_applicable_rules"} else {"ready"},
        "scope":"host_dpkg_and_running_kernel","containers_scanned":false,"unmanaged_software_scanned":false,
        "distro":inventory.distro,"release":inventory.release,"error":inventory.error,
        "packages_checked":inventory.packages.len(),"events_checked":applicable,"affected":count("affected"),"unknown":count("unknown"),
        "results":results})
}

fn reminders(previous: &mut BTreeSet<String>, report: &Value) {
    let Some(results) = report["results"].as_array() else {
        return;
    };
    for result in results {
        let Some(id) = result["id"].as_str() else {
            continue;
        };
        match result["status"].as_str() {
            Some("affected") if previous.insert(id.into()) => {
                tracing::warn!(advisory = id, title = %result["title"], evidence = %result["evidence"], "Security emergency: discovered software matches an affected version");
            }
            Some("not_affected") if previous.remove(id) => tracing::info!(
                advisory = id,
                "Security emergency: version check no longer matches an affected version"
            ),
            Some("withdrawn") => {
                previous.remove(id);
            }
            _ => {}
        }
    }
}

fn persist(path: &Path, endpoint: &str, catalog: &Catalog) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec(&Saved {
        endpoint: endpoint.into(),
        catalog: catalog.clone(),
    })?)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

fn merge_assessment(
    mut report: Value,
    software: &SoftwareInventory,
    assessment: Option<&Assessment>,
    now: i64,
) -> Value {
    let recent = |at: Option<i64>, age: i64| {
        at.is_some_and(|at| at > 0 && at <= now + 300 && now.saturating_sub(at) <= age)
    };
    let inventory_fresh = recent(Some(software.checked_at), 1800);
    let catalog_at = report["catalog_checked_at"].as_i64();
    let catalog_fresh = recent(catalog_at, 48 * 3600)
        && report["catalog_revision"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
    let matching = assessment.is_some_and(|a| a.inventory_revision == software.revision);
    let assessment_at = assessment.map(|a| a.checked_at);
    let fresh = matching && recent(assessment_at, 48 * 3600);
    let results = report["results"].as_array_mut().unwrap();
    for result in results.iter_mut() {
        if (!catalog_fresh || !inventory_fresh) && result["status"] == "not_affected" {
            result["status"] = json!("unknown");
            result["reason"] = json!("Custom catalog or local inventory is missing or stale");
        }
    }
    if let Some(assessment) = assessment {
        for finding in &assessment.results {
            let mut result = json!(finding);
            if (!fresh || !inventory_fresh || !assessment.complete)
                && finding.status == "not_affected"
            {
                result["status"] = json!("unknown");
            }
            results.push(result);
        }
    }
    let affected = results.iter().filter(|r| r["status"] == "affected").count();
    let unknown = results.iter().filter(|r| r["status"] == "unknown").count();
    let complete = fresh
        && inventory_fresh
        && catalog_fresh
        && assessment.is_some_and(|a| a.complete && a.errors.is_empty())
        && software.warnings.is_empty()
        && unknown == 0;
    report["status"] = json!(if complete {
        "ready"
    } else if assessment.is_some() {
        "partial"
    } else {
        "waiting_assessment"
    });
    report["inventory_revision"] = json!(software.revision);
    report["checked_at"] = json!(software.checked_at);
    report["assessment_checked_at"] = json!(assessment.map(|a| a.checked_at));
    report["assessment_complete"] = json!(assessment.is_some_and(|a| a.complete));
    // The combined summary expires as soon as either rule source expires.
    report["catalog_checked_at"] = json!(catalog_at.zip(assessment_at).map(|(c, a)| c.min(a)));
    report["catalog_stale"] = json!(!catalog_fresh || !fresh);
    report["scope"] = json!("discovered_software_and_dependencies");
    report["scopes"] = json!(software.scopes);
    report["coverage_warnings"] = json!(software.warnings);
    report["lookup_errors"] = json!(assessment.map(|a| &a.errors).cloned().unwrap_or_default());
    report["packages_checked"] = json!(software.components.len());
    report["affected"] = json!(affected);
    let issues: BTreeSet<_> = software
        .warnings
        .iter()
        .chain(assessment.into_iter().flat_map(|a| a.errors.iter()))
        .collect();
    report["unknown"] = json!(
        unknown
            + issues.len()
            + usize::from(!fresh)
            + usize::from(!inventory_fresh)
            + usize::from(!catalog_fresh)
    );
    report["error"] = json!(if !catalog_fresh {
        Some("Custom advisory catalog is missing or stale")
    } else if !inventory_fresh {
        Some("Local software inventory is stale")
    } else {
        None
    });
    report.as_object_mut().unwrap().remove("containers_scanned");
    report
        .as_object_mut()
        .unwrap()
        .remove("unmanaged_software_scanned");
    report
}

fn save_assessment(path: &Path, endpoint: &str, assessment: &Assessment) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec(
        &json!({"endpoint":endpoint,"assessment":assessment}),
    )?)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

type CatalogSender = watch::Sender<Option<Catalog>>;
type AssessmentSender = watch::Sender<Option<Assessment>>;
pub fn start(
    data_dir: &Path,
    endpoint: &str,
) -> (CatalogSender, AssessmentSender, Snapshot, Snapshot) {
    let path: PathBuf = data_dir.join("security-advisories.json");
    let assessment_path = data_dir.join("security-assessment.json");
    let data_dir = data_dir.to_owned();
    let endpoint = endpoint.to_string();
    let catalog = read_bounded(&path, MAX_CATALOG_BYTES + 4096)
        .and_then(|raw| serde_json::from_str::<Saved>(&raw).ok())
        .filter(|saved| saved.endpoint == endpoint && saved.catalog.validate().is_ok())
        .map(|s| s.catalog);
    let assessment = read_bounded(&assessment_path, MAX_ASSESSMENT_BYTES + 4096)
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .filter(|v| v["endpoint"] == endpoint)
        .and_then(|v| serde_json::from_value::<Assessment>(v["assessment"].clone()).ok())
        .filter(|a| a.validate().is_ok());
    let (sender, mut receiver) = watch::channel(catalog);
    let (assessment_tx, mut assessments) = watch::channel(assessment);
    let snapshot = Arc::new(Mutex::new(
        json!({"schema_version":1,"status":"waiting_assessment","affected":null,"unknown":null}),
    ));
    let software_snapshot = Arc::new(Mutex::new(json!({"status":"collecting"})));
    let task_snapshot = snapshot.clone();
    let task_software = software_snapshot.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(SCAN_INTERVAL_SECS));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = BTreeSet::new();
        let mut software: Option<SoftwareInventory> = None;
        loop {
            let refresh = tokio::select! {
                changed = receiver.changed() => {if changed.is_err() {break;} false},
                changed = assessments.changed() => {if changed.is_err() {break;} false},
                _ = timer.tick() => true,
            };
            let catalog = receiver.borrow_and_update().clone();
            let assessment = assessments.borrow_and_update().clone();
            let path = path.clone();
            let assessment_path = assessment_path.clone();
            let data_dir = data_dir.clone();
            let endpoint = endpoint.clone();
            let existing = if refresh { None } else { software.clone() };
            let result = tokio::task::spawn_blocking(move || {
                if let Some(catalog) = &catalog {
                    if let Err(error) = persist(&path, &endpoint, catalog) {
                        tracing::warn!("Security catalog persistence failed: {error}");
                    }
                }
                if let Some(assessment) = &assessment {
                    if let Err(error) = save_assessment(&assessment_path, &endpoint, assessment) {
                        tracing::warn!("Security assessment persistence failed: {error}");
                    }
                }
                let software =
                    existing.unwrap_or_else(|| crate::software_inventory::collect(&data_dir));
                let now = chrono::Utc::now().timestamp();
                let local = catalog
                    .as_ref()
                    .map(|c| scan(c, &inventory(), &software, now))
                    .unwrap_or_else(|| json!({"schema_version":1,"results":[]}));
                let report = merge_assessment(local, &software, assessment.as_ref(), now);
                (report, software)
            })
            .await;
            match result {
                Ok((report, inventory)) => {
                    reminders(&mut previous, &report);
                    *task_snapshot.lock() = report;
                    *task_software.lock() = json!(inventory);
                    software = Some(inventory);
                }
                Err(error) => {
                    tracing::warn!("Security scan failed: {error}");
                    task_snapshot.lock()["status"] = json!("unknown");
                }
            }
        }
    });
    (sender, assessment_tx, snapshot, software_snapshot)
}
