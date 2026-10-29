//! Mount state only: never stat, list, or probe a mount point (dead hard-NFS may block).
use super::run_cmd_with_timeout;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_MOUNTS: usize = 256;
const MAX_INPUT: usize = 1024 * 1024;

fn read_snapshot(path: &str) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take((MAX_INPUT + 1) as u64)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= MAX_INPUT).then_some(text)
}

fn unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|c| (b'0'..=b'7').contains(c))
        {
            let n = (bytes[i + 1] - b'0') as u16 * 64
                + (bytes[i + 2] - b'0') as u16 * 8
                + (bytes[i + 3] - b'0') as u16;
            if n <= 255 {
                result.push(n as u8);
                i += 4;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn mount_unit(path: &str) -> String {
    let normalized = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        return "-.mount".into();
    }
    let mut result = String::new();
    for (i, b) in normalized.bytes().enumerate() {
        match b {
            b'/' => result.push('-'),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b':' => result.push(b as char),
            b'.' if i != 0 => result.push('.'),
            _ => result.push_str(&format!("\\x{b:02x}")),
        }
    }
    result + ".mount"
}

#[derive(Default)]
struct Entry {
    fs_type: String,
    expected: bool,
    automount: bool,
    auto_ready: bool,
    mounted: bool,
    unit: BTreeMap<String, String>,
}

fn relevant(path: &str, typ: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && !["/proc", "/sys", "/dev", "/run"]
            .iter()
            .any(|p| path == *p || path.starts_with(&format!("{p}/")))
        && !matches!(typ, "overlay" | "squashfs" | "nsfs" | "tmpfs" | "autofs")
}

fn snapshot(
    fstab: &str,
    mountinfo: &str,
    units: Option<&str>,
    mut complete: bool,
    sampled_at: u64,
) -> Value {
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    for line in fstab.lines().filter(|l| !l.trim_start().starts_with('#')) {
        let p: Vec<_> = line.split_whitespace().collect();
        if p.len() < 4 || p[2] == "swap" {
            continue;
        }
        let path = unescape(p[1]);
        if !relevant(&path, p[2]) {
            continue;
        }
        let flags: Vec<_> = p[3].split(',').collect();
        let auto = flags.contains(&"x-systemd.automount");
        entries.insert(
            path,
            Entry {
                fs_type: p[2].into(),
                expected: !flags.contains(&"noauto") || auto,
                automount: auto,
                ..Entry::default()
            },
        );
    }
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            complete = false;
            continue;
        };
        let p: Vec<_> = left.split_whitespace().collect();
        let typ = right.split_whitespace().next().unwrap_or("");
        if p.len() < 5 {
            complete = false;
            continue;
        }
        let path = unescape(p[4]);
        if typ == "autofs" {
            if let Some(e) = entries.get_mut(&path) {
                e.automount = true;
                e.auto_ready = true;
            }
        } else if relevant(&path, typ) {
            let e = entries.entry(path).or_default();
            e.fs_type = typ.into();
            e.mounted = true;
        }
    }
    let mut mounts = BTreeMap::new();
    if let Some(raw) = units {
        for block in raw.split("\n\n") {
            let props: BTreeMap<String, String> = block
                .lines()
                .filter_map(|l| l.split_once('=').map(|(k, v)| (k.into(), v.into())))
                .collect();
            let Some(id) = props.get("Id") else {
                continue;
            };
            if id.ends_with(".mount") || id.ends_with(".automount") {
                mounts.insert(id.clone(), props);
            }
        }
        for (id, p) in &mounts {
            let path = p.get("Where").map(String::as_str).unwrap_or("");
            let typ = p.get("Type").map(String::as_str).unwrap_or("");
            if !relevant(path, typ) {
                continue;
            }
            let e = entries.entry(path.into()).or_default();
            if id.ends_with(".automount") {
                e.automount = true;
                e.auto_ready |= p.get("ActiveState").is_some_and(|s| s == "active");
            } else {
                if e.fs_type.is_empty() {
                    e.fs_type = typ.into();
                }
                e.expected |= p
                    .get("UnitFileState")
                    .is_some_and(|s| s.starts_with("enabled"));
                e.unit = p.clone();
            }
        }
    } else {
        complete = false;
    }
    let mut rows = Vec::new();
    for (path, mut e) in entries {
        let id = mount_unit(&path);
        if let Some(p) = mounts.get(&id) {
            e.unit = p.clone();
        }
        let active = e.unit.get("ActiveState").map(String::as_str).unwrap_or("");
        let result = e.unit.get("Result").map(String::as_str).unwrap_or("");
        let load = e.unit.get("LoadState").map(String::as_str).unwrap_or("");
        let auto = mounts.get(&id.replace(".mount", ".automount"));
        let auto_failed = auto.is_some_and(|p| p.get("ActiveState").is_some_and(|s| s == "failed"));
        let (status, reason) = if active == "failed" || auto_failed {
            (
                "failed",
                if result.is_empty() || result == "success" {
                    "unit_failed"
                } else {
                    result
                },
            )
        } else if e.mounted {
            ("mounted", "mount_table")
        } else if active == "activating" || active == "deactivating" {
            ("mounting", "transition")
        } else if e.automount && e.auto_ready {
            ("waiting", "on_demand")
        } else if e.automount
            && auto.is_some_and(|p| p.get("ActiveState").is_some_and(|s| s == "inactive"))
        {
            ("missing", "automount_inactive")
        } else if e.automount {
            complete = false;
            ("unknown", "state_unavailable")
        } else if !e.expected {
            ("manual", "not_required")
        } else if units.is_some()
            && (active == "inactive"
                || load == "not-found"
                || load == "masked"
                || load == "error"
                || load == "bad-setting")
        {
            ("missing", "expected_mount_absent")
        } else {
            complete = false;
            ("unknown", "state_unavailable")
        };
        rows.push(json!({"mount_point":path,"fs_type":e.fs_type,"unit":id,"status":status,"reason":reason,"expected":e.expected,"automount":e.automount}));
    }
    if rows.len() > MAX_MOUNTS {
        complete = false;
        rows.sort_by_key(|r| !matches!(r["status"].as_str(), Some("failed" | "missing")));
        rows.truncate(MAX_MOUNTS);
    }
    let failures = rows
        .iter()
        .filter(|r| matches!(r["status"].as_str(), Some("failed" | "missing")))
        .count();
    json!({"available":true,"complete":complete,"sampled_at":sampled_at,"failed_count":failures,"mounts":rows,"collector_note":"Mount-table and systemd state only; mounted does not prove filesystem I/O health. Mount paths are never probed."})
}

pub(crate) fn collect_mount_health() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    #[cfg(target_os = "linux")]
    {
        let (Some(fstab), Some(info)) = (
            read_snapshot("/etc/fstab"),
            read_snapshot("/proc/self/mountinfo"),
        ) else {
            return json!({"available":false,"complete":false,"sampled_at":now,"mounts":[],"reason":"inventory_unavailable"});
        };
        let mut args = vec![
            "show".to_string(),
            "--all".into(),
            "--property=Id,Where,Type,LoadState,ActiveState,SubState,Result,UnitFileState".into(),
            "--".into(),
            "*.mount".into(),
            "*.automount".into(),
        ];
        for line in fstab.lines().filter(|l| !l.trim_start().starts_with('#')) {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() >= 4 && p[1].starts_with('/') && p[1].len() <= 1024 && p[2] != "swap" {
                if args.len() >= 2 * MAX_MOUNTS + 6 {
                    break;
                }
                let unit = mount_unit(&unescape(p[1]));
                if p[3].split(',').any(|flag| flag == "x-systemd.automount") {
                    args.push(format!("{}automount", unit.strip_suffix("mount").unwrap()));
                }
                args.push(unit);
            }
        }
        let output = run_cmd_with_timeout(
            "systemctl",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(4),
        );
        let raw = output
            .as_ref()
            .filter(|o| o.stdout.len() <= MAX_INPUT)
            .map(|o| String::from_utf8_lossy(&o.stdout));
        snapshot(
            &fstab,
            &info,
            raw.as_deref(),
            output.as_ref().is_some_and(|o| o.status.success()),
            now,
        )
    }
    #[cfg(not(target_os = "linux"))]
    json!({"available":false,"complete":false,"sampled_at":now,"mounts":[],"reason":"unsupported_platform"})
}
