//! Bounded local inventory. Reads metadata; never installs packages or runs project code.
use crate::collectors::{run_cmd_with_timeout, run_command_with_timeout};
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use w_monitor_sdk::software_inventory::{
    Component, SoftwareInventory, MAX_COMPONENTS, MAX_INVENTORY_BYTES,
};

// openat2 confines container symlinks to that container's root, including absolute
// symlinks. Never read a container-controlled path through an ordinary host open.
fn open_in(root: &File, path: &Path) -> std::io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: 0x10 | 0x02,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd >= 0 {
        Ok(unsafe { File::from_raw_fd(fd as i32) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn read_in(root: &File, path: &Path, limit: usize) -> Option<String> {
    let file = open_in(root, path).ok()?;
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

fn release(raw: &str) -> HashMap<&str, &str> {
    raw.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k, v.trim_matches('"').trim_matches('\'')))
        .collect()
}

fn ecosystem(id: &str, version: &str) -> Option<String> {
    let major = version.split('.').next()?;
    match id {
        "ubuntu" => Some(format!(
            "Ubuntu:{version}{}",
            if version.ends_with(".04") && major.parse::<u32>().ok()? % 2 == 0 {
                ":LTS"
            } else {
                ""
            }
        )),
        "debian" => Some(format!("Debian:{major}")),
        "alpine" => Some(format!(
            "Alpine:v{}",
            version.split('.').take(2).collect::<Vec<_>>().join(".")
        )),
        "almalinux" => Some(format!("AlmaLinux:{major}")),
        "rocky" => Some(format!("Rocky Linux:{major}")),
        _ => None,
    }
}

struct Builder {
    components: BTreeSet<Component>,
    warnings: BTreeSet<String>,
    scopes: BTreeSet<String>,
    deadline: Instant,
    visited: usize,
}

impl Builder {
    fn warning(&mut self, text: impl Into<String>) {
        if self.warnings.len() < 31 {
            self.warnings.insert(
                text.into()
                    .chars()
                    .filter(|c| !c.is_control())
                    .scan(0, |bytes, c| {
                        *bytes += c.len_utf8();
                        (*bytes <= 240).then_some(c)
                    })
                    .collect(),
            );
        }
    }
    fn add(&mut self, ecosystem: &str, name: &str, version: &str, location: &str, kind: &str) {
        if self.components.len() >= MAX_COMPONENTS {
            self.warning("Software inventory component limit reached");
            return;
        }
        if !w_monitor_sdk::software_inventory::supported_ecosystem(ecosystem)
            || ecosystem.len() > 80
            || name.is_empty()
            || version.is_empty()
            || name.len() > 200
            || version.len() > 160
            || location.len() > 240
            || [name, version, location]
                .iter()
                .any(|s| s.chars().any(char::is_control))
        {
            self.warning("Invalid or oversized software identity skipped");
            return;
        }
        self.components.insert(Component {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
            location: location.into(),
            kind: kind.into(),
        });
    }
    fn native(&mut self, root: &File, label: &str, host: bool) -> Option<String> {
        let Some(raw) = read_in(root, Path::new("etc/os-release"), 16384) else {
            self.warning(format!(
                "{label}: OS metadata unavailable (openat2 required)"
            ));
            return None;
        };
        let os = release(&raw);
        let id = os.get("ID").copied().unwrap_or("");
        let version = os.get("VERSION_ID").copied().unwrap_or("");
        let Some(eco) = ecosystem(id, version) else {
            self.warning(format!(
                "{label}: unsupported OS package ecosystem {id} {version}"
            ));
            return None;
        };
        self.scopes.insert(format!("{label}: {eco}"));
        if matches!(id, "ubuntu" | "debian") {
            if let Some(raw) = read_in(root, Path::new("var/lib/dpkg/status"), 16 * 1024 * 1024) {
                let packages = parse_dpkg(&raw);
                if raw
                    .lines()
                    .filter(|l| *l == "Status: install ok installed")
                    .count()
                    != packages.len()
                {
                    self.warning(format!("{label}: malformed dpkg package metadata"));
                }
                if packages.is_empty() {
                    self.warning(format!("{label}: empty dpkg inventory"));
                }
                let kernel_sources: BTreeSet<_> = packages
                    .iter()
                    .filter(|p| p.0.starts_with("linux-image-"))
                    .map(|p| p.1.clone())
                    .collect();
                let running = if host {
                    std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()
                } else {
                    None
                };
                let mut found_kernel = false;
                for (binary, source, ver) in packages {
                    let kernel = kernel_sources.contains(&source);
                    if kernel
                        && !running.as_ref().is_some_and(|r| {
                            binary == format!("linux-image-{}", r.trim())
                                || binary == format!("linux-image-unsigned-{}", r.trim())
                        })
                    {
                        continue;
                    }
                    if kernel {
                        found_kernel = true;
                    }
                    if source.starts_with("linux-signed") || source.is_empty() {
                        self.warning(format!("{label}: signed kernel provenance unavailable"));
                        continue;
                    }
                    self.add(
                        &eco,
                        &source,
                        &ver,
                        label,
                        if kernel {
                            "running_kernel"
                        } else {
                            "source_package"
                        },
                    );
                }
                if host && !found_kernel {
                    self.warning("host: running kernel is not mapped to an installed package");
                }
            } else {
                self.warning(format!("{label}: dpkg status unavailable"));
            }
        } else if id == "alpine" {
            if host {
                self.warning("Alpine running kernel requires separate verification");
            }
            if let Some(raw) = read_in(root, Path::new("lib/apk/db/installed"), 16 * 1024 * 1024) {
                for block in raw.split("\n\n") {
                    let fields: HashMap<_, _> =
                        block.lines().filter_map(|l| l.split_once(':')).collect();
                    if let (Some(name), Some(ver)) =
                        (fields.get("o").or_else(|| fields.get("P")), fields.get("V"))
                    {
                        self.add(&eco, name, ver, label, "source_package");
                    }
                }
            } else {
                self.warning(format!("{label}: apk inventory unavailable"));
            }
        } else if host {
            if let Some(out) = run_cmd_with_timeout(
                "rpm",
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n",
                ],
                Duration::from_secs(5),
            )
            .filter(|o| o.status.success() && o.stdout.len() < 8 * 1024 * 1024)
            {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some((name, ver)) = line.split_once('\t') {
                        if name.starts_with("kernel") {
                            continue;
                        }
                        self.add(&eco, name, ver, label, "binary_package");
                    }
                }
                self.warning("RPM running kernel requires separate verification");
            } else {
                self.warning(format!("{label}: rpm inventory unavailable"));
            }
        } else {
            self.warning(format!("{label}: RPM container inventory requires an SBOM"));
        }
        Some(id.into())
    }

    fn document(&mut self, raw: &str, path: &Path, label: &str) {
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        let location = format!("{label}:{}", path.display());
        let installed = name == ".package-lock.json"
            || name == "METADATA"
            || name == "installed.json"
            || name.ends_with(".deps.json");
        let kind = if installed {
            "installed_metadata"
        } else {
            "lockfile"
        };
        match name {
            "package-lock.json" | ".package-lock.json" => {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
                    self.warning(format!("Invalid {location}"));
                    return;
                };
                if let Some(packages) = v["packages"].as_object() {
                    for (path, p) in packages {
                        if path.is_empty() || p["link"] == true {
                            continue;
                        }
                        let Some(ver) = p["version"].as_str() else {
                            self.warning(format!("Unpinned dependency: {location}"));
                            continue;
                        };
                        let pkg = p["name"]
                            .as_str()
                            .or_else(|| path.rsplit_once("node_modules/").map(|(_, n)| n));
                        if let Some(pkg) = pkg {
                            self.add("npm", pkg, ver, &location, kind);
                        }
                    }
                } else {
                    self.warning(format!("Unsupported npm lock format: {location}"));
                }
            }
            "composer.lock" | "installed.json" => {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
                    self.warning(format!("Invalid {location}"));
                    return;
                };
                if let Some(packages) = v["packages"].as_array().or_else(|| v.as_array()) {
                    for p in packages {
                        if let (Some(n), Some(v)) = (p["name"].as_str(), p["version"].as_str()) {
                            self.add("Packagist", n, v.trim_start_matches('v'), &location, kind);
                        }
                    }
                } else {
                    self.warning(format!("Missing Composer packages: {location}"));
                }
            }
            "Pipfile.lock" => {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
                    self.warning(format!("Invalid {location}"));
                    return;
                };
                if let Some(packages) = v["default"].as_object() {
                    for (name, p) in packages {
                        if let Some(ver) = p["version"]
                            .as_str()
                            .and_then(|v| v.strip_prefix("=="))
                            .filter(|v| !v.contains('*'))
                        {
                            self.add("PyPI", name, ver, &location, kind);
                        } else {
                            self.warning(format!("Unpinned Python dependency: {location}"));
                        }
                    }
                } else {
                    self.warning(format!("Missing Python dependencies: {location}"));
                }
            }
            "Gemfile.lock" => {
                let mut rubygems = false;
                for line in raw.lines() {
                    if line == "GEM" {
                        rubygems = true;
                        continue;
                    }
                    if !line.starts_with(' ') {
                        rubygems = false;
                    }
                    if rubygems && line.starts_with("    ") && !line.starts_with("     ") {
                        if let Some((name, version)) = line.trim().split_once(" (") {
                            self.add(
                                "RubyGems",
                                name,
                                version.trim_end_matches(')'),
                                &location,
                                kind,
                            );
                        }
                    }
                }
                if raw.lines().any(|l| matches!(l, "GIT" | "PATH")) {
                    self.warning(format!("Unresolved Ruby source dependency: {location}"));
                }
            }
            name if name.ends_with(".deps.json") => {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
                    self.warning(format!("Invalid {location}"));
                    return;
                };
                if let Some(libraries) = v["libraries"].as_object() {
                    for (key, value) in libraries {
                        if value["type"] == "package" {
                            if let Some((name, version)) = key.rsplit_once('/') {
                                self.add("NuGet", name, version, &location, kind);
                            } else {
                                self.warning(format!("Invalid .NET package identity: {location}"));
                            }
                        }
                    }
                } else {
                    self.warning(format!("Missing .NET library metadata: {location}"));
                }
            }
            "METADATA" => {
                let fields: HashMap<_, _> = raw
                    .lines()
                    .take_while(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(": "))
                    .collect();
                if let (Some(n), Some(v)) = (fields.get("Name"), fields.get("Version")) {
                    self.add("PyPI", n, v, &location, kind);
                } else {
                    self.warning(format!("Missing installed Python identity: {location}"));
                }
            }
            "requirements.txt" => {
                for line in raw
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    if let Some((n, v)) = line.split_once("==") {
                        let ver = v.split([' ', ';']).next().unwrap_or("");
                        if !ver.contains('*') && !n.contains(['/', ':', ' ']) {
                            self.add(
                                "PyPI",
                                n.split('[').next().unwrap_or(n),
                                ver,
                                &location,
                                kind,
                            );
                            continue;
                        }
                    }
                    self.warning(format!("Unresolved requirements: {location}"));
                }
            }
            "Cargo.lock" => {
                for package in raw.split("[[package]]").skip(1) {
                    let fields: HashMap<_, _> = package
                        .lines()
                        .filter_map(|l| l.trim().split_once(" = "))
                        .map(|(k, v)| (k, v.trim_matches('"')))
                        .collect();
                    if fields.get("source").is_some_and(|s| {
                        s.starts_with("registry+https://github.com/rust-lang/crates.io-index")
                            || s.starts_with("registry+https://index.crates.io/")
                    }) {
                        if let (Some(n), Some(v)) = (fields.get("name"), fields.get("version")) {
                            self.add("crates.io", n, v, &location, kind);
                        }
                    }
                }
            }
            "go.mod" => {
                if raw.lines().any(|l| l.trim().starts_with("replace ")) {
                    self.warning(format!("Go replacements require built SBOM: {location}"));
                    return;
                }
                let mut requires = false;
                for line in raw.lines().map(str::trim) {
                    if line == "require (" {
                        requires = true;
                        continue;
                    }
                    if line == ")" {
                        requires = false;
                        continue;
                    }
                    let words: Vec<_> = line
                        .strip_prefix("require ")
                        .or(requires.then_some(line))
                        .unwrap_or("")
                        .split_whitespace()
                        .collect();
                    if words.len() >= 2 && words[1].starts_with('v') {
                        self.add("Go", words[0], words[1], &location, kind);
                    }
                }
            }
            "bom.json" | "security-sbom.json" => {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
                    self.warning(format!("Invalid SBOM: {location}"));
                    return;
                };
                let mut remaining = MAX_COMPONENTS;
                if let Some(component) = v.pointer("/metadata/component") {
                    self.sbom_components(
                        std::slice::from_ref(component),
                        &location,
                        0,
                        &mut remaining,
                    );
                }
                if let Some(components) = v.get("components") {
                    if let Some(cs) = components.as_array() {
                        self.sbom_components(cs, &location, 0, &mut remaining);
                    } else {
                        self.warning(format!("Invalid SBOM components: {location}"));
                    }
                } else if v.pointer("/metadata/component").is_none() {
                    self.warning(format!("CycloneDX components required: {location}"));
                }
            }
            _ => {}
        }
    }

    fn sbom_components(
        &mut self,
        components: &[serde_json::Value],
        location: &str,
        depth: usize,
        remaining: &mut usize,
    ) {
        for component in components {
            if depth > 16
                || *remaining == 0
                || self.components.len() >= MAX_COMPONENTS
                || Instant::now() > self.deadline
            {
                self.warning(format!("SBOM traversal limit reached: {location}"));
                break;
            }
            *remaining -= 1;
            if let Some((eco, name, version)) = component["purl"].as_str().and_then(parse_purl) {
                self.add(&eco, &name, &version, location, "sbom");
            } else {
                self.warning(format!("Unmapped SBOM component: {location}"));
            }
            if let Some(children) = component.get("components") {
                if let Some(children) = children.as_array() {
                    self.sbom_components(children, location, depth + 1, remaining);
                } else {
                    self.warning(format!("Invalid nested SBOM components: {location}"));
                }
            }
        }
    }

    fn walk(&mut self, root: &File, path: &Path, label: &str, depth: usize) {
        if Instant::now() > self.deadline
            || self.visited >= 6000
            || self.components.len() >= MAX_COMPONENTS
        {
            self.warning("Inventory traversal limit reached; coverage is partial");
            return;
        }
        let dir = match open_in(root, path) {
            Ok(dir) if dir.metadata().is_ok_and(|m| m.is_dir()) => dir,
            Ok(_) => return,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.warning(format!(
                        "Cannot inspect directory: {label}:{}",
                        path.display()
                    ));
                }
                return;
            }
        };
        let Ok(entries) = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())) else {
            self.warning(format!("Unreadable directory: {label}:{}", path.display()));
            return;
        };
        for (index, entry) in entries.enumerate() {
            if index >= 1500 {
                self.warning(format!("Directory entry limit: {label}:{}", path.display()));
                break;
            }
            let Ok(entry) = entry else {
                self.warning(format!(
                    "Directory entry unreadable: {label}:{}",
                    path.display()
                ));
                continue;
            };
            self.visited += 1;
            if self.visited >= 6000 || Instant::now() > self.deadline {
                self.warning("Inventory traversal limit reached; coverage is partial");
                break;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let next = path.join(name.as_ref());
            if matches!(
                name.as_ref(),
                "package-lock.json"
                    | ".package-lock.json"
                    | "composer.lock"
                    | "Cargo.lock"
                    | "go.mod"
                    | "requirements.txt"
                    | "Pipfile.lock"
                    | "Gemfile.lock"
                    | "bom.json"
                    | "security-sbom.json"
            ) || name.ends_with(".deps.json")
                || (name == "METADATA" && path.to_string_lossy().ends_with(".dist-info"))
            {
                match read_in(root, &next, 2 * 1024 * 1024) {
                    Some(raw) => self.document(&raw, &next, label),
                    None => self.warning(format!(
                        "Unreadable/oversized manifest: {label}:{}",
                        next.display()
                    )),
                }
            } else if name == "vendor" {
                let metadata = next.join("composer/installed.json");
                if let Some(raw) = read_in(root, &metadata, 2 * 1024 * 1024) {
                    self.document(&raw, &metadata, label);
                } else {
                    self.warning(format!(
                        "Vendor directory has no readable installed Composer metadata: {label}:{}",
                        next.display()
                    ));
                }
            } else if name == "node_modules" {
                let lock = next.join(".package-lock.json");
                if let Some(raw) = read_in(root, &lock, 2 * 1024 * 1024) {
                    self.document(&raw, &lock, label);
                } else {
                    self.warning(format!(
                        "node_modules lacks installed lock metadata: {label}:{}",
                        next.display()
                    ));
                }
            } else if !matches!(
                name.as_ref(),
                ".git" | "target" | ".cache" | ".npm" | "vendor" | "proc" | "sys" | "dev"
            ) && entry.file_type().is_ok_and(|t| t.is_dir())
            {
                if depth < 6 {
                    self.walk(root, &next, label, depth + 1);
                } else {
                    self.warning(format!("Directory depth limit: {label}:{}", next.display()));
                }
            }
        }
    }
}

/// Dpkg source versions preserve distro backports; signed images use Built-Using.
fn parse_dpkg(raw: &str) -> Vec<(String, String, String)> {
    raw.split("\n\n")
        .filter_map(|block| {
            let f: HashMap<_, _> = block.lines().filter_map(|l| l.split_once(": ")).collect();
            if f.get("Status") != Some(&"install ok installed") {
                return None;
            }
            let binary = *f.get("Package")?;
            let version = *f.get("Version")?;
            let source = f.get("Source").copied().unwrap_or(binary);
            let (mut name, mut ver) = source
                .split_once(" (")
                .map(|(n, v)| (n, v.trim_end_matches(')')))
                .unwrap_or((source, version));
            if name.starts_with("linux-signed") {
                let built = f.get("Built-Using").copied().unwrap_or("");
                let mut sources = built.split(',').filter_map(|entry| {
                    let (name, version) = entry.trim().split_once(" (= ")?;
                    (name.starts_with("linux")
                        && !name.starts_with("linux-signed")
                        && !name.starts_with("linux-meta"))
                    .then_some((name, version.trim_end_matches(')')))
                });
                if let Some((n, v)) = sources.next().filter(|_| sources.next().is_none()) {
                    name = n;
                    ver = v;
                }
            }
            Some((binary.into(), name.into(), ver.into()))
        })
        .collect()
}

fn parse_purl(purl: &str) -> Option<(String, String, String)> {
    let value = purl.strip_prefix("pkg:")?.split(['?', '#']).next()?;
    let (package, ver) = value.rsplit_once('@')?;
    let (kind, name) = package.split_once('/')?;
    let decode = |s: &str| -> Option<String> {
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?, 16).ok()?,
                );
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    };
    let ecosystem = match kind {
        "npm" => "npm",
        "pypi" => "PyPI",
        "golang" => "Go",
        "cargo" => "crates.io",
        "maven" => "Maven",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "gem" => "RubyGems",
        "generic" => "Generic",
        _ => return None,
    };
    let mut name = decode(name)?;
    if kind == "maven" {
        name = name.replace('/', ":");
    }
    Some((ecosystem.into(), name, decode(ver)?))
}

fn trusted_executable(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    for p in canonical.ancestors() {
        let m = std::fs::metadata(p).ok()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return None;
        }
    }
    canonical.is_file().then_some(canonical)
}

fn upstream(builder: &mut Builder, native: Option<&str>) {
    let programs = [
        ("php", "https://github.com/php/php-src", vec!["-n", "-v"]),
        ("nginx", "https://github.com/nginx/nginx", vec!["-v"]),
        (
            "redis-server",
            "https://github.com/redis/redis",
            vec!["--version"],
        ),
        (
            "valkey-server",
            "https://github.com/valkey-io/valkey",
            vec!["--version"],
        ),
        (
            "postgres",
            "https://github.com/postgres/postgres",
            vec!["--version"],
        ),
        (
            "containerd",
            "https://github.com/containerd/containerd",
            vec!["--version"],
        ),
        (
            "runc",
            "https://github.com/opencontainers/runc",
            vec!["--version"],
        ),
        (
            "caddy",
            "https://github.com/caddyserver/caddy",
            vec!["version"],
        ),
    ];
    let mut seen = BTreeSet::new();
    for (name, repo, args) in programs {
        for dir in ["/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin"] {
            if Instant::now() > builder.deadline {
                builder.warning("Upstream binary probe time limit reached");
                return;
            }
            let path = Path::new(dir).join(name);
            let Some(path) = trusted_executable(&path) else {
                continue;
            };
            if !seen.insert(path.clone()) {
                continue;
            }
            let path = path.to_string_lossy();
            // Distro versions must be checked against distro advisories, never upstream ranges.
            if matches!(native, Some("ubuntu" | "debian")) {
                match run_cmd_with_timeout("dpkg-query", &["-S", &path], Duration::from_secs(2)) {
                    Some(o) if o.status.success() => continue,
                    Some(o) if o.status.code() == Some(1) => {}
                    _ => {
                        builder.warning(format!("Cannot establish binary provenance: {path}"));
                        continue;
                    }
                }
            } else if native.is_some() && !path.starts_with("/usr/local/") {
                continue;
            }
            let Some(out) = run_cmd_with_timeout(&path, &args, Duration::from_secs(2))
                .filter(|o| o.status.success())
            else {
                builder.warning(format!("Version probe failed: {name}"));
                continue;
            };
            let output = format!(
                "{} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let ver = output
                .split_whitespace()
                .flat_map(|s| s.split(['=', '/']))
                .map(|s| s.trim_start_matches('v').trim_end_matches([',', ')']))
                .find(|v| {
                    v.split('.').count() >= 3
                        && v.as_bytes().first().is_some_and(u8::is_ascii_digit)
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
                });
            if let Some(ver) = ver {
                builder.add("GIT", repo, ver, &path, "upstream_binary");
            } else {
                builder.warning(format!("Unknown upstream binary version: {name}"));
            }
        }
    }
    builder
        .scopes
        .insert("host: trusted standalone program probes".into());
}

fn run_local_docker(
    docker: &Path,
    args: &[&str],
    timeout: Duration,
) -> Option<std::process::Output> {
    let mut command = std::process::Command::new(docker);
    // A remote daemon's PIDs cannot identify this host's /proc filesystem.
    command.args(["--host", "unix:///var/run/docker.sock"]);
    for key in [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_API_VERSION",
    ] {
        command.env_remove(key);
    }
    command.args(args);
    run_command_with_timeout(&mut command, timeout)
}

fn docker_ids(raw: &[u8]) -> Option<Vec<&str>> {
    // Retain one extra ID to report truncation without copying an unbounded fleet list.
    std::str::from_utf8(raw)
        .ok()?
        .lines()
        .take(17)
        .map(|id| (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then_some(id))
        .collect()
}

pub fn collect(data_dir: &Path) -> SoftwareInventory {
    let mut builder = Builder {
        components: BTreeSet::new(),
        warnings: BTreeSet::new(),
        scopes: BTreeSet::new(),
        deadline: Instant::now() + Duration::from_secs(45),
        visited: 0,
    };
    if let Ok(root) = File::open("/") {
        let native = builder.native(&root, "host", true);
        upstream(&mut builder, native.as_deref());
        let mut roots: BTreeSet<PathBuf> = [
            "/opt",
            "/srv",
            "/app",
            "/var/www",
            "/usr/local/lib",
            "/usr/lib/python3/dist-packages",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        // Discover service working directories without reading argv, environment or credentials.
        if let Ok(procs) = std::fs::read_dir("/proc") {
            for (index, p) in procs.enumerate() {
                if index >= 4096 || Instant::now() > builder.deadline {
                    builder
                        .warning("Process discovery limit reached; service roots are incomplete");
                    break;
                }
                let Ok(p) = p else {
                    builder.warning("Process directory entry unreadable");
                    continue;
                };
                if p.file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                {
                    match std::fs::read_link(p.path().join("cwd")) {
                        Ok(cwd) => {
                            if cwd.components().count() >= 3
                                && !["/proc", "/sys", "/dev", "/tmp", "/run"]
                                    .iter()
                                    .any(|d| cwd.starts_with(d))
                            {
                                roots.insert(cwd);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                            builder.warning("Some process working directories are not readable");
                        }
                        _ => {} // Exited processes and kernel threads have no working directory.
                    }
                }
            }
        } else {
            builder.warning("Process directories unavailable; service roots are incomplete");
        }
        let sbom = data_dir.join("security-sbom.json");
        if let Some(raw) = read_in(&root, &sbom, 2 * 1024 * 1024) {
            builder.document(&raw, &sbom, "host");
        }
        if roots.len() > 24 {
            builder.warning("Service directory limit reached (24 roots)");
        }
        for path in roots.into_iter().take(24) {
            builder.walk(&root, &path, "host", 0);
        }
        builder
            .scopes
            .insert("host: bounded service directories, lockfiles and installed metadata".into());
    } else {
        builder.warning("Host filesystem unavailable");
    }
    // Inspect only running containers. No docker exec, image extraction, start or pull.
    let docker = ["/usr/bin/docker", "/usr/local/bin/docker"]
        .iter()
        .find_map(|p| trusted_executable(Path::new(p)));
    if let Some(docker) = docker {
        if let Some(out) =
            run_local_docker(&docker, &["ps", "-q", "--no-trunc"], Duration::from_secs(3))
                .filter(|o| o.status.success())
        {
            let ids = docker_ids(&out.stdout).unwrap_or_else(|| {
                builder.warning("Invalid local Docker inventory response");
                vec![]
            });
            if ids.len() > 16 {
                builder.warning("Container scan limit reached (16 running containers)");
            }
            for id in ids.iter().take(16) {
                if Instant::now() > builder.deadline {
                    builder.warning("Container inventory time limit reached");
                    break;
                }
                let Some(out) = run_local_docker(
                    &docker,
                    &["inspect", "--format", "{{.State.Pid}}", id],
                    Duration::from_secs(2),
                )
                .filter(|o| o.status.success()) else {
                    builder.warning("Docker container inspection failed");
                    continue;
                };
                let Some(pid) = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|p| *p > 1)
                else {
                    builder.warning("Container stopped during inventory");
                    continue;
                };
                let label = format!("container:{}", &id[..12]);
                let Ok(root) = File::open(format!("/proc/{pid}/root")) else {
                    builder.warning(format!("{label}: filesystem not accessible"));
                    continue;
                };
                builder.native(&root, &label, false);
                for dir in ["/app", "/opt", "/srv", "/var/www", "/usr/local/lib"] {
                    builder.walk(&root, Path::new(dir), &label, 0);
                }
            }
            builder.scopes.insert(
                "local Docker socket: bounded running-container filesystem inventory".into(),
            );
        } else {
            builder.warning("Installed Docker runtime is not accessible for inventory");
        }
    } else {
        builder
            .scopes
            .insert("Docker executable not found; container inventory not performed".into());
    }
    builder.scopes.insert("Other container runtimes, stopped images and arbitrary binary dependencies require an SBOM".into());
    let mut result = SoftwareInventory {
        schema_version: 1,
        revision: String::new(),
        checked_at: chrono::Utc::now().timestamp(),
        components: builder.components.into_iter().collect(),
        warnings: builder.warnings.into_iter().collect(),
        scopes: builder.scopes.into_iter().take(64).collect(),
    };
    while serde_json::to_vec(&result).unwrap_or_default().len() > MAX_INVENTORY_BYTES - 256 {
        result.components.pop();
        if !result
            .warnings
            .iter()
            .any(|s| s == "Inventory byte limit reached")
        {
            result.warnings.push("Inventory byte limit reached".into());
        }
    }
    result.revision = result.fingerprint();
    result
}
