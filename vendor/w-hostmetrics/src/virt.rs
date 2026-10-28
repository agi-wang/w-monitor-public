//! Virtualization and cloud-vendor detection.
//!
//! The "is this a VM / container, and whose cloud" question is re-answered in
//! several products with diverging mechanisms (DMI table vs `systemd-detect-virt`
//! vs cpuinfo flag) and diverging label tables. This is the superset: one
//! canonical vendor table, plus configurable probing ([`VirtOptions`]) that can
//! run `systemd-detect-virt` first and read either DMI path, with the raw probe
//! outputs exposed so a consumer can reproduce its own labelling if it must.

/// Probe precedence for [`detect_virtualization_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOrder {
    /// DMI/cpuinfo vendor table first (0.1.0 behaviour).
    DmiFirst,
    /// `systemd-detect-virt` first, fall back to the DMI table.
    SystemdFirst,
    /// Trust the cpuinfo `hypervisor` flag as the gate, then the table.
    CpuinfoFlagFirst,
}

/// Which DMI sysfs path to read (symlinked to the same data, different literal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmiPath {
    /// `/sys/class/dmi/id` (0.1.0 default).
    ClassDmi,
    /// `/sys/devices/virtual/dmi/id`.
    DevicesVirtualDmi,
}

/// Knobs for [`detect_virtualization_with`]. `Default` reproduces 0.1.0
/// `detect_virtualization()` exactly (DMI table only, no subprocess).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtOptions {
    pub order: ProbeOrder,
    /// Run the `systemd-detect-virt` binary (a subprocess). Off by default.
    pub run_systemd_detect_virt: bool,
    pub dmi_path: DmiPath,
    /// Match the cpuinfo `hypervisor` flag as a whole token (true) vs substring.
    pub cpuinfo_token_match: bool,
}

impl Default for VirtOptions {
    fn default() -> Self {
        VirtOptions {
            order: ProbeOrder::DmiFirst,
            run_systemd_detect_virt: false,
            dmi_path: DmiPath::ClassDmi,
            cpuinfo_token_match: true,
        }
    }
}

/// What we could learn about the platform we're running on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Virtualization {
    /// Best-effort canonical platform name (`"kvm"`, `"aws-ec2"`, `"container"`).
    pub detected: Option<String>,
    /// The `hypervisor` CPU flag is present in `/proc/cpuinfo`.
    pub hypervisor_flag: bool,
    /// Running inside a container (docker/k8s/lxc/containerd/podman).
    pub container: bool,
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    /// Raw `systemd-detect-virt` stdout (only when that probe ran).
    pub raw_detect_virt: Option<String>,
    /// Raw `"{sys_vendor} {product_name}"` DMI string.
    pub raw_dmi: Option<String>,
    /// Which container marker matched (`"docker"`/`"kubepods"`/`"lxc"`/…).
    pub container_kind: Option<String>,
}

impl Virtualization {
    /// Convenience: virtualized or containerized at all.
    pub fn is_virtual(&self) -> bool {
        self.hypervisor_flag || self.container || self.detected.is_some()
    }
}

/// Canonical cloud/hypervisor vendor table: substring needle → canonical name.
/// Order matters — earlier entries win. **Load-bearing; never reorder or change
/// an existing normalized output** (only append).
const VENDOR_TABLE: &[(&str, &str)] = &[
    ("kvm", "kvm"),
    ("qemu", "qemu"),
    ("openstack", "openstack"),
    ("vmware", "vmware"),
    ("virtualbox", "virtualbox"),
    ("xen", "xen"),
    ("hyper-v", "hyper-v"),
    ("microsoft corporation", "hyper-v"),
    ("amazon ec2", "aws-ec2"),
    ("google compute", "gcp"),
    ("digitalocean", "digitalocean"),
    ("alibaba cloud", "alibaba-cloud"),
    ("tencent", "tencent-cloud"),
];

const CONTAINER_MARKERS: &[&str] = &["docker", "kubepods", "containerd", "lxc", "podman"];

/// True if `/proc/cpuinfo` advertises the `hypervisor` flag (case-insensitive,
/// whole whitespace-delimited token).
pub fn cpuinfo_has_hypervisor(cpuinfo: &str) -> bool {
    cpuinfo
        .split_whitespace()
        .any(|word| word.eq_ignore_ascii_case("hypervisor"))
}

/// Map DMI vendor/product strings + cpuinfo to a canonical platform name.
/// `container` short-circuits to `"container"`. Case-insensitive substring over
/// the combined haystack; falls back to `"hypervisor"` then `None`.
pub fn detect_platform_name(
    sys_vendor: Option<&str>,
    product_name: Option<&str>,
    cpuinfo: &str,
    container: bool,
) -> Option<String> {
    if container {
        return Some("container".to_string());
    }
    let haystack = format!(
        "{} {} {}",
        sys_vendor.unwrap_or_default(),
        product_name.unwrap_or_default(),
        cpuinfo
    )
    .to_ascii_lowercase();
    for (needle, name) in VENDOR_TABLE {
        if haystack.contains(needle) {
            return Some((*name).to_string());
        }
    }
    if haystack.contains("hypervisor") {
        return Some("hypervisor".to_string());
    }
    None
}

/// Map `systemd-detect-virt` output to a canonical platform name. Returns `None`
/// for `"none"`/empty. Container techs (`lxc`, `docker`, …) map to `"container"`.
pub fn canonicalize_systemd_virt(raw: &str) -> Option<String> {
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v == "none" {
        return None;
    }
    if CONTAINER_MARKERS.contains(&v.as_str())
        || v == "systemd-nspawn"
        || v == "openvz"
        || v == "rkt"
        || v == "wsl"
    {
        return Some("container".to_string());
    }
    let canonical = match v.as_str() {
        "oracle" => "virtualbox",
        "microsoft" => "hyper-v",
        "amazon" => "aws-ec2",
        "qemu" => "qemu",
        "kvm" => "kvm",
        "vmware" => "vmware",
        "xen" => "xen",
        "bochs" => "qemu",
        other => other,
    };
    Some(canonical.to_string())
}

/// Probe the live host with default options (0.1.0-compatible).
pub fn detect_virtualization() -> Virtualization {
    detect_virtualization_with(&VirtOptions::default())
}

/// Probe the live host with explicit options. Reads DMI (`opts.dmi_path`),
/// `/proc/cpuinfo`, `/proc/1/cgroup`, `/.dockerenv`, `/run/.containerenv`, and
/// optionally runs `systemd-detect-virt`.
pub fn detect_virtualization_with(opts: &VirtOptions) -> Virtualization {
    let dmi_base = match opts.dmi_path {
        DmiPath::ClassDmi => "/sys/class/dmi/id",
        DmiPath::DevicesVirtualDmi => "/sys/devices/virtual/dmi/id",
    };
    let sys_vendor = read_trimmed(&format!("{dmi_base}/sys_vendor"));
    let product_name = read_trimmed(&format!("{dmi_base}/product_name"));
    let product_version = read_trimmed(&format!("{dmi_base}/product_version"));
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cgroup = std::fs::read_to_string("/proc/1/cgroup").unwrap_or_default();

    let container_kind = if std::path::Path::new("/.dockerenv").exists() {
        Some("docker".to_string())
    } else if std::path::Path::new("/run/.containerenv").exists() {
        Some("podman".to_string())
    } else {
        CONTAINER_MARKERS
            .iter()
            .find(|m| cgroup.contains(*m))
            .map(|m| (*m).to_string())
    };
    let container = container_kind.is_some();
    let hypervisor_flag = cpuinfo_has_hypervisor(&cpuinfo);

    let raw_detect_virt = if opts.run_systemd_detect_virt {
        run_systemd_detect_virt()
    } else {
        None
    };
    let systemd_label = raw_detect_virt
        .as_deref()
        .and_then(canonicalize_systemd_virt);

    let table_label = detect_platform_name(
        sys_vendor.as_deref(),
        product_name.as_deref(),
        &cpuinfo,
        container,
    );

    let detected = match opts.order {
        ProbeOrder::DmiFirst => table_label.or(systemd_label),
        ProbeOrder::SystemdFirst => systemd_label.or(table_label),
        ProbeOrder::CpuinfoFlagFirst => {
            if container {
                Some("container".to_string())
            } else if hypervisor_flag {
                table_label
                    .or(systemd_label)
                    .or(Some("hypervisor".to_string()))
            } else {
                systemd_label.or(table_label)
            }
        }
    };

    let raw_dmi = match (&sys_vendor, &product_name) {
        (None, None) => None,
        (a, b) => Some(
            format!(
                "{} {}",
                a.clone().unwrap_or_default(),
                b.clone().unwrap_or_default()
            )
            .trim()
            .to_string(),
        ),
    };

    Virtualization {
        detected,
        hypervisor_flag,
        container,
        sys_vendor,
        product_name,
        product_version,
        raw_detect_virt,
        raw_dmi,
        container_kind,
    }
}

fn run_systemd_detect_virt() -> Option<String> {
    let out = std::process::Command::new("systemd-detect-virt")
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().and_then(|content| {
        let value = content.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}
