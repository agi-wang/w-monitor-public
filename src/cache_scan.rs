use parking_lot::Mutex;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;
use tracing::{info, warn};

#[derive(Default, Clone, Copy)]
struct CacheScanTotals {
    huggingface: u64,
    modelscope: u64,
    ollama: u64,
    lmstudio: u64,
    pip: u64,
    conda_envs: u64,
    conda_pkgs: u64,
    torch: u64,
    vllm: u64,
    local_models: u64,
}

impl CacheScanTotals {
    fn grand_total(self) -> u64 {
        self.huggingface
            + self.modelscope
            + self.ollama
            + self.lmstudio
            + self.pip
            + self.conda_envs
            + self.conda_pkgs
            + self.torch
            + self.vllm
            + self.local_models
    }
}

/// Shared cache scan results — restored across agent restarts and refreshed daily.
pub struct CacheScanCache {
    pub results: Option<serde_json::Value>,
    pub last_updated: Option<Instant>,
    completed_at_unix_secs: Option<u64>,
}

impl CacheScanCache {
    pub fn new() -> Self {
        Self {
            results: None,
            last_updated: None,
            completed_at_unix_secs: None,
        }
    }

    pub fn load(path: &Path) -> Self {
        match load_persisted_cache_scan(path) {
            Ok(Some(state)) => {
                let now = unix_now_secs();
                let age = now.saturating_sub(state.completed_at_unix_secs);
                info!(
                    "cache_scan: restored last complete result from disk (age {}s)",
                    age
                );
                Self {
                    results: Some(state.result),
                    last_updated: Instant::now().checked_sub(Duration::from_secs(age)),
                    completed_at_unix_secs: Some(state.completed_at_unix_secs),
                }
            }
            Ok(None) => Self::new(),
            Err(error) => {
                warn!("cache_scan: ignored persisted state: {error}");
                Self::new()
            }
        }
    }
}

/// Timeout for a single cache scan. Machines with very large model stores
/// (e.g. 16 TB) can otherwise sustain filesystem reads for minutes. The last
/// complete result is retained when this budget is exhausted.
const SCAN_TIMEOUT_SECS: u64 = 60;
const PER_DIRECTORY_TIMEOUT_SECS: u64 = 30;
const HOME_USAGE_TIMEOUT_SECS: u64 = 5;
const HOME_USAGE_ENTRY_LIMIT: usize = 10_000;
const CACHE_SCAN_INTERVAL_SECS: u64 = 24 * 3600;
const INITIAL_SCAN_DELAY_SECS: u64 = 60;
const INITIAL_SCAN_JITTER_WINDOW_SECS: u64 = 4 * 60;
const CACHE_SCAN_STATE_SCHEMA: u8 = 1;
const MAX_PERSISTED_STATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCacheScan {
    schema_version: u8,
    completed_at_unix_secs: u64,
    result: serde_json::Value,
}

#[derive(serde::Serialize)]
struct PersistedCacheScanRef<'a> {
    schema_version: u8,
    completed_at_unix_secs: u64,
    result: &'a serde_json::Value,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_persisted_cache_scan(path: &Path) -> Result<Option<PersistedCacheScan>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    if metadata.len() > MAX_PERSISTED_STATE_BYTES {
        return Err(format!(
            "{} exceeds the {} byte state limit",
            path.display(),
            MAX_PERSISTED_STATE_BYTES
        ));
    }

    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PERSISTED_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_PERSISTED_STATE_BYTES {
        return Err(format!(
            "{} grew beyond the {} byte state limit",
            path.display(),
            MAX_PERSISTED_STATE_BYTES
        ));
    }
    let state: PersistedCacheScan = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    if state.schema_version != CACHE_SCAN_STATE_SCHEMA {
        return Err(format!(
            "unsupported schema {} in {}",
            state.schema_version,
            path.display()
        ));
    }
    if state.completed_at_unix_secs > unix_now_secs() {
        return Err(format!(
            "completion timestamp is in the future in {}",
            path.display()
        ));
    }
    if !state.result.is_object() {
        return Err(format!("result is not an object in {}", path.display()));
    }
    Ok(Some(state))
}

fn persist_cache_scan(
    path: &Path,
    result: &serde_json::Value,
    completed_at_unix_secs: u64,
) -> Result<(), String> {
    let state = PersistedCacheScanRef {
        schema_version: CACHE_SCAN_STATE_SCHEMA,
        completed_at_unix_secs,
        result,
    };
    let bytes = serde_json::to_vec(&state).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_PERSISTED_STATE_BYTES {
        return Err(format!(
            "serialized state exceeds the {} byte limit",
            MAX_PERSISTED_STATE_BYTES
        ));
    }

    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let write_result = (|| -> Result<(), String> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temp_path)
            .map_err(|error| format!("cannot create {}: {error}", temp_path.display()))?;
        std::io::Write::write_all(&mut file, &bytes)
            .map_err(|error| format!("cannot write {}: {error}", temp_path.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", temp_path.display()))?;
        replace_persisted_file(&temp_path, path).map_err(|error| {
            format!(
                "cannot replace {} with {}: {error}",
                path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn replace_persisted_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    // Unix rename replaces the destination atomically. Windows rename does
    // not replace an existing file, so retain restart persistence there with
    // a best-effort remove/rename fallback.
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(temp_path, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Cooperative cancellation shared by the async scheduler and every blocking
/// filesystem walk in one scan attempt. The global deadline is deliberately
/// checked inside directory and classification loops: dropping a Tokio
/// `spawn_blocking` handle does not stop its thread.
#[derive(Clone)]
struct ScanControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl ScanControl {
    fn new(timeout: Duration) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + timeout,
        }
    }

    #[cfg(test)]
    fn with_deadline(deadline: Instant) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline,
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn should_stop(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
}

/// Ensures aborting the async scheduler also asks an already-running blocking
/// scan to stop. On the normal timeout path we additionally retain and await
/// the JoinHandle, so the worker cannot continue detached into the next day.
struct CancelScanOnDrop(ScanControl);

impl Drop for CancelScanOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn stable_jitter_secs(seed: &[u8], window_secs: u64) -> u64 {
    if window_secs == 0 {
        return 0;
    }

    // FNV-1a is sufficient here and, unlike a randomized HashMap hasher,
    // produces the same startup offset after every service restart.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash % window_secs
}

fn startup_jitter_seed() -> Vec<u8> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(value) = std::fs::read(path) {
            let value = value
                .into_iter()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
            if !value.is_empty() {
                return value;
            }
        }
    }

    std::env::var_os("HOSTNAME")
        .map(|value| value.to_string_lossy().into_owned().into_bytes())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| b"w-monitor-cache-scan".to_vec())
}

fn initial_cache_scan_delay() -> Duration {
    initial_cache_scan_delay_for_seed(&startup_jitter_seed())
}

fn initial_cache_scan_delay_for_seed(seed: &[u8]) -> Duration {
    Duration::from_secs(
        INITIAL_SCAN_DELAY_SECS + stable_jitter_secs(seed, INITIAL_SCAN_JITTER_WINDOW_SECS),
    )
}

fn first_cache_scan_delay(completed_at_unix_secs: Option<u64>, now: u64) -> Duration {
    if let Some(completed_at) = completed_at_unix_secs {
        if let Some(age) = now.checked_sub(completed_at) {
            if age < CACHE_SCAN_INTERVAL_SECS {
                return Duration::from_secs(CACHE_SCAN_INTERVAL_SECS - age);
            }
        }
    }
    initial_cache_scan_delay()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanAttemptOutcome {
    Success,
    Panic,
    Timeout,
}

fn next_cache_scan_interval_secs(_outcome: ScanAttemptOutcome) -> u64 {
    CACHE_SCAN_INTERVAL_SECS
}

#[derive(Clone, Debug)]
struct MountInfo {
    mount_point: PathBuf,
    fs_type: String,
    device_id: u64,
}

struct CacheScanPolicy {
    mounts: Vec<MountInfo>,
}

impl CacheScanPolicy {
    fn detect(control: &ScanControl) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let mounts = parse_linux_mountinfo(control)?;
            return Some(Self::from_mounts(mounts));
        }

        #[allow(unreachable_code)]
        None
    }

    fn from_mounts(mut mounts: Vec<MountInfo>) -> Self {
        mounts.sort_by(|a, b| {
            b.mount_point
                .components()
                .count()
                .cmp(&a.mount_point.components().count())
                .then_with(|| {
                    b.mount_point
                        .as_os_str()
                        .len()
                        .cmp(&a.mount_point.as_os_str().len())
                })
        });
        Self { mounts }
    }

    fn allows_scan_root(&self, path: &Path) -> bool {
        self.mount_for_path(path)
            .and_then(|mount| {
                path_device_id(path).map(|device_id| {
                    device_id == mount.device_id && is_trusted_local_filesystem(&mount.fs_type)
                })
            })
            .unwrap_or(false)
    }

    fn should_descend(&self, root_device_id: u64, child_device_id: u64) -> bool {
        root_device_id == child_device_id
    }

    fn mount_for_path(&self, path: &Path) -> Option<&MountInfo> {
        self.mounts
            .iter()
            .find(|mount| path.starts_with(&mount.mount_point))
    }
}

#[derive(Debug)]
enum BlockingJoin {
    Failed,
    TimedOut,
}

/// Join a `spawn_blocking` worker under a hard deadline. Tokio cannot
/// cancel the worker; on expiry the caller drops the handle so the
/// collector task keeps its schedule. The thread leaks until the
/// blocking call returns.
async fn join_blocking_bounded<T: Send + 'static>(
    task: &mut JoinHandle<T>,
    timeout: Duration,
) -> Result<T, BlockingJoin> {
    match tokio::time::timeout(timeout, &mut *task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(BlockingJoin::Failed),
        Err(_) => Err(BlockingJoin::TimedOut),
    }
}

pub fn spawn_cache_scan_collector(
    cache_scan_cache: Arc<Mutex<CacheScanCache>>,
    state_path: PathBuf,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let completed_at = cache_scan_cache.lock().completed_at_unix_secs;
        let initial_delay = first_cache_scan_delay(completed_at, unix_now_secs());
        info!(
            "cache_scan: first scan scheduled in {}s",
            initial_delay.as_secs()
        );
        tokio::time::sleep(initial_delay).await;

        loop {
            info!(
                "cache_scan: starting scan (timeout {}s)...",
                SCAN_TIMEOUT_SECS
            );
            let timeout = Duration::from_secs(SCAN_TIMEOUT_SECS);
            let control = ScanControl::new(timeout);
            let _cancel_on_drop = CancelScanOnDrop(control.clone());
            let worker_control = control.clone();
            let mut task = tokio::task::spawn_blocking(move || collect_cache_scan(&worker_control));
            let result = tokio::time::timeout(timeout, &mut task).await;

            let next_interval = match result {
                Ok(Ok(Some(val))) => {
                    let completed_at = unix_now_secs();
                    let persist_path = state_path.clone();
                    let mut persisted_task = tokio::task::spawn_blocking(move || {
                        let result = persist_cache_scan(&persist_path, &val, completed_at);
                        (val, result)
                    });
                    let persisted = join_blocking_bounded(&mut persisted_task, timeout).await;
                    let val = match persisted {
                        Ok((val, Ok(()))) => Some(val),
                        Ok((val, Err(error))) => {
                            warn!("cache_scan: could not persist complete result: {error}");
                            Some(val)
                        }
                        Err(BlockingJoin::Failed) => {
                            warn!("cache_scan: persistence task failed");
                            None
                        }
                        Err(BlockingJoin::TimedOut) => {
                            warn!("cache_scan: persistence still blocked; detaching");
                            drop(persisted_task);
                            None
                        }
                    };
                    if let Some(val) = val {
                        let mut c = cache_scan_cache.lock();
                        c.results = Some(val);
                        c.last_updated = Some(Instant::now());
                        c.completed_at_unix_secs = Some(completed_at);
                        info!("cache_scan: scan complete, next in 24 hours");
                        next_cache_scan_interval_secs(ScanAttemptOutcome::Success)
                    } else {
                        next_cache_scan_interval_secs(ScanAttemptOutcome::Panic)
                    }
                }
                Ok(Ok(None)) => {
                    warn!(
                        "cache_scan: global deadline reached; partial result discarded, next in 24 hours"
                    );
                    next_cache_scan_interval_secs(ScanAttemptOutcome::Timeout)
                }
                Ok(Err(e)) => {
                    warn!("cache_scan: scan task panicked: {}", e);
                    next_cache_scan_interval_secs(ScanAttemptOutcome::Panic)
                }
                Err(_) => {
                    warn!(
                        "cache_scan: scan timed out after {}s; cancelling worker",
                        SCAN_TIMEOUT_SECS,
                    );
                    control.cancel();

                    // `spawn_blocking` cannot be aborted. Wait one more
                    // deadline for the worker to notice cancellation, then
                    // detach it. An unbounded await here turns the scan
                    // timeout into a permanently stuck collector task.
                    match join_blocking_bounded(&mut task, timeout).await {
                        Ok(_) => info!("cache_scan: cancelled worker stopped"),
                        Err(BlockingJoin::Failed) => {
                            warn!("cache_scan: cancelled worker failed");
                        }
                        Err(BlockingJoin::TimedOut) => {
                            warn!("cache_scan: cancelled worker still blocked; detaching");
                            drop(task);
                        }
                    }
                    next_cache_scan_interval_secs(ScanAttemptOutcome::Timeout)
                }
            };

            tokio::time::sleep(Duration::from_secs(next_interval)).await;
        }
    })
}

/// Returns `None` when the global deadline or cancellation signal interrupts
/// the scan. Partial reports are deliberately discarded rather than replacing
/// the last known-complete cache entry.
fn collect_cache_scan(control: &ScanControl) -> Option<serde_json::Value> {
    if control.should_stop() {
        return None;
    }

    let Some(policy) = CacheScanPolicy::detect(control) else {
        if control.should_stop() {
            return None;
        }
        warn!("cache_scan: mount policy unavailable, skipping scan for safety");
        return Some(build_cache_scan_report(
            Vec::new(),
            CacheScanTotals::default(),
        ));
    };

    let mut users = Vec::new();
    let mut totals = CacheScanTotals::default();

    for (username, home) in discover_homes(control) {
        if control.should_stop() {
            return None;
        }
        if let Some(user) = scan_home_cache(&username, &home, &policy, control) {
            if control.should_stop() {
                return None;
            }
            let user_totals = user
                .get("_totals")
                .and_then(|v| serde_json::from_value::<CacheScanTotalsSerde>(v.clone()).ok())
                .unwrap_or_default();
            totals.huggingface += user_totals.huggingface;
            totals.modelscope += user_totals.modelscope;
            totals.ollama += user_totals.ollama;
            totals.lmstudio += user_totals.lmstudio;
            totals.pip += user_totals.pip;
            totals.conda_envs += user_totals.conda_envs;
            totals.conda_pkgs += user_totals.conda_pkgs;
            totals.torch += user_totals.torch;
            totals.vllm += user_totals.vllm;

            let mut user_obj = user;
            if let Some(obj) = user_obj.as_object_mut() {
                obj.remove("_totals");
            }
            users.push(user_obj);
        }
    }

    if control.should_stop() {
        None
    } else {
        Some(build_cache_scan_report(users, totals))
    }
}

fn build_cache_scan_report(
    users: Vec<serde_json::Value>,
    totals: CacheScanTotals,
) -> serde_json::Value {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    serde_json::json!({
        "timestamp": ts,
        "users": users,
        "totals": {
            "huggingface_bytes": totals.huggingface,
            "modelscope_bytes": totals.modelscope,
            "ollama_bytes": totals.ollama,
            "lmstudio_bytes": totals.lmstudio,
            "pip_bytes": totals.pip,
            "conda_envs_bytes": totals.conda_envs,
            "conda_pkgs_bytes": totals.conda_pkgs,
            "torch_bytes": totals.torch,
            "vllm_bytes": totals.vllm,
            "local_models_bytes": totals.local_models,
            "grand_total_bytes": totals.grand_total()
        }
    })
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct CacheScanTotalsSerde {
    huggingface: u64,
    modelscope: u64,
    ollama: u64,
    lmstudio: u64,
    pip: u64,
    conda_envs: u64,
    conda_pkgs: u64,
    torch: u64,
    vllm: u64,
    local_models: u64,
}

#[derive(Default)]
struct DirSizeStats {
    bytes: u64,
    entries_scanned: usize,
    truncated: bool,
}

fn scan_home_cache(
    username: &str,
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    if control.should_stop() || !policy.allows_scan_root(home) {
        return None;
    }

    let home_usage = scan_home_usage(home, policy, control);
    let mut categories = Vec::new();
    let mut totals = CacheScanTotals::default();

    if control.should_stop() {
        return None;
    }
    if let Some(cat) = scan_hf_cache(home, policy, control) {
        totals.huggingface += cat["total_bytes"].as_u64().unwrap_or(0);
        categories.push(cat);
    }
    if control.should_stop() {
        return None;
    }
    if let Some(cat) = scan_ms_cache(home, policy, control) {
        totals.modelscope += cat["total_bytes"].as_u64().unwrap_or(0);
        categories.push(cat);
    }
    if control.should_stop() {
        return None;
    }
    if let Some(cat) = scan_ollama_cache(home, policy, control) {
        totals.ollama += cat["total_bytes"].as_u64().unwrap_or(0);
        categories.push(cat);
    }
    if control.should_stop() {
        return None;
    }
    if let Some(cat) = scan_lmstudio_cache(home, policy, control) {
        totals.lmstudio += cat["total_bytes"].as_u64().unwrap_or(0);
        categories.push(cat);
    }
    if control.should_stop() {
        return None;
    }
    if let Some(cat) = scan_local_model_dirs(home, policy, control) {
        totals.local_models += cat["total_bytes"].as_u64().unwrap_or(0);
        categories.push(cat);
    }
    for (rel, name, slot) in [
        (".cache/pip", "pip", "pip"),
        (".cache/torch", "torch", "torch"),
        (".cache/vllm", "vllm", "vllm"),
    ] {
        if control.should_stop() {
            return None;
        }
        let p = home.join(rel);
        if p.is_dir() && policy.allows_scan_root(&p) {
            let sz = dir_size_limited(&p, 50_000, policy, control);
            if sz > 0 {
                match slot {
                    "pip" => totals.pip += sz,
                    "torch" => totals.torch += sz,
                    "vllm" => totals.vllm += sz,
                    _ => {}
                }
                categories.push(serde_json::json!({
                    "name": name, "path": p.to_string_lossy(), "total_bytes": sz,
                    "models": [], "envs": []
                }));
            }
        }
    }
    for base in conda_base_candidates() {
        if control.should_stop() {
            return None;
        }
        let envs_dir = home.join(base).join("envs");
        if envs_dir.is_dir() && policy.allows_scan_root(&envs_dir) {
            if let Some(cat) = scan_conda_envs_dir(&envs_dir, base, policy, control) {
                totals.conda_envs += cat["total_bytes"].as_u64().unwrap_or(0);
                categories.push(cat);
            }
        }
        if control.should_stop() {
            return None;
        }
        let pkgs_dir = home.join(base).join("pkgs");
        if pkgs_dir.is_dir() && policy.allows_scan_root(&pkgs_dir) {
            let sz = dir_size_limited(&pkgs_dir, 50_000, policy, control);
            if sz > 0 {
                totals.conda_pkgs += sz;
                categories.push(serde_json::json!({
                    "name": format!("conda_pkgs_{}", normalize_cache_key(base)),
                    "path": pkgs_dir.to_string_lossy(), "total_bytes": sz,
                    "models": [], "envs": []
                }));
            }
        }
    }

    if control.should_stop() {
        return None;
    }
    if categories.is_empty() && home_usage.bytes == 0 {
        return None;
    }
    Some(serde_json::json!({
        "username": username,
        "home_dir": home.to_string_lossy(),
        "home_usage_bytes": home_usage.bytes,
        "home_usage_entries_scanned": home_usage.entries_scanned,
        "home_usage_truncated": home_usage.truncated,
        "categories": categories,
        "_totals": CacheScanTotalsSerde {
            huggingface: totals.huggingface,
            modelscope: totals.modelscope,
            ollama: totals.ollama,
            lmstudio: totals.lmstudio,
            pip: totals.pip,
            conda_envs: totals.conda_envs,
            conda_pkgs: totals.conda_pkgs,
            torch: totals.torch,
            vllm: totals.vllm,
            local_models: totals.local_models,
        }
    }))
}

fn scan_home_usage(home: &Path, policy: &CacheScanPolicy, control: &ScanControl) -> DirSizeStats {
    if control.should_stop() || !home.is_dir() || !policy.allows_scan_root(home) {
        return DirSizeStats::default();
    }
    dir_size_limited_stats_with_timeout(
        home,
        HOME_USAGE_ENTRY_LIMIT,
        Duration::from_secs(HOME_USAGE_TIMEOUT_SECS),
        policy,
        control,
    )
}

fn conda_base_candidates() -> &'static [&'static str] {
    &[
        "miniconda",
        "miniconda3",
        "anaconda",
        "anaconda3",
        "miniforge",
        "miniforge3",
        "mambaforge",
        "micromamba",
        ".conda",
        "opt/miniconda3",
        "opt/anaconda3",
        "opt/miniforge3",
        "opt/mambaforge",
        "opt/micromamba",
        ".local/share/mamba",
    ]
}

fn normalize_cache_key(input: &str) -> String {
    input.replace(['/', '\\', ' '], "_")
}

fn discover_homes(control: &ScanControl) -> Vec<(String, PathBuf)> {
    let mut homes = Vec::new();
    if control.should_stop() {
        return homes;
    }
    let root = PathBuf::from("/root");
    if root.is_dir() {
        homes.push(("root".into(), root));
    }
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            if control.should_stop() {
                return homes;
            }
            let p = e.path();
            if p.is_dir() {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    homes.push((n.into(), p));
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/Users") {
        for e in entries.flatten() {
            if control.should_stop() {
                return homes;
            }
            let p = e.path();
            if p.is_dir() {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    if n != "Shared" && !n.starts_with('.') {
                        homes.push((n.into(), p));
                    }
                }
            }
        }
    }
    homes
}

fn dir_size_limited(
    path: &Path,
    max: usize,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> u64 {
    dir_size_limited_stats(path, max, policy, control).bytes
}

fn dir_size_limited_stats(
    path: &Path,
    max: usize,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> DirSizeStats {
    dir_size_limited_stats_with_timeout(
        path,
        max,
        Duration::from_secs(PER_DIRECTORY_TIMEOUT_SECS),
        policy,
        control,
    )
}

fn dir_size_limited_stats_with_timeout(
    path: &Path,
    max: usize,
    timeout: Duration,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> DirSizeStats {
    fn inner(
        path: &Path,
        stats: &mut DirSizeStats,
        max: usize,
        local_deadline: Instant,
        policy: &CacheScanPolicy,
        root_device_id: u64,
        control: &ScanControl,
    ) -> u64 {
        if stats.entries_scanned > max || Instant::now() >= local_deadline || control.should_stop()
        {
            stats.truncated = true;
            return 0;
        }
        let mut total: u64 = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for e in entries.flatten() {
                if control.should_stop() {
                    stats.truncated = true;
                    break;
                }
                stats.entries_scanned += 1;
                if stats.entries_scanned > max || Instant::now() >= local_deadline {
                    stats.truncated = true;
                    break;
                }
                let ft = match e.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_file() {
                    total += e.metadata().map(|m| m.len()).unwrap_or(0);
                } else if ft.is_dir() {
                    let child_path = e.path();
                    let Some(child_device_id) = path_device_id(&child_path) else {
                        continue;
                    };
                    if !policy.should_descend(root_device_id, child_device_id) {
                        continue;
                    }
                    total += inner(
                        &child_path,
                        stats,
                        max,
                        local_deadline,
                        policy,
                        root_device_id,
                        control,
                    );
                }
            }
        }
        total
    }
    let local_deadline = Instant::now() + timeout;
    if control.should_stop() {
        return DirSizeStats {
            truncated: true,
            ..DirSizeStats::default()
        };
    }
    let Some(root_device_id) = path_device_id(path) else {
        return DirSizeStats::default();
    };
    let mut stats = DirSizeStats::default();
    stats.bytes = inner(
        path,
        &mut stats,
        max,
        local_deadline,
        policy,
        root_device_id,
        control,
    );
    stats
}

fn scan_hf_cache(
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let hub = home.join(".cache/huggingface/hub");
    if control.should_stop() || !hub.is_dir() || !policy.allows_scan_root(&hub) {
        return None;
    }
    let mut models = Vec::new();
    let mut total: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(&hub) {
        for e in entries.flatten() {
            if control.should_stop() {
                return None;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("models--") && e.path().is_dir() {
                let model_name = name
                    .strip_prefix("models--")
                    .unwrap_or(&name)
                    .replace("--", "/");
                let sz = dir_size_limited(&e.path(), 50_000, policy, control);
                total += sz;
                models.push(serde_json::json!({ "name": model_name, "size_bytes": sz }));
            }
        }
    }
    if total == 0 && models.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": "huggingface", "path": hub.to_string_lossy(),
        "total_bytes": total, "models": models, "envs": []
    }))
}

fn scan_ms_cache(
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let md = home.join(".cache/modelscope/hub/models");
    if control.should_stop() || !md.is_dir() || !policy.allows_scan_root(&md) {
        return None;
    }
    let mut models = Vec::new();
    let mut total: u64 = 0;
    if let Ok(orgs) = std::fs::read_dir(&md) {
        for org in orgs.flatten() {
            if control.should_stop() {
                return None;
            }
            if !org.path().is_dir() {
                continue;
            }
            let org_name = org.file_name().to_string_lossy().to_string();
            if org_name.starts_with('.') {
                continue;
            }
            if let Ok(ms) = std::fs::read_dir(org.path()) {
                for m in ms.flatten() {
                    if control.should_stop() {
                        return None;
                    }
                    if !m.path().is_dir() {
                        continue;
                    }
                    let mn = m.file_name().to_string_lossy().to_string();
                    if mn.starts_with('.') {
                        continue;
                    }
                    let sz = dir_size_limited(&m.path(), 50_000, policy, control);
                    total += sz;
                    models.push(serde_json::json!({ "name": format!("{}/{}", org_name, mn), "size_bytes": sz }));
                }
            }
        }
    }
    if models.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": "modelscope", "path": md.to_string_lossy(),
        "total_bytes": total, "models": models, "envs": []
    }))
}

fn scan_ollama_cache(
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let od = home.join(".ollama/models");
    if control.should_stop() || !od.is_dir() || !policy.allows_scan_root(&od) {
        return None;
    }
    let mut models = Vec::new();
    let manifest = od.join("manifests/registry.ollama.ai/library");
    if manifest.is_dir() {
        if let Ok(mds) = std::fs::read_dir(&manifest) {
            for md in mds.flatten() {
                if control.should_stop() {
                    return None;
                }
                if !md.path().is_dir() {
                    continue;
                }
                let mn = md.file_name().to_string_lossy().to_string();
                if let Ok(tags) = std::fs::read_dir(md.path()) {
                    for t in tags.flatten() {
                        if control.should_stop() {
                            return None;
                        }
                        let tag = t.file_name().to_string_lossy().to_string();
                        models.push(serde_json::json!({ "name": mn, "size_bytes": 0, "tag": tag }));
                    }
                }
            }
        }
    }
    let blobs = od.join("blobs");
    let total = if blobs.is_dir() {
        dir_size_limited(&blobs, 50_000, policy, control)
    } else {
        0
    };
    if total == 0 && models.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": "ollama", "path": od.to_string_lossy(),
        "total_bytes": total, "models": models, "envs": []
    }))
}

fn scan_lmstudio_cache(
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut models = Vec::new();
    let mut total: u64 = 0;
    for rel in [
        ".cache/lm-studio/models",
        ".cache/lmstudio/models",
        ".lmstudio/models",
        "Library/Application Support/LM Studio/models",
    ] {
        if control.should_stop() {
            return None;
        }
        let dir = home.join(rel);
        if !dir.is_dir() || !policy.allows_scan_root(&dir) {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if control.should_stop() {
                    return None;
                }
                let Ok(file_type) = e.file_type() else {
                    continue;
                };
                if file_type.is_file() {
                    total = total.saturating_add(e.metadata().map(|meta| meta.len()).unwrap_or(0));
                    continue;
                }
                if !file_type.is_dir() {
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_string();
                let model_size = dir_size_limited(&e.path(), 50_000, policy, control);
                total = total.saturating_add(model_size);
                if !name.starts_with('.') && seen.insert(name.clone()) {
                    models.push(serde_json::json!({ "name": name, "size_bytes": model_size }));
                }
            }
        }
    }
    if total == 0 && models.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": "lmstudio",
        "path": home.join(".lmstudio/models").to_string_lossy(),
        "total_bytes": total,
        "models": models,
        "envs": []
    }))
}

fn scan_local_model_dirs(
    home: &Path,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let candidates = [
        ("models", "models"),
        ("Models", "Models"),
        ("model", "model"),
        ("checkpoints", "checkpoints"),
        (".cache/huggingface/assets", "huggingface_assets"),
        (".cache/huggingface/datasets", "huggingface_datasets"),
        (".cache/sentence_transformers", "sentence_transformers"),
        (".cache/diffusers", "diffusers"),
        (".cache/clip", "clip"),
        (".cache/open_clip", "open_clip"),
        (".cache/whisper", "whisper"),
        ("ComfyUI/models", "ComfyUI"),
        ("stable-diffusion-webui/models", "stable-diffusion-webui"),
        ("text-generation-webui/models", "text-generation-webui"),
        ("Fooocus/models", "Fooocus"),
        ("InvokeAI/models", "InvokeAI"),
        ("invokeai/models", "invokeai"),
        (".invokeai/models", "invokeai"),
        ("llama.cpp/models", "llama.cpp"),
        ("LocalAI/models", "LocalAI"),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut models = Vec::new();
    let mut total: u64 = 0;

    for (rel, label) in candidates {
        if control.should_stop() {
            return None;
        }
        let dir = home.join(rel);
        if !dir.is_dir() || !policy.allows_scan_root(&dir) {
            continue;
        }
        let key = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !seen.insert(key) {
            continue;
        }
        let sz = dir_size_limited(&dir, 50_000, policy, control);
        total += sz;
        models.push(serde_json::json!({
            "name": label,
            "path": dir.to_string_lossy(),
            "size_bytes": sz
        }));
    }

    if total == 0 && models.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": "local_models",
        "path": home.to_string_lossy(),
        "total_bytes": total,
        "models": models,
        "envs": []
    }))
}

fn scan_conda_envs_dir(
    envs_dir: &Path,
    base: &str,
    policy: &CacheScanPolicy,
    control: &ScanControl,
) -> Option<serde_json::Value> {
    let mut envs = Vec::new();
    let mut total: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(envs_dir) {
        for e in entries.flatten() {
            if control.should_stop() {
                return None;
            }
            if !e.path().is_dir() {
                continue;
            }
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with('.') {
                continue;
            }
            let sz = dir_size_limited(&e.path(), 50_000, policy, control);
            total += sz;
            envs.push(serde_json::json!({ "name": n, "size_bytes": sz }));
        }
    }
    if envs.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "name": format!("conda_envs_{}", normalize_cache_key(base)), "path": envs_dir.to_string_lossy(),
        "total_bytes": total, "models": [], "envs": envs
    }))
}

#[cfg(target_os = "linux")]
fn parse_linux_mountinfo(control: &ScanControl) -> Option<Vec<MountInfo>> {
    if control.should_stop() {
        return None;
    }
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut mounts = Vec::new();

    for line in content.lines() {
        if control.should_stop() {
            return None;
        }
        let (left, right) = line.split_once(" - ")?;
        let mut left_parts = left.split_whitespace();
        let _mount_id = left_parts.next()?;
        let _parent_id = left_parts.next()?;
        let major_minor = left_parts.next()?;
        let _root = left_parts.next()?;
        let mount_point = left_parts.next()?;

        let fs_type = right.split_whitespace().next()?.to_string();
        let (major, minor) = major_minor.split_once(':')?;
        let major = major.parse::<u32>().ok()?;
        let minor = minor.parse::<u32>().ok()?;

        mounts.push(MountInfo {
            mount_point: PathBuf::from(unescape_mount_field(mount_point)),
            fs_type,
            device_id: libc::makedev(major, minor),
        });
    }

    Some(mounts)
}

#[cfg(not(target_os = "linux"))]
fn parse_linux_mountinfo(_control: &ScanControl) -> Option<Vec<MountInfo>> {
    None
}

fn unescape_mount_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &value[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(octal, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn is_trusted_local_filesystem(fs_type: &str) -> bool {
    matches!(
        fs_type.to_ascii_lowercase().as_str(),
        "ext2"
            | "ext3"
            | "ext4"
            | "xfs"
            | "btrfs"
            | "zfs"
            | "apfs"
            | "hfs"
            | "hfsplus"
            | "jfs"
            | "reiserfs"
            | "reiser4"
            | "f2fs"
            | "bcachefs"
            | "ufs"
    )
}

fn path_device_id(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        return std::fs::metadata(path).ok().map(|meta| meta.dev());
    }

    #[allow(unreachable_code)]
    None
}
