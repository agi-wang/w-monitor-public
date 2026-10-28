//! Writable runtime paths for both system services and unprivileged agents.

use std::path::{Path, PathBuf};

pub(crate) fn is_unprivileged() -> bool {
    !system_paths_are_writable()
}

pub(crate) fn data_dir() -> PathBuf {
    let xdg_state_home = nonempty_path(std::env::var_os("XDG_STATE_HOME").as_deref())
        .filter(|path| writable_ancestor(path));
    let home =
        nonempty_path(std::env::var_os("HOME").as_deref()).filter(|path| writable_ancestor(path));
    resolve_data_dir(
        system_paths_are_writable(),
        effective_uid(),
        std::env::var_os("W_MONITOR_DATA_DIR").as_deref(),
        xdg_state_home.as_deref().map(Path::as_os_str),
        home.as_deref().map(Path::as_os_str),
        &std::env::temp_dir(),
    )
}

pub(crate) fn control_socket_path() -> PathBuf {
    if let Some(path) = nonempty_path(std::env::var_os("W_MONITOR_SOCKET_PATH").as_deref()) {
        if writable_ancestor(path.parent().unwrap_or(Path::new("/"))) {
            return path;
        }
    }
    if !is_unprivileged() {
        return PathBuf::from("/run/w-monitor/control.sock");
    }
    if let Some(runtime_dir) = nonempty_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
        .filter(|path| writable_ancestor(path))
    {
        return runtime_dir.join("w-monitor/control.sock");
    }
    data_dir().join("run/control.sock")
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn system_paths_are_writable() -> bool {
    effective_uid() == 0
        && writable_ancestor(Path::new("/run"))
        && writable_ancestor(Path::new("/var/lib"))
}

fn writable_ancestor(path: &Path) -> bool {
    let mut candidate = path;
    while !candidate.exists() {
        let Some(parent) = candidate.parent() else {
            return false;
        };
        candidate = parent;
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(candidate.as_os_str().as_bytes()) else {
            return false;
        };
        unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn nonempty_path(value: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    value.filter(|path| !path.is_empty()).map(PathBuf::from)
}

fn resolve_data_dir(
    system_paths_writable: bool,
    uid: u32,
    override_dir: Option<&std::ffi::OsStr>,
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    temp_dir: &Path,
) -> PathBuf {
    if let Some(path) = nonempty_path(override_dir) {
        return path;
    }
    if system_paths_writable {
        return PathBuf::from("/var/lib/w-monitor");
    }
    if let Some(path) = nonempty_path(xdg_state_home) {
        return path.join("w-monitor");
    }
    if let Some(path) = nonempty_path(home) {
        return path.join(".local/state/w-monitor");
    }
    temp_dir.join(format!("w-monitor-{uid}"))
}
