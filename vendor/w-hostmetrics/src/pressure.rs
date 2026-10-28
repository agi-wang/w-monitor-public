//! Pressure Stall Information (PSI) — `/proc/pressure/{cpu,memory,io}`.

/// One PSI line (`some` or `full`) with the three sliding averages and the
/// cumulative stall total in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PressureLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total: u64,
}

impl PressureLine {
    /// The cumulative stall total in **microseconds** — alias for [`Self::total`]
    /// so consumers that emit a `total_usec` wire field map without renaming.
    pub fn total_usec(&self) -> u64 {
        self.total
    }
}

/// The `some` and `full` lines of one pressure file.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PressureStall {
    pub some: Option<PressureLine>,
    pub full: Option<PressureLine>,
}

/// CPU/memory/IO pressure read together (the common "read all three" pattern).
/// `cpu` has no `full` line on most kernels; `io` is absent on some hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PressureSet {
    pub cpu: Option<PressureStall>,
    pub memory: Option<PressureStall>,
    pub io: Option<PressureStall>,
}

/// Parse the full contents of a `/proc/pressure/*` file.
pub fn parse_pressure(content: &str) -> PressureStall {
    let mut stall = PressureStall::default();
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("some ") {
            stall.some = parse_pressure_line(rest);
        } else if let Some(rest) = line.strip_prefix("full ") {
            stall.full = parse_pressure_line(rest);
        }
    }
    stall
}

/// Parse the part of a PSI line after the `some `/`full ` prefix — **tolerant**:
/// unknown / non-`key=value` tokens and unparseable values are skipped rather
/// than discarding the whole line. Real kernel PSI lines parse byte-identically
/// to the strict variant; this only changes behaviour on malformed input (and
/// restores the leniency products historically relied on). Always returns
/// `Some` for a non-degenerate line. Use [`parse_pressure_line_strict`] to
/// fail-fast instead.
pub fn parse_pressure_line(rest: &str) -> Option<PressureLine> {
    let mut line = PressureLine::default();
    for part in rest.split_whitespace() {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "avg10" => {
                if let Ok(v) = value.parse() {
                    line.avg10 = v
                }
            }
            "avg60" => {
                if let Ok(v) = value.parse() {
                    line.avg60 = v
                }
            }
            "avg300" => {
                if let Ok(v) = value.parse() {
                    line.avg300 = v
                }
            }
            "total" => {
                if let Ok(v) = value.parse() {
                    line.total = v
                }
            }
            _ => {}
        }
    }
    Some(line)
}

/// Strict variant: any token without `=` or any unparseable value drops the
/// whole line to `None`. This was the 0.1.0 default; kept for callers that want
/// fail-fast parsing.
pub fn parse_pressure_line_strict(rest: &str) -> Option<PressureLine> {
    let mut line = PressureLine::default();
    for part in rest.split_whitespace() {
        let (key, value) = part.split_once('=')?;
        match key {
            "avg10" => line.avg10 = value.parse().ok()?,
            "avg60" => line.avg60 = value.parse().ok()?,
            "avg300" => line.avg300 = value.parse().ok()?,
            "total" => line.total = value.parse().ok()?,
            _ => {}
        }
    }
    Some(line)
}

/// Read and parse a live PSI file; `None` if the kernel lacks PSI or the read
/// fails (PSI requires `CONFIG_PSI=y` and is absent on some kernels/containers).
pub fn read_pressure(path: &str) -> Option<PressureStall> {
    std::fs::read_to_string(path)
        .ok()
        .map(|c| parse_pressure(&c))
}

/// Read CPU, memory and IO pressure together. Each is `None` if its file is
/// missing/unreadable (common in containers and on `CONFIG_PSI=n` kernels).
pub fn read_pressure_all() -> PressureSet {
    PressureSet {
        cpu: read_pressure("/proc/pressure/cpu"),
        memory: read_pressure("/proc/pressure/memory"),
        io: read_pressure("/proc/pressure/io"),
    }
}
