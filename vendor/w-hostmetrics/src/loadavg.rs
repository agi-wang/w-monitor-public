//! `/proc/loadavg` — load averages plus runnable/total scheduling entities.

/// A `/proc/loadavg` sample. `running`/`total_threads` come from the
/// `runnable/total` field (e.g. `7/130`) — the run-queue depth signal products
/// use to normalise load against core count.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    pub running: u64,
    pub total_threads: u64,
}

/// Parse `/proc/loadavg`. Returns `None` if the line is malformed.
pub fn parse_loadavg(content: &str) -> Option<LoadAvg> {
    let mut parts = content.split_whitespace();
    let one = parts.next()?.parse().ok()?;
    let five = parts.next()?.parse().ok()?;
    let fifteen = parts.next()?.parse().ok()?;
    let runnable = parts.next()?;
    let (running, total_threads) = runnable.split_once('/')?;
    Some(LoadAvg {
        one,
        five,
        fifteen,
        running: running.parse().ok()?,
        total_threads: total_threads.parse().ok()?,
    })
}

/// Read and parse the live `/proc/loadavg`.
pub fn read_loadavg() -> Option<LoadAvg> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|c| parse_loadavg(&c))
}
