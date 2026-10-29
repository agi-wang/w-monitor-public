//! Per-interface byte counters → bytes/sec, with counter-reset protection.
//!
//! Cumulative RX/TX counters are useless until you diff two samples over time.
//! Everyone re-derives this, and the easy bug is forgetting that counters reset
//! to zero on interface flap / reboot — without the guard you emit an enormous
//! bogus spike. [`NetRateTracker`] keeps the previous sample per interface and
//! returns `(0.0, 0.0)` on the first sample and on any backwards counter.

use std::collections::HashMap;
use std::time::Instant;

struct Sample {
    received_bytes: u64,
    transmitted_bytes: u64,
    at: Instant,
}

/// Stateful per-interface rate calculator. One instance per collector; call
/// [`NetRateTracker::calculate`] each scrape with the cumulative counters.
#[derive(Default)]
pub struct NetRateTracker {
    samples: HashMap<String, Sample>,
}

impl NetRateTracker {
    pub fn new() -> Self {
        Self {
            samples: HashMap::new(),
        }
    }

    /// Return `(rx_bytes_per_sec, tx_bytes_per_sec)` for `iface` given the
    /// current cumulative counters at instant `now`. `(0.0, 0.0)` on the first
    /// sample, a zero/negative interval, or a counter that moved backwards.
    pub fn calculate(
        &mut self,
        iface: &str,
        received_bytes: u64,
        transmitted_bytes: u64,
        now: Instant,
    ) -> (f64, f64) {
        let speeds = self
            .samples
            .get(iface)
            .and_then(|prev| {
                let elapsed = now.duration_since(prev.at).as_secs_f64();
                if elapsed <= 0.0
                    || received_bytes < prev.received_bytes
                    || transmitted_bytes < prev.transmitted_bytes
                {
                    return None;
                }
                Some((
                    (received_bytes - prev.received_bytes) as f64 / elapsed,
                    (transmitted_bytes - prev.transmitted_bytes) as f64 / elapsed,
                ))
            })
            .unwrap_or((0.0, 0.0));

        self.samples.insert(
            iface.to_string(),
            Sample {
                received_bytes,
                transmitted_bytes,
                at: now,
            },
        );

        speeds
    }
}
