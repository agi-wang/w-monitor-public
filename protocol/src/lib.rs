//! Wire types and immutable HTTP transport evidence. No command dispatcher,
//! remote file/terminal access, inbound listener, or update implementation.
pub mod report;
pub mod security_advisories;
pub mod software_inventory;
pub use report::{SystemInfo, SystemReport};
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMPACT_STICKY_COLLECTORS_KEY: &str = "__w_monitor_sticky_collectors";

pub struct TransportRuntimeState {
    endpoint: String,
}
impl TransportRuntimeState {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "active_transport": "http", "tcp_connected": false,
            "active_tcp_endpoint": null, "tcp_candidates": [],
            "http_endpoint": self.endpoint, "control_transport_alive": false,
            "control_transport_restarts_total": 0
        })
    }
}
