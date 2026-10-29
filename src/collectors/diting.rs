pub(crate) fn collect_diting_audit(
    security_posture: &serde_json::Value,
    traffic_flows: &serde_json::Value,
) -> serde_json::Value {
    collect_diting_audit_impl(security_posture, traffic_flows)
}

fn collect_diting_audit_impl(
    _security_posture: &serde_json::Value,
    _traffic_flows: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "engine": "diting-core",
        "mode": "agent-passive",
        "enabled": false,
        "reason": "feature_not_compiled"
    })
}
