# Security boundary

W-Monitor Lite is a telemetry producer, not an administration agent. The source
allowlist contains read-only collectors, report models and one outbound HTTP
sender. It excludes the standard agent's command/terminal/file-control modules,
control transport, update executor, update watchdog, service installer and brand
migration. No server response selects a local executable or installs software.

The only accepted response data is a bounded telemetry token, a bounded sampling
interval and validated declarative vulnerability catalogs/assessments. Unknown
fields, commands and update hints are ignored. The main telemetry client and
peer-discovery client disable redirects. Normal transport requires trusted HTTPS.

Limits include a 64 KiB config, 8 MiB report, 1 MiB response, 15-second HTTP request
limit, five-second connect limit and at most two request retries. The reused
collectors have their own row, byte and subprocess limits. State/config writes
remain in the operator-owned private config directory. This does not provide an
OS sandbox, prevent a privileged operator from reading local data, guarantee that
all filesystem calls can be interrupted, or prove that every third-party dependency
is free of vulnerabilities.

Full collection reads local process/service/container/software/security metadata.
Local parsers redact known credential forms and URL userinfo before emitting
command evidence. Permission failures and incomplete coverage are represented as
unavailable/incomplete; an empty or offline result is not a health guarantee.
The optional proprietary audit engine is omitted explicitly.

CI uses a locked dependency graph, RustSec auditing, pinned Actions and a static
ELF gate. Publishing requires successful AMD64/ARM64 builds and a matching version
tag contained in main. The publisher does not execute built artifacts or receive
platform deployment credentials. Consumers should verify both checksums and the
repository/workflow identity in GitHub artifact attestations. Provenance proves
origin and integrity; it is not a code audit or an authorization to auto-update.

To report a vulnerability, use this repository's private vulnerability reporting
form if enabled. Do not include credentials or live host reports in public issues.
If private reporting is unavailable, open an issue asking for a private contact
without disclosing exploit details or sensitive data.
