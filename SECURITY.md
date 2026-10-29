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
platform deployment credentials. Receiver deployment uses a separate restricted job. Consumers should verify both checksums and the
repository/workflow identity in GitHub artifact attestations. Provenance proves
origin and integrity; it is not a code audit or an authorization to auto-update.

To report a vulnerability, use this repository's private vulnerability reporting
form if enabled. Do not include credentials or live host reports in public issues.
If private reporting is unavailable, open an issue asking for a private contact
without disclosing exploit details or sensitive data.

## Public receiver

The Python receiver is independently deployable and has no host-control APIs or
control transport. It never sends commands or update directives. A full report is
accepted only with a space-matching ingest address and bootstrap/device Bearer
credential. Public projections use an explicit field allowlist, and publication
and ownership are checked before serving cached data.

Private data/configuration live outside the web root with owner-only permissions.
PyCA AES-256-GCM uses random nonces and separate authenticated purposes for links,
contacts and Redis payloads. Opaque encrypted addresses are not a substitute for
sessions, CSRF checks or TLS. Recovery keys are bearer access credentials; save them
privately. Rotation invalidates other space sessions. Share-link rotation/disable
is checked on every request, including when a cached projection exists.

Redis is required for ingestion and rate limiting; unavailable telemetry is unknown
and is never written into SQLite. Snapshot expiry, bounded projection caches, request size bounds, authentication
rate limits and short timeouts reduce unnecessary work. There are no application
quotas on device, space or page counts; hosting resources remain operator-owned.
These limits do not provide a complete public-internet DDoS defense. Enforce network
and account resource limits at the hosting edge as well.

Email requires a verified login identity and explicit space opt-in. Addresses and
queued recipients are encrypted in SQLite. Delivery uses certificate-validated
STARTTLS, bounded attempts and daily limits. Neither bootstrap credentials nor
recovery keys are included in mail. Management links in mail still require access.

Receiver CI/CD uses a dedicated child-account forced-command key. The reseller
credential is never available to GitHub Actions. Only verified versioned archives
are accepted; releases cannot overwrite an existing version or automatically
downgrade. An operator can authorize a version rebase to one exact tag using
owner-only `reset_to_tag` configuration; successful activation consumes it.
The deploy key can install receiver code and therefore must be protected
as production access. Agent installation remains a separate manual operation.
