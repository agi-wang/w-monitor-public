# W Monitor Public

Open-source, read-only host monitoring with a Rust Lite Agent, independent regional
receivers, and shareable status pages. Public monitoring runs separately from
W Monitor Private and has no remote host-control or Agent auto-update path.

## Get started

Primary domain: **[monitor.20290708.xyz](https://monitor.20290708.xyz/)**.
The current release is **v1.2.0**; the release series starts at **v1.0.0**.

Open a regional site and choose **One-command device setup**:

- [United States](https://monitor.20290708.xyz/)
- [Singapore](https://sg.monitor.20290708.xyz/)
- [United Kingdom](https://wm-uk.myfastools.com/)

The website generates an installation command for its own region. For example:

```sh
curl -fsSL --proto '=https' --max-time 30 \
  https://github.com/agi-wang/w-monitor-public/releases/latest/download/install.sh \
  | bash -s -- --public https://monitor.20290708.xyz --language en
```

This downloads the Linux Agent and checksum from the public GitHub Release, checks SHA-256,
creates an anonymous space and public page, saves a private configuration, and
starts the Agent. The terminal prints a recovery key, management URL, and public
URL. The first connected device is selected for the initial public page.
The download source is shared across regions; `--public` or `--endpoint` chooses
only the registration and telemetry destination. An explicit `vX.Y.Z` pins a release.

Requirements: Linux AMD64 or ARM64, Bash, curl, and standard GNU utilities including
`sha256sum`. The Agent does not require Python or GitHub CLI. Optional installer
flag `--verify-provenance` uses GitHub CLI to verify the release attestation.

Keep the recovery key private. It restores the same space across browsers.

New spaces use a client-generated Ed25519 recovery seed (`wmr2_...`). The browser
stores only a non-exportable signing-key handle in IndexedDB; the server receives
public keys and one-time proofs, never the seed. HttpOnly, SameSite=Lax cookies
(Secure on HTTPS) remember the selected space for 30 days, renewed during use.
Startup value `browser_session_days` is editable within 7-365 days. If a remembered
cookie expires, a saved browser key can restore the space; explicit logout stops
automatic restoration. Save the recovery key for other browsers.

Existing `wmr_...` recovery still works. A legacy space can bind a fresh local
key without removing its original recovery until explicit rotation. Rotation
replaces recovery/bootstrap credentials and other browser sessions, while keeping
devices and published pages. New Agent management URLs may contain a recovery
fragment; it is processed locally and removed before normal navigation, never
sent in HTTP requests. Treat the entire management link as private.

W-ID client `w-monitor-public` owns login/claiming, with callbacks on all three
regional origins. Its scoped login providers include GitHub. Claiming persists
space ownership in SQLite, independently of cookies; logout does not unlink it.
An account owner can return through W-ID and rotate a lost recovery key locally.
Anonymous users who lose every key/session must create a new space and run its
registration command on their devices; nobody can silently claim that lost space.

Each Agent 1.1.0+ stores its own separate device key in 0600 configuration. Its
first signed report upgrades that device without changing its existing token.
Old unbound Agents continue reporting and are never auto-updated. Once bound,
unsigned/different-key requests are rejected; do not downgrade that Agent binary.
Moving an Agent into a newly owned space requires a local registration command;
no server command or configuration setting can move it remotely.


The setup dialog offers **Realtime resource metrics** and **Compress reports**,
both enabled by default. Unchecking them adds `--no-realtime` and
`--no-compression` as initial preferences. Full read-only collection is unchanged.
For a connected device, use **Agent settings** in its private device row to change
these two booleans online. Only the space owner can save them; the Agent receives
changes on its next report, persists them locally, and confirms application.
Offline devices wait until they reconnect. Existing Agents require a manual
update to v1.0.3 or later before they can accept settings.

Online settings take precedence over installation defaults. They cannot change
endpoints, credentials, commands, executable paths or updates. The UI shows
pending versus applied state. Re-running `--public` for the same receiver reuses
the device and space; a different receiver needs a separate `--config` path.

### Interactive setup and existing devices

Start an installed Agent without parameters:

```sh
"$HOME/.local/bin/w-monitor-lite"
```

An unconfigured Agent asks for a region and an existing registration key; leaving
the key empty creates an anonymous space and prints its links. An Agent with a
saved configuration starts directly.

You can also supply a registration key explicitly:

```sh
"$HOME/.local/bin/w-monitor-lite" \
  --endpoint https://monitor.20290708.xyz/api/v1/report \
  --key wmb_REPLACE_WITH_YOUR_REGISTRATION_KEY
```

During setup, the Agent tightens an existing user-owned default configuration
directory to mode `0700`. Symlinks and directories owned by another user are
rejected. Custom configuration directories must already have private permissions.

Configuration defaults to `$HOME/.config/w-monitor-public/agent.json` and can be
selected with `--config`. The Agent writes owner-only configuration and exchanges
the registration key for a device-bound telemetry token after its first report.

**Updates are manual.** Stop your Agent, rerun the installer without setup
parameters, then restart with the saved configuration. The receiver cannot ask an
installed Agent to upgrade itself.

## Spaces and public pages

- Use an anonymous space with a private recovery key, or claim it through normal
  OAuth login. Claiming a space does not grant host-control permissions.
- Create multiple public pages and choose which of your devices each page shows.
- Visitors see names, online status, CPU, memory, disk usage, and aggregate network
  rates. IP addresses, process details, inventory, and full reports stay private.
- Bind a verified identity email and opt in to offline/recovery notifications when
  the receiver has an SMTP transport configured.
- The interface and API messages support English and Simplified Chinese, selected
  from the browser's `Accept-Language` preferences.

The Lite Agent keeps permitted read-only collection within its OS user's
permissions. It has no remote terminal, remote file-control endpoint, privilege
escalation, or self-update implementation. Read-only reports can still contain
sensitive host metadata; choose a receiver you trust.

## Architecture

| Component | Responsibility |
| --- | --- |
| Rust Lite Agent | Collect and send outbound HTTPS telemetry |
| Regional Python WSGI receiver | Authenticate devices, manage spaces/pages, and serve data |
| Private Redis Unix socket | Current metrics, encrypted report snapshots, and short-lived caches |
| SQLite WAL database | Durable spaces, credential hashes, page selections, ownership, and notification state |
| Cloudflare Pages | Public, immutable JavaScript and CSS assets |

Each region has its own database, encryption key, Redis namespace, and device
credentials. The regional URL selects the data node; a region code never grants
access. All devices report to the common `POST /api/v1/report` path. Exact indexed
credential hashes determine the owning device or space.

Regional HTML, authentication, and API requests stay on the same origin. Loading
static assets from Cloudflare does not move user data or sessions to the CDN.

## Run a receiver

Use Python 3.12+, SQLite, trusted HTTPS, Redis, and a hosting environment that can
run Python WSGI. DirectAdmin and cPanel deployments use the provider's existing web
server; the application does not open an additional public port.

1. Keep release source and private data outside the document root.
2. Install the exact wheels in `server/requirements.lock` into a `runtime` virtual
   environment beside the release's `server/` directory.
3. Copy [server/config.example.json](server/config.example.json) to an owner-only
   private configuration file. Set the public origin, paths, and a random 32-byte
   hexadecimal `instance_secret`.
4. Configure Passenger to load `server/passenger_wsgi.py`. Apache uses the ordinary
   Python executable; LiteSpeed uses its compatible `lswsgi` executable.
5. Create a mode-0600 `config-path` file at the release root containing the absolute
   private configuration path. The automated deployment gate creates it for you.
6. Verify `/health` reports `mode: public`, `host_control_enabled: false`, and
   `cache: redis`.

The WSGI entrypoint loads the adjacent virtual environment and private startup
pointer. It does not require Apache `mod_env` or `SetEnv`.

Keep private directories at mode 0700 and configuration files at mode 0600.
Back up SQLite **and** the instance encryption key. Redis snapshots are rebuildable
from subsequent Agent reports; SQLite is not a telemetry fallback. If Redis is
unavailable, ingestion fails explicitly and pages show unknown data availability.

### Runtime configuration

These settings are read at startup. Edit the private configuration and restart
the receiver; no recompilation is required.

| Setting | Default / purpose |
| --- | --- |
| `redis_socket` | Absolute path to the private Redis Unix socket |
| `static_assets_url` | Optional HTTPS origin for Cloudflare-hosted JS/CSS |
| `region_id`, `regions` | Current region and the public region catalog |
| `report_interval_ms` | About 60,000 ms between full reports |
| `metrics_interval_ms` | 3,000 ms between lightweight resource samples |
| `page_refresh_ms` | 1,500 ms between browser refreshes |
| `snapshot_cache_ms` | 500 ms view-cache window |
| `offline_grace_ms` | 15,000 ms grace for realtime-capable devices |

The receiver returns cadence hints with report responses. Agents adopt supported
hints without a binary update. Older Agents retain their slower full-report cadence.
These defaults target roughly five-second visibility; they are not a latency SLA.

Optional OAuth uses Authorization Code + PKCE with `openid profile email` and the
callback `https://YOUR_REGION/auth/callback`. Configure the `oidc_*` fields for
normal login and the `smtp_*` fields for notifications. Only verified emails can
be bound, and notification delivery requires user opt-in.

### Account-owned Redis

If the host does not supply Redis, [ops/build_redis.sh](ops/build_redis.sh) builds a
pinned static Redis binary. Install it in the private deployment folder's `bin/`
directory and place [ops/redis_watchdog.py](ops/redis_watchdog.py) beside the stable
[ops/run_periodic.py](ops/run_periodic.py) entrypoint.

Configure Redis with `port 0`, a private Unix socket with mode 0600, private
pid/log paths, `daemonize yes`, `save ""`, `appendonly no`, `maxmemory 0`, and
`enable-module-command no`. Keep its directory outside the web root. No Redis TCP
listener is required. Run the periodic entrypoint through account Cron once per
minute; it checks Redis before metrics/notifications and restarts a failed cache.

The application imposes no device, space, or page-count quotas and requires no
Redis memory cap. Compressed expiring snapshots, compact metrics, pagination, and
conditional reads reduce resource use. Hosting-provider resource limits still apply.

## Automatic publication

[GitHub Actions](.github/workflows/ci.yml) checks the locked Rust/Python sources,
builds static Linux AMD64/ARM64 Agents, packages the receiver, and verifies the
frontend build. A matching version tag on `main` publishes checksums and artifact
attestations, then deploys the receiver and website-hosted Agent downloads through
protected regional environments.

Deployment verifies the release's exact inventory, hashes, tag, and provenance.
The private gate installs an immutable release, activates it, checks health, and
restores the previous hosting configuration on failure. Application data and
configuration remain outside release directories. Server deployment never updates
installed Agents.

Supported deployment transports:

- Restricted SSH with a dedicated key and pinned host key.
- DirectAdmin's authenticated file and terminal APIs.
- cPanel's authenticated file and account Cron APIs, using a one-shot deployment
  command and preserving existing account jobs.

Set provider credentials only in protected GitHub environment secrets. The private
`deploy-config.json` specifies `public_url`, `python`, `wsgi`, `periodic_enabled`,
and, when needed, the exact account-owned `document_root`. An operator-authorized
version rebase can set `reset_to_tag` to one exact tag in this private file;
the gate consumes that permission only after successful activation.

### Cloudflare frontend CI/CD

Connect the repository to Cloudflare Pages with:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Build command | `python3 ops/package_web.py` |
| Output directory | `artifacts/web` |

Merged commits automatically publish the frontend assets. Content-addressed files
from release tags are retained so regional backends can roll forward independently.
Set GitHub variable `PUBLIC_ASSETS_ORIGIN` and each receiver's `static_assets_url`
to the same Pages HTTPS origin. GitHub checks the exact CDN asset bytes before
receiver activation. Regional HTML uses SHA-256 Subresource Integrity and allows
only the configured CDN origin in its Content Security Policy.

Only public JS/CSS receive immutable CDN caching. Regional HTML, authentication,
and tenant APIs retain private, no-store responses.

## Source and contracts

- [Agent and receiver protocol](PROTOCOL.md)
- [Receiver OpenAPI](server/openapi.json)
- [Security policy](SECURITY.md)
- [MIT license](LICENSE)

Local checks: `cargo fmt --all --check`, Python compilation for `server/` and
`ops/`, `node --check server/web/app.js`, and the Linux musl build/lint/static gates
defined in GitHub Actions.

### Complete private device details

Open a device snapshot to browse every collector, including nested fields and
unknown collector types. System, CPU, memory, disks, network, processes, containers,
services and security data render as sections/tables. Long lists are searchable
and paginated; no rows are discarded. The realtime overview stays separate from
the last-full-snapshot timestamp. Raw JSON is available on demand and as a complete
local download. Collector navigation covers every reported type, including unknown
types. Percentage fields render as occupancy bars, status/severity fields as badges,
and collector envelopes expose their data while retaining status/error details.
Public pages continue to use their deliberately limited projection.

### Device entrypoints and live trends

Select a device name or **View details** in either the public sharing page or
the private device list. Both show CPU, memory, disk and receive/transmit charts;
the public dialog uses only the already-published scalar metrics and never fetches
a private report. The device list also shows a CPU sparkline. Private details
retain all collector sections and an explicit full-snapshot refresh button.

Historical curves are read from the receiver's Redis, so page reloads and other
browsers show the same retained samples. Choose 15 minutes, 1 hour, 24 hours,
7 days, 30 days or all retained history. Missing samples stay missing; offline
periods are not filled with zeros. The live overview remains separate from the
selected historical averages. The browser keeps only a small response cache;
it never owns or reconstructs the history.

### Tiered Redis history

| Startup setting | Default | Meaning |
| --- | --- | --- |
| `history_fine_retention_seconds` | 900 | Keep second buckets for the latest 15 minutes |
| `history_minute_retention_seconds` | 3,600 | Keep minute means for the latest hour |
| `history_hour_retention_seconds` | 2,592,000 | Keep hourly means for 30 days |
| `history_fine_step_seconds` | 3 | Fine-range query aggregation, a divisor of 60 |

All three tiers consume the original accepted samples. Each metric has its own
sample count; higher-level or long-range averages are sample-weighted, never
an unweighted average of averages. Seconds without reports consume no records.
The receiver's clock defines UTC-aligned buckets; delayed reports are recorded
at receive time. Float32 means provide about seven significant digits, with
uint16 counts (the existing accepted-report cadence fits this representation).

A bucket uses 32 packed bytes for slot + five means + five counts before zlib
compression and purpose-bound AES-GCM encryption. Records are grouped into minute,
hour and day chunks. Absolute TTLs expire each chunk independently, including
on offline devices. Reads enforce the configured cutoff; physical expiry can
retain at most one additional chunk (minute/hour/day) at a tier boundary. A bounded per-device index supports immediate removal without
global scans. Reducing retention filters reads immediately and shortens existing
chunk TTLs on the next report; extending retention cannot recover expired data.
Fine/minute/hour retention must be ordered and at most 1/7/365 days respectively.

Writes atomically compare/update all three encrypted chunks together with current
telemetry. CAS conflicts retry at most twice; failure returns 503 without an ingest
acknowledgement. There are no additional SQLite writes for steady-state reports.
Shared encrypted response caches expire after 2/5/30 seconds for fine/minute/hour
views; fine views are also invalidated by incoming reports. Queries return at most
720 points, using weighted aggregation when a long range needs coarser resolution.
Only the selected device's history is fetched. No per-point Redis keys, global
history scans, background per-viewer collectors or RedisTimeSeries dependency.

Public history requires the current enabled page, a page-bound encrypted routing
reference and current device selection. Its stable `history_key` is a page-specific
pseudonym, never a private device ID. Private history requires owner session and
operation token. Removing a device deletes its indexed chunks and response caches;
disabling/rotating a page immediately prevents new historical reads. Historical
resource values are encrypted at rest and never include private collector data.

History starts accumulating when this version is activated; older unsaved samples
cannot be backfilled. Redis persistence/eviction follows the account's configured
Redis policy; this is retained telemetry, not a permanent archive or backup.
