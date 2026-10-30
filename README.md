# W Monitor Public

Open-source, read-only host monitoring with a Rust Lite Agent, independent regional
receivers, and shareable status pages. Public monitoring runs separately from
W Monitor Private and has no remote host-control or Agent auto-update path.

## Get started

Primary domain: **[monitor.20290708.xyz](https://monitor.20290708.xyz/)**.
The current release is **v1.3.8**; the release series starts at **v1.0.0**.

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
- Visitors see names, online state, last report, CPU, memory and disk by default.
  Owners opt each page into default-egress rates and historical charts separately.
  IP addresses, process details, inventory and complete reports stay private.
- Bind a verified identity email and opt in to offline/recovery notifications when
  the receiver has an SMTP transport configured.
- The interface and API messages support English and Simplified Chinese, selected
  from the browser's `Accept-Language` preferences.

The Lite Agent keeps permitted read-only collection within its OS user's
permissions. It has no remote terminal, remote file-control endpoint, privilege
escalation, or self-update implementation. Read-only reports can still contain
sensitive host metadata; choose a receiver you trust.

### Startup configuration and regional identity

At startup the Agent prints the selected `--config` path, report URL, device ID,
full-report interval, realtime and compression switches. Successful reports also
log the effective cadence and switches returned by the receiver. Authentication
tokens and signing private keys are not printed. `--language zh-CN` selects Chinese
startup and receiver-conflict messages.

A device configuration belongs to one receiver. When an existing config is used
with a different `--public` origin, the Agent first queries its original receiver.
It prints the confirmed node, monitoring space, device, recent-report age and any
enabled public pages dedicated to this device. It then exits without registering
or moving anything. The primary instruction resumes collection using the existing
config; creating a separate regional config is shown only as an optional choice.
If the original receiver is unreachable, too old, or rejects the credential, the
Agent clearly labels the local record as unconfirmed instead of claiming it is a
valid binding. Normal collection can continue with older receivers.

Query an installed Agent without reinstalling or collecting:

```bash
w-monitor-lite --show-binding --language zh-CN
```

Add `--config /path/to/agent.json` for a non-default configuration. The read-only
lookup never returns account identity, recovery keys, management capabilities or
links exposing other devices. Its login entry still needs the normal account or
recovery credential. Private keys stay on the client. A new receiver config is
only needed when the user actually chooses a new registration.

The receiver must return JSON to setup and reporting requests. If a hosting
firewall or proxy returns an HTML page, the Agent names the affected origin and
reports that page type without printing its body or cookies. Anonymous setup
stops without retrying its create request. An existing device skips immediate
retries and waits at least 60 seconds before retrying its own receiver; it never
switches regional endpoints or credentials automatically. Browser challenges must
be exempted at the hosting provider for an API domain; changing the User-Agent
cannot guarantee access.

## Architecture

The Agent consumes the public [w-monitor-collectors](https://github.com/agi-wang/w-monitor-collectors)
crate at an exact Git commit
for hardware metrics, network accounting/traffic parsing and mount health. Public
and Private pin the same reviewed collector revision while keeping their own
configuration, transports, receivers and release pipelines. Updating the shared
source does not update an installed Agent or publish either product automatically.

The shared dependency contains read-only collection and bounded diagnostic
subprocesses. It has no dependency on W Monitor Private, control handlers, inbound
control listeners or automatic updaters. Public keeps scheduling, software and
security inventory, registration and reporting in this repository. Inspect the
pinned dependency source and Cargo dependency graph when changing its revision.

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

Use Python 3.11+, SQLite, trusted HTTPS, Redis, and a hosting environment that can
run Python WSGI. DirectAdmin and cPanel deployments use the provider's existing web
server; the application does not open an additional public port.
Locked dependencies and direct WSGI entrypoint imports have been verified on
Python 3.11 and 3.13. The hosting server must also have a compatible WSGI executor;
a successful command-line import alone does not verify HTTP serving.

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

The regional deployment matrix preserves the original three targets and adds four
independent hosting accounts. Each target has its own protected GitHub environment:

| Region code | Public origin | GitHub environment |
| --- | --- | --- |
| `us` | https://monitor.20290708.xyz | `public-production` |
| `sg` | https://sg.monitor.20290708.xyz | `public-singapore` |
| `uk` | https://wm-uk.myfastools.com | `public-united-kingdom` |
| `sg-advin` | https://sg-advin.monitor.20290708.xyz | `public-singapore-advin` |
| `us-mia` | https://us-mia.monitor.20290708.xyz | `public-miami` |
| `sg-dap` | https://sg-dap.monitor.20290708.xyz | `public-singapore-dapanel` |
| `fiber100` | https://fiber.monitor.20290708.xyz | `public-fiber100` |

Only one receiver account is used per physical server; the original UK receiver
serves that server without adding a second account.

Each hosting account must pass its receiver bootstrap before its first tagged
deployment. Keep its database, encryption secret, Redis socket and credentials
independent. Configure the receiver's `region_id` and `regions` catalog at startup;
`/api/regions` supplies Agent region selection without compiled node addresses.
A command copied from a regional site continues to register with that same origin.

Deployment verifies the release's exact inventory, hashes, tag, and provenance.
The private gate installs an immutable release, activates it, checks health, and
restores the previous hosting configuration on failure. Application data and
configuration remain outside release directories. Server deployment never updates
installed Agents.

On an account's first deployment, health verification allows 20 seconds for initial
hosting readiness, then at most three attempts with 15-second requests and
30-second intervals. Existing receivers retain their shorter verification timing.
All checks still require the exact version/release, Redis and read-only state;
private gate logs record HTTP status or exception type without response bodies.

Supported deployment transports:

- Restricted SSH with a dedicated key and pinned host key. Set environment variable
  `PUBLIC_DEPLOY_PORT` for an account using a custom SSH port; omission defaults to
  22. CI accepts only decimal ports 1–65535 and keeps strict host-key validation.
  For custom ports, store the matching `[host]:port` entry in
  `PUBLIC_DEPLOY_KNOWN_HOSTS`; changing a port never bypasses the pinned key.
- DirectAdmin's authenticated file and terminal APIs.
- cPanel's authenticated file and account Cron APIs, using a one-shot deployment
  command and preserving existing account jobs.

cPanel requests connect to the protected environment's `PUBLIC_DEPLOY_HOST` while
retaining the panel URL hostname for certificate verification and TLS SNI. This
supports provider panel aliases that resolve to another account server.

Set provider credentials only in protected GitHub environment secrets. The private
`deploy-config.json` specifies `public_url`, `python`, `wsgi`, `periodic_enabled`,
and, when needed, the exact account-owned `document_root`. An operator-authorized
version rebase can set `reset_to_tag` to one exact tag in this private file;
the gate consumes that permission only after successful activation.

`python` builds the release virtual environment and installs the locked wheels;
`wsgi` becomes the `PassengerPython` hosting directive. Choose the executor for
the actual web server:

| Hosting server | `python` | `wsgi` |
| --- | --- | --- |
| Apache with Passenger | Installed Python interpreter | Compatible Python interpreter |
| CloudLinux LiteSpeed with Python 3.11 LSAPI | `/opt/alt/python311/bin/python3` | `/opt/alt/python311/bin/lswsgi` |

LiteSpeed accepts Passenger-style directives but runs its own LSAPI executor.
Use an installed `lswsgi` matching the release environment's Python major/minor;
an ordinary CPython executable is not a substitute. Having Python 3.13 installed
does not establish that a matching Python 3.13 LSAPI executor is available.
See LiteSpeed's [CloudLinux integration](https://docs.litespeedtech.com/lsws/cp/cpanel/cloudlinux/)
and [Python LSAPI configuration](https://docs.litespeedtech.com/lsws/extapp/python/).
Verify the regional HTTP `/health` through the deployment gate before considering
the receiver active. This concerns receiver hosting only; Agent installation and
manual-update behavior are unchanged.

### Automatic shared collector updates

[collectors-auto-update.yml](.github/workflows/collectors-auto-update.yml) reconciles
public shared releases every 15 minutes or through manual dispatch. Enable it with
repository variable `COLLECTORS_AUTO_UPDATE_ENABLED=true` after reviewing the
workflow. Allow Actions to create pull requests. Protect `main` with strict
up-to-date required checks `build-linux-amd64` and `build-linux-arm64`, enforced
for administrators too. Keep force pushes and branch deletion disabled. The
reconciler checks the protected required-build summary and a clean merge state;
strict up-to-date protection closes the PR merge API's concurrent-base race.

The synchronization workflow uses a dedicated GitHub App only to create candidate
commits, branches and pull requests. Install it only on `w-monitor-public`, with
Contents and Pull requests write permissions plus automatic Metadata read; it needs
no Actions, Secrets or Workflows permission, OAuth flow or webhook. Store its ID and
private key in repository secrets `COLLECTORS_APP_ID` and
`COLLECTORS_APP_PRIVATE_KEY`. Set repository variable `COLLECTORS_APP_BOT_LOGIN` to
the independently confirmed `<app-slug>[bot]` login. The pinned official token action
mints a repository-only token; the reconciler verifies that scope, the action's App
slug and the GitHub bot user ID before deriving its commit identity. PR metadata
never chooses the trusted author.

The repository's `GITHUB_TOKEN` still handles reads, guarded merges and main/tag CI
dispatch. No personal token, Private repository access or provider secret is needed.
If a shared Actions GET specifically denies integration access, it retries that
public GET anonymously; a rate-limit response remains an error.
The operator [ops/update_collectors.py](ops/update_collectors.py) requires Python
3.11+, and the workflow installs the existing pinned Rust 1.96 toolchain.

The latest stable shared release must be newer than the locked shared package and
have successful tag CI and a matching package manifest version at that exact
immutable commit. One deterministic bot branch
and PR pin that commit and increment the Public patch release. Only `Cargo.toml`,
`Cargo.lock`, receiver/OpenAPI versions and the README/protocol version declarations
may change. Lock changes are limited to the old/new exact shared package
dependency closures; unrelated packages and non-causal dependency edges must stay
unchanged. Shared dependency and transitive upgrades within those closures are
allowed, while the five-direct-dependency boundary remains fixed. An incompatible
boundary change requires manual review instead.

App-created PRs must pass the natural `pull_request` workflow associated with that
PR number and exact head SHA. A manually dispatched branch build cannot substitute
for it or bypass an approval-required PR run. GitHub documents that
[`GITHUB_TOKEN`-created PRs require workflow approval](https://docs.github.com/en/actions/concepts/security/github_token),
which is why candidate creation uses the separate App installation token.
The reconciler merges only a clean PR whose tested base remains unchanged, verifies
the merge commit's two parents and identical candidate tree, then dispatches CI on
the exact merged `main` commit. It creates an immutable product tag and dispatches
that tag through the existing build, release and seven-node deployment jobs.
Installed Agents still update only when their local operator manually installs a
release.

Pending work resumes before considering a newer shared release. Existing dispatch
runs are identified by event, ref and SHA; a pending CI is polled, not repeatedly
started. A time limit defers remaining work to the next schedule. Failed CI stops
the workflow: inspect and manually rerun its failed jobs, then reconcile again.
API failures are errors, never “no update”. A changed main, modified/unknown bot
branch, conflicting tag or closed pending bot PR also stops reconciliation; human
changes are never force-pushed or automatically rebased. Closing the pending PR
therefore halts later updates until an operator resolves it.

For an explicitly approved recovery after a source fix advances main, manually
close the old unmerged bot PR, then set repository variable
`COLLECTORS_SUPERSEDE_PR` to `<PR-number>:<full-40-character-head-SHA>`. Only that
unchanged closed PR may be skipped after its trusted creator, single parent,
metadata, complete diff and shared release evidence are revalidated. The legacy
`github-actions[bot]` identity is allowed only in this recovery path. An open,
merged, changed-head or human-authored PR cannot be acknowledged this way. New App
branches include the tested base SHA suffix, preserving the old PR/ref without
force-push or deletion. Unknown orphan branches stop for operator inspection;
they are never adopted. Keep the acknowledgement until a successor PR exists,
then remove it. Without this exact acknowledgement, closing a pending PR still
halts updates.

For a read-only current/latest comparison, dispatch with `dry_run=true` or run:

```sh
python3 ops/update_collectors.py --dry-run
```

With configured App credentials, Actions dry-run also verifies the creator App
identity and repository scope. This verifies the stable shared tag, manifest and
CI, then prints whether an update is available without creating a branch, PR, tag, release or deployment. Enabling this automation does not itself bump the current
product version.

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

Select a device name or **View details** in the private device list to see full
collector data and resource charts. Public sharing pages expose that entry only
when the owner enables history; network values/charts require a separate network
opt-in. The public dialog never fetches a private report. The device list also shows a CPU sparkline. Private details
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

Public history requires the current enabled page with history explicitly enabled,
a page-bound encrypted routing reference and current device selection. Without
network sharing, network columns and values are removed server-side, even for
previously issued references or cached full history. Its stable `history_key` is a page-specific
pseudonym, never a private device ID. Private history requires owner session and
operation token. Removing a device deletes its indexed chunks and response caches;
disabling/rotating a page immediately prevents new historical reads. Historical
resource values are encrypted at rest and never include private collector data.

History starts accumulating when this version is activated; older unsaved samples
cannot be backfilled. Redis persistence/eviction follows the account's configured
Redis policy; this is retained telemetry, not a permanent archive or backup.

### Default-egress network accounting

Network overview/history count selected default-route interfaces instead of
adding loopback, Docker bridges, veth and tunnels. The interface inventory and
classified internal observations remain available privately. Default egress may
include LAN traffic on that same interface; internal groups are not globally
deduplicated bandwidth. Unknown egress is shown as unavailable. Older Lite Agents
need a manual update for route evidence, and old ambiguous totals are never used
as egress. Historical CPU/memory/disk are preserved; old ambiguous network points
become gaps rather than zeros. Corrected egress history begins with newly
identified egress samples; old per-interface traffic cannot be retroactively
reconstructed into destination-classified Internet bandwidth. See PROTOCOL.md for accounting v2 fields/migration.

### Anonymous sharing defaults (v1.3.1)

This restricts anonymous sharing, not the Public owner's access to their devices.
Owner full snapshots, raw JSON downloads, all collectors and full resource history
remain available with the same ownership checks. Agent collection is unchanged.

Each page stores `show_network` and `show_history`, both false by default. Existing
pages migrate to false as well; owners can enable either checkbox independently.
Creation defaults to false; updates preserve omitted flags. Anonymous snapshots
include visibility permissions (see v1.3.2 below); network values/accounting metadata only
appear with network sharing, and opaque history refs only with history sharing.
Changing a flag invalidates the cached public projection immediately. Historical
authorization is checked before each read, regardless of requested range/ref.

The anonymous `/api/platform-load` response contains only coarse availability and
a collection timestamp. It never returns platform tenant/device counts, Redis
memory, host load, request rates or internal performance metrics. Sharing pages
hide the platform-status section; the home page shows coarse service status.

### Selectable public columns (v1.3.2)

Each page can independently publish CPU, memory and disk usage (`show_cpu`,
`show_memory`, `show_disk`, default true), default-egress rates (`show_network`,
default false) and historical charts (`show_history`, default false). Name, online
state and last-report time remain visible. Existing pages keep their basic metrics.
Page creation uses these defaults; updates preserve omitted visibility settings.
The owner page form exposes these choices. Sensitive details, interface addresses,
processes and raw reports have no public option and remain owner-only.

The server omits disabled snapshot fields and filters both history columns and
point values, including cached responses and old references. History uses only
selected metrics in canonical time/CPU/memory/disk/network-rx/network-tx order.
With every metric disabled, effective history is off and the public history API
returns 403. `visibility` includes cpu/memory/disk/network/history and invalidates
view caches on changes. Owner full reports and six-column history remain intact.
