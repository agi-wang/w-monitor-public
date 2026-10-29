# W Monitor Public

An independent, open-source monitoring suite: a Rust **Lite Agent** and a Python
**read-only receiver**. It runs separately from W Monitor Private. The receiver
has no host-command, terminal, remote-file or Agent-update implementation.

Create an anonymous monitoring space, save its private recovery key, and connect
your own agents. Restore the same space in another browser with that key. An
optional normal OAuth login can claim a space; login never grants host control.
Create several public pages, each with your own selection of devices. Visitors see
only names, online status and CPU/memory/disk percentages. Full reports stay private.

## One-command setup

The homepage offers **One-command device setup**. Copy its command to a Linux
host with curl, Python 3 and GitHub CLI installed. `install.sh --public ORIGIN`
verifies the Agent release, creates a new anonymous space and status page, writes
an owner-only config, prints the private recovery key and management/public URLs,
and starts the Agent in the foreground. The first real report selects that device
for the page; later devices are never published automatically. Existing Agent
configs are not overwritten. Save the printed key; use it to restore and optionally
claim the space in your browser. This explicit setup option starts the local Agent;
ordinary installation remains installation-only and all updates remain manual.

## Lite Agent

The Agent collects CPU, memory, disks, network, processes, GPU/container/service
evidence, software inventory and security posture within its OS user's permissions.
Fixed read-only diagnostic tools may run locally; it never elevates privileges.
Unavailable collection is represented explicitly. The proprietary audit engine is
omitted. The source and MIT-licensed `vendor/w-hostmetrics` need no private registry.

**Installation and updates are manual.** Review and run the installer yourself:

```sh
curl -fsSL https://raw.githubusercontent.com/agi-wang/w-monitor-public/main/install.sh -o install.sh
bash install.sh v1.0.81
```

It verifies checksums and the repository/workflow/tag attestation, then atomically
installs the binary in `$HOME/.local/bin`. It does not start it, create a service,
request root, or schedule updates. Installed Agents never upgrade on server request.
The preserved v1.0.80 release predates the repository rename and has the original
`agi-wang/w-monitor-lite` attestation identity; the installer handles that exact tag.

The space dashboard supplies a private configuration with `compress_reports: true`
(gzip over HTTPS, within the same 8 MiB decoded report limit), containing its encrypted
`endpoint_url` and registration credential. Save it as an owner-only file:

```sh
mkdir -p "$HOME/.config/w-monitor-public"
chmod 700 "$HOME/.config/w-monitor-public"
chmod 600 "$HOME/.config/w-monitor-public/agent.json"
w-monitor-lite --config "$HOME/.config/w-monitor-public/agent.json"
```

The file must already contain the dashboard's configuration. The first successful
report replaces the registration key with a device-bound telemetry token. Stop
your own process/service before manually replacing the Agent binary. Reports use
outbound HTTPS; server commands, update hints and alternate control transports
are ignored. Full read-only reports can contain sensitive host metadata, so use a
receiver you trust. See [SECURITY.md](SECURITY.md).

The backend selects Simplified Chinese or English from the browser’s
`Accept-Language` preferences (including quality values). Unsupported languages
fall back to English. Pages, UI messages and API errors share that selection;
notifications remember the browser language when email settings are saved.

## Receiver storage and security

- Redis stores compressed, encrypted dynamic reports, current metrics, short view caches,
  rate limits and bounded stream leases. Full snapshots expire five minutes after
  their last report; compact last-seen metadata remains. SQLite never stores
  telemetry snapshots. Steady-state reports do not write SQLite.
- SQLite persists monitoring spaces, hashed credentials, ownership, page choices,
  encrypted email contacts, consent and the bounded notification outbox.
- AES-256-GCM from PyCA encrypts purpose-bound public and management
  addresses, stored links, email contacts and Redis payloads. HTTPS is still required.
- A management address alone does not authorize access: a current session or
  recovery key is required. Browser changes additionally require Origin and CSRF
  validation. Report credentials cannot read the dashboard or operate a host.
- Missing Redis data displays unknown, rather than a false offline status. Failed
  ingestion returns 503; there is no SQLite telemetry fallback. There is no
  application quota on device/space/page counts or a required Redis memory cap.
  Status lists paginate 100 devices at a time and use conditional requests; page
  editing loads the complete owned device list separately.
- Back up the SQLite database **and the private instance encryption key**. Losing
  that key makes existing encrypted data and links unreadable. Do not rotate it
  casually; individual public links and recovery keys can be rotated in the UI.

Optional login uses standard Authorization Code + PKCE, `/oauth/authorize`,
`/oauth/token` and `/oauth/userinfo`, with `openid profile email`. W-ID can provide
normal GitHub login; this suite imports no private W-ID SDK. Configure a confidential
client with the exact callback `https://YOUR_DOMAIN/auth/callback`. Only a provider's
explicitly verified email can be bound, and notifications require user opt-in.
Without SMTP, the UI reports that delivery is unavailable.

## DirectAdmin deployment

Requires Python 3.12+, SQLite, a private managed Redis Unix socket, trusted HTTPS,
and Python WSGI support. HostBrr's verified LiteSpeed entry is
`/opt/alt/python313/bin/lswsgi`; the CLI/venv interpreter is
`/opt/alt/python313/bin/python3`. This is a host capability, not a guarantee that
all DirectAdmin/cPanel plans offer Python or persistent WebSockets.

Keep source **outside** `public_html`, for example
`$HOME/w-monitor-public/releases/v1.0.81/server`. Create a `runtime` venv beside
`server`, and install only the locked wheels:

```sh
/opt/alt/python313/bin/python3 -m venv runtime
runtime/bin/python -m pip install --require-hashes --only-binary=:all: -r server/requirements.lock
```

Copy `server/config.example.json` to `$HOME/.w-monitor/config.json`, set private
paths, fixed HTTPS origin, Redis socket and a random 32-byte hex `instance_secret`.
Use mode 0700 for `.w-monitor` and 0600 for its config/database. Never put them in
the web root. LiteSpeed needs traversal through source parents and read access to
public source files (parents 0711, source directories 0755, source files 0644).
Keep the venv and all private data owner-only.

The document root contains only `.htaccess`:

```apache
Options -Indexes
PassengerAppRoot "/home/ACCOUNT/w-monitor-public/releases/v1.0.81/server"
PassengerBaseURI "/"
PassengerPython "/opt/alt/python313/bin/lswsgi"
PassengerAppType wsgi
PassengerStartupFile passenger_wsgi.py
```

`passenger_wsgi.py` loads the adjacent release's venv packages. Verify `/health`
returns `mode: public`, `host_control_enabled: false`, `cache: redis`. The default
UI polls every five seconds. Optional bounded SSE invalidation is available with
`enable_events: true` only after verifying the host's streaming behavior; this is
not a WebSocket/control channel.

The homepage shows a cached platform-load snapshot refreshed by the account Cron
once per minute: request rate, mean application response time, 5xx rate, online/total
devices and Redis memory. System load is explicitly labeled as shared-host load,
not account CPU usage. The snapshot contains no tenant names, IDs or addresses.

Optional email uses a dedicated SMTP account with STARTTLS and certificate
validation. Set the `smtp_*` configuration fields. Run `server/notify.py` once per
minute using the release venv, or install `ops/run_periodic.py` as a stable
Cron entrypoint after automatic deployment is configured. It queues only opted-in
offline/recovery changes, skips unknown Redis state, and bounds retries and volume.

## CI, releases and receiver deployment

Rust is pinned, dependencies are locked, and AMD64/ARM64 Linux binaries must pass
the static musl gate. Python dependencies have exact versions and wheel hashes.
Pinned GitHub Actions check main/PRs; a matching `vMAJOR.MINOR.PATCH` tag contained
in main publishes the Agent binaries, installer and deterministic server ZIP with
checksums and artifact provenance. Existing release assets are immutable.

The separate `public-production` environment deploys the receiver and its versioned Agent downloads:

- Variables: `PUBLIC_DEPLOY_HOST`, `PUBLIC_DEPLOY_USER`.
- Secrets: a dedicated `PUBLIC_DEPLOY_KEY` and pinned `PUBLIC_DEPLOY_KNOWN_HOSTS`.
- On the child account, install `ops/deploy_receiver.py` outside the web root and
  restrict that key with `restrict,command="/opt/alt/python313/bin/python3 /home/ACCOUNT/.w-monitor/deploy_receiver.py"`.
- Private `.w-monitor/deploy-config.json` contains `public_url`, `python` (CLI
  interpreter) and `wsgi` (LiteSpeed interpreter). Never share reseller credentials.

The job verifies the published ZIP's checksum and tag/workflow attestation, then
sends it over restricted SSH. The receiver accepts a fixed file inventory, installs
hashed dependencies, activates an immutable release, verifies health, and restores
the previous hosting configuration on failure. Data/config are outside releases;
active and previous releases are retained. A deploy key inherently authorizes new
receiver code; protect repository/tag access and the deployment environment.
**This server deployment workflow never updates installed Agents.**

See [PROTOCOL.md](PROTOCOL.md) and [OpenAPI](server/openapi.json) for the contract.

All Public devices use the fixed `https://monitor.20290708.xyz/api/v1/report`
endpoint with `Authorization: Bearer <key>`. The registration key identifies the
space; the server exchanges it for a device-bound token on first report.
With the new binary, `w-monitor-lite --key <registration-key>` saves configuration
privately and starts collection. Use `--endpoint https://your-host/api/v1/report`
for a different receiver and `--config /private/path/agent.json` for a custom file.
The installer checks HTTPS downloads against the release SHA-256 inventory;
`--verify-provenance` additionally verifies the GitHub attestation using `gh`.

Public installation downloads `/downloads/install.sh`, `/downloads/version.txt`
and versioned `/downloads/vX.Y.Z/w-monitor-lite-linux-{amd64,arm64}` plus SHA-256
inventories from the receiver website. `--public https://your-host` creates an
anonymous space and prints recovery/management/public links in the Agent itself;
no Python or GitHub CLI is needed on the monitored host. No self-update is scheduled.

Tag CI builds and signs both static binaries, verifies all four published assets,
and transfers one fixed deployment inventory using the restricted SSH key. The
receiver, website downloads and installation commands activate together. The
dedicated account Cron refreshes cached platform load and optional notifications
every minute using the active release. CI never receives the tenant database or
application encryption/SMTP credentials.

On HostBrr, provision account Cron through DirectAdmin's `CMD_API_CRON_JOBS` API
(or panel) once, then set `periodic_enabled: true` in private deploy-config.json.
Run the stable `ops/run_periodic.py` entrypoint every minute. The forced SSH
environment cannot install Cron reliably; releases reuse the account Cron and
automatically select the newly activated version.

### Runtime tuning and regional setup

Cadence values are runtime configuration, not build options. Set
`report_interval_ms`, `metrics_interval_ms`, `page_refresh_ms` and
`snapshot_cache_ms` in the private receiver config, then restart its WSGI app.
The receiver returns cadence requirements with every report and status response.
The Agent keeps full diagnostic collection while sending small resource samples
more frequently. Existing installed Agents must be upgraded manually to use this.

Configure `region_id` and `regions: [{"id":"us","name":"United States",
"origin":"https://monitor.example.com"}]` per deployment; do not share database,
instance secret or Redis namespace between regions. Website installation passes
its own origin using `--public` for a new space or `--endpoint ... --key ...` for
an existing space. Running an unconfigured Agent without parameters opens a
terminal region/key setup. Existing configuration is reused without prompting.

Regional CI uses protected `public-production` (US) and `public-singapore` (SG)
environments. Each defines `PUBLIC_ORIGIN`, `PUBLIC_DEPLOY_HOST`,
`PUBLIC_DEPLOY_USER` and `PUBLIC_DEPLOY_TRANSPORT`. The SSH transport uses
`PUBLIC_DEPLOY_KEY` / `PUBLIC_DEPLOY_KNOWN_HOSTS` secrets. The DirectAdmin panel
transport uses `PUBLIC_DEPLOY_PANEL_URL`, `PUBLIC_DEPLOY_PRIVATE_DIR`,
`PUBLIC_DEPLOY_PYTHON` and the environment secret `PUBLIC_DEPLOY_PANEL_PASSWORD`.
It uploads the verified inventory privately, then invokes the preinstalled gate
through the authenticated panel terminal. Both transports verify active health
and website binary hashes. Provision the private gate/config and account Cron
once before enabling tag deployment. Ordinary hosting accounts share their Unix
identity with other vhosts; independent data directories are not OS isolation.

`offline_grace_ms` is also editable at startup (default 15000). Online status,
platform counts and notifications share one deadline calculation using each
device's negotiated reporting cadence, including legacy Agents.

### cPanel with an account-owned Redis

The `public-united-kingdom` GitHub environment uses cPanel UAPI Fileman and
account Cron with `PUBLIC_DEPLOY_PANEL_TOKEN` stored as an environment secret.
The reviewed transport uploads the attested immutable delivery to a private
folder, invokes the same private deployment gate once, checks its exit status,
and removes its temporary Cron entry. Existing account jobs are preserved.
Set `document_root` in private `deploy-config.json` to the exact cPanel-owned
absolute document root; the default remains DirectAdmin's domain directory.

If the provider does not supply Redis, build a pinned static Redis using
`ops/build_redis.sh /path/to/output` on Linux with a C compiler, libc static
archives, make and binutils. Install `redis-server` into the private deployment
folder's `bin/`, and `ops/redis_watchdog.py` beside `run_periodic.py`.
The private `redis/redis.conf` must set `port 0`, a mode-0600 Unix socket,
`daemonize yes`, private pid/log/directory paths, `save ""`, `appendonly no`,
`maxmemory 0`, and `enable-module-command no`. No Redis TCP listener or public
cache endpoint is used. User/space credentials remain durable in SQLite.
The existing account Cron wrapper checks Redis before metrics/notifications and
restarts a failed cache at the next minute tick. While Redis is unavailable,
ingest returns failure and pages show unknown status; Agent retries and resumes.
A recovered cache warms as Agents report again. This is not a lossless telemetry
store. No additional account or tenant resource quotas are imposed.

The deployment gate writes a mode-0600 `config-path` file beside each release's
`server/` directory. The WSGI entrypoint reads this private startup pointer before
loading the receiver. This avoids requiring Apache `mod_env` / `SetEnv`, which
some shared hosts omit. For a manual deployment, create the same owner-only file
containing the absolute private `config.json` path. On Apache use the ordinary
CloudLinux Python executable for `wsgi`; LiteSpeed uses its `lswsgi` executable.

### Automatic frontend publication on Cloudflare Pages

Connect this public GitHub repository to Cloudflare Pages, production branch
`main`, build command `python3 ops/package_web.py`, output `artifacts/web`.
Each merged commit automatically publishes JS/CSS assets. The build retains
content-addressed assets from release tags so regions can deploy independently.
GitHub CI also builds this output before a release passes its checks.

Set repository variable `PUBLIC_ASSETS_ORIGIN` to the Pages HTTPS origin so
GitHub verifies the exact tag's CDN asset bytes before receiver activation.
Set the receiver's private `static_assets_url` to the same origin, then
restart its application. Regional HTML uses hashed CDN URLs plus SHA-256
Subresource Integrity; CSP allows only that configured asset origin. Browser
language, authentication, API calls, installer parameters and data remain on the
selected regional origin. API/HTML responses retain their private no-store
headers. Cloudflare serves public JS/CSS with immutable caching and anonymous
CORS for integrity checks; it never receives cacheable tenant API responses.
