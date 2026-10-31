# Public monitoring contract v1.4.4

[OpenAPI](server/openapi.json) describes browser, ingestion and public-status APIs.
This receiver implements the existing v1.0 full report envelope; it has no Private
server dependency or host-control transport. Unknown report fields are tolerated.

## Lite → receiver

Send UTF-8 JSON (identity or gzip Content-Encoding) over HTTPS to the common `/api/v1/report` endpoint with
`Authorization: Bearer <bootstrap-or-device-token>`. Maximum wire and decoded body: 8 MiB.
The hashed Bearer credential identifies the space and device; the endpoint is identical for all tenants.
Required fields: `version: "1.0"`, nonempty bounded `agent_id`, object `collectors`.
Optional `hostname` supplies the display name. Collector values may be direct
objects or `{ "data": {...} }` wrappers; full reports remain visible only to the
space owner. CPU `usage_percent`/`usage`, memory and disk `usage_percent` project
to finite percentages between 0 and 100. Additional fields do not become public.

Registration returns a `sat_` device token, which the Lite Agent persists in its
private config. That token is bound to the space **and** stable agent ID. The
bootstrap key permits new registration, not browser reads. Re-registering the same
ID using the bootstrap key rotates its token. Revoking a device removes its token;
rotate a leaked bootstrap key separately to prevent new registrations.

A successful response contains `status: "ok"`, `agent_id`, `scope: "telemetry"`,
`commands: []`, `report_role: "primary"`, and a bounded `report_interval_ms`.
Unsupported delta input returns `request_full_report: true` without storing a
snapshot. There are no commands, update URLs, control-channel endpoints or ACKs.
Lite ignores control/update fields even when talking to a different server.
Redis failure returns 503; the report is not acknowledged. Steady-state reports
authenticate with a SQLite read and update only Redis. Public Agent configs enable
gzip; other receiver configs opt in locally with `compress_reports: true`.

## Language negotiation

The backend chooses `zh-CN` or `en` using `Accept-Language` quality and order,
with English as the fallback. Responses include `Content-Language` and
`Vary: Accept-Language`. HTML and `/i18n.js` use the same catalog; API error
messages are localized while machine-readable field names remain stable.
Tenant-provided names and collected host content are never translated. Email
notifications retain the locale selected when the user binds/saves settings.

## Browsers and recovery

`GET /api/session` issues a Secure, HttpOnly, SameSite=Lax session cookie and CSRF
token. Space create/restore works anonymously; the private recovery key is 256-bit
random material and stored only as a digest. Keep the returned value privately.
`POST /api/spaces/create` may explicitly request `auto_public_page: true`. It
returns the additional `ingest_url`, `manage_url` and `status_url` fields. The
page starts empty and selects only the first successfully registered real device
in the registration transaction; it does not publish subsequent devices. This
supports the homepage's manual one-command bootstrap, which prints the recovery
key and starts the local Agent after release verification.

Normal OAuth login can claim a space; claiming/rotating recovery revokes other
sessions and rotates the registration key. Existing device tokens remain valid.

Private space reads require both the current session and its encrypted
`X-Operation-Token`. Mutations additionally require exact configured `Origin` and
`X-CSRF-Token`. Encrypted management URLs identify a space but do not log anyone in.
The normal OAuth client uses state, PKCE and a fixed callback. An authenticated
identity may explicitly claim a recovered space; identity never grants host control.

## Public pages and refresh

Each space supports independently selected pages without a fixed count quota. Only device IDs owned
by that space can be selected. `/status/{encrypted-token}` renders the page and
`/api/public/status/{encrypted-token}` returns only names, online status, last receive
time, CPU/memory/disk percentages, data availability and refresh metadata. Lists are paginated using zero-based `?page=N` with 100 devices per page and
`page`, `page_size`, `total` response fields. This limits work per view without
limiting registered or published device counts. The owner-only `/api/device-options`
returns the complete device ID/name list for selection. There are no device
identifiers in public projections, addresses, full collectors or credentials. Disabled,
rotated or deleted links return 404 before cache access.

Redis holds AES-GCM-encrypted dynamic reports/metrics and short view caches.
SQLite holds only durable identity/ownership/credential/page/contact/outbox state.
Raw snapshots are compressed before encryption and expire five minutes after their
last update; last-seen metrics remain until the device is removed. View caches have
fixed scope/page keys with short expiry and bounded working memory. Responses use
ETag/If-None-Match after authorization, returning 304 when unchanged. Shared
snapshots refresh at configured subsecond boundaries rather than invalidating every page
for every report; access changes and publication are checked on every request.
An absent last report yields `online: null`; unavailable or absent Redis data never
becomes an inferred host outage. Offline percentages are null. Reporting deadlines
use server receive time and the configured interval. Browser polling follows the server-provided refresh_ms; optional authenticated, bounded SSE carries only invalidations and
rechecks access. Shared hosting does not promise native WebSocket streaming.

## Email

A normal canonical W-ID login can explicitly bind its original verified OAuth
subject for W-Mail notifications, including accounts without an external email.
The receiver's hashed local owner is never used as that subject. W-ID/W-Mail
resolve its chosen or sole mailbox, enforce current exact-product admission and
check the target again before provider submission. Other OIDC issuers cannot
select a W-ID recipient. SMTP continues to require `email_verified: true` and
binds only that login's verified contact. No arbitrary address or user ID is
accepted from the caller. Subjects, addresses and queued targets are encrypted.
The optional Cron worker sends bounded offline/recovery changes; SMTP uses
validated STARTTLS and W-Mail uses its authenticated project API. Missing telemetry is skipped.
Email is not a login or recovery-key delivery channel. Users can disable delivery
or unbind the target, retaining pending records as superseded history. Existing
W-Mail POST markers always reconcile by GET only; legacy unposted address-mode
W-Mail records require rebinding and are never replayed.

`GET /api/email` adds `provider`, `binding` (`w-id`, `email` or null),
`requires_login` and `requires_rebind`. In W-ID mode `email` is null, without
disclosing the centrally resolved address; `enabled` and binding existence remain
independent. `can_bind` requires a fresh trusted W-ID subject for W-Mail or a
verified contact for SMTP. Existing cookie, operation-token, Origin and CSRF
requirements remain. `POST /api/email/bind` still accepts only explicit enablement,
never a target. Enabling a binding from another provider returns409 until rebind.

`GET /api/email/deliveries` reads retained **system** mail history for only the
current cookie-selected space and requires its `X-Operation-Token`. It remains
available after disabling/unbinding notifications or removing provider settings.
It returns `{items, nextBefore}`, ordered by decreasing outbox ID. `limit` defaults
to20 and accepts1–100; pass the opaque, space-bound `nextBefore` as `before` for
the next page. Invalid, repeated or unknown parameters and wrong-space cursors
return400. No offsets or caller-selected space/recipient are accepted.

Items expose `id`, `channel: "system"`, `provider`, `deviceId`, `eventType`,
`status`, `attempts`, `operationId`, `eventId`, `attemptId`, `jobId`, `providerId`,
`submissionStatus`, `recipientStatus`, safe `review`, `createdAt`, `attemptedAt`,
`checkedAt`, `completedAt`, fixed `code`, `checkCount` and `reconcileComplete`.
Times are Unix seconds; unavailable legacy times/IDs are null. `checkCount` counts
GET receipt lookups. `reconcileComplete` means polling has stopped, including
deadline exhaustion, failure and supersession; it is not proof of delivery.
SMTP `sent` means relay acceptance only. W-Mail `provider_accepted`/`submitted`
also remains distinct from recipient `delivered`; failed receipt lookups retain
previously verified acceptance and polling remains bounded to six GETs/two days.

The endpoint performs no send, retry, reconciliation, session renewal or delivery
mutation. Its whitelist projection never decrypts recipients or renders content,
and excludes addresses/subjects, user IDs, ciphertext, bodies, private links,
credentials and raw provider errors. System project senders, queue budgets and
Sent auditing remain independent of personal receiving mailboxes. Existing SMTP
verified external contacts remain supported without creating W-ID recipients.
Revoking a device retains its original `deviceId` and mail history. Its unposted
pending rows become `superseded` with `mail_device_revoked`; posted W-Mail rows
continue original-key GET reconciliation even though the device no longer exists.
Explicit deletion of the entire monitoring space still deletes that space's
private data, including this history. No cross-space administrator access is added.

## Platform load

Public `GET /api/platform-load` reads a cached aggregate snapshot, refreshed once
per minute by `server/metrics.py` from account Cron. It returns `available: false`
when the snapshot is missing or older than three minutes. Numeric fields describe
registered/online/unknown device counts, previous complete minute request rate,
mean application processing time, 5xx rate, dedicated Redis memory, collection
time and shared-host load averages. Missing request samples remain null. No tenant
identifiers, names, contact details, addresses, credentials or raw reports appear.
Host load is explicitly shared-host scope, not account CPU usage. Request counters
use three-minute Redis buckets and never write SQLite.

Credential matching uses an exact SHA-256 lookup in a SQLite UNIQUE index. Token
prefixes select either the bootstrap-key index or device-token index; they do not
authorize requests. Established devices need one indexed lookup and no SQLite
write. Invalid credentials are rejected before report decompression. Bootstrap
registration rechecks the key inside its write transaction to serialize revocation.

Public downloads use GET/HEAD `/downloads/[vX.Y.Z/]filename` with a fixed allowlist
for the installer, Linux amd64/arm64 binaries, SHA-256 inventories, provenance and
`version.txt`. Versioned responses are immutable. Current aliases revalidate.
Files stream with bounded buffers and never expose configuration or tenant data.

## Runtime cadence and fast samples

The private server configuration controls `report_interval_ms` (full reports,
default 60000), `metrics_interval_ms` (default 3000), `page_refresh_ms` (default
1500) and `snapshot_cache_ms` (default 500). Edit configuration and restart the
receiver to change them without compiling. Every successful report response
returns both report intervals; the Agent validates and adopts each response.
Status snapshots return `refresh_ms`, and the browser adjusts its polling period.
These defaults target roughly five-second resource visibility; network delay and
actual host capacity must be measured separately.

After a full report establishes a device token, a supporting Agent sends bounded
CPU/memory/disk/network samples using `X-WM-Report-Kind: metrics` and
`report_kind: "metrics"`. Decoded/wire fast samples are limited to 64 KiB and
require a device credential. Fast samples update Redis metrics and last-seen time;
they never replace or extend the full diagnostic snapshot. Full read-only
collection continues at its own cadence. Old Agents ignore the additive interval
hint and continue full reporting; Agent upgrades remain manual. Invalid keys are
rejected before decompression, and valid-device request protection is scoped to
the credential rather than a shared NAT address.

GET `/api/regions` returns the runtime-configured regional names and origins.
Regions hold independent spaces, keys, SQLite and Redis data. Website commands
explicitly pass that website's origin; an unconfigured Agent launched without
parameters uses terminal prompts to select a region and either enter a key or
create a new anonymous space. Creation prints recovery/management/public links.
Only non-recovery links may be saved with the device configuration.

Online state, aggregate counts and notifications use the same per-device expected
interval. Supporting Agents advertise `metadata.capabilities["telemetry.metrics"]`
and fast samples use the configured metrics interval; legacy devices retain their
full-report deadline. Runtime `offline_grace_ms` (default 15000) prevents short
collection/network gaps from producing false outage transitions.

Local setup flags `--no-realtime` and `--no-compression` persist initial client
preferences. With realtime disabled, `telemetry.metrics` is false and the Agent
ignores lightweight cadence hints while retaining full reports.

### Allowlisted online settings

Owner-authenticated GET/POST `/api/devices/{id}/settings` manages exactly two
boolean fields: `realtime_metrics` and `compress_reports`. POST requires the
selected-space management operation token, Origin and CSRF token; unknown fields
or non-boolean values are rejected. A device-settings table stores desired values
with an ON DELETE CASCADE device foreign key. Telemetry reads the indexed
settings row along with device authentication; it does not write SQLite.

A report reply may include `agent_config` with `version: 1`, a 16-character lower
hex `revision`, and `settings` containing exactly the two booleans. The Agent
independently validates all these conditions before atomically changing only
those local preferences. Malformed or unsupported envelopes are ignored.
Commands, endpoints, credentials, paths and updates remain excluded.

New Agents advertise `telemetry.settings: 1`, `telemetry.metrics`,
`telemetry.compression`, and `telemetry.config_revision` in metadata capabilities.
They immediately send a full report after applying a changed revision. Pending
state clears only after both that revision and the exact settings are reported.
Offline devices retain pending preferences. Installation flags are initial
preferences; saved online preferences take precedence. Legacy Agents continue
reporting but require a manual update to support online configuration.


### Independent client-held ownership and device keys (1.1.0)

Ed25519 signing uses browser WebCrypto, the existing ring TLS crypto backend in
Rust, and the locked PyCA cryptography package for server verification. Spaces
and devices have independent random 32-byte seeds. New recovery is wmr2_ followed
by 64 lower hex characters; it is never sent to an API. Legacy wmr_ remains a
legacy recovery secret, not a newly generated private key.

Browser ownership proof: POST /api/keys/challenge with purpose and public_key;
sign wm-space-v1 LF origin LF purpose LF challenge. Challenges are sealed,
current-session/purpose/space/public-key bound, expire 120s and are consumed once
in Redis. Create, bind, restore, rotate and claim paths accept the proof. Restore
rotates SID/CSRF; account claim additionally verifies the existing W-ID identity.
Old recovery can bind a fresh key; only explicit rotation revokes the old recovery.

Device proof headers and canonical message are defined in OpenAPI. They bind the
wire-body hash, bearer-credential hash, kind, encoding, origin and monotonic Unix
millisecond timestamp. Verification precedes any report acknowledgement. A Redis
CAS retains one timestamp per key+credential (TTL 600s, clock window 300s), bounding
memory by active devices instead of report count. Legacy auth remains only for
unbound devices. The first valid signed report binds the independent public key;
all subsequent reports require it. Private keys never enter reports or SQLite.

Durable space_keys/device_keys tables cascade on owner-authorized deletion.
Existing devices, tokens, pages and account relationships remain unchanged.
Browser cookies persist 30 days by default; browser_session_days accepts 7-365.
The IndexedDB key is non-exportable; logout clears the active-key reference,
while saved account ownership remains server-side for explicit future login.

## Redis-backed historical resource samples (v1.2.0)

GET `/api/devices/{id}/history?range=15m` requires the same owner session and
operation token as complete device reads. Public snapshots add `history_key`
(page-specific opaque pseudonym) and `history_ref` (page-bound encrypted routing
reference). GET `/api/public/status/{slug}/history?ref=REFERENCE&range=15m` checks
the current slug, enabled page, tenant and selected device on every read. A ref
from another page, removed device or old/disabled page is rejected with404.
These refs never grant access to complete reports or device operations.

`range` is one of `15m`, `1h`, `24h`, `7d`, `30d`, `all` (default `15m`). Response
`columns` is `[time,cpu_percent,memory_percent,disk_percent,network_rx_bps,network_tx_bps]`;
`points` is an ordered array of corresponding six-element rows, at most720, with
Unix-second bucket starts and null for a missing metric. Unknown fields remain
tolerated. `from`, `to`, `resolution_seconds`, `retention_seconds`,
`max_retention_seconds` and `refresh_ms` describe the bounded returned range.
`storage=redis`, `aggregation=sample_weighted_mean`. Queries select retained
second/minute/hour tiers and aggregate weighted counts for wider ranges. Reports
retain their existing envelope and cadence; server rollout needs no Agent update.
Historical samples are acknowledged atomically with current telemetry; Redis or
CAS failures return503. Responses remain private/no-store; shared server cache
is encrypted and does not bypass publication or owner authorization.

## Network accounting v2

The network collector now distinguishes `egress`, `lan`, `loopback`, `container`,
`tunnel`, and `unknown` observations. `accounting_version=2` with
`accounting_scope=default_route_interfaces` means `total_*` includes only selected
default-route logical interfaces, each once. `default_route_interfaces` lists
those names; each complete interface has `traffic_class`, and `traffic_groups`
contains receive/transmit cumulative bytes and rates plus interface counts.
IPv4/IPv6 lowest-metric active default routes are combined and deduplicated;
known container/tunnel/loopback paths and selected lower/member interfaces are
excluded. A route-carrying bridge/bond/VLAN can be the selected logical interface.

This is **default egress interface traffic**, not destination-classified Internet
traffic: a NAT/private-address egress interface remains valid, and that interface
can carry LAN traffic too. Internal groups are raw interface observations and
can overlap across bridges/veth; do not sum them as deduplicated LAN bandwidth.
No routing evidence yields null egress values, never an all-interface fallback.

Compact reports retain accounting/version/route/group fields. A legacy full report
can be recomputed only when it explicitly supplies selected default interfaces;
without that evidence legacy all-interface totals and compact totals are unknown.
Owners may still inspect individual legacy interfaces and their internal classes.
Old cached all-interface values are hidden. Manual Lite update is required to
obtain new route evidence; no remote update or host-control path is introduced.

Existing encrypted history chunks (`wmh1_`) retain CPU/memory/disk but their network
counts are ignored. New chunks (`wmh2_`) bind AES-GCM associated data to
`network-accounting-v2`, so changing a prefix cannot bypass the migration. An old
chunk touched by ingestion is rewritten with valid network samples only. Cache
purposes change with the accounting policy; old high network values cannot mix
with corrected default-egress curves, while old non-network history stays intact.

## Anonymous publication privacy (v1.3.1)

`PageWrite` adds independent booleans `show_network` and `show_history`, default
false on create when omitted; updates preserve stored flags. Both columns default false, including
migrated existing pages. Owner pages GET returns both flags. Owner complete
reports, collectors, raw JSON and resource history remain unchanged.

Anonymous snapshots include visibility permissions (expanded in v1.3.2 below). Default device fields
are only name, online, last_seen, cpu_percent, memory_percent and disk_percent.
Network rates/accounting_scope require show_network; history_key/history_ref
require show_history. Both flags enter the shared-view cache fingerprint.

Public history checks show_history on every request and rejects403 when disabled,
including old refs and any range. Columns and tuple values are filtered by the
selected metrics (see v1.3.2 below); network_accounting_scope is absent without
network sharing. Owner history always retains the full6-column form. Filtering
runs after the shared encrypted cache and does not mutate the owner's view.

`/api/platform-load` returns only available and, when current, collected_at.
Cross-tenant counts, Redis/RSS, host load and performance counters are not public.
No role system or Agent collection changes are introduced.

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

## Existing device binding lookup

POST `/api/v1/binding` accepts a JSON object with optional `agent_id` (string or
null, at most 255 UTF-8 bytes). It uses the existing `ReportBearer` credential.
A `sat_` token can inspect only its own device; a `wmb_` token can query its own
space and, when an agent ID is supplied, that device in the same space. A device
with a bound public key must sign this request using the existing device signature
headers and canonical envelope, with `POST`, `/api/v1/binding`, `full`, `identity`
and the exact request-body SHA-256. Existing report signatures are unchanged;
signatures cannot be replayed across paths. Binding queries use a separate
replay timestamp slot so they cannot suppress reports from a running Agent; the
existing reporting replay keys remain unchanged. Legacy unsigned devices remain
compatible until their normal signed report binds a key.

The response contains `status: "ok"`, `receiver_origin`, `region_id`,
`space: {id,title}`, `device: {id,agent_id,name}` or null, `last_report_at` (Unix
seconds or null), `dashboard_url` (ordinary login origin), and `public_pages`
(up to five `{title,url}` entries). Only enabled pages whose selection contains
exactly this device are returned. Multi-device/global pages, management tokens,
account identifiers, recovery secrets and private keys are never returned.

Lookup does not register devices, rotate tokens, bind keys, update heartbeats or
write history. Authentication replay/rate protections still apply. Invalid or
revoked credentials return 401; a mismatched device ID returns 403; malformed
requests return 400; Redis unavailability during signature verification returns
503. Missing telemetry alone returns null `last_report_at`, preserving durable
binding information. Old receivers return 404 and clients label lookup unconfirmed
while preserving their existing configuration and normal report compatibility.

## Agent-hosted service checks and availability (v1.4.0)

The Agent host can serve as its owner's probe. A local operator must explicitly
start with `--enable-service-probes` (persisted in its existing 0600 config).
Remote configuration cannot enable this consent. Older Agents remain supported
and need a local manual update to gain probing; they receive no new commands.

A signed Agent advertises `metadata.capabilities["telemetry.service_probes"]=true`.
The normal report response may then include a separate `service_probes` object:
`{revision,probes:[{id,kind,target,interval_seconds,timeout_seconds}]}`. It does not
extend the existing two-boolean `agent_config`, preserving older clients. Once the
Agent acknowledges the current revision, this object is omitted until it changes.
Only HTTP(S) GET and TCP connect are accepted, with no shell, custom headers,
credentials, query, fragment, redirects or response-body collection. HTTP status
200-399 means the first endpoint responds successfully; redirects are not followed.
Targets may be loopback/LAN because execution occurs on the opted-in user's host,
never on a receiver. Intervals are 60-3600 seconds, total timeouts 1-10 seconds,
with at most 64 checks / 32 KiB per configuration and eight concurrent checks.
Overdue work is scheduled fairly without accumulating a retry queue.

Reports optionally carry `service_probes:{revision,results:[{id,ok,status_code,
latency_ms,error,age_seconds}]}`. Result age uses Linux CLOCK_BOOTTIME, including
suspend. Accepted results must match the credential-bound device's configured
revision and IDs. Pending configuration, stale results or an offline probe make
service status unknown. No target URL, raw response, credential or exception is
uploaded. Error classes are only `timeout`, `connection_or_tls` or null.

`GET /api/devices/{id}/uptime?monitor=device&range=24h`, and owner/CSRF-protected
`POST /api/services/create|delete` are described in OpenAPI. Service targets and
history are private. Existing anonymous sharing does not acquire new fields.
History is minute-observed availability (not proof of uninterrupted service):
known up/down samples determine availability, unknowns are excluded and coverage
is reported separately. Missing minutes stay missing. Packed, compressed,
authenticated Redis chunks retain minute/hour tiers; `uptime_retention_days`
controls the longest tier (1-365 days, default30). Transition logs retain the most
recent100 entries per monitor (latest20 returned). Removing a device, monitor or
space removes its stored monitoring history. SQL holds definitions, not telemetry.
