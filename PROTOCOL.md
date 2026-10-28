# Public monitoring contract v1.0.81

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
snapshots refresh at five-second boundaries rather than invalidating every page
for every report; access changes and publication are checked on every request.
An absent last report yields `online: null`; unavailable or absent Redis data never
becomes an inferred host outage. Offline percentages are null. Reporting deadlines
use server receive time and the configured interval. Browser polling defaults to
five seconds; optional authenticated, bounded SSE carries only invalidations and
rechecks access. Shared hosting does not promise native WebSocket streaming.

## Email

A normal identity with `email_verified: true` can bind its verified email and
explicitly enable notifications. No arbitrary recipient is accepted. Addresses
and queued recipients are encrypted. The optional Cron worker sends bounded
offline/recovery changes using validated STARTTLS; missing telemetry is skipped.
Email is not a login or recovery-key delivery channel. Users can disable delivery
or unbind the email, cancelling pending messages.

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
