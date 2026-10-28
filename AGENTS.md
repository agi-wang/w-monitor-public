# W Monitor Public

Independent, open-source read-only monitoring suite: the existing Rust Lite Agent
and a Python WSGI receiver in `server/`. No dependency on W Monitor Private.

- Keep the Agent's full permitted read-only collection. Never add remote command,
  terminal/file control, a control listener, privilege escalation or auto-update.
- The receiver may manage monitoring spaces, credentials and status pages; it must
  never dispatch host operations or return executable/update directives.
- Use the smallest direct implementation; use the standard library except for
  the locked PyCA authenticated-encryption dependency. Keep collector wire types
  additive and tolerate unknown fields.
- Never put credentials, cookies, recovery keys, tenant reports or private runtime
  configuration in Git or evidence. Data/configuration stay outside the web root.
- Do not write unit or integration tests. Run syntax/lint/build checks and bounded
  manual acceptance against isolated data. Do not modify unrelated deployments.
- Before GitHub publication run `w-cli github export` and inspect the sanitized
  export. Preserve immutable existing release assets and attestations.
- Existing Agent checks: `cargo fmt --all --check`; Linux musl workspace clippy,
  static binary gate and dependency audit as defined in `.github/workflows/ci.yml`.
- Receiver checks: `python3 -m compileall -q server`; `node --check server/web/app.js`.
- Deployment/configuration usage belongs in README; the wire contract belongs in
  PROTOCOL.md and server/openapi.json. Durable environment findings go in Radar
  project `w-monitor-public`, workspace `ws_platform`.
