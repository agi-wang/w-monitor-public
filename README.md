# W-Monitor Lite

An open-source Linux monitoring agent with full permitted **read-only collection**.
There is no remote command dispatcher, terminal, remote file manager, inbound
listener, software installer, or self-updater in this repository.

It collects CPU, memory, disks, network, processes, GPU/container/service evidence,
software inventory and security posture to the extent allowed by its OS user.
Read-only diagnostics can invoke fixed local tools (for example `nvidia-smi`,
`systemctl show`, `docker stats`, ping and traceroute). It does not elevate privileges.
Run as an ordinary user when possible; unavailable system data is reported explicitly.

## Manual installer

After installing `curl`, Python 3 and the current GitHub CLI, download the
reviewable installer and run it yourself:

```sh
curl -fsSL https://raw.githubusercontent.com/agi-wang/w-monitor-lite/main/install.sh -o install.sh
bash install.sh v1.0.80
```

It checks the checksum **and the signed repository/workflow/tag provenance**,
then atomically installs only the binary into `$HOME/.local/bin`. It does not
create a system service, start the agent, ask for root, or schedule future updates.
Omit the tag only when you intentionally want the latest stable release. If `gh`
requires authentication on your system, sign in with your own GitHub account or
build from source; the installer never receives a platform signing key.

## Run

Download the Linux AMD64 or ARM64 binary and its `.sha256` file from [Releases](https://github.com/agi-wang/w-monitor-lite/releases).
Verify the checksum and the GitHub Actions attestation before running it:

```sh
sha256sum -c w-monitor-lite-linux-amd64.sha256
gh attestation verify ./w-monitor-lite-linux-amd64 \
  --repo agi-wang/w-monitor-lite \
  --signer-workflow agi-wang/w-monitor-lite/.github/workflows/ci.yml
chmod 700 w-monitor-lite-linux-amd64
```

Create a private configuration directory and file:

```sh
mkdir -p "$HOME/.config/w-monitor-lite"
chmod 700 "$HOME/.config/w-monitor-lite"
(umask 077; cat > "$HOME/.config/w-monitor-lite/config.json" <<'JSON'
{
  "endpoint_url": "https://monitor.example.com/api/v1/report",
  "auth_token": "REPLACE_WITH_YOUR_OWN_BOOTSTRAP_KEY",
  "interval": 60000
}
JSON
)
./w-monitor-lite-linux-amd64 --config "$HOME/.config/w-monitor-lite/config.json"
```

The file must be owned by the current user, have mode 0600 and contain no URL
credentials. Only HTTPS is accepted in normal operation. A loopback-only
`--allow-local-http` switch is available for local development. No command-line
auth-token argument is provided. The first successful handshake persists the
server-issued telemetry credential and stable agent ID to this same private file.
`lite-state/` holds only this agent's local collection/security caches.

## Updates and compatibility

**Updates are manual.** Download and verify a new release, stop your local process
or user service, replace the binary and start it again. Responses containing
`commands`, `update_version`, remote terminal data or alternate transport endpoints
are ignored. Publishing a GitHub release does not update installed agents.

This version sends bounded full snapshots over outbound HTTP(S), using the
W-Monitor v1 report envelope. It does not open a TCP control connection or socket.
The receiving server must support the `agent.lite` capability marker and enforce
telemetry-only machine credentials. The corresponding W-Monitor server change is
required before using this with an older server. Public status pages are a separate,
server-side feature: they expose only the devices and scalar fields selected by
the account owner, and do not make these full reports public.

## Data and trust

Full read-only collection can include hostnames, addresses, local account names,
process names, service/configuration paths, public SSH-key metadata and security
evidence. Collection performs credential redaction, but this is not a sandbox or a
guarantee that arbitrary application output contains no sensitive text. Use only a
monitoring endpoint you trust. Private keys, browser sessions and full environment
files are not report payloads. Keep the bootstrap key and config private.

The optional proprietary audit-engine integration is not included; its collector
explicitly reports unavailable. The remaining collectors are derived from the
W-Monitor read-only sources; `vendor/w-hostmetrics` is MIT-licensed source so a
public checkout needs no private registry credentials.

## Build and release

Rust is pinned in `rust-toolchain.toml`; dependencies are locked in `Cargo.lock`.
On Linux with `musl-tools` installed:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
```

GitHub Actions builds static AMD64 and ARM64 binaries for main/PR checks. A
`vMAJOR.MINOR.PATCH` tag matching `Cargo.toml` and pointing into main publishes the
same artifacts after both builds succeed. Actions are pinned to commit IDs. The
build jobs have read-only repository permissions; the separate publisher has no
source checkout and never executes an uploaded binary. GitHub's short-lived OIDC
identity signs [build provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
without platform production keys or a long-lived signing secret. Existing release
assets are not overwritten.

See [SECURITY.md](SECURITY.md) for the security boundary and reporting process.
