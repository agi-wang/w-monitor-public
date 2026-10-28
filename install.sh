#!/usr/bin/env bash
# Manual installation/update only. No daemon, privilege escalation or self-update.
set -euo pipefail
umask 077
REPOSITORY=agi-wang/w-monitor-public
version=""
public_origin=""
language=en
agent_args=()
verify_provenance=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key|--endpoint|--config) [ "$#" -ge 2 ] || exit 2; agent_args+=("$1" "$2"); shift 2 ;;
    --verify-provenance) verify_provenance=true; shift ;;
    --public) [ "$#" -ge 2 ] || exit 2; public_origin="$2"; shift 2 ;;
    --language) [ "$#" -ge 2 ] || exit 2; language="$2"; shift 2 ;;
    v*) [ -z "$version" ] || exit 2; version="$1"; shift ;;
    *) echo 'Usage: install.sh [vX.Y.Z] [--public https://monitor.example.com] [--language en|zh-CN]' >&2; exit 2 ;;
  esac
done
case "$language" in en|zh-CN) ;; *) echo 'Unsupported language' >&2; exit 2 ;; esac
if [ -n "$public_origin" ]; then
  [ ! -e "$HOME/.config/w-monitor-public/agent.json" ] && [ ! -L "$HOME/.config/w-monitor-public/agent.json" ] || { echo 'An Agent config already exists. Use your saved configuration; refusing to create a duplicate space.' >&2; exit 1; }
fi
for program in curl sha256sum install; do
  command -v "$program" >/dev/null 2>&1 || { printf 'Required tool not installed: %s\n' "$program" >&2; exit 1; }
done
if [ -n "$public_origin" ]; then command -v python3 >/dev/null || { echo "Python 3 is needed for anonymous setup" >&2; exit 1; }; fi
if $verify_provenance; then command -v gh >/dev/null || { echo "gh is required for --verify-provenance" >&2; exit 1; }; fi
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) platform=linux-amd64 ;;
  aarch64|arm64) platform=linux-arm64 ;;
  *) echo 'Supported architectures: x86_64 and aarch64' >&2; exit 1 ;;
esac
if [ -z "$version" ]; then
  version=$(curl -fsSL --proto '=https' --tlsv1.2 --max-time 20 --retry 2 --max-filesize 1048576 \
    "https://api.github.com/repos/$REPOSITORY/releases/latest" | sed -n 's/.*"tag_name": *"\(v[0-9]*\.[0-9]*\.[0-9]*\)".*/\1/p')
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
asset="w-monitor-lite-$platform"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
base="https://github.com/$REPOSITORY/releases/download/$version"
files=("$asset" "$asset.sha256")
if $verify_provenance; then files+=(provenance.jsonl); fi
for file in "${files[@]}"; do
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 120 --retry 2 --max-filesize 134217728 \
    "$base/$file" -o "$temporary/$file"
done
(cd "$temporary" && sha256sum -c "$asset.sha256")
signer_repository="$REPOSITORY"
# The immutable first release predates the repository rename. Its signed
# certificate must still match the original identity, never a broad fallback.
if [ "$version" = v1.0.80 ]; then signer_repository=agi-wang/w-monitor-lite; fi
if $verify_provenance; then gh attestation verify "$temporary/$asset" --bundle "$temporary/provenance.jsonl" \
  --repo "$signer_repository" --source-ref "refs/tags/$version" \
  --signer-workflow "$signer_repository/.github/workflows/ci.yml"; fi
binary_dir="$HOME/.local/bin"
[ ! -L "$binary_dir" ] || { echo 'Binary directory cannot be a symlink' >&2; exit 1; }
mkdir -p "$binary_dir"
[ -O "$binary_dir" ] || { echo 'Binary directory must belong to the current user' >&2; exit 1; }
permissions=$(stat -c %a "$binary_dir")
(( (8#$permissions & 8#022) == 0 )) || { echo "Binary directory must not be writable by other users" >&2; exit 1; }
[ ! -e "$binary_dir/w-monitor-lite" ] || [ -f "$binary_dir/w-monitor-lite" ] || { echo 'Existing binary path is not a regular file' >&2; exit 1; }
staged="$binary_dir/.w-monitor-lite.$$.tmp"
[ ! -e "$staged" ] && [ ! -L "$staged" ] || { echo 'Staging path already exists' >&2; exit 1; }
( set -C; : > "$staged" )
install -m 700 "$temporary/$asset" "$staged"
mv -f "$staged" "$binary_dir/w-monitor-lite"
printf 'Installed %s to %s\n' "$version" "$binary_dir/w-monitor-lite"
echo 'Updates remain manual. Stop/restart your own process to use the new binary.'
if [ -n "$public_origin" ]; then
  python3 - "$public_origin" "$binary_dir/w-monitor-lite" "$language" <<'PYTHON_PUBLIC_SETUP'
import http.cookiejar
import json
import os
import re
from pathlib import Path
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

origin, binary, language = sys.argv[1:]
url = urllib.parse.urlsplit(origin)
if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
    raise SystemExit("Public setup requires a fixed HTTPS origin without credentials")
origin = origin.rstrip("/")
directory = Path.home() / ".config/w-monitor-public"
if directory.is_symlink():
    raise SystemExit("Private config directory cannot be a symlink")
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
if directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
    raise SystemExit("Private config directory must be owned by you with mode 0700")
descriptor = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
# Reserve the file before creating any remote state; never replace an existing
# device's credentials or silently register the host into a second space.
file = os.open("agent.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
def request(path, value=None, csrf=None):
    headers = {"Accept": "application/json", "Accept-Language": language, "User-Agent": "W-Monitor-Public-Setup"}
    if value is not None:
        headers.update({"Content-Type": "application/json", "Origin": origin, "X-CSRF-Token": csrf})
    req = urllib.request.Request(origin + path, data=None if value is None else json.dumps(value).encode(), headers=headers)
    with client.open(req, timeout=15) as response:
        raw = response.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("Setup response exceeds limit")
    return json.loads(raw)
try:
    session = request("/api/session")
    result = request("/api/spaces/create", {"title": socket.gethostname()[:80] or "My device", "auto_public_page": True}, session["csrf"])
    for key, pattern in (("recovery", r"wmr_[a-f0-9]{64}"), ("bootstrap_key", r"wmb_[a-f0-9]{64}")):
        if not re.fullmatch(pattern, result.get(key, "")):
            raise ValueError("Invalid setup credential")
    for key, path in (("manage_url", "manage"), ("status_url", "status")):
        if not re.fullmatch(re.escape(origin) + "/" + path + r"/wm1_[A-Za-z0-9_-]{40,320}", result.get(key, "")):
            raise ValueError("Setup addresses must stay on the chosen origin")
    if result.get("ingest_url") != origin + "/api/v1/report":
        raise ValueError("Invalid report endpoint")
    # Show the only recovery copy before any further step can fail.
    labels = ("私密恢复 Key（请保存，勿公开）", "管理地址", "公开状态页") if language == "zh-CN" else ("Private recovery key (save securely, do not share)", "Management", "Public status")
    for label, key in zip(labels, ("recovery", "manage_url", "status_url")):
        print(label + ": " + result[key], flush=True)
    with os.fdopen(file, "w") as stream:
        file = None
        json.dump({"endpoint_url": result["ingest_url"], "auth_token": result["bootstrap_key"], "interval": 60000, "compress_reports": True}, stream)
        stream.flush()
        os.fsync(stream.fileno())
except Exception as error:
    if file is not None:
        os.close(file)
        os.unlink("agent.json", dir_fd=descriptor)
    if isinstance(error, urllib.error.HTTPError):
        raise SystemExit("Setup rejected: HTTP " + str(error.code)) from None
    raise SystemExit("Setup failed; keep any recovery key printed above. No automatic retry or update was scheduled.") from None
finally:
    os.close(descriptor)
print("首次真实上报后，设备会自动出现在公开页。Agent 在前台运行；按 Ctrl+C 停止，更新仅手动执行。" if language == "zh-CN" else "The first real report publishes this device. The Agent runs in the foreground; Ctrl+C stops it. Updates remain manual.", flush=True)
os.execv(binary, [binary, "--config", str(directory / "agent.json")])
PYTHON_PUBLIC_SETUP
fi

if [ "${#agent_args[@]}" -gt 0 ]; then exec "$binary_dir/w-monitor-lite" "${agent_args[@]}"; fi
