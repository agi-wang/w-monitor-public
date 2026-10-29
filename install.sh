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
download_origin=https://monitor.20290708.xyz
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key|--endpoint|--config) [ "$#" -ge 2 ] || exit 2; agent_args+=("$1" "$2");
      if [ "$1" = --endpoint ]; then download_origin="${2%/api/v1/report}"; fi
      shift 2 ;;
    --verify-provenance) verify_provenance=true; shift ;;
    --public) [ "$#" -ge 2 ] || exit 2; public_origin="$2"; download_origin="${2%/}"; shift 2 ;;
    --language) [ "$#" -ge 2 ] || exit 2; language="$2"; shift 2 ;;
    v*) [ -z "$version" ] || exit 2; version="$1"; shift ;;
    *) echo 'Usage: install.sh [vX.Y.Z] [--public https://monitor.example.com | --key KEY] [--endpoint URL] [--config FILE] [--language en|zh-CN] [--verify-provenance]' >&2; exit 2 ;;
  esac
done
case "$language" in en|zh-CN) ;; *) echo 'Unsupported language' >&2; exit 2 ;; esac
for program in curl sha256sum install; do
  command -v "$program" >/dev/null 2>&1 || { printf 'Required tool not installed: %s\n' "$program" >&2; exit 1; }
done
if $verify_provenance; then command -v gh >/dev/null || { echo "gh is required for --verify-provenance" >&2; exit 1; }; fi
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) platform=linux-amd64 ;;
  aarch64|arm64) platform=linux-arm64 ;;
  *) echo 'Supported architectures: x86_64 and aarch64' >&2; exit 1 ;;
esac
if [ -z "$version" ]; then
  version=$(curl -fsSL --proto '=https' --tlsv1.2 --max-time 20 --retry 2 --max-filesize 1048576 \
    "$download_origin/downloads/version.txt")
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
asset="w-monitor-lite-$platform"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
base="$download_origin/downloads/$version"
files=("$asset" "$asset.sha256")
if $verify_provenance; then files+=(provenance.jsonl); fi
for file in "${files[@]}"; do
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 120 --retry 2 --max-filesize 134217728 \
    "$base/$file" -o "$temporary/$file"
done
(cd "$temporary" && sha256sum -c "$asset.sha256")
if $verify_provenance; then gh attestation verify "$temporary/$asset" --bundle "$temporary/provenance.jsonl" \
  --repo "$REPOSITORY" --source-ref "refs/tags/$version" \
  --signer-workflow "$REPOSITORY/.github/workflows/ci.yml"; fi
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
  exec "$binary_dir/w-monitor-lite" --public "$public_origin" --language "$language" "${agent_args[@]}"
fi
if [ "${#agent_args[@]}" -gt 0 ]; then exec "$binary_dir/w-monitor-lite" "${agent_args[@]}"; fi
