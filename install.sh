#!/usr/bin/env bash
# Manual installation/update only. No daemon, privilege escalation or self-update.
set -euo pipefail
umask 077
REPOSITORY=agi-wang/w-monitor-lite
version="${1:-}"
for program in curl python3 gh sha256sum install; do
  command -v "$program" >/dev/null 2>&1 || { printf 'Required tool not installed: %s\n' "$program" >&2; exit 1; }
done
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) platform=linux-amd64 ;;
  aarch64|arm64) platform=linux-arm64 ;;
  *) echo 'Supported architectures: x86_64 and aarch64' >&2; exit 1 ;;
esac
if [ -z "$version" ]; then
  version=$(curl -fsSL --proto '=https' --tlsv1.2 --max-time 20 --retry 2 --max-filesize 1048576 \
    "https://api.github.com/repos/$REPOSITORY/releases/latest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
asset="w-monitor-lite-$platform"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
base="https://github.com/$REPOSITORY/releases/download/$version"
for file in "$asset" "$asset.sha256" provenance.jsonl; do
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 120 --retry 2 --max-filesize 134217728 \
    "$base/$file" -o "$temporary/$file"
done
(cd "$temporary" && sha256sum -c "$asset.sha256")
gh attestation verify "$temporary/$asset" --bundle "$temporary/provenance.jsonl" \
  --repo "$REPOSITORY" --source-ref "refs/tags/$version" \
  --signer-workflow "$REPOSITORY/.github/workflows/ci.yml"
binary_dir="$HOME/.local/bin"
[ ! -L "$binary_dir" ] || { echo 'Binary directory cannot be a symlink' >&2; exit 1; }
mkdir -p "$binary_dir"
[ -O "$binary_dir" ] || { echo 'Binary directory must belong to the current user' >&2; exit 1; }
python3 -c 'import os,stat,sys; m=os.stat(sys.argv[1]); sys.exit(1 if m.st_mode & 0o022 else 0)' "$binary_dir"
[ ! -e "$binary_dir/w-monitor-lite" ] || [ -f "$binary_dir/w-monitor-lite" ] || { echo 'Existing binary path is not a regular file' >&2; exit 1; }
staged="$binary_dir/.w-monitor-lite.$$.tmp"
[ ! -e "$staged" ] && [ ! -L "$staged" ] || { echo 'Staging path already exists' >&2; exit 1; }
( set -C; : > "$staged" )
install -m 700 "$temporary/$asset" "$staged"
mv -f "$staged" "$binary_dir/w-monitor-lite"
printf 'Installed %s to %s\n' "$version" "$binary_dir/w-monitor-lite"
echo 'Updates remain manual. Stop/restart your own process to use the new binary.'
