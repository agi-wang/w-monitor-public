#!/usr/bin/env bash
# Manual installation/update only. No daemon, privilege escalation or self-update.
set -euo pipefail
umask 077
REPOSITORY=agi-wang/w-monitor-public
version=""
public_origin=""
language=en
agent_args=()
config_path="$HOME/.config/w-monitor-public/agent.json"
resume_args=()
existing_action=""
verify_provenance=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) [ "$#" -ge 2 ] || exit 2; config_path="$2"; shift 2 ;;
    --key|--endpoint) [ "$#" -ge 2 ] || exit 2; agent_args+=("$1" "$2");
      shift 2 ;;
    --verify-provenance) verify_provenance=true; shift ;;
    --no-realtime|--no-compression) agent_args+=("$1"); resume_args+=("$1"); shift ;;
    --public) [ "$#" -ge 2 ] || exit 2; public_origin="$2"; shift 2 ;;
    --language) [ "$#" -ge 2 ] || exit 2; language="$2"; shift 2 ;;
    v*) [ -z "$version" ] || exit 2; version="$1"; shift ;;
    *) echo 'Usage: install.sh [vX.Y.Z] [--public https://monitor.example.com | --key KEY] [--endpoint URL] [--config FILE] [--language en|zh-CN] [--verify-provenance]' >&2; exit 2 ;;
  esac
done
case "$language" in en|zh-CN) ;; *) echo 'Unsupported language' >&2; exit 2 ;; esac
# Query before release resolution, downloads, or replacement of the installed binary.
# The installer itself arrives on stdin, so interactive choices must use /dev/tty.
binary_dir="$HOME/.local/bin"
existing_binary="$binary_dir/w-monitor-lite"
if [ -f "$config_path" ] || [ -L "$config_path" ]; then
  if [ "$language" = zh-CN ]; then
    printf '检测到已有 Agent 配置：%q\n' "$config_path"
  else
    printf 'Existing Agent configuration: %q\n' "$config_path"
  fi
  if [ -x "$existing_binary" ] && [ ! -L "$existing_binary" ] && [ -O "$existing_binary" ] &&
    [ ! -L "$binary_dir" ] && [ -O "$binary_dir" ] &&
    permissions=$(stat -c %a "$binary_dir") && (( (8#$permissions & 8#022) == 0 )); then
    if ! "$existing_binary" --show-binding --config "$config_path" --language "$language"; then
      if [ "$language" = zh-CN ]; then
        echo '当前绑定未确认（旧版本可能不支持查询或节点暂不可达）；原配置保持不变。'
      else
        echo 'Binding unconfirmed (older Agent or unreachable receiver); original configuration is preserved.'
      fi
    fi
  else
    if [ "$language" = zh-CN ]; then echo '找不到可运行的本用户 Agent，当前绑定未确认。';
    else echo 'No executable owned Agent found; binding is unconfirmed.'; fi
  fi
  if [ "$language" = zh-CN ]; then
    echo '1) 继续使用当前安装（不下载、不重复启动）  2) 手动更新并使用原配置  3) 换节点（独立配置）  0) 退出'
  else
    echo '1) Keep current installation (no download or duplicate start)  2) Manually update with current config  3) Switch receiver (separate config)  0) Exit'
  fi
  choice=""
  if { exec 3<>/dev/tty; } 2>/dev/null; then
    while :; do
      printf '> ' >&3
      if ! IFS= read -r choice <&3; then choice=0; break; fi
      case "$choice" in 0|1|2|3) break ;; esac
    done
    exec 3>&-
  else
    if [ "$language" = zh-CN ]; then echo '无交互终端；仅显示信息，未更新或切换节点。';
    else echo 'No interactive terminal; no update or receiver change performed.'; fi
    exit 0
  fi
  case "$choice" in
    0) exit 0 ;;
    1)
      if [ "$language" = zh-CN ]; then echo '继续使用已有进程；若未运行，可执行：';
      else echo 'Keep the existing process; if stopped, resume with:'; fi
      printf '%q --config %q --language %q\n' "$existing_binary" "$config_path" "$language"
      exit 0 ;;
    2)
      existing_action=update
      public_origin=""
      agent_args=("${resume_args[@]}") ;;
    3)
      # Leave the existing identity intact; create a distinct local configuration.
      config_path="${config_path}.receiver-$(date +%s)-$$.json"
      ;;
  esac
fi
agent_args+=(--config "$config_path")
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
  release_url=$(curl -fsSLI --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 20 --retry 2 \
    --output /dev/null --write-out '%{url_effective}' "https://github.com/$REPOSITORY/releases/latest")
  [[ "$release_url" == "https://github.com/$REPOSITORY/releases/tag/"* ]] || { echo 'Invalid release URL' >&2; exit 1; }
  version="${release_url##*/}"
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
asset="w-monitor-lite-$platform"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
base="https://github.com/$REPOSITORY/releases/download/$version"
files=("$asset" "$asset.sha256")
if $verify_provenance; then files+=(provenance.jsonl); fi
for file in "${files[@]}"; do
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 120 --retry 2 --max-filesize 134217728 \
    "$base/$file" -o "$temporary/$file"
done
(cd "$temporary" && sha256sum -c "$asset.sha256")
if $verify_provenance; then gh attestation verify "$temporary/$asset" --bundle "$temporary/provenance.jsonl" \
  --repo "$REPOSITORY" --source-ref "refs/tags/$version" \
  --signer-workflow "$REPOSITORY/.github/workflows/ci.yml"; fi
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
if [ "$existing_action" = update ]; then
  # The old Agent may predate binding lookup. Query again using the verified update.
  "$binary_dir/w-monitor-lite" --show-binding --config "$config_path" --language "$language" || true
  if [ "$language" = zh-CN ]; then echo '更新完成。请停止旧进程后，用以下命令启动，避免重复采集：';
  else echo 'Update complete. Stop the old process before starting, to avoid duplicate collection:'; fi
  printf '%q --language %q ' "$binary_dir/w-monitor-lite" "$language"
  printf '%q ' "${agent_args[@]}"
  printf '\n'
  exit 0
fi
if [ -n "$public_origin" ]; then
  exec "$binary_dir/w-monitor-lite" --public "$public_origin" --language "$language" "${agent_args[@]}"
fi
if [ "${#agent_args[@]}" -gt 0 ]; then exec "$binary_dir/w-monitor-lite" --language "$language" "${agent_args[@]}"; fi
