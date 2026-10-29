#!/usr/bin/env bash
# Account infrastructure bootstrap, separate from receiver/Agent releases.
set -euo pipefail
output=${1:?Provide an empty output directory}
mkdir -p "$output"
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
curl -fsSL --proto '=https' --max-time 60 --retry 2 https://download.redis.io/releases/redis-8.2.11.tar.gz -o "$temporary/source.tar.gz"
printf '%s  %s\n' fba14b77c4bdcb2d5418b6741fc0cdaac4b78bc73eab9b2e5f3c255d597f16fa "$temporary/source.tar.gz" | sha256sum -c -
tar xzf "$temporary/source.tar.gz" -C "$temporary"
make -C "$temporary/redis-8.2.11" -j4 MALLOC=libc BUILD_TLS=no LDFLAGS=-static redis-server redis-cli
for name in redis-server redis-cli; do
  binary="$temporary/redis-8.2.11/src/$name"
  strip "$binary"
  file "$binary" | grep -Eq 'statically linked|static-pie linked'
  if readelf -l "$binary" | grep -q INTERP; then exit 1; fi
  if readelf -d "$binary" | grep -q NEEDED; then exit 1; fi
  install -m 0755 "$binary" "$output/$name"
done
(cd "$output" && sha256sum redis-server redis-cli > SHA256SUMS)
