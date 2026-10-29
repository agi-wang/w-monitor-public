#!/usr/bin/env python3
"""Build public immutable assets for Cloudflare Pages' GitHub integration."""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
output = root / "artifacts/web"
output.mkdir(parents=True, exist_ok=True)
# Retain release assets so independent regions can roll forward separately.
for attempt in range(3):
    result = subprocess.run(["git", "fetch", "--quiet", "origin", "--tags"], cwd=root, capture_output=True, timeout=45)
    if result.returncode == 0:
        break
else:
    raise SystemExit("Cannot fetch public release asset history")
refs = subprocess.check_output(["git", "tag", "--list", "v*"], cwd=root, text=True).splitlines()
manifest = {}
for name in ("app.js", "style.css"):
    versions = [(root / "server/web" / name).read_bytes()]
    for ref in refs:
        result = subprocess.run(["git", "show", ref + ":server/web/" + name], cwd=root, capture_output=True, timeout=10)
        if result.returncode == 0:
            versions.append(result.stdout)
    for data in versions:
        digest = hashlib.sha256(data).hexdigest()
        target = output / "assets" / digest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest[name] = "/assets/" + hashlib.sha256(versions[0]).hexdigest() + "/" + name
(output / "assets-manifest.json").write_text(json.dumps(manifest, sort_keys=True))
(output / "index.html").write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>W Monitor Public assets</title><p>W Monitor Public static assets.</p></html>')
(output / "_headers").write_text("/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n  Access-Control-Allow-Origin: *\n  X-Content-Type-Options: nosniff\n/assets-manifest.json\n  Cache-Control: no-cache\n")
print("Packaged immutable public assets: " + str(len(list((output / "assets").rglob("*.*")))))
