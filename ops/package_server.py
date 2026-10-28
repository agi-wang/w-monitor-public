#!/usr/bin/env python3
"""Create the fixed, hashed WSGI release bundle. No runtime configuration/data."""
import hashlib
import json
from pathlib import Path
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
paths = sorted(path for path in (ROOT / "server").rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
allowed = {"app.py", "redis_cache.py", "encryption.py", "i18n.py", "metrics.py", "notify.py", "requirements.lock", "passenger_wsgi.py", "config.example.json", "openapi.json", "web/index.html", "web/app.js", "web/style.css"}
if {path.relative_to(ROOT / "server").as_posix() for path in paths} != allowed:
    raise SystemExit("Server source inventory does not match the release allowlist")
if f'VERSION = "{version}"' not in (ROOT / "server/app.py").read_text():
    raise SystemExit("Agent/server release versions must match")
output = ROOT / "artifacts"
output.mkdir(exist_ok=True)
archive = output / "w-monitor-public-server.zip"
manifest = {"schema": "w-monitor-public-release/v1", "version": version, "files": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
    for path in paths:
        info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
        info.external_attr = 0o100600 << 16
        bundle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    bundle.writestr("manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")))
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / (archive.name + ".sha256")).write_text(checksum + "  " + archive.name + "\n")
print(f"Packaged public receiver {version}: {len(paths)} source files")
