#!/usr/bin/env python3
"""Forced SSH command for versioned receiver deployments to one hosting account.

Install this outside the web root. Input is one verified GitHub release archive;
SSH_ORIGINAL_COMMAND must be `deploy vX.Y.Z SHA256`. No shell commands are accepted.
Private config/database files are never read into deployment output or replaced.
"""
import ast
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

os.umask(0o077)
PRIVATE = Path.home() / ".w-monitor"
ROOT = Path.home() / "w-monitor-public"
CONFIG = PRIVATE / "deploy-config.json"
EXPECTED = {"server/app.py", "server/redis_cache.py", "server/encryption.py", "server/i18n.py", "server/metrics.py", "server/notify.py", "server/requirements.lock", "server/passenger_wsgi.py", "server/config.example.json", "server/openapi.json", "server/web/index.html", "server/web/app.js", "server/web/style.css"}


def atomic(path, data, mode=0o600):
    temporary = path.parent / (".wm-" + secrets.token_hex(16))
    with open(temporary, "xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def healthy(origin, version):
    for attempt in range(3):
        try:
            request = Request(origin + "/health", headers={"User-Agent": "W-Monitor-Public-Deploy", "Cache-Control": "no-cache"})
            with build_opener(NoRedirect()).open(request, timeout=5) as response:
                raw = response.read(65537)
            value = json.loads(raw) if len(raw) <= 65536 else {}
            if value.get("status") == "ok" and value.get("version") == version and value.get("release_tag") == "v" + version and value.get("mode") == "public" and value.get("host_control_enabled") is False and value.get("cache") == "redis":
                return True
        except Exception:
            pass
        if attempt < 2:
            time.sleep(3)
    return False


def deploy():
    arguments = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if len(arguments) != 3 or arguments[0] != "deploy" or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", arguments[1]) or not re.fullmatch(r"[a-f0-9]{64}", arguments[2]):
        raise RuntimeError("Only a versioned receiver deployment is allowed")
    tag, checksum = arguments[1:]
    if PRIVATE.is_symlink() or PRIVATE.stat().st_uid != os.geteuid() or PRIVATE.stat().st_mode & 0o077 or CONFIG.is_symlink() or CONFIG.stat().st_mode & 0o077:
        raise RuntimeError("Private deployment configuration is required")
    config = json.loads(CONFIG.read_text())
    origin = config["public_url"].rstrip("/")
    url = urlsplit(origin)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise RuntimeError("Invalid public origin")
    python = config["python"]
    wsgi = config["wsgi"]
    if not all(isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9/._-]+", value) for value in (python, wsgi)):
        raise RuntimeError("Invalid hosting Python executable")
    document_root = Path.home() / "domains" / url.hostname / "public_html"
    if document_root.is_symlink() or document_root.resolve() != document_root or not document_root.is_dir():
        raise RuntimeError("Expected dedicated account document root")
    ROOT.mkdir(mode=0o711, exist_ok=True)
    if ROOT.is_symlink() or ROOT.resolve() != ROOT:
        raise RuntimeError("Release directory cannot be a symlink")
    ROOT.chmod(0o711)
    releases = ROOT / "releases"
    releases.mkdir(mode=0o711, exist_ok=True)
    if releases.is_symlink():
        raise RuntimeError("Release directory cannot be a symlink")
    releases.chmod(0o711)
    with open(PRIVATE / "deploy.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        active_path = PRIVATE / "active-release.json"
        active = json.loads(active_path.read_text()) if active_path.exists() else {}
        active_tag = active.get("tag", "")
        if active_tag and tuple(map(int, tag[1:].split("."))) < tuple(map(int, active_tag[1:].split("."))):
            raise RuntimeError("Automatic deployments cannot downgrade an active release")
        raw = sys.stdin.buffer.read(192 * 1024 * 1024 + 1)
        if len(raw) > 192 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != checksum:
            raise RuntimeError("Archive size or checksum mismatch")
        # CI verifies provenance before sending this exact, bounded inventory.
        assets = {"w-monitor-lite-linux-amd64", "w-monitor-lite-linux-arm64", "install.sh", "w-monitor-public-server.zip"}
        inventory = assets | {name + ".sha256" for name in assets} | {"provenance.jsonl"}
        with zipfile.ZipFile(io.BytesIO(raw)) as delivery:
            entries = delivery.infolist()
            if len(entries) != len(inventory) or {item.filename for item in entries} != inventory or any(item.file_size > 64 * 1024 * 1024 or stat.S_ISLNK(item.external_attr >> 16) for item in entries):
                raise RuntimeError("Unexpected deployment assets")
            downloads = {name: delivery.read(name) for name in inventory}
        for name in assets:
            expected = hashlib.sha256(downloads[name]).hexdigest() + "  " + name
            if downloads[name + ".sha256"].decode().strip() != expected:
                raise RuntimeError("Asset checksum mismatch")
        server_archive = downloads.pop("w-monitor-public-server.zip")
        downloads.pop("w-monitor-public-server.zip.sha256")
        downloads["version.txt"] = (tag + "\n").encode()
        with zipfile.ZipFile(io.BytesIO(server_archive)) as archive:
            entries = archive.infolist()
            if len(entries) != len(EXPECTED) + 1 or {entry.filename for entry in entries} != EXPECTED | {"manifest.json"} or any(entry.file_size > 4 * 1024 * 1024 or stat.S_ISLNK(entry.external_attr >> 16) for entry in entries):
                raise RuntimeError("Unexpected release inventory")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("schema") != "w-monitor-public-release/v1" or manifest.get("version") != tag[1:] or set(manifest.get("files", {})) != EXPECTED:
                raise RuntimeError("Release manifest mismatch")
            source = {}
            for name in EXPECTED:
                data = archive.read(name)
                if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
                    raise RuntimeError("Source checksum mismatch")
                if name.endswith(".py"):
                    ast.parse(data, filename=name)
                if name.endswith(".json"):
                    json.loads(data)
                source[name] = data
            if ("VERSION = \"" + tag[1:] + "\"").encode() not in source["server/app.py"]:
                raise RuntimeError("Receiver version mismatch")
        target = releases / tag
        if target.exists():
            if target.is_symlink() or not (target / "archive.sha256").is_file() or (target / "archive.sha256").read_text().strip() != checksum:
                raise RuntimeError("A release version cannot be overwritten")
        else:
            staging = releases / (".staging-" + secrets.token_hex(16))
            staging.mkdir(mode=0o711)
            staging.chmod(0o711)
            try:
                for name, data in source.items():
                    path = staging / name
                    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    # LiteSpeed must traverse the app directory before changing
                    # UID. Only public source is readable; private data stays 0700.
                    path.parent.chmod(0o755)
                    atomic(path, data, 0o644)
                download_root = staging / "downloads"
                download_root.mkdir(mode=0o755)
                download_root.chmod(0o755)
                for name, data in downloads.items():
                    atomic(download_root / name, data, 0o644)
                subprocess.run([python, "-m", "venv", str(staging / "runtime")], check=True, timeout=45, stdout=subprocess.DEVNULL)
                subprocess.run([str(staging / "runtime/bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--require-hashes", "--only-binary=:all:", "--index-url", "https://pypi.org/simple", "--retries", "2", "--timeout", "10", "-r", str(staging / "server/requirements.lock")], check=True, timeout=150, stdout=subprocess.DEVNULL)
                atomic(staging / "archive.sha256", (checksum + "\n").encode())
                os.rename(staging, target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        htaccess = document_root / ".htaccess"
        if htaccess.is_symlink():
            raise RuntimeError("Hosting configuration cannot be a symlink")
        previous = htaccess.read_bytes() if htaccess.exists() else b"Require all denied\n"
        settings = f'Options -Indexes\nPassengerAppRoot "{target}/server"\nPassengerBaseURI "/"\nPassengerPython "{wsgi}"\nPassengerAppType wsgi\nPassengerStartupFile passenger_wsgi.py\nSetEnv WM_PUBLIC_CONFIG "{PRIVATE}/config.json"\n'
        atomic(htaccess, settings.encode(), 0o644)
        if not healthy(origin, tag[1:]):
            atomic(htaccess, previous, 0o644)
            raise RuntimeError("Candidate health failed; prior hosting configuration restored")
        previous_tag = active_tag if active_tag and active_tag != tag else active.get("previous_tag")
        atomic(active_path, json.dumps({"tag": tag, "sha256": checksum, "previous_tag": previous_tag}).encode())
        periodic = PRIVATE / "run_periodic.py"
        if not periodic.is_file() or periodic.is_symlink():
            raise RuntimeError("Trusted periodic entrypoint missing")
        previous_cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        if previous_cron.returncode not in (0, 1):
            raise RuntimeError("Cannot read account crontab")
        lines = [line for line in previous_cron.stdout.splitlines() if not line.endswith("# w-monitor-public")]
        lines.append(f"* * * * * {python} {periodic} >> {PRIVATE}/periodic.log 2>&1 # w-monitor-public")
        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True, timeout=10)
        subprocess.run([python, str(periodic)], check=True, timeout=60, stdout=subprocess.DEVNULL)
        # Retain active and one preceding immutable release. Application data and
        # configuration are outside this directory and never touched here.
        candidates = sorted((path for path in releases.iterdir() if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", path.name) and path.is_dir() and not path.is_symlink()), key=lambda path: tuple(map(int, path.name[1:].split("."))), reverse=True)
        keep = {target}
        if previous_tag and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", previous_tag):
            keep.add(releases / previous_tag)
        for candidate in candidates:
            if candidate not in keep:
                shutil.rmtree(candidate)
        print(json.dumps({"deployed": tag, "healthy": True, "host_control_enabled": False}))


if __name__ == "__main__":
    try:
        deploy()
    except Exception as error:
        print("Deployment refused: " + str(error), file=sys.stderr)
        raise SystemExit(1) from None
