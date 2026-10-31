#!/usr/bin/env python3
"""Forced SSH command for versioned receiver deployments to one hosting account.

Install this outside the web root. Input is one verified GitHub release archive;
SSH_ORIGINAL_COMMAND must be `deploy vX.Y.Z SHA256`. No shell commands are accepted.
A private mail-only overlay is accepted only for the eight owned fleet receivers.
Private configuration/database values never enter deployment output or releases.
"""
import ast
from contextlib import contextmanager
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
PRIVATE = Path(__file__).resolve().parent
ROOT = Path.home() / "w-monitor-public"
CONFIG = PRIVATE / "deploy-config.json"
EXPECTED = {"server/app.py", "server/redis_cache.py", "server/encryption.py", "server/i18n.py", "server/metrics.py", "server/notify.py", "server/requirements.lock", "server/passenger_wsgi.py", "server/config.example.json", "server/openapi.json", "server/web/index.html", "server/web/app.js", "server/web/style.css"}


MAIL_TARGETS = {
    "us": "https://monitor.20290708.xyz",
    "sg": "https://sg.monitor.20290708.xyz",
    "uk": "https://wm-uk.myfastools.com",
    "sg-advin": "https://sg-advin.monitor.20290708.xyz",
    "us-mia": "https://us-mia.monitor.20290708.xyz",
    "sg-dap": "https://sg-dap.monitor.20290708.xyz",
    "fiber100": "https://fiber.monitor.20290708.xyz",
    "hostypanel-us1": "https://us1.monitor.20290708.xyz",
}
MAIL_FIELDS = {"email_provider", "w_mail_url", "w_mail_project_id", "w_mail_mailbox_id", "w_mail_api_key"}


def validate_mail_overlay(value, origin):
    if (not isinstance(value, dict) or set(value) != {"schema", "region", "public_url", "config"} or
            value.get("schema") != "w-monitor-public-mail/v1" or
            MAIL_TARGETS.get(value.get("region")) != origin or value.get("public_url") != origin):
        raise RuntimeError("Private mail target refused")
    fields = value["config"]
    if (not isinstance(fields, dict) or set(fields) != MAIL_FIELDS or
            fields.get("email_provider") != "w-mail" or fields.get("w_mail_url") != "https://wmail.myfastools.com" or
            fields.get("w_mail_project_id") != "w-monitor-public" or
            fields.get("w_mail_mailbox_id") != "a4de77a04c49483a995d9dfb1fb1ac28" or
            not isinstance(fields.get("w_mail_api_key"), str) or
            not re.fullmatch(r"wid_sk_[A-Za-z0-9_-]{16,512}", fields["w_mail_api_key"])):
        raise RuntimeError("Private mail profile refused")
    return fields


def private_bytes(path, maximum=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError("Owner-only configuration required")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise RuntimeError("Private configuration exceeds bound")
    return raw


def deployment_settings():
    if PRIVATE.is_symlink() or PRIVATE.stat().st_uid != os.geteuid() or PRIVATE.stat().st_mode & 0o077:
        raise RuntimeError("Private deployment configuration is required")
    config = json.loads(private_bytes(CONFIG))
    origin = config["public_url"].rstrip("/")
    url = urlsplit(origin)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise RuntimeError("Invalid public origin")
    python, wsgi = config["python"], config["wsgi"]
    if not all(isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9/._-]+", value) for value in (python, wsgi)):
        raise RuntimeError("Invalid hosting Python executable")
    document_root = Path(config.get("document_root", str(Path.home() / "domains" / url.hostname / "public_html")))
    if (not document_root.is_absolute() or not document_root.is_relative_to(Path.home()) or
            document_root.is_symlink() or document_root.resolve() != document_root or not document_root.is_dir()):
        raise RuntimeError("Expected dedicated account document root")
    if PRIVATE.is_relative_to(document_root):
        raise RuntimeError("Private deployment directory cannot be web-accessible")
    return config, origin, python, wsgi, document_root


def mail_preflight(origin):
    _, actual, _, _, _ = deployment_settings()
    if actual != origin or origin not in MAIL_TARGETS.values():
        raise RuntimeError("Private mail target refused")
    rollback = PRIVATE / "mail-config-rollback.json"
    if rollback.exists() or rollback.is_symlink():
        raise RuntimeError("Pending private mail rollback requires operator recovery")
    current = json.loads(private_bytes(PRIVATE / "config.json"))
    if not isinstance(current, dict) or current.get("public_url", "").rstrip("/") != origin:
        raise RuntimeError("Receiver configuration does not own this mail target")


def delivery_input(raw, checksum, origin):
    # Public attestation and immutable-release identity always cover only the
    # original nine assets. The optional outer envelope is private transport.
    overlay = None
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if {item.filename for item in entries} == {"release.zip", "mail-overlay.json"}:
            if len(entries) != 2 or any(stat.S_ISLNK(item.external_attr >> 16) for item in entries):
                raise RuntimeError("Private delivery inventory refused")
            if archive.getinfo("release.zip").file_size > 192 * 1024 * 1024 or archive.getinfo("mail-overlay.json").file_size > 16384:
                raise RuntimeError("Private delivery exceeds bound")
            overlay = json.loads(archive.read("mail-overlay.json"))
            validate_mail_overlay(overlay, origin)
            raw = archive.read("release.zip")
    if len(raw) > 192 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != checksum:
        raise RuntimeError("Archive size or checksum mismatch")
    return raw, overlay


@contextmanager
def mail_configuration(overlay, origin):
    if overlay is None:
        yield False
        return
    fields = validate_mail_overlay(overlay, origin)
    mail_preflight(origin)
    path, rollback = PRIVATE / "config.json", PRIVATE / "mail-config-rollback.json"
    original = private_bytes(path)
    current = json.loads(original)
    if not isinstance(current, dict) or current.get("public_url", "").rstrip("/") != origin:
        raise RuntimeError("Receiver configuration changed before mail update")
    merged = json.dumps({**current, **fields}, ensure_ascii=False, separators=(",", ":")).encode()
    if len(merged) > 65536:
        raise RuntimeError("Merged private configuration exceeds bound")
    # The old instance's secrets never leave this account. A killed deployment
    # leaves this private recovery copy and refuses further automatic changes.
    atomic(rollback, original)
    restored = False
    try:
        if private_bytes(path) != original:
            raise RuntimeError("Receiver configuration changed before mail update")
        atomic(path, merged)
        yield True
    except BaseException:
        observed = private_bytes(path)
        if observed == merged:
            atomic(path, original)
        elif observed != original:
            raise RuntimeError("Mail rollback refused concurrent configuration change") from None
        restored = True
        raise
    else:
        restored = True
    finally:
        if restored:
            rollback.unlink()


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


def healthy(origin, version, first_deployment=False, require_mail=False):
    if first_deployment:
        print("Candidate health: waiting 20s for initial hosting readiness", flush=True)
        time.sleep(20)
    for attempt in range(3):
        try:
            request = Request(origin + "/health", headers={"User-Agent": "W-Monitor-Public-Deploy", "Cache-Control": "no-cache"})
            with build_opener(NoRedirect()).open(request, timeout=15 if first_deployment else 5) as response:
                print("Candidate health attempt " + str(attempt + 1) + ": HTTP " + str(response.status), flush=True)
                raw = response.read(65537)
            value = json.loads(raw) if len(raw) <= 65536 else {}
            if value.get("status") == "ok" and value.get("version") == version and value.get("release_tag") == "v" + version and value.get("mode") == "public" and value.get("host_control_enabled") is False and value.get("cache") == "redis" and (not require_mail or (value.get("email_channel") == "w-mail" and value.get("email_channel_configured") is True)):
                return True
            print("Candidate health: response does not match required release state", flush=True)
        except Exception as error:
            status = getattr(error, "code", None)
            detail = "HTTP " + str(status) if type(status) is int else type(error).__name__
            print("Candidate health attempt " + str(attempt + 1) + ": " + detail, flush=True)
        if attempt < 2:
            time.sleep(30 if first_deployment else 3)
    return False


def restart_passenger(target):
    directory = target / "server/tmp"
    if directory.is_symlink():
        raise RuntimeError("Passenger restart directory cannot be a symlink")
    directory.mkdir(mode=0o755, exist_ok=True)
    atomic(directory / "restart.txt", str(time.time_ns()).encode())


def deploy():
    arguments = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if len(arguments) != 3 or arguments[0] != "deploy" or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", arguments[1]) or not re.fullmatch(r"[a-f0-9]{64}", arguments[2]):
        raise RuntimeError("Only a versioned receiver deployment is allowed")
    tag, checksum = arguments[1:]
    config, origin, python, wsgi, document_root = deployment_settings()
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
        if active_tag and tuple(map(int, tag[1:].split("."))) < tuple(map(int, active_tag[1:].split("."))) and config.get("reset_to_tag") != tag:
            raise RuntimeError("Automatic deployments cannot downgrade an active release")
        raw = sys.stdin.buffer.read(192 * 1024 * 1024 + 131073)
        if len(raw) > 192 * 1024 * 1024 + 131072:
            raise RuntimeError("Private delivery exceeds bound")
        raw, overlay = delivery_input(raw, checksum, origin)
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
                environment = dict(os.environ)
                venv = [python, "-m", "venv"]
                if config.get("transport") == "unix-php":
                    wheel = PRIVATE / "bin/pip.whl"
                    if wheel.is_symlink() or hashlib.sha256(wheel.read_bytes()).hexdigest() != config.get("pip_sha256"):
                        raise RuntimeError("Verified deployment pip wheel required")
                    venv.append("--without-pip")
                    environment["PYTHONPATH"] = str(wheel)
                    environment["PIP_CONFIG_FILE"] = "/dev/null"
                subprocess.run([*venv, str(staging / "runtime")], check=True, timeout=45, stdout=subprocess.DEVNULL)
                subprocess.run([str(staging / "runtime/bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--require-hashes", "--only-binary=:all:", "--index-url", "https://pypi.org/simple", "--retries", "2", "--timeout", "10", "-r", str(staging / "server/requirements.lock")], check=True, timeout=150, stdout=subprocess.DEVNULL, env=environment)
                atomic(staging / "config-path", (str(PRIVATE / "config.json") + "\n").encode())
                atomic(staging / "archive.sha256", (checksum + "\n").encode())
                os.rename(staging, target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        htaccess = document_root / ".htaccess"
        if htaccess.is_symlink():
            raise RuntimeError("Hosting configuration cannot be a symlink")
        previous = htaccess.read_bytes() if htaccess.exists() else b"Require all denied\n"
        unix = config.get("transport") == "unix-php"
        gateway = PRIVATE / "socket_gateway.py"
        gateway_pointer = PRIVATE / "gateway-active.json"
        previous_gateway = gateway_pointer.read_bytes() if gateway_pointer.exists() else None
        try:
            with mail_configuration(overlay, origin) as require_mail:
                if unix:
                    if gateway.is_symlink() or not gateway.is_file():
                        raise RuntimeError("Trusted Unix gateway required")
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("wm_socket_gateway", gateway)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if require_mail:
                        subprocess.run([python, str(gateway), "stop", tag], check=True, timeout=20, stdout=subprocess.DEVNULL)
                    subprocess.run([python, str(gateway), "request", tag], check=True, timeout=100, stdout=subprocess.DEVNULL)
                    atomic(document_root / "index.php", module.php_front(PRIVATE).encode(), 0o644)
                    settings = 'Options -Indexes\nDirectoryIndex index.php\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.php [L,QSA]\n'
                    atomic(gateway_pointer, json.dumps({"tag": tag}).encode())
                else:
                    settings = f'Options -Indexes\nPassengerAppRoot "{target}/server"\nPassengerBaseURI "/"\nPassengerPython "{wsgi}"\nPassengerAppType wsgi\nPassengerStartupFile passenger_wsgi.py\n'
                    if require_mail:
                        restart_passenger(target)
                atomic(htaccess, settings.encode(), 0o644)
                if not healthy(origin, tag[1:], first_deployment=not active_tag, require_mail=require_mail):
                    raise RuntimeError("Candidate health failed")
                periodic = PRIVATE / "run_periodic.py"
                if not periodic.is_file() or periodic.is_symlink() or config.get("periodic_enabled") is not True:
                    raise RuntimeError("Trusted periodic worker must be provisioned")
                # The stable existing Cron selects the committed active release.
                # Do not provision a new worker or change notification consent.
                if not unix:
                    subprocess.run([python, str(periodic)], check=True, timeout=60, stdout=subprocess.DEVNULL)
                previous_tag = active_tag if active_tag and active_tag != tag else active.get("previous_tag")
                atomic(active_path, json.dumps({"tag": tag, "sha256": checksum, "previous_tag": previous_tag}).encode())
        except BaseException:
            # mail_configuration restores this account's original bytes first.
            atomic(htaccess, previous, 0o644)
            if unix:
                if previous_gateway is None:
                    gateway_pointer.unlink(missing_ok=True)
                else:
                    atomic(gateway_pointer, previous_gateway)
                if active_tag:
                    if overlay is not None and active_tag == tag:
                        subprocess.run([python, str(gateway), "stop", active_tag], check=True, timeout=20, stdout=subprocess.DEVNULL)
                    atomic(PRIVATE / "gateway-request.json", json.dumps({"tag": active_tag}).encode())
                else:
                    (PRIVATE / "gateway-request.json").unlink(missing_ok=True)
            elif overlay is not None and active_tag:
                restart_passenger(releases / active_tag)
            raise
        if config.get("reset_to_tag") == tag:
            config.pop("reset_to_tag")
            atomic(CONFIG, json.dumps(config).encode())
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
        preflight = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
        if len(preflight) == 2 and preflight[0] == "mail-preflight":
            mail_preflight(preflight[1])
            print(json.dumps({"private_mail_target_ready": True}))
        else:
            deploy()
    except Exception as error:
        print("Deployment refused: " + str(error), file=sys.stderr)
        raise SystemExit(1) from None
