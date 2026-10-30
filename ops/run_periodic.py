#!/usr/bin/env python3
"""Stable account-Cron entrypoint selecting the active immutable receiver."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

private = Path(__file__).resolve().parent
deploy_config = private / "deploy-config.json"
if deploy_config.exists() and json.loads(deploy_config.read_text()).get("transport") == "unix-php":
    os.execv(sys.executable, [sys.executable, str(private / "socket_gateway.py"), "supervise"])
watchdog = private / "redis_watchdog.py"
if watchdog.is_file() and not watchdog.is_symlink():
    subprocess.run([sys.executable, str(watchdog)], check=True, timeout=15)
if not (private / "active-release.json").exists():
    raise SystemExit(0)
active = json.loads((private / "active-release.json").read_text())
tag = active.get("tag", "")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("No active receiver release")
root = Path.home() / "w-monitor-public/releases" / tag
environment = dict(os.environ, WM_PUBLIC_CONFIG=str(private / "config.json"))
failed = False
for module, timeout in (("metrics.py", 10), ("notify.py", 45)):
    try:
        result = subprocess.run([str(root / "runtime/bin/python"), str(root / "server" / module)], env=environment, capture_output=True, timeout=timeout)
        failed = failed or result.returncode != 0
    except subprocess.TimeoutExpired:
        failed = True
# Never emit recipient addresses, credentials or reports into Cron output.
if failed:
    print("W Monitor periodic worker failed")
raise SystemExit(1 if failed else 0)
