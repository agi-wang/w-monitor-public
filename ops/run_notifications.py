#!/usr/bin/env python3
"""Stable account-Cron entrypoint selecting the active immutable receiver."""
import json
import os
from pathlib import Path
import re
import subprocess

private = Path.home() / ".w-monitor"
active = json.loads((private / "active-release.json").read_text())
tag = active.get("tag", "")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("No active receiver release")
root = Path.home() / "w-monitor-public/releases" / tag
environment = dict(os.environ, WM_PUBLIC_CONFIG=str(private / "config.json"))
result = subprocess.run([str(root / "runtime/bin/python"), str(root / "server/notify.py")], env=environment, capture_output=True, timeout=55)
# Keep delivery status free of recipient addresses, credentials and host reports.
if result.returncode:
    print("W Monitor notification worker failed")
raise SystemExit(result.returncode)
