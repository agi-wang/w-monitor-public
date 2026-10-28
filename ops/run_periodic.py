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
