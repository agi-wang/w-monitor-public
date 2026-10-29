#!/usr/bin/env python3
"""Keep one account-owned cache alive over a private Unix socket only."""
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import time

os.umask(0o077)
private = Path(__file__).resolve().parent
root = private / "redis"
if private.is_symlink() or private.stat().st_uid != os.geteuid() or private.stat().st_mode & 0o077:
    raise SystemExit("Private runtime directory required")


def healthy():
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(root / "redis.sock"))
            client.sendall(b"*1\r\n$4\r\nPING\r\n")
            return client.recv(32) == b"+PONG\r\n"
    except OSError:
        return False


with open(private / "redis-watchdog.lock", "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    if not healthy():
        subprocess.run([str(private / "bin/redis-server"), str(root / "redis.conf")], check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for attempt in range(3):
            if healthy():
                break
            time.sleep(0.2)
        else:
            raise SystemExit("Private Redis did not become healthy")
