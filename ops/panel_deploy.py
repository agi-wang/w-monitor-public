#!/usr/bin/env python3
"""Deliver an attested release through DirectAdmin's authenticated APIs.

The panel account is supplied by the protected GitHub environment. Only the
fixed private gate and its version/checksum arguments are invoked; no downloaded
application artifact is executed by the CI runner.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Terminal:
    def __init__(self, origin, authorization):
        parsed = urlsplit(origin)
        host, port = parsed.hostname, parsed.port or 443
        raw = socket.create_connection((host, port), timeout=15)
        try:
            self.socket = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise
        self.socket.settimeout(30)
        self.buffer = b""
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = f"GET /api/terminal?cols=120&rows=24 HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: {authorization}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origin}\r\n\r\n"
        self.socket.sendall(request.encode())
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise RuntimeError("Panel terminal closed during upgrade")
            self.buffer += chunk
            if len(self.buffer) > 65536:
                raise RuntimeError("Panel terminal headers exceed bound")
        headers, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        values = {}
        for line in headers.split(b"\r\n")[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                values[name.lower()] = value.strip()
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if b" 101 " not in headers.split(b"\r\n", 1)[0] or values.get(b"sec-websocket-accept") != accept:
            raise RuntimeError("Panel terminal upgrade rejected")

    def close(self):
        self.socket.close()

    def send(self, data, opcode=1):
        if len(data) > 65535:
            raise RuntimeError("Terminal input exceeds bound")
        mask = secrets.token_bytes(4)
        header = bytes([0x80 | opcode, 0x80 | len(data)]) if len(data) < 126 else bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", len(data))
        self.socket.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(data)))

    def read(self, count):
        while len(self.buffer) < count:
            chunk = self.socket.recv(65536)
            if not chunk:
                raise RuntimeError("Panel terminal closed before completion")
            self.buffer += chunk
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def frame(self):
        flags, size = self.read(2)
        length = size & 127
        if length == 126:
            length = struct.unpack("!H", self.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.read(8))[0]
        if length > 4 * 1024 * 1024:
            raise RuntimeError("Panel terminal frame exceeds bound")
        if size & 128:
            raise RuntimeError("Unexpected masked server frame")
        return flags & 15, self.read(length)

    def run(self, command):
        self.send(command.encode())
        output = b""
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            if not self.buffer and not self.socket.pending() and not select.select([self.socket], [], [], 5)[0]:
                self.send(b"wm", 9)
                continue
            opcode, data = self.frame()
            if opcode in (0, 1, 2):
                output += data
                if len(output) > 4 * 1024 * 1024:
                    raise RuntimeError("Panel terminal output exceeds bound")
                match = re.search(rb"__WM_DEPLOY_EXIT__([0-9]+)__", output)
                if match:
                    if int(match[1]) != 0:
                        raise RuntimeError("Private deployment gate failed")
                    return
            elif opcode == 9:
                self.send(data, 10)
            elif opcode == 8:
                raise RuntimeError("Panel terminal closed before deployment confirmation")
        raise RuntimeError("Panel deployment exceeded deadline")


def deploy():
    archive, tag, checksum = sys.argv[1:]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise RuntimeError("Invalid immutable release identity")
    origin = os.environ["PUBLIC_DEPLOY_PANEL_URL"].rstrip("/")
    parsed = urlsplit(origin)
    user = os.environ["PUBLIC_DEPLOY_USER"]
    private = os.environ["PUBLIC_DEPLOY_PRIVATE_DIR"]
    python = os.environ["PUBLIC_DEPLOY_PYTHON"]
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise RuntimeError("Invalid panel origin")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", user) or not re.fullmatch(r"\.[a-zA-Z0-9._-]{1,63}", private) or not re.fullmatch(r"/[A-Za-z0-9/._-]+", python):
        raise RuntimeError("Invalid dedicated deployment paths")
    data = Path(archive).read_bytes()
    if len(data) > 192 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError("Deployment inventory checksum mismatch")
    authorization = "Basic " + base64.b64encode((user + ":" + os.environ["PUBLIC_DEPLOY_PANEL_PASSWORD"]).encode()).decode()
    filename = "incoming-" + secrets.token_hex(16) + ".zip"
    boundary = "wm-" + secrets.token_hex(16)
    body = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="upload"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + data + f"\r\n--{boundary}--\r\n".encode()
    url = origin + "/api/filemanager-actions/upload?" + urlencode({"dir": private, "name": filename, "perm": "0600"})
    request = Request(url, data=body, headers={"Authorization": authorization, "Content-Type": "multipart/form-data; boundary=" + boundary, "User-Agent": "W-Monitor-Public-Deploy"})
    with build_opener(NoRedirect()).open(request, timeout=90) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("Panel upload response exceeds bound")
        result = json.loads(raw) if raw else {}
        if result and result.get("error"):
            raise RuntimeError("Panel refused private release upload")
    home = "/home/" + user + "/" + private
    incoming = home + "/" + filename
    command = "SSH_ORIGINAL_COMMAND=" + shlex.quote("deploy " + tag + " " + checksum) + " " + shlex.quote(python) + " " + shlex.quote(home + "/deploy_receiver.py") + " < " + shlex.quote(incoming)
    command += "; wm_result=$?; rm -f -- " + shlex.quote(incoming) + "; printf '\\n__WM_DEPLOY_EXIT__%s__\\n' \"$wm_result\"\r"
    terminal = Terminal(origin, authorization)
    try:
        terminal.run(command)
    finally:
        terminal.close()
    print(json.dumps({"deployed": tag, "transport": "directadmin", "gate_confirmed": True}))


if __name__ == "__main__":
    try:
        deploy()
    except Exception as error:
        # Never print request objects, headers, terminal output or account data.
        print("Panel deployment failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
