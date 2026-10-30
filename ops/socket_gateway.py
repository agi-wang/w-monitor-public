#!/usr/bin/env python3
"""Account-owned WSGI over private Unix sockets for PHP-only shared hosting."""
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, ServerHandler

os.umask(0o077)
PRIVATE = Path(__file__).resolve().parent
ROOT = Path.home() / "w-monitor-public/releases"


def paths(tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise RuntimeError("Invalid gateway release")
    return PRIVATE / ("http-" + tag + ".sock"), PRIVATE / ("http-" + tag + ".pid")


def check_private():
    info = PRIVATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError("Owner-only gateway directory required")


def healthy(tag):
    path, _ = paths(tag)
    class UnixConnection(http.client.HTTPConnection):
        def connect(self):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2)
            try:
                client.connect(str(path))
                self.sock = client
            except Exception:
                client.close()
                raise
    connection = UnixConnection("localhost", timeout=2)
    try:
        connection.request("GET", "/health", headers={"X-WM-Client-IP": "127.0.0.1"})
        response = connection.getresponse()
        value = json.loads(response.read(65537))
        return response.status == 200 and value.get("release_tag") == tag and value.get("cache") == "redis" and value.get("host_control_enabled") is False
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def process(tag):
    _, file = paths(tag)
    try:
        if file.is_symlink():
            return None
        record = json.loads(file.read_text())
        pid = record["pid"]
        if type(pid) is not int or pid < 2:
            return None
        start = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if start != record["start"] or str(Path(__file__).resolve()).encode() not in args or b"run" not in args or tag.encode() not in args:
            return None
        return pid
    except (OSError, ValueError, KeyError, IndexError):
        return None


def stop(tag):
    pid = process(tag)
    if pid:
        os.kill(pid, signal.SIGTERM)
        for _ in range(40):
            if process(tag) != pid:
                break
            time.sleep(0.25)
        if process(tag) == pid:
            os.kill(pid, signal.SIGKILL)
    if process(tag) is None:
        for path in paths(tag):
            if path.exists() and not path.is_symlink() and path.stat().st_uid == os.geteuid():
                path.unlink()


def start(tag):
    if healthy(tag):
        return
    stop(tag)
    target = ROOT / tag
    # Avoid retaining request data or URLs in process output.
    descriptor = os.open(PRIVATE / "gateway.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "ab") as output:
        child = subprocess.Popen([str(target / "runtime/bin/python"), str(Path(__file__).resolve()), "run", tag], stdin=subprocess.DEVNULL, stdout=output, stderr=output, close_fds=True, start_new_session=True)
    try:
        start_time = Path(f"/proc/{child.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        path = paths(tag)[1]
        with open(path, "x") as file:
            json.dump({"pid": child.pid, "start": start_time}, file)
        for _ in range(20):
            if healthy(tag):
                return
            if child.poll() is not None:
                break
            time.sleep(0.25)
        raise RuntimeError("Unix receiver failed readiness")
    except Exception:
        if process(tag) == child.pid:
            stop(tag)
        raise


def serve(tag):
    target = ROOT / tag
    os.environ["WM_PUBLIC_CONFIG"] = str(PRIVATE / "config.json")
    sys.path.insert(0, str(target / "server"))
    from app import application, CONFIG
    workers = CONFIG.get("unix_workers", 32)
    if type(workers) is not int or not 1 <= workers <= 256:
        raise RuntimeError("Invalid Unix receiver concurrency")
    class Handler(WSGIRequestHandler):
        def setup(self):
            self.client_address = ("127.0.0.1", 0)
            self.request.settimeout(20)
            super().setup()
        def log_message(self, *_args):
            pass
        def handle(self):
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline, self.request_version, self.command = "", "", ""
                self.send_error(414)
                return
            if not self.parse_request():
                return
            environ = self.get_environ()
            try:
                environ["REMOTE_ADDR"] = str(ipaddress.ip_address(environ.pop("HTTP_X_WM_CLIENT_IP", "")))
            except ValueError:
                self.send_error(400)
                return
            handler = ServerHandler(self.rfile, self.wfile, self.get_stderr(), environ, multithread=True)
            handler.request_handler = self
            handler.run(application)
    class Server(socketserver.ThreadingMixIn, WSGIServer):
        address_family = socket.AF_UNIX
        request_queue_size = 128
        daemon_threads = False
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "localhost", 0
            self.setup_environ()
        def process_request(self, request, client_address):
            self.slots.acquire()
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.slots.release()
                raise
        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()
    path, _ = paths(tag)
    server = Server(str(path), Handler)
    server.slots = threading.BoundedSemaphore(workers)
    path.chmod(0o600)
    signal.signal(signal.SIGTERM, lambda *_args: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        path.unlink(missing_ok=True)


def php_front(private):
    # Fixed socket origin only; client input can never choose a destination.
    source = r'''<?php
ini_set('display_errors', '0');
$private = PRIVATE_PATH;
$active = json_decode(@file_get_contents($private . '/gateway-active.json'), true);
$tag = $active['tag'] ?? '';
if (!preg_match('/^v[0-9]+\.[0-9]+\.[0-9]+$/D', $tag)) { http_response_code(503); exit('Receiver unavailable'); }
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!str_starts_with($uri, '/') || preg_match('/[\x00-\x20\x7f]/', $uri) || !in_array($method, ['GET','POST','HEAD'], true)) { http_response_code(400); exit; }
$body = file_get_contents('php://input', false, null, 0, 8388609);
if (strlen($body) > 8388608) { http_response_code(413); exit; }
$headers = ['X-WM-Client-IP: ' . ($_SERVER['REMOTE_ADDR'] ?? '')];
foreach ($_SERVER as $key => $value) {
    if (!str_starts_with($key, 'HTTP_')) { continue; }
    $name = str_replace('_', '-', substr($key, 5));
    if (in_array($name, ['AUTHORIZATION','COOKIE','ORIGIN','ACCEPT','ACCEPT-LANGUAGE','IF-NONE-MATCH','X-CSRF-TOKEN','X-OPERATION-TOKEN'], true) || str_starts_with($name, 'X-WM-') && $name !== 'X-WM-CLIENT-IP') {
        if (!preg_match('/[\r\n]/', $value)) { $headers[] = $name . ': ' . $value; }
    }
}
if (!isset($_SERVER['HTTP_AUTHORIZATION']) && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) { $headers[] = 'Authorization: ' . $_SERVER['REDIRECT_HTTP_AUTHORIZATION']; }
foreach (['CONTENT_TYPE'=>'Content-Type','HTTP_CONTENT_ENCODING'=>'Content-Encoding'] as $key=>$name) {
    if (isset($_SERVER[$key]) && !preg_match('/[\r\n]/', $_SERVER[$key])) { $headers[] = $name . ': ' . $_SERVER[$key]; }
}
$curl = curl_init('http://localhost' . $uri);
curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH=>$private . '/http-' . $tag . '.sock', CURLOPT_CUSTOMREQUEST=>$method, CURLOPT_HTTPHEADER=>$headers, CURLOPT_POSTFIELDS=>$method === 'POST' ? $body : null, CURLOPT_FOLLOWLOCATION=>false, CURLOPT_PROXY=>'', CURLOPT_CONNECTTIMEOUT=>3, CURLOPT_TIMEOUT=>25,
CURLOPT_HEADERFUNCTION=>function($ch,$line) {
    if (preg_match('/^HTTP\/\S+ ([0-9]{3})/', $line, $m)) { http_response_code((int)$m[1]); }
    elseif (str_contains($line, ':')) {
        $name = strtolower(trim(explode(':', $line, 2)[0]));
        if (!in_array($name,['connection','transfer-encoding','keep-alive','server'],true)) { header(trim($line), false); }
    }
    return strlen($line);
}, CURLOPT_WRITEFUNCTION=>function($ch,$data) { echo $data; return strlen($data); }]);
$ok = curl_exec($curl);
if ($ok === false && !headers_sent()) { http_response_code(503); echo 'Receiver unavailable'; }
curl_close($curl);
'''
    return source.replace("PRIVATE_PATH", json.dumps(str(private)))


if __name__ == "__main__":
    check_private()
    if len(sys.argv) != 3 or sys.argv[1] not in ("start", "stop", "run"):
        raise SystemExit("Usage: socket_gateway.py start|stop|run vX.Y.Z")
    with open(PRIVATE / "gateway.lock", "a") as lock:
        if sys.argv[1] != "run":
            fcntl.flock(lock, fcntl.LOCK_EX)
        {"start": start, "stop": stop, "run": serve}[sys.argv[1]](sys.argv[2])
