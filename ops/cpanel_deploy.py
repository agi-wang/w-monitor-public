"""Deliver a verified archive through cPanel Fileman and account Cron APIs."""
from http.client import HTTPSConnection
import json
import os
import secrets
import shlex
import socket
import time
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from panel_deploy import NoRedirect


def deploy(origin, user, private, python, data, tag, checksum):
    authorization = "cpanel " + user + ":" + os.environ["PUBLIC_DEPLOY_PANEL_TOKEN"]
    connect_host = os.environ.get("DEPLOY_HOST", "")

    class PanelHTTPSHandler(HTTPSHandler):
        def https_open(self, request):
            def connection(host, **kwargs):
                client = HTTPSConnection(host, **kwargs)
                if connect_host:
                    # Route the TCP socket to the registered server while the
                    # original hostname still controls TLS verification and SNI.
                    client._create_connection = lambda address, timeout=None, source_address=None: socket.create_connection((connect_host, address[1]), timeout, source_address)
                return client
            return self.do_open(connection, request, context=self._context)

    opener = build_opener(NoRedirect(), ProxyHandler({}), PanelHTTPSHandler())

    def request(path, body=None, content_type=None):
        headers = {"Authorization": authorization, "User-Agent": "W-Monitor-Public-Deploy"}
        if content_type:
            headers["Content-Type"] = content_type
        with opener.open(Request(origin + path, data=body, headers=headers), timeout=90) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError("cPanel response exceeds bound")
        return json.loads(raw)

    def api(module, function, values):
        return request("/execute/" + module + "/" + function + "?" + urlencode(values))

    def api2(module, function, values):
        fields = dict(values, cpanel_jsonapi_user=user, cpanel_jsonapi_apiversion=2, cpanel_jsonapi_module=module, cpanel_jsonapi_func=function)
        result = request("/json-api/cpanel", urlencode(fields).encode(), "application/x-www-form-urlencoded")["cpanelresult"]
        if result.get("error") or result.get("event", {}).get("result") != 1 or any(row.get("status") == 0 or row.get("result") == 0 for row in result.get("data", [])):
            raise RuntimeError("cPanel account operation refused")
        return result["data"]

    home = "/home/" + user + "/" + private
    nonce = secrets.token_hex(16)
    filename = "incoming-" + nonce + ".zip"
    incoming = home + "/" + filename
    status = home + "/deploy-" + nonce + ".json"
    log = home + "/deploy-" + nonce + ".log"
    lock = home + "/deploy-" + nonce + ".lock"
    boundary = "wm-" + secrets.token_hex(16)
    body = f'--{boundary}\r\nContent-Disposition: form-data; name="file-0"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + data + f"\r\n--{boundary}--\r\n".encode()
    result = request("/execute/Fileman/upload_files?" + urlencode({"dir": home, "overwrite": "0", "permissions": "0600"}), body, "multipart/form-data; boundary=" + boundary)
    if result.get("status") != 1:
        raise RuntimeError("cPanel private upload refused")
    q = shlex.quote
    # The private gate validates the exact archive before activation. mkdir is
    # an atomic one-shot guard even when pip spans more than one Cron tick.
    command = "umask 077; if [ ! -e " + q(status) + " ] && mkdir " + q(lock) + " 2>/dev/null; then "
    command += "SSH_ORIGINAL_COMMAND=" + q("deploy " + tag + " " + checksum) + " " + q(python) + " " + q(home + "/deploy_receiver.py") + " < " + q(incoming) + " > " + q(log) + " 2>&1; wm_exit=$?; "
    # Cron treats even quoted percent signs as stdin separators.
    command += "echo '{\"exit\":'\"$wm_exit\"'}' > " + q(status) + "; rm -f -- " + q(incoming) + "; fi"
    api2("Cron", "add_line", dict(minute="*", hour="*", day="*", month="*", weekday="*", command=command))
    completed = False
    try:
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            result = api("Fileman", "get_file_content", {"dir": home, "file": status.rsplit("/", 1)[1], "charset": "utf-8"})
            content = (result.get("data") or {}).get("content")
            if result.get("status") == 1 and content:
                if json.loads(content).get("exit") != 0:
                    raise RuntimeError("Private cPanel deployment gate failed")
                completed = True
                break
            time.sleep(5)
        if not completed:
            raise RuntimeError("cPanel deployment exceeded deadline")
    finally:
        for row in api2("Cron", "listcron", {}):
            if row.get("command") == command:
                api2("Cron", "remove_line", {"linekey": row["linekey"]})
        # Keep failed gate diagnostics private for an operator. Never emit them.
        if completed:
            api2("Fileman", "fileop", {"op": "trash", "sourcefiles": ",".join((status, log, lock)), "doubledecode": "0"})
    print(json.dumps({"deployed": tag, "transport": "cpanel", "gate_confirmed": True}))
