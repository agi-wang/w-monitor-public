"""Once-per-minute aggregate load snapshot; never publishes tenant identifiers."""
import json
import os
import time



def main():
    from app import BOX, CACHE, NAMESPACE, database, live_metadata, offline_after
    now = int(time.time())
    info = CACHE.command("INFO", "memory")
    counters = CACHE.command("HMGET", NAMESPACE + "requests:" + str(now // 60 - 1), "requests", "duration_us", "errors")
    if not isinstance(info, str) or counters is None:
        return {"stored": False}
    memory = dict(line.split(":", 1) for line in info.splitlines() if ":" in line and not line.startswith("#"))
    requests, duration, errors = (int(value or 0) for value in counters)
    online, total, known = 0, 0, 0
    with database() as db:
        cursor = db.execute("SELECT id FROM devices")
        while True:
            rows = cursor.fetchmany(512)
            if not rows:
                break
            total += len(rows)
            metadata, available = live_metadata(rows)
            if not available:
                return {"stored": False}
            for item in metadata.values():
                if type(item.get("received_at")) is int:
                    known += 1
                    online += item["received_at"] >= now - offline_after(item)
    try:
        host_load = [round(value, 2) for value in os.getloadavg()]
    except OSError:
        host_load = None
    snapshot = {"available": True, "collected_at": now, "period_start": (now // 60 - 1) * 60, "period_seconds": 60, "devices": total, "online_devices": online, "unknown_devices": total - known, "requests_per_second": round(requests / 60, 2) if counters[0] is not None else None, "mean_response_ms": round(duration / requests / 1000, 2) if requests else None, "server_error_percent": round(errors / requests * 100, 2) if requests else None, "redis_used_bytes": int(memory.get("used_memory", "0")), "redis_rss_bytes": int(memory.get("used_memory_rss", "0")), "host_load": host_load, "host_load_scope": "shared_host"}
    result = CACHE.command("SETEX", NAMESPACE + "platform-load", 180, BOX.seal("platform-load", snapshot))
    return {"stored": result == "OK"}


import fcntl
import json
import math
import secrets
import time
from urllib.parse import urlsplit
from redis_cache import MetricHistory


def validate_probe(value):
    if not isinstance(value, dict) or set(value) != {"name", "kind", "target", "interval_seconds", "timeout_seconds"}:
        raise ValueError("Invalid service monitor fields")
    name, kind, target = value["name"], value["kind"], value["target"]
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not isinstance(target, str) or len(target) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in name + target):
        raise ValueError("Invalid service name or target")
    if type(value["interval_seconds"]) is not int or not 60 <= value["interval_seconds"] <= 3600 or type(value["timeout_seconds"]) is not int or not 1 <= value["timeout_seconds"] <= 10:
        raise ValueError("Invalid service probe interval or timeout")
    parsed = urlsplit("tcp://" + target if kind == "tcp" else target)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Service target must not contain credentials, query or fragment")
    _ = parsed.port  # Reject invalid ports before configuration is stored.
    if kind == "tcp":
        if parsed.scheme != "tcp" or not parsed.port or parsed.path:
            raise ValueError("TCP target requires host:port")
    elif kind != "http" or parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) and TCP checks are supported")
    return {**value, "name": name.strip()}


def configuration(db, box, device):
    rows = db.execute("SELECT * FROM service_monitors WHERE device_id=? ORDER BY id", (device,)).fetchall()
    probes = []
    for row in rows:
        settings = box.open("service-monitor:" + row["id"], row["settings"])
        probes.append({"id": row["id"], **{key: settings[key] for key in ("kind", "target", "interval_seconds", "timeout_seconds")}})
    import hashlib
    revision = hashlib.sha256(json.dumps(probes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return {"revision": revision, "probes": probes}


class AvailabilityHistory(MetricHistory):
    fields = sources = ("up_percent", "down_percent", "latency_ms", "known_percent", "unknown_percent")
    include_counts = True

    def __init__(self, cache, box, namespace, days):
        super().__init__(cache, box, namespace, (60, 86400, days * 86400), 60)
        self.policy = "availability-minute-v1:" + str(days)

    def snapshot(self, identifier, selection, created):
        value = self.read(identifier, selection)
        counts = value.pop("sample_counts")
        samples = sum(row[0] for row in counts)
        total = sum(point[1] * count[0] for point, count in zip(value["points"], counts) if point[1] is not None)
        expected = max(1, math.ceil((value["to"] - max(created, value["from"])) / 60))
        return {**value, "availability_percent": round(total / samples, 3) if samples else None, "known_samples": samples, "expected_samples": expected, "coverage_percent": min(100, round(samples / expected * 100, 3)), "aggregation": "minute_observation_weighted", "network_accounting_scope": None}


def probe_status(meta, probe, online, revision, now=None):
    if online is not True:
        return {"state": "unknown", "reason": "probe_offline", "latency_ms": None}
    if meta.get("service_probe_revision") != revision:
        return {"state": "unknown", "reason": "configuration_pending", "latency_ms": None}
    result = meta.get("service_results", {}).get(probe["id"], {})
    if type(result.get("checked_at")) is not int or result["checked_at"] < (int(time.time()) if now is None else now) - max(30, probe["interval_seconds"] * 2):
        return {"state": "unknown", "reason": "awaiting_check", "latency_ms": None}
    return {"state": "up" if result["ok"] else "down", "latency_ms": result.get("latency_ms"), "status_code": result.get("status_code"), "reason": result.get("error"), "checked_at": result["checked_at"]}


def collect_uptime():
    import app
    with open(app.DATA / "uptime.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"already_running": True}
        now = int(time.time())
        with app.database() as db:
            rows = db.execute("SELECT id,space_id,created_at FROM devices ORDER BY id").fetchall()
            metadata, available = app.live_metadata(rows)
            if not available:
                return {"dynamic_available": False}  # A Redis failure is not a tenant outage.
            recorded = 0
            cursor = app.CACHE.command("GET", app.UPTIME_DYNAMIC + ":cursor") or ""
            rows = sorted(rows, key=lambda row: (row["id"] <= cursor, row["id"]))
            deadline = time.monotonic() + 30
            for row in rows:
                if time.monotonic() >= deadline:
                    break
                meta = metadata.get(row["id"], {})
                received = meta.get("received_at")
                online = received >= now - app.offline_after(meta) if type(received) is int else None
                observations = [(row["id"], {"state": "up" if online else "down" if online is False else "unknown", "latency_ms": None})]
                config = configuration(db, app.BOX, row["id"])
                observations += [(row["id"] + ":" + probe["id"], probe_status(meta, probe, online, config["revision"], now)) for probe in config["probes"]]
                for identifier, observation in observations:
                    previous = app.CACHE.command("HGET", app.UPTIME_DYNAMIC, "meta:" + identifier)
                    old = app.BOX.open("meta:" + identifier, previous) if previous else {}
                    if old.get("received_at", 0) // 60 >= now // 60:
                        continue
                    state = observation["state"]
                    known = state in ("up", "down")
                    values = {"received_at": now, "up_percent": 100 if state == "up" else 0 if state == "down" else None, "down_percent": 100 if state == "down" else 0 if state == "up" else None, "latency_ms": observation.get("latency_ms") if state == "up" else None, "known_percent": 100 if known else 0, "unknown_percent": 0 if known else 100}
                    meta_value = {**observation, "received_at": now, "since": old.get("since", now) if old.get("state") == state and now - old.get("received_at", 0) <= 180 else now}
                    stored = app.CACHE.store_report(app.UPTIME_DYNAMIC, identifier, row["space_id"], "", app.BOX.seal("meta:" + identifier, meta_value), secrets.token_hex(16), app.UPTIME_HISTORY, values)
                    if stored != 1:
                        return {"dynamic_available": False}
                    event_key = app.UPTIME_DYNAMIC + ":events:" + identifier
                    if old.get("state") != state or now - old.get("received_at", 0) > 180:
                        # Keep a bounded, encrypted transition log, including collector gaps.
                        event = app.BOX.seal("uptime-event:" + identifier, {"at": now, "state": state, "previous": old.get("state") if now - old.get("received_at", 0) <= 180 else "unknown"})
                        app.CACHE.command("EVAL", "redis.call('LPUSH',KEYS[1],ARGV[1]);redis.call('LTRIM',KEYS[1],0,99);redis.call('EXPIRE',KEYS[1],ARGV[2]);return 1", 1, event_key, event, app.UPTIME_HISTORY.retention[2])
                    recorded += 1
                app.CACHE.command("SETEX", app.UPTIME_DYNAMIC + ":cursor", 3600, row["id"])
            app.CACHE.command("SETEX", app.UPTIME_DYNAMIC + ":worker", 180, now)
            return {"recorded": recorded, "resolution_seconds": 60}


if __name__ == "__main__":
    print(json.dumps(main()))
