"""Once-per-minute aggregate load snapshot; never publishes tenant identifiers."""
import json
import os
import time

from app import BOX, CACHE, INTERVAL, NAMESPACE, database, live_metadata


def main():
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
                    online += item["received_at"] >= now - max(60, INTERVAL / 1000 * 2.1)
    try:
        host_load = [round(value, 2) for value in os.getloadavg()]
    except OSError:
        host_load = None
    snapshot = {"available": True, "collected_at": now, "period_start": (now // 60 - 1) * 60, "period_seconds": 60, "devices": total, "online_devices": online, "unknown_devices": total - known, "requests_per_second": round(requests / 60, 2) if counters[0] is not None else None, "mean_response_ms": round(duration / requests / 1000, 2) if requests else None, "server_error_percent": round(errors / requests * 100, 2) if requests else None, "redis_used_bytes": int(memory.get("used_memory", "0")), "redis_rss_bytes": int(memory.get("used_memory_rss", "0")), "host_load": host_load, "host_load_scope": "shared_host"}
    result = CACHE.command("SETEX", NAMESPACE + "platform-load", 180, BOX.seal("platform-load", snapshot))
    return {"stored": result == "OK"}


if __name__ == "__main__":
    print(json.dumps(main()))
