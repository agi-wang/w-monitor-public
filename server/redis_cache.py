"""Bounded Redis storage over one hosting account's private Unix socket.

All callers use fixed commands/scripts. Redis owns dynamic telemetry, cache,
rate limits and stream leases; it never grants tenant or host-control authority.
"""
import json
import socket
import struct
import math
import time

LIMIT = 12 * 1024 * 1024


class RedisCache:
    def __init__(self, path):
        self.path = path
        self.retry_at = 0

    def command(self, *parts):
        if not self.path or time.monotonic() < self.retry_at:
            return None
        try:
            encoded = [part if isinstance(part, bytes) else str(part).encode() for part in parts]
            request = b"*%d\r\n" % len(encoded)
            request += b"".join(b"$%d\r\n" % len(part) + part + b"\r\n" for part in encoded)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(self.path)
                client.sendall(request)
                with client.makefile("rb") as reply:
                    def read(depth=0):
                        if depth > 3:
                            raise ValueError()
                        line = reply.readline(256)
                        if not line.endswith(b"\r\n"):
                            raise ValueError()
                        marker, value = line[:1], line[1:-2]
                        if marker == b"+":
                            return value.decode()
                        if marker == b":":
                            return int(value)
                        if marker == b"-":
                            return None  # A cache refusal is not a broken socket.
                        if marker == b"*":
                            size = int(value)
                            if not 0 <= size <= 4096:
                                raise ValueError()
                            return [read(depth + 1) for _ in range(size)]
                        if marker == b"$":
                            size = int(value)
                            if size == -1:
                                return None
                            if not 0 <= size <= LIMIT:
                                raise ValueError()
                            raw = reply.read(size + 2)
                            if len(raw) != size + 2 or raw[-2:] != b"\r\n":
                                raise ValueError()
                            return raw[:-2].decode()
                        raise ValueError()
                    return read()
        except (OSError, ValueError, UnicodeError):
            self.retry_at = time.monotonic() + 5
            return None

    def put(self, key, value, registry):
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(raw.encode()) > 131072:
            return None
        # At most 512 projections (64 MiB working cache) with one fixed key per
        # scope. The registry expires too; stale entries cannot grow forever.
        script = """
        redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',ARGV[2])
        if redis.call('ZSCORE',KEYS[2],KEYS[1])==false and redis.call('ZCARD',KEYS[2])>=512 then
          local old=redis.call('ZPOPMIN',KEYS[2],1)
          if #old>0 then redis.call('DEL',old[1]) end
        end
        redis.call('SETEX',KEYS[1],15,ARGV[1])
        redis.call('ZADD',KEYS[2],tonumber(ARGV[2])+15,KEYS[1])
        redis.call('EXPIRE',KEYS[2],30)
        return 1
        """
        return self.command("EVAL", script, 2, key, registry, raw, int(time.time()))

    def read_view(self, dynamic, key, space):
        return self.command("EVAL", "return {redis.call('HGET',KEYS[1],'__epoch'),redis.call('HGET',KEYS[1],'rev:'..ARGV[1]),redis.call('GET',KEYS[2])}", 2, dynamic, key, space)

    def healthy(self):
        return self.command("PING") == "PONG"

    def record_request(self, namespace, status, duration_us):
        script = """
        redis.call('HINCRBY',KEYS[1],'requests',1)
        redis.call('HINCRBY',KEYS[1],'duration_us',ARGV[1])
        if tonumber(ARGV[2])>=500 then redis.call('HINCRBY',KEYS[1],'errors',1) end
        redis.call('EXPIRE',KEYS[1],180)
        return 1
        """
        return self.command("EVAL", script, 1, namespace + "requests:" + str(int(time.time()) // 60), max(0, int(duration_us)), status)

    def store_report(self, key, device, space, raw, meta, epoch, history, values):
        # Compare-and-swap the three encrypted chunks together with the current
        # telemetry. A failed CAS changes nothing; retries cannot lose an update.
        script = """
        for i=3,5 do
          local old=redis.call('GET',KEYS[i]) or ''
          if old~=ARGV[8+(i-3)*4] then return 0 end
        end
        if ARGV[3]~='' then redis.call('SETEX',KEYS[2],300,ARGV[3]) end
        if redis.call('HEXISTS',KEYS[1],'__epoch')==0 then redis.call('HSET',KEYS[1],'__epoch',ARGV[5]) end
        redis.call('HSET',KEYS[1],'meta:'..ARGV[1],ARGV[4])
        redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[2],1)
        local newblock=redis.call('HEXISTS',KEYS[6],ARGV[9])==0
        if newblock or redis.call('HGET',KEYS[6],'__policy')~=ARGV[7] then
          local fields=redis.call('HGETALL',KEYS[6])
          for i=1,#fields,2 do
            local tier,block=string.match(fields[i],'^([fmh]):(%d+)$')
            if tier then
              local offset=({f=1,m=2,h=3})[tier]
              local spans={60,3600,86400}
              local keep=tonumber(ARGV[20+offset])
              local deadline=math.min(tonumber(fields[i+1]),(tonumber(block)+1)*spans[offset]+keep)
              local chunk=ARGV[6]..fields[i]
              if deadline<=tonumber(ARGV[20]) then
                redis.call('UNLINK',chunk); redis.call('HDEL',KEYS[6],fields[i])
              elseif deadline<tonumber(fields[i+1]) then
                redis.call('EXPIREAT',chunk,deadline); redis.call('HSET',KEYS[6],fields[i],deadline)
              end
            end
          end
          redis.call('HSET',KEYS[6],'__policy',ARGV[7])
        end
        for i=3,5 do
          local offset=8+(i-3)*4
          redis.call('SET',KEYS[i],ARGV[offset+2],'EXAT',ARGV[offset+3])
          redis.call('HSET',KEYS[6],ARGV[offset+1],ARGV[offset+3])
        end
        redis.call('HINCRBY',KEYS[6],'__revision',1)
        redis.call('EXPIREAT',KEYS[6],ARGV[24])
        redis.call('DEL',ARGV[6]..'view:15m',ARGV[6]..'view:1h')
        return 1
        """
        now = values["received_at"]
        try:
            for _ in range(3):  # Initial attempt plus at most two bounded retries.
                chunks = history.prepare(device, now, values)
                if chunks is None:
                    return None
                prefix = history.prefix(device)
                arguments = [device, space, raw or "", meta, epoch, prefix, history.policy]
                for chunk, previous, encoded, deadline in chunks:
                    arguments.extend((previous or "", chunk.removeprefix(prefix), encoded, deadline))
                arguments.extend((now, *history.retention, now + max(history.retention) + 86400))
                result = self.command("EVAL", script, 6, key, key + ":snapshot:" + device, *(chunk[0] for chunk in chunks), prefix + "index", *arguments)
                if result != 0:
                    return result
        except (ValueError, OverflowError, struct.error):
            return None
        return None

    def remove_reports(self, key, devices, space, forget_space=False):
        script = """
        for i=3,#ARGV do
          redis.call('HDEL',KEYS[1],'meta:'..ARGV[i])
          redis.call('UNLINK',KEYS[1]..':snapshot:'..ARGV[i])
          local prefix=KEYS[1]..':history:'..ARGV[i]..':'
          local fields=redis.call('HKEYS',prefix..'index')
          local keys={prefix..'index'}
          for _,field in ipairs(fields) do
            if string.match(field,'^[fmh]:%d+$') then table.insert(keys,prefix..field) end
          end
          for _,range in ipairs({'15m','1h','24h','7d','30d','all'}) do table.insert(keys,prefix..'view:'..range) end
          redis.call('UNLINK',unpack(keys))
        end
        if ARGV[2]=='1' then redis.call('HDEL',KEYS[1],'rev:'..ARGV[1])
        else redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[1],1) end
        return 1
        """
        return self.command("EVAL", script, 1, key, space, int(forget_space), *devices)

    def rate(self, key, identity, maximum, seconds):
        script = """
        if redis.call('HEXISTS',KEYS[1],ARGV[1])==0 and redis.call('HLEN',KEYS[1])>=10000 then return -1 end
        local value=redis.call('HINCRBY',KEYS[1],ARGV[1],1)
        redis.call('EXPIRE',KEYS[1],tonumber(ARGV[3])*2)
        if value>tonumber(ARGV[2]) then return 0 end
        return 1
        """
        return self.command("EVAL", script, 1, key, identity, maximum, seconds)

    def lease(self, key, member, scope, now):
        script = """
        redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',ARGV[3])
        local members=redis.call('ZRANGE',KEYS[1],0,-1)
        if #members>=32 then return 0 end
        local count=0
        for _,v in ipairs(members) do if string.sub(v,1,64)==ARGV[2] then count=count+1 end end
        if count>=4 then return 0 end
        redis.call('ZADD',KEYS[1],tonumber(ARGV[3])+20,ARGV[1]); redis.call('EXPIRE',KEYS[1],30)
        return 1
        """
        return self.command("EVAL", script, 1, key, member, scope, now)


class MetricHistory:
    """Three encrypted, packed rollups; chunk keys have absolute TTLs.

    A record is a slot plus five float32 means and five uint16 sample counts
    (32 bytes before compression/encryption). Missing metrics have zero count.
    All levels consume original samples, never unweighted means of means.
    """
    record = struct.Struct(">H5f5H")
    fields = ("cpu_percent", "memory_percent", "disk_percent", "network_rx_bps", "network_tx_bps")
    sources = ("cpu", "memory", "disk", "network_rx_bps", "network_tx_bps")
    spans = (60, 3600, 86400)
    steps = (1, 60, 3600)
    tiers = ("f", "m", "h")
    ranges = {"15m": 900, "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}

    def __init__(self, cache, box, namespace, retention, fine_step=3):
        self.cache, self.box, self.namespace = cache, box, namespace
        self.retention, self.fine_step = tuple(retention), fine_step
        if not (60 <= retention[0] <= 86400 and retention[0] <= retention[1] <= 604800 and retention[1] <= retention[2] <= 31536000):
            raise ValueError("Invalid history retention")
        if fine_step not in (1, 2, 3, 5, 6, 10, 12, 15, 20, 30, 60):
            raise ValueError("History fine step must divide one minute")
        self.policy = ":".join(map(str, (*retention, fine_step)))

    def prefix(self, device):
        return self.namespace + ":history:" + device + ":"

    def decode(self, key, encoded):
        if encoded is None:
            return {}
        raw = self.box.open_history(key, encoded)
        if len(raw) % self.record.size:
            raise ValueError("Invalid history record size")
        result = {}
        for record in self.record.iter_unpack(raw):
            slot, means, counts = record[0], list(record[1:6]), list(record[6:])
            if slot in result or slot >= 60 or any(not math.isfinite(mean) or mean < 0 for mean in means):
                raise ValueError("Invalid history record")
            result[slot] = [means, counts]
        return result

    def encode(self, key, records):
        raw = b"".join(self.record.pack(slot, *means, *counts) for slot, (means, counts) in sorted(records.items()))
        return self.box.seal_history(key, raw)

    def prepare(self, device, now, metadata):
        prefix = self.prefix(device)
        keys = [prefix + tier + ":" + str(now // span) for tier, span in zip(self.tiers, self.spans)]
        previous = self.cache.command("MGET", *keys)
        if previous is None:
            return None
        chunks = []
        for key, old, span, step, retention in zip(keys, previous, self.spans, self.steps, self.retention):
            records = self.decode(key, old)
            slot = (now % span) // step
            means, counts = records.setdefault(slot, [[0.0] * 5, [0] * 5])
            for index, source in enumerate(self.sources):
                value = metadata.get(source)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1e30:
                    if counts[index] >= 65535:
                        raise ValueError("History bucket sample count exceeded")
                    counts[index] += 1
                    means[index] += (value - means[index]) / counts[index]
            chunks.append((key, old, self.encode(key, records), (now // span + 1) * span + retention))
        return chunks

    def read(self, device, selection, now=None):
        now = int(time.time()) if now is None else int(now)
        if selection not in (*self.ranges, "all"):
            raise ValueError("Invalid history range")
        seconds = min(self.ranges.get(selection, self.retention[2]), self.retention[2])
        tier, step = 2, 3600
        if seconds <= self.retention[0] and math.ceil(seconds / self.fine_step) <= 720:
            tier, step = 0, self.fine_step
        elif seconds <= self.retention[1] and math.ceil(seconds / 60) <= 720:
            tier, step = 1, 60
        if tier == 2:
            step *= max(1, math.ceil(seconds / (3600 * 720)))
        start = ((now - seconds) // step) * step
        # Complete intersecting buckets may straddle a retention boundary.
        start = max(start, math.ceil((now - self.retention[tier]) / step) * step)
        start = max(start, (now // step - 719) * step)
        prefix, span = self.prefix(device), self.spans[tier]
        view_key = prefix + "view:" + selection
        state = self.cache.command("EVAL", "return {redis.call('HGET',KEYS[1],'__revision') or '0',redis.call('GET',KEYS[2])}", 2, prefix + "index", view_key)
        if state is None:
            raise ConnectionError("History cache unavailable")
        purpose = view_key + ":" + self.policy
        if state[1]:
            try:
                return self.box.open_report(purpose, state[1])
            except ValueError:
                pass
        keys = [prefix + self.tiers[tier] + ":" + str(block) for block in range(start // span, now // span + 1)]
        values = self.cache.command("MGET", *keys)
        if values is None:
            raise ConnectionError("History chunks unavailable")
        buckets = {}
        for key, encoded in zip(keys, values):
            block = int(key.rsplit(":", 1)[1])
            for slot, (means, counts) in self.decode(key, encoded).items():
                timestamp = block * span + slot * self.steps[tier]
                if not start <= timestamp <= now:
                    continue
                bucket = timestamp // step * step
                sums, totals = buckets.setdefault(bucket, [[0.0] * 5, [0] * 5])
                for index in range(5):
                    sums[index] += means[index] * counts[index]
                    totals[index] += counts[index]
        points = [[timestamp, *(round(sums[i] / counts[i], 6) if counts[i] else None for i in range(5))] for timestamp, (sums, counts) in sorted(buckets.items()) if any(counts)]
        if len(points) > 720:
            raise ValueError("History response exceeds bound")
        result = {"columns": ["time", *self.fields], "points": points, "from": start, "to": now, "resolution_seconds": step, "retention_seconds": self.retention[tier], "max_retention_seconds": self.retention[2], "refresh_ms": 3000 if tier == 0 else 5000 if tier == 1 else 30000, "storage": "redis", "aggregation": "sample_weighted_mean"}
        encoded = self.box.seal_report(purpose, result)
        # Prevent a slow reader from publishing a pre-ingest view after the writer
        # has invalidated it. Coarse views intentionally refresh less frequently.
        script = "if (redis.call('HGET',KEYS[1],'__revision') or '0')~=ARGV[1] then return 0 end; redis.call('SETEX',KEYS[2],ARGV[2],ARGV[3]); return 1"
        self.cache.command("EVAL", script, 2, prefix + "index", view_key, state[0], 2 if tier == 0 else 5 if tier == 1 else 30, encoded)
        return result
