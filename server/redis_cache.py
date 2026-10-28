"""Bounded Redis storage over one hosting account's private Unix socket.

All callers use fixed commands/scripts. Redis owns dynamic telemetry, cache,
rate limits and stream leases; it never grants tenant or host-control authority.
"""
import json
import socket
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

    def get(self, key):
        raw = self.command("GET", key)
        try:
            return json.loads(raw) if raw else None
        except (ValueError, TypeError):
            return None

    def put(self, key, value):
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return self.command("SETEX", key, 15, raw) if len(raw.encode()) <= 1024 * 1024 else None

    def healthy(self):
        return self.command("PING") == "PONG"

    def store_report(self, key, device, space, raw, meta, epoch, budget):
        # One hash keeps its byte counter and data in the same Redis eviction
        # unit. Atomic fixed Lua prevents concurrent writers exceeding budget.
        script = """
        local a='raw:'..ARGV[1]; local b='meta:'..ARGV[1]
        local old=string.len(redis.call('HGET',KEYS[1],a) or '')+string.len(redis.call('HGET',KEYS[1],b) or '')
        local total=tonumber(redis.call('HGET',KEYS[1],'__bytes') or 0)-old+string.len(ARGV[3])+string.len(ARGV[4])
        if total>tonumber(ARGV[6]) then return -1 end
        if redis.call('HEXISTS',KEYS[1],'__epoch')==0 then redis.call('HSET',KEYS[1],'__epoch',ARGV[5]) end
        redis.call('HSET',KEYS[1],a,ARGV[3],b,ARGV[4],'__bytes',total)
        redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[2],1)
        return 1
        """
        return self.command("EVAL", script, 1, key, device, space, raw, meta, epoch, budget)

    def remove_reports(self, key, devices, space):
        if not devices:
            return 1
        script = """
        local removed=0
        for i=2,#ARGV do
          local a='raw:'..ARGV[i]; local b='meta:'..ARGV[i]
          removed=removed+string.len(redis.call('HGET',KEYS[1],a) or '')+string.len(redis.call('HGET',KEYS[1],b) or '')
          redis.call('HDEL',KEYS[1],a,b)
        end
        local total=math.max(0,tonumber(redis.call('HGET',KEYS[1],'__bytes') or 0)-removed)
        redis.call('HSET',KEYS[1],'__bytes',total)
        redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[1],1)
        return 1
        """
        return self.command("EVAL", script, 1, key, space, *devices)

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
