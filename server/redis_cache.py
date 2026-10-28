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

    def store_metrics(self, key, device, space, meta, epoch):
        # Fast resource samples never replace or extend the full diagnostic snapshot.
        script = """
        if redis.call('HEXISTS',KEYS[1],'__epoch')==0 then redis.call('HSET',KEYS[1],'__epoch',ARGV[4]) end
        redis.call('HSET',KEYS[1],'meta:'..ARGV[1],ARGV[3])
        redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[2],1)
        return 1
        """
        return self.command("EVAL", script, 1, key, device, space, meta, epoch)

    def store_report(self, key, device, space, raw, meta, epoch):
        # Full snapshots are a short-lived compressed cache, not a resource
        # quota. Offline raw payloads expire; compact last-seen metadata remains.
        script = """
        redis.call('SETEX',KEYS[2],300,ARGV[3])
        if redis.call('HEXISTS',KEYS[1],'__epoch')==0 then redis.call('HSET',KEYS[1],'__epoch',ARGV[5]) end
        redis.call('HSET',KEYS[1],'meta:'..ARGV[1],ARGV[4])
        redis.call('HINCRBY',KEYS[1],'rev:'..ARGV[2],1)
        return 1
        """
        return self.command("EVAL", script, 2, key, key + ":snapshot:" + device, device, space, raw, meta, epoch)

    def remove_reports(self, key, devices, space, forget_space=False):
        script = """
        for i=3,#ARGV do
          redis.call('HDEL',KEYS[1],'meta:'..ARGV[i])
          redis.call('DEL',KEYS[1]..':snapshot:'..ARGV[i])
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
