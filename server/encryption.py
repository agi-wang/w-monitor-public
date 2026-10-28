"""Purpose-bound authenticated encryption; no custom cipher implementation."""
import base64
import hashlib
import hmac
import json
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SealedData:
    def __init__(self, instance_secret):
        key = hmac.digest(bytes.fromhex(instance_secret), b"w-monitor-public:aes-gcm:v1", hashlib.sha256)
        self.cipher = AESGCM(key)

    def seal(self, purpose, value):
        nonce = secrets.token_bytes(12)
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        encrypted = self.cipher.encrypt(nonce, raw, ("w-monitor-public:v1:" + purpose).encode())
        return "wm1_" + base64.urlsafe_b64encode(nonce + encrypted).decode().rstrip("=")

    def open(self, purpose, token):
        if not isinstance(token, str) or len(token) > 12 * 1024 * 1024 or not re.fullmatch(r"wm1_[A-Za-z0-9_-]+", token):
            raise ValueError("Invalid sealed value")
        try:
            raw = base64.urlsafe_b64decode(token[4:] + "=" * (-len(token[4:]) % 4))
            if len(raw) < 29:
                raise ValueError()
            return json.loads(self.cipher.decrypt(raw[:12], raw[12:], ("w-monitor-public:v1:" + purpose).encode()))
        except (ValueError, InvalidTag, UnicodeError, RecursionError):
            raise ValueError("Invalid sealed value") from None
