"""Purpose-bound authenticated encryption; no custom cipher implementation."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import zlib

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def verify_signature(public_key, signature, message):
    if not isinstance(public_key, str) or not re.fullmatch(r"[a-f0-9]{64}", public_key) or not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{128}", signature):
        raise ValueError("Invalid signature encoding")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(signature), message.encode())
    except (ValueError, InvalidSignature) as error:
        raise ValueError("Invalid signature") from error


class SealedData:
    def __init__(self, instance_secret):
        key = hmac.digest(bytes.fromhex(instance_secret), b"w-monitor-public:aes-gcm:v1", hashlib.sha256)
        self.cipher = AESGCM(key)

    def seal(self, purpose, value):
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        return self._seal("wm1_", purpose, raw)

    def _seal(self, prefix, purpose, raw):
        nonce = secrets.token_bytes(12)
        encrypted = self.cipher.encrypt(nonce, raw, ("w-monitor-public:v1:" + purpose).encode())
        return prefix + base64.urlsafe_b64encode(nonce + encrypted).decode().rstrip("=")

    def open(self, purpose, token):
        try:
            return json.loads(self._open("wm1_", purpose, token))
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("Invalid sealed value") from None

    def _open(self, prefix, purpose, token):
        if not isinstance(token, str) or len(token) > 12 * 1024 * 1024 or not re.fullmatch(prefix + r"[A-Za-z0-9_-]+", token):
            raise ValueError("Invalid sealed value")
        try:
            encoded = token[len(prefix):]
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            if len(raw) < 29:
                raise ValueError()
            return self.cipher.decrypt(raw[:12], raw[12:], ("w-monitor-public:v1:" + purpose).encode())
        except (ValueError, InvalidTag, UnicodeError, RecursionError):
            raise ValueError("Invalid sealed value") from None

    def seal_report(self, purpose, report):
        raw = json.dumps(report, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        return self._seal("wmz1_", purpose + ":zlib", zlib.compress(raw, level=3))

    def open_report(self, purpose, token):
        try:
            compressed = self._open("wmz1_", purpose + ":zlib", token)
            decoder = zlib.decompressobj()
            raw = decoder.decompress(compressed, 8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024 or not decoder.eof or decoder.unused_data:
                raise ValueError()
            return json.loads(raw)
        except (ValueError, zlib.error, UnicodeError, RecursionError):
            raise ValueError("Invalid report snapshot") from None

    def seal_history(self, purpose, raw):
        return self._seal("wmh1_", purpose, zlib.compress(raw, level=1))

    def open_history(self, purpose, token):
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(self._open("wmh1_", purpose, token), 4097)
            if len(raw) > 4096 or not decoder.eof or decoder.unused_data:
                raise ValueError()
            return raw
        except (ValueError, zlib.error):
            raise ValueError("Invalid history chunk") from None
