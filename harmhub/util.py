"""时间、标识与哈希工具。"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone


def utcnow():
    """统一的 UTC 时间戳（秒级精度，便于演示与比对）。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_id(prefix):
    return f"{prefix}_{secrets.token_hex(6)}"


def new_token():
    """入口令牌，只以哈希形式落盘。"""
    return secrets.token_urlsafe(24)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def same_secret(a, b):
    return hmac.compare_digest(str(a or ""), str(b or ""))
