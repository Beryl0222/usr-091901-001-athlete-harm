"""敏感材料分区：报案人联系方式与未公开身份材料。

设计要点：
- 独立保管箱文件（vault），与案件研判材料物理分离；
- 使用标准库实现 Encrypt-then-MAC 认证加密（每密文随机 nonce，HMAC-SHA256 校验）；
- 密钥独立文件（pii.key，0600），不与数据同放；
- 任何解密读取都必须登记用途并写入访问日志（在 workflow 层完成）。
"""

import hmac
import json
import os
from hashlib import sha256
from pathlib import Path

from .errors import ApiError


def _derive(master_key, label):
    return hmac.new(master_key, label, sha256).digest()


def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(enc_key, b"stream" + nonce + counter.to_bytes(8, "big"), sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


class Vault:
    """存放报案人敏感材料的加密保管箱。"""

    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._vault_path = self.dir / "vault.json"
        self._key_path = self.dir / "pii.key"
        self._master_key = self._load_or_create_key()
        self._enc_key = _derive(self._master_key, b"encryption-v1")
        self._mac_key = _derive(self._master_key, b"authentication-v1")

    def _load_or_create_key(self):
        if self._key_path.exists():
            key = self._key_path.read_bytes()
            if len(key) >= 32:
                return key
        key = os.urandom(32)
        self._key_path.write_bytes(key)
        os.chmod(self._key_path, 0o600)
        return key

    def _decrypt_blob(self):
        if not self._vault_path.exists():
            return {}
        envelope = json.loads(self._vault_path.read_text(encoding="utf-8"))
        nonce = bytes.fromhex(envelope["nonce"])
        ciphertext = bytes.fromhex(envelope["ct"])
        tag = bytes.fromhex(envelope["mac"])
        expected = hmac.new(self._mac_key, nonce + ciphertext, sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ApiError(500, "敏感材料保管箱完整性校验失败")
        stream = _keystream(self._enc_key, nonce, len(ciphertext))
        plain = bytes(a ^ b for a, b in zip(ciphertext, stream))
        return json.loads(plain.decode("utf-8"))

    def _encrypt_blob(self, obj):
        plain = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(16)
        stream = _keystream(self._enc_key, nonce, len(plain))
        ciphertext = bytes(a ^ b for a, b in zip(plain, stream))
        tag = hmac.new(self._mac_key, nonce + ciphertext, sha256).hexdigest()
        envelope = {"v": 1, "nonce": nonce.hex(), "ct": ciphertext.hex(), "mac": tag}
        tmp = self._vault_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self._vault_path)
        if self._vault_path.exists():
            os.chmod(self._vault_path, 0o600)

    def put_lead_secret(self, lead_id, secret):
        blob = self._decrypt_blob()
        blob.setdefault("leads", {})[lead_id] = secret
        self._encrypt_blob(blob)

    def get_lead_secret(self, lead_id):
        blob = self._decrypt_blob()
        return blob.get("leads", {}).get(lead_id)
