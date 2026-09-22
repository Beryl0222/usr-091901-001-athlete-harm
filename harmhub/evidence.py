"""证据保全：原始内容留存、内容哈希、可信时间戳与链式保全回执。

即使原始链接失效，仍可用「保全时间 + 内容哈希 + 链式回执」证明当时所见：
- 内容文件只读落盘（evidence/<ev_id>.bin），永不修改；
- 保全回执包含：取证时间、来源 URL、归一化原文、SHA-256、保全人、上一环节点哈希；
- 节点哈希链式相扣（evidence_chain_tip），任何事后篡改都会断链；
- 修订/补件一律新建保全记录，绝不覆盖旧记录。
"""

import json
import os
import re
from pathlib import Path

from .util import new_id, sha256_hex, utcnow


def normalize_content(content):
    """归一化：统一换行并去除首尾空白，哈希对同样文本稳定可复算。"""
    text = content.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def canonical_text(content):
    return re.sub(r"\s+", " ", normalize_content(content)).lower()


class EvidenceService:
    def __init__(self, store, data_dir):
        self.store = store
        self.dir = Path(data_dir) / "evidence"
        self.dir.mkdir(parents=True, exist_ok=True)

    def preserve(self, *, url, content, content_type, captured_by, platform, note=None, observed_at=None):
        """对一次「当时所见」出具保全回执。observed_at 为线索声称的发布时间。"""
        with self.store.lock:
            record_id = new_id("ev")
            normalized = normalize_content(content)
            content_hash = sha256_hex(normalized)
            captured_at = utcnow()
            tip = self.store.state["evidence_chain_tip"]

            node_material = json.dumps(
                {
                    "id": record_id,
                    "content_hash": content_hash,
                    "captured_at": captured_at,
                    "url": url,
                    "prev": tip,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            node_hash = sha256_hex(node_material)

            blob_path = self.dir / f"{record_id}.bin"
            blob_path.write_text(normalized, encoding="utf-8")
            os.chmod(blob_path, 0o444)

            record = {
                "id": record_id,
                "url": url,
                "platform": platform,
                "content_type": content_type,
                "observed_at": observed_at,
                "captured_at": captured_at,
                "content_sha256": content_hash,
                "content_chars": len(normalized),
                "captured_by": captured_by,
                "note": note,
                "prev_hash": tip,
                "receipt_hash": node_hash,
                "blob": str(blob_path),
                "supersedes": None,
            }
            self.store.state["evidence_index"].append(record)
            self.store.state["evidence_chain_tip"] = node_hash
            self.store.audit(
                captured_by,
                "证据保全",
                target=record_id,
                detail={"url": url, "content_sha256": content_hash},
            )
            self.store.save()
            return record

    def re_preserve(self, *, previous_evidence_id, **kwargs):
        """对同一来源重新取证（链接内容更新）：追加新记录并关联旧记录，旧记录不动。"""
        previous = self.get(previous_evidence_id)
        if previous is None:
            raise KeyError(previous_evidence_id)
        record = self.preserve(**kwargs)
        record["supersedes"] = previous_evidence_id
        self.store.save()
        return record

    def get(self, evidence_id):
        for record in self.store.state["evidence_index"]:
            if record["id"] == evidence_id:
                return record
        return None

    def verify_chain(self):
        """从创世节点逐条重算哈希链，返回 (是否完好, 问题节点或 None)。"""
        tip = "GENESIS"
        for record in self.store.state["evidence_index"]:
            if record["prev_hash"] != tip:
                return False, record["id"]
            material = json.dumps(
                {
                    "id": record["id"],
                    "content_hash": record["content_sha256"],
                    "captured_at": record["captured_at"],
                    "url": record["url"],
                    "prev": record["prev_hash"],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if sha256_hex(material) != record["receipt_hash"]:
                return False, record["id"]
            blob_path = Path(record["blob"])
            if not blob_path.exists() or sha256_hex(blob_path.read_text(encoding="utf-8")) != record["content_sha256"]:
                return False, record["id"]
            tip = record["receipt_hash"]
        return True, None
