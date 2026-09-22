"""线程内安全的 JSON 状态存储与追加式审计日志。"""

import json
import os
import threading
from pathlib import Path

from .util import new_id, utcnow

COLLECTIONS = ("tokens", "leads", "incidents", "evidence_index", "audit", "pii_access", "rules")


class Store:
    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "state.json"
        self.lock = threading.RLock()
        self.state = self._load()

    def _load(self):
        if self.path.exists():
            state = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            state = {}
        state.setdefault("version", 1)
        maps = {"tokens", "leads", "incidents", "rules"}
        for name in COLLECTIONS:
            state.setdefault(name, {} if name in maps else [])
        state.setdefault("evidence_chain_tip", "GENESIS")
        return state

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)

    def audit(self, actor, action, target="", detail=None, rule_version=None):
        """追加一条不可修改的审计记录。"""
        entry = {
            "id": new_id("aud"),
            "at": utcnow(),
            "actor": actor,
            "action": action,
            "target": target,
            "detail": detail or {},
        }
        if rule_version:
            entry["rule_version"] = rule_version
        self.state["audit"].append(entry)
        return entry

    def record_pii_access(self, actor, lead_id, purpose, incident_id):
        entry = {
            "id": new_id("piiacc"),
            "at": utcnow(),
            "actor": actor,
            "lead_id": lead_id,
            "incident_id": incident_id,
            "purpose": purpose,
        }
        self.state["pii_access"].append(entry)
        self.state["audit"].append(
            {
                "id": new_id("aud"),
                "at": entry["at"],
                "actor": actor,
                "action": "接触敏感材料",
                "target": incident_id,
                "detail": {"lead_id": lead_id, "purpose": purpose},
            }
        )
        return entry
