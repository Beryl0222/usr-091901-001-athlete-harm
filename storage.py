"""存储层：案件库与联系方式保密封库物理分离，核心表全部仅追加。

- ``casebook.db`` 保存线索、事件、证据、保全回执、研判建议、人工决定、申诉与补件；
  所有业务表均挂载 UPDATE/DELETE 触发器，任何篡改尝试都会被 SQLite 拒绝，
  因此“申诉、规则升级、重复举报、跨平台补件”只能以追加新行的方式发生。
- ``contacts.db`` 是联系方式保封库，与案件研判库分离，案件视图默认不含联系方式，
  仅经授权入口可调阅，且每次接触都写入访问台账。
- 保全回执按出具顺序构成哈希链，任一条被改动都会导致链校验失败。
"""

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

APPEND_ONLY_TABLES = [
    "reports",
    "report_status_log",
    "events",
    "event_reports",
    "event_status_log",
    "evidences",
    "receipts",
    "assessments",
    "decisions",
    "decision_receipts",
    "appeals",
    "appeal_resolutions",
    "supplements",
    "rule_versions",
    "audit_log",
]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(payload):
    """对字典做稳定序列化后取哈希，作为证据/回执内容指纹。"""
    return sha256_text(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":")))


SCHEMA = """
CREATE TABLE IF NOT EXISTS subjects(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  public_profile TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users(
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  org TEXT
);
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY,
  received_at TEXT NOT NULL,
  channel TEXT NOT NULL,
  reporter_role TEXT NOT NULL,
  reporter_ref TEXT,
  subject_id TEXT NOT NULL,
  platform TEXT,
  content_url TEXT,
  url_key TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  category_hint TEXT,
  target_scope INTEGER NOT NULL,
  spread_scope INTEGER NOT NULL,
  credibility INTEGER NOT NULL,
  urgency INTEGER NOT NULL,
  claim_key TEXT,
  fingerprint TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_subject_url
  ON reports(subject_id, url_key);
CREATE TABLE IF NOT EXISTS report_status_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL,
  status TEXT NOT NULL,
  at TEXT NOT NULL,
  by_role TEXT NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  title TEXT NOT NULL,
  cluster_key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS event_reports(
  event_id TEXT NOT NULL,
  report_id TEXT NOT NULL,
  linked_at TEXT NOT NULL,
  link_reason TEXT NOT NULL,
  PRIMARY KEY(event_id, report_id)
);
CREATE TABLE IF NOT EXISTS event_status_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  status TEXT NOT NULL,
  at TEXT NOT NULL,
  by_role TEXT NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS evidences(
  id TEXT PRIMARY KEY,
  report_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  url TEXT,
  snapshot TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  source_role TEXT NOT NULL,
  supersedes_id TEXT,
  note TEXT
);
CREATE TABLE IF NOT EXISTS receipts(
  id TEXT PRIMARY KEY,
  receipt_no TEXT NOT NULL UNIQUE,
  evidence_id TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  prev_hash TEXT,
  chain_hash TEXT NOT NULL,
  sealed_by TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments(
  id TEXT PRIMARY KEY,
  event_id TEXT,
  report_id TEXT,
  rule_version TEXT NOT NULL,
  scores_json TEXT NOT NULL,
  category TEXT NOT NULL,
  suggestions_json TEXT NOT NULL,
  triggers_json TEXT NOT NULL,
  rationale TEXT NOT NULL,
  advisory INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions(
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  decision_type TEXT NOT NULL,
  action TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  decided_by_role TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  rationale TEXT NOT NULL,
  created_at TEXT NOT NULL,
  supersedes_decision_id TEXT
);
CREATE TABLE IF NOT EXISTS decision_receipts(
  id TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  receipt_kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS appeals(
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  report_id TEXT,
  decision_id TEXT,
  submitted_by TEXT NOT NULL,
  submitter_role TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  preserved_assessment_id TEXT
);
CREATE TABLE IF NOT EXISTS appeal_resolutions(
  id TEXT PRIMARY KEY,
  appeal_id TEXT NOT NULL,
  resolution TEXT NOT NULL,
  reviewed_by TEXT NOT NULL,
  reviewer_role TEXT NOT NULL,
  review_note TEXT NOT NULL,
  reviewed_rule_version TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS supplements(
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  report_id TEXT,
  kind TEXT NOT NULL,
  submitted_by TEXT NOT NULL,
  submitted_by_role TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_versions(
  version TEXT PRIMARY KEY,
  note TEXT NOT NULL,
  published_by TEXT NOT NULL,
  published_at TEXT NOT NULL,
  supersedes TEXT,
  rules_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT,
  object_id TEXT,
  allowed INTEGER NOT NULL,
  detail TEXT
);
"""

CONTACTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS subject_contacts(
  subject_id TEXT PRIMARY KEY,
  contact_detail TEXT NOT NULL,
  identity_material TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contact_access_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  allowed INTEGER NOT NULL
);
"""


class Store:
    """案件研判库。单连接加锁，供线程化 HTTP 服务使用。"""

    def __init__(self, db_path, seed=True):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        if seed:
            self._seed()

    def _init_schema(self):
        with self._lock:
            self.conn.executescript(SCHEMA)
            for table in APPEND_ONLY_TABLES:
                self.conn.execute(
                    f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update BEFORE UPDATE ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'append-only table: " + table + "'); END")
                self.conn.execute(
                    f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete BEFORE DELETE ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'append-only table: " + table + "'); END")
            self.conn.commit()

    def _seed(self):
        with self._lock:
            count = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                users = [
                    ("tok_self_lin", "u_lin", "林晓（队员）", "athlete", "个人"),
                    ("tok_club_tiger", "u_club", "猛虎俱乐部联络员", "club", "猛虎俱乐部"),
                    ("tok_plat_weibo", "u_plat", "微博台协查员", "platform", "微博台"),
                    ("tok_plat_douyin", "u_plat2", "抖音台协查员", "platform", "抖音台"),
                    ("tok_duty", "u_duty", "协会值班员", "duty", "体育协会"),
                    ("tok_police", "u_police", "公安联络员", "police", "属地网安"),
                ]
                self.conn.executemany(
                    "INSERT INTO users(token,user_id,name,role,org) VALUES(?,?,?,?,?)", users)
                self.conn.execute(
                    "INSERT INTO subjects(id,name,public_profile,created_at) VALUES(?,?,?,?)",
                    ("s_lin", "林晓", "猛虎俱乐部一线队员", utcnow()))
                self.conn.commit()

    # ---- 基础工具 ----
    def execute(self, sql, params=()):
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def query(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def query_one(self, sql, params=()):
        with self._lock:
            r = self.conn.execute(sql, params).fetchone()
            return dict(r) if r else None

    def audit(self, actor, role, action, allowed, object_type=None, object_id=None, detail=None):
        self.execute(
            "INSERT INTO audit_log(ts,actor,role,action,object_type,object_id,allowed,detail) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (utcnow(), actor, role, action, object_type, object_id, 1 if allowed else 0, detail))

    # ---- 保全回执哈希链 ----
    def last_receipt(self):
        return self.query_one("SELECT * FROM receipts ORDER BY rowid DESC LIMIT 1")

    def seal_receipt(self, receipt_id, evidence_id, sealed_by, payload):
        """出具保全回执：内容哈希 + 前序回执哈希构成链式证据。"""
        prev = self.last_receipt()
        prev_hash = prev["chain_hash"] if prev else None
        content_hash = payload["content_hash"]
        chain_hash = sha256_text(
            canonical_hash(payload) + (prev_hash or "GENESIS"))
        receipt_no = "RC" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        self.execute(
            "INSERT INTO receipts(id,receipt_no,evidence_id,captured_at,content_hash,"
            "prev_hash,chain_hash,sealed_by,payload_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (receipt_id, receipt_no, evidence_id, payload["captured_at"], content_hash,
             prev_hash, chain_hash, sealed_by,
             json.dumps(payload, ensure_ascii=False)))
        return self.query_one("SELECT * FROM receipts WHERE id=?", (receipt_id,))

    def verify_chain(self):
        """从创世回执开始逐条重算哈希链，返回全部断点。"""
        receipts = self.query("SELECT * FROM receipts ORDER BY rowid")
        prev_hash = None
        breaks = []
        for r in receipts:
            payload = json.loads(r["payload_json"])
            expected = sha256_text(canonical_hash(payload) + (prev_hash or "GENESIS"))
            if expected != r["chain_hash"]:
                breaks.append(r["receipt_no"])
            prev_hash = r["chain_hash"]
        return {"receipts": len(receipts), "breaks": breaks,
                "intact": not breaks}


class ContactVault:
    """联系方式保封库：独立文件，不与案件研判库连接。"""

    def __init__(self, db_path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(CONTACTS_SCHEMA)
        self.conn.commit()
        if self.conn.execute("SELECT COUNT(*) FROM subject_contacts").fetchone()[0] == 0:
            self.conn.execute(
                "INSERT INTO subject_contacts(subject_id,contact_detail,identity_material,updated_at)"
                " VALUES(?,?,?,?)",
                ("s_lin", "电话 138-0000-0000（仅值班席知晓）",
                 "身份证号/家庭住址等未公开身份材料，密封存储", utcnow()))
            self.conn.commit()

    def access(self, actor, role, subject_id, purpose, allowed):
        with self._lock:
            self.conn.execute(
                "INSERT INTO contact_access_log(ts,actor,role,subject_id,purpose,allowed)"
                " VALUES(?,?,?,?,?,?)",
                (utcnow(), actor, role, subject_id, purpose, 1 if allowed else 0))
            self.conn.commit()
            if not allowed:
                return None
            row = self.conn.execute(
                "SELECT * FROM subject_contacts WHERE subject_id=?", (subject_id,)).fetchone()
            return dict(row) if row else None

    def access_ledger(self):
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM contact_access_log ORDER BY id").fetchall()]
