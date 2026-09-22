"""处置流水线：线索归集 → 同源聚合 → 证据保全 → 规则建议 → 人工确认。

设计原则（与领域契约 invariants 一一对应）：
1. 规则引擎产物只写入 assessments（advisory=1），decisions 只能由人工接口创建；
2. 申诉、规则升级、重复举报、跨平台补件一律 INSERT 新行，核心表触发器拒绝 UPDATE/DELETE；
3. 每条 decision 固化 rule_version 与 assessment_id，历史研判永不被重算覆盖；
4. 联系方式在独立保封库，案件视图不含任何联系方式字段，调阅必须授权且留痕。
"""

import json
import uuid
from pathlib import Path

import rules
from storage import ContactVault, Store, canonical_hash, sha256_text, utcnow

CONTRACT_PATH = Path(__file__).with_name("domain_contract.json")
VALID_STATES = {"已接收", "待核验", "保护处置中", "待申诉", "已归档"}
SCORE_FIELDS = ("target_scope", "spread_scope", "credibility", "urgency")
# 演示用：保护对象账号与保护对象主体的绑定（生产中应由授权关系表维护）
ATHLETE_SUBJECT = {"u_lin": "s_lin"}
DECISION_PERM = {
    "restrict": "decision.restrict",
    "protect_contact": "decision.protect_contact",
    "refer_law_enforcement": "decision.refer",
}


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Pipeline:
    def __init__(self, store: Store, vault: ContactVault):
        self.store = store
        self.vault = vault
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.role_perms = {role: set(info["permissions"])
                           for role, info in contract["roles"].items()}
        self.role_channels = {role: set(info["channels"])
                              for role, info in contract["roles"].items()}
        self._seed_rules()

    # ============ 鉴权 ============
    def authenticate(self, token):
        return self.store.query_one("SELECT * FROM users WHERE token=?", (token,))

    def can(self, role, perm):
        return perm in self.role_perms.get(role, ())

    def require(self, user, perm):
        if not self.can(user["role"], perm):
            self.store.audit(user["user_id"], user["role"], perm, False,
                             detail="权限不足被拒绝")
            raise ApiError(403, "forbidden",
                           f"角色 {user['role']} 无权执行 {perm}，自动规则建议不能替代人工确认")

    def audit(self, user, action, allowed=True, object_type=None, object_id=None, detail=None):
        self.store.audit(user["user_id"], user["role"], action, allowed,
                         object_type, object_id, detail)

    # ============ 规则版本 ============
    def _seed_rules(self):
        for version, rule in rules.RULE_VERSIONS.items():
            exists = self.store.query_one(
                "SELECT 1 FROM rule_versions WHERE version=?", (version,))
            if not exists:
                self.store.execute(
                    "INSERT INTO rule_versions(version,note,published_by,published_at,supersedes,rules_json)"
                    " VALUES(?,?,?,?,?,?)",
                    (version, rule["note"], "seed",
                     "2026-09-22T08:00:00Z" if version.endswith("r1") else "2026-09-22T09:00:00Z",
                     rule.get("supersedes"),
                     json.dumps(rule, ensure_ascii=False)))

    def current_rule_version(self):
        row = self.store.query_one(
            "SELECT version FROM rule_versions ORDER BY published_at DESC, rowid DESC LIMIT 1")
        return row["version"] if row else rules.CURRENT_VERSION

    def get_rule(self, version):
        row = self.store.query_one(
            "SELECT * FROM rule_versions WHERE version=?", (version,))
        if row:
            return json.loads(row["rules_json"])
        return rules.get_rule(version)

    def publish_rule(self, user, version, rule_body, note, supersedes=None):
        """发布规则新版本：只影响此后产生的研判，旧研判保留旧版本。"""
        self.require(user, "rule.publish")
        if self.store.query_one("SELECT 1 FROM rule_versions WHERE version=?", (version,)):
            raise ApiError(409, "version_exists", f"规则版本 {version} 已存在，规则版本不可修改")
        for key in ("weights", "threat", "abuse_risk_gte"):
            if key not in rule_body:
                raise ApiError(400, "bad_rule", f"规则缺少字段 {key}")
        rule_body["version"] = version
        self.store.execute(
            "INSERT INTO rule_versions(version,note,published_by,published_at,supersedes,rules_json)"
            " VALUES(?,?,?,?,?,?)",
            (version, note, user["user_id"], utcnow(), supersedes,
             json.dumps(rule_body, ensure_ascii=False)))
        self.audit(user, "rule.publish", object_type="rule_version", object_id=version,
                   detail=note)
        return {"version": version, "note": note, "supersedes": supersedes,
                "published_at": utcnow()}

    # ============ 线索提交（四个入口） ============
    def submit_report(self, user, body):
        self.require(user, "report.submit")
        channel = body.get("channel")
        if channel not in self.role_channels[user["role"]]:
            raise ApiError(403, "channel_denied",
                           f"角色 {user['role']} 不能使用 {channel} 入口")
        subject_id = body.get("subject_id")
        if not subject_id:
            subject_id = ATHLETE_SUBJECT.get(user["user_id"], "s_lin")
        if not self.store.query_one("SELECT 1 FROM subjects WHERE id=?", (subject_id,)):
            raise ApiError(400, "unknown_subject", f"保护对象 {subject_id} 不存在")
        excerpt = body.get("excerpt")
        if not excerpt or not str(excerpt).strip():
            raise ApiError(400, "bad_report", "excerpt 为必填，线索必须包含可见内容摘录")
        scores = {}
        for f in SCORE_FIELDS:
            try:
                v = int(body.get(f))
            except (TypeError, ValueError):
                raise ApiError(400, "bad_score", f"{f} 必须为 1-5 的整数")
            if not 1 <= v <= 5:
                raise ApiError(400, "bad_score", f"{f} 必须为 1-5 的整数")
            scores[f] = v
        url = body.get("content_url")
        platform = body.get("platform")
        url_key = url if url else f"offline://{platform or 'unknown'}/{sha256_text(excerpt)[:24]}"
        content_hash = body.get("content_hash") or sha256_text(excerpt)
        claim_key = body.get("claim_key")
        fingerprint = sha256_text("|".join(
            [subject_id, url_key, content_hash, channel]))

        report_id = _new_id("rpt")
        try:
            self.store.execute(
                "INSERT INTO reports(id,received_at,channel,reporter_role,reporter_ref,"
                "subject_id,platform,content_url,url_key,excerpt,content_hash,category_hint,"
                "target_scope,spread_scope,credibility,urgency,claim_key,fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (report_id, utcnow(), channel, user["role"], user["user_id"],
                 subject_id, platform, url, url_key, excerpt, content_hash,
                 body.get("category_hint"), scores["target_scope"], scores["spread_scope"],
                 scores["credibility"], scores["urgency"], claim_key, fingerprint))
        except Exception as exc:  # 同 URL 重复举报
            if "UNIQUE" in str(exc):
                existing = self.store.query_one(
                    "SELECT * FROM reports WHERE url_key=?", (url_key,))
                # 重复举报只追加一条协作记录，绝不重算或覆盖原研判
                self.store.execute(
                    "INSERT INTO supplements(id,event_id,report_id,kind,submitted_by,"
                    "submitted_by_role,payload_json,received_at) VALUES(?,?,?,?,?,?,?,?)",
                    (_new_id("sup"),
                     self._event_of_report(existing["id"])["id"], existing["id"],
                     "repeat_report", user["user_id"], user["role"],
                     json.dumps({"note": "同源重复举报，沿用既有研判", "channel": channel},
                                ensure_ascii=False), utcnow()))
                self.audit(user, "report.duplicate", object_type="report",
                           object_id=existing["id"], detail="重复举报仅追加登记")
                return {"duplicate": True, "report_id": existing["id"],
                        "event_id": self._event_of_report(existing["id"])["id"],
                        "note": "重复举报已登记，未覆盖既有判断"}
            raise

        self.store.execute(
            "INSERT INTO report_status_log(report_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (report_id, "已接收", utcnow(), user["role"], f"经 {channel} 入口接收"))
        self.audit(user, "report.submit", object_type="report", object_id=report_id)

        # 1) 规则研判 —— 仅建议
        report_row = self.store.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
        result = rules.evaluate(report_row, self.get_rule(self.current_rule_version()))
        assessment_id = self._save_assessment(None, report_id, result)

        # 2) 同源聚合
        event = self._cluster(report_row, result)

        # 3) 证据保全（时间戳 + 内容哈希 + 链式回执）
        self._preserve_evidence(report_row, event["id"], user["role"], excerpt)

        # 4) 刷新事件级聚合建议
        merged_id = self._refresh_event_assessment(event["id"])
        return {"report_id": report_id, "event_id": event["id"],
                "advisory": {k: result[k] for k in
                             ("category", "category_text", "suggestions", "triggers",
                              "rationale", "rule_version")},
                "assessment_id": assessment_id, "event_assessment_id": merged_id,
                "reminder": "以上为自动建议，限制传播/联系保护对象/移送执法须人工确认"}

    def _save_assessment(self, event_id, report_id, result):
        aid = _new_id("asm")
        self.store.execute(
            "INSERT INTO assessments(id,event_id,report_id,rule_version,scores_json,"
            "category,suggestions_json,triggers_json,rationale,advisory,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, event_id, report_id, result["rule_version"],
             json.dumps(result["scores"], ensure_ascii=False), result["category"],
             json.dumps(result["suggestions"], ensure_ascii=False),
             json.dumps(result["triggers"], ensure_ascii=False),
             result["rationale"], 1, utcnow()))
        return aid

    def _cluster(self, report_row, result):
        """按对象 + 主张键/内容哈希聚合同源事件。"""
        sid = report_row["subject_id"]
        existing = self.store.query_one(
            "SELECT e.* FROM events e JOIN event_reports er ON er.event_id=e.id "
            "JOIN reports r ON r.id=er.report_id "
            "WHERE r.subject_id=? AND ((? IS NOT NULL AND r.claim_key=?) "
            "OR r.content_hash=?) LIMIT 1",
            (sid, report_row["claim_key"], report_row["claim_key"],
             report_row["content_hash"]))
        if existing:
            reason = "同主张键" if report_row["claim_key"] else "同内容哈希（跨平台同源）"
            self.store.execute(
                "INSERT OR IGNORE INTO event_reports(event_id,report_id,linked_at,link_reason)"
                " VALUES(?,?,?,?)",
                (existing["id"], report_row["id"], utcnow(), reason))
            return existing
        event_id = _new_id("evt")
        title = f"{sid} 网络侵害事件 · {result['category_text']}"
        self.store.execute(
            "INSERT INTO events(id,created_at,subject_id,title,cluster_key)"
            " VALUES(?,?,?,?,?)",
            (event_id, utcnow(), sid, title, _new_id("ck")))
        self.store.execute(
            "INSERT INTO event_reports(event_id,report_id,linked_at,link_reason)"
            " VALUES(?,?,?,?)",
            (event_id, report_row["id"], utcnow(), "首条线索建事件"))
        self.store.execute(
            "INSERT INTO event_status_log(event_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (event_id, "待核验", utcnow(), report_row["reporter_role"], "事件建立，等待人工核验"))
        return self.store.query_one("SELECT * FROM events WHERE id=?", (event_id,))

    def _preserve_evidence(self, report_row, event_id, source_role, snapshot,
                           note=None, supersedes_id=None):
        evidence_id = _new_id("evd")
        captured_at = utcnow()
        self.store.execute(
            "INSERT INTO evidences(id,report_id,event_id,url,snapshot,content_hash,"
            "captured_at,source_role,supersedes_id,note) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, report_row["id"], event_id, report_row["content_url"],
             snapshot, report_row["content_hash"], captured_at, source_role,
             supersedes_id, note))
        payload = {
            "evidence_id": evidence_id,
            "report_id": report_row["id"],
            "event_id": event_id,
            "url": report_row["content_url"],
            "content_hash": report_row["content_hash"],
            "captured_at": captured_at,
            "source_role": source_role,
            "snapshot": snapshot,
        }
        receipt = self.store.seal_receipt(_new_id("rcp"), evidence_id,
                                          f"system:{source_role}", payload)
        self.store.audit("system", source_role, "evidence.preserve", True,
                         "evidence", evidence_id, f"保全回执 {receipt['receipt_no']}")
        return evidence_id, receipt

    def _refresh_event_assessment(self, event_id):
        # 每条线索只取其最新一次研判（规则升级重算后，旧研判仍保留但不参与当前聚合）
        rows = self.store.query(
            "SELECT a.* FROM assessments a "
            "JOIN (SELECT MAX(rowid) AS maxrow FROM assessments "
            "WHERE report_id IS NOT NULL GROUP BY report_id) latest ON latest.maxrow=a.rowid "
            "JOIN event_reports er ON er.report_id=a.report_id "
            "WHERE er.event_id=? AND a.event_id IS NULL", (event_id,))
        results = [{
            "rule_version": r["rule_version"],
            "category": r["category"],
            "suggestions": json.loads(r["suggestions_json"]),
            "scores": json.loads(r["scores_json"]),
        } for r in rows]
        merged = rules.merge_assessments(results)
        merged_result = {
            "rule_version": self.current_rule_version(),
            "scores": {"dimensions": {"target_scope": 0, "spread_scope": merged["max_spread_scope"],
                                      "credibility": 0, "urgency": 0},
                       "risk_total": 0},
            "category": merged["category"],
            "category_text": merged["category_text"],
            "suggestions": merged["suggestions"],
            "suggestion_text": merged["suggestion_text"],
            "triggers": [f"聚合 {merged['report_count']} 条同源线索；"
                         f"涉及规则版本 {','.join(merged['rule_versions_in_event'])}"],
            "rationale": "事件级聚合建议（仅建议，不产生处置效力）",
            "advisory": True,
        }
        return self._save_assessment(event_id, None, merged_result)

    # ============ 人工决策 ============
    def decide(self, user, event_id, decision_type, rationale, action=None, override=False):
        perm = DECISION_PERM.get(decision_type)
        if not perm:
            raise ApiError(400, "bad_decision", f"未知决策类型 {decision_type}")
        self.require(user, perm)
        event = self._event_or_404(event_id)
        assessment = self.store.query_one(
            "SELECT * FROM assessments WHERE event_id=? ORDER BY rowid DESC LIMIT 1",
            (event_id,))
        if not assessment:
            raise ApiError(409, "no_assessment", "缺少研判建议，无法作出决定")
        suggestion_key = {
            "restrict": "advise_restrict",
            "protect_contact": "advise_protect_contact",
            "refer_law_enforcement": "consider_refer",
        }[decision_type]
        suggested = suggestion_key in json.loads(assessment["suggestions_json"])
        # 自动规则只是建议：人工可以采纳，也可以偏离，但偏离必须显式声明并写明理由。
        if not suggested and not override:
            raise ApiError(
                409, "suggestion_mismatch",
                "当前研判未建议该措施。人工可偏离建议，但须 override=true 并在 rationale 中说明理由")
        if override and not rationale:
            raise ApiError(400, "rationale_required", "偏离自动建议时必须填写人工理由")
        did = _new_id("dec")
        self.store.execute(
            "INSERT INTO decisions(id,event_id,decision_type,action,decided_by,"
            "decided_by_role,rule_version,assessment_id,rationale,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (did, event_id, decision_type, action or decision_type, user["user_id"],
             user["role"], assessment["rule_version"], assessment["id"],
             rationale, utcnow()))
        new_state = "保护处置中"
        self.store.execute(
            "INSERT INTO event_status_log(event_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (event_id, new_state, utcnow(), user["role"],
             f"{user['name']} 确认 {decision_type}，依据规则 {assessment['rule_version']}"))
        self.audit(user, f"decision.{decision_type}", object_type="decision",
                   object_id=did, detail=f"规则版本 {assessment['rule_version']}")
        return self._decision_view(did)

    def acknowledge_referral(self, user, decision_id, note=""):
        """执法联络员接收移送，出具接收回执（仅追加）。"""
        self.require(user, "receipt.confirm")
        decision = self.store.query_one("SELECT * FROM decisions WHERE id=?", (decision_id,))
        if not decision or decision["decision_type"] != "refer_law_enforcement":
            raise ApiError(404, "not_found", "移送决定不存在")
        if self.store.query_one(
                "SELECT 1 FROM decision_receipts WHERE decision_id=? AND receipt_kind='law_enforcement_receipt'",
                (decision_id,)):
            raise ApiError(409, "already_acknowledged", "已出具接收回执，不得重复或修改")
        rid = _new_id("drc")
        self.store.execute(
            "INSERT INTO decision_receipts(id,decision_id,receipt_kind,actor,actor_role,"
            "note,created_at) VALUES(?,?,?,?,?,?,?)",
            (rid, decision_id, "law_enforcement_receipt", user["user_id"], user["role"],
             note, utcnow()))
        self.audit(user, "receipt.confirm", object_type="decision", object_id=decision_id)
        return self._decision_view(decision_id)

    def reverse_decision(self, user, decision_id, rationale):
        """撤销/变更旧决定：新决定 supersedes 旧决定，旧行保留。"""
        self.require(user, "decision.restrict")  # 值班席统一复核
        old = self.store.query_one("SELECT * FROM decisions WHERE id=?", (decision_id,))
        if not old:
            raise ApiError(404, "not_found", "决定不存在")
        did = _new_id("dec")
        self.store.execute(
            "INSERT INTO decisions(id,event_id,decision_type,action,decided_by,"
            "decided_by_role,rule_version,assessment_id,rationale,created_at,"
            "supersedes_decision_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (did, old["event_id"], old["decision_type"], "reversed:" + old["action"],
             user["user_id"], user["role"], self.current_rule_version(),
             old["assessment_id"], rationale, utcnow(), decision_id))
        self.audit(user, "decision.reverse", object_type="decision", object_id=did,
                   detail=f"变更 {decision_id}，原决定保留")
        return self._decision_view(did)

    def _decision_view(self, did):
        d = self.store.query_one("SELECT * FROM decisions WHERE id=?", (did,))
        d["receipts"] = self.store.query(
            "SELECT * FROM decision_receipts WHERE decision_id=? ORDER BY rowid", (did,))
        return d

    # ============ 误报申诉 ============
    def submit_appeal(self, user, event_id, reason, report_id=None, decision_id=None):
        if not (self.can(user["role"], "appeal.submit.own") or
                self.can(user["role"], "case.read.linked")):
            raise ApiError(403, "forbidden", "该角色不能提交申诉")
        self._event_or_404(event_id)
        if not self._may_read_event(user, event_id):
            raise ApiError(403, "forbidden", "只能对与自己相关的案件申诉")
        current = self.store.query_one(
            "SELECT * FROM assessments WHERE event_id=? ORDER BY rowid DESC LIMIT 1",
            (event_id,))
        aid = _new_id("apl")
        self.store.execute(
            "INSERT INTO appeals(id,event_id,report_id,decision_id,submitted_by,"
            "submitter_role,reason,created_at,preserved_assessment_id)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (aid, event_id, report_id, decision_id, user["user_id"], user["role"],
             reason, utcnow(), current["id"] if current else None))
        self.store.execute(
            "INSERT INTO event_status_log(event_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (event_id, "待申诉", utcnow(), user["role"], "收到误报申诉，等待复核"))
        self.audit(user, "appeal.submit", object_type="appeal", object_id=aid)
        return {"appeal_id": aid, "preserved_assessment_id":
                current["id"] if current else None,
                "note": "申诉时的研判已固化，复核不会覆盖旧判断"}

    def resolve_appeal(self, user, appeal_id, resolution, note, reevaluate=False):
        self.require(user, "appeal.review")
        appeal = self.store.query_one("SELECT * FROM appeals WHERE id=?", (appeal_id,))
        if not appeal:
            raise ApiError(404, "not_found", "申诉不存在")
        if self.store.query_one(
                "SELECT 1 FROM appeal_resolutions WHERE appeal_id=?", (appeal_id,)):
            raise ApiError(409, "already_resolved", "该申诉已有复核结论，结论仅追加不可修改")
        if resolution not in ("upheld", "rejected"):
            raise ApiError(400, "bad_resolution", "resolution 须为 upheld/rejected")
        new_assessment_id = None
        used_version = self.current_rule_version()
        if reevaluate:
            # 规则升级后的重新研判：产生新 assessment，旧 assessment 原样保留
            event_id = appeal["event_id"]
            report_rows = self.store.query(
                "SELECT r.* FROM reports r JOIN event_reports er ON er.report_id=r.id "
                "WHERE er.event_id=?", (event_id,))
            for r in report_rows:
                result = rules.evaluate(r, self.get_rule(used_version))
                self._save_assessment(None, r["id"], result)
            new_assessment_id = self._refresh_event_assessment(event_id)
        rid = _new_id("apr")
        self.store.execute(
            "INSERT INTO appeal_resolutions(id,appeal_id,resolution,reviewed_by,"
            "reviewer_role,review_note,reviewed_rule_version,reviewed_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (rid, appeal_id, resolution, user["user_id"], user["role"], note,
             used_version, utcnow()))
        self.audit(user, "appeal.resolve", object_type="appeal_resolution", object_id=rid,
                   detail=f"{resolution}，规则 {used_version}，新研判 {new_assessment_id}")
        return {"resolution_id": rid, "resolution": resolution,
                "reviewed_rule_version": used_version,
                "new_assessment_id": new_assessment_id,
                "preserved_assessment_id": appeal["preserved_assessment_id"],
                "note": "原研判与原决定均未被覆盖；如采纳申诉，请另作人工变更决定"}

    # ============ 跨平台/执法补件 ============
    def add_supplement(self, user, event_id, kind, payload, report_id=None):
        allowed_kinds = {
            "platform": ("platform_status", "cross_platform_evidence"),
            "police": ("police_update", "cross_platform_evidence"),
            "duty": ("platform_status", "cross_platform_evidence", "police_update", "misc"),
        }
        if user["role"] != "duty":
            self.require(user, "supplement.submit")
        if user["role"] not in allowed_kinds or kind not in allowed_kinds[user["role"]]:
            raise ApiError(403, "forbidden", f"角色 {user['role']} 不能提交 {kind} 补件")
        self._event_or_404(event_id)
        # 平台协查员可对任何已知案件补件（跨平台协作的前提）；
        # 执法联络员仅限已移送或自己报送的案件。
        if user["role"] == "police" and not self._may_read_event(user, event_id):
            raise ApiError(403, "forbidden", "只能对已移送或自己报送的案件补件")
        sid = _new_id("sup")
        self.store.execute(
            "INSERT INTO supplements(id,event_id,report_id,kind,submitted_by,"
            "submitted_by_role,payload_json,received_at) VALUES(?,?,?,?,?,?,?,?)",
            (sid, event_id, report_id, kind, user["user_id"], user["role"],
             json.dumps(payload, ensure_ascii=False), utcnow()))
        evidence = None
        # 补件带来的新快照同样保全，旧证据不受影响（supersedes 仅作关联指针）
        if payload.get("snapshot"):
            target_report_id = report_id or self.store.query_one(
                "SELECT report_id FROM event_reports WHERE event_id=? ORDER BY rowid LIMIT 1",
                (event_id,))["report_id"]
            report_row = self.store.query_one(
                "SELECT * FROM reports WHERE id=?", (target_report_id,))
            snapshot = payload["snapshot"]
            report_row = dict(report_row)
            report_row["content_hash"] = payload.get("content_hash") or sha256_text(snapshot)
            report_row["content_url"] = payload.get("content_url", report_row["content_url"])
            _, receipt = self._preserve_evidence(
                report_row, event_id, user["role"], snapshot,
                note=f"补件保全：{kind}", supersedes_id=None)
            evidence = {"receipt_no": receipt["receipt_no"],
                        "chain_hash": receipt["chain_hash"],
                        "captured_at": receipt["captured_at"]}
        self.audit(user, "supplement.submit", object_type="supplement", object_id=sid)
        return {"supplement_id": sid, "kind": kind, "evidence": evidence}

    def update_platform_status(self, user, report_id, status, action_detail=""):
        self.require(user, "report.platform_status")
        report = self.store.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
        if not report:
            raise ApiError(404, "not_found", "线索不存在")
        self.store.execute(
            "INSERT INTO report_status_log(report_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (report_id, status, utcnow(), user["role"],
             f"平台回传：{action_detail}"))
        self.audit(user, "report.platform_status", object_type="report",
                   object_id=report_id, detail=status)
        return {"report_id": report_id, "status": status}

    # ============ 值班席案件视图 ============
    def _event_or_404(self, event_id):
        event = self.store.query_one("SELECT * FROM events WHERE id=?", (event_id,))
        if not event:
            raise ApiError(404, "not_found", "事件不存在")
        return event

    def _event_of_report(self, report_id):
        row = self.store.query_one(
            "SELECT e.* FROM events e JOIN event_reports er ON er.event_id=e.id "
            "WHERE er.report_id=?", (report_id,))
        return row

    def _may_read_event(self, user, event_id):
        role = user["role"]
        if role == "duty":
            return True
        if role == "athlete":
            bound = ATHLETE_SUBJECT.get(user["user_id"])
            event = self.store.query_one("SELECT * FROM events WHERE id=?", (event_id,))
            return bool(event and bound and event["subject_id"] == bound)
        if role in ("club", "platform"):
            return bool(self.store.query_one(
                "SELECT 1 FROM event_reports er JOIN reports r ON r.id=er.report_id "
                "WHERE er.event_id=? AND r.reporter_ref=?", (event_id, user["user_id"])))
        if role == "police":
            return bool(self.store.query_one(
                "SELECT 1 FROM decisions WHERE event_id=? AND decision_type='refer_law_enforcement'",
                (event_id,))) or bool(self.store.query_one(
                "SELECT 1 FROM event_reports er JOIN reports r ON r.id=er.report_id "
                "WHERE er.event_id=? AND r.reporter_ref=?", (event_id, user["user_id"])))
        return False

    def case_view(self, user, event_id):
        event = self._event_or_404(event_id)
        read_perm = {"duty": "case.read", "athlete": "case.read.own",
                     "club": "case.read.linked", "platform": "case.read.linked",
                     "police": "case.read.referred"}[user["role"]]
        self.require(user, read_perm)
        if not self._may_read_event(user, event_id):
            self.audit(user, "case.read", False, "event", event_id, "越权访问被拒")
            raise ApiError(403, "forbidden", "无权查看该案件（执法联络员仅可见已移送案件）")
        self.audit(user, "case.read", object_type="event", object_id=event_id)

        reports = self.store.query(
            "SELECT id,received_at,channel,reporter_role,platform,content_url,"
            "content_hash,excerpt,category_hint,target_scope,spread_scope,credibility,"
            "urgency FROM reports r JOIN event_reports er ON er.report_id=r.id "
            "WHERE er.event_id=? ORDER BY r.rowid", (event_id,))
        # 每条线索的“最新+原始”研判，直观呈现规则升级前后的差异
        for r in reports:
            r["assessments"] = self.store.query(
                "SELECT id,rule_version,category,suggestions_json,triggers_json,"
                "rationale,created_at FROM assessments WHERE report_id=? ORDER BY rowid",
                (r["id"],))

        evidences = self.store.query(
            "SELECT id,report_id,url,content_hash,captured_at,source_role,"
            "supersedes_id,note FROM evidences WHERE event_id=? ORDER BY rowid",
            (event_id,))
        receipts = self.store.query(
            "SELECT rc.receipt_no,rc.evidence_id,rc.captured_at,rc.content_hash,"
            "rc.prev_hash,rc.chain_hash,rc.sealed_by FROM receipts rc "
            "JOIN evidences e ON e.id=rc.evidence_id WHERE e.event_id=? ORDER BY rc.rowid",
            (event_id,))
        if evidences:
            self.audit(user, "evidence.read", object_type="event", object_id=event_id,
                       detail=f"接触 {len(evidences)} 份证据")

        assessments = self.store.query(
            "SELECT id,event_id,report_id,rule_version,category,suggestions_json,"
            "triggers_json,rationale,created_at FROM assessments WHERE event_id=? "
            "ORDER BY rowid", (event_id,))
        decisions = [self._decision_view(d["id"]) for d in self.store.query(
            "SELECT id FROM decisions WHERE event_id=? ORDER BY rowid", (event_id,))]
        appeals = self.store.query(
            "SELECT * FROM appeals WHERE event_id=? ORDER BY rowid", (event_id,))
        for a in appeals:
            a["resolutions"] = self.store.query(
                "SELECT * FROM appeal_resolutions WHERE appeal_id=? ORDER BY rowid", (a["id"],))
        supplements = self.store.query(
            "SELECT id,report_id,kind,submitted_by_role,payload_json,received_at "
            "FROM supplements WHERE event_id=? ORDER BY rowid", (event_id,))
        status_log = self.store.query(
            "SELECT status,at,by_role,note FROM event_status_log WHERE event_id=? "
            "ORDER BY rowid", (event_id,))
        chain = self.store.verify_chain()

        opinion_items, action_items = [], []
        for r in reports:
            latest = r["assessments"][-1] if r["assessments"] else None
            bucket = opinion_items if (latest and latest["category"] == "opinion") else action_items
            bucket.append({"report_id": r["id"], "excerpt": r["excerpt"],
                           "category": latest["category"] if latest else None,
                           "rule_version": latest["rule_version"] if latest else None,
                           "triggers": json.loads(latest["triggers_json"]) if latest else []})

        return {
            "event": {k: event[k] for k in ("id", "title", "subject_id", "created_at")},
            "state": status_log[-1]["status"] if status_log else "待核验",
            "state_timeline": status_log,
            "viewpoint_vs_action": {
                "opinion_only": opinion_items,
                "protection_triggered": action_items,
                "note": "opinion_only 为观点/正常批评，不触发限制或保护；"
                        "protection_triggered 的具体触发行为见各条 triggers"},
            "reports": reports,
            "evidence": {"items": evidences, "receipts": receipts,
                         "chain_verification": chain,
                         "note": "原始链接失效时，可凭 captured_at、content_hash 与链式回执证明当时所见"},
            "assessments_timeline": assessments,
            "decisions": decisions,
            "appeals": appeals,
            "supplements": supplements,
            "contacts_included": False,
            "contacts_note": "报案人联系方式与未公开身份材料存于独立保封库，本视图不含；"
                             "调阅记录见 /contacts/ledger",
        }

    def set_event_state(self, user, event_id, state, note=""):
        self.require(user, "case.read")
        if state not in VALID_STATES:
            raise ApiError(400, "bad_state", f"状态须为 {VALID_STATES}")
        self._event_or_404(event_id)
        self.store.execute(
            "INSERT INTO event_status_log(event_id,status,at,by_role,note)"
            " VALUES(?,?,?,?,?)",
            (event_id, state, utcnow(), user["role"], note))
        self.audit(user, "event.state", object_type="event", object_id=event_id, detail=state)
        return {"event_id": event_id, "state": state}

    # ============ 联系方式保封库 ============
    def read_contacts(self, user, subject_id, purpose):
        purpose = (purpose or "").strip()
        # 无权限者的接触尝试同样写入保封库台账（拒绝记录），再拒绝。
        if not self.can(user["role"], "case.contact.read"):
            self.vault.access(user["user_id"], user["role"], subject_id or "?",
                              purpose or "未填事由", False)
            self.store.audit(user["user_id"], user["role"], "contact.read", False,
                             "subject", subject_id, "越权调阅联系方式被拒")
            raise ApiError(403, "forbidden", "联系方式与未公开身份材料仅限授权值班员调阅")
        if not purpose:
            raise ApiError(400, "purpose_required", "调阅联系方式必须说明事由，以便留痕")
        row = self.vault.access(user["user_id"], user["role"], subject_id, purpose, True)
        self.store.audit(user["user_id"], user["role"], "contact.read", True,
                         "subject", subject_id, purpose)
        if not row:
            raise ApiError(404, "not_found", "无该保护对象的封存联系方式")
        return {"subject_id": subject_id,
                "contact_detail": row["contact_detail"],
                "identity_material": row["identity_material"],
                "accessed_at": row["updated_at"]}

    def contact_ledger(self, user):
        self.require(user, "audit.read")
        return {"contact_access": self.vault.access_ledger(),
                "case_audit": self.store.query(
                    "SELECT ts,actor,role,action,object_type,object_id,allowed,detail "
                    "FROM audit_log ORDER BY id")}

    # ============ 审计与链校验 ============
    def audit_trail(self, user):
        self.require(user, "audit.read")
        return self.store.query(
            "SELECT ts,actor,role,action,object_type,object_id,allowed,detail "
            "FROM audit_log ORDER BY id")

    def verify_evidence_chain(self, user=None):
        return self.store.verify_chain()

    def list_events(self, user):
        read_perm = {"duty": "case.read", "athlete": "case.read.own",
                     "club": "case.read.linked", "platform": "case.read.linked",
                     "police": "case.read.referred"}[user["role"]]
        self.require(user, read_perm)
        if user["role"] == "duty":
            rows = self.store.query("SELECT * FROM events ORDER BY rowid")
        elif user["role"] == "police":
            rows = self.store.query(
                "SELECT DISTINCT e.* FROM events e "
                "LEFT JOIN decisions d ON d.event_id=e.id AND d.decision_type='refer_law_enforcement' "
                "LEFT JOIN event_reports er ON er.event_id=e.id "
                "LEFT JOIN reports r ON r.id=er.report_id AND r.reporter_ref=? "
                "WHERE d.id IS NOT NULL OR r.id IS NOT NULL ORDER BY e.rowid",
                (user["user_id"],))
        else:
            rows = self.store.query(
                "SELECT DISTINCT e.* FROM events e JOIN event_reports er ON er.event_id=e.id "
                "JOIN reports r ON r.id=er.report_id WHERE r.reporter_ref=? ORDER BY e.rowid",
                (user["user_id"],))
        return [{"id": r["id"], "title": r["title"], "subject_id": r["subject_id"]}
                for r in rows]
