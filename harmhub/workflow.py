"""处置工作流：多入口线索归集、同源聚合、人工确认、申诉复核与案件视图。

所有历史均为追加式（append-only）：
- evaluations：每次自动评估一条，永久保留其规则版本；
- decisions：每次人工决定一条，记录采纳/超建议/申诉复核及规则版本；
- appeals：申诉与复核结论独立留存，不改写原始判断；
- evidence：补件/重新取证只新增，旧保全不动。
"""

from .errors import ApiError
from .evidence import EvidenceService, canonical_text
from .rules import RuleEngine
from .security import Vault
from .storage import Store
from .util import new_id, sha256_hex, utcnow

SEED_RULE_VERSION = "rules-2026.09.0"
SEED_RULE_NOTES = "初版：按对象、传播范围、可信度、紧迫程度四维评估，仅输出风险建议。"

DUTY = "协会值班员"
POLICE = "执法联络员"


class Hub:
    def __init__(self, data_dir):
        self.store = Store(data_dir)
        self.vault = Vault(data_dir)
        self.evidence = EvidenceService(self.store, data_dir)
        self.rules = RuleEngine(self.store)
        self.rules.ensure_seed(SEED_RULE_VERSION, SEED_RULE_NOTES)

    # ================= 身份与入口 =================
    def bootstrap_identities(self):
        """初始化各入口令牌（每个保护对象独立令牌以隔离互视）。明文仅此一次返回。"""
        from .util import new_token

        if self.store.state["tokens"]:
            return None
        seeds = [
            ("self:lirui", "保护对象", "self", "李锐（保护对象）"),
            ("self:zhoulan", "保护对象", "self", "周岚（保护对象）"),
            ("club:zhangyun", "俱乐部联络员", "club", "张云（俱乐部联络员）"),
            ("platform:wangning", "平台协查员", "platform", "王宁（平台协查员）"),
            ("duty:chenchen", DUTY, "duty", "陈晨（协会值班员）"),
            ("police:zhaojing", POLICE, "police", "赵静（公安联络员）"),
        ]
        plain = []
        for sub, actor, channel, label in seeds:
            token = new_token()
            self.store.state["tokens"][sha256_hex(token)] = {
                "sub": sub,
                "actor": actor,
                "channel": channel,
                "label": label,
                "created_at": utcnow(),
            }
            plain.append({"token": token, "sub": sub, "actor": actor, "label": label})
        self.store.audit("system", "入口令牌初始化", detail={"count": len(plain)})
        self.store.save()
        return plain

    def authenticate(self, token):
        if not token:
            raise ApiError(401, "缺少入口令牌")
        identity = self.store.state["tokens"].get(sha256_hex(token))
        if not identity:
            raise ApiError(401, "入口令牌无效")
        return identity

    # ================= 线索提交 =================
    def submit_lead(self, identity, payload, incident_id=None):
        self._require_fields(payload, ["target", "url", "content"])
        target = str(payload["target"]).strip()
        if not target:
            raise ApiError(400, "被侵害对象不能为空")

        channel = identity["channel"]
        platform = payload.get("platform") or self._guess_platform(payload["url"], channel)

        # 1) 证据保全（原始内容留存 + 哈希 + 时间戳 + 链式回执）
        record = self.evidence.preserve(
            url=payload["url"],
            content=payload["content"],
            content_type=payload.get("content_type", "text"),
            captured_by=identity["label"],
            platform=platform,
            note=payload.get("note"),
            observed_at=payload.get("observed_at"),
        )

        lead = {
            "id": new_id("lead"),
            "reporter_sub": identity["sub"],
            "reporter_actor": identity["actor"],
            "reporter_label": identity["label"],
            "channel": channel,
            "platform": platform,
            "url": payload["url"],
            "target": target,
            "content": record["blob"] and self._read_blob(record["id"]),
            "reach": int(payload.get("reach", 0) or 0),
            "credibility_hint": int(payload.get("credibility_hint", 0) or 0),
            "hours_since_posted": payload.get("hours_since_posted"),
            "explicit_location": bool(payload.get("explicit_location")),
            "category_hints": payload.get("category_hints", []),
            "observed_at": payload.get("observed_at"),
            "evidence_id": record["id"],
            "incident_id": None,
            "is_duplicate_of": None,
            "created_at": utcnow(),
        }

        # 2) 敏感材料进加密保管箱，研判区只留元信息
        secret = {
            "contact_name": payload.get("contact_name"),
            "contact_phone": payload.get("contact_phone"),
            "contact_note": payload.get("contact_note"),
            "private_materials": payload.get("private_materials", []),
            "submitted_via": channel,
        }
        if any(secret[k] for k in ("contact_name", "contact_phone", "contact_note")) or secret["private_materials"]:
            self.vault.put_lead_secret(lead["id"], secret)
            lead["pii"] = {
                "has_contact": bool(secret["contact_name"] or secret["contact_phone"]),
                "private_material_count": len(secret["private_materials"]),
            }
        else:
            lead["pii"] = {"has_contact": False, "private_material_count": 0}

        with self.store.lock:
            # 3) 同源判定：指定补件 / 精确重复 / 模糊同源 / 新建
            if incident_id:
                incident = self._get_incident(incident_id)
                self._require_incident_access(identity, incident)
                mode = self._attach(incident, lead, explicit=True)
            else:
                incident, mode = self._match_or_create(identity, lead)

            self.store.audit(
                identity["label"],
                {
                    "new": "提报新线索",
                    "duplicate": "重复举报归并",
                    "cross_platform": "跨平台补件归并",
                    "explicit": "补件归并",
                    "corroboration": "同源佐证归并",
                }[mode],
                target=incident["id"],
                detail={"lead_id": lead["id"], "url": lead["url"], "mode": mode},
            )

            # 4) 除精确重复外，追加一次聚合评估（旧评估原样保留）
            if mode != "duplicate":
                self._append_evaluation(incident, trigger=mode, actor=identity["label"])
            else:
                incident["duplicate_count"] = incident.get("duplicate_count", 0) + 1

            self.store.save()
            return {
                "lead_id": lead["id"],
                "incident_id": incident["id"],
                "merge_mode": mode,
                "evidence_receipt": self._receipt_summary(record),
                "incident_status": incident["status"],
                "latest_risk_level": incident["risk_level"],
            }

    def _attach(self, incident, lead, explicit):
        same_url = any(lid and self._lead(lid)["url"] == lead["url"] for lid in incident["lead_ids"])
        existing_platforms = {self._lead(lid)["platform"] for lid in incident["lead_ids"]}
        if same_url:
            mode = "duplicate"
            earlier = next(self._lead(lid) for lid in incident["lead_ids"] if self._lead(lid)["url"] == lead["url"])
            lead["is_duplicate_of"] = earlier["id"]
        elif lead["platform"] not in existing_platforms:
            mode = "cross_platform" if not explicit else "explicit"
        else:
            mode = "corroboration" if not explicit else "explicit"
        self._store_lead(incident, lead)
        return mode

    def _match_or_create(self, identity, lead):
        best = None
        best_score = 0.0
        best_kind = None
        for incident in self.store.state["incidents"].values():
            if not self._same_target(incident, lead):
                continue
            score, kind = self._similarity(incident, lead)
            if score > best_score:
                best_score, best, best_kind = score, incident, kind
        if best is not None and best_score >= 0.42:
            existing_platforms = {self._lead(lid)["platform"] for lid in best["lead_ids"]}
            if best_kind == "url":
                mode = "duplicate"
                lead["is_duplicate_of"] = next(
                    lid for lid in best["lead_ids"] if self._lead(lid)["url"] == lead["url"]
                )
            elif best_kind == "cross" or lead["platform"] not in existing_platforms:
                mode = "cross_platform"
            else:
                mode = "corroboration"
            self._store_lead(best, lead)
            return best, mode

        incident = {
            "id": new_id("inc"),
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "status": "已接收",
            "targets": [lead["target"]],
            "lead_ids": [],
            "evidence_ids": [],
            "evaluations": [],
            "decisions": [],
            "appeals": [],
            "actions": {},
            "risk_level": "待评估",
            "duplicate_count": 0,
            "created_by": identity["label"],
        }
        self._store_lead(incident, lead)
        self.store.state["incidents"][incident["id"]] = incident
        self._transition(incident, "待核验", reason="线索已保全并完成自动评估")
        return incident, "new"

    def _store_lead(self, incident, lead):
        lead["incident_id"] = incident["id"]
        self.store.state.setdefault("leads", {})[lead["id"]] = lead
        incident["lead_ids"].append(lead["id"])
        if lead["evidence_id"] not in incident["evidence_ids"]:
            incident["evidence_ids"].append(lead["evidence_id"])
        if lead["target"] not in incident["targets"]:
            incident["targets"].append(lead["target"])
        incident["updated_at"] = utcnow()

    # ================= 聚合评估 =================
    def _append_evaluation(self, incident, trigger, actor):
        leads = [self._lead(lid) for lid in incident["lead_ids"] if self._lead(lid)["is_duplicate_of"] is None]
        if not leads:
            leads = [self._lead(lid) for lid in incident["lead_ids"]]
        aggregate = {
            "channel": leads[0]["channel"],
            "content": "\n---\n".join(l["content"] for l in leads),
            "reach": max(l["reach"] for l in leads),
            "credibility_hint": max(l["credibility_hint"] for l in leads),
            "hours_since_posted": min(
                (l["hours_since_posted"] for l in leads if l["hours_since_posted"] is not None),
                default=None,
            ),
            "explicit_location": any(l["explicit_location"] for l in leads),
            "category_hints": [h for l in leads for h in l["category_hints"]],
        }
        version = self.rules.current_version()
        suggestion = self.rules.evaluate(aggregate, version)
        suggestion["trigger"] = trigger
        suggestion["evaluated_lead_ids"] = [l["id"] for l in leads]
        suggestion["generated_by"] = actor
        if incident["evaluations"]:
            suggestion["supersedes"] = incident["evaluations"][-1]["id"]
        incident["evaluations"].append(suggestion)
        incident["risk_level"] = suggestion["risk_level"]
        return suggestion

    def reevaluate(self, identity, incident_id):
        self._require_role(identity, DUTY)
        incident = self._get_incident(incident_id)
        with self.store.lock:
            suggestion = self._append_evaluation(incident, trigger="manual_reevaluate", actor=identity["label"])
            self.store.audit(
                identity["label"],
                "按新规则版本重新评估",
                target=incident["id"],
                detail={"new_suggestion": suggestion["id"], "rule_version": suggestion["rule_version"]},
                rule_version=suggestion["rule_version"],
            )
            self.store.save()
        return suggestion

    # ================= 人工确认（保护措施） =================
    ACTION_KEY = {"限制传播": "restrict", "联系保护对象": "contact", "移送执法": "refer_police"}

    def confirm_action(self, identity, incident_id, payload):
        self._require_fields(payload, ["action"])
        action = payload["action"]
        contract = self._contract()
        if action not in contract["protected_actions"]:
            raise ApiError(400, f"未知保护措施：{action}")
        allowed = contract["protected_actions"][action]
        if identity["actor"] not in allowed:
            raise ApiError(403, f"{identity['actor']}无权确认「{action}」，需：{'/'.join(allowed)}")

        incident = self._get_incident(incident_id)
        with self.store.lock:
            key = self.ACTION_KEY[action]
            current = incident["actions"].get(key)
            if current and current.get("state") == "已确认":
                raise ApiError(409, f"「{action}」已确认并在执行中；历史决定不可覆盖，如情形变化请发起新决定")

            latest = incident["evaluations"][-1] if incident["evaluations"] else None
            suggested = latest and action in latest["suggested_actions"]
            reason = payload.get("reason")
            if not suggested and not reason:
                raise ApiError(400, "自动规则未建议该措施；人工超建议决定必须填写理由")
            basis = "采纳自动建议" if suggested else "人工研判（超出自动建议）"
            rule_version = self.rules.current_version()

            decision = {
                "id": new_id("dec"),
                "at": utcnow(),
                "actor": identity["label"],
                "actor_role": identity["actor"],
                "action": action,
                "approved": True,
                "basis": basis,
                "reason": reason,
                "linked_suggestion": latest["id"] if latest else None,
                "linked_suggestion_version": latest["rule_version"] if latest else None,
                "rule_version": rule_version,
                "kind": "保护措施确认",
            }
            incident["decisions"].append(decision)
            incident["actions"][key] = {
                "state": "已确认",
                "decision_id": decision["id"],
                "confirmed_at": decision["at"],
                "confirmed_by": identity["label"],
                "rule_version": rule_version,
            }
            if incident["status"] != "保护处置中":
                self._transition(incident, "保护处置中", reason=f"确认{action}")
            self.store.audit(
                identity["label"],
                f"确认保护措施：{action}",
                target=incident["id"],
                detail={"decision_id": decision["id"], "basis": basis},
                rule_version=rule_version,
            )
            self.store.save()
            return decision

    # ================= 误报申诉（不覆盖旧判断） =================
    def appeal(self, identity, incident_id, payload):
        self._require_fields(payload, ["reason"])
        incident = self._get_incident(incident_id)
        self._require_incident_access(identity, incident)
        with self.store.lock:
            entry = {
                "id": new_id("apl"),
                "at": utcnow(),
                "by": identity["label"],
                "by_role": identity["actor"],
                "reason": payload["reason"],
                "status": "待复核",
                "resolution": None,
            }
            incident["appeals"].append(entry)
            if incident["status"] != "待申诉":
                self._transition(incident, "待申诉", reason="收到误报申诉")
            self.store.audit(identity["label"], "提交误报申诉", target=incident["id"], detail={"appeal_id": entry["id"]})
            self.store.save()
            return entry

    def review_appeal(self, identity, incident_id, appeal_id, payload):
        self._require_role(identity, DUTY)
        self._require_fields(payload, ["uphold"])
        incident = self._get_incident(incident_id)
        entry = next((a for a in incident["appeals"] if a["id"] == appeal_id), None)
        if entry is None:
            raise ApiError(404, "申诉不存在")
        if entry["status"] != "待复核":
            raise ApiError(409, "该申诉已复核，结论不可覆盖")
        with self.store.lock:
            rule_version = self.rules.current_version()
            uphold = bool(payload["uphold"])
            resolution = {
                "reviewed_at": utcnow(),
                "reviewed_by": identity["label"],
                "verdict": "维持原判断" if uphold else "申诉成立",
                "note": payload.get("note", ""),
                "rule_version": rule_version,
            }
            entry["status"] = "已复核"
            entry["resolution"] = resolution
            decision = {
                "id": new_id("dec"),
                "at": resolution["reviewed_at"],
                "actor": identity["label"],
                "actor_role": identity["actor"],
                "action": "申诉复核",
                "approved": uphold,
                "basis": "维持原判断" if uphold else "申诉成立，调整措施",
                "reason": payload.get("note", ""),
                "linked_appeal": entry["id"],
                "rule_version": rule_version,
                "kind": "申诉复核",
            }
            if not uphold:
                # 只追加撤销决定，不删除原先的确认记录
                for key, action in (
                    ("restrict", "限制传播"),
                    ("contact", "联系保护对象"),
                    ("refer_police", "移送执法"),
                ):
                    current = incident["actions"].get(key)
                    if current and current.get("state") == "已确认":
                        revoke = {
                            "id": new_id("dec"),
                            "at": utcnow(),
                            "actor": identity["label"],
                            "actor_role": identity["actor"],
                            "action": f"撤销{action}",
                            "approved": True,
                            "basis": "申诉成立，撤销措施（原确认记录保留）",
                            "reason": payload.get("note", ""),
                            "linked_appeal": entry["id"],
                            "rule_version": rule_version,
                            "kind": "措施撤销",
                        }
                        incident["decisions"].append(revoke)
                        current["state"] = "已撤销（申诉成立）"
                        current["revoke_decision_id"] = revoke["id"]
                        current["revoked_at"] = revoke["at"]
            incident["decisions"].append(decision)
            active = any(a.get("state") == "已确认" for a in incident["actions"].values())
            self._transition(incident, "保护处置中" if active else "待核验", reason="申诉复核完成")
            self.store.audit(
                identity["label"],
                "复核误报申诉",
                target=incident["id"],
                detail={"appeal_id": entry["id"], "verdict": resolution["verdict"]},
                rule_version=rule_version,
            )
            self.store.save()
            return entry

    # ================= 规则升级（旧判断冻结） =================
    def upgrade_rules(self, identity, payload):
        self._require_role(identity, DUTY)
        self._require_fields(payload, ["version", "notes"])
        try:
            meta = self.rules.upgrade(payload["version"], payload["notes"], identity["label"])
        except ValueError as error:
            raise ApiError(409, str(error))
        return meta

    # ================= 查询与案件视图 =================
    def list_incidents(self, identity):
        items = []
        for incident in self.store.state["incidents"].values():
            if not self._can_see_incident(identity, incident):
                continue
            items.append(
                {
                    "id": incident["id"],
                    "status": incident["status"],
                    "targets": incident["targets"],
                    "risk_level": incident["risk_level"],
                    "lead_count": len(incident["lead_ids"]),
                    "platforms": sorted({self._lead(lid)["platform"] for lid in incident["lead_ids"]}),
                    "active_actions": [
                        a for a, v in zip(
                            ("限制传播", "联系保护对象", "移送执法"),
                            ("restrict", "contact", "refer_police"),
                        )
                        if incident["actions"].get(v, {}).get("state") == "已确认"
                    ],
                    "updated_at": incident["updated_at"],
                }
            )
        return sorted(items, key=lambda x: x["updated_at"], reverse=True)

    def incident_detail(self, identity, incident_id):
        incident = self._get_incident(incident_id)
        self._require_incident_access(identity, incident)
        return self._incident_view(incident, include_pii=False)

    def case_dossier(self, identity, incident_id):
        """值班席案件总览：观点/触发保护的行为/证据接触链/每决定的规则版本。"""
        self._require_role(identity, DUTY)
        incident = self._get_incident(incident_id)
        view = self._incident_view(incident, include_pii=False)

        opinion, actionable = [], []
        for lid in incident["lead_ids"]:
            lead = self._lead(lid)
            cats = self.rules.classify_content(lead["content"], lead["category_hints"])
            row = {
                "lead_id": lid,
                "platform": lead["platform"],
                "url": lead["url"],
                "categories": cats,
                "duplicate_of": lead["is_duplicate_of"],
                "evidence_id": lead["evidence_id"],
                "reporter_channel": lead["channel"],
            }
            (opinion if cats == ["观点"] else actionable).append(row)

        protections = []
        for key, label in (("restrict", "限制传播"), ("contact", "联系保护对象"), ("refer_police", "移送执法")):
            cur = incident["actions"].get(key)
            if cur:
                protections.append({"action": label, **cur})

        chain_ok, broken = self.evidence.verify_chain()
        evidence_rows = []
        for ev_id in incident["evidence_ids"]:
            ev = self.evidence.get(ev_id)
            evidence_rows.append(self._receipt_summary(ev))

        access_log = [
            {
                "at": e["at"],
                "actor": e["actor"],
                "action": e["action"],
                "lead_id": e.get("detail", {}).get("lead_id"),
                "purpose": e.get("detail", {}).get("purpose"),
            }
            for e in self.store.state["audit"]
            if e["action"] in ("证据保全", "接触证据", "接触敏感材料")
            and (
                e["target"] in incident["evidence_ids"]
                or e.get("detail", {}).get("lead_id") in incident["lead_ids"]
                or e["target"] == incident["id"]
            )
        ]

        return {
            "case_id": incident["id"],
            "generated_at": utcnow(),
            "duty_officer": identity["label"],
            "summary": view,
            "opinion_content": opinion,
            "actionable_content": actionable,
            "protections": protections,
            "evidence": evidence_rows,
            "evidence_chain_ok": chain_ok,
            "evidence_chain_broken_at": broken,
            "evidence_and_pii_access": access_log,
            "pii_access_register": [
                row for row in self.store.state["pii_access"] if row["incident_id"] == incident["id"]
            ],
            "decisions": incident["decisions"],
            "appeals": incident["appeals"],
            "evaluation_history": [
                {
                    "suggestion_id": s["id"],
                    "at": s["at"],
                    "rule_version": s["rule_version"],
                    "risk_level": s["risk_level"],
                    "categories": s["categories"],
                    "suggested_actions": s["suggested_actions"],
                    "trigger": s["trigger"],
                    "supersedes": s.get("supersedes"),
                    "generated_by": s.get("generated_by"),
                }
                for s in incident["evaluations"]
            ],
        }

    def read_evidence_content(self, identity, incident_id, evidence_id):
        incident = self._get_incident(incident_id)
        self._require_incident_access(identity, incident)
        if evidence_id not in incident["evidence_ids"]:
            raise ApiError(404, "该保全不属于本案")
        ev = self.evidence.get(evidence_id)
        with self.store.lock:
            self.store.audit(
                identity["label"],
                "接触证据",
                target=evidence_id,
                detail={"lead_id": next((lid for lid in incident["lead_ids"] if self._lead(lid)["evidence_id"] == evidence_id), None)},
            )
            self.store.save()
        return {
            "evidence_id": evidence_id,
            "receipt": self._receipt_summary(ev),
            "content": self._read_blob(evidence_id),
        }

    def view_pii(self, identity, incident_id, payload):
        """分区授权：仅值班员与执法联络员可凭明确用途解密，并强制登记。"""
        if identity["actor"] not in (DUTY, POLICE):
            raise ApiError(403, "联系方式与未公开身份材料仅限协会值班员、执法联络员按授权接触")
        purpose = (payload or {}).get("purpose")
        if not purpose:
            raise ApiError(400, "接触敏感材料必须声明用途")
        incident = self._get_incident(incident_id)
        out = []
        with self.store.lock:
            for lid in incident["lead_ids"]:
                secret = self.vault.get_lead_secret(lid)
                if not secret:
                    continue
                self.store.record_pii_access(identity["label"], lid, purpose, incident["id"])
                out.append({"lead_id": lid, "secret": secret})
            self.store.save()
        return {"incident_id": incident_id, "purpose": purpose, "items": out}

    def pii_access_register(self, identity, incident_id):
        self._require_role(identity, DUTY)
        incident = self._get_incident(incident_id)
        return [row for row in self.store.state["pii_access"] if row["incident_id"] == incident["id"]]

    def archive(self, identity, incident_id):
        self._require_role(identity, DUTY)
        incident = self._get_incident(incident_id)
        with self.store.lock:
            self._transition(incident, "已归档", reason="值班员归档")
            self.store.audit(identity["label"], "案件归档", target=incident_id)
            self.store.save()
        return {"id": incident_id, "status": incident["status"]}

    def audit_log(self, identity):
        self._require_role(identity, DUTY)
        return self.store.state["audit"]

    def verify_chain(self):
        ok, broken = self.evidence.verify_chain()
        return {"chain_ok": ok, "broken_at": broken, "tip": self.store.state["evidence_chain_tip"]}

    # ================= 内部辅助 =================
    def _contract(self):
        from .config import load_contract

        return load_contract()

    def _read_blob(self, evidence_id):
        from pathlib import Path

        return Path(self.evidence.get(evidence_id)["blob"]).read_text(encoding="utf-8")

    def _receipt_summary(self, ev):
        return {
            "evidence_id": ev["id"],
            "url": ev["url"],
            "platform": ev["platform"],
            "captured_at": ev["captured_at"],
            "observed_at": ev.get("observed_at"),
            "content_sha256": ev["content_sha256"],
            "receipt_hash": ev["receipt_hash"],
            "prev_hash": ev["prev_hash"],
            "supersedes": ev.get("supersedes"),
        }

    def _lead(self, lead_id):
        return self.store.state.setdefault("leads", {})[lead_id]

    def _get_incident(self, incident_id):
        incident = self.store.state["incidents"].get(incident_id)
        if incident is None:
            raise ApiError(404, "案件不存在")
        return incident

    def _require_fields(self, payload, fields):
        for field in fields:
            value = payload.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                raise ApiError(400, f"缺少必填字段：{field}")

    def _require_role(self, identity, actor):
        if identity["actor"] != actor:
            raise ApiError(403, f"该操作仅{actor}可执行")

    def _is_reporter(self, identity, incident):
        return any(self._lead(lid)["reporter_sub"] == identity["sub"] for lid in incident["lead_ids"])

    def _can_see_incident(self, identity, incident):
        if identity["actor"] == "保护对象":
            return self._is_reporter(identity, incident)
        return True

    def _require_incident_access(self, identity, incident):
        if not self._can_see_incident(identity, incident):
            raise ApiError(403, "只能操作与本人相关的案件")

    def _same_target(self, incident, lead):
        target = lead["target"].replace(" ", "")
        return any(target == t.replace(" ", "") for t in incident["targets"])

    def _similarity(self, incident, lead):
        """返回 (相似度, 类型)。url 精确重复、跨平台同文、高相似文本。"""
        for lid in incident["lead_ids"]:
            other = self._lead(lid)
            if other["url"] == lead["url"]:
                return 1.0, "url"
        canon_new = canonical_text(lead["content"])
        best = 0.0
        for lid in incident["lead_ids"]:
            other = self._lead(lid)
            canon_old = canonical_text(other["content"])
            if canon_new == canon_old:
                return 0.98, "cross"
            score = self._jaccard(canon_new, canon_old)
            best = max(best, score)
        return best, "fuzzy"

    @staticmethod
    def _jaccard(a, b):
        # 中文短文本以二元字组度量，兼顾同义改写（如「垃圾/废物」替换）与不同内容的区分
        def grams(text):
            return {text[i : i + 2] for i in range(max(0, len(text) - 1))} or {text}

        sa, sb = grams(a), grams(b)
        return len(sa & sb) / len(sa | sb)

    def _guess_platform(self, url, channel):
        for name in ("weibo", "xiaohongshu", "douyin", "twitter", "x.com", "zhihu", "bilibili"):
            if name in url.lower():
                return name
        return {"police": "公安报送", "club": "俱乐部报送"}.get(channel, "unknown")

    def _transition(self, incident, new_status, reason):
        contract = self._contract()
        allowed = contract["state_machine"].get(incident["status"], [])
        if new_status != incident["status"] and new_status not in allowed:
            raise ApiError(409, f"状态不可由「{incident['status']}」转为「{new_status}」")
        old = incident["status"]
        incident["status"] = new_status
        incident["updated_at"] = utcnow()
        self.store.audit(
            "system",
            "状态流转",
            target=incident["id"],
            detail={"from": old, "to": new_status, "reason": reason},
        )

    def _incident_view(self, incident, include_pii):
        return {
            "id": incident["id"],
            "status": incident["status"],
            "created_at": incident["created_at"],
            "updated_at": incident["updated_at"],
            "targets": incident["targets"],
            "duplicate_count": incident.get("duplicate_count", 0),
            "leads": [
                {
                    "id": lid,
                    "channel": self._lead(lid)["channel"],
                    "reporter_actor": self._lead(lid)["reporter_actor"],
                    "platform": self._lead(lid)["platform"],
                    "url": self._lead(lid)["url"],
                    "reach": self._lead(lid)["reach"],
                    "observed_at": self._lead(lid).get("observed_at"),
                    "is_duplicate_of": self._lead(lid)["is_duplicate_of"],
                    "evidence_id": self._lead(lid)["evidence_id"],
                    "pii": self._lead(lid).get("pii"),
                    "created_at": self._lead(lid)["created_at"],
                }
                for lid in incident["lead_ids"]
            ],
            "latest_evaluation": incident["evaluations"][-1] if incident["evaluations"] else None,
            "evaluation_versions": [s["rule_version"] for s in incident["evaluations"]],
            "actions": incident["actions"],
            "appeals": incident["appeals"],
            "decisions": incident["decisions"],
            "evidence_receipts": [self._receipt_summary(self.evidence.get(e)) for e in incident["evidence_ids"]],
        }
