"""端到端测试：线索归集、同源聚合、观点/威胁分级、人工权限决策、
证据保全链、误报申诉与规则升级不覆盖旧判断、联系方式隔离与留痕。"""

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import service as service_module
from pipeline import ApiError, Pipeline
from service import Handler, SERVICE_ID, health_payload, load_contract
from storage import ContactVault, Store

TOKENS = {
    "athlete": "tok_self_lin",
    "club": "tok_club_tiger",
    "platform": "tok_plat_weibo",
    "platform2": "tok_plat_douyin",
    "duty": "tok_duty",
    "police": "tok_police",
}


class PipelineTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "casebook.db")
        self.vault = ContactVault(Path(self.tmp.name) / "contacts.db")
        self.app = Pipeline(self.store, self.vault)
        self.users = {role: self.store.query_one(
            "SELECT * FROM users WHERE token=?", (tok,))
            for role, tok in TOKENS.items()}

    def tearDown(self):
        self.store.conn.close()
        self.vault.conn.close()
        self.tmp.cleanup()

    def user(self, role):
        return self.users[role]

    def submit(self, role, **overrides):
        body = {
            "channel": {"athlete": "self", "club": "club", "platform": "platform",
                        "platform2": "platform", "duty": "self", "police": "police"}[role],
            "subject_id": "s_lin",
            "platform": "微博台",
            "content_url": f"https://example.com/{overrides.pop('_slug', self._slug())}",
            "excerpt": "测试内容",
            "target_scope": 2, "spread_scope": 3,
            "credibility": 3, "urgency": 3,
        }
        body.update(overrides)
        return self.app.submit_report(self.user(role), body)

    _n = 0

    def _slug(self):
        PipelineTestBase._n += 1
        return f"p{PipelineTestBase._n}"

    def expect_error(self, status, fn, *args, **kwargs):
        with self.assertRaises(ApiError) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.status, status)
        return ctx.exception


class IntakeAndRulesTest(PipelineTestBase):
    def test_four_intake_channels_and_channel_mismatch_rejected(self):
        r1 = self.submit("athlete", excerpt="请求帮助")
        r2 = self.submit("club", excerpt="俱乐部代为报送")
        r3 = self.submit("platform", excerpt="平台巡查发现")
        r4 = self.submit("police", excerpt="公安转来线索")
        self.assertTrue(all(x["report_id"] for x in (r1, r2, r3, r4)))
        # 运动员不能走平台入口
        body = {"channel": "platform", "excerpt": "越权入口",
                "content_url": "https://example.com/x1", "target_scope": 1,
                "spread_scope": 1, "credibility": 1, "urgency": 1}
        self.expect_error(403, self.app.submit_report, self.user("athlete"), body)

    def test_opinion_is_distinguished_from_abuse_and_threat(self):
        opinion = self.submit("athlete", excerpt="今天打得差，战术令人失望，批评！")
        self.assertEqual(opinion["advisory"]["category"], "opinion")
        self.assertEqual(opinion["advisory"]["suggestions"], [])

        abuse = self.submit("club", excerpt="你就是个垃圾，滚出球队",
                            target_scope=2, spread_scope=3, credibility=3, urgency=2)
        self.assertEqual(abuse["advisory"]["category"], "abuse")
        self.assertIn("advise_restrict", abuse["advisory"]["suggestions"])

        threat = self.submit("platform", excerpt="我知道你家住哪，上门找你，等着瞧",
                             target_scope=1, spread_scope=5, credibility=4, urgency=5)
        self.assertEqual(threat["advisory"]["category"], "threat")
        self.assertIn("advise_protect_contact", threat["advisory"]["suggestions"])

        impersonation = self.submit("platform2", excerpt="内部人爆料：开房记录流出，黑料包")
        self.assertEqual(impersonation["advisory"]["category"], "impersonation")

    def test_automation_is_advisory_only_no_decision_without_human(self):
        self.submit("platform", excerpt="我要杀了你，等着瞧",
                    credibility=4, urgency=5, spread_scope=5)
        self.assertEqual(self.store.query("SELECT COUNT(*) c FROM decisions")[0]["c"], 0)
        asm = self.store.query_one("SELECT * FROM assessments ORDER BY rowid LIMIT 1")
        self.assertEqual(asm["advisory"], 1)


class PermissionAndDecisionTest(PipelineTestBase):
    def test_restrict_requires_duty_and_can_deviate_with_override(self):
        res = self.submit("club", excerpt="垃圾，滚出",
                          target_scope=2, spread_scope=3, credibility=3, urgency=2)
        event_id = res["event_id"]
        # 平台协查员不能确认限制传播
        self.expect_error(403, self.app.decide, self.user("platform"),
                          event_id, "restrict", "平台想直接下架")
        # 值班员确认
        dec = self.app.decide(self.user("duty"), event_id, "restrict", "辱骂成片传播，予以下架")
        self.assertEqual(dec["decision_type"], "restrict")
        self.assertEqual(dec["decided_by_role"], "duty")
        self.assertTrue(dec["rule_version"])

        # 对纯观点事件采取限制必须显式 override 并附理由
        opinion = self.submit("athlete", excerpt="状态低迷，令人失望")
        ev2 = opinion["event_id"]
        self.expect_error(409, self.app.decide, self.user("duty"),
                          ev2, "restrict", "")
        overridden = self.app.decide(self.user("duty"), ev2, "restrict",
                                     "人工复核认为其中含影射性内容，从严处理", override=True)
        self.assertTrue(overridden["id"])

    def test_referral_workflow_and_police_visibility(self):
        res = self.submit("platform", excerpt="砍死他，血洗全家",
                          credibility=4, urgency=5, spread_scope=4)
        event_id = res["event_id"]
        # 公安联络员在移送前看不到案件
        self.expect_error(403, self.app.case_view, self.user("police"), event_id)
        # 值班员无权代替公安出具接收回执；先移送
        dec = self.app.decide(self.user("duty"), event_id,
                              "refer_law_enforcement", "显式死亡威胁，移送属地网安")
        # 值班员不能确认接收
        self.expect_error(403, self.app.acknowledge_referral,
                          self.user("duty"), dec["id"])
        ack = self.app.acknowledge_referral(self.user("police"), dec["id"], "已受案")
        self.assertEqual(ack["receipts"][0]["receipt_kind"], "law_enforcement_receipt")
        # 移送后公安可以查看案件
        view = self.app.case_view(self.user("police"), event_id)
        self.assertEqual(view["event"]["id"], event_id)
        # 接收回执仅追加，不得重复
        self.expect_error(409, self.app.acknowledge_referral,
                          self.user("police"), dec["id"], "再次接收")

    def test_reverse_decision_keeps_original(self):
        res = self.submit("club", excerpt="垃圾，不要脸",
                          target_scope=2, spread_scope=3, credibility=3, urgency=2)
        dec = self.app.decide(self.user("duty"), res["event_id"], "restrict", "初判下架")
        new = self.app.reverse_decision(self.user("duty"), dec["id"], "申诉成立，撤销下架")
        self.assertEqual(new["supersedes_decision_id"], dec["id"])
        old = self.store.query_one("SELECT * FROM decisions WHERE id=?", (dec["id"],))
        self.assertIsNotNone(old)  # 旧决定仍在
        self.assertEqual(old["action"], "restrict")


class ClusteringAndImmutabilityTest(PipelineTestBase):
    def test_same_claim_across_platforms_merges_into_one_event(self):
        a = self.submit("platform", platform="微博台",
                        content_url="https://weibo/1", excerpt="等着瞧，上门找你",
                        claim_key="claim-001", credibility=4, urgency=5, spread_scope=5)
        b = self.submit("platform2", platform="抖音台",
                        content_url="https://douyin/9", excerpt="等着瞧，上门找你",
                        claim_key="claim-001", credibility=3, urgency=4, spread_scope=4)
        self.assertEqual(a["event_id"], b["event_id"])
        view = self.app.case_view(self.user("duty"), a["event_id"])
        self.assertEqual(len(view["reports"]), 2)
        self.assertEqual(view["evidence"]["chain_verification"]["intact"], True)
        # 未参与该事件的俱乐部联络员看不到
        self.expect_error(403, self.app.case_view, self.user("club"), a["event_id"])

    def test_identical_content_cross_platform_clusters_without_claim_key(self):
        h = "hash-same-text-001"
        a = self.submit("platform", content_url="https://weibo/x",
                        excerpt="同一段截图文字", content_hash=h)
        b = self.submit("platform2", content_url="https://douyin/y",
                        excerpt="同一段截图文字", content_hash=h)
        self.assertEqual(a["event_id"], b["event_id"])

    def test_duplicate_report_appends_and_preserves_prior_judgment(self):
        first = self.submit("platform", content_url="https://weibo/dup",
                            excerpt="垃圾内容", credibility=3, urgency=2, spread_scope=3)
        asm_before = self.store.query(
            "SELECT id FROM assessments WHERE report_id=?", (first["report_id"],))
        again = self.submit("platform2", content_url="https://weibo/dup",
                            excerpt="垃圾内容", credibility=5, urgency=5, spread_scope=5)
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["event_id"], first["event_id"])
        asm_after = self.store.query(
            "SELECT id FROM assessments WHERE report_id=?", (first["report_id"],))
        self.assertEqual(asm_before, asm_after)  # 新举报的评分没有覆盖旧研判
        sups = self.store.query("SELECT kind FROM supplements")
        self.assertIn("repeat_report", [s["kind"] for s in sups])

    def test_append_only_triggers_reject_update_and_delete(self):
        res = self.submit("platform", excerpt="测试篡改性")
        rid, eid = res["report_id"], res["event_id"]
        cases = [
            ("reports", f"id='{rid}'"),
            ("evidences", f"event_id='{eid}'"),
            ("assessments", f"report_id='{rid}'"),
            ("receipts", "1=1"),
            ("audit_log", "1=1"),
        ]
        for table, where in cases:
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.execute(f"UPDATE {table} SET rowid=rowid WHERE {where}")
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.execute(f"DELETE FROM {table} WHERE {where}")
        # 核心研判数量在篡改尝试后保持不变
        self.assertEqual(len(self.store.query("SELECT * FROM receipts")), 1)


class EvidenceTest(PipelineTestBase):
    def test_dead_link_still_provable_by_timestamp_hash_and_receipt(self):
        res = self.submit("athlete", content_url=None, platform="线下传单",
                          excerpt="线下拍摄到的侮辱海报文字")
        ev = self.store.query_one("SELECT * FROM evidences WHERE event_id=?",
                                  (res["event_id"],))
        rc = self.store.query_one("SELECT * FROM receipts WHERE evidence_id=?", (ev["id"],))
        self.assertIsNone(ev["url"])  # 链接从一开始就不存在
        self.assertTrue(ev["captured_at"])
        self.assertEqual(len(ev["content_hash"]), 64)
        self.assertEqual(rc["content_hash"], ev["content_hash"])
        self.assertIsNone(rc["prev_hash"])  # 创世回执
        chain = self.store.verify_chain()
        self.assertEqual(chain["intact"], True)

    def test_chain_links_multiple_receipts(self):
        self.submit("platform", content_url="https://a/1", excerpt="垃圾1",
                    credibility=3, urgency=2, spread_scope=3)
        self.submit("platform", content_url="https://a/2", excerpt="垃圾2",
                    credibility=3, urgency=2, spread_scope=3)
        receipts = self.store.query("SELECT * FROM receipts ORDER BY rowid")
        self.assertGreaterEqual(len(receipts), 2)
        self.assertEqual(receipts[1]["prev_hash"], receipts[0]["chain_hash"])

    def test_cross_platform_supplement_adds_evidence_without_touching_old(self):
        res = self.submit("platform", content_url="https://a/1", excerpt="威胁原文：等着瞧",
                          credibility=4, urgency=5, spread_scope=4)
        event_id = res["event_id"]
        before = self.store.query(
            "SELECT id FROM evidences WHERE event_id=?", (event_id,))
        sup = self.app.add_supplement(
            self.user("platform2"), event_id, "cross_platform_evidence",
            {"snapshot": "抖音台二次传播截图文字", "content_url": "https://douyin/z"})
        self.assertIsNotNone(sup["evidence"]["receipt_no"])
        after = self.store.query(
            "SELECT id,note FROM evidences WHERE event_id=? ORDER BY rowid", (event_id,))
        self.assertEqual(len(after), len(before) + 1)
        self.assertTrue(any(e["id"] == before[0]["id"] for e in after))  # 旧证据未动
        self.assertEqual(self.store.verify_chain()["intact"], True)
        # 俱乐部角色没有补件权限
        other = self.submit("club", content_url="https://club/1", excerpt="另一个事件")
        self.expect_error(403, self.app.add_supplement, self.user("club"),
                          other["event_id"], "cross_platform_evidence", {"snapshot": "x"})


class AppealAndRuleUpgradeTest(PipelineTestBase):
    def test_appeal_and_rule_upgrade_never_overwrites_old_judgment(self):
        res = self.submit("athlete", content_url="https://a/9",
                          excerpt="内容无伤害词，但评分高",
                          target_scope=3, spread_scope=4, credibility=4, urgency=5)
        event_id = res["event_id"]
        report_id = res["report_id"]
        old_report_asm = self.store.query_one(
            "SELECT * FROM assessments WHERE report_id=? ORDER BY rowid", (report_id,))
        self.assertEqual(old_report_asm["category"], "threat")  # r2：高紧迫+高可信判威胁
        old_event_asm = self.store.query_one(
            "SELECT * FROM assessments WHERE event_id=? ORDER BY rowid DESC LIMIT 1",
            (event_id,))
        self.app.decide(self.user("duty"), event_id, "protect_contact", "按建议联系保护对象")

        # 误报申诉（固化申诉时点的事件级研判）
        appeal = self.app.submit_appeal(self.user("athlete"), event_id, "内容是夸张气话，无真实意图")
        self.assertEqual(appeal["preserved_assessment_id"], old_event_asm["id"])

        # 值班员发布收紧后的规则 r3：仅凭评分不再判威胁
        r3 = {"weights": {"target_scope": 0.2, "spread_scope": 0.25,
                          "credibility": 0.25, "urgency": 0.3},
              "threat": {"require_phrase_and_credibility": 2,
                         "urgency_gte": 6, "credibility_gte": 3},
              "abuse_risk_gte": 2.5, "impersonation_autodetect": True}
        self.expect_error(403, self.app.publish_rule, self.user("platform"),
                          "2026-09-22-r3", r3, "平台不能发规则")
        self.app.publish_rule(self.user("duty"), "2026-09-22-r3", r3,
                              "仅凭高评分不再判威胁，须有伤害表述", supersedes="2026-09-22-r2")
        self.assertEqual(self.app.current_rule_version(), "2026-09-22-r3")
        # 版本号不可复用
        self.expect_error(409, self.app.publish_rule, self.user("duty"),
                          "2026-09-22-r3", r3, "重复发布")

        # 复核并按新规则重算
        review = self.app.resolve_appeal(
            self.user("duty"), appeal["appeal_id"], "upheld",
            "申诉成立，按 r3 重新研判", reevaluate=True)
        self.assertEqual(review["reviewed_rule_version"], "2026-09-22-r3")
        self.assertIsNotNone(review["new_assessment_id"])

        # 旧研判仍在且仍是 r2/threat；新研判为 r3/opinion
        all_asm = self.store.query(
            "SELECT rule_version,category FROM assessments WHERE report_id=? ORDER BY rowid",
            (report_id,))
        self.assertIn(("2026-09-22-r2", "threat"), [tuple(a.values()) for a in all_asm])
        newest = self.store.query_one(
            "SELECT * FROM assessments WHERE report_id=? ORDER BY rowid DESC", (report_id,))
        self.assertEqual(newest["rule_version"], "2026-09-22-r3")
        self.assertEqual(newest["category"], "opinion")
        # 旧决定仍记录旧规则版本，未被抹掉
        decision = self.store.query_one("SELECT * FROM decisions ORDER BY rowid LIMIT 1")
        self.assertEqual(decision["rule_version"], "2026-09-22-r2")
        # 同一申诉不能二次复核（结论只追加）
        self.expect_error(409, self.app.resolve_appeal, self.user("duty"),
                          appeal["appeal_id"], "rejected", "试图改判")

    def test_rule_upgrade_only_affects_future_reports(self):
        self.app.publish_rule(
            self.user("duty"), "2026-09-22-r3",
            {"weights": {"target_scope": 0.2, "spread_scope": 0.25,
                         "credibility": 0.25, "urgency": 0.3},
             "threat": {"require_phrase_and_credibility": 2,
                        "urgency_gte": 6, "credibility_gte": 3},
             "abuse_risk_gte": 9, "impersonation_autodetect": True},
            "演示规则", supersedes="2026-09-22-r2")
        res = self.submit("club", content_url="https://a/10", excerpt="垃圾，滚出",
                          target_scope=2, spread_scope=3, credibility=3, urgency=2)
        # r3 阈值变化后，同内容在新线索上不再判 abuse
        self.assertEqual(res["advisory"]["rule_version"], "2026-09-22-r3")
        self.assertEqual(res["advisory"]["category"], "opinion")


class ContactIsolationTest(PipelineTestBase):
    def test_case_view_excludes_contacts_and_records_evidence_access(self):
        res = self.submit("platform", excerpt="上门找你，等着瞧",
                          credibility=4, urgency=5, spread_scope=4)
        view = self.app.case_view(self.user("duty"), res["event_id"])
        self.assertFalse(view["contacts_included"])
        raw = json.dumps(view, ensure_ascii=False)
        self.assertNotIn("138-0000-0000", raw)
        self.assertNotIn("身份证号", raw)

    def test_contact_read_requires_purpose_and_leaves_denial_ledger(self):
        res = self.submit("platform", excerpt="威胁", credibility=4, urgency=5)
        # 平台协查员调阅被拒，拒绝也要在保封库台账留痕
        self.expect_error(403, self.app.read_contacts, self.user("platform"),
                          "s_lin", "想看电话")
        # 值班员不填事由被拒
        self.expect_error(400, self.app.read_contacts, self.user("duty"),
                          "s_lin", "")
        # 值班员凭事由调阅
        out = self.app.read_contacts(self.user("duty"), "s_lin", "需启动紧急联系保护")
        self.assertIn("138", out["contact_detail"])
        ledger = self.app.contact_ledger(self.user("duty"))
        denials = [x for x in ledger["contact_access"] if x["allowed"] == 0]
        grants = [x for x in ledger["contact_access"] if x["allowed"] == 1]
        self.assertTrue(denials and grants)
        self.assertEqual(denials[0]["role"], "platform")
        # 平台无权查看接触台账
        self.expect_error(403, self.app.contact_ledger, self.user("platform"))


class CaseViewTest(PipelineTestBase):
    def test_duty_sees_full_case_timeline_and_rule_versions(self):
        res = self.submit("platform", excerpt="等着瞧，上门找你",
                          credibility=4, urgency=5, spread_scope=5)
        event_id = res["event_id"]
        dec = self.app.decide(self.user("duty"), event_id, "protect_contact", "立即联系")
        # 公安补件需先移送并接收
        referral = self.app.decide(self.user("duty"), event_id,
                                   "refer_law_enforcement", "移送")
        self.app.acknowledge_referral(self.user("police"), referral["id"], "受案")
        self.app.add_supplement(self.user("police"), event_id, "police_update",
                                {"note": "已加强巡逻"})
        self.app.set_event_state(self.user("duty"), event_id, "保护处置中", "措施执行中")

        view = self.app.case_view(self.user("duty"), event_id)
        # 触发保护行为的内容被单独归入 protection_triggered
        self.assertTrue(view["viewpoint_vs_action"]["protection_triggered"])
        self.assertEqual(view["state"], "保护处置中")
        # 每次决定可追溯规则版本与建议
        for d in view["decisions"]:
            self.assertTrue(d["rule_version"])
            self.assertTrue(d["assessment_id"])
        # 证据由谁接触：审计里能找到 evidence.read
        actions = [x["action"] for x in self.app.audit_trail(self.user("duty"))]
        self.assertIn("evidence.read", actions)
        self.assertIn("case.read", actions)
        self.assertEqual(len(view["evidence"]["receipts"]), 1)
        self.assertEqual(view["evidence"]["chain_verification"]["intact"], True)
        self.assertTrue(dec["id"] and referral["id"])

    def test_platform_status_append(self):
        res = self.submit("platform", excerpt="垃圾，滚出",
                          credibility=3, urgency=2, spread_scope=3)
        out = self.app.update_platform_status(
            self.user("platform"), res["report_id"], "已下架", "断链+屏蔽转发")
        self.assertEqual(out["status"], "已下架")
        logs = self.store.query("SELECT status,note FROM report_status_log ORDER BY rowid")
        self.assertIn("已下架", [x["status"] for x in logs])


class HttpServiceTest(unittest.TestCase):
    """HTTP 层：鉴权、路由与既有 /health /contract 契约。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["AHR_DATA_DIR"] = cls.tmp.name
        service_module._APP = None
        service_module._DATA_DIR = cls.tmp.name
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        app = getattr(service_module, "_APP", None)
        if app:
            app.store.conn.close()
            app.vault.conn.close()
        cls.tmp.cleanup()
        os.environ.pop("AHR_DATA_DIR", None)

    def request(self, method, path, token=None, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        return urlopen(req, timeout=3)

    def read_json(self, path):
        with urlopen(f"{self.base_url}{path}", timeout=2) as response:
            self.assertEqual(response.headers.get_content_type(), "application/json")
            return json.load(response)

    def test_health_and_contract_unchanged(self):
        self.assertEqual(self.read_json("/health"), health_payload())
        contract = self.read_json("/contract")
        self.assertEqual(contract["service_id"], SERVICE_ID)
        self.assertGreaterEqual(len(contract["invariants"]), 6)

    def test_auth_required_and_role_enforced(self):
        with self.assertRaises(HTTPError) as e:
            urlopen(f"{self.base_url}/api/v1/events", timeout=2)
        self.assertEqual(e.exception.code, 401)
        e.exception.close()
        with self.assertRaises(HTTPError) as e:
            self.request("GET", "/api/v1/events", token="tok_bad")
        self.assertEqual(e.exception.code, 401)
        e.exception.close()
        with self.request("GET", "/api/v1/events", token=TOKENS["duty"]) as r:
            self.assertEqual(r.status, 200)
        # 未移送案件，公安列表为空但可访问
        with self.request("GET", "/api/v1/events", token=TOKENS["police"]) as r:
            self.assertEqual(json.load(r)["events"], [])

    def test_full_flow_over_http(self):
        with self.request("POST", "/api/v1/reports", TOKENS["platform"], {
                "channel": "platform", "subject_id": "s_lin",
                "content_url": "http://w/1", "excerpt": "等着瞧，上门找你",
                "target_scope": 1, "spread_scope": 5,
                "credibility": 4, "urgency": 5}) as r:
            created = json.load(r)
        self.assertEqual(created["advisory"]["category"], "threat")
        event_id = created["event_id"]
        # 平台尝试直接处置被拒
        with self.assertRaises(HTTPError) as e:
            self.request("POST", f"/api/v1/events/{event_id}/decisions",
                         TOKENS["platform"], {"decision_type": "restrict"})
        self.assertEqual(e.exception.code, 403)
        e.exception.close()
        with self.request("POST", f"/api/v1/events/{event_id}/decisions", TOKENS["duty"], {
                "decision_type": "protect_contact",
                "rationale": "显式威胁，立即联系保护对象"}) as r:
            dec = json.load(r)
        self.assertEqual(dec["decided_by_role"], "duty")
        with self.request("GET", f"/api/v1/evidence/verify", TOKENS["duty"]) as r:
            self.assertTrue(json.load(r)["intact"])


class SelfCheckTest(unittest.TestCase):
    def test_self_check_passes(self):
        service_module.run_self_check()


if __name__ == "__main__":
    unittest.main()
