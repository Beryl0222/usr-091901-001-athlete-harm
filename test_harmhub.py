"""端到端领域测试：覆盖多入口、同源聚合、证据保全、人工确认、
申诉/规则升级不覆盖旧判断、观点与威胁区分以及敏感材料隔离。"""

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from harmhub import Hub
from harmhub.api import create_handler
from harmhub.util import sha256_hex

THREAT = {
    "target": "李锐",
    "platform": "weibo",
    "url": "https://weibo.example/p/111",
    "content": "李锐就是垃圾，我知道你住哪个小区，等着，今晚上门找你！",
    "reach": 50000,
    "credibility_hint": 2,
    "hours_since_posted": 2,
    "explicit_location": True,
    "category_hints": ["人身威胁"],
    "contact_name": "李锐本人",
    "contact_phone": "13800000001",
    "private_materials": ["未公开行程单.pdf"],
}
OPINION = {
    "target": "李锐",
    "platform": "weibo",
    "url": "https://weibo.example/p/222",
    "content": "李锐今晚打得太差了，状态低迷，教练应该换人。",
    "reach": 30,
}


class HubTestBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.hub = Hub(self.dir)
        self.tokens = {t["sub"]: t["token"] for t in self.hub.bootstrap_identities()}

    def ident(self, sub):
        return self.hub.authenticate(self.tokens[sub])

    def submit(self, sub, payload, incident_id=None):
        return self.hub.submit_lead(self.ident(sub), payload, incident_id=incident_id)

    def incident(self, result):
        return self.hub._get_incident(result["incident_id"])


class IntakeAndAggregationTest(HubTestBase):
    def test_multi_channel_ingest_and_receipt(self):
        result = self.submit("self:lirui", THREAT)
        self.assertEqual(result["merge_mode"], "new")
        receipt = result["evidence_receipt"]
        self.assertTrue(receipt["evidence_id"].startswith("ev_"))
        self.assertRegex(receipt["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(receipt["captured_at"].endswith("Z"))
        self.assertEqual(receipt["prev_hash"], "GENESIS")
        # 内容已只读留存且哈希可复算
        blob = Path(self.dir) / "evidence" / f"{receipt['evidence_id']}.bin"
        self.assertEqual(sha256_hex(blob.read_text(encoding="utf-8")), receipt["content_sha256"])
        self.assertEqual(Path(blob).stat().st_mode & 0o777, 0o444)

    def test_duplicate_exact_url_and_cross_platform_merge(self):
        first = self.submit("self:lirui", THREAT)
        # 同一 URL 的重复举报（即使报送入口不同）
        dup = self.submit("club:zhangyun", {**THREAT, "platform": "club"})
        self.assertEqual(dup["incident_id"], first["incident_id"])
        self.assertEqual(dup["merge_mode"], "duplicate")
        # 不同平台、改写后的同文 → 跨平台补件
        cross = self.submit(
            "platform:wangning",
            {
                "target": "李锐",
                "platform": "douyin",
                "url": "https://dy.example/v/9",
                "content": "李锐就是个废物！我知道你住哪个小区，等着，今晚上门！",
                "reach": 12000,
                "hours_since_posted": 3,
            },
        )
        self.assertEqual(cross["merge_mode"], "cross_platform")
        incident = self.incident(first)
        self.assertEqual(len(incident["lead_ids"]), 3)
        # 重复举报不产生新评估；新件/补件/跨平台各追加评估
        self.assertEqual(len(incident["evaluations"]), 2)
        self.assertGreaterEqual(incident.get("duplicate_count", 0), 1)

    def test_explicit_attach_endpoint_and_opinion_is_separate(self):
        first = self.submit("self:lirui", THREAT)
        police = self.submit(
            "police:zhaojing",
            {
                "target": "李锐",
                "platform": "公安报送",
                "url": "https://report.police.local/case/88",
                "content": "报警人提供的威胁私信截图：等着，今晚上门找你",
                "reach": 1,
                "credibility_hint": 3,
            },
            incident_id=first["incident_id"],
        )
        self.assertEqual(police["merge_mode"], "explicit")
        # 正常批评即使对象相同，也不并入威胁事件
        opinion = self.submit("platform:wangning", OPINION)
        self.assertEqual(opinion["merge_mode"], "new")
        self.assertNotEqual(opinion["incident_id"], first["incident_id"])
        self.assertEqual(opinion["latest_risk_level"], "低")

    def test_invalid_token_rejected(self):
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError) as ctx:
            self.hub.authenticate("not-a-token")
        self.assertEqual(ctx.exception.status, 401)


class RulesAndPermissionsTest(HubTestBase):
    def test_automation_only_advises(self):
        result = self.submit("self:lirui", THREAT)
        incident = self.incident(result)
        latest = incident["evaluations"][-1]
        self.assertTrue(latest["automated"])
        self.assertEqual(latest["status"], "待确认")
        self.assertIn("人身威胁", latest["categories"])
        self.assertIn("移送执法", latest["suggested_actions"])
        # 没有人工确认前，任何保护措施都不得生效
        self.assertEqual(incident["actions"], {})

    def test_opinion_never_triggers_protection(self):
        result = self.submit("platform:wangning", OPINION)
        incident = self.incident(result)
        self.assertEqual(incident["evaluations"][-1]["categories"], ["观点"])
        self.assertEqual(incident["evaluations"][-1]["suggested_actions"], [])
        # 即使值班员想限制传播，也必须以人工超建议为由填写理由
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError) as ctx:
            self.hub.confirm_action(self.ident("duty:chenchen"), result["incident_id"], {"action": "限制传播"})
        self.assertEqual(ctx.exception.status, 400)

    def test_protected_action_permission_matrix(self):
        result = self.submit("self:lirui", THREAT)
        iid = result["incident_id"]
        from harmhub.errors import ApiError

        # 平台协查员不能限制传播
        with self.assertRaises(ApiError) as ctx:
            self.hub.confirm_action(self.ident("platform:wangning"), iid, {"action": "限制传播"})
        self.assertEqual(ctx.exception.status, 403)
        # 保护对象本人不能确认任何措施
        with self.assertRaises(ApiError) as ctx:
            self.hub.confirm_action(self.ident("self:lirui"), iid, {"action": "联系保护对象"})
        self.assertEqual(ctx.exception.status, 403)
        # 值班员可限制传播；俱乐部联络员可联系保护对象；执法联络员可移送执法
        self.hub.confirm_action(self.ident("duty:chenchen"), iid, {"action": "限制传播"})
        self.hub.confirm_action(self.ident("club:zhangyun"), iid, {"action": "联系保护对象", "reason": "协会转办，提醒安全"})
        self.hub.confirm_action(self.ident("police:zhaojing"), iid, {"action": "移送执法"})
        incident = self.incident(result)
        self.assertEqual(incident["status"], "保护处置中")
        self.assertTrue(all(v["state"] == "已确认" for v in incident["actions"].values()))
        # 已确认措施不可重复决定/覆盖
        with self.assertRaises(ApiError) as ctx:
            self.hub.confirm_action(self.ident("duty:chenchen"), iid, {"action": "限制传播"})
        self.assertEqual(ctx.exception.status, 409)

    def test_manual_override_requires_reason_and_is_recorded(self):
        result = self.submit("platform:wangning", OPINION)
        decision = self.hub.confirm_action(
            self.ident("duty:chenchen"),
            result["incident_id"],
            {"action": "限制传播", "reason": "虽无威胁措辞，但当事人明确表示恐慌，先行限流"},
        )
        self.assertEqual(decision["basis"], "人工研判（超出自动建议）")
        self.assertTrue(decision["rule_version"].startswith("rules-"))


class AppendOnlyHistoryTest(HubTestBase):
    def _confirmed_case(self):
        result = self.submit("self:lirui", THREAT)
        iid = result["incident_id"]
        self.hub.confirm_action(self.ident("duty:chenchen"), iid, {"action": "限制传播"})
        self.hub.confirm_action(self.ident("police:zhaojing"), iid, {"action": "移送执法"})
        return result

    def test_appeal_overturn_keeps_original_decisions(self):
        result = self._confirmed_case()
        iid = result["incident_id"]
        before_decisions = len(self.incident(result)["decisions"])
        appeal = self.hub.appeal(self.ident("self:lirui"), iid, {"reason": "发布者是熟人，已道歉，是玩笑"})
        reviewed = self.hub.review_appeal(
            self.ident("duty:chenchen"), iid, appeal["id"], {"uphold": False, "note": "核实为玩笑"}
        )
        self.assertEqual(reviewed["resolution"]["verdict"], "申诉成立")
        incident = self.incident(result)
        # 原确认记录仍在，且新增了撤销记录
        self.assertGreater(len(incident["decisions"]), before_decisions)
        bases = [d["basis"] for d in incident["decisions"]]
        self.assertIn("采纳自动建议", bases)
        self.assertTrue(any("原确认记录保留" in b for b in bases))
        self.assertEqual(incident["actions"]["restrict"]["state"], "已撤销（申诉成立）")
        # 复核结论不可再次覆盖
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError) as ctx:
            self.hub.review_appeal(self.ident("duty:chenchen"), iid, appeal["id"], {"uphold": True})
        self.assertEqual(ctx.exception.status, 409)

    def test_appeal_uphold_preserves_measures(self):
        result = self._confirmed_case()
        iid = result["incident_id"]
        appeal = self.hub.appeal(self.ident("club:zhangyun"), iid, {"reason": "俱乐部认为误报"})
        self.hub.review_appeal(self.ident("duty:chenchen"), iid, appeal["id"], {"uphold": True, "note": "威胁明确"})
        incident = self.incident(result)
        self.assertEqual(incident["actions"]["restrict"]["state"], "已确认")
        self.assertEqual(incident["status"], "保护处置中")

    def test_rule_upgrade_freezes_old_judgements(self):
        result = self.submit("self:lirui", THREAT)
        iid = result["incident_id"]
        self.hub.confirm_action(self.ident("duty:chenchen"), iid, {"action": "限制传播"})
        old_eval = self.incident(result)["evaluations"][-1]
        self.hub.upgrade_rules(
            self.ident("duty:chenchen"),
            {"version": "rules-2026.09.1", "notes": "提高辱骂类风险阈值，威胁类保持不变"},
        )
        # 升级不自动改写历史；值班员主动按新版本复评，仅追加
        new_eval = self.hub.reevaluate(self.ident("duty:chenchen"), iid)
        self.assertEqual(new_eval["rule_version"], "rules-2026.09.1")
        self.assertEqual(new_eval["supersedes"], old_eval["id"])
        incident = self.incident(result)
        self.assertEqual([e["rule_version"] for e in incident["evaluations"]], ["rules-2026.09.0", "rules-2026.09.1"])
        # 原决定仍记录其作出时的规则版本
        confirm = next(d for d in incident["decisions"] if d.get("kind") == "保护措施确认")
        self.assertEqual(confirm["rule_version"], "rules-2026.09.0")
        # 旧版本已冻结，重复发布同名版本被拒绝
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError):
            self.hub.upgrade_rules(self.ident("duty:chenchen"), {"version": "rules-2026.09.1", "notes": "x"})


class EvidenceTest(HubTestBase):
    def test_chain_tamper_detected(self):
        result = self.submit("self:lirui", THREAT)
        self.submit("platform:wangning", {**THREAT, "url": "https://x.example/2", "platform": "x"})
        ok, _ = self.hub.evidence.verify_chain()
        self.assertTrue(ok)
        ev_id = result["evidence_receipt"]["evidence_id"]
        blob = Path(self.dir) / "evidence" / f"{ev_id}.bin"
        blob.chmod(0o644)
        blob.write_text("事后伪造的内容", encoding="utf-8")
        ok, broken = self.hub.evidence.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(broken, ev_id)

    def test_dead_link_still_provable(self):
        result = self.submit("self:lirui", THREAT)
        receipt = result["evidence_receipt"]
        # 原始链接“404 失效”后，仍可凭保全记录举证：时间戳 + 哈希 + 链式回执 + 留存原文
        ev = self.hub.evidence.get(receipt["evidence_id"])
        viewed = self.hub.read_evidence_content(self.ident("duty:chenchen"), result["incident_id"], ev["id"])
        self.assertIn("上门找你", viewed["content"])
        self.assertEqual(viewed["receipt"]["content_sha256"], receipt["content_sha256"])
        self.assertTrue(self.hub.verify_chain()["chain_ok"])

    def test_re_preserve_appends_instead_of_overwrite(self):
        result = self.submit("self:lirui", THREAT)
        old = result["evidence_receipt"]
        new = self.hub.evidence.re_preserve(
            previous_evidence_id=old["evidence_id"],
            url=old["url"],
            content="页面更新后的内容",
            content_type="text",
            captured_by="王宁（平台协查员）",
            platform="weibo",
        )
        self.assertEqual(new["supersedes"], old["evidence_id"])
        self.assertNotEqual(new["id"], old["evidence_id"])
        # 旧保全原样保留且链完好
        self.assertEqual(self.hub.evidence.get(old["evidence_id"])["content_sha256"], old["content_sha256"])
        self.assertTrue(self.hub.verify_chain()["chain_ok"])


class PiiIsolationTest(HubTestBase):
    def test_pii_partitioned_and_access_logged(self):
        result = self.submit("self:lirui", THREAT)
        iid = result["incident_id"]
        # 研判视图中不出现联系方式原文，只有存在性元信息
        view = self.hub.incident_detail(self.ident("duty:chenchen"), iid)
        serialized = json.dumps(view, ensure_ascii=False)
        self.assertNotIn("13800000001", serialized)
        self.assertNotIn("未公开行程单.pdf", serialized)
        self.assertTrue(view["leads"][0]["pii"]["has_contact"])
        # 保管箱文件本身加密，磁盘上不可见明文
        vault_bytes = (Path(self.dir) / "vault.json").read_text(encoding="utf-8")
        self.assertNotIn("13800000001", vault_bytes)
        self.assertNotIn("未公开行程单", vault_bytes)

        from harmhub.errors import ApiError

        for sub in ("platform:wangning", "club:zhangyun", "self:zhoulan"):
            with self.assertRaises(ApiError) as ctx:
                self.hub.view_pii(self.ident(sub), iid, {"purpose": "查看"})
            self.assertEqual(ctx.exception.status, 403)
        # 无用途不放行
        with self.assertRaises(ApiError) as ctx:
            self.hub.view_pii(self.ident("duty:chenchen"), iid, {})
        self.assertEqual(ctx.exception.status, 400)
        # 值班员凭用途解密，全程登记
        pii = self.hub.view_pii(self.ident("duty:chenchen"), iid, {"purpose": "安排保护性联系"})
        self.assertEqual(pii["items"][0]["secret"]["contact_phone"], "13800000001")
        register = self.hub.pii_access_register(self.ident("duty:chenchen"), iid)
        self.assertEqual(len(register), 1)
        self.assertEqual(register[0]["purpose"], "安排保护性联系")
        # 执法联络员也可按授权接触并登记
        self.hub.view_pii(self.ident("police:zhaojing"), iid, {"purpose": "移送前核实身份"})
        self.assertEqual(len(self.hub.pii_access_register(self.ident("duty:chenchen"), iid)), 2)

    def test_athletes_are_isolated_from_each_other(self):
        mine = self.submit("self:lirui", THREAT)
        other = self.submit(
            "self:zhoulan",
            {"target": "周岚", "platform": "weibo", "url": "https://w.example/z1", "content": "周岚滚出国家队，去死吧垃圾", "reach": 500},
        )
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError) as ctx:
            self.hub.incident_detail(self.ident("self:lirui"), other["incident_id"])
        self.assertEqual(ctx.exception.status, 403)
        listing = self.hub.list_incidents(self.ident("self:lirui"))
        self.assertEqual([i["id"] for i in listing], [mine["incident_id"]])
        # 值班员可见全部
        self.assertEqual(len(self.hub.list_incidents(self.ident("duty:chenchen"))), 2)


class DossierTest(HubTestBase):
    def test_dossier_separates_opinion_actions_evidence_and_versions(self):
        threat = self.submit("self:lirui", THREAT)
        iid = threat["incident_id"]
        self.submit(
            "platform:wangning",
            {"target": "李锐", "platform": "weibo", "url": "https://weibo.example/p/333", "content": "李锐今晚打得差，看得失望，该不该给新人机会？", "reach": 12},
            incident_id=iid,
        )
        self.hub.confirm_action(self.ident("duty:chenchen"), iid, {"action": "限制传播"})
        self.hub.view_pii(self.ident("duty:chenchen"), iid, {"purpose": "保护性联系"})
        dossier = self.hub.case_dossier(self.ident("duty:chenchen"), iid)

        self.assertEqual(len(dossier["opinion_content"]), 1)
        self.assertEqual(len(dossier["actionable_content"]), 1)
        self.assertIn("人身威胁", dossier["actionable_content"][0]["categories"])
        # 证据与每次决定、规则版本可追溯
        self.assertTrue(dossier["evidence_chain_ok"])
        self.assertEqual(len(dossier["evidence"]), 2)
        protection = next(p for p in dossier["protections"] if p["action"] == "限制传播")
        self.assertEqual(protection["state"], "已确认")
        self.assertTrue(protection["rule_version"].startswith("rules-"))
        decision_versions = {d["rule_version"] for d in dossier["decisions"]}
        self.assertTrue(decision_versions)
        # 证据/敏感材料接触链可见
        self.assertTrue(any(e["action"] == "接触敏感材料" for e in dossier["evidence_and_pii_access"]))
        self.assertEqual(len(dossier["pii_access_register"]), 1)
        # 非值班员不能调取案件总览
        from harmhub.errors import ApiError

        with self.assertRaises(ApiError) as ctx:
            self.hub.case_dossier(self.ident("police:zhaojing"), iid)
        self.assertEqual(ctx.exception.status, 403)


class HttpApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.hub = Hub(cls.dir)
        cls.tokens = {t["sub"]: t["token"] for t in cls.hub.bootstrap_identities()}
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(cls.hub))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, sub=None, payload=None):
        headers = {"Content-Type": "application/json"}
        if sub:
            headers["Authorization"] = f"Bearer {self.tokens[sub]}"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        req = Request(f"{self.base}{path}", data=data, headers=headers, method=method)
        with urlopen(req, timeout=3) as resp:
            return resp.status, json.load(resp)

    def request_error(self, method, path, sub=None, payload=None):
        headers = {"Content-Type": "application/json"}
        if sub:
            headers["Authorization"] = f"Bearer {self.tokens[sub]}"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        req = Request(f"{self.base}{path}", data=data, headers=headers, method=method)
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        return ctx.exception.code, json.load(ctx.exception)

    def test_health_and_contract_open(self):
        _, health = self.request("GET", "/health")
        self.assertEqual(health["service"], "athlete-harm-response")
        _, contract = self.request("GET", "/contract")
        self.assertIn("限制传播", contract["protected_actions"])

    def test_auth_required_and_full_flow_over_http(self):
        code, _ = self.request_error("GET", "/incidents")
        self.assertEqual(code, 401)
        _, created = self.request("POST", "/leads", "self:lirui", THREAT)
        iid = created["incident_id"]
        # 越权确认被拒
        code, body = self.request_error("POST", f"/incidents/{iid}/actions", "platform:wangning", {"action": "限制传播"})
        self.assertEqual(code, 403)
        # 值班员确认
        self.request("POST", f"/incidents/{iid}/actions", "duty:chenchen", {"action": "限制传播"})
        _, detail = self.request("GET", f"/incidents/{iid}", "duty:chenchen")
        self.assertEqual(detail["actions"]["restrict"]["state"], "已确认")
        # PII 必须声明用途
        code, _ = self.request_error("POST", f"/incidents/{iid}/pii", "duty:chenchen", {})
        self.assertEqual(code, 400)
        _, pii = self.request("POST", f"/incidents/{iid}/pii", "police:zhaojing", {"purpose": "侦查"})
        self.assertEqual(pii["items"][0]["secret"]["contact_phone"], "13800000001")
        # 证据链核验接口（需鉴权）
        _, verify = self.request("GET", "/evidence/verify", "duty:chenchen")
        self.assertTrue(verify["chain_ok"])


if __name__ == "__main__":
    unittest.main()
