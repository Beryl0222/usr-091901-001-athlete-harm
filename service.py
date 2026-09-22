"""运动员网络侵害处置中枢的 HTTP 服务入口。

在原有 /health、/contract 基础上提供完整处置 API：
- POST   /api/v1/reports                       四入口报送线索
- GET    /api/v1/events                        案件列表（按角色过滤）
- GET    /api/v1/events/{id}                   值班席案件视图
- POST   /api/v1/events/{id}/decisions         人工确认处置（权限校验）
- POST   /api/v1/decisions/{id}/acknowledge    执法联络员接收回执
- POST   /api/v1/decisions/{id}/reverse        变更旧决定（旧决定保留）
- POST   /api/v1/events/{id}/appeals           误报申诉
- POST   /api/v1/appeals/{id}/resolve          值班席复核（可按新规则重算，旧判断保留）
- POST   /api/v1/events/{id}/supplements       平台/执法跨平台补件
- POST   /api/v1/reports/{id}/platform-status  平台回传处置情况
- POST   /api/v1/events/{id}/state             状态流转
- POST   /api/v1/contacts/read                 授权调阅联系方式（强制留痕）
- GET    /api/v1/contacts/ledger               联系方式接触台账
- GET    /api/v1/audit                         全量操作审计
- GET    /api/v1/evidence/verify               保全回执哈希链校验
- GET    /api/v1/rules                         规则版本列表
- POST   /api/v1/rules                         发布规则新版本

鉴权：Authorization: Bearer <token>。演示令牌见 README。
"""

import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pipeline import ApiError, Pipeline
from storage import ContactVault, Store

SERVICE_ID = "athlete-harm-response"
SERVICE_NAME = "运动员网络侵害处置中枢"
CONTRACT_PATH = Path(__file__).with_name("domain_contract.json")

_APP = None
_DATA_DIR = None


def load_contract():
    """读取并校验项目领域契约。"""
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if contract.get("service_id") != SERVICE_ID:
        raise ValueError("领域契约与服务身份不一致")
    return contract


def health_payload():
    """返回服务运行状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def get_app():
    """惰性构建流水线（健康检查/契约接口不触碰数据库）。"""
    global _APP
    if _APP is None:
        data_dir = Path(_DATA_DIR) if _DATA_DIR else Path(
            os.environ.get("AHR_DATA_DIR", Path(__file__).with_name("data")))
        data_dir.mkdir(parents=True, exist_ok=True)
        store = Store(data_dir / "casebook.db")
        vault = ContactVault(data_dir / "contacts.db")
        _APP = Pipeline(store, vault)
    return _APP


class Handler(BaseHTTPRequestHandler):
    """REST 接口：Bearer 鉴权 → 角色权限 → 流水线。"""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send_json(health_payload())
            return
        if path == "/contract":
            self._send_json(load_contract())
            return
        if path.startswith("/api/"):
            self._dispatch("GET", path, parse_qs(parsed.query))
            return
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self.send_error(404)
            return
        self._dispatch("POST", path, None)

    # ---- 路由与鉴权 ----
    def _dispatch(self, method, path, query):
        user = self._authenticate()
        if user is None:
            self._send_error(401, "unauthorized", "缺少或无效的 Bearer 令牌")
            return
        try:
            app = get_app()
            body = self._read_body() if method == "POST" else {}
            if body is None:
                return
            p = [x for x in path.strip("/").split("/") if x]
            result = self._route(app, user, method, p, body, query or {})
            if result is not None:
                self._send_json(result)
        except ApiError as exc:
            self._send_error(exc.status, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - 服务层兜底，避免堆栈外泄
            self._send_error(500, "internal_error", f"服务内部错误：{type(exc).__name__}")

    def _route(self, app, user, method, p, body, query):
        # /api/v1/...
        if len(p) >= 2 and p[0] == "api" and p[1] == "v1":
            p = p[2:]
        if method == "POST" and p == ["reports"]:
            return app.submit_report(user, body)
        if method == "GET" and p == ["events"]:
            return {"events": app.list_events(user)}
        if method == "GET" and len(p) == 2 and p[0] == "events":
            return app.case_view(user, p[1])
        if method == "POST" and len(p) == 3 and p[0] == "events" and p[2] == "decisions":
            return app.decide(user, p[1], body.get("decision_type"),
                              body.get("rationale", ""), body.get("action"),
                              bool(body.get("override")))
        if method == "POST" and len(p) == 3 and p[0] == "events" and p[2] == "appeals":
            return app.submit_appeal(user, p[1], body.get("reason", ""),
                                     body.get("report_id"), body.get("decision_id"))
        if method == "POST" and len(p) == 3 and p[0] == "events" and p[2] == "supplements":
            return app.add_supplement(user, p[1], body.get("kind"),
                                      body.get("payload", {}), body.get("report_id"))
        if method == "POST" and len(p) == 3 and p[0] == "events" and p[2] == "state":
            return app.set_event_state(user, p[1], body.get("state"), body.get("note", ""))
        if method == "POST" and len(p) == 3 and p[0] == "reports" and p[2] == "platform-status":
            return app.update_platform_status(user, p[1], body.get("status"),
                                              body.get("action_detail", ""))
        if method == "POST" and len(p) == 3 and p[0] == "appeals" and p[2] == "resolve":
            return app.resolve_appeal(user, p[1], body.get("resolution"),
                                      body.get("note", ""), bool(body.get("reevaluate")))
        if method == "POST" and len(p) == 3 and p[0] == "decisions" and p[2] == "acknowledge":
            return app.acknowledge_referral(user, p[1], body.get("note", ""))
        if method == "POST" and len(p) == 3 and p[0] == "decisions" and p[2] == "reverse":
            return app.reverse_decision(user, p[1], body.get("rationale", ""))
        if method == "POST" and p == ["contacts", "read"]:
            return app.read_contacts(user, body.get("subject_id"), body.get("purpose"))
        if method == "GET" and p == ["contacts", "ledger"]:
            return app.contact_ledger(user)
        if method == "GET" and p == ["audit"]:
            return {"audit": app.audit_trail(user)}
        if method == "GET" and p == ["evidence", "verify"]:
            return app.verify_evidence_chain(user)
        if method == "GET" and p == ["rules"]:
            return {"current": app.current_rule_version(),
                    "versions": app.store.query(
                        "SELECT version,note,published_by,published_at,supersedes "
                        "FROM rule_versions ORDER BY rowid")}
        if method == "POST" and p == ["rules"]:
            return app.publish_rule(user, body.get("version"), body.get("rule", {}),
                                    body.get("note", ""), body.get("supersedes"))
        raise ApiError(404, "not_found", f"未知路由：/{'/'.join(p)}")

    def _authenticate(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return get_app().authenticate(header[7:])

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error(400, "bad_json", "请求体必须是 UTF-8 JSON")
            return None
        if not isinstance(data, dict):
            self._send_error(400, "bad_json", "请求体必须是 JSON 对象")
            return None
        return data

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, code, message):
        self._send_json({"error": {"code": code, "message": message}}, status)

    def log_message(self, *_args):
        return


def run_self_check():
    """配置自检：契约完整、规则可研判、仅追加触发器真实生效、哈希链可验。"""
    contract = load_contract()
    assert contract["states"] and contract["invariants"]
    assert len(contract["roles"]) == 5
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "casebook.db")
        vault = ContactVault(Path(tmp) / "contacts.db")
        app = Pipeline(store, vault)
        # 仅追加：直接篡改必须被触发器拒绝
        store.execute("INSERT INTO audit_log(ts,actor,role,action,allowed) "
                      "VALUES('t','x','duty','probe',1)")
        import sqlite3
        try:
            store.execute("UPDATE audit_log SET actor='hacker' WHERE action='probe'")
            raise AssertionError("仅追加触发器未拦截 UPDATE")
        except sqlite3.IntegrityError:
            pass
        # 规则引擎可运行且只产出建议
        import rules
        sample = {"excerpt": "我要上门找你，等着瞧", "target_scope": 1,
                  "spread_scope": 5, "credibility": 4, "urgency": 5}
        result = rules.evaluate(sample, app.get_rule(app.current_rule_version()))
        assert result["advisory"] is True and result["category"] == "threat"
        assert store.verify_chain()["intact"] is True
    print("基础检查通过：契约完整、仅追加触发器生效、规则引擎与保全链正常")


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", default=str(Path(__file__).with_name("data")))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        run_self_check()
        return
    global _DATA_DIR
    _DATA_DIR = args.data_dir
    get_app()  # 启动即初始化数据库
    print(f"{SERVICE_NAME} 已启动：http://0.0.0.0:{args.port} （数据目录 {args.data_dir}）")
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
