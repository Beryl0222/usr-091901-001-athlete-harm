"""HTTP 接口层：令牌鉴权、路由分发与分区授权。

鉴权：`Authorization: Bearer <token>` 或 `X-Auth-Token: <token>`。
自动规则永远不借接口直接生效；保护措施接口只接受人工确认。
"""

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from .errors import ApiError


def create_handler(hub):
    """创建 HTTP 处理器类。hub 可为中枢实例或返回实例的工厂（延迟装配）。"""
    get_hub = hub if callable(hub) else lambda: hub

    class ApiHandler(BaseHTTPRequestHandler):
        server_version = "HarmHub/1.0"

        # ---------- 基础收发 ----------
        def _send_json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ApiError(400, "请求体不是合法 JSON")
            if not isinstance(payload, dict):
                raise ApiError(400, "请求体必须是 JSON 对象")
            return payload

        def _identity(self):
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else self.headers.get("X-Auth-Token", "")
            return get_hub().authenticate(token)

        def _path_segments(self):
            return [seg for seg in urlparse(self.path).path.split("/") if seg]

        def log_message(self, *_args):
            return

        # ---------- 路由 ----------
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method):
            try:
                segments = self._path_segments()
                if method == "GET" and segments == ["health"]:
                    from .config import SERVICE_ID, SERVICE_NAME

                    self._send_json({"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME})
                    return
                if method == "GET" and segments == ["contract"]:
                    from .config import load_contract

                    self._send_json(load_contract())
                    return

                route = self._match_route(method, segments)
                if route is None:
                    self.send_error(404)
                    return

                identity = self._identity()
                h = get_hub()
                body = self._read_json() if method == "POST" else {}

                kind, ids = route
                if kind == "submit_lead":
                    self._send_json(h.submit_lead(identity, body))
                elif kind == "attach_lead":
                    self._send_json(h.submit_lead(identity, body, incident_id=ids[0]))
                elif kind == "list_incidents":
                    self._send_json({"incidents": h.list_incidents(identity)})
                elif kind == "incident_detail":
                    self._send_json(h.incident_detail(identity, ids[0]))
                elif kind == "confirm_action":
                    self._send_json(h.confirm_action(identity, ids[0], body))
                elif kind == "appeal":
                    self._send_json(h.appeal(identity, ids[0], body))
                elif kind == "review_appeal":
                    self._send_json(h.review_appeal(identity, ids[0], ids[1], body))
                elif kind == "reevaluate":
                    self._send_json(h.reevaluate(identity, ids[0]))
                elif kind == "archive":
                    self._send_json(h.archive(identity, ids[0]))
                elif kind == "dossier":
                    self._send_json(h.case_dossier(identity, ids[0]))
                elif kind == "evidence_content":
                    self._send_json(h.read_evidence_content(identity, ids[0], ids[1]))
                elif kind == "view_pii":
                    self._send_json(h.view_pii(identity, ids[0], body))
                elif kind == "pii_access":
                    self._send_json({"access": h.pii_access_register(identity, ids[0])})
                elif kind == "upgrade_rules":
                    self._send_json(h.upgrade_rules(identity, body))
                elif kind == "list_rules":
                    self._send_json({"versions": h.rules.versions(), "current": h.rules.current_version()})
                elif kind == "audit":
                    self._send_json({"audit": h.audit_log(identity)})
                elif kind == "verify_chain":
                    self._send_json(h.verify_chain())
            except ApiError as error:
                self._send_json({"error": error.message}, status=error.status)
            except Exception as error:  # noqa: BLE001 - 兜底，避免堆栈外泄
                self._send_json({"error": f"服务器内部错误：{type(error).__name__}"}, status=500)

        @staticmethod
        def _match_route(method, s):
            """返回 (路由名, 路径参数)；未匹配返回 None（先于鉴权判定，避免接口枚举）。"""
            if method == "POST" and s == ["leads"]:
                return "submit_lead", []
            if method == "POST" and len(s) == 3 and s[:2] == ["incidents", "leads"]:
                return "attach_lead", [s[2]]
            if method == "GET" and s == ["incidents"]:
                return "list_incidents", []
            if method == "GET" and len(s) == 2 and s[0] == "incidents":
                return "incident_detail", [s[1]]
            if method == "POST" and len(s) == 3 and s[0] == "incidents" and s[2] == "actions":
                return "confirm_action", [s[1]]
            if method == "POST" and len(s) == 3 and s[0] == "incidents" and s[2] == "appeals":
                return "appeal", [s[1]]
            if (
                method == "POST"
                and len(s) == 5
                and s[0] == "incidents"
                and s[2] == "appeals"
                and s[4] == "review"
            ):
                return "review_appeal", [s[1], s[3]]
            if method == "POST" and len(s) == 3 and s[0] == "incidents" and s[2] == "reevaluate":
                return "reevaluate", [s[1]]
            if method == "POST" and len(s) == 3 and s[0] == "incidents" and s[2] == "archive":
                return "archive", [s[1]]
            if method == "GET" and len(s) == 3 and s[0] == "incidents" and s[2] == "dossier":
                return "dossier", [s[1]]
            if method == "GET" and len(s) == 4 and s[0] == "incidents" and s[2] == "evidence":
                return "evidence_content", [s[1], s[3]]
            if method == "POST" and len(s) == 3 and s[0] == "incidents" and s[2] == "pii":
                return "view_pii", [s[1]]
            if method == "GET" and len(s) == 4 and s[0] == "incidents" and s[2:] == ["pii", "access"]:
                return "pii_access", [s[1]]
            if method == "POST" and s == ["rules", "upgrade"]:
                return "upgrade_rules", []
            if method == "GET" and s == ["rules"]:
                return "list_rules", []
            if method == "GET" and s == ["audit"]:
                return "audit", []
            if method == "GET" and s == ["evidence", "verify"]:
                return "verify_chain", []
            return None

        def send_error(self, code, message=None):
            self._send_json({"error": message or "未找到接口"}, status=code)

    return ApiHandler
