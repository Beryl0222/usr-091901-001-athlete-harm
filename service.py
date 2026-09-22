"""运动员网络侵害处置中枢的服务入口。

用法：
  python3 service.py --check                    # 配置与证据链自检
  python3 service.py --port 8000                # 启动 HTTP 服务（默认数据目录 ./.harmhub_data）
  python3 service.py --data ./data --print-tokens   # 指定数据目录并初始化/打印各入口令牌

保留基础契约接口：GET /health、GET /contract，以及模块级
Handler / SERVICE_ID / health_payload / load_contract 供既有测试使用。
"""

import argparse
import os
from http.server import ThreadingHTTPServer

from harmhub.api import create_handler
from harmhub.config import CONTRACT_PATH, SERVICE_ID, SERVICE_NAME, load_contract

DEFAULT_DATA_DIR = os.environ.get("HARMHUB_DATA", ".harmhub_data")

_hub = None
_hub_dir = None


def get_hub(data_dir=DEFAULT_DATA_DIR):
    """进程内共享的中枢实例（懒加载）。"""
    global _hub, _hub_dir
    if _hub is None or _hub_dir != str(data_dir):
        from harmhub import Hub

        _hub = Hub(data_dir)
        _hub_dir = str(data_dir)
    return _hub


def health_payload():
    """返回服务运行状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


# 既有测试直接 `ThreadingHTTPServer(addr, Handler)`；这里以工厂方式延迟装配，
# 仅在首个请求到达时才创建默认数据目录。
Handler = create_handler(lambda: get_hub())


def self_check(data_dir=DEFAULT_DATA_DIR):
    contract = load_contract()
    assert contract["states"] and contract["invariants"]
    assert {"channels", "protected_actions", "state_machine"} <= set(contract)
    hub = get_hub(data_dir)
    chain_ok, broken = hub.evidence.verify_chain()
    assert chain_ok, f"证据保全链断裂于：{broken}"
    return contract, hub


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data", default=DEFAULT_DATA_DIR, help="数据与证据目录")
    parser.add_argument("--check", action="store_true", help="配置与证据链自检")
    parser.add_argument("--print-tokens", action="store_true", help="初始化并打印各入口令牌")
    args = parser.parse_args()

    hub = get_hub(args.data)

    if args.check:
        contract, hub = self_check(args.data)
        print("基础检查通过")
        print(f"  服务：{SERVICE_ID} / 契约版本 {contract['contract_version']}")
        print(f"  规则版本：{hub.rules.versions()}（当前 {hub.rules.current_version()}）")
        print("  证据保全链：完好")
        return

    if args.print_tokens:
        tokens = hub.bootstrap_identities()
        if tokens is None:
            print("入口令牌此前已初始化，明文不再保存；如需重置请清空数据目录。")
        else:
            print(f"以下入口令牌仅显示一次，请分发给对应人员并妥善保存（数据目录：{args.data}）：")
            for item in tokens:
                print(f"  [{item['actor']}] {item['label']}")
                print(f"    {item['token']}")

    server = ThreadingHTTPServer(("0.0.0.0", args.port), create_handler(hub))
    print(f"{SERVICE_NAME}已启动：http://0.0.0.0:{args.port}（/health、/contract、/incidents 等）")
    server.serve_forever()


if __name__ == "__main__":
    main()
