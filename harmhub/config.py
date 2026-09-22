"""运行配置与领域契约装载。"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = ROOT / "domain_contract.json"

SERVICE_ID = "athlete-harm-response"
SERVICE_NAME = "运动员网络侵害处置中枢"


def load_contract(path=CONTRACT_PATH):
    """读取并校验领域契约。"""
    contract = json.loads(Path(path).read_text(encoding="utf-8"))
    if contract.get("service_id") != SERVICE_ID:
        raise ValueError("领域契约与服务身份不一致")
    required = ("actors", "states", "invariants", "channels", "protected_actions")
    missing = [key for key in required if key not in contract]
    if missing:
        raise ValueError(f"领域契约缺少必要字段：{missing}")
    return contract
