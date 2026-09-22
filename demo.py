"""焦点比赛后的网络侵害处置全流程演示（自包含，直接运行：python3 demo.py）。

剧情：决赛后，核心队员李锐遭遇大规模辱骂与人身威胁。四个入口分别报送，
值班席完成聚合研判、人工确认、证据保全、误报申诉与规则升级，全程留痕。
演示结束后可在 ./.harmhub_demo 目录查看只读证据文件与加密保管箱。
"""

import json
import shutil
from pathlib import Path

from harmhub import Hub
from harmhub.errors import ApiError

DEMO_DIR = Path(".harmhub_demo")


def hr(title=""):
    print("\n" + "=" * 72)
    if title:
        print(title)
        print("-" * 72)


def show(label, value):
    print(f"{label}：{value}")


def main():
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    hub = Hub(DEMO_DIR)
    tokens = {t["sub"]: t["token"] for t in hub.bootstrap_identities()}

    def ident(sub):
        return hub.authenticate(tokens[sub])

    hr("① 焦点赛后 2 小时 · 四个入口陆续报送")
    threat = {
        "target": "李锐",
        "platform": "weibo",
        "url": "https://weibo.example/p/111",
        "content": "李锐就是垃圾，我知道你住哪个小区，等着，今晚上门找你！",
        "reach": 52000,
        "credibility_hint": 2,
        "hours_since_posted": 2,
        "explicit_location": True,
        "category_hints": ["人身威胁"],
        "contact_name": "李锐本人",
        "contact_phone": "138****0001",
        "private_materials": ["李锐未公开行程单.pdf"],
    }
    r1 = hub.submit_lead(ident("self:lirui"), threat)
    show("本人入口", f"立案件 {r1['incident_id']}｜风险={r1['latest_risk_level']}｜保全={r1['evidence_receipt']['evidence_id']}")

    r2 = hub.submit_lead(
        ident("club:zhangyun"),
        {
            "target": "李锐",
            "platform": "俱乐部报送",
            "url": threat["url"],
            "content": threat["content"],
            "reach": threat["reach"],
            "hours_since_posted": 2,
        },
    )
    show("俱乐部入口（同链接重复举报）", r2["merge_mode"])

    r3 = hub.submit_lead(
        ident("platform:wangning"),
        {
            "target": "李锐",
            "platform": "douyin",
            "url": "https://dy.example/v/9",
            "content": "李锐就是个废物！我知道你住哪个小区，等着，今晚上门！",
            "reach": 12000,
            "hours_since_posted": 3,
        },
    )
    show("平台入口（抖音同文改写）", f"{r3['merge_mode']}，并入同一案件")

    r4 = hub.submit_lead(
        ident("police:zhaojing"),
        {
            "target": "李锐",
            "platform": "公安报送",
            "url": "https://report.police.local/case/88",
            "content": "110 联动：报警人收到威胁私信「等着，今晚上门找你」，附嫌疑人账号",
            "reach": 1,
            "credibility_hint": 3,
        },
        incident_id=r1["incident_id"],
    )
    show("公安入口（指定案件补件）", r4["merge_mode"])

    # 俱乐部把一条正常批评作为同案补充材料报送：允许归入，但总览中必须标为“观点”
    hub.submit_lead(
        ident("club:zhangyun"),
        {
            "target": "李锐",
            "platform": "weibo",
            "url": "https://weibo.example/p/333",
            "content": "平心而论李锐最后一投选择有问题，年轻队员该多锻炼，别骂了。",
            "reach": 200,
        },
        incident_id=r1["incident_id"],
    )
    show("俱乐部补件（正常批评，同案留档）", "explicit，自动归类应为「观点」")

    hr("② 正常批评必须放行 · 自动规则只给建议")
    opinion = hub.submit_lead(
        ident("platform:wangning"),
        {
            "target": "李锐",
            "platform": "weibo",
            "url": "https://weibo.example/p/222",
            "content": "李锐今晚打得太差了，状态低迷，教练该不该换人？",
            "reach": 88,
        },
    )
    op_incident = hub._get_incident(opinion["incident_id"])
    show("批评帖自动归类", op_incident["evaluations"][-1]["categories"])
    show("批评帖建议措施", op_incident["evaluations"][-1]["suggested_actions"] or "无（仅记录，不封禁）")
    main_incident = hub._get_incident(r1["incident_id"])
    latest = main_incident["evaluations"][-1]
    show("威胁案自动建议", f"风险={latest['risk_level']}；建议动作={latest['suggested_actions']}")
    show("自动建议状态", latest["status"] + "（未确认前不生效）")

    hr("③ 权限矩阵 · 保护措施只能人工确认")
    try:
        hub.confirm_action(ident("platform:wangning"), r1["incident_id"], {"action": "限制传播"})
    except ApiError as error:
        show("平台协查员尝试限流被拒", error.message)
    d1 = hub.confirm_action(ident("duty:chenchen"), r1["incident_id"], {"action": "限制传播"})
    show("值班员确认限制传播", f"决定 {d1['id']}｜依据：{d1['basis']}｜规则版本：{d1['rule_version']}")
    d2 = hub.confirm_action(
        ident("club:zhangyun"), r1["incident_id"], {"action": "联系保护对象", "reason": "协会转办，提醒注意住所安全"}
    )
    show("俱乐部联络员确认联系保护对象", f"{d2['actor']}｜规则版本：{d2['rule_version']}")
    d3 = hub.confirm_action(ident("police:zhaojing"), r1["incident_id"], {"action": "移送执法"})
    show("公安联络员确认移送执法", f"{d3['actor']}｜案件状态：{main_incident['status']}")

    hr("④ 原始链接失效 · 时间戳+内容哈希+链式回执仍可举证")
    receipt = r1["evidence_receipt"]
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    chain = hub.verify_chain()
    show("证据哈希链核验", chain)
    show(
        "举证逻辑",
        "即使 https://weibo.example/p/111 已删除，保全时间(captured_at)+SHA-256+receipt_hash 链式回执+留存原文互相印证",
    )

    hr("⑤ 误报申诉 · 不覆盖旧判断，只追加撤销")
    # 另有一条「冒名爆料」被值班员限流，当事人申诉系玩梗，申诉成立
    leak = hub.submit_lead(
        ident("self:lirui"),
        {
            "target": "李锐",
            "platform": "xiaohongshu",
            "url": "https://xhs.example/n/55",
            "content": "知情人爆料李锐疑似女友的真实姓名和住址，速看",
            "reach": 3000,
            "hours_since_posted": 4,
        },
    )
    hub.confirm_action(ident("duty:chenchen"), leak["incident_id"], {"action": "限制传播"})
    appeal = hub.appeal(
        ident("self:lirui"), leak["incident_id"], {"reason": "该帖是球迷玩梗的旧闻合集，姓名住址均为公开且张冠李戴"}
    )
    reviewed = hub.review_appeal(
        ident("duty:chenchen"), leak["incident_id"], appeal["id"], {"uphold": False, "note": "核实为旧闻拼贴，不构成冒名爆料"}
    )
    leak_incident = hub._get_incident(leak["incident_id"])
    show("申诉结论", reviewed["resolution"]["verdict"])
    show("限流措施当前状态", leak_incident["actions"]["restrict"]["state"])
    show("历史决定是否保留", "是 —— 原始确认与撤销决定各一条，均可审计")

    hr("⑥ 规则升级 · 新版本生效，旧判断冻结")
    hub.upgrade_rules(
        ident("duty:chenchen"),
        {"version": "rules-2026.09.1", "notes": "提高辱骂类阈值；涉具体地址的人身威胁保持紧急"},
    )
    new_eval = hub.reevaluate(ident("duty:chenchen"), r1["incident_id"])
    show("复评采用版本", new_eval["rule_version"])
    show("历次评估版本", [e["rule_version"] for e in main_incident["evaluations"]])
    old_confirm = next(d for d in main_incident["decisions"] if d["id"] == d1["id"])
    show("原限流决定的规则版本不变", old_confirm["rule_version"])

    hr("⑦ 敏感材料分区 · 凭用途解密，全程留痕")
    try:
        hub.view_pii(ident("platform:wangning"), r1["incident_id"], {"purpose": "好奇看看"})
    except ApiError as error:
        show("平台协查员接触联系方式被拒", error.message)
    pii = hub.view_pii(ident("duty:chenchen"), r1["incident_id"], {"purpose": "安排今晚保护性联系"})
    show("值班员凭用途解密", f"联系电话={pii['items'][0]['secret']['contact_phone']}，未公开材料={pii['items'][0]['secret']['private_materials']}")
    register = hub.pii_access_register(ident("duty:chenchen"), r1["incident_id"])
    show("接触登记", f"{len(register)} 人次：" + "；".join(f"{x['actor']} 用途「{x['purpose']}」" for x in register))

    hr("⑧ 值班席案件总览（dossier）")
    dossier = hub.case_dossier(ident("duty:chenchen"), r1["incident_id"])
    show("观点类内容", f"{len(dossier['opinion_content'])} 条（本案件内补件）")
    show("触发保护的行为", [(x["platform"], x["categories"]) for x in dossier["actionable_content"]])
    show("已生效/撤销的保护措施", [(p["action"], p["state"]) for p in dossier["protections"]])
    show("证据保全", f"{len(dossier['evidence'])} 份，哈希链完好={dossier['evidence_chain_ok']}")
    show("每次决定的规则版本", sorted({d["rule_version"] for d in dossier["decisions"]}))
    show("证据/敏感材料接触链条目", len(dossier["evidence_and_pii_access"]))

    hub.archive(ident("duty:chenchen"), r1["incident_id"])
    show("案件归档", main_incident["status"])

    print("\n演示完成。可检查落地产物：")
    print(f"  - 只读证据原文：{DEMO_DIR}/evidence/*.bin（0444）")
    print(f"  - 加密保管箱：{DEMO_DIR}/vault.json（联系方式密文，磁盘不可读）")
    print(f"  - 全量状态与审计：{DEMO_DIR}/state.json")


if __name__ == "__main__":
    main()
