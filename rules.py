"""版本化规则引擎。

引擎的唯一产物是 *建议*（advisory）：给出评分、类别与建议动作，
永远不直接限制传播、联系保护对象或移送执法——这些必须由有权限的人确认。
规则版本一经发布不可修改；新版本只覆盖之后产生的研判，旧研判永久保留其规则版本。
"""

import re

# ---- 语义词典（演示用，可随规则版本演进而增删） ----
OPINION_MARKERS = ["打得差", "状态低迷", "令人失望", "批评", "质疑", "不应该上场", "战术问题"]
ABUSE_MARKERS = ["垃圾", "滚出", "脑残", "废物", "去死", "恶心", "不要脸", "白痴"]
HARM_INTENT_MARKERS = ["杀了", "打死", "弄死", "砍", "血洗", "灭门", "等着瞧",
                       "上门找你", "让你消失", "报复你", "别想活着"]
IMPERSONATION_MARKERS = ["内部人爆料", "冒名", "我是他同学", "实名爆料", "知情人士曝",
                         "聊天记录流出", "开房记录", "黑料包"]

# 各版本阈值与权重。已发布版本只能被新版本 supersede，禁止原地修改。
RULE_VERSIONS = {
    "2026-09-22-r1": {
        "version": "2026-09-22-r1",
        "note": "初始评分规则，辱骂与威胁共用紧迫度阈值",
        "weights": {"target_scope": 0.25, "spread_scope": 0.25,
                    "credibility": 0.2, "urgency": 0.3},
        "threat": {"require_phrase_and_credibility": None,
                   "urgency_gte": 4, "credibility_gte": 3},
        "impersonation_autodetect": False,
        "abuse_risk_gte": 2.5,
    },
    "2026-09-22-r2": {
        "version": "2026-09-22-r2",
        "note": "收紧威胁判定：显式伤害意图+可信来源即建议联系保护；新增冒名爆料类别",
        "weights": {"target_scope": 0.2, "spread_scope": 0.25,
                    "credibility": 0.25, "urgency": 0.3},
        "threat": {"require_phrase_and_credibility": 2,
                   "urgency_gte": 4, "credibility_gte": 3},
        "impersonation_autodetect": True,
        "abuse_risk_gte": 2.5,
    },
}

CURRENT_VERSION = "2026-09-22-r2"

SUGGESTION_TEXT = {
    "advise_restrict": "建议由协会值班员确认后采取限制传播措施",
    "advise_protect_contact": "建议由协会值班员立即联系保护对象并启动保护措施",
    "consider_refer": "建议评估移送执法（由值班员发起、执法联络员接收）",
}

CATEGORY_TEXT = {
    "opinion": "观点与正常批评",
    "abuse": "辱骂诽谤等一般侵害",
    "impersonation": "冒名爆料",
    "threat": "人身威胁等紧迫侵害",
}


def get_rule(version=CURRENT_VERSION):
    if version not in RULE_VERSIONS:
        raise KeyError(f"未知规则版本: {version}")
    return RULE_VERSIONS[version]


def _contains_any(text, markers):
    return [m for m in markers if m in text]


def risk_score(report, rule):
    weights = rule["weights"]
    dims = {k: int(report[k]) for k in
            ("target_scope", "spread_scope", "credibility", "urgency")}
    total = round(sum(dims[k] * weights[k] for k in dims), 3)
    return dims, total


def classify(report, version=CURRENT_VERSION):
    """对单条线索做规则研判，返回结构化建议（不含任何处置效力）。"""
    return evaluate(report, get_rule(version))


def evaluate(report, rule):
    """用给定（可能来自数据库的新版本）规则字典执行研判。"""
    version = rule["version"]
    dims, total = risk_score(report, rule)
    text = report.get("excerpt", "") or ""
    hint = report.get("category_hint")

    hits_harm = _contains_any(text, HARM_INTENT_MARKERS)
    hits_abuse = _contains_any(text, ABUSE_MARKERS)
    hits_impersonation = _contains_any(text, IMPERSONATION_MARKERS)
    hits_opinion = _contains_any(text, OPINION_MARKERS)

    triggers = []
    category = "opinion"
    suggestions = []

    # 威胁：r2 起，显式伤害意图 + 可信度达阈值即判威胁；两版本都保留高紧迫+高可信通道。
    threat_by_phrase = False
    need_cred = rule["threat"]["require_phrase_and_credibility"]
    if hits_harm and (need_cred is None or dims["credibility"] >= need_cred):
        threat_by_phrase = True
    threat_by_score = dims["urgency"] >= rule["threat"]["urgency_gte"] and \
        dims["credibility"] >= rule["threat"]["credibility_gte"]
    if hint == "threat" or threat_by_phrase or threat_by_score:
        category = "threat"
        if hits_harm:
            triggers.append(f"显式伤害意图表述：{ '、'.join(hits_harm) }")
        if threat_by_score:
            triggers.append(
                f"紧迫度{dims['urgency']}/可信度{dims['credibility']}达威胁阈值")
        suggestions = ["advise_protect_contact", "consider_refer"]

    # 冒名爆料：r2 起支持自动识别，r1 只接受人工 hint。
    if category == "opinion" and (
            hint == "impersonation" or
            (rule["impersonation_autodetect"] and hits_impersonation)):
        category = "impersonation"
        triggers.append(f"冒名/爆料特征：{ '、'.join(hits_impersonation) or '人工标记' }")
        suggestions = ["advise_restrict"]

    # 辱骂诽谤。
    if category == "opinion" and (hint == "abuse" or (
            hits_abuse and total >= rule["abuse_risk_gte"])):
        category = "abuse"
        triggers.append(f"辱骂性表述：{ '、'.join(hits_abuse) }")
        suggestions = ["advise_restrict"]

    # 纯观点/批评：无任何保护性触发，仅记录统计。
    if category == "opinion" and hits_opinion:
        triggers.append("仅含观点表达或正常批评，不触发保护措施")

    rationale = (
        f"规则{version}：四维评分{dims}，加权风险{total}；"
        f"命中行为【{ '；'.join(triggers) or '无' }】，归类为{CATEGORY_TEXT[category]}。"
        "本结果为自动建议，不产生处置效力。")

    return {
        "rule_version": version,
        "scores": {"dimensions": dims, "risk_total": total},
        "category": category,
        "category_text": CATEGORY_TEXT[category],
        "suggestions": suggestions,
        "suggestion_text": [SUGGESTION_TEXT[s] for s in suggestions],
        "triggers": triggers,
        "rationale": rationale,
        "advisory": True,
    }


def merge_assessments(results):
    """事件级聚合研判：取同源线索中的最高类别与建议并集，仍为建议。"""
    rank = {"opinion": 0, "abuse": 1, "impersonation": 2, "threat": 3}
    worst = max(results, key=lambda r: rank[r["category"]]) if results else None
    suggestions = sorted({s for r in results for s in r["suggestions"]})
    versions = sorted({r["rule_version"] for r in results})
    spread_values = [r["scores"]["dimensions"]["spread_scope"] for r in results]
    worst_category = worst["category"] if worst else "opinion"
    return {
        "category": worst_category,
        "category_text": CATEGORY_TEXT[worst_category],
        "suggestions": suggestions,
        "suggestion_text": [SUGGESTION_TEXT[s] for s in suggestions],
        "rule_versions_in_event": versions,
        "report_count": len(results),
        "max_spread_scope": max(spread_values, default=0),
        "advisory": True,
    }
