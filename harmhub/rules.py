"""版本化自动规则引擎。

不可破坏的原则：
- 规则只产出「风险建议」与「建议动作」，绝不直接执行限制传播/联系保护对象/移送执法；
- 规则版本不可变，升级时新建版本并冻结旧版本；
- 每条线索评估时快照当时规则版本，后续升级不改变历史判断（历史只读、新评估单独追加）。

评估四个维度（与领域契约一致）：对象、传播范围、可信度、紧迫程度。
"""

import re

from .util import new_id, utcnow

CATEGORIES = ("观点", "辱骂", "冒名爆料", "人身威胁")

# 触发保护的行为类别（观点不在其中，只记录、不处置）。
ACTIONABLE = {"辱骂", "冒名爆料", "人身威胁"}

_THREAT_PATTERNS = [
    r"杀|弄死|砍死|打死|陪葬|血洗|灭门",
    r"我知道你(住|家|地址)|堵(你|到你家门口)|上门找你|蹲你",
    r"小心点|等着|别出门|不会放过你",
]
_ABUSE_PATTERNS = [
    r"垃圾|废物|滚出|恶心|无耻|去死|傻逼|脑残|畜生|人渣",
]
_IMPERSONATION_PATTERNS = [
    r"爆料|内部消息|知情人|据(说|悉)|疑似.*女友|疑似.*住址|真实姓名|身份证|户籍",
]

OPINION_MARKERS = ["打得差", "状态差", "失望", "批评", "不该上场", "换人", "下课"]


class RuleEngine:
    def __init__(self, store):
        self.store = store

    # ---------- 版本管理 ----------
    def ensure_seed(self, version, notes):
        with self.store.lock:
            if version not in self.store.state["rules"]:
                self.store.state["rules"][version] = {
                    "version": version,
                    "created_at": utcnow(),
                    "frozen": False,
                    "notes": notes,
                }
                self.store.save()
            return self.store.state["rules"][version]

    def versions(self):
        with self.store.lock:
            return list(self.store.state["rules"].keys())

    def current_version(self, preferred=None):
        with self.store.lock:
            if preferred:
                if preferred not in self.store.state["rules"]:
                    raise KeyError(preferred)
                return preferred
            return sorted(self.store.state["rules"].keys())[-1]

    def upgrade(self, new_version, notes, published_by):
        """发布新版本：冻结旧版本，新版本从发布起生效，旧判断保持不变。"""
        with self.store.lock:
            if new_version in self.store.state["rules"]:
                raise ValueError("规则版本已存在")
            for meta in self.store.state["rules"].values():
                meta["frozen"] = True
            self.store.state["rules"][new_version] = {
                "version": new_version,
                "created_at": utcnow(),
                "frozen": False,
                "notes": notes,
            }
            self.store.audit(published_by, "规则升级", target=new_version, detail={"notes": notes})
            self.store.save()
            return self.store.state["rules"][new_version]

    # ---------- 自动评估 ----------
    def classify_content(self, text, hint=None):
        """返回自动识别的类别集合。显式声明 hint 优先纳入，但观点永远可被识别。"""
        cats = set()
        for label, patterns in (
            ("人身威胁", _THREAT_PATTERNS),
            ("辱骂", _ABUSE_PATTERNS),
            ("冒名爆料", _IMPERSONATION_PATTERNS),
        ):
            if any(re.search(p, text or "") for p in patterns):
                cats.add(label)
        if hint:
            for item in hint:
                if item in CATEGORIES:
                    cats.add(item)
        if not cats:
            cats.add("观点")
        return sorted(cats)

    def evaluate(self, lead, rule_version):
        """对一条线索按指定规则版本做评估，产出风险建议（不产生任何处置效果）。"""
        text = lead.get("content", "")
        categories = self.classify_content(text, lead.get("category_hints"))
        is_opinion_only = categories == ["观点"]

        reach = int(lead.get("reach", 0) or 0)
        credibility = self._score_credibility(lead)
        urgency_score, urgency_reasons = self._score_urgency(lead, categories)

        # 传播范围评分：0-3
        reach_score = 3 if reach >= 10000 else 2 if reach >= 1000 else 1 if reach >= 100 else 0

        # 综合风险（满分 12）：传播范围 0-3、可信度 0-3、紧迫程度 0-3、行为性质 0-3
        nature = 0 if is_opinion_only else 3 if "人身威胁" in categories else 2
        total = reach_score + credibility + urgency_score + nature

        if total >= 9:
            level = "紧急"
        elif total >= 6:
            level = "高"
        elif total >= 3:
            level = "中"
        else:
            level = "低"
        if is_opinion_only:
            level = "低"

        suggested = []
        if not is_opinion_only:
            if "人身威胁" in categories or urgency_score >= 3:
                suggested.append("联系保护对象")
                suggested.append("移送执法")
            suggested.append("限制传播")

        return {
            "id": new_id("sug"),
            "at": utcnow(),
            "rule_version": rule_version,
            "automated": True,
            "categories": categories,
            "is_opinion_only": is_opinion_only,
            "scores": {
                "传播范围": reach_score,
                "可信度": credibility,
                "紧迫程度": urgency_score,
                "行为性质": nature,
                "总分": total,
            },
            "urgency_reasons": urgency_reasons,
            "risk_level": level,
            "suggested_actions": suggested,
            "status": "待确认",
        }

    def _score_credibility(self, lead):
        score = int(lead.get("credibility_hint", 0) or 0)
        if lead.get("channel") in ("platform", "police"):
            score += 1
        if lead.get("evidence_verified"):
            score += 1
        return max(0, min(3, score))

    def _score_urgency(self, lead, categories):
        reasons = []
        score = 0
        if "人身威胁" in categories:
            score += 3
            reasons.append("内容含人身威胁表述")
        hours = lead.get("hours_since_posted")
        if hours is not None and hours <= 6 and ("辱骂" in categories or "冒名爆料" in categories):
            score += 1
            reasons.append("发布6小时内且仍在扩散")
        if int(lead.get("reach", 0) or 0) >= 10000:
            score = max(score, 2)
            reasons.append("传播过万")
        if lead.get("explicit_location"):
            score = max(score, 3)
            reasons.append("出现具体地址或行踪信息")
        return min(3, score), reasons
