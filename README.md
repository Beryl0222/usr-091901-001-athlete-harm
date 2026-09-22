# 运动员网络侵害处置中枢

为体育协会值班席提供**线索归集、风险分级、证据保全和人工处置**的统一后端。比赛结束后的数小时内，辱骂、冒名爆料与人身威胁从各平台涌入，本系统帮助值班席回答四个问题：

1. 这些分散的链接是不是同一件事？（按对象、主张、内容哈希聚合同源事件）
2. 哪些只是观点和正常批评，哪些行为触发保护措施？（规则引擎只给建议）
3. 原始链接失效后，怎么证明"当时所见"？（时间戳 + 内容哈希 + 链式保全回执）
4. 每条结论是谁、按哪版规则、在什么证据上作出的？报案人联系方式谁接触过？（全量审计 + 联系方式物理隔离）

## 快速开始

```bash
python3 service.py --check          # 配置自检（契约/仅追加触发器/规则引擎/保全链）
python3 service.py --port 8000      # 启动服务（默认数据目录 ./data）
python3 -m unittest -v              # 23 项端到端测试
```

无第三方依赖，仅需 Python 3 标准库。

## 角色与演示令牌

| 角色 | Bearer 令牌 | 报送入口 | 关键权限 |
| --- | --- | --- | --- |
| 保护对象（林晓） | `tok_self_lin` | self | 本人报送、本人申诉 |
| 俱乐部联络员 | `tok_club_tiger` | club | 队内报送 |
| 平台协查员（微博/抖音） | `tok_plat_weibo` / `tok_plat_douyin` | platform | 报送、跨平台补件、回传平台处置状态 |
| 协会值班员 | `tok_duty` | 全部 | 确认限制传播、联系保护对象、移送执法、发布规则、复核申诉、调阅联系方式 |
| 公安联络员 | `tok_police` | police | 报送/补件、查看已移送案件、出具执法接收回执 |

所有接口需 `Authorization: Bearer <token>`；`/health`、`/contract` 无需鉴权。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/reports` | 四个入口提交线索（`channel`: self/club/platform/police） |
| GET | `/api/v1/events` | 案件列表（按角色可见性过滤） |
| GET | `/api/v1/events/{id}` | 值班席案件视图（见下） |
| POST | `/api/v1/events/{id}/decisions` | 人工确认：`restrict` / `protect_contact` / `refer_law_enforcement`；偏离建议须 `override=true`+理由 |
| POST | `/api/v1/decisions/{id}/acknowledge` | 公安联络员确认接收移送（仅一次，仅追加） |
| POST | `/api/v1/decisions/{id}/reverse` | 变更旧决定（新决定 supersedes 旧决定，旧决定保留） |
| POST | `/api/v1/events/{id}/appeals` | 误报申诉（固化申诉时点研判 ID） |
| POST | `/api/v1/appeals/{id}/resolve` | 值班员复核；`reevaluate=true` 按当前规则重新研判，旧研判保留 |
| POST | `/api/v1/events/{id}/supplements` | 平台/执法补件；带 `snapshot` 时自动追加证据保全 |
| POST | `/api/v1/reports/{id}/platform-status` | 平台回传下架/屏蔽等处置状态 |
| POST | `/api/v1/events/{id}/state` | 状态流转：已接收/待核验/保护处置中/待申诉/已归档 |
| POST | `/api/v1/contacts/read` | 凭**事由**调阅联系方式，每次接触留痕 |
| GET | `/api/v1/contacts/ledger` | 联系方式接触台账（授权 + 拒绝都记录） |
| GET | `/api/v1/audit` | 全量操作审计 |
| GET | `/api/v1/evidence/verify` | 重算保全回执哈希链 |
| GET/POST | `/api/v1/rules` | 规则版本列表 / 发布新版本（不可改旧版本） |

报送示例：

```bash
curl -X POST localhost:8000/api/v1/reports \
  -H "Authorization: Bearer tok_plat_weibo" -H "Content-Type: application/json" \
  -d '{"channel":"platform","subject_id":"s_lin","content_url":"https://...",
       "excerpt":"今晚上门找你，等着瞧",
       "target_scope":1,"spread_scope":5,"credibility":4,"urgency":5,
       "claim_key":"claim-001"}'
```

四维评分均为 1–5：`target_scope`（针对对象的明确程度）、`spread_scope`（传播范围）、
`credibility`（来源可信度）、`urgency`（紧迫程度）。

## 值班席案件视图里有什么

`GET /api/v1/events/{id}` 在一个响应中回答：

- **`viewpoint_vs_action`**：`opinion_only`（观点/正常批评，不触发任何措施）与
  `protection_triggered`（辱骂/冒名/威胁，附触发行为 `triggers`）两栏分开；
- **`reports` + `assessments_timeline`**：每条线索的每次研判及其规则版本，规则升级前后的判断并排可见；
- **`evidence`**：证据清单、保全回执（`captured_at` 时间戳、`content_hash`、链式 `chain_hash`）、
  当场重算的链校验结果；
- **`decisions`**：每个人工决定、决定人、所依据的 `rule_version` 与 `assessment_id`、移送接收回执；
- **`appeals` / `supplements` / `state_timeline`**：申诉与复核结论、跨平台补件、完整状态时间线；
- **`contacts_included: false`**：案件视图永远不含联系方式（见隔离设计）。

## 领域不变量如何落地

领域契约（`domain_contract.json`）中的每条不变量都有机制保障，而非约定：

1. **自动分析只形成建议** — 规则引擎只写 `assessments`（`advisory=1`）；
   限制传播/联系保护对象/移送执法的 HTTP 路径做角色权限校验，平台协查员调用直接 403。
   人工可以偏离建议，但必须显式 `override=true` 并书面说明理由。
2. **证据可证明"当时所见"** — 每条线索入库即保全：UTC 时间戳、SHA-256 内容哈希、
   快照文本；回执按出具顺序构成**哈希链**（后一条包含前一条的 `chain_hash`），
   任意一条被改动，`/api/v1/evidence/verify` 立即报告断点。无链接的线下内容同样可保全。
3. **旧判断永不被覆盖** — `reports/evidences/receipts/assessments/decisions/appeals/
   supplements/rule_versions/audit_log` 等全部业务表挂载 SQLite
   `BEFORE UPDATE/DELETE` 触发器，篡改在数据库层即被拒绝（有测试验证）。
   - 重复举报 → 追加 `supplements(repeat_report)`，沿用既有研判，新评分不重算；
   - 跨平台补件 → 追加新证据行，旧证据保留；
   - 误报申诉 → 固化申诉时点的研判 ID；复核可按新规则**另存**新研判，旧研判、旧决定原样保留；
   - 规则升级 → 新版本只影响之后的研判与重算请求，版本号不可复用；
   - 变更决定 → 新决定行引用 `supersedes_decision_id`，旧行保留。
4. **联系方式严格隔离** — 联系方式与未公开身份材料存于独立数据库文件
   `contacts.db`，与案件研判库 `casebook.db` 没有任何连接；案件视图的 JSON 经测试确认
   不含联系方式。调阅仅限值班员、必须填事由，授权与拒绝访问都写入独立接触台账。

## 代码结构

| 文件 | 职责 |
| --- | --- |
| `domain_contract.json` | 领域契约：角色权限矩阵、入口、决策类型、状态、分类、不变量、规则版本沿革 |
| `storage.py` | SQLite 双库：仅追加表 + 触发器、哈希链回执、联系方式保封库与接触台账 |
| `rules.py` | 版本化规则引擎：四维评分、观点/辱骂/冒名/威胁判定，产物恒为建议 |
| `pipeline.py` | 领域流水线：鉴权、归集聚合、保全、人工决策、申诉复核、补件、案件视图 |
| `service.py` | HTTP 层：Bearer 鉴权、路由、`--check` 自检，保留 `/health`、`/contract` |
| `test_service.py` | 23 项测试：含仅追加触发器拦截、哈希链、规则升级不覆盖、越权留痕等 |

生产化提示：演示令牌直接写在种子数据中，部署前应替换为外部身份提供者签发的令牌；
SQLite 文件应置于加密磁盘并按值班席运维制度备份；规则词典目前为内置中文关键词示例，
可在发布新规则版本时随版本演进。
