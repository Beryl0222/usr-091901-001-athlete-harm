# 运动员网络侵害处置中枢（HarmHub）

为体育协会值班席提供**线索归集、风险分级、证据保全和人工处置**的统一后端。一场焦点比赛后，
本人、俱乐部、平台、公安联络员从各自入口提交线索；系统按对象、传播范围、可信度、紧迫程度
聚合同源事件；自动规则只给风险建议；限制传播、联系保护对象、移送执法必须由有权人员人工确认。

## 快速开始

```bash
python3 service.py --check                 # 配置与证据保全链自检
python3 service.py --data ./data --print-tokens   # 初始化并打印六个入口令牌（仅显示一次）
python3 service.py --port 8000 --data ./data      # 启动服务
python3 demo.py                             # 自包含全流程演示（无需起服务）
python3 -m unittest -v                      # 22 个契约/端到端/HTTP 测试
```

健康与契约接口无需鉴权：`GET /health`、`GET /contract`。其余接口需请求头
`Authorization: Bearer <入口令牌>`。

## 角色与入口

| 入口令牌 | 角色 | 能做什么 |
| --- | --- | --- |
| `self:*` | 保护对象 | 提交本人线索、对本人案件申诉/补件；彼此互不可见 |
| `club:*` | 俱乐部联络员 | 提交/补件、确认「联系保护对象」 |
| `platform:*` | 平台协查员 | 提交/跨平台补件（自动处置不授权） |
| `duty:*` | 协会值班员 | 全部案件视图、确认三类保护措施、复核申诉、规则升级、接触 PII |
| `police:*` | 执法联络员 | 公安报送、确认「移送执法」、按授权接触 PII |

权限矩阵固化在 `domain_contract.json` 的 `protected_actions`，由服务端强制执行。

## 核心接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /leads` | 任意入口提交线索（自动同源聚合：新建/重复举报/跨平台补件/同源佐证） |
| `POST /incidents/{id}/leads` | 向指定案件补件 |
| `GET /incidents` / `GET /incidents/{id}` | 案件列表（按角色过滤）/ 案件详情 |
| `POST /incidents/{id}/actions` | **人工确认**保护措施：限制传播 / 联系保护对象 / 移送执法 |
| `POST /incidents/{id}/appeals`、`.../appeals/{aid}/review` | 误报申诉与值班员复核 |
| `POST /incidents/{id}/reevaluate` | 规则升级后按新版本追加复评 |
| `GET /incidents/{id}/dossier` | 值班席案件总览（观点/侵害分类、措施、证据接触链、规则版本） |
| `GET /incidents/{id}/evidence/{evid}` | 调阅保全原文（调阅行为入审计） |
| `POST /incidents/{id}/pii`、`GET .../pii/access` | 凭用途解密联系方式；接触登记册 |
| `POST /rules/upgrade`、`GET /rules` | 规则版本升级（旧版冻结）/ 版本列表 |
| `GET /evidence/verify`、`GET /audit` | 证据哈希链核验、全量审计日志 |

## 不可破坏的业务原则

1. **自动分析只形成建议。** 规则引擎（`harmhub/rules.py`）输出 `风险等级 + 建议动作`，
   状态恒为「待确认」；没有任何代码路径让建议自动生效。人工超建议处置必须填写理由。
2. **人工确认 + 权限矩阵。** 三类保护措施按契约授权校验（403）；已确认措施不可重复决定，
   情形变化只能追加新决定。
3. **历史只追加、不覆盖。**
   - 误报申诉：原始确认决定保留，申诉成立时追加「撤销」决定；
   - 规则升级：发布即冻结旧版本，复评只新增评估（`supersedes` 指向旧评估），
     每次决定永久记录作出时的 `rule_version`；
   - 重复举报：标记 `is_duplicate_of`，不触发新评估；
   - 跨平台补件/重新取证：新建证据记录（`supersedes` 关联旧记录），旧记录不动。
4. **证据可在链接失效后举证。** 每次取证保存归一化原文（只读 0444 文件）、SHA-256 内容哈希、
   UTC 保全时间，并以 `prev_hash` 串成哈希链；回执含 `receipt_hash`。任一文件被篡改，
   `GET /evidence/verify` 立即定位断裂节点。
5. **敏感材料分区。** 报案人联系方式与未公开身份材料进入独立**加密保管箱**
   （Encrypt-then-MAC，密钥独立文件 `pii.key` 0600），研判区只有「是否存在」的元信息；
   仅值班员/执法联络员凭**明确用途**解密，每次接触写入 `pii_access` 登记册并同步审计。
6. **观点不封禁。** 纯批评内容自动归类为「观点」，风险低且不产生任何建议措施；案件总览
   将「观点类」与「触发保护的行为」分列呈现。

## 数据落地（默认 `./.harmhub_data/`，可用 `--data` 更换）

- `state.json`（0600）：案件、线索元信息、评估/决定/申诉历史、规则版本、审计日志；
- `vault.json`（0600）：PII 密文，磁盘上不含明文；
- `pii.key`（0600）：保管箱密钥，已被 `.gitignore` 忽略；
- `evidence/*.bin`（0444）：只读保全原文。

## 代码结构

```
domain_contract.json      领域契约：角色/入口/状态机/权限矩阵/不变量/规则维度
service.py                启动入口与 --check
harmhub/
  config.py               契约装载
  rules.py                版本化规则引擎（只出建议）
  evidence.py             内容哈希 + 时间戳 + 哈希链保全回执
  security.py             PII 加密保管箱
  storage.py              JSON 状态存储 + 追加式审计
  workflow.py             归集/聚合/确认/申诉/升级/案件总览
  api.py                  HTTP 路由、鉴权与分区授权
test_service.py           基础契约测试（随首个提交保留）
test_harmhub.py           端到端与 HTTP 测试（19 项，全套共 22 项）
demo.py                   焦点赛事全流程演示
```
