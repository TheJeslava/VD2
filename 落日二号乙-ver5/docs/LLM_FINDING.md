# LLM-finding（DeepFinder）设计

> 目标：让落日二号乙具备 AutoCVE Finding 阶段的「自主发现」能力，同时保持零工具调用契约。

## 1. 与 AutoCVE 的关系

| 维度 | AutoCVE Finding | 落日二号 DeepFinder |
|---|---|---|
| 判断标准 | CVE 级、零误报、完整 source→sink、可复现 POC | 同一套标准，prompt 结构对齐 |
| 代码获取 | 模型调 Read / Grep / Glob / Bash | Python 装 CODE PACK，模型只读输入 |
| 提交方式 | `FinalizeFinding` 工具 | 严格 JSON（`findings` / `summary` / `coverage`） |
| 循环 | 多轮工具调用 | 一次调用 |
| 校验 | 运行时工具校验 | 服务端白名单 + 行号 clamp + 片段回填 |
| 产物 | finding | `Candidate(origin=llm_finding)` → finding + 确定性 POC |

`prompts/deep_finder.md` 保留了 AutoCVE Finding prompt 的主干：角色与使命、核心原则、按 CVE 接受率排序的漏洞梯队、审计方式、利用链规范、POC 规范、字段说明、终止条件、评分取舍；删除了工具协议、Skill 协议、Runtime Memory OS，换成 CODE PACK 说明与「没有工具」的硬约束。

## 2. 为什么不用工具

落日二号的整条管线依赖三个性质：可预测、可复现、安全边界清晰。工具调用会同时破坏三者：

- 模型可以读到预算外的文件，报告无法复现「模型当时看到了什么」；
- 工具参数/返回值是又一条注入通道；
- 成本与轮次不可控，难以做 per-run 预算。

因此 DeepFinder 把「读」交给确定性代码，把「判断」留给模型。这不是能力退化：对单文件/单模块的审计，把相关代码按行号内联，模型拿到的上下文往往比多次 grep 更完整。

## 3. CODE PACK

### 3.1 选文件

- 跳过：SafetyGuard 隔离文件、二进制、`lines < 3`、`size > 400KB`、非可审计语言（XML 仅在含 `${` 时保留）；
- 打分：端点文件 +8、入口命名（Controller/Servlet/Filter/…）+4、鉴权命名/正文 +5、sink 密度（≤4）、source 密度（≤2）、超大文件 −2；
- 取前 `llm_finding_max_files`（默认 12）个。

### 3.2 切窗口

- 完整文件放得下就整篇给；
- 放不下时按 sink/source 命中行取 ±35 行窗口，合并重叠，每文件最多 240 行；
- 每行前缀 `0001|`，模型可以精确引用行号；
- 每文件字符上限 `budget / 文件数`（1200–7000），超出时截断并标记。

### 3.3 预算

`llm_finding_budget` 默认 36000 字符（4000–44000）。`llm_finding_max_files` 默认 12，可用环境变量 `SUNSET_LLM_FINDING_MAX_FILES` 调整。

## 4. 一次调用

请求体：

```json
{
  "task": "source_to_sink_discovery",
  "contract": {"tool_access": "none", "context": "...", "output": "..."},
  "project": {"languages": {}, "frameworks": [], "file_count": 0, "endpoint_count": 0},
  "policy": {"min_severity": "high", "min_confidence": 0.6, "max_findings": 12},
  "surface_notes": {},
  "endpoints": [],
  "code_pack": [{"path": "...", "language": "java", "total_lines": 120,
                 "shown_ranges": ["60-95"], "truncated": false, "code": "..."}]
}
```

- 只有 `messages`（system + user），没有 `tools` / `tool_choice` / `functions`；
- 整个 user 消息包在 `<<<SUNSET_UNTRUSTED_DATA_BEGIN nonce=... trust=untrusted>>>` 信封里；
- 隔离文件的正文不会出现在 `code_pack`。

## 5. 输出校验

`validate_llm_payload` 先做通用清洗，DeepFinder 再做领域校验：

| 检查 | 处理 |
|---|---|
| `file_path` 不在仓库清单 | 丢弃 |
| 行号越界/倒置 | clamp 到文件行数，倒置修正 |
| 缺 `source` / `sink` / `description` / `exploit_chain` | 丢弃并计入 `rejected` |
| `code_snippet` 与源码不符 | 用 `line_start..line_end` 的真实源码回填 |
| `severity` 不在枚举 | 回退到 taxonomy 默认值 |
| `confidence` | clamp 到 0.55–0.90（静态证据没有动态验证） |
| `<|tool_call|>` 等工具语法 | 从文本字段剥离 |
| 低于 `min_severity` / `min_confidence` | 计入 `suppressed`，不进入 finding |

## 6. 候选合并与后续阶段

- 新候选：`candidate_id = LLM-<sha1(file:line:type)>`，`origin=llm_finding`，`rule_id=llm-deep-discovery`；
- 同一批模型输出命中 `(vuln_type, file, |line_end 差| ≤ 3)` → 不重复新增；
- 模型候选进入 CandidateScreener（可被 LLM 复核降权/丢弃，但高危类型仍受保护）；URL 模式则筛选 AWVS 候选；
- VulnerabilityAnalyzer 对 `llm_finding` 候选**不再做第二次文本补全**，避免模型自证与多余调用；finding 的 title/description/impact/CVE 论证直接取 DeepFinder 的输出，`evidence_level=llm_inferred`；
- POC 由 `poc.py` 的确定性模板生成，模型给出的 POC 只作为 `verification_notes` 中的要点，不能改写请求结构。

## 7. 报告

`report.json.llm.finding`：

```json
{
  "enabled": true,
  "mode": "on",
  "tool_calls": 0,
  "files": 12,
  "chars": 36000,
  "truncated_files": 6,
  "findings": 3,
  "duplicates": 1,
  "rejected": [],
  "rejected_count": 0,
  "suppressed": [],
  "summary": "...",
  "audited_files": ["..."],
  "gaps": ["..."],
  "note": "单次 LLM 调用；请求体不含 tools/tool_choice/function calling；..."
}
```

`report.md` §2.1 输出同一组统计；`summary.by_origin` 可区分 `llm_finding` / `second_order` / `awvs`。

## 8. 使用

```powershell
# 默认 auto：有 key 就执行
python -m sunset scan .\sample.zip --llm on -o .\results\sample

# 关闭 zip 模式候选发现
python -m sunset scan .\sample.zip --llm off --llm-finding off

# 缩小预算（大仓库/低配额）
python -m sunset scan .\sample.zip --llm on --llm-finding-budget 12000
```

## 9. 验证

```powershell
python -m unittest tests.test_llm_finder -v
```

覆盖：

- 模型输出 → 候选（描述、链、行号、端点、confidence）；
- 请求体无 `tools` / `tool_choice`，CODE PACK 内联且带信封；
- 非仓库路径丢弃、越界行号 clamp、缺 source/chain 拒绝；
- `--llm-finding off` 不发起调用；
- 同一批模型输出重复时合并且报告可见。

## 10. 已知限制

- 预算外的文件模型看不到；跨文件调用链可能因此断裂（`gaps` 会记录）；
- 静态结论最高 0.90，仍需人工/动态验证；
- prompt 里的「计分」只用于校准取舍，不改变服务端校验；
- DeepFinder 依赖 LLM key；无 key 时等价于 `off`，管线仍可完成报告流程但 zip 模式不会有静态候选。
