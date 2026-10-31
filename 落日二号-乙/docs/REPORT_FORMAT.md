# 结构化报告格式（report.json / SARIF / HTML）

落日一号每次扫描都会输出稳定契约，而不仅是自然语言报告。

## 1. 文件

| 文件 | 说明 |
|---|---|
| `report.json` | 交付契约；平台、CI、二次开发消费 |
| `report.schema.json` | `report.json` 的 JSON Schema（`schema_version=1.0`） |
| `report.sarif` | SARIF 2.1.0；可导入 GitHub Code Scanning/IDE/漏洞平台 |
| `report.html` | 独立 HTML，无外部依赖，可直接打开 |
| `report.md` | 人类可读的中文报告 |
| `result.json` | 管线内部全量结果（调试/复现），不是交付契约 |

## 2. report.json 顶层

```json
{
  "schema_version": "1.0",
  "generator": {"name": "落日一号 / Sunset One", "version": "1.0.0"},
  "run": {
    "run_id": "...",
    "generated_at": "...",
    "zip_path": "...",
    "zip_sha256": "...",
    "duration_sec": 12.3
  },
  "project": {
    "file_count": 5,
    "text_file_count": 5,
    "languages": {"java": 3},
    "frameworks": ["servlet"],
    "endpoint_count": 3,
    "endpoints": [],
    "files": []
  },
  "summary": {
    "text": "执行摘要",
    "total_findings": 1,
    "with_poc": 1,
    "by_severity": {"high": 1},
    "by_verdict": {"candidate": 1},
    "by_evidence_level": {"static_closed": 1},
    "second_order": 0,
    "injection_signals": 0,
    "quarantined_files": []
  },
  "findings": [],
  "second_order": [],
  "security": {},
  "awvs": {},
  "coverage": {},
  "llm": {},
  "limitations": []
}
```

## 3. finding 字段

| 字段 | 含义 |
|---|---|
| `id` | 稳定 finding id |
| `title` | 标题 |
| `vulnerability_type` | 规范类型（与 AutoCVE 对齐的 12 类 + 扩展） |
| `cwe` / `cwe_name` | CWE 编号与中文名 |
| `severity` | critical / high / medium / low |
| `cvss_estimate` | 按严重度给的粗略估计，不是正式评分 |
| `confidence` | 0.0–1.0 |
| `verdict` | candidate / external |
| `evidence_level` | llm_inferred / externally_corroborated / external_only |
| `location` | file / line_start / line_end / endpoint / http_method |
| `source` / `sink` | 污点源与危险汇点 |
| `description` / `impact` | 成因与影响 |
| `cve_justification` | CWE/CVE 价值论证 |
| `exploit_chain` | 逐步链（位置/描述/数据状态/绕过原因） |
| `poc` | description/preconditions/steps/payload/scripts/safety/artifact_dir |
| `external_evidence` | AWVS 等外部佐证 |
| `verification_notes` | 验证边界说明 |
| `safety` | executed/network_egress/requires_authorization 等 |
| `tags` | 类型/CWE/严重度/origin/evidence_level |

## 4. SARIF 映射

- `ruleId`：`sunset/<vulnerability_type>`
- `level`：critical/high → `error`；medium → `warning`；low → `note`
- `locations[0].physicalLocation.artifactLocation.uri`：源码相对路径；外部 finding 使用端点
- `region`：`line_start` / `line_end`
- `partialFingerprints.sunsetFindingId`：finding id
- `properties`：confidence / verdict / evidence_level / cwe / endpoint / has_poc / origin

## 5. 契约校验

```python
from sunset.structured_report import validate_structured_report
errors = validate_structured_report(report)  # [] 表示通过
```

测试：`tests/test_pipeline.py::TestTarget00002::test_structured_report_contract`。

## 6. 安全边界

- `report.json` 中的 POC 只是文本，不执行；
- `poc.safety.executed` 恒为 `false`；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM，也不会作为静态候选输入；
- 报告不写入 LLM API Key；错误信息会脱敏。
