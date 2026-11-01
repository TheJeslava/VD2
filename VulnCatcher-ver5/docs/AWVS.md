# AWVS 联动设计

## ver5 集成数据集覆盖

`runtime/dataset-targets.json` 使用 `awvs-compatible-manifest-v2`，包含 58 个编号样本和 20 个金标类别。`sunset/baofeng.py` 是唯一的类别注册表，URL 本地探针、ZIP 的 `awvs/targets.json` 和覆盖统计都从这里生成，避免不同入口出现类别漂移。

本地探针对可由 HTTP 响应确认的注入、XSS、重定向、CSP、上传、认证和访问控制信号执行基线/攻击比较。清单中的类别和参数只用于选择探针，不会在没有响应证据时生成 finding；弱加密、二次注入等不能由单次 HTTP 请求确认的类别应使用 ZIP 分析、跨请求动态流程或真实 AWVS/人工复核。

VulnCatcher不使用 Semgrep。它把「经典动态扫描器」AWVS 作为外部信号源，做**双向**联动：

1. **source → AWVS**：把源码识别出的 HTTP 端点导出为 AWVS 目标种子；
2. **AWVS → source**：导入 AWVS JSON/XML 报告，与静态 finding 关联，作为外部佐证；
3. **可选 API 触发**：让外部 AWVS 实例扫描授权目标，轮询并回灌。

---

## 0. 先澄清：AWVS 不是 Semgrep 式“源码补丁”

| 维度 | Semgrep（AutoCVE） | AWVS（VulnCatcher） |
|---|---|---|
| 类型 | 源码 SAST | 动态 Web 扫描器 |
| 输入 | 源码 | 运行中的目标 URL |
| 管线位置 | LLM 前的源码候选来源 | 源码端点播种 + 外部结果回灌/佐证 |
| 纯源码 zip | 可运行 | 不能直接运行，需要部署目标 |
| 是否必需 | AutoCVE 依赖 | 可选；没有 AWVS 也能跑完 |
| 输出用途 | 规则命中/候选 | `external_evidence` / external-only finding |

因此：

- AWVS **不参与**源码规则匹配，不替代 LLM 的 source→sink 分析；
- 它不是“给大模型打补丁”的源码扫描器，而是提供运行时外部信号的动态扫描器；
- 只有在你能提供可访问目标、并且显式传入 `--awvs-url/--awvs-key/--awvs-target` 时才会触发扫描；
- 默认情况下（纯源码 zip）只导出 `awvs/targets.json`，供你稍后导入 AWVS。

---

## 1. 为什么是 AWVS

- AutoCVE 用 Semgrep 做源码规则扫描；VulnCatcher已经有自己的轻量规则，不需要再引入 SAST。
- AWVS 是动态黑盒扫描器，能提供源码静态分析看不到的运行时证据（响应差异、报错、可访问性）。
- 两者结合：源码告诉 AWVS「打哪里」，AWVS 告诉源码「哪里真的响应异常」。
- VulnCatcher**不执行** AWVS 的扫描逻辑，只消费结果；动态验证发生在外部 AWVS，符合「管线不搭沙箱/不自动验证」的边界。

---

## 2. source → AWVS：目标播种

每次扫描自动输出 `awvs/targets.json`：

```json
{
  "generated_by": "VulnCatcher / SurfaceMapper",
  "note": "将 TARGET 替换为实际授权目标后导入 AWVS；结果可用 --awvs-report 回灌。",
  "targets": [
    {
      "url": "http://TARGET:8080/pathtraver-00/BenchmarkTest00002",
      "method": "POST",
      "source_file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java",
      "source_line": 27,
      "params": [],
      "framework": "servlet"
    }
  ]
}
```

来源：`indexer.extract_endpoints`，支持：
- Java `@WebServlet` / `@RequestMapping` / `@GetMapping` 等；
- Python Flask/FastAPI；
- Express/Koa；
- Go Gin；
- ASP.NET；
- HTML `<form action>`。

---

## 3. AWVS → source：报告导入

### 3.1 JSON

支持数组、`{"vulnerabilities": [...]}`、`{"vulns": [...]}`、`{"issues": [...]}`，以及 JSONL。

字段兼容：
- `vt_name` / `name` / `title` / `type`
- `affects_url` / `url` / `target` / `location`
- `severity` / `risk`
- `details` / `description` / `detail` / `info`
- `request` / `http_request` / `raw_request`
- `cwe` / `cwe_id`

### 3.2 XML

递归查找标签名包含 `vulnerability` / `issue` 的节点，读取子节点 `name`/`url`/`severity`/`details`/`request`/`cwe`。

### 3.3 类型映射

| AWVS 名称 / CWE | VulnCatcher类型 |
|---|---|
| SQL Injection / CWE-89 | `sql_injection` |
| OS Command Injection / CWE-78 | `command_injection` |
| Path Traversal / CWE-22 | `path_traversal` |
| SSRF / CWE-918 | `ssrf` |
| XXE / CWE-611 | `xxe` |
| XSS / CWE-79 | `xss` |
| Deserialization / CWE-502 | `deserialization` |
| Template Injection / CWE-1336 | `ssti` |
| LDAP / CWE-90 | `ldap_injection` |
| XPath / CWE-643 | `xpath_injection` |
| Open Redirect / CWE-601 | `open_redirect` |
| CSRF / CWE-352 | `csrf` |
| File Upload / CWE-434 | `file_upload` |
| IDOR / CWE-639 | `idor` |
| Authentication / CWE-287 | `auth_bypass` |

---

## 4. 关联算法

`correlate(findings, vulns, project)`：

1. 对每个静态 finding，提取其端点（来自 `cve_justification` 的 `POST /path` 等）；
2. 在 AWVS 结果中找：
   - 类型映射一致；
   - 端点路径 tail 一致（`/a/b/Test00002` vs `http://host/a/b/Test00002`）；
3. 命中：
   - `external_evidence` 追加 AWVS 记录；
   - `confidence += 0.03`；
   - `evidence_level = externally_corroborated`；
   - `verification_notes` 追加「AWVS 外部佐证」；
4. 未命中的 AWVS 结果：
   - 生成 `origin=awvs`、`evidence_level=external_only` 的 finding；
   - 保留 AWVS 原始请求作为 POC；
   - `verdict=external`，明确「无源码证据，需人工定位」。

关联明细写入 `awvs/correlations.json`。

> 注意：AWVS 是外部工具，「corroborated」不等于本管线动态验证；报告会明确写「未在本管线执行扫描」。

---

## 5. 可选：AWVS REST API 触发

命令行：

```powershell
python -m sunset scan .\sample.zip `
  --awvs-url https://awvs.example:3443 `
  --awvs-key $env:AWVS_API_KEY `
  --awvs-target https://authorized-target.example `
  --awvs-profile 11111111-1111-1111-1111-111111111111 `
  --awvs-wait 1800
```

流程（`sunset/awvs.py::AwvsClient`）：

```
POST /api/v1/targets          {"address": target, "description": "sunset-one"}
POST /api/v1/scans            {"target_id": ..., "profile_id": ..., "schedule": {...}}
GET  /api/v1/scans/{scan_id}  轮询 status
GET  /api/v1/vulnerabilities?q=scan_id:<id>
```

- Header：`X-Auth: <api_key>`；
- 只有显式提供 `--awvs-url/--awvs-key/--awvs-target` 才会联网；
- 失败会被捕获并跳过，不影响主流程；
- 测试中不发起真实扫描，只用 fixture 验证导入/关联。

---

## 6. TLS 与凭据安全

- 默认应验证 AWVS 的 TLS 证书；如果 AWVS 使用自签名证书，需要显式选择 insecure 模式（`--awvs-insecure`，对应 `AwvsClient(verify_tls=False)`）；
- 不要把 API key 发到不可信端点；
- 报告和日志不会输出 API key；
- `X-Auth` 只存在内存中，不落盘。

---

## 7. 测试

```powershell
python -m unittest tests.test_pipeline.TestAwvs -v
```

fixtures：

- `tests/fixtures/awvs/path_traversal.json`：AWVS 报告与 00002 静态 finding 同类型同端点 → `externally_corroborated`；
- `tests/fixtures/awvs/external_only.json`：AWVS 独有 SQLi → `origin=awvs`、`external_only`、POC 来自 AWVS 请求。

---

## 8. 限制

- AWVS 需要运行中的目标；纯源码 zip 没有可扫描 URL，因此默认只导出目标种子，不自动扫描；
- AWVS 的端点路径可能带 context path（如 `/benchmark/...`），关联使用 tail 匹配；
- AWVS 报告字段随版本变化，导入器做了兼容但可能需要按实际导出手工调整；
- 外部扫描结果可能包含误报，VulnCatcher只把它作为佐证/外部 finding，不自动升级为 confirmed。
