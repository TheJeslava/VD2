# VulnCatcher URL 模式（AWVS 候选管线）

## 1. 为什么有两条管线

VulnCatcher的 zip 模式从源码出发，适合「拿到压缩包、快速给出 source→sink + POC」。  
但 AWVS 是动态扫描器，它只能对**运行中的 URL**工作。URL 模式把 AWVS 放在候选提出位置：

```
zip 模式：zip → 源码规则/LLM → POC/报告
URL 模式：URL + AWVS → 动态候选 → POC/报告
```

AWVS 不是 Semgrep 式源码补丁，也不替代静态规则；它只提出「哪个 URL 上观察到了什么」，后续 agent 负责保留证据、生成可重放 POC、交给VulnCatcher-Verify动态确认。

## 2. 三种 AWVS 来源

| 来源 | 参数 | 说明 |
|---|---|---|
| AWVS 导出报告 | `--awvs-report report.json\|report.xml` | 消费外部 AWVS 已完成的扫描结果 |
| AWVS REST API | `--awvs-url --awvs-key --awvs-target --awvs-profile` | 创建 target、启动 scan、轮询、拉取 vulnerabilities |
| 本地 AWVS-compatible 探针 | `--awvs-local --awvs-manifest runtime/lite-targets.json` | 无 AWVS 实例时的离线替代；按 benchmark 的 cookie/header/param 通道发送类别 payload，输出 AWVS 形状的结果 |

> 本地探针只覆盖黑盒可观测的类别（cmdi / sqli / xss / pathtraver / ldapi / xpathi / securecookie）。  
> crypto / hash / weakrand / trustbound 没有 HTTP 响应信号，本地探针不会伪造候选。

## 3. 命令

```powershell
cd C:\Users\liyuf\Desktop\794\VulnCatcher

# 真实 AWVS 报告
py -m sunset scan --mode url --target https://target/endpoint `
  --awvs-report .\awvs.json --llm off -o .\results\url-case

# 真实 AWVS API
py -m sunset scan --mode url --target https://target/endpoint `
  --awvs-url https://awvs:3443 --awvs-key $env:AWVS_API_KEY `
  --awvs-target https://target --awvs-profile 11111111-1111-1111-1111-111111111111 `
  --awvs-insecure --llm off -o .\results\url-case

# 本地探针（无 AWVS 实例）
py -m sunset scan --mode url `
  --target http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00002 `
  --awvs-local --awvs-manifest .\runtime\lite-targets.json `
  --llm off -o .\results\url-case
```

## 4. 输出

与 zip 模式共享：

```
results/<run-id>/
├─ report.md / report.json / report.schema.json / report.sarif / report.html
├─ result.json / findings.csv / coverage.json / manifest.json
├─ poc/<finding-id>/{poc.sh,request.http,README.md}
└─ awvs/{scan.json,targets.json,correlations.json}
```

差异：

- `report.json.run.input_mode = "url"`，并带 `target_url`；
- finding 的 `location.file=""`、`line_start/line_end=0`，保留 `endpoint/http_method`；
- `poc.safety.target_url` 保存实际目标，`poc` 文本仍使用 `TARGET` 占位；
- `awvs/scan.json` 保存 AWVS 原始候选（含 channel/parameter/payload/evidence）。

## 5. Agent 适配点

| Agent | zip 模式 | URL 模式 |
|---|---|---|
| SafetyGuard | 扫描源码 Prompt 注入 | 无源码，仍执行策略与输出校验 |
| SurfaceMapper | 文件/路由/攻击面 | 目标 URL、AWVS 渠道、候选端点 |
| CandidateScreener | LLM 候选 | AWVS 候选去重/排序 |
| VulnerabilityAnalyzer | source→sink finding | 保留 URL/请求/证据，不伪造文件/行号 |
| SecondOrderAnalyzer | store→read→sink | 跳过（无源码） |
| PocWriter | 按 source_kind 生成请求 | 优先保留 AWVS 原始请求，生成可重放 POC |
| Coordinator | 文件+行号去重 | endpoint+类型去重 |

## 6. 与VulnCatcher-Verify的衔接

VulnCatcher只写 POC，不执行。`../VulnCatcher-Verify` 读取 `report.json`：

- `--mode url`：使用 `poc.safety.target_url`（或 run.target_url）解析目标；
- `--mode zip`：用 `--target-base` + endpoint 解析 `TARGET`；
- 默认只允许 localhost/127.0.0.1/::1，不执行 POC shell。

## 7. 66 个 lite 样本的实验（本机）

环境：Docker Tomcat 9 + lite WAR，HTTP `http://localhost:8080/benchmark`，HSQLDB 9001 + ApacheDS 10389。  
并发：`--workers 4`。候选来源：本地 AWVS-compatible 探针。

| 指标 | URL 模式 | ZIP 模式 |
|---|---|---|
| 实验数 | 66 | 66 |
| 产出 POC 的样本 | 20 | 25（29 条 POC） |
| VulnCatcher-Verify verified | 20 | 11 |
| rejected | 0 | 15 |
| inconclusive | 0 | 3 |
| error | 0 | 0 |

URL 模式检出的 20 条全部是 lite 的真漏洞（precision 100%）；13 条真漏洞未产出 POC，其中 12 条属于 crypto/hash/weakrand/trustbound 这类黑盒不可观测类别，1 条是 xpathi（00607）未命中。  
ZIP 模式的 15 条 rejected 主要是静态规则的误报（例如把 xpathi 输出误判为 XSS）或盲注/无回显场景；VulnCatcher-Verify能把这些 POC 拒掉，说明验证环节有实际区分力。

复现脚本：

```powershell
py .\runtime\run_experiments.py --mode url --workers 4
py .\runtime\run_experiments.py --mode zip --workers 4

cd ..\VulnCatcher-Verify
py -m sunset_verify verify --mode url --results-dir ..\VulnCatcher-ver4\results\url `
  --out ..\VulnCatcher-ver4\results\url-verification --workers 4
py -m sunset_verify verify --mode zip --results-dir ..\VulnCatcher-ver4\results\zip `
  --target-base http://localhost:8080/benchmark `
  --out ..\VulnCatcher-ver4\results\zip-verification --workers 4
```
