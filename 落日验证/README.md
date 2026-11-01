# 落日验证（Sunset Verify）

> 对VulnCatcher产出的 POC 做自动化动态验证。支持 **URL 模式** 与 **zip 模式** 两条管线，对应VulnCatcher的两种输入模式。

## 1. 定位

VulnCatcher只生成 POC，不执行 POC。落日验证负责：

1. 从VulnCatcher结果目录读取 `report.json` 与 POC；
2. 把 POC 解析成结构化 HTTP 请求（不执行 shell）；
3. 在沙箱边界内请求 **localhost / allowlist 主机**；
4. 对比 baseline 与 attack 响应，按漏洞类型判定：
   - `verified`：出现类别特有的动态证据；
   - `rejected`：无可信差异；
   - `inconclusive`：有差异但缺少类别证据；
   - `unsupported`：该类漏洞没有 HTTP 可观测量（弱加密/弱随机/信任边界/硬编码密钥）；
   - `error`：请求失败或目标不可达。

最终输出：

```
<result>/verification/
├─ verification.json
├─ verification.md
└─ poc_results.csv
```

批量模式还会输出：

```
<out>/verification-batch.json
<out>/verification-batch.md
```

## 2. 两条管线

| 模式 | 目标解析 | 适用 |
|---|---|---|
| `url` | 优先使用 POC 的 `poc.safety.target_url` / `run.target_url`（AWVS 扫描目标） | VulnCatcher `--mode url` |
| `zip` | 使用 `--target-base` + finding 的 endpoint 解析 `TARGET` 占位符 | VulnCatcher `--mode zip` |

zip 模式的 POC 文本里是 `http://TARGET:8080/...`；验证器把它映射到已部署的 lite 靶场（如 `https://localhost:8443`），不会访问任意外部主机。

## 3. 快速开始

```powershell
cd C:\Users\liyuf\Desktop\794\落日验证

# 单个 URL 模式结果
py -m sunset_verify verify --mode url `
  --result ..\VulnCatcher\results\url\BenchmarkTest00002

# 单个 zip 模式结果（需要已部署的 lite 靶场）
py -m sunset_verify verify --mode zip `
  --result ..\VulnCatcher\results\zip\BenchmarkTest00002 `
  --target-base https://localhost:8443

# 批量验证 + 汇总
py -m sunset_verify verify --mode url `
  --results-dir ..\VulnCatcher\results\url `
  --out .\results\url-verification --workers 4
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--mode url|zip` | 必选，对应VulnCatcher输入模式 |
| `--result` | 单个结果目录 |
| `--results-dir` | 批量结果根目录（递归找 `report.json`） |
| `--target-base` | zip 模式靶场基址；url 模式可作兜底 |
| `--out` | 批量汇总目录 |
| `--workers` | 并发数，默认 4 |
| `--timeout` | 单请求超时，默认 15s |
| `--allow-host` | 额外允许的主机（默认只允许 localhost/127.0.0.1/::1） |
| `--verify-tls` | 严格校验 TLS（默认关闭，适配自签名靶场） |

## 4. 智能体

| 代号 | 职责 |
|---|---|
| `PocCollectorAgent` | 读 `report.json`，解析 POC 的 curl/raw HTTP，生成 `PocCase` |
| `SandboxExecutorAgent` | 在 allowlist 边界内执行 baseline/attack；多步骤 POC 使用同一 Cookie jar 顺序回放 |
| `EvidenceJudgeAgent` | 按类型做响应差分与证据判定 |
| `VerificationReporterAgent` | 写 per-run 与批量报告 |

## 5. 安全边界

- 不执行 POC 里的 shell 脚本，只执行解析出的 HTTP 请求；
- 默认只允许 localhost/127.0.0.1/::1；外部主机直接判 `error`；
- 不写目标文件、不调用系统命令；
- POC 中连续请求按步骤回放，自动吸收 `Set-Cookie` 并在后续请求携带；单次数字 Cookie 不足以证明 weak_id；
- `verification.json` 的 `safety.executed=true` 仅表示验证器执行了 HTTP 请求，不表示 POC 中的破坏性命令被执行。

## 6. 测试

```powershell
py -m unittest discover -s tests -v
```
