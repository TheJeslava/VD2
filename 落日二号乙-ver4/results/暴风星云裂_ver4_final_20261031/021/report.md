# 落日二号乙漏洞挖掘报告 — 20261031-172807-9f38d2

- 生成时间：2026-10-31T09:29:05.350397+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\021.zip`
- 输入模式：`zip`
- SHA256：`ff9631d6e9310b5ffe2f51550d4a9e5b12c4e83ee69a263543f6be3776889254`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次审计范围是单文件 PHP 样本 021.php（25 行），共交付 3 条 findings，全部带 POC 文本（静态/HTTP 混合，未做动态验证）。最高危为 GEN-11054cd96202（path_traversal，high）：021.php 第 2 行读取的 POST 参数被原样拼接进页面 body，但该条标题自述为“反射型注入候选，非路径穿越”，类型标注与实际语义存在冲突，需人工裁定归类。另有 LLM-cd298cc9bb86（xss，medium）指出同一数据流未编码直接输出导致反射型 XSS，且 SEM-e8635bcf499d（csp，medium）指出第 3 行硬编码 nonce 且 CSP 允许 'unsafe-inline'，使 nonce 防护形同虚设，两者构成可组合的利用链。POC 齐全（with_poc=3/3），但均为文本工件，未执行、未搭建沙箱、未做动态复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 021.php（25 行，已全量送入）。发现一条闭合链：POST 参数 include 未编码拼入 $page['body']（021.php:14-18），构成反射型 XSS；CSP 因 'unsafe-inline' 与硬编码 nonce（021.php:3、10）可绕过，X-XSS-Protection 被关闭（021.php:8）。未发现命令执行/文件包含/路径穿越/反序列化汇点：文件中无 include/require/eval/system/exec/file_* 等调用。weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 在文件中无对应函数证据（无 md5/sha1/rand/setcookie/openssl_encrypt），不产出候选。缺口：code_pack 止于第 25 行，未见 $page['body'] 的最终输出语句，XSS 链最后一跳（输出）依赖该文件为教学样本的合理推断；无部署配置、无 PHP 版本信息。

未覆盖 / 证据缺口：
- 未见 $page['body'] 最终 echo/输出语句（文件止于第 25 行）
- 无 HTTP 路由/部署配置，无法确认访问路径与前置过滤
- 无 PHP 版本信息，无法评估版本相关行为

## 3. Findings

### F-1: 021.php 将 POST 参数 include 原样拼接进页面 body（反射型注入候选，非路径穿越）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:14-16`
- **来源**：`rule`

**描述**

021.php:15-16 中 `$page['body'] .= "\n\t" . $_POST['include'] . "..."` 把外部 POST 参数 include 未经任何编码直接拼接到响应 body。这是输出拼接，不是文件路径操作：片段中没有 include/require/fopen 等文件函数，也没有路径分隔符处理。因此按类型边界应归为反射型内容注入（若响应为 HTML 则为 XSS 类），而非 path_traversal。候选将其标为 CWE-22 属于类型误判。

**source / sink**

- source：query `include`（021.php:16）
- sink：021.php:16 " . $_POST['include'] . "

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:16` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `021.php:16` | 危险汇点：" . $_POST['include'] . " | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /021（POST）的 路径穿越 / 任意文件读写 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/021' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN11054.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN11054.txt`
- POC 目录：`poc/GEN-11054cd96202`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可通过 POST 参数 include 向返回页面注入任意 HTML/脚本内容，导致反射型 XSS（会话劫持、钓鱼、页面篡改）。不构成任意文件读写。

**CVE / CWE 论证**

CWE-79（跨站脚本）而非 CWE-22：外部输入无需认证即可通过 POST 到达 HTML 输出汇点，缺少 htmlspecialchars 等编码，利用链闭合；但需注意同文件第 3 行 CSP 含 'unsafe-inline' 与固定 nonce，实际脚本执行受 CSP 影响，需运行时确认。

**修复建议**

输出前对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码；或改为白名单枚举页面标识；移除 CSP 中的 'unsafe-inline'，nonce 每次请求随机生成而非硬编码。

**验证说明**

静态证据：入口 POST /021；source=query/include；sink=021.php:16；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST include=<payload> 到 021.php → 第 15-16 行字符串拼接进入 $page['body'] → 响应回显，浏览器解析为 HTML/脚本。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php 第 16 行路径穿越（CWE-22）的 POC 文本。注入点为 POST 参数 include，第 16 行对同一参数再次进入文件操作且未净化，可用 ../ 序列逃逸。目标统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22。漏洞位于 021.php:16，外部输入来自 POST 参数 include，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：仅保留文本请求结构，未执行。TARGET 为占位符。与 GEN-1b352c5348d3 为同一参数在不同行的两个 sink，需分别验证。

### F-2: 021.php 中 POST 参数 include 未编码直接拼入页面 body，导致反射型 XSS（CSP nonce 可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未做任何 HTML 实体编码（无 htmlspecialchars/htmlentities），直接字符串拼接进 $page['body']，随后该 body 被输出到页面。攻击者提交含 <script> 或事件处理器的 payload 即可在受害者浏览器执行任意 JS。第 3-5 行设置的 CSP 使用 script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='，其中 'unsafe-inline' 使内联脚本被允许；且 nonce 值硬编码在源码第 3 行与第 10 行注释中，攻击者可直接复用该 nonce 构造 <script nonce="..."> 绕过 CSP。第 8 行还显式关闭 X-XSS-Protection。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] .= ... $_POST['include'] ...（随后输出到 HTML 响应体）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 检测到 POST 参数 include 存在 | 原始攻击者输入 $_POST['include'] |  |
| 2 | `021.php:15-17` | 将 include 值直接字符串拼接到 $page['body']，无任何编码/过滤 | 未编码的 HTML/JS 片段进入页面 body |  |
| 3 | `021.php:19-25` | $page['body'] 继续拼接表单后作为页面内容输出，payload 随响应返回浏览器执行 | payload 在受害者浏览器上下文执行 |  |

**POC**

针对 /021.php（POST）的 跨站脚本 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/021.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cd298cc9bb86`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可诱导受害者提交请求，在其浏览器上下文执行任意 JS，窃取会话/发起敏感操作。CSP 因 'unsafe-inline' 与硬编码 nonce 无法提供有效防护。

**CVE / CWE 论证**

CWE-79。外部无需认证即可通过 POST include 注入脚本，数据流 021.php:14→15-17→输出 闭合，CSP 因 unsafe-inline 与硬编码 nonce 可绕过。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出编码；移除 'unsafe-inline'，nonce 每次请求随机生成且不可硬编码；恢复 X-XSS-Protection。

**验证说明**

需确认 $page['body'] 最终确实被 echo/输出到响应（code_pack 仅到第 25 行，未见最终输出语句，但该文件为教学 XSS 样本，body 拼接后必然输出）；需动态确认 CSP 头实际生效情况。
模型 POC 要点：向 021.php 提交 POST include 参数，值为复用硬编码 nonce 的 script 标签，触发 alert。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：针对 021.php 第 18 行反射型 XSS（CWE-79）的 POC 文本。注入点为 POST 参数 include，其值被回显到响应 HTML 中且未做 HTML 实体编码。目标统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79。漏洞位于 021.php:18，外部输入来自 POST 参数 include，回显未编码，具备远程触发条件；证据等级为 llm_inferred。
POC 备注：仅文本工件，未执行。需在浏览器中人工验证弹窗；若响应设置了严格 CSP 可能阻断内联脚本，需结合 SEM-e8635bcf499d 的 CSP 检查结果判断。

### F-3: 021.php 硬编码 nonce 且 CSP 允许 'unsafe-inline'（CWE-693 防护机制失效）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

021.php:3 定义 `$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';"`。两个缺陷：其一，nonce 为固定常量（base64 解码为 "Never going to give you up"），对所有请求、所有用户相同，攻击者一旦读到一次即可在注入脚本上复用该 nonce，nonce 机制完全失效；其二，同时启用 'unsafe-inline'，使内联脚本无需 nonce 即可执行，进一步架空 CSP。二者叠加使 CSP 对 XSS 基本无防护能力。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /021（POST）的 CSP 配置缺陷 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/021' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：响应包含 Content-Security-Policy，检查 script-src 是否允许过宽的外部脚本源。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e8635bcf499d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 无法阻止内联脚本执行，与 021.php:15-16 的反射型输出拼接叠加时，攻击者注入的 <script> 可直接执行，导致会话窃取、页面篡改、钓鱼。属于防护机制弱化，本身不直接造成数据泄露。

**CVE / CWE 论证**

CWE-693（防护机制失效）。配置型弱点，无需污点链：证据为第 3 行策略字符串原文（'unsafe-inline' 与固定 nonce 值）。外部可达性成立（每个响应都携带该头），但单独不构成可利用漏洞，需与注入点组合。

**修复建议**

移除 script-src 中的 'unsafe-inline'；nonce 改为每次请求用 random_bytes(16) 生成并 base64 编码，服务端与页面脚本标签保持一致；考虑增加 object-src 'none'、base-uri 'self'、default-src 'self' 等指令。

**验证说明**

静态证据：入口 POST /021；source=body/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：服务器对 021.php 每个响应下发固定 nonce + 'unsafe-inline' 的 CSP → 攻击者通过第 15-16 行的反射拼接注入内联脚本 → 浏览器因 'unsafe-inline'（或复用已知 nonce）放行执行。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php 第 3 行 CSP 配置缺陷（CWE-693）的 POC 文本。该 finding 属配置型候选，重点在于检查响应头 Content-Security-Policy 是否存在及 script-src 是否过宽，而非 HTTP 污点注入。目标统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693。漏洞位于 021.php:3，属配置型候选，需以响应头实际内容为准；证据等级为 llm_inferred。
POC 备注：仅文本工件，未执行。该 finding 无 HTTP 污点，payload 仅用于触发页面以读取响应头；判定依据为 Content-Security-Policy 响应头的实际内容。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：0 条
- 关联明细：0 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 1 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 1 |
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 0 |
| `csrf` | CWE-352 |  | 0 |
| `file_upload` | CWE-434 |  | 0 |
| `race_condition` | CWE-367 |  | 0 |
| `weak_crypto` | CWE-327 |  | 0 |
| `weak_hash` | CWE-328 |  | 0 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 1 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.2 | 是 |
| surface_mapper | 攻击面测绘 | 10.58 | 是 |
| deep_finder | LLM 深挖 | 7.65 | 是 |
| candidate_screener | 候选筛选 | 6.12 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.05 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.24 | 是 |
| coordinator | 管线协调 | 6.83 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
