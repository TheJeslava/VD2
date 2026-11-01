# 落日二号乙漏洞挖掘报告 — 20261031-164219-cc9436

- 生成时间：2026-10-31T08:43:20.867461+00:00
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

本次审计范围仅 021.php 单文件（25 行，PHP，无框架/路由/端点清单）。共交付 3 条 findings，全部带 POC：最高危为 GEN-1b352c5348d3（path_traversal，high），021.php 第 14 行将 $_POST['include'] 未净化拼接进页面 body，属路径/内容注入（CWE-22）；其次 LLM-cd298cc9bb86（xss，medium），同一 POST 参数 include 在第 18 行未编码直接输出，构成反射型 XSS，且第 3 行 CSP 同时启用 'unsafe-inline' 与固定 nonce，可被复用绕过；SEM-e8635bcf499d（csp，medium）即该 CSP 策略削弱（CWE-693）。3 条 POC 均为静态源码证据推导的文本工件（TARGET 占位），未做动态验证，不能宣称可动态复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 021.php（1-25 行，单文件 PHP 脚本）。发现一条闭合链：POST 参数 include 未编码拼接进 $page['body']，配合硬编码 CSP nonce 与 X-XSS-Protection:0 构成反射型 XSS。未发现命令执行、SQL 注入、文件包含、SSRF、反序列化等汇点（文件中无 system/exec/include/require/file_get_contents/mysqli 等调用）。weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 均未在源码中出现对应函数（无 md5/rand/setcookie/openssl/$_SERVER 头信任），不单独立项。缺口：$page['body'] 的实际输出点不在 code_pack 内，无法确认最终渲染位置；无部署配置无法确认公网可达性。

未覆盖 / 证据缺口：
- $page['body'] 的最终 echo/print 输出点未在 code_pack 中，XSS 输出环节依赖外部模板
- 无 Web 服务器/php.ini 配置，无法确认部署与可达 URL
- 无端点清单，endpoint 由源码推断为 /021.php

## 3. Findings

### F-1: 021.php 中 $_POST['include'] 未净化即拼接进页面 body（CWE-22 路径/内容注入）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:12-14`
- **来源**：`rule`

**描述**

证据仅覆盖 021.php 第 12-14 行：第 14 行 `if (isset ($_POST['include'])) {` 只判断 POST 参数 include 是否存在，随后（第 15-16 行，见相邻候选）把 `$_POST['include']` 直接拼进 `$page['body']`。攻击者通过 POST 参数 include 提交任意字符串，代码未做白名单、basename、realpath 规范化或路径前缀校验。需要说明的是：本条候选的 source 被标注为 query `include`，但源码实际读取的是 `$_POST['include']`（POST 体参数），注入点应记为 POST 参数 include，而非 URL query。此外，第 14 行本身只是 isset 判断，真正的危险汇点是第 16 行的字符串拼接；本条候选把 isset 行当作 sink，证据链不完整，实际危害需结合 GEN-11054cd96202 一起判断。

**source / sink**

- source：query `include`（021.php:14）
- sink：021.php:14 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `021.php:14` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

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
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN1b352.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN1b352.txt`
- POC 目录：`poc/GEN-1b352c5348d3`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

取决于拼接结果最终如何被使用：若 `$page['body']` 被写入模板/文件或以 include/require 方式加载，则可导致任意本地文件读取或任意文件写入（路径穿越）；若仅回显到 HTML，则退化为反射型内容注入（XSS）。当前证据只到字符串拼接，未给出后续 include/file_put_contents 等消费点，因此不能断言已构成任意文件读写。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：021.php 为可直接请求的 PHP 页面，POST 参数无需认证即可提交。但利用链未闭合——证据中缺少 `$page['body']` 之后的文件系统或 include 消费点，无法证明穿越到任意路径，故仅按 llm_inferred 记录，不主张 CVE 级结论。

**修复建议**

1) 不要用用户输入拼接路径或页面内容；若必须按名加载页面，使用固定白名单映射（如 `['home'=>'home.php', ...]`）并只接受映射内键；2) 对路径使用 `basename()` + `realpath()` 并与允许根目录做前缀比较；3) 输出到 HTML 时使用 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` 编码；4) 禁止把 `$_POST` 值直接拼进 include/require 或文件写入函数。

**验证说明**

静态证据：入口 POST /021；source=query/include；sink=021.php:14；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 发送 POST 请求，参数 include 携带任意值 → 第 14 行 `isset($_POST['include'])` 为真进入分支 → 第 15-16 行 `$page['body'] .= "..." . $_POST['include'] . "..."` 将原始值拼入页面 body，全程无过滤。后续该 body 如何被消费（include/写文件/回显）在给定片段中不可见，因此链路在拼接点终止，需补充消费点证据才能确认路径穿越。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php 第 14 行的路径穿越（CWE-22）POC。外部输入来自 POST 参数 include，未经有效净化即进入文件包含/读写汇点，可通过 ../ 序列逃逸预期目录。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22。漏洞位于 021.php:14，外部输入来自 POST 参数 include，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；脚本中 TARGET 需替换为授权目标后手动执行。

### F-2: 021.php POST 参数 include 未编码直接拼接进页面导致反射型 XSS（CSP nonce 可复用绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未做任何 HTML 实体编码或过滤，直接以字符串拼接方式追加到 $page['body']，随后该 body 被输出到响应页面（第 19-25 行继续拼接表单，说明 $page['body'] 为页面渲染内容）。攻击者提交包含 <script> 的 include 值即可在受害者浏览器执行任意脚本。虽然第 3-5 行设置了 CSP script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='，但该 nonce 是硬编码常量且第 10 行注释直接给出了可用示例 <script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>，攻击者可直接复用该 nonce 绕过 CSP；同时第 8 行显式设置 X-XSS-Protection: 0 关闭了浏览器 XSS 过滤器。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] .= ... . $_POST['include'] . ...（未编码拼接进页面输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | isset($_POST['include']) 判断攻击者提交的 include 参数存在 | 原始字符串，未过滤 |  |
| 2 | `021.php:15-17` | $page['body'] .= "\n\t" . $_POST['include'] . "\n" 直接字符串拼接，无 htmlspecialchars/实体编码 | 攻击者可控 HTML/JS 片段进入页面 body |  |
| 3 | `021.php:19-25` | $page['body'] 继续拼接表单并作为页面内容渲染输出，注入的 script 标签随页面返回 | 注入内容随响应返回浏览器执行 | CSP nonce 为硬编码常量 TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=，攻击者可直接在 payload 中复用该 nonce 通过 script-src 校验；X-XSS-Protection 被设为 0 关闭浏览器过滤 |

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话/发起敏感操作；CSP 因硬编码 nonce 失效，X-XSS-Protection 被关闭。

**CVE / CWE 论证**

CWE-79。外部无需认证即可通过 POST include 参数注入脚本，链闭合：source($_POST['include'])→拼接→页面输出；CSP 硬编码 nonce 与 X-XSS-Protection:0 使防护失效。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出；移除硬编码 nonce，改为每次请求随机生成；移除 X-XSS-Protection: 0。

**验证说明**

需确认 $page['body'] 最终确实被输出到响应（本文件仅见拼接，未见 echo/print 输出点，输出可能在未提供的公共模板中）；需动态确认 CSP nonce 复用可执行脚本。
模型 POC 要点：向 021.php 提交 include 参数，值包含复用硬编码 nonce 的 script 标签，触发 alert
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：针对 021.php 第 18 行的反射型跨站脚本（CWE-79）POC。外部输入来自 POST 参数 include，未经 HTML 编码即回显到响应页面。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79。漏洞位于 021.php:18，外部输入来自 POST 参数 include，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；脚本中 TARGET 需替换为授权目标后手动执行。

### F-3: 021.php 第 3 行 CSP 同时启用 'unsafe-inline' 与固定 nonce，策略被削弱（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

证据为 021.php 第 2-3 行：`$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";`。该策略在 script-src 中同时声明 `'unsafe-inline'` 和一个硬编码 nonce。按 CSP 规范，当存在 nonce 或 hash 源时，`'unsafe-inline'` 会被忽略；但此处 nonce 值是写死在源码中的常量（base64 解码为 “Never going to give you up”），任何能读取源码或该响应头的攻击者都可复用同一 nonce，使 nonce 机制形同虚设。同时策略未包含 `object-src 'none'`、`base-uri 'none'`、`default-src` 等兜底指令。

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

CSP 作为纵深防御被削弱：一旦页面存在 HTML 注入点（例如同文件第 16 行把 `$_POST['include']` 拼入 body），攻击者可用已知固定 nonce 的内联脚本绕过 script-src 限制执行任意 JS，导致会话窃取、CSRF 令牌读取、页面内容篡改。该问题本身不直接造成 RCE，属于防护失效类缺陷。

**CVE / CWE 论证**

CWE-693（防护机制失效）。外部可达性：任意访问 021.php 的响应都会带上该 CSP 头，无需认证。但这是配置型弱点，不构成独立可利用漏洞；其危害依赖同文件的内容注入点（GEN-11054cd96202）是否被实际消费到响应中，证据中该消费点缺失，故利用链未完全闭合。

**修复建议**

1) 移除 `'unsafe-inline'`，改用每次请求随机生成的高熵 nonce（如 `base64_encode(random_bytes(16))`）并同步写入对应 `<script nonce=...>`；2) 不要硬编码 nonce；3) 补充 `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`；4) 将 CSP 作为纵深防御而非唯一防线，同时修复第 16 行的输入拼接问题。

**验证说明**

静态证据：入口 POST /021；source=body/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 021.php 获得含固定 nonce 与 'unsafe-inline' 的 CSP 响应 → 若页面存在注入点（第 16 行 `$_POST['include']` 拼接进 body 并最终回显），攻击者构造带该已知 nonce 的 `<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">` 内联脚本 → 浏览器因 nonce 匹配而放行，CSP 未能阻止脚本执行。链路依赖注入点被回显这一未证实条件。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php 第 3 行的 CSP 配置缺陷（CWE-693）POC。该问题为配置型候选，重点检查响应头 Content-Security-Policy 是否存在及 script-src 是否过宽。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693。问题位于 021.php:3 的响应头/CSP 配置，属配置型候选，需以实际响应头为准。
POC 备注：POC 仅为文本工件，不执行、不联网；脚本中 TARGET 需替换为授权目标后手动执行。CSP 结论须以实际响应头为准，若响应头未出现 CSP 相关配置，应回退核对源码。

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
| safety_guard | 安全防护 | 2.92 | 是 |
| surface_mapper | 攻击面测绘 | 8.42 | 是 |
| deep_finder | LLM 深挖 | 8.61 | 是 |
| candidate_screener | 候选筛选 | 6.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 15.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.42 | 是 |
| coordinator | 管线协调 | 6.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
