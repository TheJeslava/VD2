# 落日二号乙漏洞挖掘报告 — 20261031-010025-94666e

- 生成时间：2026-10-30T17:01:16.693426+00:00
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

本次汇总基于单文件 PHP 脚本 021.php（25 行）的静态审计结果，共 3 条已去重 findings，全部带 POC（3/3）。最高危为 GEN-11054cd96202：021.php 第 16 行将 $_POST['include'] 直接拼接进页面 body，构成路径穿越/任意文件包含（CWE-22，high），POC 为 HTTP 型。其次为 LLM-cd298cc9bb86：同一 POST 参数 include 未编码直接输出到响应体，构成反射型 XSS（medium，HTTP POC），且第 3 行硬编码 CSP 同时启用 unsafe-inline 与固定 nonce（SEM-e8635bcf499d，medium，CWE-693），使 CSP 无法作为缓解措施。三条 POC 均为静态构造的 HTTP 请求文本，未做动态验证；CSP 一条属配置型静态证据 POC，不能宣称可动态复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 021.php（25 行，已全量审计）。该文件为无框架裸 PHP：第 3-8 行设置 CSP（硬编码 nonce）并关闭 X-XSS-Protection；第 14-18 行读取 $_POST['include'] 未编码拼入 $page['body']，第 19-25 行拼接表单，构成反射型 XSS，且硬编码 nonce 使 CSP 可被绕过，链闭合，confidence 0.88。surface_notes 提到的 sql_injection/command_injection/path_traversal/文件包含在本文件中均无对应 sink（无 SQL、无 exec/system、无 include/require/fopen），故不报告。未闭合线索：第 19-25 行仅见 $page['body'] 拼接，未见显式 echo/print，实际输出依赖未送入的模板/包含逻辑，需人工确认渲染路径；无 composer.json、Web 服务器配置、数据库配置，无法确认部署与依赖；无 Cookie/session/加密/随机数代码，配置型攻击面（weak_crypto/weak_hash/weak_random/insecure_cookie/hardcoded_secret）本轮无文件可挂，不能据此判定不存在。

未覆盖 / 证据缺口：
- 未见 $page['body'] 的最终输出语句（echo/print/模板渲染），XSS 回显依赖外部渲染逻辑
- 无 HTTP 端点清单，无法确认 021.php 访问路径、方法与鉴权要求
- 无部署/依赖/数据库配置，无法确认运行环境
- 配置型攻击面（加密/随机数/Cookie/session）本轮无代码覆盖

## 3. Findings

### F-1: 021.php 通过 $_POST['include'] 拼接进页面 body 导致的路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:14-16`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 include 提交外部输入。021.php:14 用 isset($_POST['include']) 判断参数是否存在，随后在 021.php:15-16 把 $_POST['include'] 直接字符串拼接进 $page['body']（" . $_POST['include'] . "），中间没有任何白名单、basename()、realpath() 规范化或路径前缀限制。该值最终进入页面 body 的拼接/输出流程，属于未净化的外部路径/内容输入。注意：输入片段只覆盖 021.php:12-16，未给出 $page['body'] 后续被 include/require/readfile 等消费的代码，因此“任意文件读取/包含”的最终汇点在本证据范围内无法闭合确认，当前可确认的是外部输入未经校验进入路径/内容拼接点。

**source / sink**

- source：query `include`（021.php:16）
- sink：021.php:16 " . $_POST['include'] . "

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:16` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `021.php:16` | 危险汇点：" . $_POST['include'] . " | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /021（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/021?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN11054.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN11054.txt`
- POC 目录：`poc/GEN-11054cd96202`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 $page['body'] 后续被文件包含或文件读取函数消费，攻击者可利用 ../ 序列穿越目录读取或包含任意本地文件，导致源码/配置泄露，若可包含可控文件则可能进一步导致代码执行；若仅作为 HTML 输出，则可注入任意标记/脚本内容。具体影响取决于未提供的下游消费代码，证据不足部分不作断言。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：021.php 为可直接请求的 PHP 页面，include 为 POST 参数，无需认证即可提交。利用链：POST include → isset 判断（021.php:14）→ 字符串拼接进 $page['body']（021.php:16）→ 下游消费（未在片段中给出）。由于下游消费点缺失，利用链尚未完全闭合，故置信度中等偏低。

**修复建议**

不要将用户输入直接拼接进路径或页面内容。若用于选择页面，应使用固定白名单映射（如数组 key → 固定文件名），拒绝任何含 ../、绝对路径、空字节的输入；使用 basename() 与 realpath() 规范化并校验结果仍位于允许目录内；输出到 HTML 时使用 htmlspecialchars() 转义。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:16；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 发送 POST 请求，include 参数携带 ../ 或任意路径/内容；021.php:14 仅做 isset 存在性检查，021.php:15-16 将原始值直接拼入 $page['body']，无任何净化，随后该值随页面 body 进入下游处理。下游是否执行文件包含/读取需结合未提供的代码确认。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php:16 的路径穿越（CWE-22）POC。外部输入来自 query 参数 include，未净化即进入文件包含/读写汇点，可通过 ../ 序列逃逸预期目录。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22。漏洞位于 021.php:16，外部输入来自 query 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构（GET /021?include=...），仅补充基线与对比说明。脚本为文本工件，不自动执行；执行前需人工替换 TARGET 并确认授权。

### F-2: 021.php 中 POST 参数 include 未编码直接拼入页面 body 导致反射型 XSS（CSP nonce 硬编码可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未经 htmlspecialchars 等任何编码，直接字符串拼接进 $page['body']；第 19-25 行把 $page['body'] 与表单一起输出到响应体。攻击者提交含 <script> 的 include 值即可在受害者浏览器执行任意脚本。同时第 3 行 CSP 使用硬编码 nonce 'TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='（base64 解码为 'Never going to give you up'），且第 10 行注释已直接给出可用的 nonce 值，攻击者可在注入的 <script nonce="..."> 中复用该 nonce 通过 CSP；第 8 行还显式设置 X-XSS-Protection: 0 关闭浏览器 XSS 过滤。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] .= ... $_POST['include'] ... 后随页面输出（第 19-25 行拼接表单并回显 body）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | isset($_POST['include']) 判断请求体是否携带 include 参数 | 外部可控字符串进入脚本 |  |
| 2 | `021.php:15-17` | $page['body'] .= "\n\t" . $_POST['include'] . "\n" 直接字符串拼接，无任何编码/过滤 | 原始 HTML 片段进入 $page['body'] |  |
| 3 | `021.php:19-25` | $page['body'] .= 表单 HTML，随后页面输出 $page['body']，注入内容随响应返回 | 未编码 HTML 输出到响应体 |  |
| 4 | `021.php:3-5` | CSP 使用硬编码 nonce，第 10 行注释泄露该 nonce 值，注入脚本可携带相同 nonce 通过 script-src 校验 | CSP 白名单被固定 nonce 绕过 | nonce 为静态硬编码值且源码注释直接给出，攻击者可复用 |

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

反射型 XSS：可在受害者浏览器上下文执行任意 JS，窃取会话 Cookie/令牌、伪造请求执行敏感操作、钓鱼。CSP 因硬编码 nonce 失效，X-XSS-Protection 被显式关闭，防护形同虚设。

**CVE / CWE 论证**

CWE-79。外部可达（POST 参数直接进入响应体），无需认证，链完整闭合；CSP nonce 硬编码（CWE-330 相关）使防护可绕过。属 DVWA 类教学靶场 CSP 绕过场景，真实部署中可被赏金平台接收为反射型 XSS。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出；CSP nonce 每次请求随机生成（random_bytes）而非硬编码；移除 X-XSS-Protection: 0；对输入做白名单校验。

**验证说明**

需确认 021.php 实际可匿名访问及响应体确实回显 $page['body']（第 19-25 行仅见拼接，未见显式 echo，但页面结构表明 body 会被渲染输出）；需动态确认 CSP 头与 nonce 复用生效。
模型 POC 要点：向 021.php 提交 POST include 参数，值为携带硬编码 nonce 的 script 标签，触发 alert。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：针对 021.php:18 的反射型跨站脚本（CWE-79）POC。POST 参数 include 的值未经 HTML 编码即回显到响应，可注入脚本。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79。漏洞位于 021.php:18，外部输入来自 POST body 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的 POST 请求结构，仅补充基线与回显验证说明。脚本为文本工件，不自动执行；执行前需人工替换 TARGET 并确认授权。

### F-3: 021.php 硬编码 CSP 同时启用 unsafe-inline 与固定 nonce（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

021.php:3 定义 $headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';"。该策略同时包含 'unsafe-inline' 与一个硬编码、可预测的 nonce。'unsafe-inline' 会使内联脚本无需 nonce 即可执行，从而大幅削弱 CSP 对 XSS 的缓解作用；固定 nonce 写在源码中，任何能读到源码或猜到该常量的人都能构造带该 nonce 的脚本标签。此外该 CSP 未包含 default-src、object-src 等兜底指令。输入片段仅覆盖 021.php:2-3，未给出该 header 实际被 header() 输出的代码，也未给出页面中内联脚本的注入点，因此“可被利用执行任意脚本”的完整链路在本证据范围内未闭合。

**source / sink**

- source：query `include`（021.php）
- sink：021.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /021（ANY）的 CSP 配置缺陷 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/021?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e8635bcf499d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 对内联脚本注入的防护基本失效：一旦页面存在任何 HTML/JS 注入点（例如同文件 021.php:16 将 $_POST['include'] 拼入 body），注入的内联脚本可绕过 CSP 执行，导致会话劫持、页面篡改或钓鱼。当前证据不足以证明存在可直接利用的注入点。

**CVE / CWE 论证**

CWE-693（防护机制失效）。外部可达性：CSP 随 021.php 响应下发，任何访问者均可获得。利用链：响应头下发弱 CSP（021.php:3）→ 页面存在注入点（未在片段中确认）→ 内联脚本执行。因缺少注入点与 header 输出代码，链条未闭合。

**修复建议**

移除 'unsafe-inline'，改用基于 nonce 或 hash 的严格策略；nonce 必须每次请求随机生成（如 random_bytes + base64），不得硬编码在源码中；补充 default-src 'self'、object-src 'none'、base-uri 'self' 等指令；同时修复 021.php:16 的输入拼接问题，避免依赖 CSP 作为唯一防线。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：021.php:3 定义含 'unsafe-inline' 与固定 nonce 的 CSP → 响应下发（header 输出代码未提供）→ 若页面存在内联脚本注入点（未在片段中确认）→ 注入脚本在弱 CSP 下执行。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php:3 的 CSP/安全配置缺陷（CWE-693）POC。该处响应缺少或弱化内容安全策略等防护头，属于配置型候选，无 HTTP 污点依赖。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693（防护机制缺失）。问题位于 021.php:3 的响应头配置，属配置型缺陷，需结合响应头证据判定。
POC 备注：保留原确定性 POC 的请求结构，仅补充响应头检查说明。此为配置型候选，证据等级为静态推断，需以实际响应头确认；脚本为文本工件，不自动执行。

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
| safety_guard | 安全防护 | 2.67 | 是 |
| surface_mapper | 攻击面测绘 | 6.33 | 是 |
| deep_finder | LLM 深挖 | 9.04 | 是 |
| candidate_screener | 候选筛选 | 6.61 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.56 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.55 | 是 |
| coordinator | 管线协调 | 5.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
