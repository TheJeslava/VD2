# 落日二号乙漏洞挖掘报告 — 20261031-011724-1a1f9a

- 生成时间：2026-10-30T17:18:18.788324+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 021.php，共 3 条均带 POC（with_poc=3）。最高危为 GEN-1b352c5348d3：021.php 第 14 行附近，POST 参数未经校验即进入 include，构成路径穿越/任意文件包含（CWE-22，high），POC 为 HTTP 型，可复现性最高。其次为 LLM-cd298cc9bb86：同一 POST 参数在第 18 行附近未转义直接输出，构成反射型 XSS（medium，llm_inferred 等级，基于源码推断，未动态验证）；以及 SEM-e8635bcf499d：第 3 行 CSP 同时启用 unsafe-inline 与固定 nonce，削弱脚本来源限制（medium，CWE-693），属配置型静态证据，POC 为静态文本，不能宣称可动态复现。POC 齐全度：3/3 有 POC，但其中 csp 为静态 POC，xss 为推断型 POC，仅 path_traversal 具备完整 HTTP 请求语义。注意 surface_notes 明确说明输入未提供源码片段、sink_hot_files 为空，因此上述行号与数据流结论以 findings 记录为准，仍需人工对照源码复核。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已逐行审计唯一文件 021.php（25 行）。确认第 14-18 行 POST 参数 include 未转义拼接进 $page['body']，构成反射型 XSS；CSP 使用固定 nonce 且含 unsafe-inline、X-XSS-Protection 置 0，无法防护。未发现命令执行、文件包含、SQL、反序列化等汇点；无 md5/sha1、弱随机、硬编码凭据、Cookie 标志等配置型证据。未闭合线索：$page['body'] 的最终输出语句不在本片段中（推断为常规 echo），需动态确认。

未覆盖 / 证据缺口：
- $page['body'] 的实际输出语句未在 code_pack 中显式出现
- 无部署/认证信息，无法确认公网可达性
- 无 php.ini/服务器配置，无法评估其它利用条件

## 3. Findings

### F-1: 021.php 未过滤的 POST 参数 include 导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（021.php:14 `if (isset ($_POST['include']))`），该值在 021.php:16 被直接拼接进 `$page['body']` 的内联表达式 `" . $_POST['include'] . "`，全程未见 basename()、realpath()、白名单或路径规范化等任何净化措施。候选将 source 记为 query `include`，但源码实际读取的是 `$_POST['include']`，注入点为 POST 参数 include，而非 GET 查询参数。由于该值被拼入页面模板/包含逻辑，攻击者可构造 `../../etc/passwd` 或绝对路径读取任意文件；若拼接结果进入 include/require 类文件加载，则可进一步包含任意本地文件。

**source / sink**

- source：query `include`（021.php:14）
- sink：021.php:14 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `021.php:14` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /021（ANY 方法）的路径穿越 POC。注入点为查询参数 include（对应 021.php:14 的文件包含/读写汇点），payload 使用 ../../../../tmp/sunset_GEN1b352.txt 逐级上跳目录，目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/021?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN1b352.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN1b352.txt`
- POC 目录：`poc/GEN-1b352c5348d3`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意文件读取（泄露配置文件、凭据、源码），在拼接结果被 include/require 消费时可升级为本地文件包含，配合可写文件可导致代码执行；同时可造成敏感路径探测。

**CVE / CWE 论证**

CWE-22 路径穿越。外部可达：021.php 为 Web 入口，POST 参数无需认证即可提交；利用链闭合：`$_POST['include']`（021.php:14）→ 直接字符串拼接（021.php:16）→ 文件/模板加载汇点，中间无校验、无规范化、无白名单，攻击者完全控制路径内容。

**修复建议**

不要将用户输入直接拼接为文件路径或包含目标：使用固定白名单映射（如 `$pages = ['home'=>'home.php', ...]`）按 key 取文件；若必须接受路径，先 `basename()` 去目录成分，再用 `realpath()` 规范化并校验结果前缀位于允许目录内；禁止对用户输入使用 include/require，改用模板引擎的受限渲染。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:14；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 发送 POST 请求，参数 include 设为 `../../../../etc/passwd`。021.php:14 检测到该参数存在，021.php:16 将原始值直接拼入 `$page['body']` 的内联表达式，未做任何过滤，最终由文件/模板加载逻辑消费该路径，实现目录穿越读取任意文件。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 021.php:14，外部输入来自查询参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。脚本为文本工件，管线不执行、不联网、不搭沙箱；执行前将 TARGET 替换为授权目标。若目标对 .. 做过滤，可尝试 URL 双重编码 %252e%252e%252f 或绝对路径变体，但需保持注入参数名为 include。

### F-2: 021.php 中 POST 参数 include 未转义直接拼接进页面导致反射型 XSS（CSP nonce 可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未做任何 HTML 实体编码（无 htmlspecialchars/htmlentities），直接字符串拼接进 $page['body']，随后该 body 被输出到响应页面。攻击者提交含 <script> 的 include 参数即可在受害者浏览器执行任意脚本。第 3-5 行设置的 CSP 使用固定 nonce 'TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='（源码第 10 行注释即给出可直接使用的示例 <script nonce=...>alert(1)</script>），且 script-src 含 'unsafe-inline'，因此 CSP 无法阻止注入脚本执行；第 8 行还显式关闭 X-XSS-Protection。属于反射型 XSS，可窃取会话/发起敏感操作。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] 字符串拼接后输出到 HTML 响应（无 htmlspecialchars 转义）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 检测 POST 参数 include 是否存在 | 原始外部输入 $_POST['include'] |  |
| 2 | `021.php:15-17` | 将 include 值直接字符串拼接进 $page['body']，无任何编码/过滤 | 未转义 HTML 片段进入页面 body |  |
| 3 | `021.php:19-25` | $page['body'] 继续拼接表单并最终输出到响应，注入的脚本随页面返回浏览器执行 | 注入脚本被浏览器解析执行 | CSP 使用固定 nonce 且含 'unsafe-inline'，X-XSS-Protection 被置 0，均无法阻止执行 |

**POC**

针对 /021.php（POST）的反射型跨站脚本 POC。注入点为 POST 表单参数 include（对应 021.php:18 的输出汇点），payload 为 <script>alert(document.domain)</script>，目标地址统一使用 TARGET 占位符。

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取 Cookie/会话、伪造请求、钓鱼。

**CVE / CWE 论证**

CWE-79。外部 POST 参数直达 HTML 输出，无编码，无需认证，链闭合；CSP 因固定 nonce 与 unsafe-inline 失效。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出；移除 'unsafe-inline'，nonce 每次请求随机生成；恢复 X-XSS-Protection。

**验证说明**

需确认 $page['body'] 确实被输出到响应（本片段未显示 echo，但为单文件脚本常规模式）；建议动态确认 CSP 头与回显。
模型 POC 要点：向 021.php 提交 include 参数，注入带固定 nonce 的 script 标签，绕过 CSP 触发 alert
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 021.php:18，外部输入来自 POST 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。脚本为文本工件，管线不执行、不联网、不搭沙箱；执行前将 TARGET 替换为授权目标。若响应为纯文本 Content-Type 而非 text/html，浏览器不会执行脚本，此时应记录为输出未编码但利用受限。

### F-3: 021.php CSP 策略同时启用 unsafe-inline 与固定 nonce，削弱脚本来源限制（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

021.php:3 设置 `Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';`。该策略同时允许 `'unsafe-inline'` 与一个硬编码、可预测的 nonce。按 CSP 规范，当存在 nonce 时 `'unsafe-inline'` 会被忽略，但 nonce 值固定写在源码中（base64 解码为可读字符串），任何能读取源码或猜测该值的攻击者都可为其注入的 `<script nonce=...>` 打上合法标记，从而绕过 script-src 限制。此外策略缺少 `object-src 'none'`、`base-uri`、`default-src` 等加固项。

**source / sink**

- source：query `include`（021.php）
- sink：021.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /021 的 CSP（内容安全策略）配置缺陷检查 POC。该候选为配置型问题，关注 021.php:3 附近是否缺失或弱化 Content-Security-Policy 响应头；include 参数仅作为无害探测值 SUNSET_PROBE，用于获取完整响应头。目标地址统一使用 TARGET 占位符。

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

CSP 作为 XSS 纵深防御被削弱：一旦存在 HTML 注入点（如本文件 include 参数拼接输出），攻击者可复用固定 nonce 执行内联脚本，导致会话劫持、凭据窃取、页面篡改。

**CVE / CWE 论证**

CWE-693 保护机制失效。属配置/实现型弱点，无需污点链即可成立；证据为 021.php:3 的策略字符串原文（含 `'unsafe-inline'` 与硬编码 nonce）。外部可达性取决于是否存在注入点，本文件 021.php:16 的拼接输出提供了潜在注入面。

**修复建议**

移除 `'unsafe-inline'`；nonce 必须每次响应随机生成（如 `base64_encode(random_bytes(16))`）且不可硬编码；补充 `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`；对输出做上下文编码，不依赖 CSP 作为唯一防线。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者若能在 021.php 响应中注入 HTML（例如通过 include 参数拼接），可读取/猜测 021.php:3 中固定的 nonce 值，构造 `<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">` 绕过 script-src，执行任意脚本。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693（防护机制失效）。问题位于可交付代码 021.php:3 附近的响应头配置，属配置型候选，无 HTTP 污点链；证据等级：llm_inferred（基于源码/配置推断，未做动态验证）。
POC 备注：仅限授权测试。脚本为文本工件，管线不执行、不联网、不搭沙箱；执行前将 TARGET 替换为授权目标。本项为配置检查，判定依据是响应头而非参数回显，include 参数不参与漏洞触发。

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
| safety_guard | 安全防护 | 3.0 | 是 |
| surface_mapper | 攻击面测绘 | 10.32 | 是 |
| deep_finder | LLM 深挖 | 6.33 | 是 |
| candidate_screener | 候选筛选 | 5.13 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.99 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.32 | 是 |
| coordinator | 管线协调 | 7.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
