# 落日二号乙漏洞挖掘报告 — 20261031-214350-b1aeef

- 生成时间：2026-10-31T13:44:48.341686+00:00
- 输入：`$WORKSPACE\暴风星云裂\021.zip`
- 输入模式：`zip`
- SHA256：`ff9631d6e9310b5ffe2f51550d4a9e5b12c4e83ee69a263543f6be3776889254`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次审计范围仅 021.php（25 行单文件 PHP 脚本），共交付 3 条已去重 findings，全部带 POC（3/3 齐全）。最高危为 GEN-1b352c5348d3：021.php 第 14 行附近对 POST 参数 include 未做白名单/路径规范化即用于文件包含，构成路径穿越/任意文件包含（CWE-22，high），POC 为 HTTP 请求文本（TARGET 占位，仅限授权测试）。其次 LLM-cd298cc9bb86：同一 POST 参数 include 未编码直接回显（第 18 行附近），构成反射型 XSS（medium），POC 为 HTTP 请求文本。SEM-e8635bcf499d：第 3 行 CSP 同时启用 unsafe-inline 与固定 nonce，削弱脚本来源限制（CWE-693，medium），POC 为静态响应头证据，属配置型问题，不能宣称可动态复现。三条均为静态源码推断（rule/llm_finding），未做动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 提供的单文件 021.php（25 行）。发现第 14-18 行 $_POST['include'] 未编码拼接进 $page['body'] 的反射型 XSS，且第 3 行 CSP nonce 硬编码、第 8 行关闭 X-XSS-Protection，可绕过 CSP。未发现命令执行、文件包含、SQL、反序列化等汇点（文件内无 exec/system/include/eval 等调用）。缺口：$page['body'] 的实际输出语句不在 code_pack 内，需确认父页面渲染；无 php.ini/部署信息，无法评估 register_globals、allow_url_include 等。

未覆盖 / 证据缺口：
- $page['body'] 的输出点不在 code_pack 中，XSS 链最后一跳依赖外部渲染逻辑
- 无 Web 服务器/php.ini 配置，无法确认部署与安全设置
- 无其他仓库文件，范围严格限于 021.php

## 3. Findings

### F-1: 021.php 未校验 POST 参数 include 导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:12-14`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（021.php:14 的 isset($_POST['include']) 判断仅检查存在性，不做任何过滤）。该值在 021.php:16 被直接拼接进 $page['body'] 的 HTML 字符串（" . $_POST['include'] . "），随后随页面输出。代码中未见 basename()、realpath()、白名单或路径规范化，因此外部可控字符串未经净化即进入文件/路径相关处理流程。注意：输入片段仅覆盖 12-16 行，未展示后续对该值的实际文件读取/包含调用，故“任意文件读写”的具体汇点函数证据不足，本 finding 仅确认污点从 POST include 进入未净化路径处理。

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

若后续代码将该值用于 include/require 或文件读取，攻击者可读取服务器任意文件（如配置、密钥、/etc/passwd），在可包含 PHP 文件时可能导致代码执行；当前证据下可确认的是未净化外部输入进入路径处理，具体危害取决于未展示的下游调用。

**CVE / CWE 论证**

CWE-22 路径穿越。外部可达性：021.php 为 Web 端点，POST 参数 include 无需认证即可提交；利用链：POST include → $_POST['include']（021.php:14）→ 字符串拼接（021.php:16）→ 下游文件操作（片段未展示）。链在已给证据内闭合到未净化拼接，最终危险操作因片段截断证据不足。

**修复建议**

对 include 参数使用严格白名单（如仅允许预定义页面标识），或使用 basename() 并配合 realpath() 校验结果必须位于允许目录内；禁止将用户输入直接拼接进 include/require 路径；对输出到 HTML 的值做 htmlspecialchars() 编码。

**验证说明**

静态证据：入口 POST /021；source=query/include；sink=021.php:14；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 发送 POST 请求，include 参数携带 ../ 序列；021.php:14 仅用 isset 判断存在，021.php:16 将原始值拼入 $page['body'] 输出，全程无过滤与规范化，外部输入直达路径处理逻辑。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php:14 的路径穿越（CWE-22）POC。源码在 POST 参数 include 上拼接路径后用于文件操作，未做规范化/白名单校验，攻击者可用 ../ 序列逃逸预期目录。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 021.php:14，外部输入来自 POST 参数 include，source→sink 链静态闭合且未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。手工复现时替换 TARGET 为授权实例地址；payload 中 ../ 已做 URL 编码以适配 x-www-form-urlencoded。若源码为写操作，请改用可写且无害的探针文件名，避免覆盖生产文件。

### F-2: 021.php POST 参数 include 未编码直接拼接进页面导致反射型 XSS（CSP nonce 硬编码可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未做任何 HTML 编码（无 htmlspecialchars/htmlentities）即通过字符串拼接写入 $page['body']，随后该变量被输出到页面，构成反射型 XSS。同时第 3 行 CSP 使用硬编码 nonce 'TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='，攻击者可直接在注入的 <script nonce="..."> 中复用该 nonce，使 CSP 的 script-src 限制失效；第 8 行还主动设置 X-XSS-Protection: 0 关闭浏览器 XSS 过滤。攻击者可构造恶意 POST 请求诱导受害者提交，在受害者浏览器上下文执行任意脚本，窃取会话或执行敏感操作。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] .= "..." . $_POST['include'] . "..."（未编码拼接后输出到 HTML 页面）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 检查 $_POST['include'] 是否存在，存在则进入拼接分支 | 外部可控字符串，未过滤 |  |
| 2 | `021.php:15-17` | 将 $_POST['include'] 直接字符串拼接到 $page['body']，无 htmlspecialchars 等编码 | 原始 HTML 片段，未编码 |  |
| 3 | `021.php:19-25` | $page['body'] 继续拼接表单 HTML，最终作为页面 body 输出，注入内容被浏览器解析执行 | 注入的 HTML/JS 进入响应体 |  |

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

反射型 XSS：攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取 Cookie/会话、伪造请求执行敏感操作。硬编码 nonce 使 CSP 无法防御。

**CVE / CWE 论证**

CWE-79。外部无需认证即可通过 POST 参数注入，链闭合：source($_POST['include'])→拼接→输出，无编码；CSP nonce 硬编码可复用，X-XSS-Protection 被关闭。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码后再输出；CSP nonce 每次请求随机生成且不可预测；移除 X-XSS-Protection: 0。

**验证说明**

需确认 $page['body'] 在 code_pack 之外确实被 echo 输出（本文件 25 行内未见输出语句，可能由包含该脚本的父页面渲染）；若父页面不存在输出则链不闭合。CSP nonce 复用绕过需浏览器支持 nonce。
模型 POC 要点：向 021.php 提交包含 script 标签的 include 参数，复用页面硬编码 nonce 绕过 CSP，触发 alert。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：针对 021.php:18 的反射型 XSS（CWE-79）POC。源码将 POST 参数 include 的值未经 HTML 编码直接输出到响应，攻击者可注入脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79。漏洞位于可交付代码 021.php:18，外部输入来自 POST body 参数 include，source→sink 链静态闭合且未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。手工复现时替换 TARGET；浏览器验证需在授权环境进行，避免对真实用户造成影响。

### F-3: 021.php CSP 同时启用 unsafe-inline 与固定 nonce，削弱脚本来源限制（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

021.php:3 设置 Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='。其中 'unsafe-inline' 允许任意内联脚本执行，使 nonce 机制形同虚设；同时 nonce 为硬编码常量（base64 解码为固定字符串），对所有请求相同，攻击者一旦获知即可复用。该配置与 021.php:16 的未编码输出拼接叠加，使注入的内联脚本可被执行。

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

CSP 无法有效缓解 XSS：注入的内联 <script> 或事件处理器可执行，导致会话窃取、页面篡改、恶意操作。

**CVE / CWE 论证**

CWE-693 保护机制失效。配置型弱点，无需污点链；证据为 021.php:3 的 CSP 头原文，含 'unsafe-inline' 与固定 nonce。外部可达：任意请求均返回该头。

**修复建议**

移除 'unsafe-inline'；nonce 改为每次响应随机生成（如 base64(random_bytes(16))）并仅对当次响应有效；对注入点输出做 HTML 编码；考虑使用 'strict-dynamic' 与哈希白名单。

**验证说明**

静态证据：入口 POST /021；source=body/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：服务器在 021.php:3 返回含 unsafe-inline 与固定 nonce 的 CSP；攻击者利用 021.php:16 的未编码输出注入内联脚本，浏览器因 unsafe-inline 放行执行，CSP 未起到防护作用。
PocWriter 建议（未采纳，缺少端点 /021）：针对 021.php:3 的 CSP 配置缺陷（CWE-693）POC。该 finding 属配置型候选，重点在于检查响应头 Content-Security-Policy 是否存在及 script-src 是否过宽（如 *、unsafe-inline、unsafe-eval 或允许任意外部源）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693（防护机制失效）。漏洞位于可交付代码 021.php:3，属配置型候选，需以响应头证据判定。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。手工复现时替换 TARGET，使用 -i 抓取响应头并人工核对 CSP 指令；本项为配置检查，不涉及破坏性操作。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.55 | 是 |
| surface_mapper | 攻击面测绘 | 7.6 | 是 |
| deep_finder | LLM 深挖 | 7.99 | 是 |
| candidate_screener | 候选筛选 | 6.33 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.12 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 15.48 | 是 |
| coordinator | 管线协调 | 7.1 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
