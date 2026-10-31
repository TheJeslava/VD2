# 落日二号乙漏洞挖掘报告 — 20261031-011404-b58a5b

- 生成时间：2026-10-30T17:14:44.522261+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
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

本次审计范围极小：仅 1 个 PHP 文件（003.php，98 行），无框架、无路由配置、无端点清单，源码层面共交付 2 条高危发现，均集中在 003.php 同一文件内，且都具备 POC 文本（静态/HTTP 文本工件，未执行、未动态验证）。最高危的是 LLM-d891d8de8c0d：003.php 第 51 行附近将 $_SERVER['REQUEST_URI'] 直接拼入 JavaScript 字符串上下文，构成反射型/DOM 型 XSS（high）；其次是 SEM-b5ee97e20ce3：003.php 第 4 行附近通过 REQUEST_URI 字符串替换把 API 路径信息带入响应，构成 CWE-200 信息泄露（high）。两条 POC 齐全（with_poc=2/2），但均为源码推断 + 规则匹配，未经动态复现。攻击面测绘提示的注入类（command_injection / sql_injection / path_traversal / ssrf）、文件包含、配置型（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret）均未形成 findings，属未覆盖而非已排除，需按 human_review 逐项复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 003.php（98 行）。发现一条闭合的反射型 XSS 链：REQUEST_URI → str_replace 弱过滤 → 拼接进 <script> 单引号字符串 → 响应输出。未发现命令执行、SQL 注入、文件包含、反序列化等 sink（文件中无 system/exec/mysql/include 等调用）。第 83 行 $_SERVER['PHP_SELF'] 进入 form action 属性，存在潜在反射 XSS，但 PHP_SELF 通常已被服务器规范化且利用依赖路径信息，证据弱于第 31/51 行，未单独立项。文件中无 md5/sha1/rand/setcookie/硬编码凭据，配置型候选均不成立。未提供 Web 服务器配置与认证机制，无法确认匿名可达性。

未覆盖 / 证据缺口：
- 无 Web 服务器配置，无法确认路径规范化与匿名可达性
- 无认证/会话机制证据
- 第 83 行 PHP_SELF 反射点未单独立项（证据较弱）

## 3. Findings

### F-1: 003.php 通过 REQUEST_URI 反射注入 JavaScript 字符串（DOM/反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:3-51`
- **来源**：`llm_finding`

**描述**

脚本在第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行仅用 str_replace 删除字面量 "/vulnerabilities/api/"，未做任何 HTML/JS 编码或白名单校验，随后在第 31、51 行把 $stripped_url 直接拼接进 <script> 内的单引号 JS 字符串常量（const url = '...'）。攻击者可在请求路径中构造包含单引号与 JS 代码的 URI，闭合字符串后注入任意 JavaScript，在受害者浏览器中执行，属于反射型 XSS。

**source / sink**

- source：path `REQUEST_URI`（003.php:3）
- sink：003.php:51 第 31/51 行字符串拼接进 <script> 内 JS 单引号字符串，最终由第 6/78 行 $html 输出到响应体

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:3` | 从 $_SERVER['REQUEST_URI'] 读取完整请求 URI，包含攻击者可控的路径与查询串 | 原始 URI 字符串，未过滤 |  |
| 2 | `003.php:4` | 仅用 str_replace 删除字面量 "/vulnerabilities/api/"，不改变引号、尖括号、反斜杠等危险字符 | 去除固定子串后的 URI，仍含单引号等元字符 | str_replace 只做固定子串删除，不是编码也不是白名单，攻击者可用单引号闭合 JS 字符串 |
| 3 | `003.php:31` | 把 $stripped_url 拼接进 <script> 中的 const url = '...' 单引号字符串 | 注入的 JS 代码进入脚本上下文 |  |
| 4 | `003.php:6` | $html 变量最终输出到 HTTP 响应，浏览器解析执行注入的脚本 | 响应体中的可执行 JavaScript |  |

**POC**

针对 /vulnerabilities/api/003.php（GET）的 跨站脚本 POC。注入点：URL path；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/api/003.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/api/003.php'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-d891d8de8c0d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取会话、伪造请求、篡改页面内容

**CVE / CWE 论证**

CWE-79 反射型 XSS：外部 URI 直接进入脚本上下文，无编码/白名单，链闭合，无需认证

**修复建议**

对 $stripped_url 使用 json_encode 或 htmlspecialchars 输出到 JS 上下文，或改用固定相对路径而非从 REQUEST_URI 派生

**验证说明**

需确认 Web 服务器是否对路径中的单引号做规范化/拒绝；需确认 003.php 实际部署路径与是否匿名可达
模型 POC 要点：在请求路径中注入单引号闭合 JS 字符串并执行任意脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/api/003.php）：针对 003.php:51 的反射型跨站脚本（CWE-79）。外部输入来自请求路径 REQUEST_URI，未经有效编码即被输出到响应中，导致脚本在受害者浏览器执行。注入通道为 URL path，payload 为 <script>alert(document.domain)</script>。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/api/003.php）：符合 CWE-79。漏洞位于 003.php:51，外部输入来自 path 的 REQUEST_URI，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；实际发送时需对 path 中的 payload 做 URL 编码。

### F-2: 003.php 通过 REQUEST_URI 字符串替换暴露 API 路径信息（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`003.php:3-4`
- **来源**：`rule`

**描述**

证据仅覆盖 003.php 第 3-4 行：第 3 行 `$request_url = $_SERVER['REQUEST_URI'];` 读取客户端可控的请求 URI（攻击者输入点），第 4 行 `$stripped_url = str_replace("/vulnerabilities/api/", "", $request_url);` 仅做一次字面量字符串替换，把 `/vulnerabilities/api/` 前缀从 URI 中剥离，未做任何白名单校验、路径规范化或输出编码。该 `$stripped_url` 后续如何被使用（是否回显到响应体、是否用于文件/路由拼接、是否进入日志或错误页）在给定片段中不可见，因此“信息泄露”的具体汇点无法从现有证据闭合。当前证据只能确认：请求 URI 被原样读取并做弱处理，属于语义模式命中，尚不足以证明存在可观测的敏感信息返回。

**source / sink**

- source：request `API version/user object`（003.php）
- sink：003.php:4 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:4` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /003（ANY）的 API 信息泄露 POC。注入点：ANY 参数 API version/user object；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/003'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 API 信息泄露 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/003?API version/user object=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-b5ee97e20ce3`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若 `$stripped_url` 被回显或用于构造响应/错误信息，可能向未认证请求方泄露内部 API 路径结构、版本或路由信息，辅助后续攻击面枚举；但由于缺少下游使用点证据，实际泄露内容与影响范围证据不足，不能断言可读取敏感数据或越权。

**CVE / CWE 论证**

CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。外部可达性：`$_SERVER['REQUEST_URI']` 由任意 HTTP 请求控制，无需认证即可触达第 3-4 行。但利用链未闭合：缺少 `$stripped_url` 的输出/使用汇点，无法证明敏感信息实际返回给攻击者，故不满足 CVE 论证所需的“可达 + 泄露内容明确 + 链路闭合”三要素，当前仅为候选。

**修复建议**

1) 不要基于原始 REQUEST_URI 做字符串替换来推导路由，改用框架路由或显式白名单映射；2) 对 URI 做规范化（解码、去除 `..`、多重斜杠）后再匹配；3) 任何回显到响应/错误页的路径信息应做最小化处理，避免暴露内部目录与版本；4) 对 API 端点统一加鉴权与统一错误响应，避免差异化信息泄露。

**验证说明**

静态证据：入口 ANY /003；source=request/API version/user object；sink=003.php:4；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造任意请求 URI（如包含 `/vulnerabilities/api/` 前缀的路径）→ 003.php:3 读取 `$_SERVER['REQUEST_URI']` 到 `$request_url` → 003.php:4 用 `str_replace` 剥离固定前缀得到 `$stripped_url`，无校验、无规范化 → 后续使用点未在证据中给出，无法确认是否到达响应输出或敏感操作，链路在此中断。
PocWriter 建议（未采纳，缺少端点 /003）：针对 003.php:4 的 API 信息泄露（CWE-200）。接口对 API version / user object 等参数缺少访问控制或过滤，返回了不应暴露的版本/用户对象信息。注入通道为 query 参数，探测值 SUNSET_PROBE。
PocWriter 建议（未采纳，缺少端点 /003）：符合 CWE-200。漏洞位于 003.php:4，外部输入来自 query 参数 API version/user object，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；参数名含空格与斜杠，实际发送时需 URL 编码。

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
| `path_traversal` | CWE-22 | 是 | 0 |
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
| `api_info_disclosure` | CWE-200 |  | 1 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.08 | 是 |
| surface_mapper | 攻击面测绘 | 8.18 | 是 |
| deep_finder | LLM 深挖 | 6.77 | 是 |
| candidate_screener | 候选筛选 | 3.25 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.69 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.24 | 是 |
| coordinator | 管线协调 | 7.04 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
