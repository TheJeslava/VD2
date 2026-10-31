# 落日二号乙漏洞挖掘报告 — 20261031-013641-fbec52

- 生成时间：2026-10-30T17:37:19.406993+00:00
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

本次汇总基于单文件 PHP 脚本 003.php（98 行）的源码审计结果，共交付 2 条 XSS 发现，均带 POC：高危项 LLM-d891d8de8c0d 为通过 REQUEST_URI 反射注入 JavaScript 上下文（行至 51），中危项 LLM-427b279e78e6 为通过 PHP_SELF 反射注入表单 action 属性（行至 83）。两条均为静态源码推断（llm_inferred）并附文本 POC，未做动态验证，POC 中目标统一使用 TARGET 占位符，仅限授权测试。最高危为 REQUEST_URI 反射型 XSS。POC 齐全度：2/2 有 POC，但均为 HTTP 型静态 POC，不代表已动态复现。本次未交付二次注入链、命令注入、SQL 注入、路径穿越、SSRF 等类型；攻击面测绘提示的配置类弱点（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均未形成 findings，需人工按代码/会话语义复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 003.php（98 行），已完整审计。发现两处反射型 XSS：一是第 3-4 行 REQUEST_URI 经 str_replace 后在第 31/51 行拼入 <script> 单引号字符串；二是第 83 行 PHP_SELF 拼入 form action 属性。两处均无有效编码，链在单文件内闭合。未发现命令执行、SQL、文件、反序列化、SSRF 等汇点；文件内无 md5/sha1/rand/setcookie 等配置类弱点证据，故未报告 weak_hash/weak_crypto/weak_random/insecure_cookie。未闭合线索：无法确认 Web 服务器对 URI 特殊字符的规范化行为、PHP 版本与 PATH_INFO 配置，故 XSS 需动态确认；文件是否被 include、实际访问路径未知。输入中未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/PHP 配置，无法确认 URI 特殊字符是否被拒绝及 PATH_INFO 是否启用
- 无法确认该文件实际访问路径与是否被 include
- 无数据库/依赖清单，未评估第三方引入漏洞

## 3. Findings

### F-1: 003.php 通过 REQUEST_URI 反射注入 JavaScript 上下文（DOM/反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:3-51`
- **来源**：`llm_finding`

**描述**

脚本第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行仅用 str_replace 删除固定子串 "/vulnerabilities/api/"，未做任何 HTML/JS 编码或白名单校验。第 31、51 行把 $stripped_url 直接拼接进 <script> 内的单引号字符串常量：const url = '" . $stripped_url . "/vulnerabilities/api/v2/user/2';。攻击者构造包含单引号与 JS 代码的请求路径，即可闭合字符串并注入任意 JavaScript，在受害者浏览器中执行（反射型 XSS）。由于该页面本身是 API 演示页，注入脚本可读取/篡改页面数据、发起带凭据的请求，甚至结合第 25 行 user_info.innerHTML 造成持久化展示。

**source / sink**

- source：path `REQUEST_URI`（003.php:3）
- sink：003.php:51 第 31/51 行字符串拼接进 <script> 内单引号 JS 字符串常量，最终输出到 HTML 响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:3` | 从 $_SERVER['REQUEST_URI'] 读取完整请求 URI，包含攻击者可控的路径与查询串 | 原始 URI 字符串，含单引号等特殊字符 |  |
| 2 | `003.php:4` | str_replace 仅删除固定子串 "/vulnerabilities/api/"，不转义单引号、尖括号、反斜杠 | 去除固定子串后的 URI，仍保留攻击者注入的 ' 与 JS 代码 | str_replace 是字符串替换而非编码/白名单，无法阻止单引号闭合 JS 字符串 |
| 3 | `003.php:31` | 把 $stripped_url 拼进 <script> 中 const url = '...' 的单引号字符串 | 注入内容进入 JavaScript 字符串上下文 |  |
| 4 | `003.php:51` | 同样拼接出现在 update_name() 中，形成第二处注入点 | 注入内容进入 JavaScript 字符串上下文 |  |
| 5 | `003.php:6` | $html 最终作为响应输出，浏览器解析执行注入的 JS | HTML/JS 响应体 |  |

**POC**

针对 /vulnerabilities/api/（GET）的 跨站脚本 POC。注入点：URL path；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/api/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/api/'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-d891d8de8c0d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可诱导受害者（含管理员）在目标域执行任意 JS，窃取会话、以受害者身份调用 API（如第 56 行 PUT 修改用户），造成账户接管或数据篡改。

**CVE / CWE 论证**

CWE-79。外部无需认证即可通过请求 URI 触发，source→sink 链在单文件内闭合，str_replace 不构成有效防护。

**修复建议**

对 $stripped_url 使用 json_encode() 或 htmlspecialchars(..., ENT_QUOTES) 后再嵌入 JS 字符串；更佳做法是使用 data-* 属性或服务端生成绝对 URL，避免把请求 URI 反射进脚本。

**验证说明**

需确认 Web 服务器是否对 URI 中的单引号做规范化/拒绝；需确认响应 Content-Type 为 text/html 且浏览器执行脚本。
模型 POC 要点：在请求路径中注入单引号闭合 JS 字符串并执行 alert，验证反射型 XSS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/api/）：针对 003.php:51 的反射型 XSS（CWE-79）。注入点为 URL path（REQUEST_URI），payload 需放在请求路径中，而非查询参数；目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/api/）：符合 CWE-79。漏洞位于可交付代码 003.php:51，外部输入来自 path 变量 REQUEST_URI，source→sink 链在给定代码范围内静态闭合，未发现有效 HTML 编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。原始草稿中的 curl 命令未携带 payload，此处已按源码注入通道（URL path）修正；请勿使用 curl|sh 形式自动执行。

### F-2: 003.php 通过 PHP_SELF 反射注入表单 action 属性

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:83-83`
- **来源**：`llm_finding`

**描述**

第 83 行把 $_SERVER['PHP_SELF'] 直接拼进 <form method='post' action="..."> 的双引号属性中，未做 HTML 属性编码。攻击者构造形如 /003.php/"><script>...</script> 的路径（PATH_INFO），PHP_SELF 会包含该路径，从而闭合 action 属性并注入 HTML/JS，形成反射型 XSS。

**source / sink**

- source：path `PHP_SELF`（003.php:83）
- sink：003.php:83 第 83 行拼接进 HTML 属性 action="..."

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:83` | 读取 $_SERVER['PHP_SELF'] 并直接拼入 action 属性双引号内 | 含攻击者 PATH_INFO 的字符串，未编码 |  |
| 2 | `003.php:78` | $html 拼接后输出到响应，浏览器解析注入的标签 | HTML 响应体 |  |

**POC**

针对 /003.php（GET）的 跨站脚本 POC。注入点：URL path；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/003.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/003.php'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-427b279e78e6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可窃取会话或以受害者身份操作。

**CVE / CWE 论证**

CWE-79。PHP_SELF 为客户端可控，未编码直接进入 HTML 属性。

**修复建议**

使用 htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8')，或直接使用空 action 或固定脚本名。

**验证说明**

需确认服务器是否启用 PATH_INFO 及是否对路径做过滤；部分现代配置会拒绝含 < > 的 URI。
模型 POC 要点：利用 PATH_INFO 注入闭合 action 属性并执行脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /003.php）：针对 003.php:83 的反射型 XSS（CWE-79）。注入点为 URL path（PHP_SELF），payload 需放在请求路径中，而非查询参数；目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /003.php）：符合 CWE-79。漏洞位于可交付代码 003.php:83，外部输入来自 path 变量 PHP_SELF，source→sink 链在给定代码范围内静态闭合，未发现有效 HTML 编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。原始草稿中的 curl 命令未携带 payload，此处已按源码注入通道（URL path / PHP_SELF）修正；请勿使用 curl|sh 形式自动执行。

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
| `xss` | CWE-79 | 是 | 2 |
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
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.1 | 是 |
| surface_mapper | 攻击面测绘 | 8.33 | 是 |
| deep_finder | LLM 深挖 | 11.24 | 是 |
| candidate_screener | 候选筛选 | 4.3 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.12 | 是 |
| coordinator | 管线协调 | 5.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
