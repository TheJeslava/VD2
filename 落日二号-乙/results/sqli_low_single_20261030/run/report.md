# 落日二号乙漏洞挖掘报告 — 20261030-220605-b30e19

- 生成时间：2026-10-30T14:06:40.656280+00:00
- 输入：`C:\Users\liyuf\Desktop\794\落日二号-乙\results\sqli_low_single_20261030\low.php.single.zip`
- 输入模式：`zip`
- SHA256：`e262a228e4d8a95be9e181ef504e2f3a0f43b5102553f79ecdf0d07bf0f65060`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`medium`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅包含 1 条已去重发现：DVWA sqli low 等级文件 sqli/source/low.php 第 11 行附近，$_REQUEST['id'] 未经预处理直接拼接进 SELECT 查询，构成 SQL 注入（high，llm_inferred，基于源码推断，未做动态验证）。该发现已附带 POC 文本（HTTP 型，目标以 TARGET 占位），POC 齐全度为 1/1。最高危项即此条 SQL 注入，链路短（请求参数直达 SQL 汇点）、可达性高。本次无二次注入链、无外部 AWVS 证据、无配置型候选（weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary 均未出现在 findings 中）。需强调：所有结论均为静态源码推断，未经任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含 1 个文件 sqli/source/low.php（共 56 行，仅展示 1-46 行）。已逐行审计：第 3 行以 $_REQUEST['Submit'] 作为入口开关，第 5 行从 $_REQUEST['id'] 取污点，第 10 行（MYSQL 分支）与第 31 行（SQLITE 分支）均将 $id 直接拼入 SELECT 语句，第 11 行 mysqli_query 执行并在失败时 die() 回显 mysqli_error，第 34 行 SQLite3::query 同样执行拼接语句。确认存在一条完整闭合的 SQL 注入链（MYSQL 分支），已作为 finding 交付；SQLITE 分支为同一污点源、同一参数、同一文件内的同类拼接，属同一漏洞的不同数据库后端实现，未重复单独立项。第 20 行将 $id 原样回显到 HTML（<pre>ID: {$id}...），存在反射型 XSS 可能，但需结合响应头/编码策略确认，且价值低于 SQLi，未单独立项，记入线索。未覆盖范围：文件第 47-56 行未送入（truncated=false 但 shown_ranges 仅 1-46），无法确认后续是否有额外 sink；无 README、composer.json、数据库 schema、Web 服务器与 PHP 配置，无法评估 magic_quotes、数据库最小权限与实际暴露方式；无端点清单，POC 路径按文件路径推断。

未覆盖 / 证据缺口：
- 文件 47-56 行未在 code_pack 中展示，未审计
- 缺少数据库 schema，无法确认 users 表外可读取范围
- 缺少部署/认证配置，无法确认是否需登录及实际 URL 路由
- 第 20 行 $id 原样回显的反射型 XSS 未做响应头/编码确认，未立项
- SQLITE 分支（第 31、34 行）注入与 MYSQL 分支同源，未单独报告

## 3. Findings

### F-1: DVWA sqli low 等级：$_REQUEST['id'] 直接拼接进 SELECT 查询导致 SQL 注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`sqli/source/low.php:5-11`
- **来源**：`llm_finding`

**描述**

脚本在 isset($_REQUEST['Submit']) 成立时，直接把 $_REQUEST['id'] 赋给 $id（第 5 行），随后在第 10 行以单引号包裹的方式拼入 SQL 语句 "SELECT first_name, last_name FROM users WHERE user_id = '$id';"，未做任何转义、类型转换或参数化。攻击者可通过 id 参数闭合单引号并注入任意 SQL（UNION 联合查询、布尔/时间盲注、堆叠查询视驱动而定），读取 users 表乃至数据库内其它数据。第 11 行在查询失败时通过 die() 回显 mysqli_error，构成基于报错的注入确认与数据外带通道。

**source / sink**

- source：query `id`（sqli/source/low.php）
- sink：sqli/source/low.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行），$query 由第 10 行字符串拼接构造

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `sqli/source/low.php:3` | 以 isset($_REQUEST['Submit']) 作为进入注入分支的开关，攻击者只需附带 Submit 参数即可触发 | 请求参数 Submit 存在即进入分支 |  |
| 2 | `sqli/source/low.php:5` | 从 $_REQUEST 中取出 id 并赋给 $id，无任何过滤/转义/类型校验 | 原始攻击者字符串，未净化 |  |
| 3 | `sqli/source/low.php:10` | 将 $id 以单引号包裹拼入 SELECT 语句，攻击者可用 ' 闭合字符串上下文 | 污点字符串进入 SQL 语法上下文 |  |
| 4 | `sqli/source/low.php:11` | 拼接后的 $query 交给 mysqli_query 执行；失败时 die() 回显 mysqli_error，形成报错注入通道 | SQL 语句被执行，错误信息回显到响应 |  |

**POC**

针对 sqli/source/low.php 第 11 行（GET 路由 /sqli/source/low.php）的 SQL 注入 POC。注入点为 GET 查询参数 id，其值未经净化直接进入 SQL 查询汇点，构成 CWE-89。目标地址统一使用 TARGET 占位符，POC 仅为文本工件，不执行、不联网。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/sqli/source/low.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/sqli/source/low.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-a4152ee0bbec`
- 执行状态：未执行（`executed=False`）

**影响**

未授权攻击者可读取 users 表全部记录（用户名/口令哈希等）及同库其它表数据，并可通过报错信息进一步枚举数据库结构，导致敏感数据大规模泄露。

**CVE / CWE 论证**

CWE-89：外部 HTTP 参数 id 未经参数化直接拼入 SQL 并在 mysqli_query 执行，source→sink 链路在 CODE PACK 内完整闭合（第 5→10→11 行），无需认证即可触发，属典型 SQL 注入。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param 或 PDO 占位符），对 id 做整型强转（如 (int)$id）；关闭向用户回显数据库错误信息，改为记录日志并返回通用错误页。

**验证说明**

需动态确认：1) 目标实际暴露路径与是否需要登录；2) $_DVWA['SQLI_DB'] 实际取值（MYSQL 分支已闭合，SQLITE 分支第 31 行同样存在拼接注入）；3) 数据库账号权限是否限制堆叠/文件读写；4) 是否开启 display_errors 影响报错回显。
模型 POC 要点：利用 id 参数闭合单引号，先用 UNION SELECT 回显任意数据，再用报错/布尔条件确认注入点。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /sqli/source/low.php）：符合 CWE-89（SQL 注入）。漏洞位于 sqli/source/low.php 第 11 行，外部输入来自 GET 查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化/参数化处理，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本形式请求，不生成可自动执行的脚本；如需手工复现，请将 TARGET 替换为已授权实例地址后手动发送上述请求。禁止对非授权目标使用。

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
| `sql_injection` | CWE-89 | 是 | 1 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 0 |
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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.48 | 是 |
| surface_mapper | 攻击面测绘 | 6.62 | 是 |
| deep_finder | LLM 深挖 | 10.85 | 是 |
| candidate_screener | 候选筛选 | 3.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.05 | 是 |
| coordinator | 管线协调 | 5.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
