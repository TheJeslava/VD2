# 落日二号乙漏洞挖掘报告 — 20261031-010339-20bb60

- 生成时间：2026-10-30T17:04:16.566117+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\040.zip`
- 输入模式：`zip`
- SHA256：`a7a3a902cbf51a117eedf45420f67900d6bd15338d9838b48c773e4175ce8254`
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

本次汇总基于已去重的 2 条 LLM 源码审计发现，均集中在单文件 PHP 脚本 040.php。最高危为 LLM-b04dcf20e12f：SQL 注入（high），$_SESSION['id'] 被直接拼接进 SQL 查询，且存在 MySQL/SQLite 双分支；其次为 LLM-0c0cfd9fd4a7：未转义 $id 输出到 HTML 的 XSS（medium）。两条发现均带 POC（with_poc=2），但均为静态源码推断（origin=llm_finding），未做动态验证，POC 属静态证据型，不能宣称可动态复现。本次无二次注入链交付，无外部 AWVS 证据。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 040.php（可见 1-46 行，共 53 行，末尾 47-53 行未送入）。该文件为 DVWA SQL 注入模块后端片段：$_SESSION['id'] 未过滤直接拼接进 MySQL（第 10-11 行）与 SQLite（第 28、31 行）查询，构成 SQL 注入；同一 $id 未转义输出到 HTML（第 20、44 行），构成 XSS。未发现命令执行、文件包含、反序列化、SSRF 等汇点。未闭合线索：040.php 是否被 Web 服务器直接暴露、$_SESSION['id'] 的实际写入路径、$_DVWA['SQLI_DB'] 配置值、第 47-53 行内容均无法从输入确认。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未送入 code_pack
- 无 Web 服务器配置，无法确认 040.php 外部可达性
- 无 $_SESSION['id'] 写入点源码，会话污染路径需人工确认
- 无 $_DVWA 配置与数据库连接初始化代码

## 3. Findings

### F-1: DVWA SQL 注入模块：$_SESSION['id'] 直接拼接进 SQL 查询（MySQL/SQLite 双分支）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:5-11`
- **来源**：`llm_finding`

**描述**

040.php 从 $_SESSION['id'] 读取 $id，未做任何类型转换、转义或参数化，直接以单引号包裹拼入 SELECT 语句。MySQL 分支（第 10 行）与 SQLite 分支（第 28 行）均存在同一缺陷。攻击者只要能控制会话中的 id 值（DVWA 的 SQL 注入页面会把用户提交的 id 写入 $_SESSION['id']，或通过会话固定/会话注入手段写入），即可闭合单引号注入任意 SQL 语法，读取 users 表以外的数据（如 dvwa.users 的 password 字段、information_schema），造成数据库信息泄露与认证凭据窃取。

**source / sink**

- source：session `id`（040.php:5）
- sink：040.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:5` | 从会话读取 id，未做任何过滤 | $id = 攻击者可控字符串 |  |
| 2 | `040.php:10` | 以单引号包裹拼入 SQL 语句 | SQL 文本中嵌入未转义输入，单引号可闭合 |  |
| 3 | `040.php:11` | mysqli_query 执行拼接后的语句 | 注入的 SQL 语法被数据库执行 |  |

**POC**

针对 /vulnerabilities/sqli/（GET）的 SQL 注入 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/sqli/?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b04dcf20e12f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取任意数据库表（含用户口令哈希），导致凭据泄露与进一步横向利用。

**CVE / CWE 论证**

CWE-89：外部可控会话值未经参数化直接拼接进 SQL，链闭合，无需额外权限即可触发。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO），并对 id 做整型强转；不要信任会话中的原始输入。

**验证说明**

需确认 040.php 是否被直接暴露、$_SESSION['id'] 的实际写入路径（DVWA 页面是否把 GET id 存入会话），以及 SQLI_DB 配置值。
模型 POC 要点：先通过 DVWA SQL 注入页面把恶意 id 写入会话，再访问本脚本触发拼接查询。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：针对 040.php:11 的 SQL 注入 POC（CWE-89）。注入点为 GET 参数 id，payload 为 ' OR '1'='1，目标地址统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：符合 CWE-89。漏洞位于 040.php:11，外部输入经 GET 参数 id 进入 SQL 查询汇点，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。目标地址使用 TARGET 占位符，需手动替换后由测试人员自行执行；管线不执行、不联网。禁止使用 DROP 等破坏性语句。

### F-2: 040.php 将未转义的 $id 直接输出到 HTML（反射/存储型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:20-20`
- **来源**：`llm_finding`

**描述**

第 20 行与第 44 行把 $id 直接插入 HTML 字符串 $html 输出，未做 htmlspecialchars 转义。若 $id 来自会话中的用户输入，则可注入脚本，在受害者浏览器执行，窃取会话或执行敏感操作。

**source / sink**

- source：session `id`（040.php:5）
- sink：040.php:20 $html 拼接输出到页面（第 20 行 / 第 44 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:5` | 读取会话 id | $id 含 HTML/JS 字符 |  |
| 2 | `040.php:20` | 未转义拼入 HTML 输出 | 脚本标签进入响应体 |  |

**POC**

针对 /vulnerabilities/sqli/（GET）的 跨站脚本 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/sqli/?id=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-0c0cfd9fd4a7`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意脚本，窃取会话 Cookie 或发起 CSRF。

**CVE / CWE 论证**

CWE-79：未转义输出用户可控数据到 HTML 上下文。

**修复建议**

输出前使用 htmlspecialchars($id, ENT_QUOTES, 'UTF-8')。

**验证说明**

需确认 $id 是否真能包含脚本字符（会话写入路径）以及输出是否直接进入响应。
模型 POC 要点：在会话 id 中写入脚本标签，访问 040.php 触发执行。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：针对 040.php:20 的反射型 XSS POC（CWE-79）。注入点为 GET 参数 id，payload 为 <script>alert(document.domain)</script>，目标地址统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：符合 CWE-79。漏洞位于 040.php:20，外部输入经 GET 参数 id 输出到 HTML 响应汇点，source→sink 链静态闭合且未见有效编码，具备远程触发条件。
POC 备注：仅限授权测试。目标地址使用 TARGET 占位符，需手动替换后由测试人员自行执行；管线不执行、不联网。

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
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.8 | 是 |
| surface_mapper | 攻击面测绘 | 8.69 | 是 |
| deep_finder | LLM 深挖 | 9.98 | 是 |
| candidate_screener | 候选筛选 | 3.77 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.66 | 是 |
| coordinator | 管线协调 | 5.81 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
