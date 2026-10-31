# 落日二号乙漏洞挖掘报告 — 20261031-173147-aa25cb

- 生成时间：2026-10-31T09:32:27.839685+00:00
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

本次汇总基于已去重的 2 条 LLM 发现，均集中在单文件 PHP 脚本 040.php：一条 high 级 SQL 注入（LLM-b04dcf20e12f，$_SESSION['id'] 直接拼接进 MySQL/SQLite 查询，约 11 行），一条 medium 级 XSS（LLM-0c0cfd9fd4a7，$id 未编码回显到 HTML，约 20 行）。最高危为 SQL 注入。两条均带 POC（has_poc=true，共 2/2），但均为静态证据 POC，未做动态验证，不能宣称可动态复现。未收到二次注入链输入，故本次不涉及二次注入三要素评估。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中 040.php 的 1-46 行（共 53 行，末尾 47-53 行未提供）。发现两条链：会话值 $_SESSION['id'] 未参数化拼接进 MySQL/SQLite 查询（第 10/28 行，sink 第 11/31 行）构成 SQL 注入；同一值未编码回显（第 20/44 行）构成 XSS。两条链的 source 均为会话变量，写入点不在 code_pack 内，故置信度受限。未发现命令执行、文件包含、SSRF、反序列化等汇点；weak_hash/weak_crypto/weak_random/insecure_cookie 在可见代码中无对应调用。未覆盖：040.php 第 47-53 行、上游会话写入逻辑、$_DVWA 配置与数据库连接配置。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未在 code_pack 中提供
- $_SESSION['id'] 的写入点不在 code_pack，无法确认外部可控性
- $_DVWA['SQLI_DB'] 配置取值未知，无法确定实际走 MySQL 还是 SQLite 分支
- 无部署配置（php.ini、Web 服务器）与认证机制信息

## 3. Findings

### F-1: DVWA SQL 注入（low 级别）：$_SESSION['id'] 直接拼接进 MySQL/SQLite 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:5-11`
- **来源**：`llm_finding`

**描述**

脚本从 $_SESSION['id'] 取出用户可控值 $id，未做任何转义或参数化，直接以单引号包裹拼接进 SQL 语句（第 10 行 MySQL 分支、第 28 行 SQLite 分支），随后分别交给 mysqli_query 与 sqlite 的 query() 执行。攻击者只要能让会话中的 id 变为任意字符串（例如通过 DVWA 的 SQL 注入页面把 id 写入会话，或任何可写该会话键的入口），即可闭合单引号注入任意 SQL 语法，读取 users 表之外的数据（如 dvwa 库中的 users/password 哈希），造成数据库信息泄露与潜在的数据篡改。

**source / sink**

- source：session `id`（040.php:5）
- sink：040.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:3` | 脚本检查 $_SESSION['id'] 是否存在，存在则进入注入分支 | 会话已建立且 id 键存在 |  |
| 2 | `040.php:5` | 从会话读取 id 到局部变量 $id，无任何过滤 | $id = 攻击者可控字符串 |  |
| 3 | `040.php:10` | 将 $id 以单引号包裹拼接进 SELECT 语句 | SQL 语句被攻击者输入改变语法结构 | 无转义、无参数化、无类型转换（未 intval），单引号可直接闭合 |
| 4 | `040.php:11` | mysqli_query 执行拼接后的语句并回显 first_name/last_name 与 $id | 注入结果通过 $html 回显（第 20 行） |  |

**POC**

针对 /040.php（GET）的 SQL 注入 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/040.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/040.php?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b04dcf20e12f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取数据库中任意表（如用户凭据哈希），并可进一步通过 UNION/子查询进行数据篡改或提权，导致数据库信息泄露与账户接管风险。

**CVE / CWE 论证**

CWE-89：外部可控会话值未经参数化直接拼接进 SQL 并执行，链闭合；DVWA 场景下需已登录会话，属认证后注入，但仍是真实可利用的 SQL 注入。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO），对 id 做 intval 强类型转换，禁止字符串拼接 SQL。

**验证说明**

需确认上游确实将用户输入写入 $_SESSION['id']（本 code_pack 未包含写入点），以及 $_DVWA['SQLI_DB'] 的实际取值分支。
模型 POC 要点：先使会话中的 id 变为注入 payload，再访问 040.php 触发拼接查询。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /040.php）：针对 040.php（GET）的 SQL 注入 POC。注入点为 GET 参数 id，源码 040.php:11 处将外部输入拼接进 SQL 查询且未见有效净化；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /040.php）：符合 CWE-89（SQL 注入）。漏洞位于 040.php:11，外部 GET 参数 id 未经参数化直接进入 SQL 查询，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权环境地址；建议先做基线再发载荷，保留响应长度/状态码对比记录。

### F-2: 040.php 将 $id 未编码回显到 HTML（反射/存储型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:20-20`
- **来源**：`llm_finding`

**描述**

第 20 行与第 44 行把 $id 直接插入 $html 字符串并输出到页面，未做 htmlspecialchars 等编码。若会话中的 id 含 HTML/JS，浏览器会执行，可窃取会话或触发敏感操作。

**source / sink**

- source：session `id`（040.php:5）
- sink：040.php:20 $html 拼接输出（第 20 行 / 第 44 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:5` | 从会话读取 id | $id 含 HTML 标签 |  |
| 2 | `040.php:20` | 将 $id 原样拼入 HTML 输出 | 未编码的 HTML/JS 进入响应体 | 无 htmlspecialchars/编码 |

**POC**

针对 /040.php（GET）的 跨站脚本 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/040.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/040.php?id=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-0c0cfd9fd4a7`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意 JS，窃取会话 Cookie 或发起 CSRF 式操作。

**CVE / CWE 论证**

CWE-79：会话值未编码回显到 HTML，链闭合；需会话可控。

**修复建议**

输出前使用 htmlspecialchars($id, ENT_QUOTES, 'UTF-8')。

**验证说明**

需确认上游写入点与页面实际渲染上下文。
模型 POC 要点：使会话 id 含脚本标签后访问页面。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /040.php）：针对 040.php（GET）的反射型跨站脚本 POC。注入点为 GET 参数 id，源码 040.php:20 处将外部输入输出到响应且未见编码；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /040.php）：符合 CWE-79（跨站脚本）。漏洞位于 040.php:20，外部 GET 参数 id 未经输出编码直接写入响应，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权环境地址；若输出位于属性或脚本上下文，需按实际上下文调整闭合方式，不得伪造未确认的字段。

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
| safety_guard | 安全防护 | 3.13 | 是 |
| surface_mapper | 攻击面测绘 | 9.49 | 是 |
| deep_finder | LLM 深挖 | 11.03 | 是 |
| candidate_screener | 候选筛选 | 3.24 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.39 | 是 |
| coordinator | 管线协调 | 5.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
