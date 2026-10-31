# 落日二号乙漏洞挖掘报告 — 20261030-224947-795700

- 生成时间：2026-10-30T14:50:22.515259+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\038.zip`
- 输入模式：`zip`
- SHA256：`c09d22cf17e0571866be3b8075d761031599ef920bd9e7aa6bd584dbd9a3cd5a`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：038.php 中 `id` 参数直接拼接进 SQL 查询（MySQL/SQLite 双分支），类型 sql_injection，严重度 high，已附带 POC（HTTP 型，可动态复现路径清晰）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，无缺失。未交付任何二次注入链（输入中无二次注入证据）。需注意：本次 min_severity=high、suppressed_count=0，因此不存在被策略抑制的候选；但攻击面测绘提出的 path_traversal、command_injection、trust_boundary、weak_hash、weak_random、insecure_cookie、weak_crypto 等方向均未形成 finding，属于未覆盖而非已排除，需人工按源码复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 038.php（57 行，DVWA SQL 注入练习页）。已逐行审计：第 3 行 `isset($_GET['Submit'])` 为入口，第 5 行 `$_GET['id']` 为唯一外部输入，第 11/32 行字符串拼接、第 13/34 行执行构成完整 SQL 注入链，MySQL 与 SQLite 两个分支均存在同一缺陷，已合并为一条 finding。第 44-52 行的 404/存在性反馈为布尔盲注提供了可观测差异。未发现命令执行、文件包含、反序列化、SSRF、XSS 输出点（`$html` 仅拼接固定字符串，无用户输入回显）、弱哈希/弱随机/不安全 Cookie/弱加密等线索；`$_DVWA`、`$GLOBALS["___mysqli_ston"]`、`$sqlite_db_connection` 定义在 CODE PACK 之外，无法确认其初始化，但不影响注入链闭合。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 无 composer.json/框架配置/Web 服务器配置，无法确认部署方式、PHP 版本与访问控制
- `$_DVWA['SQLI_DB']`、数据库连接对象定义在 code_pack 之外，无法确认实际生效分支
- 无数据库 schema，无法确认 users 表字段与可联合查询的其它表
- 页面是否回显查询结果未知，影响直接回显注入与盲注的取舍

## 3. Findings

### F-1: DVWA SQL 注入页 038.php 中 `id` 参数直接拼接进 SQL 查询（MySQL/SQLite 双分支）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`038.php:5-13`
- **来源**：`llm_finding`

**描述**

038.php 在 `isset($_GET['Submit'])` 成立时，直接把 `$_GET['id']` 赋给 `$id`（第 5 行），未做任何类型转换、转义或参数化，随后在第 11 行（MYSQL 分支）与第 32 行（SQLITE 分支）以单引号包裹方式拼进 `SELECT first_name, last_name FROM users WHERE user_id = '$id';`，分别交给 `mysqli_query()`（第 13 行）与 `$sqlite_db_connection->query()`（第 34 行）执行。攻击者可通过闭合单引号注入任意 SQL 片段，读取 users 表全部数据、联合查询其他表，或基于第 44-52 行的“User ID exists / MISSING”布尔差异做盲注。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 13 行）；SQLITE 分支 $sqlite_db_connection->query($query)（第 34 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:3` | 判断 `Submit` 参数存在，进入注入处理分支 | 攻击者控制请求参数集合 |  |
| 2 | `038.php:5` | 直接读取 `$_GET['id']` 赋给 `$id`，无 trim/intval/转义 | 原始攻击者字符串，未过滤 |  |
| 3 | `038.php:11` | 将 `$id` 以单引号包裹拼入 SQL 语句，形成 `user_id = '$id'` | 字符串拼接，单引号可被闭合 |  |
| 4 | `038.php:13` | 拼接后的 `$query` 交给 `mysqli_query` 执行（SQLITE 分支对应第 32/34 行） | 完整恶意 SQL 被执行 | 无 mysqli_real_escape_string、无预处理语句、无白名单校验 |

**POC**

针对 /038.php（GET）的 SQL 注入 POC。注入点为 GET 参数 id，源码 038.php:13 将外部输入直接拼入 SQL 查询，未做参数化或有效转义。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/038.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-48e11c62dd6c`
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可读取数据库任意表数据（含用户凭据哈希），并可进一步基于布尔差异做完整盲注提取，导致数据泄露与后续账户接管。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部可达（GET 参数直达），无需认证，source→sink 链在 CODE PACK 内完整闭合（第 5→11→13 行，SQLITE 分支第 32→34 行），无任何过滤或参数化。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param / PDO prepared statement）；若必须拼接，至少对 `$id` 做 `intval()` 强制整型转换并校验白名单。

**验证说明**

需确认部署环境 `$_DVWA['SQLI_DB']` 取值与数据库连接是否可用；页面是否回显查询结果决定是直接回显注入还是仅布尔盲注。POC 仅为文本，未执行。
模型 POC 要点：利用 `id` 参数闭合单引号，用 UNION 读取 users 表凭据字段；或使用布尔条件做盲注。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /038.php）：符合 CWE-89（SQL 注入）。漏洞位于 038.php:13，外部输入来自 GET 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；所有请求中的目标统一为 TARGET:8080 占位符。执行前须替换 TARGET 并获得授权。POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。

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
| safety_guard | 安全防护 | 3.37 | 是 |
| surface_mapper | 攻击面测绘 | 8.4 | 是 |
| deep_finder | LLM 深挖 | 9.41 | 是 |
| candidate_screener | 候选筛选 | 2.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.93 | 是 |
| coordinator | 管线协调 | 6.6 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
