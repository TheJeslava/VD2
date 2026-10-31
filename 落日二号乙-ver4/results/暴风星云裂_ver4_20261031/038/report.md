# 落日二号乙漏洞挖掘报告 — 20261031-164539-54ada6

- 生成时间：2026-10-31T08:46:28.480311+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\038.zip`
- 输入模式：`zip`
- SHA256：`c09d22cf17e0571866be3b8075d761031599ef920bd9e7aa6bd584dbd9a3cd5a`
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

本次汇总基于单文件 PHP 脚本 038.php（57 行）的源码审计结果，共交付 2 条去重后的 SQL 注入发现，均位于 038.php：GEN-5bc99d7a2891（critical，query 参数 id 拼接进 SQL，行 13 附近）与 LLM-b7203a166ab9（high，用户 ID 查询参数 id 直接拼接，行 34 附近），两条均带 POC。最高危为 GEN-5bc99d7a2891（critical，CWE-89），其证据来自规则匹配，属静态源码证据，POC 为文本工件，未做动态验证。POC 齐全度为 2/2（均有 POC），但均为静态/HTTP 文本 POC，未执行、未搭建沙箱、未动态复现。除 SQL 注入外，其余注入类（command_injection / path_traversal / xss）与配置类（weak_hash / weak_crypto / weak_random / insecure_cookie / hardcoded_secret / trust_boundary）在本次 findings 中均无交付项，需按档位与人工复核处理，不能表述为不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 038.php（57 行，已完整展示 1-57 行）。审计确认：第 3 行 `isset($_GET['Submit'])` 为入口，第 5 行读取 `$_GET['id']`，第 11/32 行以单引号拼接进 SQL，第 13/34 行分别经 mysqli_query 与 SQLite query 执行，构成完整 SQL 注入链（CWE-89），已作为唯一 finding 交付。其余攻击面核查结论：未发现命令执行（无 exec/system/passthru）、文件包含/路径穿越（无 include/fopen/readfile）、反序列化、SSRF、模板注入、XSS 输出（第 46/52 行输出为静态字符串，不含 $id）、弱哈希/弱加密/弱随机（无 md5/sha1/rand/mt_rand）、不安全 Cookie（无 setcookie）、硬编码密钥（无凭据常量）。第 49 行使用 `$_SERVER['SERVER_PROTOCOL']` 构造 header，属服务端自身字段，非攻击者可控，不构成注入。未闭合线索：缺少 php.ini/Web 服务器配置与包含链，无法确认该脚本是否在鉴权之后执行；缺少数据库 schema 与连接配置，无法评估多语句执行与文件读写权限。code_pack 之外无其它文件，未覆盖范围即整个仓库仅此一文件。

未覆盖 / 证据缺口：
- 无法确认 038.php 是否可被外部直接请求（缺 Web 服务器/rewrite 配置）
- 无法确认是否被其他入口 include 及是否处于认证之后
- 缺少数据库配置与 schema，无法评估多语句/文件权限扩展
- 未提供运行时部署方式，命令执行类汇点不存在，无需评估

## 3. Findings

### F-1: 038.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该输入在 038.php:5 被读取后未做任何类型转换、转义或参数化，直接以字符串拼接方式进入 038.php:11 构造的 SQL 语句：`$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`。由于 `$id` 被包裹在单引号内且未经过 mysqli_real_escape_string 或预处理语句处理，攻击者可闭合单引号并注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。随后该拼接后的 `$query` 在 038.php:13 被传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行，污点从 source 到 sink 全程无有效净化，利用链闭合。代码注释显示已移除 'or die' 以抑制 MySQL 错误回显，但这只影响报错信息的可见性，不构成任何防护。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 038.php（端点写作 /038）的 GET 型 SQL 注入 POC。源码在 038.php:13 处将外部可控的 GET 参数 id 拼接到 SQL 查询中，未做参数化或有效转义。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/038?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-5bc99d7a2891`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑可被任意篡改：攻击者可绕过 user_id 过滤条件读取 users 表全部记录（first_name、last_name），并通过 UNION 注入进一步读取其他表（如用户名、口令哈希等敏感数据），造成数据泄露；在数据库账户权限过高时还可能读写文件或进一步影响数据库服务。属于机密性与完整性层面的严重风险。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：038.php:5 读取输入 → 038.php:11 字符串拼接进 SQL → 038.php:13 mysqli_query 执行，中间无参数化、无转义、无白名单校验，攻击者完全控制 SQL 语法结构。

**修复建议**

改用参数化查询（预处理语句）：使用 mysqli_prepare 配合 `SELECT first_name, last_name FROM users WHERE user_id = ?`，通过 bind_param('s' 或 'i', $id) 绑定参数，杜绝字符串拼接；同时对 `id` 做严格的类型校验（如强制转换为整数并校验范围）。若必须保留动态拼接，至少使用 mysqli_real_escape_string 并配合白名单，但首选参数化。另建议为数据库账户配置最小权限，避免 UNION 后可跨库读取。

**验证说明**

静态证据：入口 GET /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /038.php?id=1' UNION SELECT user,password FROM users-- -`（仅限授权测试，目标写 TARGET）。038.php:5 从 query 读取 `id`，值原样保留；038.php:11 将其拼入 `WHERE user_id = '$id'`，单引号被闭合，注入的 UNION 子句成为 SQL 语句一部分；038.php:13 调用 mysqli_query 执行该语句，返回攻击者指定的结果集，完成注入。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 038.php:13，外部输入来自 GET 参数 id，source→sink 链在给定代码范围内静态闭合，未发现参数化或有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动运行；禁止自动化批量执行。request.http 中 Content-Length 仅作示例，实际以发送工具计算为准。

### F-2: 038.php 用户 ID 查询参数 id 直接拼接进 SQL 语句导致 SQL 注入（DVWA SQL Injection 场景）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`038.php:5-34`
- **来源**：`llm_finding`

**描述**

脚本在 `isset($_GET['Submit'])` 成立时，直接把 `$_GET['id']` 赋给 `$id`（第 5 行），未做任何类型转换、转义或参数化，随后在第 11 行（MySQL 分支）与第 32 行（SQLite 分支）以单引号包裹方式拼接进 `SELECT first_name, last_name FROM users WHERE user_id = '$id';`，并分别交给 `mysqli_query()`（第 13 行）与 `$sqlite_db_connection->query()`（第 34 行）执行。攻击者可通过闭合单引号注入任意 SQL 片段（如 UNION SELECT 读取其他表、布尔/时间盲注），从而读取数据库中的任意数据（用户表、凭据等）。代码中不存在白名单、`intval()`、`mysqli_real_escape_string()` 或预处理语句，属于典型的 source→sink 直连。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:34 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 13 行）与 $sqlite_db_connection->query($query)（第 34 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:3` | 判断 `Submit` 参数是否存在，决定是否进入注入分支 | $_GET['Submit'] 存在即进入 |  |
| 2 | `038.php:5` | 从 GET 参数读取 `id` 并赋给 $id，无任何过滤 | 原始攻击者字符串 |  |
| 3 | `038.php:11` | 将 $id 以单引号包裹拼接进 SQL 字符串（MySQL 分支） | 字符串拼接，单引号可闭合 |  |
| 4 | `038.php:13` | 拼接后的 SQL 交给 mysqli_query 执行 | 完整恶意 SQL 语句被执行 |  |
| 5 | `038.php:32` | SQLite 分支同样拼接 $id 并交给 query() 执行（第 34 行） | 完整恶意 SQL 语句被执行 |  |

**POC**

针对 /038.php（GET）的 SQL 注入 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/038.php?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b7203a166ab9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可读取数据库中任意表数据（包括用户凭据），在具备多语句/文件权限时可进一步扩展；属于高危数据泄露与数据库接管风险。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 `id` 未经任何转义直接拼接进 SQL 并执行，无需认证即可触发（脚本本身无鉴权逻辑），source→sink 链在 CODE PACK 内完整闭合。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO 参数绑定）；对 `id` 强制转换为整数（如 `$id = (int)$_GET['id'];`）；移除拼接式 SQL。

**验证说明**

需确认 038.php 在部署环境中可被外部直接访问、$_DVWA['SQLI_DB'] 的实际取值以及数据库连接是否可用；未做动态验证。
模型 POC 要点：通过闭合 user_id 的单引号注入 UNION SELECT，读取 users 表以外的数据；也可用布尔条件验证注入点。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /038.php）：针对 038.php 的 GET 型 SQL 注入 POC。源码在 038.php:34 处将外部可控的 GET 参数 id 拼接到 SQL 查询中，未做参数化或有效转义，导致布尔/报错型注入。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /038.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 038.php:34，外部输入来自 GET 参数 id，source→sink 链在给定代码范围内静态闭合，未发现参数化或有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动运行；禁止自动化批量执行。request.http 中 Content-Length 仅作示例，实际以发送工具计算为准。

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
| `sql_injection` | CWE-89 | 是 | 2 |
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
| safety_guard | 安全防护 | 3.76 | 是 |
| surface_mapper | 攻击面测绘 | 10.33 | 是 |
| deep_finder | LLM 深挖 | 9.29 | 是 |
| candidate_screener | 候选筛选 | 4.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.35 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.46 | 是 |
| coordinator | 管线协调 | 7.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
