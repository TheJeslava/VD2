# 落日二号乙漏洞挖掘报告 — 20261031-163926-1fd4f6

- 生成时间：2026-10-31T08:40:18.708614+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次汇总仅基于已去重 findings 与攻击面测绘结果，未新增漏洞。共交付 3 条 sql_injection（均为 critical），全部位于单文件 PHP 脚本 009.php：第 22 行用户存在性检查、第 29 行用户信息查询、第 73 行日志写入，均带 POC（HTTP 型，可复现性依赖实际部署环境）。最高危为 009.php 的 SQL 注入链，输入直连 SQL 汇点、缺少参数化，属典型 CWE-89。POC 齐全（with_poc=3/3），但均为静态构造的 HTTP 请求文本，未做动态验证。二次注入链：本次输入未提供，故不涉及。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 009.php 第 1-61 行（共 79 行，62-79 行未送入）。发现 user_id 参数经正则校验后仍拼接 SQL，且 token 硬编码 'user_token' 使访问控制可绕过，构成越权读取与潜在 SQL 注入。第 7 行 dvwaCurrentUser() 拼接亦为注入面但来源为内部函数，未单列。62-79 行（日志写入部分）未覆盖，可能存在二次注入或日志注入，需补充代码。

未覆盖 / 证据缺口：
- 009.php 第 62-79 行未送入，日志写入逻辑未审计
- 无部署与认证配置，无法确认公网可达性
- dvwaCurrentUser() 实现未提供

## 3. Findings

### F-1: 009.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id`（009.php:17 读取）控制 `$id`，该值被赋给 `$current_user_id` 后直接以字符串拼接方式嵌入 INSERT 语句 `$log_query`（009.php:71-72：`VALUES ({$current_user_id}, {$target_id}, '{$ip}')`），随后在 009.php:73 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。代码中未见 `intval()`、`mysqli_real_escape_string()`、类型转换或预处理语句，`$current_user_id` 甚至未加引号，因此任何非数字内容都会直接改变 SQL 语法结构。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-07807b8ead6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可对后端数据库执行任意 SQL：通过 UNION/子查询读取 users 等表的凭据与个人信息（数据泄露），通过布尔/时间盲注枚举数据，在具备堆叠查询能力的驱动下可写入或篡改 bac_log 及其他表（数据完整性破坏），并可能借文件写入或高权限账户进一步扩大影响。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `user_id`，无需认证即可构造请求；利用链闭合：`user_id` → `$id` → `$current_user_id` → `$log_query` 字符串拼接 → `mysqli_query` 执行，中间无有效净化，属典型一次注入。

**修复建议**

改用预处理语句（`mysqli_prepare` + `bind_param('iii', ...)` 或 PDO 占位符），对 `user_id`、`target_id` 强制 `intval()`/类型校验，`ip` 使用 `mysqli_real_escape_string()` 或绑定参数；对数据库账户实施最小权限，关闭堆叠查询；对输入做白名单校验并统一错误处理，避免回显 SQL 错误。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=<payload>` → 009.php:17 读取 query `user_id` → 赋值 `$id`/`$current_user_id` → 009.php:71-72 拼接进 INSERT 语句 → 009.php:73 `mysqli_query` 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行 SQL 注入点的 POC。注入通道为 GET 查询参数 user_id，payload 为布尔恒真式 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:73，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效参数化或转义。
POC 备注：POC 仅为文本工件，不执行、不联网；执行前须替换 TARGET 并确认授权。保留原请求结构，仅补充基线与对照步骤。

### F-2: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

同一 query 参数 `user_id`（009.php:17）进入 `$id`，在 009.php:21 被拼接为 `SELECT user_id FROM users WHERE user_id = '$id'`，并于 009.php:22 由 `mysqli_query` 执行。虽然该值被单引号包裹，但未做转义，攻击者可闭合引号注入 `' OR '1'='1` 等条件改变查询语义。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-769728152047`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过用户存在性判断、枚举或读取 users 表数据，并作为布尔/联合注入点泄露数据库内容；与日志写入点组合可形成完整的数据读取与篡改链。

**CVE / CWE 论证**

CWE-89。外部可达性：HTTP query 参数 `user_id` 直接可达，无需认证；利用链闭合：`user_id` → `$id` → `$check_query` → `mysqli_query`（009.php:22），无参数化或转义。

**修复建议**

使用预处理语句绑定 `user_id`，或至少 `intval()` 强制整数化后再拼接；禁止将外部输入直接拼入 SQL；统一使用参数化数据访问层。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=' OR '1'='1` → 009.php:17 读取 → 009.php:21 拼接 → 009.php:22 执行，条件被篡改。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行 SQL 注入点的 POC。注入通道为 GET 查询参数 user_id，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:22，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网；执行前须替换 TARGET 并确认授权。

### F-3: 009.php 用户信息查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

query 参数 `user_id`（009.php:17）经 `$id` 在 009.php:28 拼入 `SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';`，并在 009.php:29 由 `mysqli_query` 执行。该分支在 `$user_exists` 为真时触发，未使用转义或参数化，单引号可被闭合注入。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-1f0233ec126f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取任意用户资料（姓名、头像、user_id），结合 UNION 可拖取其他表数据，造成敏感信息泄露；若查询结果回显到页面，还可放大为批量数据窃取。

**CVE / CWE 论证**

CWE-89。外部可达性：HTTP query 参数 `user_id` 无需认证即可触发；利用链闭合：`user_id` → `$id` → `$query` → `mysqli_query`（009.php:29），无有效净化。

**修复建议**

改为预处理语句并绑定 `user_id` 为整数；对输出做上下文转义；限制数据库账户权限并关闭详细错误回显。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=1' UNION SELECT ...-- -` → 009.php:17 读取 → 009.php:28 拼接 → 009.php:29 执行，返回被篡改的结果集。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行 SQL 注入点的 POC。注入通道为 GET 查询参数 user_id，payload 为 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:29，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网；执行前须替换 TARGET 并确认授权。

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
| `sql_injection` | CWE-89 | 是 | 3 |
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
| safety_guard | 安全防护 | 4.52 | 是 |
| surface_mapper | 攻击面测绘 | 8.7 | 是 |
| deep_finder | LLM 深挖 | 7.02 | 是 |
| candidate_screener | 候选筛选 | 7.29 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.14 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.58 | 是 |
| coordinator | 管线协调 | 6.96 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
