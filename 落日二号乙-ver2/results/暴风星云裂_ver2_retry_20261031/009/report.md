# 落日二号乙漏洞挖掘报告 — 20261031-001806-925698

- 生成时间：2026-10-30T16:18:56.433440+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次汇总基于已去重的 3 条 findings，全部为 009.php 中的 SQL 注入（CWE-89），严重度均为 critical，且 3 条均附带 POC（HTTP 型，可动态复现）。最高危的是 009.php 第 22 行用户存在性检查注入、第 29 行用户详情查询注入、第 73 行日志 INSERT 写入注入，三者均属请求参数直接拼接进 SQL 语句的单跳污点链，利用门槛低。POC 齐全（with_poc=3/3），但均为静态构造文本，未做动态验证。覆盖统计仅 1 个文件、1 种语言（php）、0 个端点、无框架，属单文件小工具类脚本，审计面很窄。surface_notes 中提出的路径遍历/文件包含、反射型 XSS、配置类风险（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均未被 findings 覆盖，需人工复核，不能据此判定不存在。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：仅审计 009.php 前 61 行（共 79 行，62-79 未送入）。发现 user_id 参数拼接 SQL 且 token 硬编码可绕过访问控制，构成 IDOR/注入候选。第 6 行热点实为注释，真正 sink 在 21/28 行。未覆盖 62-79 行及部署配置。

未覆盖 / 证据缺口：
- 009.php 62-79 行未送入
- 无 php.ini/部署配置
- 无认证上下文

## 3. Findings

### F-1: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 `user_id`（009.php:17 读取）传入任意字符串，该值未经转义或参数化即被拼接进 `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'"`（009.php:21），随后在 009.php:22 由 `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` 执行。由于 `$id` 被单引号包裹但未做 `mysqli_real_escape_string` 或预处理绑定，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1`、`1' UNION SELECT ...`）。该查询是后续逻辑的前置判断，注入结果直接决定 `$user_exists` 分支走向，因此可被用于布尔盲注或联合查询读取任意表数据。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-769728152047`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可读取 users 表及其他库表内容（用户名、口令哈希、个人信息）；结合后续查询可进一步枚举/篡改数据；若数据库账户权限过高，可能读写文件或造成数据完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：`user_id` 来自 HTTP 查询参数，无需认证即可触发；利用链闭合：009.php:17 取值 → 009.php:21 字符串拼接 → 009.php:22 mysqli_query 执行，中间无白名单、类型转换或参数化，校验无效。

**修复建议**

改用预处理语句：`$stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；同时对 `$id` 做整型强制转换（`$id = (int)$_GET['user_id']`）作为纵深防御；数据库账户遵循最小权限，禁止 FILE 权限。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 参数 `user_id` → 变量 `$id`（009.php:17）→ 拼接进 `$check_query`（009.php:21）→ `mysqli_query` 执行（009.php:22）→ 注入生效并影响 `$user_exists` 分支。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行 SQL 注入汇点的 POC。注入通道为查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。外部输入来自查询参数 user_id，在 009.php:22 处进入 SQL 语句，静态链闭合且未见有效参数化或转义。
POC 备注：保留原请求结构；脚本仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-2: 009.php 用户详情查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

同一外部输入 `user_id`（009.php:17）在通过存在性检查后，被再次拼接进 `$query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"`（009.php:28），并在 009.php:29 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。`$id` 未转义、未参数化，攻击者可用 `1' UNION SELECT ...` 直接控制结果集，将任意表字段映射到 first_name/last_name/avatar 输出位置，实现数据外带。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-1f0233ec126f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：通过 UNION 注入把任意表（如凭据表）内容回显到页面字段，导致敏感信息泄露；也可用于报错注入获取库结构。

**CVE / CWE 论证**

CWE-89。外部可达：`user_id` 为 HTTP 查询参数，无需认证；利用链闭合：009.php:17 → 009.php:28 拼接 → 009.php:29 执行，无有效净化。注意该注入点位于 `$user_exists` 为真的分支内，攻击者可用恒真条件（如 `1' OR '1'='1`）同时满足前置检查与本次查询。

**修复建议**

使用预处理语句绑定 `user_id` 整型参数；对输出字段做 HTML 转义；限制数据库账户权限；对 `user_id` 做严格数字白名单校验。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 参数 `user_id` → `$id`（009.php:17）→ 前置检查通过 → 拼接进 `$query`（009.php:28）→ `mysqli_query` 执行（009.php:29）→ UNION/布尔注入回显数据。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行 SQL 注入汇点的 POC。注入通道为查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。user_id 在 009.php:29 处拼入 SQL，未见净化。
POC 备注：保留原请求结构；文本工件，不执行。

### F-3: 009.php 日志写入 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

009.php:71-72 构造 `$log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')"`，其中 `{$current_user_id}`、`{$target_id}` 为无引号数值位，`'{$ip}'` 为引号包裹的字符串位，均未转义，随后在 009.php:73 由 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。`$target_id` 与 `$current_user_id` 源自同一外部 `user_id` 输入链路（009.php:17），`$ip` 通常来自 `REMOTE_ADDR` 或可伪造头。攻击者可在数值位直接注入（如 `1),(1,1,(SELECT ...))-- -`）或闭合 `$ip` 单引号注入，实现堆叠/子查询注入。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-07807b8ead6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被污染，可插入伪造日志、通过子查询外带数据（盲注/报错注入），并可能破坏审计日志完整性；若驱动允许堆叠语句，可进一步执行任意 SQL。

**CVE / CWE 论证**

CWE-89。外部可达：`target_id`/`user_id` 来自 HTTP 参数，`ip` 可能来自请求头，无需认证；利用链闭合：009.php:17 → 009.php:71-72 拼接 → 009.php:73 执行，无参数化。该点置信度略低于前两处，因 `$current_user_id`、`$target_id`、`$ip` 的具体赋值行未在片段中给出，但拼接与执行证据明确。

**修复建议**

使用预处理语句绑定 user_id、target_id、ip_address 三个参数；对数值字段强制整型转换；`$ip` 使用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验后再绑定；审计日志表使用独立最小权限账户。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 参数 `user_id` → `$target_id`/`$current_user_id`（009.php:17 链路）→ 拼接进 `$log_query`（009.php:71-72）→ `mysqli_query` 执行（009.php:73）→ 注入写入/外带数据。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行 SQL 注入汇点的 POC。注入通道为查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。user_id 在 009.php:73 处拼入 SQL，未见净化。
POC 备注：保留原请求结构；文本工件，不执行。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.28 | 是 |
| surface_mapper | 攻击面测绘 | 9.45 | 是 |
| deep_finder | LLM 深挖 | 7.3 | 是 |
| candidate_screener | 候选筛选 | 6.05 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.75 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.21 | 是 |
| coordinator | 管线协调 | 7.06 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
