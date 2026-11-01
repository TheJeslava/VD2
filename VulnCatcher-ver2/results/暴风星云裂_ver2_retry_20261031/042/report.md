# 落日二号乙漏洞挖掘报告 — 20261031-002322-b176f7

- 生成时间：2026-10-30T16:24:13.456666+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 042.php，类型均为 sql_injection（CWE-89），严重度 critical，且两条都带有 POC。最高危的是 GEN-65bf75938433：042.php 中 query 参数 id 被直接拼入 SQL 查询（行 1-12），属于典型的一次注入，污点从请求参数直达查询汇点，可利用性最高。另一条 GEN-06e09e46e3b6（042.php:55）标注为“查询为常量语句、证据不足”，虽然 has_poc=true，但规则自身已说明未构成可利用注入，建议按低置信/待复核处理，不应与前者等同。POC 齐全性：2/2 条 finding 均标记 has_poc=true，但均为静态文本 POC（HTTP 型），本次未做任何动态验证，不能宣称可动态复现。二次注入链：输入未提供任何二次注入链，且 surface_notes 明确提示若存在“参数写入存储→读取→汇点”需单独定位写点/读点/汇点，本次无此类证据，故不认定二次注入。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 042.php（59 行，DVWA SQL 注入练习页）。已审计：POST id 参数 → mysqli_real_escape_string → 无引号拼接 → mysqli_query/SQLite query 的完整污点链，确认数字型 SQL 注入（第 5、7、11、12、27、30 行），MYSQL 与 SQLITE 两分支均受影响，已作为 high 级 finding 交付。其余攻击面核查结论：未发现命令执行、文件包含/路径拼接、反序列化、SSRF、模板等汇点；第 21/43 行 $id 与数据库字段被拼入 HTML 回显，但 $id 已经 mysqli_real_escape_string 处理且输出未做 HTML 编码，理论上存在反射型 XSS 可能，但需结合 DVWA 外层页面与浏览器上下文确认，证据不足以单独申报，故未列入 findings。配置类线索（硬编码凭据、弱哈希、弱随机、Cookie 标志位）在本文件中无对应代码，未发现。未覆盖：php.ini/disable_functions、Web 服务器配置、认证与部署暴露情况、数据库 schema 均不在 CODE PACK 内，无法确认。输入中未出现诱导性 prompt_injection 文本。

未覆盖 / 证据缺口：
- 无 php.ini/disable_functions 信息，无法确认危险函数是否被禁用
- 无路由/认证配置，无法确认 042.php 是否需登录及公网暴露
- 无数据库 schema，UNION 查询列数与表结构需运行时确认
- 第 21/43 行 HTML 回显的反射型 XSS 需结合外层页面上下文确认，证据不足未申报

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id`（042.php:5 读取）提交任意字符串。该值未经任何过滤、类型转换或参数化，被直接拼接进 SQL 语句：042.php:11 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于数值上下文且无引号包裹，攻击者可构造如 `1 UNION SELECT user, password FROM users` 或布尔/时间盲注载荷改变查询语义。校验无效的原因：代码路径中不存在 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单校验，污点从 source 到 sink 全程未净化。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:12 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:12` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /042（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/042?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-65bf75938433`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可读取 users 表之外的任意表（如用户名/口令哈希），并可进一步通过 UNION/盲注枚举数据库结构；结合 042.php:12 的 `mysqli_error` 回显，错误信息会直接输出到响应，构成报错型注入，显著降低利用门槛。若数据库账户权限过高，还可能造成数据篡改。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 042.php 触发；利用链闭合：source（042.php:5 query `id`）→ 字符串拼接（042.php:11）→ 执行汇点（042.php:12 mysqli_query），中间无净化函数，且错误信息回显（mysqli_error）为攻击者提供反馈通道。

**修复建议**

改用参数化查询/预处理语句：`$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id);`，并对 `id` 做 `intval()` 或严格数字白名单校验；关闭生产环境的 `mysqli_error` 回显，改为记录日志；数据库账户遵循最小权限，仅授予所需表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `042.php?id=<payload>` → 042.php:5 读取 query 参数 `id` → 042.php:11 直接拼接进 `SELECT ... WHERE user_id = $id;` → 042.php:12 `mysqli_query` 执行被篡改的 SQL → 结果/错误信息回显给攻击者，完成注入。
PocWriter 建议（未采纳，缺少端点 /042）：针对 042.php 第 12 行 SQL 注入的 POC（query 参数 id）。外部输入经 URL 查询参数 id 进入 SQL 语句拼接，未发现有效净化，构成 CWE-89。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 042.php:12，外部输入来自 query 参数 id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试实例地址，并确保已获书面授权。禁止使用 DROP/破坏性语句。

### F-2: 042.php:55 查询为常量语句，未构成可利用 SQL 注入（证据不足）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:53-55`
- **来源**：`rule`

**描述**

候选声称 042.php:53-55 存在 SQL 注入，source 指向 042.php:5 的 query 参数 `id`。但代码片段显示 042.php:54 的 `$query` 被赋值为常量字符串 `"SELECT COUNT(*) FROM users;"`，042.php:55 将该常量传入 `mysqli_query` 执行。片段中不存在把外部输入 `$id` 拼接到该 `$query` 的语句，因此 source 与 sink 之间缺少数据流连接。若 042.php:5 的 `$id` 与 042.php:54 的 `$query` 之间存在片段未展示的赋值关系，则属于证据缺口，无法在现有证据下确认。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:55 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:55` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /042（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/042?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-06e09e46e3b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足：在给定代码片段范围内，042.php:55 执行的是固定常量查询，攻击者无法通过 `id` 参数影响该语句，暂不能认定数据泄露或篡改影响。

**CVE / CWE 论证**

CWE-89 的成立需要外部可控数据到达 SQL 执行汇点。当前证据中 042.php:54 的 `$query` 为字面量常量，042.php:55 的 `mysqli_query` 参数不包含外部输入，污点链在片段内不闭合，故不满足 CWE-89 的利用条件。

**修复建议**

若后续确认存在将外部输入拼入该 `$query` 的代码，应统一改为参数化查询并做类型校验；对常量查询无需改动。建议补充 042.php:5 至 042.php:54 之间的完整代码以复核数据流。

**验证说明**

静态证据：入口 ANY /042；source=query/id；sink=042.php:55；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选链路为 042.php:5 query `id` → 042.php:55 `mysqli_query`，但片段显示 042.php:54 的 `$query` 是常量 `SELECT COUNT(*) FROM users;`，未观察到 `$id` 流入该变量，链路在现有证据下断开。
PocWriter 建议（未采纳，缺少端点 /042）：针对 042.php 第 55 行 SQL 注入的 POC（query 参数 id）。外部输入经 URL 查询参数 id 进入 SQL 语句拼接，未发现有效净化，构成 CWE-89。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 042.php:55，外部输入来自 query 参数 id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试实例地址，并确保已获书面授权。禁止使用 DROP/破坏性语句。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.93 | 是 |
| surface_mapper | 攻击面测绘 | 9.4 | 是 |
| deep_finder | LLM 深挖 | 9.18 | 是 |
| candidate_screener | 候选筛选 | 4.73 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.52 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.09 | 是 |
| coordinator | 管线协调 | 6.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
