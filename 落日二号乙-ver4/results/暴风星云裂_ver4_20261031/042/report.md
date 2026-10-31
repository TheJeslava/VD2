# 落日二号乙漏洞挖掘报告 — 20261031-164629-81c480

- 生成时间：2026-10-31T08:47:16.935249+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
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

本次汇总仅含 1 条已去重 finding：042.php 中基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（1/1 齐全）。最高危即该 SQL 注入，属单文件 PHP 脚本中请求参数直达数据库汇点的一次注入，无需跨文件追踪。其余攻击面（命令执行、路径穿越、SSRF、反射型 XSS、配置/实现类风险）在 surface_notes 中被列为优先核查区，但本次 findings 未覆盖，均需人工复核；输入未提供 042.php 代码正文，所有汇点函数名与参数名细节无法在本次结论中确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 042.php（59 行，DVWA SQL Injection 模块）。已逐行审计：第 3 行以 $_POST['Submit'] 作为触发条件，第 5 行读取 $_POST['id']，第 7 行仅做 mysqli_real_escape_string，第 11/27 行将 $id 直接拼接进 SQL，第 12/30 行执行查询，第 21/43 行回显。确认存在一条闭合的数字型 SQL 注入链（MySQL 与 SQLite 两分支同构）。第 21/43 行虽将 $id 回显到 HTML，但 $id 已经过 mysqli_real_escape_string，且该页面为 DVWA 靶场模块，XSS 价值低且非本次重点，未单独立项。未发现命令执行、文件操作、反序列化、SSRF、模板注入等其它汇点；无认证/会话/加密相关代码，故 weak_hash/weak_crypto/weak_random/insecure_cookie 等配置型候选在本文件中无证据。输入中未出现诱导性文本。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 042.php 是否公网可达及是否需认证
- 无 composer.json/数据库 schema，无法确认 $_DVWA['SQLI_DB'] 取值与 users 表结构
- endpoints 为空，实际访问路径与 HTTP 方法依据 DVWA 惯例推断为 POST /042.php

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（042.php:5 读取），该值未经任何类型转换、转义或参数化处理，被直接拼接进 SQL 语句：042.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 SQL 语句的数值上下文且无引号包裹，攻击者可注入 `1 OR 1=1`、`1 UNION SELECT ...` 等片段改变查询语义；同时 042.php:12 的 `or die('<pre>' . mysqli_error(...) . '</pre>')` 会把数据库错误信息回显到响应中，为报错型注入与结构探测提供便利。校验无效的原因：代码路径中不存在 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单校验，污点从 source 到 sink 全程未净化。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:12 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:12` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 042.php 第 12 行的 SQL 注入 POC（端点写作 /042）。注入点为 POST 参数 id，被直接拼接进 SQL 查询；请求需携带触发按钮字段 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/042' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-65bf75938433`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可 UNION 查询拖取 users 表及其他库表内容（如用户名、口令哈希）；可读取数据库元信息（库名、表结构、当前用户/版本）；在数据库账户权限较高且文件权限允许时，可能通过文件读写原语进一步扩大影响。属于未授权即可远程触发的数据机密性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：042.php:5 读取参数 → 042.php:11 字符串拼接 → 042.php:12 `mysqli_query` 执行，且错误信息经 `mysqli_error` 回显，形成完整的可控输入到危险汇点路径。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须拼接，先对 `$id` 做严格数值校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval()`）并拒绝非法值；关闭生产环境的数据库错误回显，将 `mysqli_error` 输出改为记录到服务端日志；数据库账户遵循最小权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 POST /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /042.php?id=1 UNION SELECT user,password FROM users` → 042.php:5 将 `id` 读入变量 → 042.php:11 直接拼接为 `SELECT first_name, last_name FROM users WHERE user_id = 1 UNION SELECT user,password FROM users;` → 042.php:12 交由 `mysqli_query` 执行 → 结果集被页面输出，攻击者获得任意表数据；若语句出错，`mysqli_error` 回显进一步暴露数据库结构。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89。漏洞位于 042.php:12，外部输入来自 POST 参数 id，source→sink 链静态闭合，未见有效参数化或转义，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例地址；禁止对生产环境使用。

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
| safety_guard | 安全防护 | 4.02 | 是 |
| surface_mapper | 攻击面测绘 | 11.51 | 是 |
| deep_finder | LLM 深挖 | 8.73 | 是 |
| candidate_screener | 候选筛选 | 3.42 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.92 | 是 |
| coordinator | 管线协调 | 6.25 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
