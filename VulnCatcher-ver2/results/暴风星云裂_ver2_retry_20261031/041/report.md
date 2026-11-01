# 落日二号乙漏洞挖掘报告 — 20261031-002313-cec7a3

- 生成时间：2026-10-30T16:23:55.402365+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\041.zip`
- 输入模式：`zip`
- SHA256：`79e2a6d843927e577eebaaeee2a818debf8da783d298ea705037330b946c7905`
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

本次汇总仅含 1 条已去重 finding：041.php 第 2 行附近读取的 query 参数 id 直接进入 SQL 查询汇点（第 11 行），判定为 sql_injection / critical（CWE-89），来源为规则命中，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，无缺失。未发现二次注入链（无存储写点/读点/危险汇点三元组证据）。需强调：本次 min_severity=high、suppressed_count=0，但攻击面测绘明确列出 weak_hash、weak_random、insecure_cookie、trust_boundary、weak_crypto 五类待人工复核项，这些均未形成候选，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 041.php（共 56 行，仅展示 1-46 行），无框架、无路由、无端点清单。已逐行审计：入口为 $_REQUEST['Submit'] 与 $_REQUEST['id']（第 3、5 行），sink 为 mysqli_query（第 11 行）与 SQLite3::query（第 34 行），确认存在从 id 参数到 SQL 执行的完整注入链，无任何过滤/参数化，判定为 SQL 注入（CWE-89），置信度高。第 20 行将 $id 与查询结果拼入 HTML 输出，存在反射型 XSS 可能，但需管理员会话窃取等条件，且与 SQL 注入同源，未单独立项。未发现命令执行、文件包含、反序列化、SSRF 等其它 sink。弱哈希/弱随机/Cookie 标志/信任边界等配置类风险在已展示的 1-46 行中未见对应代码（无 md5/sha1/rand/setcookie/$_SERVER 头信任），第 47-56 行未送入，无法确认。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未在 code_pack 中展示，无法审计该段是否存在其它 sink 或输出编码问题
- 无 php.ini/Web 服务器配置，无法确认 041.php 是否对外暴露、是否位于上传目录
- 无数据库初始化代码（$GLOBALS['___mysqli_ston']、$sqlite_db_connection 的来源），无法确认运行时连接是否可用
- 无认证/会话代码，无法判断是否存在未授权访问前置条件
- 第 20 行 $id 直接输出到 HTML 的反射型 XSS 未单独立项，需人工确认是否具备窃取会话的实际价值

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何过滤、转义或类型转换，被直接拼接进 SQL 语句：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 041.php:11 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被包裹在单引号字符串字面量中且未调用 `mysqli_real_escape_string` 或使用预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中不存在白名单、类型校验或参数化，校验完全缺失，因此注入必然生效。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 041.php 第 11 行的 SQL 注入 POC（同一注入点，端点写法为 /041）。注入点为查询参数 id，被直接拼接进 SQL 语句（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/041'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/041?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cee48d9ee314`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取 users 表全部记录（first_name、last_name），并通过 UNION 注入进一步读取数据库名、表结构及其他表数据，造成敏感数据泄露；结合 041.php:11 的 `or die(... mysqli_error ...)` 错误回显，攻击者可获得数据库报错信息用于盲注/报错注入辅助，属于未授权远程数据泄露。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问；利用链闭合：041.php:5 读取参数 → 041.php:10 字符串拼接 → 041.php:11 `mysqli_query` 执行，全程无净化，攻击者输入直达数据库解析器。证据等级为基于源码的推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('s', $id); $stmt->execute();`；若必须拼接，先对 `$id` 做严格类型校验（如 `(int)$id` 或白名单数字校验）并使用 `mysqli_real_escape_string`；同时关闭生产环境的数据库错误回显（移除 041.php:11 的 `or die(mysqli_error(...))`），改为记录日志并返回通用错误。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?id=1' OR '1'='1` → 041.php:5 读取 query 参数 `id` → 041.php:10 将 `$id` 原样拼入 `WHERE user_id = '$id'` → 041.php:11 `mysqli_query` 执行被篡改的 SQL → 返回 users 表全部行，完成注入。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。原草稿中的 HTTP 方法 ANY 不是合法方法，实际发送请使用 GET（或按目标实际支持的方法）。禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 3.11 | 是 |
| surface_mapper | 攻击面测绘 | 7.82 | 是 |
| deep_finder | LLM 深挖 | 9.31 | 是 |
| candidate_screener | 候选筛选 | 3.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.91 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.46 | 是 |
| coordinator | 管线协调 | 7.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
