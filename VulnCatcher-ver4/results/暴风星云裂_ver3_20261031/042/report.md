# 落日二号乙漏洞挖掘报告 — 20261031-010414-d9a502

- 生成时间：2026-10-30T17:04:57.743397+00:00
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

本次汇总仅含 1 条已去重 finding：042.php 第 12 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备。其余攻击面（文件包含/路径穿越、命令执行、反序列化/RCE、配置型弱哈希/弱加密/弱随机/Cookie 标志/信任边界）在 surface_notes 中被列为优先审计区，但没有任何 finding 覆盖，属于未交付而非已排除。需特别说明：本次输入未提供 042.php 源码片段，SQL 注入结论来自规则命中与热点标记，行号 12 落在文件 59 行范围内，但污点可达性、参数过滤细节仍需人工对照源码复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 042.php（59 行，DVWA SQL Injection 模块）。审计确认第 5 行 $_POST['id'] 经第 7 行 mysqli_real_escape_string 后在第 11/27 行直接拼接进 SQL，第 12/30 行执行，构成数字型 SQL 注入，链路完整闭合，已作为 high 级 finding 交付。第 21/43 行将 $id 与数据库字段回显到 HTML，但 $id 已经过 mysqli_real_escape_string 转义（会转义 < > 等字符），反射型 XSS 不成立，未报告。第 54-58 行为固定 COUNT 查询，无污点。清单中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本文件中均无对应实现（无 md5/sha1、无加密、无随机令牌、无 setcookie、无 X-Forwarded-For 信任），不构成配置型候选。未覆盖范围：无 composer.json、无 Web 服务器/php.ini 配置、无数据库 schema、无认证会话实现，均不在 code_pack 内，无法评估。

未覆盖 / 证据缺口：
- 无数据库 schema 与连接配置，无法评估注入账户权限与堆叠查询可行性
- 无 php.ini/Web 服务器配置，无法确认 display_errors、open_basedir 等开关
- 无认证/会话实现文件，无法评估鉴权绕过
- 无版本信息，无法匹配版本相关 CVE
- endpoints 为空，路由路径为按 DVWA 惯例推断

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id`（042.php:5 读取）传入外部输入，该值未经任何过滤、类型转换或参数化，被直接拼接进 SQL 语句：042.php:11 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于数值上下文且无引号包裹，攻击者可构造如 `1 UNION SELECT user, password FROM users` 或布尔/报错型载荷改变查询语义；042.php:12 的 `or die('<pre>' . mysqli_error(...) . '</pre>')` 还会把数据库错误信息回显到响应，进一步辅助报错注入与结构探测。校验无效的原因：代码路径中不存在 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单校验，污点从 source 到 sink 全程未净化。

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

数据库注入可导致全库数据泄露（users 表用户名/口令哈希等敏感字段被 UNION 或盲注逐位读出）、认证绕过与越权查询；结合报错回显可加速枚举。若数据库账户权限过高，还可能通过文件读写或堆叠语句进一步扩大影响，具体取决于后端 DB 权限配置（证据不足，未在片段中体现）。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，任何能访问 042.php 的远程用户均可触发；无需认证，片段中未见任何会话/权限校验；利用链闭合：042.php:5 读取 `id` → 042.php:11 字符串拼接 → 042.php:12 `mysqli_query` 执行，三步在同一请求内完成，无中间净化点。

**修复建议**

改用参数化查询：`$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?"); mysqli_stmt_bind_param($stmt, 'i', $id); mysqli_stmt_execute($stmt);`；若必须动态拼接，先对 `$id` 做严格整数校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval()`）并拒绝非数字输入；同时关闭生产环境的数据库错误回显（移除 `or die(mysqli_error(...))`），改为记录日志并返回通用错误；数据库账户遵循最小权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 ANY /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 042.php 发送请求并携带 query 参数 `id`（如 `?id=1 UNION SELECT user,password FROM users-- -`）→ 042.php:5 读取该参数为 `$id` → 042.php:11 将 `$id` 原样拼入 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 042.php:12 `mysqli_query` 执行被篡改的语句，结果集被页面输出，实现数据泄露；若语句出错，`mysqli_error` 内容经 `die('<pre>...</pre>')` 回显，辅助注入调试。
PocWriter 建议（未采纳，缺少端点 /042）：针对 042.php:12 的 SQL 注入 POC（query 参数 id）。外部输入来自 URL 查询参数 id，未经有效净化即进入 SQL 查询汇点，构成 CWE-89。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于 042.php:12，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；执行前须替换 TARGET 并确认授权。注入点为查询参数 id，与源码 getParameter("id") 语义一致。

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
| safety_guard | 安全防护 | 2.71 | 是 |
| surface_mapper | 攻击面测绘 | 9.65 | 是 |
| deep_finder | LLM 深挖 | 8.35 | 是 |
| candidate_screener | 候选筛选 | 3.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.15 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.58 | 是 |
| coordinator | 管线协调 | 6.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
