# 落日二号乙漏洞挖掘报告 — 20261031-012106-25b2a0

- 生成时间：2026-10-30T17:21:44.828859+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\041.zip`
- 输入模式：`zip`
- SHA256：`79e2a6d843927e577eebaaeee2a818debf8da783d298ea705037330b946c7905`
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

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），定级 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径最短）。最高危即此条，也是唯一交付项。POC 齐全度：1/1 有 POC，无缺失。二次注入链：输入未提供任何存储写点/读点/汇点组合，故本次无二次注入交付。需强调：本次仅覆盖 1 个 PHP 文件、0 个端点清单，surface_notes 明确说明未提供 041.php 源码正文，攻击面测绘基于元数据，因此除该 SQL 注入外的注入类、文件类、配置类风险均处于未覆盖状态，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 041.php 的第 1-46 行（共 56 行，第 47-56 行未送入）。已审计该文件全部可见代码：确认存在一条闭合的 SQL 注入链——$_REQUEST['id']（第 5 行）未经任何过滤直接拼接进 SELECT 语句（第 10 行 MySQL 分支、第 31 行 SQLite 分支），分别由 mysqli_query（第 11 行）与 SQLite3::query（第 34 行）执行，且第 11 行 die(mysqli_error) 与第 20 行结果回显为报错注入与联合查询注入提供了回显通道。该文件为 DVWA 的 SQL 注入练习页，属已知教学漏洞，但代码层面链路完整、外部可达。surface_notes 中提到的 weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 等配置类线索，在可见的 1-46 行内未发现对应调用（无 md5/sha1、rand/mt_rand、setcookie、mcrypt/openssl、X-Forwarded-For 等），故不单独立项。第 47-56 行未覆盖，可能存在结果回显或收尾逻辑，但不影响已确认的注入链。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未送入 code_pack，未审计
- 无 php.ini/.htaccess/config.php 等全局配置，无法评估 magic_quotes、错误显示等运行时设置
- 无部署信息，无法确认 041.php 是否受 DVWA 登录鉴权保护及公网可达性
- SQLite 分支依赖 $sqlite_db_connection 的初始化位置（可能在未送入的行或外部包含文件中），未完全确认

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何转义或类型校验，被直接拼接进 SQL 语句：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 041.php:11 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被包裹在单引号内且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中不存在白名单、类型转换或参数化，校验完全缺失，因此注入必然生效。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /041（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

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

可读取数据库中任意表数据（如 users 表全部记录、其他业务表），通过 UNION/布尔/报错注入实现数据泄露；结合数据库权限可能进一步读写文件或造成数据篡改，属于高危数据泄露与数据库失陷风险。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 041.php；利用链闭合：source（041.php:5 的 `id`）→ 字符串拼接（041.php:10）→ 执行汇点 `mysqli_query`（041.php:11），中间无有效净化，攻击者可直接控制 SQL 语义。

**修复建议**

改用参数化查询：使用 `mysqli_prepare` 配合 `bind_param('i', $id)` 或 PDO 预处理语句，将 `id` 作为绑定参数而非拼接；同时对 `id` 做整型强制转换（如 `(int)$id`）并校验取值范围；关闭详细数据库错误回显（当前 `die(mysqli_error(...))` 会泄露报错信息，便于报错注入），改为记录日志并返回通用错误；数据库账户遵循最小权限原则。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `041.php?id=1' OR '1'='1` → 041.php:5 读取 `id` → 041.php:10 拼接进 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1'` → 041.php:11 `mysqli_query` 执行被篡改的查询 → 返回全部用户记录，实现 SQL 注入数据泄露。
PocWriter 建议（未采纳，缺少端点 /041）：针对 041.php 的 SQL 注入 POC（查询参数方式）。注入点为 URL 查询参数 id，源码 041.php:11 将外部输入直接拼入 SQL 语句。目标地址统一使用 TARGET 占位符，仅限授权测试。注意：源码未明确限定 HTTP 方法，实际方法以部署环境为准，建议优先使用 GET。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。原草稿使用 ANY 方法，实际请求请按部署环境改为 GET 或 POST；执行前须将 TARGET 替换为授权目标并确认授权范围。

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
| safety_guard | 安全防护 | 2.41 | 是 |
| surface_mapper | 攻击面测绘 | 6.58 | 是 |
| deep_finder | LLM 深挖 | 9.18 | 是 |
| candidate_screener | 候选筛选 | 3.16 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.1 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.58 | 是 |
| coordinator | 管线协调 | 6.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
