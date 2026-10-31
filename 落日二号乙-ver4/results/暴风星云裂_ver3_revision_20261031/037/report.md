# 落日二号乙漏洞挖掘报告 — 20261031-012020-c16b62

- 生成时间：2026-10-30T17:21:05.131494+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\037.zip`
- 输入模式：`zip`
- SHA256：`2350166e5e411d8f34c674251eff07993757e4851f9d5957708018206bf598c9`
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

本次汇总仅含 1 条已去重 finding：037.php 第 3 行 query 参数 id 直达同文件 SQL 汇点（第 13 行），类型 sql_injection，严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一且最高危的问题，污点链极短（source 与 sink 同文件、行距近），若脚本无鉴权则前置条件默认成立。POC 齐全度：1/1 有 POC；但其余攻击面（命令执行、文件包含/路径穿越、反射型 XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）均无 finding 覆盖，属未交付而非未检出，需人工按源码复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 037.php（63 行，已完整审计 1-63 行）。该文件是 DVWA 的 SQL 注入练习页（Cookie 型），核心链路为 Cookie `id`（037.php:5）→ 字符串插值拼接 SQL（037.php:11 MYSQL 分支 / 037.php:33 SQLITE 分支）→ mysqli_query（037.php:13）/ SQLite query（037.php:35）执行，全程无转义、无参数化、无白名单，构成闭合的 SQL 注入链，已作为唯一 finding 交付。其余审计面结论：037.php:51-52 使用 rand() 做随机 sleep，仅用于干扰时序，不承载安全语义，不构成 weak_random 可申报问题；037.php:56 使用 $_SERVER['SERVER_PROTOCOL'] 设置状态行，该值由 Web 服务器填充而非客户端任意可控，未构成响应头注入；文件内无 include/require、无文件读写、无 system/exec/eval 等命令或代码执行汇点，故无 RCE/LFI 类发现；无 echo 直接回显用户输入（仅回显固定文案），无反射型 XSS；无 setcookie/session 配置，无 insecure_cookie 证据；无 md5/sha1/openssl 调用，无 weak_hash/weak_crypto 证据。未闭合线索：脚本依赖外部 include 提供的 $_DVWA 配置与 $GLOBALS["___mysqli_ston"] 连接对象，这些文件不在 CODE PACK 内，无法确认数据库账号权限与 SQLI_DB 实际取值；端点真实 URL 路径与是否存在前置 WAF 未知。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 前置 include 文件（DVWA 配置与数据库连接）不在 CODE PACK，无法确认 SQLI_DB 取值与数据库账号权限
- 无 php.ini/.htaccess/nginx.conf，无法确认运行环境与 WAF
- 端点清单为空，037.php 的真实 URL 路径与匿名可达性未确认
- SQLite 分支的 $sqlite_db_connection 初始化位置未知

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该值在 037.php:5 被读取后直接拼接到 SQL 语句中：037.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，`$id` 被原样嵌入单引号字符串内，未做类型转换、转义或参数化；随后 037.php:13 调用 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行该语句。由于拼接发生在 SQL 语法层，攻击者只需闭合单引号即可改变查询语义（例如 `id=1' OR '1'='1` 或 UNION 注入），校验无效的根本原因是全程没有使用 prepared statement 或 `mysqli_real_escape_string` 等任何净化手段。代码注释显示已移除 `or die` 以抑制 MySQL 错误回显，这会降低报错型注入的可见性，但不影响布尔/UNION 型注入成立。

**source / sink**

- source：query `id`（037.php:5）
- sink：037.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `037.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `037.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /037（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/037'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/037?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-86a3d201a6c6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑可被任意篡改：可绕过 `user_id` 条件读取 users 表全部记录（first_name/last_name 泄露），可进一步通过 UNION 查询读取同库其他表（如用户名、口令散列等敏感数据），在数据库账户权限较高时还可能结合文件读写或堆叠语句造成更严重后果。属于未授权即可触发的数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 037.php 触发；利用链闭合：source（037.php:5 读取 `id`）→ 字符串拼接（037.php:11）→ 执行汇点 `mysqli_query`（037.php:13），中间无任何过滤或参数化，因此构成完整的注入链。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1"); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整数白名单校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）。若必须动态拼接，至少使用 `mysqli_real_escape_string` 并强制加引号，同时遵循最小权限原则，为应用数据库账户仅授予必要的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /037.php?id=1' OR '1'='1`（仅限授权测试，目标写为 TARGET）。037.php:5 从 query 读取 `id`，其值 `1' OR '1'='1` 在 037.php:11 被拼入 `WHERE user_id = '$id'`，形成 `WHERE user_id = '1' OR '1'='1' LIMIT 1`，单引号被闭合、条件恒真；037.php:13 将该语句交给 `mysqli_query` 执行，返回结果被后续逻辑输出，从而泄露非预期用户数据。
PocWriter 建议（未采纳，缺少端点 /037）：针对 037.php 的 SQL 注入 POC（query 参数 id）。源码 037.php:13 将请求参数 id 直接拼入 SQL 查询，未做参数化或有效转义。payload 使用 TARGET 占位符，仅限授权测试。注意：源码注入通道为 query 参数 id，HTTP 方法应以实际路由为准（GET 优先）。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89。漏洞位于 037.php:13，外部输入来自 query 参数 id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。目标地址统一使用 TARGET 占位符，仅限授权测试。原草稿使用 ANY 方法与 /037 路径，已按源码注入通道修正为 query 参数 id 与 037.php 路径；实际方法以路由为准，建议优先 GET。

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
| safety_guard | 安全防护 | 2.21 | 是 |
| surface_mapper | 攻击面测绘 | 10.12 | 是 |
| deep_finder | LLM 深挖 | 10.32 | 是 |
| candidate_screener | 候选筛选 | 3.73 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.37 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.62 | 是 |
| coordinator | 管线协调 | 6.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
