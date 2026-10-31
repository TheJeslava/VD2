# 落日二号乙漏洞挖掘报告 — 20261031-010329-4c1395

- 生成时间：2026-10-30T17:04:12.493144+00:00
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

本次汇总仅含 1 条已去重 finding：038.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可对 TARGET 复现，仅限授权测试）。这是本次唯一且最高危的问题，污点链路短（单文件 57 行，3 处 source 热点、1 处 sink 热点），利用门槛低。POC 齐全度：1/1 finding 有 POC，但仅覆盖 SQL 注入这一类；其余攻击面（文件包含/路径拼接、命令执行、反射型 XSS）在 surface_notes 中被列为优先排查区，尚无对应 finding，属未覆盖而非已排除。所有结论均为静态源码审计与规则命中，未做动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 038.php（57 行，DVWA SQL Injection 页面）。已审计全部 57 行：入口为 $_GET['Submit'] 与 $_GET['id']（第 3、5 行），sink 为 mysqli_query（第 13 行）与 SQLite query（第 34 行），确认存在未参数化的 SQL 拼接，构成闭合的 SQL 注入链，已作为 high 级 finding 交付。其余观察：第 49 行使用 $_SERVER['SERVER_PROTOCOL'] 构造 404 头，属服务端常量，非用户可控，不构成漏洞；第 46/52 行 $html 拼接为固定字符串，无用户输入回显，不构成 XSS；文件中未见 md5/sha1、rand/mt_rand、setcookie、include/require、system/exec 等其它 sink，故未报告弱哈希/弱随机/文件包含/命令执行类问题。未覆盖范围：无 php.ini、Web 服务器配置、composer 依赖与路由/鉴权中间件，无法判断该页面是否匿名可达及是否存在统一过滤层；这些属证据缺口，不影响本 finding 的链闭合判断。

未覆盖 / 证据缺口：
- 缺少 php.ini / Web 服务器配置，无法确认 display_errors、magic_quotes 等运行时条件
- 缺少 DVWA 全局配置（$_DVWA、数据库连接初始化文件），无法确认 SQLI_DB 取值与连接可用性
- 无鉴权/路由配置，无法确认该页面是否需登录访问
- 无外部 AWVS 证据，全部结论为 llm_inferred 级别

## 3. Findings

### F-1: 038.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（038.php:5 读取该参数），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：038.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 038.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于单引号字符串字面量内部且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中仅用 try/catch 抑制了 MySQL 错误回显（注释“Removed 'or die' to suppress mysql errors”），这并不构成任何安全校验，只是减少了报错信息泄露，注入本身依然成立。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /038（ANY 方法）的 SQL 注入 POC。注入点为查询参数 id，对应 038.php:13 的 SQL 拼接点。由于路由未限定 HTTP 方法，GET 即可触发；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/038?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-5bc99d7a2891`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑被完全控制：可绕过 user_id 条件读取 users 表全部记录（first_name、last_name），并通过 UNION SELECT 读取同库其他表（如账号、口令哈希）造成敏感数据泄露；在数据库账户权限较高时还可进一步读写文件或实施二次利用。属于机密性严重受损的注入类漏洞。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可控输入 `id` 未经参数化/转义直接进入 SQL 语句并执行，构成典型注入。可达性：该脚本为 Web 入口，参数 `id` 来自 HTTP query，无需认证即可访问；利用链闭合：source（038.php:5 的 `id`）→ 字符串拼接（038.php:11）→ 执行汇点（038.php:13），中间无有效净化，因此外部攻击者可直接利用。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('i', $id); $stmt->execute();`，并将 `$id` 强制转换为整数（`$id = (int)$_GET['id']`）。若必须动态拼接，至少使用 `mysqli_real_escape_string` 并加单引号包裹，但优先参数化。同时遵循最小权限原则，为应用数据库账户仅授予必要的 SELECT 权限，并避免向客户端回显数据库错误。

**验证说明**

静态证据：入口 ANY /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?id=1' OR '1'='1` → 038.php:5 读取 query 参数 `id` → 038.php:11 将 `$id` 原样拼入 `WHERE user_id = '$id'`，形成 `WHERE user_id = '1' OR '1'='1'` → 038.php:13 `mysqli_query` 执行被篡改的语句 → 返回 users 表全部行，攻击者从响应中获取 first_name/last_name 等数据；替换为 UNION SELECT 即可读取其他表。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89（SQL 注入）。漏洞位于 038.php:13，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；路由接受任意方法，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网。原始草稿中的 -X ANY 不是合法 curl 方法，实际测试请改用 GET/POST 等具体方法；TARGET 需由授权测试人员手动替换，Content-Length 按实际请求体调整。

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
| safety_guard | 安全防护 | 2.64 | 是 |
| surface_mapper | 攻击面测绘 | 9.11 | 是 |
| deep_finder | LLM 深挖 | 9.25 | 是 |
| candidate_screener | 候选筛选 | 3.19 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.33 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.11 | 是 |
| coordinator | 管线协调 | 6.11 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
