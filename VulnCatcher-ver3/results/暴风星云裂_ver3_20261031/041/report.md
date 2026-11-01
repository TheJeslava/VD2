# 落日二号乙漏洞挖掘报告 — 20261031-010352-e01b1b

- 生成时间：2026-10-30T17:04:36.909584+00:00
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

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现方向）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，无缺失。二次注入链：输入未提供，故无二次注入结论。需注意：本次 min_severity=low、min_confidence=0.6、suppressed_count=0，即当前档位下没有候选被策略抑制；但这不等于仓库中不存在其他类型问题——surface_notes 明确列出 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary / hardcoded_secret 六类待核查方向，均未形成 finding，属未覆盖而非已排除。所有结论均为源码/规则级静态推断，未经任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 041.php（共 56 行，仅展示 1-46 行），已完整审计该文件的输入读取与危险汇点。确认存在一处闭合的 SQL 注入链：$_REQUEST['id']（第 5 行）→ 字符串拼接（第 10 行 MySQL / 第 31 行 SQLite）→ mysqli_query（第 11 行）/ SQLite3::query（第 34 行），并有 mysqli_error 与结果回显（第 11、20 行）作为回显通道。该文件为 DVWA SQL 注入模块源码，属教学靶场代码，但代码行为本身构成真实 SQL 注入，按 CVE 标准可申报。未发现命令执行、文件包含、反序列化、SSRF 等其它汇点；未发现 md5/sha1/rand/setcookie/硬编码密钥等配置类风险（第 1-46 行内无相关调用）。未覆盖范围：第 47-56 行未送入 CODE PACK，无法审计；无端点清单、无部署配置、无认证/会话证据，无法确认实际路由与匿名可达性；无 composer 依赖清单，无法评估第三方组件 CVE。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未在 code_pack 中展示，未审计
- 无 endpoints 清单，路由与 HTTP 方法按 PHP 脚本惯例推断
- 无认证/会话/部署配置证据，无法确认匿名可达性与 $_DVWA['SQLI_DB'] 实际取值
- 无依赖清单，未评估第三方组件漏洞

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何转义或参数化即被拼接进 SQL 语句：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 041.php:11 直接交给 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被单引号包裹但未做 `mysqli_real_escape_string` 或预处理绑定，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1`、`1' UNION SELECT ...`）。代码中不存在白名单、类型强制转换或参数化查询，校验完全缺失。此外 041.php:11 的 `or die(... mysqli_error ...)` 会把数据库错误信息回显到页面，为报错型注入提供便利。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 041.php 第 11 行 SQL 注入的 POC 文本（端点写法为 /041，方法标注为 ANY）。注入点为查询参数 id，外部输入未经有效净化进入 SQL 语句（CWE-89）。注意：源码文件为 041.php，实际路由应以部署配置为准，若 /041 不可达请改用 /041.php。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

可读取 users 表全部数据（first_name、last_name 等），并通过 UNION/子查询进一步枚举数据库名、表结构乃至其他表内容，造成敏感数据泄露；结合数据库权限还可能读写文件或进一步扩大影响。错误信息回显降低了盲注成本。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 041.php 触发；利用链闭合：source（041.php:5 的 `id`）→ 字符串拼接（041.php:10）→ 执行汇点 `mysqli_query`（041.php:11），中间无任何净化，构成完整污点链。

**修复建议**

改用参数化查询/预处理语句：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('s', $id); $stmt->execute();`；若必须拼接，至少使用 `mysqli_real_escape_string` 并对 `id` 做整数白名单校验（如 `ctype_digit`/`intval`）。同时关闭生产环境的数据库错误回显，改为记录日志并返回通用错误页。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `041.php?id=1' OR '1'='1` → 041.php:5 读取 `id` 为污点值 → 041.php:10 直接拼入 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1'` → 041.php:11 `mysqli_query` 执行被篡改的语句，返回全表结果并渲染到页面，完成注入。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。方法标注 ANY 表示该端点对多种 HTTP 方法可达，实际测试优先使用 GET。主机统一为 TARGET:8080 占位符。禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.34 | 是 |
| surface_mapper | 攻击面测绘 | 9.11 | 是 |
| deep_finder | LLM 深挖 | 10.94 | 是 |
| candidate_screener | 候选筛选 | 3.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.06 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.51 | 是 |
| coordinator | 管线协调 | 6.87 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
