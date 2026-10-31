# 落日二号乙漏洞挖掘报告 — 20261031-010312-48539b

- 生成时间：2026-10-30T17:03:50.582577+00:00
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

本次汇总仅含 1 条已去重 finding：037.php 中基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，且已附带 POC（HTTP 型，可动态复现方向）。最高危即该条 SQL 注入，污点链路短（source 约在 037.php:3，sink 在同文件第 13 行附近），无跨文件净化环节。POC 齐全度为 1/1，但需注意该 POC 属静态推导产物，未做动态验证。覆盖面上仅审计了 1 个 PHP 文件、0 个解析出的端点，无框架、无配置、无依赖清单；surface_notes 中列出的路径/包含类、命令执行类、XSS 输出类攻击面以及 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置实现类风险点均未被 findings 覆盖，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 037.php（63 行，已全量审计）。确认一条闭合的 SQL 注入链：Cookie `id`（第 5 行）→ 字符串拼接（第 11/33 行）→ mysqli_query/query 执行（第 13/35 行），无任何转义或参数化，属高危可利用漏洞。其余攻击面核查：第 51-52 行 rand()/sleep() 仅用于随机延迟，不构成安全令牌生成，无 weak_random 实质影响；无 setcookie/session 配置，无 insecure_cookie；无 md5/sha1 摘要，无 weak_hash；无 include/file 操作，无路径穿越；无命令执行函数；无输出回显用户输入（仅固定文案），无 XSS。未覆盖：无 php.ini/部署配置、无依赖清单、无版本信息，无法评估 allow_url_include、open_basedir 等对利用的影响。

未覆盖 / 证据缺口：
- 无部署/服务器配置，无法确认数据库连接与权限
- 无依赖与版本信息
- 页面仅布尔回显，联合查询数据外带需结合 DVWA 前端确认

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（037.php:5 读取），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：037.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，随后在 037.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 位于单引号字符串字面量内部且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可闭合引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询），校验完全缺失，污点从 source 到 sink 链路闭合。

**source / sink**

- source：query `id`（037.php:5）
- sink：037.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `037.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `037.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /037（任意方法）的 SQL 注入 POC。注入通道为查询参数 `id`（源码 037.php:13 处将参数值拼入 SQL 查询），payload 使用 TARGET 占位符，仅限授权测试。

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

数据库查询逻辑可被任意篡改：可绕过 user_id 条件读取 users 表全部记录（first_name/last_name），并通过 UNION 注入进一步读取其他表（如用户名、口令散列）造成敏感数据泄露；结合数据库权限还可能进行数据篡改。属于机密性与完整性影响。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 037.php；利用链闭合：037.php:5 读取输入 → 037.php:11 字符串拼接 → 037.php:13 mysqli_query 执行，中间无净化函数，攻击者可直接控制 SQL 语义。

**修复建议**

改用参数化查询：使用 `mysqli_prepare` 配合 `bind_param('i', $id)` 或 PDO 预处理语句，将 `id` 作为绑定参数而非字符串拼接；同时对 `id` 做整型白名单校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）；遵循最小权限原则，为应用数据库账号仅授予必要表的 SELECT 权限，避免 UNION 注入扩大影响面。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `037.php?id=1' OR '1'='1` → 037.php:5 读取 `id` 到变量 → 037.php:11 拼接进 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1' LIMIT 1` → 037.php:13 `mysqli_query` 执行被篡改的语句 → 返回全部用户记录，实现 SQL 注入与数据泄露。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89。漏洞位于 037.php:13，外部输入来自查询参数 `id`，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。注入点必须放在查询参数 `id` 中，不能写成 Cookie 或请求头。目标统一使用 TARGET 占位符，仅限授权测试。

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
| safety_guard | 安全防护 | 2.83 | 是 |
| surface_mapper | 攻击面测绘 | 9.09 | 是 |
| deep_finder | LLM 深挖 | 6.83 | 是 |
| candidate_screener | 候选筛选 | 3.08 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.41 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.04 | 是 |
| coordinator | 管线协调 | 5.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
