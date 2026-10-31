# 落日二号乙漏洞挖掘报告 — 20261031-214721-3ae828

- 生成时间：2026-10-31T13:48:09.970705+00:00
- 输入：`$WORKSPACE\暴风星云裂\037.zip`
- 输入模式：`zip`
- SHA256：`2350166e5e411d8f34c674251eff07993757e4851f9d5957708018206bf598c9`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：037.php 第 13 行（文件共 63 行）基于 query 参数 id 的 SQL 注入，严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径明确）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，无缺失。需说明：输入未提供 037.php 的代码行内容，finding 的参数名 id 与汇点位置来自规则引擎，本次汇总不新增漏洞、不做动态验证，因此该结论仍属静态/规则证据，未经运行确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 037.php（63 行，DVWA SQL 注入练习页）。已审计全部 63 行：入口为 Cookie `id`（第 3、5 行），在 MySQL 分支（第 11-13 行）与 SQLite 分支（第 33-35 行）均直接字符串拼接进 SQL，无转义/参数化，构成闭合的 SQL 注入链，已作为 finding 交付。其余观察：第 51-52 行使用 rand() 做随机 sleep，属非安全用途，不构成 weak_random 漏洞；第 56 行 header 使用 $_SERVER['SERVER_PROTOCOL'] 拼接状态行，存在响应头注入的理论可能，但该值由服务器自身设置、攻击者不可控，未闭合，不报告；未发现硬编码凭据、弱加密、insecure_cookie 等配置型问题。surface_notes 中提到的 Java 风格汇点（getParameterMap、Runtime.exec 等）在本 PHP 文件中不适用。未覆盖范围：无端点清单、无 composer 依赖、无 php.ini/部署配置，无法评估第三方组件 CVE 与 register_globals 等运行时影响；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 无端点清单，路由/请求方法按脚本级推断
- 无部署配置，无法确认 SQLI_DB 取值与数据库可达性
- 无依赖清单，无法评估第三方组件 CVE
- 第 56 行 SERVER_PROTOCOL 头拼接攻击者不可控，未闭合

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（037.php:5 读取），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：037.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，随后在 037.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于单引号字符串字面量内部且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可闭合引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中仅移除了 `or die` 以抑制错误回显，并未引入任何净化逻辑，因此校验完全缺失。

**source / sink**

- source：query `id`（037.php:5）
- sink：037.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `037.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `037.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 037.php 的 SQL 注入 POC（查询参数通道）。注入点为查询字符串参数 id，源码在 037.php:13 处将该参数值拼入 SQL 查询且未见有效净化。原草稿使用 ANY 方法与路径 /037，与源码文件 037.php 不一致，此处按源码修正为 GET /037.php 并保留 Submit 触发字段。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/037'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/037?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-86a3d201a6c6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑被完全控制：可绕过 `user_id` 条件读取 users 表全部记录（first_name/last_name），并通过 UNION SELECT 进一步读取其他表（如凭据、会话数据），造成敏感数据泄露；在数据库权限较高或支持堆叠查询时可导致数据篡改。属于高危数据泄露类 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 037.php；利用链闭合：037.php:5 读取 `id` → 037.php:11 字符串拼接 → 037.php:13 `mysqli_query` 执行，全程无净化点。证据等级为基于源码的推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1"); mysqli_stmt_bind_param($stmt, 'i', $id); mysqli_stmt_execute($stmt);`。若必须动态拼接，至少对 `$id` 做整型强制转换（`(int)$id`）或 `mysqli_real_escape_string` 转义，并对输入做白名单校验；同时遵循最小权限原则，限制数据库账号仅具备必要表的 SELECT 权限，并避免向客户端回显数据库错误。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /037.php?id=1' OR '1'='1` → 037.php:5 从 query 参数 `id` 读取原始字符串 → 037.php:11 直接拼入 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1' LIMIT 1` → 037.php:13 `mysqli_query` 执行被篡改的语句 → 返回 users 表记录，实现注入与数据泄露。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89（SQL 注入）。漏洞位于 037.php:13，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网。原草稿的 ANY 方法与 /037 路径已按源码修正为 GET /037.php；TARGET 需由授权测试人员手动替换；参数值已做 URL 编码。若为盲注可改用基于时间的载荷，但不得使用 DROP 等破坏性语句。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 5.06 | 是 |
| surface_mapper | 攻击面测绘 | 8.52 | 是 |
| deep_finder | LLM 深挖 | 8.91 | 是 |
| candidate_screener | 候选筛选 | 4.28 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.94 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.34 | 是 |
| coordinator | 管线协调 | 6.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
