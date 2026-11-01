# 落日二号乙漏洞挖掘报告 — 20261031-002231-919469

- 生成时间：2026-10-30T16:23:11.998708+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\037.zip`
- 输入模式：`zip`
- SHA256：`2350166e5e411d8f34c674251eff07993757e4851f9d5957708018206bf598c9`
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

本次汇总仅含 1 条已去重 finding：037.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次最高危且唯一交付项。攻击面测绘显示 source 热点在 037.php:3、sink 热点同文件单处，污点链路极短，与上述 SQL 注入结论一致。POC 齐全度：1/1 finding 有 POC；但该 POC 属 HTTP 请求型，需在授权环境自行验证，本次未做任何动态验证。审计范围仅限 code_pack 中的 037.php（63 行），仓库其他文件视为不存在，结论均为源码推断（llm_inferred），未覆盖配置、部署与依赖层面。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：仅审计了 code_pack 中的 037.php（63 行）。发现一条闭合链：Cookie id → 字符串拼接 → mysqli_query/sqlite query，构成 SQL 注入（布尔盲注）。第 51-52 行使用 rand() 做随机 sleep，属弱随机但仅影响响应时延，不构成独立高危，未单独立项。未发现命令执行、文件包含、反序列化、SSRF、XSS 输出点（$html 仅拼接固定字符串）。配置类（weak_crypto/weak_hash/insecure_cookie/hardcoded_secret/trust_boundary）在文件中无对应实现。code_pack 之外文件视为不存在，未覆盖。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认部署与暴露面
- 无端点清单，无法确认是否被其他页面 include
- $_DVWA 配置来源未知
- rand() 弱随机仅影响时延，未立项

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（037.php:5 读取该参数），该值未经任何转义或类型校验即被拼接进 SQL 语句：037.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，将 `$id` 直接放入单引号字符串字面量中；随后在 037.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 未经过 `mysqli_real_escape_string`、整型强制转换或预处理语句参数化，单引号可闭合 `user_id = '...'` 字面量，从而注入任意 SQL 片段（如 `' OR '1'='1`、`' UNION SELECT ...`）。代码注释显示已移除 `or die` 以抑制 MySQL 错误回显，但这只是隐藏报错，并不构成任何输入校验，注入仍然成立。

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

数据库查询逻辑可被任意篡改：可绕过 `user_id` 条件枚举/拖取 users 表全部记录（数据泄露），可通过 UNION 读取其他表（如凭据、会话数据），在数据库账户权限较高时可进一步读写文件或造成数据破坏。属于未授权远程可利用的 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 037.php；利用链闭合：037.php:5 读取 `id` → 037.php:11 字符串拼接进 `$query` → 037.php:13 `mysqli_query` 执行，中间无有效净化或参数化，攻击者输入直达 SQL 解析器。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1'); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整型校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）。若必须拼接，至少使用 `mysqli_real_escape_string` 并加引号包裹，但优先参数化。同时为数据库账户配置最小权限，避免 FILE 等高风险权限。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `037.php?id=1' OR '1'='1`（或 UNION 变体）。037.php:5 从 query 读取 `id`，值原样进入 037.php:11 的 SQL 字符串，闭合 `user_id = '` 后的字面量；037.php:13 将该被污染的 `$query` 交给 `mysqli_query` 执行，数据库按攻击者控制的语义解析，返回非预期结果集。
PocWriter 建议（未采纳，缺少端点 /037）：针对 037.php 的 SQL 注入 POC（查询参数通道）。注入点为 URL 查询参数 `id`，payload 使用 TARGET 占位符，仅限授权测试。注意：源码中实际取值通道需以 037.php 第 13 行附近代码为准；若源码仅从 Cookie 取值，则本条的 query 通道应视为待确认项。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89（SQL 注入）。漏洞位于 037.php 第 13 行附近，外部输入来自查询参数 `id`，source→sink 链在给定代码中静态闭合，未见有效参数化或转义。证据等级：llm_inferred（基于源码推断，未做动态验证）；注入通道（query vs cookie）需以源码实际取值为准。
POC 备注：POC 仅为文本工件，不执行、不联网。目标地址统一使用 TARGET 占位符；HTTP 方法以源码实际处理方式为准（GET 优先），禁止自动化批量扫描。

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
| safety_guard | 安全防护 | 2.76 | 是 |
| surface_mapper | 攻击面测绘 | 8.74 | 是 |
| deep_finder | LLM 深挖 | 6.81 | 是 |
| candidate_screener | 候选筛选 | 3.71 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.35 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.31 | 是 |
| coordinator | 管线协调 | 6.2 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
