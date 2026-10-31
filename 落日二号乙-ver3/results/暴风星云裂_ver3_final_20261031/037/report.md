# 落日二号乙漏洞挖掘报告 — 20261031-014230-78cfe3

- 生成时间：2026-10-30T17:43:06.687204+00:00
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

本次汇总仅含 1 条已去重 finding：037.php 中基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，且已附带 POC（has_poc=true），是本次唯一且最高危的问题。该文件为单文件 PHP 脚本（63 行），source 热点位于第 3 行、sink 热点 1 处，输入到汇点链路极短，利用门槛低。POC 齐全度：1/1 条 finding 有 POC，但该 POC 属 HTTP 型静态构造文本，未做动态验证，不能宣称已可动态复现。其余攻击面（文件包含/路径穿越、配置类弱点）仅有测绘线索，未形成 finding，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 037.php（63 行）。确认 Cookie `id` 在第 5 行读取后未经净化，于第 11/33 行拼接进 SQL 并在第 13/35 行执行，构成闭合的 SQL 注入链（MySQL 与 SQLite 两分支均存在）。第 51-52 行 rand/sleep 仅影响响应时延，可辅助时间盲注但不单独构成漏洞。未发现命令执行、文件包含、反序列化等其它 sink。weak_hash/weak_random/insecure_cookie/hardcoded_secret 等配置类线索在文件中无对应实现（无 md5/sha1、无 setcookie、无硬编码密钥），不成立。未覆盖：上层 include 页面、php.ini（disable_functions/open_basedir）、部署暴露面与鉴权，均不在 CODE PACK 内。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认命令执行/文件读取可达性
- 无端点清单，无法确认 037.php 对外路径与鉴权
- 无上层 include 与公共库，调用链上游未覆盖
- 无数据库连接串，SQL 注入实际可利用性依赖运行时配置

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（037.php:5 读取），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：037.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，随后在 037.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被单引号包裹但未做 `mysqli_real_escape_string` 或参数化处理，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中仅用 try/catch 抑制了 MySQL 错误回显（037.php:12-13 注释“Removed 'or die' to suppress mysql errors”），这并不构成任何输入净化，只是隐藏报错，无法阻止注入生效。

**source / sink**

- source：query `id`（037.php:5）
- sink：037.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `037.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `037.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /037（ANY）的 SQL 注入 POC。注入点为查询参数 id，payload 为 ' OR '1'='1，目标地址统一使用 TARGET 占位符。仅限授权测试。

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

数据库查询逻辑被完全控制：可绕过 user_id 条件读取 users 表全部记录（first_name、last_name），并通过 UNION 注入进一步读取其他表（如用户名/口令哈希），造成敏感数据泄露；在数据库账户权限较高时还可能读写文件或执行管理操作。属于未认证远程可利用的严重数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 037.php；利用链闭合：source（037.php:5 的 `id`）→ 字符串拼接（037.php:11）→ 执行汇点 `mysqli_query`（037.php:13），中间无有效净化，仅错误抑制不影响注入。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1"); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整数类型强校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）。若必须拼接，至少使用 `mysqli_real_escape_string` 并加引号，但优先参数化。同时遵循最小权限原则，限制数据库账户权限，避免使用可读写文件或跨库的高权限账号。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /037.php?id=1' OR '1'='1` → 037.php:5 读取 `id` 进入变量 → 037.php:11 直接拼入 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1' LIMIT 1` → 037.php:13 `mysqli_query` 执行被篡改的语句 → 返回全部用户记录，完成注入。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89。漏洞位于 037.php:13，外部输入来自查询参数 id，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址使用 TARGET 占位符，仅限授权测试。请求结构沿用输入中的确定性 POC，仅补充说明与预期结果。

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
| safety_guard | 安全防护 | 2.24 | 是 |
| surface_mapper | 攻击面测绘 | 8.22 | 是 |
| deep_finder | LLM 深挖 | 6.65 | 是 |
| candidate_screener | 候选筛选 | 2.73 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.19 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.94 | 是 |
| coordinator | 管线协调 | 5.84 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
