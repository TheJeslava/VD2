# 落日二号乙漏洞挖掘报告 — 20261031-164526-ff479f

- 生成时间：2026-10-31T08:46:14.723757+00:00
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

本次汇总仅含 1 条已去重 finding：037.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径明确）。这是本次最高危且唯一交付项。POC 齐全度为 1/1，但该 POC 未经动态验证，仅为文本工件。其余攻击面（文件包含/路径拼接、命令执行、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）在 surface_notes 中被列为待确认，均未形成 finding，需人工复核。注意：surface_notes 中「未提供 037.php 源码正文」与 findings 中已定位到 037.php:13 存在信息不一致，说明攻击面测绘阶段与发现阶段看到的上下文不同，行号与函数结论应以发现阶段为准并人工回看源码确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 037.php（63 行，DVWA SQL 注入模块片段）。已逐行审计：第 3-5 行 Cookie `id` 取值，第 11/33 行字符串拼接 SQL，第 13/35 行执行，第 45-59 行结果回显与随机 sleep。确认一条闭合的 SQL 注入链（Cookie → 拼接 → mysqli_query/sqlite query → 布尔/时间盲注）。第 51-53 行 rand()/sleep() 仅用于混淆，不构成独立弱随机漏洞（非安全令牌用途）。未发现命令执行、文件包含、反序列化、SSRF、XSS 等其它汇点。未覆盖范围：无 php.ini/Web 服务器配置、无 endpoints 清单、无依赖版本信息，无法评估 allow_url_include、部署可达性及第三方组件 CVE；这些缺口不影响上述 SQL 注入结论。

未覆盖 / 证据缺口：
- 缺少 php.ini / Web 服务器配置，无法确认部署方式与可达性
- endpoints 为空，无法确认该脚本是否被其它页面 include 或需认证前置
- 无依赖清单与版本信息，无法评估第三方组件 CVE
- 未提供 $GLOBALS["___mysqli_ston"] 与 $sqlite_db_connection 的初始化代码，运行时连接状态需人工确认

## 3. Findings

### F-1: 037.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`037.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该值在 037.php:5 被读取后，于 037.php:11 直接以字符串拼接方式嵌入 SQL 语句：`$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"`，随后在 037.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。代码中未对 `$id` 做类型转换（如 intval）、转义（mysqli_real_escape_string）或参数化处理，单引号包裹的字符串上下文可被 `'` 闭合，因此校验完全无效。037.php:13 的注释表明仅移除了 `or die` 以抑制错误回显，这并不构成任何防护，反而说明开发者意识到错误处理问题但未修复注入。

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

数据库数据泄露：攻击者可构造 UNION 查询读取 users 表及其他库表数据（如凭据、个人信息）；也可通过布尔/时间盲注逐字节提取数据。取决于数据库账户权限，还可能读写文件或进一步影响数据库服务，属于高危数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：`id`（037.php:5）→ 字符串拼接（037.php:11）→ `mysqli_query` 执行（037.php:13），中间无有效净化，攻击者输入直接改变 SQL 语义。

**修复建议**

改用预处理语句与参数绑定：`$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1"); mysqli_stmt_bind_param($stmt, 'i', $id); mysqli_stmt_execute($stmt);`。若必须拼接，至少对 `$id` 做严格整数校验（`filter_var($id, FILTER_VALIDATE_INT)`）并使用 `mysqli_real_escape_string`；同时为数据库账户配置最小权限，避免 FILE 等高风险权限。

**验证说明**

静态证据：入口 ANY /037；source=query/id；sink=037.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 037.php 发送请求，在 query 参数 `id` 中注入如 `1' UNION SELECT user, password FROM users-- -` 的载荷；037.php:5 读取该值，037.php:11 将其原样拼入 `WHERE user_id = '$id'`，闭合单引号后追加任意 SQL；037.php:13 的 `mysqli_query` 执行被篡改的语句，查询结果随页面返回，攻击者据此获取数据库数据。
PocWriter 建议（未采纳，缺少端点 /037）：针对 037.php（第 13 行）的 SQL 注入 POC。注入通道为查询参数 `id`（配合触发字段 `Submit=Submit`），其值被直接拼接到 SQL 查询中。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /037）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 037.php:13，外部输入来自查询参数 `id`，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。输入草稿中的 `ANY` 方法为抽象占位，已按源码读取参数的实际方式改为 GET 并保留 `Submit=Submit` 触发字段；若源码实际为 POST 读取，需按源码调整方法与 Body。步骤 3 为补充的对比确认步骤，未新增 finding、未改文件与行号。

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
| safety_guard | 安全防护 | 3.46 | 是 |
| surface_mapper | 攻击面测绘 | 9.9 | 是 |
| deep_finder | LLM 深挖 | 9.3 | 是 |
| candidate_screener | 候选筛选 | 3.15 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.79 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.52 | 是 |
| coordinator | 管线协调 | 8.18 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
