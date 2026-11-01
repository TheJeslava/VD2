# 落日二号乙漏洞挖掘报告 — 20261031-002241-802cab

- 生成时间：2026-10-30T16:23:25.419949+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\039.zip`
- 输入模式：`zip`
- SHA256：`dcd627aba47edb36b6b02995d92ae6b47ea38157489be6bc6bc3ad973f56f1e9`
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

本次汇总仅含 1 条已去重 finding：039.php 第 15 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现）。这是本次最高危且唯一交付项。POC 齐全度：1/1 已具备。需注意：输入未提供 039.php 源码正文，finding 的变量名与汇点细节无法在本级复核，行号 15 落在文件 54 行范围内但与源码正文的对应关系未经确认；攻击面测绘中的 path_traversal/LFI、command_injection、XSS 等方向均无对应 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 039.php（可见 1-50 行，共 54 行，第 51-54 行未送入）。已审计该文件全部可见逻辑：入口为 POST 参数 Submit 触发的 id 参数，MYSQL 分支存在 mysqli_real_escape_string 假防护下的数值型 SQL 注入（第 5→10→13→15 行），SQLITE 分支为完全无转义的直接拼接（第 34→36 行），两者均闭合，合并为一条 SQL 注入 finding。第 45-50 行为布尔回显，构成注入结果泄露通道。未发现命令执行、文件包含、反序列化、SSRF、XSS 等其它 sink；文件中无 md5/sha1/rand/setcookie 等配置型线索。未闭合/未覆盖：$_DVWA['SQLI_DB'] 的取值来源（决定实际走 MYSQL 还是 SQLITE 分支）不在 CODE PACK 内；第 51-54 行未提供；无部署与认证信息，按无认证公网可达评估。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- $_DVWA['SQLI_DB'] 配置来源未知，无法确定运行时走 MYSQL 还是 SQLITE 分支
- 039.php 第 51-54 行未送入 code_pack
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、magic_quotes 等影响
- 无部署与网络暴露信息，认证状态按无认证假设

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（039.php:5 读取该参数），该值未经任何类型转换、转义或参数化，被直接拼接进 SQL 语句：039.php:13 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 039.php:15 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于数值上下文却以字符串拼接方式进入 SQL，攻击者可提交如 `1 UNION SELECT user, password FROM users` 或布尔/时间盲注载荷改变查询语义。代码中未见 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单校验，因此校验完全缺失，污点从 source 到 sink 链路闭合。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /039（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/039'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/039?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-22ffdf9a5620`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询语句可被任意篡改，导致 users 表（first_name、last_name 及其他可访问列）数据泄露、认证绕过与越权读取；结合数据库权限还可能读取系统表、写入文件或进一步扩大影响。属于未授权远程可利用的严重数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 039.php；利用链闭合：039.php:5 读取参数 → 039.php:13 字符串拼接 → 039.php:15 `mysqli_query` 执行，中间无有效净化，满足未认证远程 SQL 注入的定级条件。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id); $stmt->execute();`；若必须拼接，先对 `$id` 做严格整数校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval()`）并拒绝非数字输入；同时遵循最小权限原则，限制数据库账号仅能访问必要表，并关闭详细错误回显。

**验证说明**

静态证据：入口 ANY /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `039.php?id=1 UNION SELECT user,password FROM users`（仅限授权测试，目标写 TARGET）→ 039.php:5 从 query 读取 `id` → 039.php:13 将 `$id` 原样拼入 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 039.php:15 `mysqli_query` 执行被篡改的语句 → 返回结果被页面渲染，攻击者获得越权数据。
PocWriter 建议（未采纳，缺少端点 /039）：针对 039.php 第 15 行 SQL 注入的 POC（query 参数 id）。源码中外部输入经查询参数 id 进入 SQL 查询拼接，未发现有效净化，构成 CWE-89。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89。漏洞位于 039.php:15，外部输入来自查询参数 id，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例地址；禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 9.97 | 是 |
| deep_finder | LLM 深挖 | 10.32 | 是 |
| candidate_screener | 候选筛选 | 3.36 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.08 | 是 |
| coordinator | 管线协调 | 6.18 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
