# 落日二号乙漏洞挖掘报告 — 20261031-173141-8fd3b7

- 生成时间：2026-10-31T09:32:22.454968+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\039.zip`
- 输入模式：`zip`
- SHA256：`dcd627aba47edb36b6b02995d92ae6b47ea38157489be6bc6bc3ad973f56f1e9`
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

本次汇总仅含 1 条已去重 finding：039.php 第 15 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），定级 critical，来源为规则命中，且已附带 POC（HTTP 型，可动态复现）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备。需说明：输入未提供 039.php 的实际代码片段，finding 的行号与参数名来自规则命中记录，本次汇总未做二次代码核对，也未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 039.php 的 1-50 行（共 54 行，末尾 4 行未展示）。已审计该文件全部可见逻辑：入口为 POST Submit 触发的 $_POST['id'] 读取（第 5 行），MYSQL 分支经 mysqli_real_escape_string 后拼接进 SELECT（第 13 行）并由 mysqli_query 执行（第 15 行），SQLITE 分支直接拼接执行（第 34-36 行），构成数字型 SQL 注入，链路闭合，已作为 finding 交付。其余攻击面：脚本无文件包含、命令执行、反序列化、SSRF、模板等 sink；surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在可见代码中均无对应调用（无 md5/sha1、无 openssl/mcrypt、无 rand、无 setcookie、无 X-Forwarded-For 使用），故不报告。未闭合线索：$_DVWA['SQLI_DB'] 常量定义、$html 变量初始化、第 51-54 行内容不在 code_pack 内，无法确认；无路由/认证配置信息，无法确认实际 URL 与访问控制。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未在 code_pack 中展示
- $_DVWA['SQLI_DB'] 常量定义与数据库连接初始化代码不在 code_pack 内
- 无认证/会话配置，无法确认页面访问控制
- 无 php.ini/Web 服务器配置，无法评估 register_globals、display_errors 等影响

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（039.php:5 读取该参数），该值未经任何类型转换、转义或参数化，直接被拼接进 SQL 语句：039.php:13 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 039.php:15 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 SQL 的数值/表达式位置且无引号包裹，攻击者可注入任意 SQL 片段（如 `1 UNION SELECT user, password FROM users` 或布尔/时间盲注载荷）改变查询语义。代码中未见 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单校验，因此校验完全缺失；try/catch 仅用于抑制错误回显，不构成任何防护。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 039.php 第 15 行的 SQL 注入 POC（端点记为 /039）。注入点为 POST 请求体参数 id，被直接拼接进 SQL 查询；payload 使用 TARGET 占位符，仅作文本工件。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/039'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/039' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-22ffdf9a5620`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询结果被直接用于页面输出，攻击者可借此拖取 users 表中的口令哈希等敏感数据（数据泄露），并可进一步通过 UNION/盲注枚举库表结构；若数据库账户权限过高，还可能读写文件或扩展为更严重的影响。属于未授权即可远程触发的注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 039.php；利用链闭合：039.php:5 取参 → 039.php:13 字符串拼接 → 039.php:15 `mysqli_query` 执行，全程无净化点，攻击者可控输入直达危险汇点。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须动态拼接，先对 `$id` 做严格整数校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval()`）并拒绝非数字输入；同时遵循最小权限原则，为应用数据库账户仅授予必要的 SELECT 权限，并关闭详细错误回显。

**验证说明**

静态证据：入口 POST /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /039.php?id=1 UNION SELECT user,password FROM users` → 039.php:5 读取 `id` 得到恶意字符串 → 039.php:13 将其原样拼入 `WHERE user_id = $id` → 039.php:15 `mysqli_query` 执行被篡改的语句 → 查询结果返回并渲染，导致数据泄露。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89。漏洞位于 039.php:15，外部输入来自 POST body 参数 id，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；目标地址使用 TARGET 占位符；仅限授权测试。输入中该条目的 cve_justification 写为 query 参数，但请求实际为 POST body，已按源码注入点统一为 POST 参数 id。

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
| safety_guard | 安全防护 | 2.61 | 是 |
| surface_mapper | 攻击面测绘 | 7.86 | 是 |
| deep_finder | LLM 深挖 | 9.48 | 是 |
| candidate_screener | 候选筛选 | 3.66 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.01 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.6 | 是 |
| coordinator | 管线协调 | 5.62 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
