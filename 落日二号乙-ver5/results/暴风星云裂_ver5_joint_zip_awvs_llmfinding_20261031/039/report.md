# 落日二号乙漏洞挖掘报告 — 20261031-214750-0993d4

- 生成时间：2026-10-31T13:48:44.722564+00:00
- 输入：`$WORKSPACE\暴风星云裂\039.zip`
- 输入模式：`zip`
- SHA256：`dcd627aba47edb36b6b02995d92ae6b47ea38157489be6bc6bc3ad973f56f1e9`
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

本次汇总仅含 1 条已去重 finding：039.php 第 15 行（文件内）基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可动态复现路径）。最高危即该条 SQL 注入，属单文件 PHP 脚本中参数直连危险汇点。POC 齐全度：1/1 有 POC，无缺失。二次注入链：本次输入未提供任何二次注入链，故不涉及存储写点/读点/汇点三要素的判定。需强调：本次仅 1 个文件、0 个端点被覆盖，surface_notes 明确说明未提供 039.php 代码正文，攻击面排序均为基于行号分布的推断，因此除该条 SQL 注入外，其余攻击面（文件包含/路径穿越、命令执行、反射型 XSS、配置类）均处于未覆盖状态，不能据此宣称不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 039.php 第 1-50 行（共 54 行，第 51-54 行未送入）。已审计该文件的请求入口（第 3 行 Submit 判定、第 5 行 $_POST['id'] 读取）与全部 SQL 汇点（第 15 行 mysqli_query、第 36 行 SQLite query）。确认存在一条闭合的 SQL 注入链：mysqli_real_escape_string 仅做字符串转义，而 $id 被拼入无引号的数值上下文，转义无法阻止注入；SQLITE 分支完全无转义。第 45-50 行的 exists 分支提供布尔回显。未发现命令执行、文件包含、反序列化、SSRF、XSS 回显等其它汇点（第 47/50 行 $html 拼接为固定字符串，不含用户输入）。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本片段中无对应代码，未单独立项。第 51-54 行未覆盖，可能包含页面渲染逻辑，若其中回显查询结果列值，则 UNION 注入可直接回显数据，需人工补充确认。输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未送入 code_pack，无法确认是否存在结果列回显或其它汇点
- 未提供 php.ini / Web 服务器配置，无法确认 allow_url_include、magic_quotes 等开关
- 未提供 $_DVWA['SQLI_DB'] 的实际配置值，MYSQL/SQLITE 分支哪条生效需运行时确认
- 无端点清单，无法确认该脚本是否位于认证之后

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（039.php:5 读取该参数），该值未经任何类型转换、转义或参数化，直接被拼接进 SQL 语句：039.php:13 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`。由于 `$id` 位于 SQL 的数值比较位置且无引号包裹，攻击者可注入 `1 UNION SELECT ...`、`1 OR 1=1` 等片段改变查询语义。随后在 039.php:15 该拼接后的 `$query` 被传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行，污点从 source 到 sink 全程无有效净化，利用链闭合。代码注释显示移除了 `or die` 以抑制 MySQL 错误回显，但这只影响报错信息的可见性，不构成任何防护。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /039（POST）的 SQL 注入 POC。注入点：POST 参数 id；payload 使用 TARGET 占位符。

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

数据库数据泄露：攻击者可通过 UNION 注入读取 users 表之外的任意表（如用户名、口令哈希、其他业务数据），也可通过布尔/时间盲注逐字节提取数据；在数据库账户权限较高且支持堆叠查询时可能进一步写入或篡改数据。属于未授权远程可利用的机密性/完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：039.php:5 读取参数 → 039.php:13 字符串拼接 → 039.php:15 `mysqli_query` 执行，中间无白名单、无 `intval`、无 `mysqli_real_escape_string`、无预处理语句。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id); $stmt->execute();`。若必须保留拼接，至少对 `$id` 做严格整数校验（`filter_var($id, FILTER_VALIDATE_INT)` 失败即拒绝）并配合 `mysqli_real_escape_string`；同时为数据库账户实施最小权限，关闭详细错误回显到客户端。

**验证说明**

静态证据：入口 POST /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /039.php?id=1 UNION SELECT user,password FROM users` → 039.php:5 将 `id` 读入变量 → 039.php:13 直接内插进 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 039.php:15 交由 `mysqli_query` 执行 → 返回结果被页面渲染，攻击者获得任意查询结果。
PocWriter 建议（未采纳，缺少端点 /039）：针对 039（POST）的 SQL 注入 POC。注入点为 POST 参数 id，源码在 039.php:15 附近将该参数拼接进 SQL 语句；payload 使用 TARGET 占位符，仅限授权测试。注意：输入中该条目的 cve_justification 写为 query 参数，但请求方法与 body 均为 POST 表单，实际注入通道以 POST body 参数 id 为准。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89。漏洞位于可交付代码 039.php:15，外部输入来自 POST body 参数 id，source→sink 链已静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；目标地址使用 TARGET 占位符；仅限授权测试。请求结构沿用输入中的确定性 POC，仅补充基线与状态确认步骤。

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
| safety_guard | 安全防护 | 4.48 | 是 |
| surface_mapper | 攻击面测绘 | 10.64 | 是 |
| deep_finder | LLM 深挖 | 13.23 | 是 |
| candidate_screener | 候选筛选 | 4.39 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.28 | 是 |
| coordinator | 管线协调 | 7.58 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
