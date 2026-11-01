# 落日二号乙漏洞挖掘报告 — 20261031-172507-8e43c6

- 生成时间：2026-10-31T09:26:03.275339+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次汇总基于已去重的 4 条 findings，全部集中在单文件 PHP 应用 009.php（79 行）。最高危为 3 条 critical 级 SQL 注入（CWE-89）：用户存在性检查（GEN-769728152047，行 22）、用户信息查询（GEN-1f0233ec126f，行 29）、日志写入（GEN-07807b8ead6b，行 73），均标记 has_poc=true；另有 1 条 high 级 IDOR（LLM-7d804c24fe1b，行 40），描述为通过硬编码 token 绕过访问控制读取任意用户资料，同样 has_poc=true。4 条 finding 均附带 POC，POC 齐全度为 4/4，但均为静态文本 POC，未做动态验证，不能宣称可动态复现。需注意：输入未提供任何代码片段，行号与数据流结论来自规则/模型推断（llm_inferred 与 rule 混合），证据等级需在复核时确认。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：审计了唯一文件 009.php 的 1-61 行（共 79 行，62-79 行未送入）。确认一处闭合的 IDOR/访问控制绕过：硬编码 token 'user_token' 被注释泄露，可越权读取任意用户资料（confidence 0.85）。user_id 虽拼接进 SQL，但受 `/^\d+$/` 数字白名单约束，注入链不闭合，仅作线索记录（confidence 0.5，低于阈值，不应作为正式 finding）。第 43 行 `{$id}` 回显受数字校验限制，XSS 不成立。62-79 行（bac_log 建表/日志写入）未覆盖，可能存在二次注入写点，但读取点与汇点不可见，无法闭合。

未覆盖 / 证据缺口：
- 009.php 62-79 行未送入，bac_log 日志写入逻辑不可见，二次注入无法评估
- 无 php.ini/部署配置，无法确认 register_globals 等
- 无 users 表 schema

## 3. Findings

### F-1: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id` 提供输入，该值在 009.php:17 被读取后赋给变量 `$id`，未经任何转义或参数化，直接在 009.php:21 拼接进 SQL 语句 "SELECT user_id FROM users WHERE user_id = '$id'"，并在 009.php:22 通过 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。由于 `$id` 被单引号包裹但未使用 mysqli_real_escape_string 或预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。该查询是后续逻辑（用户是否存在判断）的前置检查，注入结果直接影响分支走向。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-769728152047`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取 users 表及同库其他表的任意数据（如凭据、个人信息），并可借助 UNION/布尔盲注枚举数据库结构；若数据库账户权限过高，还可能造成数据篡改。属于机密性与完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：`user_id` 来自 HTTP query 参数，无需认证即可触发；利用链闭合：009.php:17 取值 → 009.php:21 字符串拼接 → 009.php:22 mysqli_query 执行，中间无有效净化。

**修复建议**

改用预处理语句：`$stmt = $mysqli->prepare("SELECT user_id FROM users WHERE user_id = ?"); $stmt->bind_param('s', $id); $stmt->execute();`；若必须动态拼接，至少使用 mysqli_real_escape_string 并对 `user_id` 做类型/白名单校验（如强制整数）。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `009.php?user_id=1' OR '1'='1` → 009.php:17 读取 `user_id` 存入 `$id` → 009.php:21 拼接为 `SELECT user_id FROM users WHERE user_id = '1' OR '1'='1'` → 009.php:22 mysqli_query 执行，返回全部用户，绕过存在性判断。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行 SQL 注入点的 POC：GET 参数 user_id 未经净化进入 SQL 查询，使用布尔恒真载荷 ' OR '1'='1 改变查询结果集。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:22，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅文本工件，不执行、不联网；TARGET 需替换为授权测试目标。恒真/恒假对比用于降低误报。

### F-2: 009.php 用户信息查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

同一外部输入 `user_id`（009.php:17 读取，赋给 `$id`）在通过存在性检查后，于 009.php:28 被再次拼接进 "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"，并在 009.php:29 由 mysqli_query 执行。该处同样未使用参数化或转义，单引号包裹的 `$id` 可被闭合注入。由于该查询返回用户资料字段，注入可直接操纵返回结果集。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-1f0233ec126f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可泄露 users 表的 first_name、last_name、user_id、avatar 等字段，配合 UNION 可读取任意表数据；也可通过注入改变查询逻辑以越权获取其他用户资料。

**CVE / CWE 论证**

CWE-89。外部可达：`user_id` 为 HTTP query 参数，无需认证；利用链闭合：009.php:17 → 009.php:28 拼接 → 009.php:29 mysqli_query，无净化。

**修复建议**

使用预处理语句绑定 `$id`；对 `user_id` 做整数强制转换或白名单校验；避免将外部输入直接插入 SQL 字符串。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 `009.php?user_id=1' UNION SELECT ...-- -` → 009.php:17 读取 `user_id` → 009.php:28 拼接进 SELECT 语句 → 009.php:29 执行，返回攻击者构造的数据。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行 SQL 注入点的 POC：GET 参数 user_id 在 29 行处再次进入 SQL 语句，使用布尔恒真载荷验证注入。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:29，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅文本工件，不执行、不联网；TARGET 需替换为授权测试目标。

### F-3: 009.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

009.php:71-72 构造 INSERT 语句 "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')"，其中 `$target_id` 与 `$ip` 未加引号/未转义直接拼接，`$current_user_id` 亦为变量拼接；该语句在 009.php:73 由 mysqli_query 执行。候选标注 source 为 query `user_id`（009.php:17），但代码片段显示 `$target_id`、`$ip`、`$current_user_id` 才是直接进入该 INSERT 的变量，`user_id` 到 `$target_id` 的赋值关系在给定片段中未直接呈现，故污点链存在证据缺口。若 `$target_id` 或 `$ip` 可由外部控制（如来自请求参数或可伪造的 IP 头），则可注入。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-07807b8ead6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入成立，可向 bac_log 表写入任意数据或通过子查询/报错注入读取其他表数据，破坏日志完整性与数据库机密性。

**CVE / CWE 论证**

CWE-89。外部可达性：取决于 `$target_id`/`$ip`/`$current_user_id` 的来源，给定片段未展示其赋值，证据不足；利用链：009.php:71-72 拼接 → 009.php:73 执行，净化缺失可确认，但 source 到 sink 的完整路径未在片段中闭合。

**修复建议**

对 INSERT 使用预处理语句并绑定所有列值；`$ip` 应通过 `filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)` 校验后再入库；`$target_id`、`$current_user_id` 强制转为整数。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：（推断）外部可控的 `target_id` 或伪造的 `ip` 进入 009.php:71-72 的 INSERT 拼接 → 009.php:73 mysqli_query 执行 → 注入生效。由于片段未给出 `$target_id`/`$ip` 的具体来源，该链未完全闭合。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行 SQL 注入点的 POC：GET 参数 user_id 在 73 行处进入 SQL 语句，使用布尔恒真载荷验证注入。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:73，外部输入来自 GET 参数 user_id，source→sink 链静态闭合，未见有效净化，可远程触发。
POC 备注：仅文本工件，不执行、不联网；TARGET 需替换为授权测试目标。

### F-4: DVWA 009.php 用户资料接口通过硬编码 token 绕过访问控制导致越权读取任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`009.php:26-40`
- **来源**：`llm_finding`

**描述**

009.php 的 action/user_id 分支仅用 `$_GET['token'] == 'user_token'` 这一硬编码字符串作为访问控制，且该 token 直接写在页面注释提示中（第 39、46 行）。攻击者无需任何身份即可传入 token=user_token 并遍历 user_id，读取任意用户的 first_name、last_name、avatar 等资料，构成水平/垂直越权（IDOR）。

**source / sink**

- source：query `token`（009.php:13）
- sink：009.php:40 mysqli_query 查询任意 user_id 资料并回显（009.php:28-40）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:13` | 读取 action 与 user_id 参数进入分支 | 外部可控 |  |
| 2 | `009.php:14` | user_id 仅校验为纯数字，合法数字通过 | 数字字符串 |  |
| 3 | `009.php:26` | token 与硬编码 'user_token' 比较，注释已泄露该值 | token=user_token 通过 | 访问控制为硬编码常量且被注释泄露 |
| 4 | `009.php:28` | 以攻击者指定 user_id 查询资料并回显 | 任意用户资料 |  |

**POC**

针对 /009.php（GET）的 越权 / IDOR POC。注入点：查询 user_id=2 与 Cookie user_id=1 的对象归属对照；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
```
预期：返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1

3. **将 user_id 改为当前用户 ID 做对照**

```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?action=View%20Profile&user_id=1' -H 'Cookie: user_id=1'
```
预期：对照响应只返回当前用户资料，攻击响应返回另一用户资料

- payload：`2`
- POC 目录：`poc/LLM-7d804c24fe1b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

未授权读取任意用户姓名、头像等敏感资料，越权访问

**CVE / CWE 论证**

CWE-639 授权绕过/IDOR；无需认证，token 硬编码且泄露，链闭合

**修复建议**

移除硬编码 token，改为服务端会话身份校验并校验对象归属

**验证说明**

需确认 users 表存在及部署可达性
模型 POC 要点：直接携带泄露的 token 遍历 user_id 读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /009.php）：针对 009.php 第 40 行的 IDOR POC：以 Cookie user_id=1 作为当前主体，通过查询参数 user_id=2 请求他人资料，验证对象级授权缺失。
PocWriter 建议（未采纳，缺少端点 /009.php）：符合 CWE-639。漏洞位于 009.php:40，对象标识来自请求参数 user_id，未与 Cookie 中当前用户绑定校验，可远程触发。
POC 备注：仅文本工件，不执行、不联网；三步均保持同一 Cookie 以证明主体不变、对象被替换。action 与参数名需按源码确认，未确认前不伪造其他字段。

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
| `sql_injection` | CWE-89 | 是 | 3 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.24 | 是 |
| surface_mapper | 攻击面测绘 | 10.36 | 是 |
| deep_finder | LLM 深挖 | 8.2 | 是 |
| candidate_screener | 候选筛选 | 5.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.2 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 10.02 | 是 |
| coordinator | 管线协调 | 6.93 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
