# 落日二号乙漏洞挖掘报告 — 20261031-013721-78e2aa

- 生成时间：2026-10-30T17:38:19.265684+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\008.zip`
- 输入模式：`zip`
- SHA256：`dfae4e0605b1c5ffe8c4a8291c00c73ea277b830eed60f0489dfec01c43f36a6`
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

本次汇总基于已去重的 5 条 findings，全部集中在单文件 PHP 脚本 008.php（code_pack 仅含该文件，96 行）。最高危为 3 条 critical 级 SQL 注入：GEN-31888d7d7e9c（日志写入，line_end 81）、GEN-f0aa8e8c7f6b（用户存在性检查，line_end 23）、GEN-efda4d219748（用户详情查询，line_end 36），均为规则命中且带 POC。另有 1 条 high 级 IDOR（LLM-12766729f097，可篡改 user_id Cookie 越权读取任意用户资料，line_end 45）与 1 条 medium 级存储型 XSS（LLM-3ee4fdec5d75，资料字段未编码输出，line_end 47）。5 条 findings 均标记 has_poc=true，POC 齐全；但需注意这些 POC 为静态构造文本，未做动态验证，且 IDOR/XSS 两条为 llm_inferred 等级，证据强度低于规则命中的 SQL 注入。本次未发现二次注入链（无存储写点/读点/危险汇点三元组证据），也未发现 prompt_injection 证据。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 CODE PACK 提供的 008.php 第 1-65 行（共 96 行，66-96 行未送入）。已确认两条链：(1) 第 30-33 行基于客户端 Cookie user_id 的归属校验可被伪造，配合第 15-19 行参数构成 IDOR，读取任意用户资料，链闭合、置信度高；(2) 第 40-47 行将数据库字段未编码输出，存在存储型 XSS 可能，但写入点不在 CODE PACK 内，置信度中等。第 7 行 dvwaCurrentUser() 拼接进 SQL 属框架函数，未在包内展示其实现，无法确认是否可注入，未报告。第 60-65 行 SHOW TABLES/CREATE TABLE 为固定语句，无污点。未发现命令执行、文件包含、反序列化、SSRF 等 sink。66-96 行（日志写入逻辑）未覆盖，可能存在额外注入点，需后续补充。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入，日志写入逻辑未审计
- dvwaCurrentUser() 实现未提供，第 7 行 SQL 注入无法确认
- 资料写入入口（first_name/last_name/avatar 来源）不在 CODE PACK，XSS 写入点未闭合
- 无认证/会话配置，无法确认页面访问控制与 Cookie 是否另有签名

## 3. Findings

### F-1: 008.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id`（008.php:19 读取）控制 `$id`，该值被赋给 `$current_user_id` 后直接以字符串拼接方式嵌入 INSERT 语句 `$log_query`（008.php:79-80），未做整型转换、未使用 mysqli_real_escape_string、也未使用预处理语句，最终在 008.php:81 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。由于 `{$current_user_id}` 位于 VALUES 列表的数值位置，攻击者提交如 `1),(1,1,'x')-- -` 之类的值即可闭合元组并注入任意 SQL 片段，校验完全失效。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:81 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `008.php:81` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-31888d7d7e9c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可向 bac_log 表写入任意数据（日志伪造/审计污染），并可通过 UNION/子查询读取 users 等表内容，造成数据库数据泄露；若数据库账号权限过高，还可进一步读写文件或篡改业务数据。

**CVE / CWE 论证**

CWE-89：外部可控的 query 参数 `user_id` 未经参数化直接拼接到 SQL 语句并在 008.php:81 执行，攻击者无需认证即可通过 HTTP 触发，利用链（source 008.php:19 → $current_user_id → $log_query → mysqli_query 008.php:81）闭合。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param），对 user_id 强制 `(int)` 转换或 filter_var(FILTER_VALIDATE_INT) 校验；ip_address 使用参数绑定而非字符串拼接；数据库账号遵循最小权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：008.php:19 从 query 读取 `user_id` → 赋值给 `$current_user_id` → 008.php:79-80 字符串拼接进 `$log_query` 的 VALUES 数值位 → 008.php:81 `mysqli_query` 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:81 的 SQL 注入 POC。外部输入来自查询参数 user_id，被拼接进 SQL 语句后执行，未发现有效净化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:81，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。请求结构沿用输入草稿，仅补充基线与对照步骤；目标统一使用 TARGET。

### F-2: 008.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

query 参数 `user_id`（008.php:19）进入 `$id` 后，在 008.php:22 被直接拼接为 `SELECT user_id FROM users WHERE user_id = $id`，未做类型转换或转义，随后在 008.php:23 由 `mysqli_query` 执行。攻击者可在 `user_id` 中注入布尔/UNION 载荷，改变查询语义。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:23 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `008.php:23` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-f0aa8e8c7f6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过用户存在性判断逻辑，并通过 UNION/布尔盲注枚举 users 表数据（user_id 等），造成信息泄露并为后续越权访问铺路。

**CVE / CWE 论证**

CWE-89：外部可控参数 `user_id` 未经参数化拼接进 SELECT 并在 008.php:23 执行，HTTP 可达、无需认证，source→sink 链闭合。

**修复建议**

使用 mysqli_prepare 绑定整型参数，或对 `$id` 执行 `(int)` 强制转换；禁止字符串拼接构造 SQL。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：008.php:19 读取 query `user_id` → `$id` → 008.php:22 拼接 `$check_query` → 008.php:23 `mysqli_query` 执行。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:23 的 SQL 注入 POC。外部输入来自查询参数 user_id，被拼接进 SQL 语句后执行，未发现有效净化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:23，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。请求结构沿用输入草稿，仅补充基线与对照步骤；目标统一使用 TARGET。

### F-3: 008.php 用户详情查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

query 参数 `user_id`（008.php:19）经 `$id` 在 008.php:35 被拼接进 `SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;`，未做任何过滤或参数化，在 008.php:36 由 `mysqli_query` 执行。攻击者可注入 UNION SELECT 直接控制返回的 first_name/last_name/avatar 等字段。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:36 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `008.php:36` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-efda4d219748`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取任意表数据（如凭据、个人信息），并可通过控制返回字段影响页面渲染内容，造成数据泄露与内容伪造。

**CVE / CWE 论证**

CWE-89：外部可控 `user_id` 未经参数化进入 SELECT 并在 008.php:36 执行，HTTP 可达、无需认证，利用链闭合。

**修复建议**

改用预处理语句绑定整型参数；对 `$id` 做 `(int)` 或 FILTER_VALIDATE_INT 校验；输出侧对返回字段做 HTML 转义以防二次风险。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：008.php:19 读取 query `user_id` → `$id` → 008.php:35 拼接 `$query` → 008.php:36 `mysqli_query` 执行。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:36 的 SQL 注入 POC。外部输入来自查询参数 user_id，被拼接进 SQL 语句后执行，未发现有效净化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:36，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。请求结构沿用输入草稿，仅补充基线与对照步骤；目标统一使用 TARGET。

### F-4: DVWA BAC 页面通过可篡改的 user_id Cookie 实现越权访问任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-45`
- **来源**：`llm_finding`

**描述**

008.php 第 15 行从 $_GET['user_id'] 读取目标用户 ID，第 16 行仅用 /^\d+$/ 校验为纯数字，第 19 行 intval 后进入业务逻辑。第 30-33 行的访问控制完全依赖客户端 Cookie $_COOKIE['user_id']：只要 Cookie 中的 user_id 与请求参数 user_id 相等（$id == $cookie_id），即视为“本人”并放行。Cookie 由攻击者完全可控，因此攻击者只需把 Cookie user_id 与查询参数 user_id 设为同一个任意受害者 ID，即可绕过归属校验，读取任意用户的 first_name、last_name、avatar 等资料。服务端从未将请求中的 user_id 与当前登录会话（dvwaCurrentUser() 查出的 $current_user_id）比对，属于典型的水平越权（IDOR）。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:45 mysqli_query 执行 SELECT first_name,last_name,user_id,avatar FROM users WHERE user_id = $id 并将结果回显到页面

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 从 $_GET['action'] 与 $_GET['user_id'] 读取请求参数，进入越权分支 | 攻击者可控字符串 |  |
| 2 | `008.php:16` | preg_match('/^\d+$/') 仅校验纯数字，不校验归属 | 纯数字字符串 | 只做格式校验，任意数字均通过 |
| 3 | `008.php:19` | intval 转换为整数 $id | 整数 $id |  |
| 4 | `008.php:30` | 读取攻击者可控的 Cookie user_id | 攻击者可控 Cookie 值 |  |
| 5 | `008.php:31` | intval 转换为 $cookie_id | 整数 $cookie_id |  |
| 6 | `008.php:33` | $id == $cookie_id 判定为“本人”，放行 | 两值相等即通过 | 归属校验基于客户端 Cookie，攻击者可将 Cookie 设为任意受害者 ID |
| 7 | `008.php:35` | 以 $id 查询受害者资料 | 整数 $id 拼入 SQL |  |
| 8 | `008.php:43` | 将受害者 first_name/last_name/avatar 回显到页面 | 数据库返回的受害者资料 |  |

**POC**

针对 /008.php?action=view&user_id=<id>（GET）的越权/IDOR POC。服务端以 Cookie user_id 作为身份标识，且未校验请求的 user_id 是否属于当前身份，导致可读取他人资料。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php?action=view&user_id=<id>'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=view&user_id=<id>' \
  -H 'Cookie: user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`2`
- POC 目录：`poc/LLM-12766729f097`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意已认证（甚至仅需能访问该页面）的攻击者可读取其他用户的姓名、头像等个人资料，造成水平越权与隐私泄露；结合第 7 行 dvwaCurrentUser() 可知服务端本可拿到真实当前用户 ID 却未用于校验。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）。外部可通过 HTTP 直接触发，无需高权限，仅需可控 Cookie；链闭合：source(Cookie/参数)→格式校验→Cookie 相等判定→SQL 查询→回显。

**修复建议**

服务端应使用会话中已认证的 $current_user_id（第 10 行）与请求的 $id 比对，禁止信任客户端 Cookie 做归属判断；对敏感资料查询强制 WHERE user_id = 当前会话用户。

**验证说明**

需确认部署中该页面是否要求登录、Cookie user_id 是否由前端可任意设置（源码显示直接读取 $_COOKIE，未做签名校验，故可伪造）。
模型 POC 要点：将 Cookie user_id 与查询参数 user_id 设为同一受害者 ID，绕过归属校验读取他人资料。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php?action=view&user_id=<id>）：符合 CWE-639。漏洞位于 008.php:45，身份标识来自 Cookie user_id，对象 ID 来自请求参数 user_id，二者未做归属校验，source→sink 链在给定代码范围内静态闭合。
POC 备注：POC 仅为文本工件，不执行、不联网。请求结构沿用输入草稿，仅补充基线与遍历步骤；目标统一使用 TARGET。

### F-5: 008.php 用户资料字段未编码直接输出导致存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.52`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:40-47`
- **来源**：`llm_finding`

**描述**

第 40-47 行将数据库返回的 $row['first_name']、$row['last_name']、$row['avatar'] 直接拼接进 HTML 字符串并输出，未调用 htmlspecialchars/htmlentities 编码。若攻击者能控制自己资料中的这些字段（如通过资料编辑功能写入含脚本的 avatar 或姓名），则当其他用户（含管理员）查看该资料页时脚本在其浏览器执行，构成存储型 XSS。

**source / sink**

- source：repository `avatar`（008.php）
- sink：008.php:47 $html 拼接后输出到页面（echo/print）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:39` | mysqli_fetch_assoc 取出用户资料行 | 数据库存储的字段值 |  |
| 2 | `008.php:44` | 将 first_name/last_name 直接插入 HTML | 未编码的原始字符串 |  |
| 3 | `008.php:45` | 将 avatar 直接插入 HTML | 未编码的原始字符串 |  |
| 4 | `008.php:40` | $html 最终输出到响应页面 | 含未编码用户数据的 HTML |  |

**POC**

针对 008.php:47 的存储型 XSS POC。用户资料字段（first_name/last_name/avatar 等）从数据库读出后直接拼接进 HTML 输出，未做 HTML 编码；攻击者先通过资料更新写入 payload，再在查看页面触发。目标地址使用 TARGET 占位符，仅限授权测试。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 008.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-3ee4fdec5d75`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /008.php?action=view&user_id=<id>, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

存储型 XSS，可在受害者（含管理员）浏览器执行任意脚本，窃取会话或发起敏感操作。

**CVE / CWE 论证**

CWE-79。外部可达，输出点未编码；但写入点（资料编辑）不在 CODE PACK 内，链的 source 端依赖外部功能，故置信度中等。

**修复建议**

输出前对所有用户数据使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码；对 avatar 等 URL 字段做协议白名单校验。

**验证说明**

CODE PACK 仅含 008.php 1-65 行，未展示资料写入入口；需确认 first_name/last_name/avatar 是否可由用户控制写入，否则仅为反射/无实际写入的推断。
模型 POC 要点：在可控资料字段写入脚本标签，受害者查看资料页时触发。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：POC 仅为文本工件，不执行、不联网。写点路由 action=update 为基于源码的推断，若实际写入口不同需按部署调整；目标统一使用 TARGET。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 2.46 | 是 |
| surface_mapper | 攻击面测绘 | 9.3 | 是 |
| deep_finder | LLM 深挖 | 13.37 | 是 |
| candidate_screener | 候选筛选 | 6.82 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.32 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 12.08 | 是 |
| coordinator | 管线协调 | 6.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
