# 落日二号乙漏洞挖掘报告 — 20261031-214049-a23cff

- 生成时间：2026-10-31T13:41:58.173695+00:00
- 输入：`$WORKSPACE\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次汇总基于单文件 PHP 脚本 009.php（79 行）的已去重 findings：共 4 条，其中 3 条为 critical 级 SQL 注入（GEN-07807b8ead6b 日志写入点 line_end=73、GEN-769728152047 用户存在性检查 line_end=22、GEN-1f0233ec126f 用户信息查询 line_end=29），1 条为 medium 级 IDOR（LLM-7d804c24fe1b，硬编码 token 绕过访问控制，line_end=40）。最高危为三处 SQL 注入，均位于同一文件且污点路径极短（source 热点 009.php:9 → sink 热点 009.php:6），一旦参数未经预处理直接拼接即构成未授权数据读取/写入。4 条 finding 均标记 has_poc=true，但需注意：SQL 注入与 IDOR 的 POC 属 HTTP 请求型文本工件（目标统一为 TARGET，仅限授权测试），本次未做任何动态验证，POC 可复现性仅为静态推断。未发现二次注入链（输入未提供存储写点/读点/汇点三元组证据），故不单列。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 009.php（DVWA 风格单文件脚本，code_pack 仅提供 1-61 行，62-79 行未送入）。发现两条链：1) user_id 参数经弱数字正则后直接拼接进 SQL（第 21、28 行），token 为硬编码常量 user_token 可被任意满足，构成 SQL 注入；2) 同一 token 机制导致任意用户资料越权读取（IDOR）。第 7 行 dvwaCurrentUser() 拼接进 SQL 但该函数实现不在 code_pack 中，无法确认其是否可控，未单独报告。第 43 行 $id 直接回显存在反射型 XSS 可能，但受数字正则限制，未单独报告。62-79 行（日志写入 bac_log 表）未送入，可能存在二次注入写点，需补充代码后复核。

未覆盖 / 证据缺口：
- 009.php 第 62-79 行未送入 code_pack，日志写入逻辑（bac_log）无法审计，可能存在二次注入
- dvwaCurrentUser() 实现不在 code_pack，无法确认第 7 行 SQL 是否可控
- 缺少部署/认证配置，无法确认脚本是否暴露公网
- 无 php.ini/数据库配置，无法评估实际可利用边界

## 3. Findings

### F-1: 009.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id`（009.php:17 读取）控制 `$id`，该值被赋给 `$current_user_id` 后直接以字符串插值方式拼入 INSERT 语句 `$log_query`（009.php:71-72），最终在 009.php:73 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。代码未使用 `mysqli_real_escape_string`、预处理语句或类型强制转换（如 `intval`），因此单引号可闭合 `'{$ip}'` 或数字位 `{$current_user_id}` 上下文注入任意 SQL。

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

可对 `bac_log` 表执行任意 INSERT/子查询，进而通过报错或时间盲注读取 `users` 等库内数据（账号、口令哈希、日志），在数据库账号权限较高时可写入任意表数据，造成数据泄露与数据完整性破坏。

**CVE / CWE 论证**

CWE-89：外部可控的 query 参数未经参数化直接拼接进 SQL 并执行，攻击者无需认证即可通过公开页面触发，利用链 source(009.php:17)→拼接(009.php:71-72)→sink(009.php:73) 闭合。

**修复建议**

改用 mysqli 预处理语句并为占位符绑定参数（`$stmt = $mysqli->prepare("INSERT INTO bac_log (user_id,target_id,ip_address) VALUES (?,?,?)"); $stmt->bind_param('iis', $current_user_id, $target_id, $ip);`）；对 `user_id`/`target_id` 强制 `intval()`，对 `$ip` 使用 `filter_var(..., FILTER_VALIDATE_IP)` 校验；数据库账号遵循最小权限，仅授予 INSERT 权限。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=<payload>` → 009.php:17 读取 → `$id`/`$current_user_id` → 009.php:71-72 字符串拼接进 `$log_query` → 009.php:73 `mysqli_query` 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行附近 SQL 查询拼接点的注入 POC。注入通道为 GET 参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:73，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义。
POC 备注：仅文本工件，不执行。保留原请求结构，补充了恒假对照步骤以增强可复现性；TARGET 需替换为授权环境地址。

### F-2: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

同一 query 参数 `user_id`（009.php:17）被赋给 `$id` 后，在 009.php:21 以 `"SELECT user_id FROM users WHERE user_id = '$id'"` 形式拼接进 `$check_query`，并在 009.php:22 由 `mysqli_query` 执行。单引号闭合即可注入，代码未做转义或参数化。

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

可绕过用户存在性判断并读取 `users` 表任意数据（如通过 UNION/布尔盲注枚举 user_id、口令哈希），为后续越权或撞库提供信息。

**CVE / CWE 论证**

CWE-89：外部 query 参数直接拼接进 SELECT 并执行，无需认证，source(009.php:17)→拼接(009.php:21)→sink(009.php:22) 链路闭合。

**修复建议**

使用预处理语句绑定 `user_id`（`SELECT user_id FROM users WHERE user_id = ?`），并对输入做 `intval()` 白名单化；统一封装数据库访问层，禁止字符串拼接 SQL。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=<payload>` → 009.php:17 → `$id` → 009.php:21 拼接 `$check_query` → 009.php:22 `mysqli_query` 执行。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行附近 SQL 查询拼接点的注入 POC。注入通道为 GET 参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:22，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合。
POC 备注：仅文本工件，不执行。TARGET 需替换为授权环境地址。

### F-3: 009.php 用户信息查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

在 `$user_exists` 为真分支中，009.php:28 将 `$id` 直接拼入 `"SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"`，并在 009.php:29 由 `mysqli_query` 执行。`$id` 源自 009.php:17 的 query 参数 `user_id`，无转义、无参数化。

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

可注入 UNION/布尔/时间盲注读取 `users` 表任意列（姓名、头像路径、user_id 等），造成敏感数据泄露；结合前两处注入可扩大读取范围。

**CVE / CWE 论证**

CWE-89：外部可控 query 参数拼接进 SELECT 并执行，无需认证，source(009.php:17)→拼接(009.php:28)→sink(009.php:29) 闭合。

**修复建议**

改为预处理语句绑定参数（`SELECT first_name,last_name,user_id,avatar FROM users WHERE user_id = ?`），对 `user_id` 做整数校验；输出侧对 `avatar` 等字段做转义以防二次利用。

**验证说明**

静态证据：入口 GET /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求 `?user_id=<payload>` → 009.php:17 → `$id` → 009.php:28 拼接 `$query` → 009.php:29 `mysqli_query` 执行。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行附近 SQL 查询拼接点的注入 POC。注入通道为 GET 参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:29，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合。
POC 备注：仅文本工件，不执行。TARGET 需替换为授权环境地址。

### F-4: 009.php 用户资料越权访问（硬编码 token 绕过访问控制）

- **类型**：`idor` / CWE-639
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`009.php:26-40`
- **来源**：`llm_finding`

**描述**

第 26 行以 $_GET['token'] == 'user_token' 作为访问控制，token 为硬编码常量且与当前用户无关；第 28 行按客户端提供的 user_id 查询任意用户资料，未校验该 user_id 是否属于当前登录用户（第 7 行虽查询了当前用户 ID 但未用于授权判断）。任意攻击者提供 token=user_token 即可读取任意用户资料。

**source / sink**

- source：query `user_id`（009.php:13）
- sink：009.php:40 按客户端 user_id 查询并回显任意用户资料（第 28-38 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:13` | 读取 action 与 user_id | 客户端可控 |  |
| 2 | `009.php:26` | token 硬编码校验通过 | 校验通过 | token 为固定常量 user_token，与用户身份无关 |
| 3 | `009.php:28` | 按客户端 user_id 查询任意用户资料 | 越权查询 |  |
| 4 | `009.php:36` | 资料回显到页面 | 敏感数据泄露 |  |

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

未授权读取任意用户个人资料（姓名、头像路径），构成水平越权。

**CVE / CWE 论证**

CWE-639：访问控制依赖客户端可控的硬编码 token，且未校验对象归属，外部可直接触发。

**修复建议**

基于服务端会话确定当前用户，禁止客户端指定 user_id；移除硬编码 token。

**验证说明**

需确认部署中 token 常量未被修改，以及是否存在前置认证。
模型 POC 要点：提供硬编码 token 并遍历 user_id 读取其他用户资料。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /009.php）：针对 009.php 第 40 行附近对象访问控制的 IDOR POC。通过 GET 参数 user_id 指定对象，与 Cookie user_id 表示的主体身份做对照，验证是否缺少归属校验。仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009.php）：符合 CWE-639。漏洞位于 009.php:40，对象标识来自 GET 参数 user_id，主体标识来自 Cookie user_id，代码范围内未见归属校验。
POC 备注：仅文本工件，不执行。三步均为独立请求，Cookie 保持不变以体现主体一致；TARGET 需替换为授权环境地址。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.83 | 是 |
| surface_mapper | 攻击面测绘 | 11.69 | 是 |
| deep_finder | LLM 深挖 | 13.07 | 是 |
| candidate_screener | 候选筛选 | 8.22 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.28 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 14.06 | 是 |
| coordinator | 管线协调 | 9.37 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
