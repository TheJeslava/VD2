# 落日二号乙漏洞挖掘报告 — 20261031-013721-ba75ab

- 生成时间：2026-10-30T17:38:14.331060+00:00
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

本次汇总 4 条已去重 findings，全部集中在单文件 PHP 脚本 009.php（79 行）：3 条 SQL 注入（critical，分别位于用户存在性检查、用户详情查询、日志写入，行号 22/29/73）与 1 条硬编码 token 导致的访问控制绕过（medium，行号 28）。最高危为 009.php 中三处 SQL 拼接注入，均带 POC（HTTP 型，可动态复现）。4 条 finding 均标注 has_poc=true，POC 齐全；但 POC 仅为文本工件，未执行、未做动态验证。auth_bypass 属逻辑/凭据类问题，其 POC 为静态证据型，需代码与会话语义复核，不能宣称已动态复现。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 009.php 的前 61 行（共 79 行，第 62-79 行未送入）。已审计：第 7 行 dvwaCurrentUser() 拼接（来源为框架函数，非直接外部输入，未单列）、第 13-47 行 user_id 参数流与 token 访问控制、第 50-61 行 bac_log 建表逻辑（SQL 为常量，无注入）。发现两条链：user_id SQL 注入（依赖 PCRE $ 换行绕过，置信度 0.72）与硬编码 token 访问控制绕过（置信度 0.8）。未闭合线索：第 62-79 行未覆盖，可能含日志写入（二次注入写点）或更多 sink；dvwaCurrentUser() 实现不在 code_pack 内，无法确认其是否可被污染；无 Web 服务器/认证配置证据，无法确认页面暴露面。

未覆盖 / 证据缺口：
- 009.php 第 62-79 行未送入 code_pack，日志写入与后续逻辑未审计
- dvwaCurrentUser() 定义不在 code_pack，无法判断第 7 行是否可被外部污染
- 无部署/认证配置，无法确认页面是否公网可达及是否需要登录
- 无数据库结构证据，UNION 列数需按实际 users 表调整

## 3. Findings

### F-1: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 user_id 提供输入，在 009.php:17 被读取并赋给 $id。该值未经任何转义或参数化，直接在 009.php:21 被拼接进双引号 SQL 字符串 "SELECT user_id FROM users WHERE user_id = '$id'"，随后在 009.php:22 通过 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。由于 $id 被单引号包裹且未使用 mysqli_real_escape_string 或预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 user_id=1' OR '1'='1 或 UNION 查询）。校验无效的原因：代码仅做字符串拼接，没有任何白名单、类型转换（如 intval）或参数绑定。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-769728152047`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：攻击者可读取 users 表及其他表内容（凭据、个人信息）；结合 UNION 可跨表读取；在具备 FILE 权限时可读写服务器文件，进一步可能导致 RCE。该查询位于用户存在性检查路径，属于无需认证即可触达的入口。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：user_id 来自 HTTP 查询参数，无需认证即可访问 009.php；利用链闭合：source（009.php:17）→ 字符串拼接（009.php:21）→ mysqli_query 执行（009.php:22），全程无有效净化。

**修复建议**

改用预处理语句与参数绑定：$stmt = $mysqli->prepare("SELECT user_id FROM users WHERE user_id = ?"); $stmt->bind_param('i', $id); 并对 $id 做 intval 类型强制；禁止将外部输入直接拼接进 SQL。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 009.php?user_id=1' OR '1'='1 → 009.php:17 读取 user_id 赋给 $id → 009.php:21 拼接进 $check_query → 009.php:22 mysqli_query 执行被篡改的 SQL，绕过存在性判断并泄露数据。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行 SQL 注入汇点的 POC。注入通道为 HTTP 查询参数 user_id，payload 为布尔恒真式 ' OR '1'='1，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:22，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未见参数化或有效转义。
POC 备注：POC 仅为文本工件，不执行、不联网。手工测试时替换 TARGET 为授权目标；禁止使用 DROP/破坏性语句。

### F-2: 009.php 用户详情查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

同一外部输入 user_id 在 009.php:17 被读取为 $id，在用户存在性判断通过后（009.php:27），于 009.php:28 被拼接进 "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"，并在 009.php:29 由 mysqli_query 执行。$id 未做转义或参数化，单引号可被闭合注入。校验无效原因：仅字符串拼接，无预处理、无转义、无类型约束。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-1f0233ec126f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据泄露：攻击者可读取 users 表的 first_name、last_name、user_id、avatar 等字段，并通过 UNION 注入读取任意表数据；若数据库账户权限过高，可进一步读写文件。无需认证即可触达。

**CVE / CWE 论证**

CWE-89。外部可达性：user_id 为 HTTP 查询参数，匿名可访问；利用链闭合：source（009.php:17）→ 拼接（009.php:28）→ mysqli_query（009.php:29），无有效净化。

**修复建议**

使用预处理语句绑定 user_id 参数，并对输入做整数校验；避免字符串拼接构造 SQL。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交恶意 user_id → 009.php:17 读取 → 009.php:27 存在性判断通过 → 009.php:28 拼接进 $query → 009.php:29 执行，返回被注入查询的结果。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行 SQL 注入汇点的 POC。注入通道为查询参数 user_id，payload 为 ' OR '1'='1，目标使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:29，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内闭合，未见有效净化。
POC 备注：文本工件，不执行。仅限授权测试，替换 TARGET 后手工发送。

### F-3: 009.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

在 009.php:71-72 构造 INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')，其中 {$ip} 被单引号包裹但未转义，{$current_user_id} 与 {$target_id} 为无引号数值位。候选标注 source 为 query user_id（009.php:17），但代码片段显示该 INSERT 直接拼接的是 $current_user_id、$target_id、$ip 三个变量，其具体来源在给定片段中未完整展示（证据不足，无法确认 user_id 是否直接流入这些变量）。可确认的是：$ip 等变量在 009.php:72 被直接拼接，009.php:73 通过 mysqli_query 执行，若其中任一变量可由外部控制（如 X-Forwarded-For 头或参数），即可注入。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-07807b8ead6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 $ip/$target_id/$current_user_id 可被外部控制，攻击者可注入任意 SQL，篡改或读取 bac_log 及关联表数据，甚至通过堆叠/子查询影响其他表；日志表污染还可用于二次注入。

**CVE / CWE 论证**

CWE-89。外部可达性：取决于 $ip 等变量来源，代码片段未展示其赋值，故外部可达性证据不足；利用链在 009.php:72→73 处闭合（拼接→执行），但 source 端证据不足。

**修复建议**

对 INSERT 使用预处理语句绑定 user_id、target_id、ip_address 三个参数；对 IP 使用 filter_var($ip, FILTER_VALIDATE_IP) 校验；对数值字段做 intval 强制。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求触发日志记录逻辑 → 009.php:71-72 将 $current_user_id、$target_id、$ip 拼接进 $log_query → 009.php:73 mysqli_query 执行。source 端（这些变量如何由 user_id 或其他外部输入赋值）在给定片段中未展示，需补充证据确认。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行 SQL 注入汇点的 POC，注入参数 user_id，payload 为 ' OR '1'='1，目标使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。漏洞位于 009.php:73，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内闭合，未见有效净化。
POC 备注：文本工件，不执行。仅限授权测试，替换 TARGET 后手工发送。

### F-4: 009.php 硬编码 token=user_token 访问控制可被任意用户绕过

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`009.php:26-28`
- **来源**：`llm_finding`

**描述**

第 26 行以 `$_GET['token'] == 'user_token'` 作为访问控制，token 为硬编码常量且注释直接提示（第 39、46 行），任何攻击者只要附加 token=user_token 即可通过校验，读取任意 user_id 的资料，构成水平/垂直越权与认证绕过。

**source / sink**

- source：query `token`（009.php）
- sink：009.php:28 访问控制判断后执行资料查询并回显

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:26` | 硬编码 token 比较，攻击者直接提供 user_token 即通过 | 常量 token 匹配成功 | token 为公开硬编码值，注释亦泄露 |
| 2 | `009.php:28` | 通过后查询任意 user_id 资料并回显 | 越权读取 |  |

**POC**

针对 /009.php 第 28 行认证逻辑的绕过 POC。通过查询参数 token 传入固定值 admin，尝试以伪造身份访问受保护资源。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?token=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-3a729819e914`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意访问者可读取其他用户资料，绕过本应存在的访问控制。

**CVE / CWE 论证**

CWE-284/CWE-798 硬编码凭据导致访问控制绕过，外部可达且无需真实认证。

**修复建议**

移除硬编码 token，改用服务端会话与基于对象归属的授权校验。

**验证说明**

需确认部署环境中该页面是否对外暴露；token 值在源码中明文可见。
模型 POC 要点：附加硬编码 token 读取任意用户资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /009.php）：符合 CWE-287。漏洞位于 009.php:28，认证判断直接使用外部查询参数 token，缺少可信校验。
POC 备注：文本工件，不执行、不联网。仅限授权测试；token 值需按目标实际逻辑调整，但不得指向真实主机。

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
| `auth_bypass` | CWE-287 | 是 | 1 |
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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 7.54 | 是 |
| deep_finder | LLM 深挖 | 10.88 | 是 |
| candidate_screener | 候选筛选 | 6.51 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.55 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 9.65 | 是 |
| coordinator | 管线协调 | 5.78 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
