# 落日二号乙漏洞挖掘报告 — 20261031-005800-4a0f85

- 生成时间：2026-10-30T16:58:55.894005+00:00
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

本次汇总基于单文件 PHP 脚本 009.php（79 行）的源码审计，共交付 4 条去重后 findings：3 条 critical 级 SQL 注入（GEN-769728152047 用户查询 user_id、GEN-1f0233ec126f 用户详情查询 user_id、GEN-07807b8ead6b 日志写入语句，均位于 009.php，CWE-89）与 1 条 high 级 IDOR/访问控制绕过（LLM-c8fa3f82d085，009.php 第 47 行附近，硬编码 token 绕过鉴权读取他人资料）。最高危为 3 条 SQL 注入，其中日志写入语句注入（line_end=73）意味着写入路径同样未参数化，影响面可能超出读取。4 条 finding 均标注 has_poc=true，POC 文本齐全；但全部为源码推断 + 静态 POC，未经任何动态验证，SQL 注入 POC 使用 TARGET 占位符，仅限授权测试。本次无二次注入链交付（单文件证据不足以确认存储写点/读点/汇点三段式）。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：审计 009.php 第 1-61 行（共 79 行，62-79 未送入）。确认 IDOR/授权绕过（硬编码 token）链闭合；SQL 注入因数字校验存在不确定性，置信度 0.6。未覆盖 62-79 行及 dvwaCurrentUser() 实现。

未覆盖 / 证据缺口：
- 009.php 62-79 行未送入
- dvwaCurrentUser() 实现不可见
- 无部署/认证配置

## 3. Findings

### F-1: 009.php 用户查询 user_id 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id`（009.php:17 读取）传入恶意字符串，该值未经任何转义或参数化即被拼接进 `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'"`（009.php:21），随后在 009.php:22 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` 执行。由于 `$id` 被直接放入单引号字符串字面量中，攻击者可闭合引号并注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询），校验逻辑（判断用户是否存在）因此完全失效。代码中未见 mysqli_real_escape_string、预处理语句或类型强制转换等有效净化。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（任意方法）的 SQL 注入 POC。注入点为查询参数 user_id，payload 使用 TARGET 占位符；对应源码 009.php:22 处将外部输入拼接进 SQL 语句。

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

可读取 users 表及同库其他表的数据（用户名、口令哈希、会话令牌等），并可借助 UNION/布尔/时间盲注逐字节提取数据库内容；若数据库账户权限过高，还可能进一步读写文件或影响业务数据完整性。属于未授权即可触发的数据库数据泄露。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `user_id`，无需认证即可访问该脚本路径；利用链闭合：source（009.php:17 的 `user_id`）→ 字符串拼接（009.php:21）→ 危险汇点 `mysqli_query`（009.php:22），中间无有效校验或参数化，攻击者可控输入直达 SQL 解析器。

**修复建议**

改用预处理语句：`$stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `$id` 做整型强制转换（`$id = (int)$_GET['user_id'];`）。若必须动态拼接，使用 `mysqli_real_escape_string` 并配合白名单校验；同时为数据库账户实施最小权限，关闭 FILE 权限。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /009.php?user_id=1' OR '1'='1` → 009.php:17 读取 `user_id` 到 `$id` → 009.php:21 拼接进 `$check_query` 的单引号字面量 → 009.php:22 `mysqli_query` 执行被篡改的 SQL，绕过用户存在性校验并返回任意查询结果。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89（SQL 注入）。漏洞位于 009.php:22，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；如需脚本化请人工替换 TARGET 后在授权环境手动运行，禁止管道自动执行。

### F-2: 009.php 用户详情查询 user_id 参数 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

同一外部输入 `user_id`（009.php:17）在通过存在性检查后，被再次拼接进 `$query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"`（009.php:28），并在 009.php:29 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。`$id` 未做转义或参数化，攻击者可用单引号闭合注入 UNION SELECT 等语句，从 users 表或其他表读取任意列数据。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（任意方法）的 SQL 注入 POC。注入点为查询参数 user_id，payload 使用 TARGET 占位符；对应源码 009.php:29 处的 SQL 拼接点。

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

可直接泄露 users 表的 first_name、last_name、avatar 等字段，并通过 UNION 注入读取任意表（如凭据、令牌）数据，造成敏感信息批量泄露；结合前一处注入可扩大数据提取面。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：HTTP query 参数 `user_id` 无需认证即可提交；利用链闭合：source（009.php:17）→ 拼接（009.php:28）→ 汇点 `mysqli_query`（009.php:29），无有效净化，输入直达 SQL 解析。

**修复建议**

使用预处理语句绑定 `user_id` 为整型参数，例如 `$stmt = $mysqli->prepare('SELECT first_name,last_name,user_id,avatar FROM users WHERE user_id = ?'); $stmt->bind_param('i',$id);`；对输入做 `(int)` 转换与白名单校验；数据库账户最小权限。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `user_id=1' UNION SELECT ...-- -` → 009.php:17 读入 `$id` → 009.php:28 拼接进 `$query` → 009.php:29 `mysqli_query` 执行，返回攻击者指定的查询结果，实现数据泄露。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89（SQL 注入）。漏洞位于 009.php:29，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；禁止管道自动执行。

### F-3: 009.php 日志写入语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.58`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

在日志写入分支中，`$log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')"`（009.php:71-72）将多个变量直接拼接进 SQL，其中 `$target_id` 与 `$ip` 等值可追溯至外部输入（`user_id` 参数及客户端可控的 IP 来源），随后在 009.php:73 由 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。由于 `$target_id` 未加引号且未做类型约束，攻击者可注入任意 SQL 片段（如 `1); DROP/UPDATE ...` 或子查询），`$ip` 位于单引号内亦可闭合注入。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（任意方法）的 SQL 注入 POC。注入点为查询参数 user_id，payload 使用 TARGET 占位符；对应源码 009.php:73 处的 SQL 拼接点。

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

可向 bac_log 表写入伪造记录、篡改或删除日志（掩盖攻击痕迹），并通过子查询/报错注入读取其他表数据；日志完整性被破坏会影响审计与溯源。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：拼接值来源于 HTTP 请求参数与客户端可控字段，无需认证；利用链闭合：source（009.php:17 的 `user_id` 及 IP 相关输入）→ 拼接（009.php:71-72）→ 汇点 `mysqli_query`（009.php:73），无参数化或转义。

**修复建议**

使用预处理语句绑定所有列值：`$stmt = $mysqli->prepare('INSERT INTO bac_log (user_id,target_id,ip_address) VALUES (?,?,?)'); $stmt->bind_param('iis',$current_user_id,$target_id,$ip);`；对 `$target_id`、`$current_user_id` 强制整型转换，对 `$ip` 使用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验；日志表账户限制为仅 INSERT 权限。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者控制 `user_id`（及可伪造的 IP 来源）→ 009.php:17 读入 → 009.php:71-72 拼接进 `$log_query` 的 VALUES 子句 → 009.php:73 `mysqli_query` 执行，注入任意 SQL，篡改日志或读取数据。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89（SQL 注入）。漏洞位于 009.php:73，外部输入来自查询参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；禁止管道自动执行。

### F-4: DVWA 用户资料页通过硬编码 token 绕过访问控制，任意读取他人资料（IDOR/BAC）

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`009.php:13-47`
- **来源**：`llm_finding`

**描述**

009.php 第 13 行从 $_GET 读取 action 与 user_id，第 14 行仅用 /^\d+$/ 校验 user_id 为纯数字，第 26 行用 `$_GET['token'] == 'user_token'` 作为唯一“授权”判断，该 token 为硬编码常量且源码注释（第 39、46 行）直接泄露。攻击者只要带上 token=user_token 并遍历 user_id，即可在第 28-29 行查询并回显任意用户的 first_name/last_name/avatar，完全绕过“当前用户”身份校验（第 7 行查出的 $current_user_id 从未用于比对）。

**source / sink**

- source：query `user_id`（009.php:13）
- sink：009.php:47 009.php:28-29 拼接查询并回显任意用户资料

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:13` | 读取 action 与 user_id 参数 | 外部可控字符串 |  |
| 2 | `009.php:14` | 仅校验 user_id 为纯数字，不校验归属 | 数字字符串，通过校验 |  |
| 3 | `009.php:26` | 硬编码 token 比较，token=user_token 即通过 | 授权被常量绕过 |  |
| 4 | `009.php:28-29` | 按 user_id 查询并回显资料 | 任意用户数据返回 |  |

**POC**

针对 /009.php（GET）的越权/IDOR POC。注入点为 GET 查询参数 user_id，通过替换对象标识访问他人数据；对应源码 009.php:47 处按 user_id 直接取对象且未见归属校验。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`2`
- POC 目录：`poc/LLM-c8fa3f82d085`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意用户可读取全部用户资料，越权访问敏感个人信息

**CVE / CWE 论证**

CWE-639 授权绕过/IDOR；外部 GET 可达，token 硬编码于源码，链闭合

**修复建议**

移除硬编码 token，改为服务端会话身份与目标 user_id 归属校验

**验证说明**

需确认部署环境与 users 表存在；token 常量已在源码可见
模型 POC 要点：带硬编码 token 遍历 user_id 读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /009.php）：符合 CWE-639（通过用户可控键的授权绕过/IDOR）。漏洞位于 009.php:47，外部输入来自查询参数 user_id，直接用于对象定位且给定代码范围内未见归属校验。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；需在授权环境手动运行，禁止管道自动执行。

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
| safety_guard | 安全防护 | 2.98 | 是 |
| surface_mapper | 攻击面测绘 | 7.83 | 是 |
| deep_finder | LLM 深挖 | 8.26 | 是 |
| candidate_screener | 候选筛选 | 7.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.77 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 11.63 | 是 |
| coordinator | 管线协调 | 7.22 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
