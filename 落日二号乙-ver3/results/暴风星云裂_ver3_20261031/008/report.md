# 落日二号乙漏洞挖掘报告 — 20261031-005748-5c5a2e

- 生成时间：2026-10-30T16:58:46.508732+00:00
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

本次汇总基于单文件 PHP 脚本 008.php（96 行）的静态源码审计，共去重后交付 5 条 findings：3 条 critical 级 SQL 注入（GEN-f0aa8e8c7f6b 用户存在性检查、GEN-efda4d219748 用户信息查询、GEN-31888d7d7e9c 日志写入，均位于 008.php，CWE-89）、1 条 high 级 IDOR（LLM-be8d58eeb7fa，通过可篡改的 user_id Cookie 越权访问任意用户资料，008.php 第 47 行附近）、1 条 medium 级存储型 XSS（LLM-3ee4fdec5d75，用户资料字段未转义直接输出，008.php 第 47 行附近）。最高危为 008.php 中三处字符串拼接式 SQL 注入，其中日志写入点（第 81 行附近）同时构成二次注入的存储写点，风险叠加。5 条 findings 均标注 has_poc=true，POC 文本齐全；但需注意这些 POC 均为基于源码静态推断的文本工件，未做动态验证，SQL 注入 POC 不含 DROP 等破坏性语句，目标统一使用 TARGET 占位符，仅限授权测试。IDOR 与 XSS 的 POC 属 HTTP 语义可复现类型，SQL 注入 POC 亦为 HTTP 请求形态，但均未经运行时确认。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 008.php 第 1-65 行（共 96 行，66-96 行未送入）。确认两条链：1) 基于可篡改 Cookie 的 IDOR 越权读取任意用户资料（高）；2) 资料字段未转义输出的存储型 XSS（中，写点不在包内）。第 7 行 dvwaCurrentUser() 拼接进 SQL，但该函数实现不在 CODE PACK，无法确认是否可控，未报告 SQL 注入。第 60-65 行建表逻辑与后续 66-96 行未覆盖。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入
- dvwaCurrentUser() 实现未知，无法判定第 7 行 SQL 注入
- 资料字段写入入口不在 CODE PACK
- 无服务器配置/认证机制信息

## 3. Findings

### F-1: 008.php 用户存在性检查处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `user_id`（008.php:19 读取）传入恶意字符串，该值被直接拼接到 `$check_query = "SELECT user_id FROM users WHERE user_id = $id"`（008.php:22），随后在 008.php:23 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $check_query)` 执行。代码未对该参数做类型转换（如 intval）、未使用 mysqli 预处理/参数绑定、也未做白名单校验，因此 `$id` 中的引号、`OR 1=1`、`UNION SELECT`、子查询等均可改变 SQL 语义。该查询位于用户存在性检查分支，是后续授权判断的前置逻辑，注入结果会直接影响程序走向。

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

可读取 users 表及其他库表数据（如凭据、个人信息），可绕过存在性/授权判断，配合后续查询可进一步枚举或篡改数据；在数据库权限较高时可导致全库数据泄露。属于未认证远程可利用的 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `user_id`，无需认证即可到达 008.php:19-23；利用链闭合：source（query `user_id`）→ 字符串拼接（008.php:22）→ mysqli_query 执行（008.php:23），中间无有效净化，符合 CWE-89 的完整污点链。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id);`；若业务上 user_id 必为整数，先做 `$id = (int)$_GET['user_id']` 强制类型转换并校验范围；同时遵循最小权限原则，为应用数据库账号仅授予必要表的 SELECT/INSERT 权限。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?user_id=1 OR 1=1`（或 `1 UNION SELECT ...`）→ 008.php:19 读取 query `user_id` 赋给 `$id` → 008.php:22 直接拼接进 `$check_query` → 008.php:23 `mysqli_query` 执行被篡改的 SQL → 返回攻击者控制的结果集，影响存在性判断并泄露数据。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:23 的 SQL 注入 POC。外部输入来自查询参数 user_id，被直接拼接进 SQL 语句执行，未做参数化或有效转义。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:23，source 为查询参数 user_id，sink 为 SQL 执行，静态链闭合且未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权实例地址；建议先做基线对比再判定。

### F-2: 008.php 用户信息查询处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

同一外部输入 query 参数 `user_id`（008.php:19）在通过存在性检查后，被拼接到 `$query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;"`（008.php:35），并在 008.php:36 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。该处同样未做整数转换、未参数化、未过滤，`$id` 中的 SQL 片段可注入。由于该查询位于“Access granted”分支，攻击者可通过注入使前置检查通过后在此处执行任意 SELECT 表达式。

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

可泄露 users 表的 first_name、last_name、user_id、avatar 等字段，并可通过 UNION/子查询读取其他表数据；结合 avatar 等字段可能进一步用于社工或后续攻击。未认证远程可利用。

**CVE / CWE 论证**

CWE-89。外部可达性：HTTP query 参数 `user_id` 无需认证即可到达 008.php:19；利用链闭合：source（query `user_id`）→ 拼接（008.php:35）→ mysqli_query（008.php:36），无有效净化。

**修复建议**

使用预处理语句绑定整型参数（`bind_param('i', $id)`）；对 `user_id` 做 `(int)` 强制转换与合法性校验；禁止将外部输入直接插入 SQL 字符串；数据库账号最小权限。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 `?user_id=1 UNION SELECT ...` → 008.php:19 读取 `$id` → 前置检查（008.php:22-23）被构造为通过 → 008.php:35 拼接进 `$query` → 008.php:36 执行，返回攻击者指定的数据列，造成数据泄露。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:36 的 SQL 注入 POC。外部输入来自查询参数 user_id，在 008.php:36 处被拼入 SQL 语句，未参数化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:36，source 为查询参数 user_id，sink 为 SQL 执行，静态链闭合且未见有效净化。
POC 备注：文本工件，不执行。将 TARGET 替换为授权实例；以基线对比判定。

### F-3: 008.php 日志写入处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

008.php:79-80 构造 `$log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')"`，并在 008.php:81 由 `mysqli_query($GLOBALS["___mysqli_ston"], $log_query)` 执行。其中 `$target_id` 与 `$current_user_id` 来源于同一外部 query 参数 `user_id`（008.php:19）派生，`$ip` 为客户端可影响的地址值，均以字符串拼接方式进入 INSERT 语句，未参数化、未转义。攻击者可在 `user_id` 中注入闭合 VALUES 的片段，改写 INSERT 语义。

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

可向 bac_log 表写入伪造记录（日志污染/审计绕过），并可通过报错注入或基于 INSERT 的子查询实现数据外带；若数据库权限允许，还可能借助堆叠/子查询影响其他表。未认证远程可利用。

**CVE / CWE 论证**

CWE-89。外部可达性：注入源为 HTTP query 参数 `user_id`（008.php:19），无需认证；利用链闭合：source → 拼接（008.php:79-80）→ mysqli_query（008.php:81），无有效净化。

**修复建议**

对 INSERT 使用预处理语句并绑定 `user_id`、`target_id`、`ip_address` 参数；对 `user_id`/`target_id` 做整型转换，对 `$ip` 使用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验或参数绑定；限制数据库账号对 bac_log 的写权限范围。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交含 SQL 片段的 `user_id` → 008.php:19 读取并派生 `$current_user_id`/`$target_id` → 008.php:79-80 拼接进 `$log_query` → 008.php:81 执行，篡改 INSERT 或触发报错注入外带数据。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:81 的 SQL 注入 POC。外部输入来自查询参数 user_id，在 008.php:81 处被拼入 SQL 语句，未参数化。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:81，source 为查询参数 user_id，sink 为 SQL 执行，静态链闭合且未见有效净化。
POC 备注：文本工件，不执行。将 TARGET 替换为授权实例；以基线对比判定。

### F-4: DVWA BAC 页面通过可篡改的 user_id Cookie 实现越权访问任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 的访问控制完全依赖客户端 Cookie `user_id`：第 30-33 行读取 `$_COOKIE['user_id']` 并与请求参数 `$_GET['user_id']` 比较，相等即放行第 35-47 行的资料查询与输出。攻击者只需同时把 Cookie 与查询参数设为同一目标用户 ID，即可绕过“只能查看自己资料”的限制，读取任意用户的 first_name/last_name/avatar。服务端从未用会话中的真实身份（第 7-11 行查出的 $current_user_id）做归属校验，属于典型的信任客户端可控数据导致的 IDOR/越权。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 mysqli_query 查询任意 user_id 的资料并输出到页面（008.php:35-47）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 读取 GET 参数 action 与 user_id | 攻击者完全可控 |  |
| 2 | `008.php:16-19` | 仅用正则 ^\d+$ 校验 user_id 为数字，随后 intval 转换 | 纯数字，无归属校验 | 正则只限制格式，不限制取值，任意用户 ID 均通过 |
| 3 | `008.php:30-33` | 读取 Cookie user_id 并与 GET user_id 比较，相等即授权 | 两个值均由攻击者控制 | 授权判断基于客户端 Cookie，攻击者可任意设置使其相等 |
| 4 | `008.php:35-47` | 以 $id 查询并输出目标用户资料 | 目标用户 ID 进入 SQL 并回显 |  |

**POC**

针对 /008.php（GET）的 越权 / IDOR POC。注入点：Cookie: user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php' \
  -H 'Cookie: user_id=2'
```
预期：使用其他对象 ID 返回他人数据或执行他人操作。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意登录/未登录用户可越权读取其他用户资料（姓名、头像等），破坏访问控制。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）：授权依据为客户端 Cookie，外部可直接构造，链闭合。

**修复建议**

使用服务端会话中的真实用户 ID 做归属校验，禁止信任客户端 Cookie 决定权限。

**验证说明**

需确认部署环境是否要求登录；DVWA 场景下通常低权限即可。
模型 POC 要点：将 Cookie 与参数设为同一目标用户 ID，读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：针对 008.php:47 的越权/IDOR POC。应用从 Cookie user_id 读取当前用户标识并据此查询/展示用户资料，未校验该标识是否属于当前会话，攻击者修改 Cookie 即可访问他人资料。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639。漏洞位于 008.php:47，source 为 Cookie user_id，sink 为用户资料查询/渲染，未见归属校验。
POC 备注：文本工件，不执行。将 TARGET 替换为授权实例；对比不同 user_id 的返回内容判定越权。

### F-5: 008.php 用户资料字段未转义直接输出导致存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:40-47`
- **来源**：`llm_finding`

**描述**

第 40-47 行将数据库中的 first_name/last_name/avatar 直接拼接进 HTML 输出，未做 htmlspecialchars 转义。若攻击者能控制自身资料字段（如注册/编辑资料处写入脚本），则查看该资料的用户（含管理员）会触发存储型 XSS。

**source / sink**

- source：repository `first_name/last_name/avatar`（008.php）
- sink：008.php:47 字符串拼接进 $html 后输出（008.php:40-47）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:35-39` | 从 users 表取出资料字段 | 存储的用户可控数据 |  |
| 2 | `008.php:40-47` | 未转义拼接进 HTML 输出 | 原样输出到页面 | 无 htmlspecialchars 等编码 |

**POC**

针对 008.php:47 的存储型/反射型 XSS 候选 POC。008.php:47 处将数据库字段（user_id、first_name、last_name、avatar）直接拼接进 HTML 输出，未做 HTML 编码。若这些字段可由用户写入（如资料编辑），则构成存储型 XSS；若来自可控输入则构成反射型。目标地址使用 TARGET 占位符，仅限授权测试。

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
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /008.php, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

可窃取查看者会话或执行敏感操作。

**CVE / CWE 论证**

CWE-79 存储型 XSS；但写入点不在本 CODE PACK 内，链部分依赖外部入口。

**修复建议**

输出前对 first_name/last_name/avatar 使用 htmlspecialchars 转义。

**验证说明**

存储写点不在 CODE PACK，需确认资料字段可由攻击者写入。
模型 POC 要点：在资料字段写入脚本，受害者查看时执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：文本工件，不执行。将 TARGET 替换为授权实例；若不存在资料写入入口，则按反射型验证（将 payload 放入被回显的参数）。

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
| safety_guard | 安全防护 | 1.98 | 是 |
| surface_mapper | 攻击面测绘 | 9.44 | 是 |
| deep_finder | LLM 深挖 | 9.3 | 是 |
| candidate_screener | 候选筛选 | 7.35 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.83 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 11.75 | 是 |
| coordinator | 管线协调 | 8.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
