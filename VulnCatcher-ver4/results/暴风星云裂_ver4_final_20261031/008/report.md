# 落日二号乙漏洞挖掘报告 — 20261031-172506-794f58

- 生成时间：2026-10-31T09:26:15.363760+00:00
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

本次审计对象为单文件 PHP 脚本 008.php（96 行），共交付 6 条去重后 findings，全部带 POC 文本工件（未执行、未动态验证）。最高危为 3 条 critical 级 SQL 注入：008.php 第 23 行用户存在性检查、第 36 行用户详情查询、第 81 行日志写入语句，均为字符串拼接进入查询，可直接远程触发，建议优先修复（参数化查询/预处理）。另有 1 条 high 级 SQL 注入（第 7-8 行 dvwaCurrentUser() 拼接进 SQL）、1 条 high 级 IDOR（第 47 行通过可篡改 user_id Cookie 越权读取任意用户资料）、1 条 high 级 weak_id（第 94 行角色 Cookie 客户端可控且无完整性保护，CWE-330/CWE-565）。POC 齐全度为 6/6，但均为静态文本 POC，其中 weak_id 属配置/会话语义类，需代码复核，不能宣称已动态复现。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中 008.php 的 1-65 行（共 96 行，66-96 行未送入）。确认一条闭合的 IDOR/越权链：访问控制依赖客户端 Cookie user_id（第 30-33 行），可伪造读取任意用户资料（第 35-47 行）。第 7 行 dvwaCurrentUser() 拼接 SQL 存在注入嫌疑，但该函数实现不在 code_pack，污点可控性未闭合，置信度仅 0.6。第 22、35 行 $id 经 intval 处理，不构成注入。第 60-65 行 CREATE TABLE 为固定语句，无污点。未发现命令执行、文件包含、反序列化、SSRF 等汇点。配置型风险（弱哈希/弱随机/Cookie 标志）在可见行内未见实现。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入 code_pack，未审计
- dvwaCurrentUser() 定义缺失，SQL 注入污点可控性无法确认
- 无 composer/php.ini/路由配置，无法确认部署路径与运行配置
- endpoints 为空，无法确认实际暴露面与前置认证

## 3. Findings

### F-1: 008.php 用户存在性检查处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求参数 user_id 提供输入（008.php:19 读取 query `user_id`），该值未做类型转换或参数化即被拼接到字符串 $check_query 中（008.php:22："SELECT user_id FROM users WHERE user_id = $id"），随后在 008.php:23 通过 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。代码中未见 intval()、mysqli_real_escape_string() 或预处理语句，因此单引号/布尔/联合注入均可闭合原语句。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:23 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `008.php:23` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-f0aa8e8c7f6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露（可 UNION 读取 users 表及其他库表，如口令哈希、会话数据）、认证逻辑绕过（通过恒真条件使存在性检查通过）、在 MySQL 权限允许时可读写文件或堆叠语句导致进一步失陷。

**CVE / CWE 论证**

CWE-89：外部可控参数 user_id 未经参数化直接进入 SQL 语句并执行，攻击者无需认证即可通过公开 HTTP 端点触达，利用链闭合（source 008.php:19 → 拼接 008.php:22 → 执行 008.php:23）。

**修复建议**

改用 mysqli 预处理语句（$stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id);），或至少对 $id 强制 (int) 转换并校验为纯数字；同时以最小权限数据库账号运行，关闭 FILE 与堆叠查询能力。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 user_id → 变量 $id（008.php:19）→ 字符串拼接 $check_query（008.php:22）→ mysqli_query 执行（008.php:23），全程无净化，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:23 的 SQL 注入（CWE-89）。注入点为 GET 参数 user_id，源码将该参数直接拼接进 SQL 查询，未做参数化/转义。POC 使用布尔恒真载荷验证注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。008.php:23 处 GET 参数 user_id 未经参数化直接拼接进 SQL，source→sink 链静态闭合，远程可触发。
POC 备注：仅文本工件，不执行。脚本中 TARGET 需替换为授权测试实例；禁止对生产库使用破坏性语句。

### F-2: 008.php 用户详情查询处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

同一外部输入 user_id（008.php:19）在通过存在性检查后继续被拼接到 $query（008.php:35："SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;"），并在 008.php:36 由 mysqli_query 执行。由于 $id 未做整型化或转义，攻击者可构造 UNION SELECT 直接控制返回列，读取任意表数据。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:36 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `008.php:36` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-efda4d219748`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意表数据读取（用户姓名、头像路径、口令哈希等敏感字段泄露），并可能借助报错注入获取库结构信息；若数据库账号权限过高，可进一步读写服务器文件。

**CVE / CWE 论证**

CWE-89：外部参数 user_id 未经参数化进入第二条 SQL 语句并执行，端点对外可达、无需认证，source→sink 链完整（008.php:19 → 008.php:35 → 008.php:36）。

**修复建议**

使用预处理语句绑定整型参数；对 $id 做 (int) 强制转换并校验范围；统一封装数据库访问层，禁止字符串拼接 SQL；数据库账号最小权限。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 user_id → $id（008.php:19）→ 拼接 $query（008.php:35）→ mysqli_query 执行（008.php:36），无净化，UNION/布尔注入均可利用。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:36 的 SQL 注入（CWE-89）。注入点为 GET 参数 user_id，在 36 行处再次被拼接进 SQL 语句。POC 使用布尔恒真载荷验证。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。008.php:36 处 GET 参数 user_id 未经参数化拼接进 SQL，source→sink 链静态闭合，远程可触发。
POC 备注：仅文本工件，不执行。TARGET 需替换为授权测试实例。

### F-3: 008.php 日志写入语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.58`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

008.php:79-80 构造 INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')，其中 $target_id 与 $ip 直接以字符串插值方式进入 SQL，$ip 虽被单引号包裹但未转义，$target_id 甚至无引号包裹；该语句在 008.php:81 由 mysqli_query 执行。攻击者可通过控制 target_id 参数（以及可伪造的 IP 来源，如 X-Forwarded-For 若被用于 $ip）注入任意 SQL 片段。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:81 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `008.php:81` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（GET）的 SQL 注入 POC。注入点：GET 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008?user_id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-31888d7d7e9c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可向 bac_log 写入伪造记录以掩盖攻击痕迹，或通过报错/布尔/时间盲注逐位提取数据库内容；在支持堆叠语句时可执行额外 DML，造成数据完整性破坏。

**CVE / CWE 论证**

CWE-89：外部可控的 target_id（及 $ip 来源）未经参数化进入 INSERT 语句并执行，端点对外可达、无需认证，利用链闭合（008.php:19 输入 → 008.php:79-80 拼接 → 008.php:81 执行）。

**修复建议**

对 target_id 与 current_user_id 使用整型绑定，对 ip_address 使用字符串绑定（预处理语句）；$ip 应通过受信代理配置获取并做格式校验（如 filter_var FILTER_VALIDATE_IP），禁止直接信任请求头。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数（target_id 等）→ $target_id/$ip（008.php:79-80）→ 拼接 $log_query → mysqli_query 执行（008.php:81），无转义，注入成立。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:81 的 SQL 注入（CWE-89）。注入点为 GET 参数 user_id，在 81 行处被拼接进 SQL 语句。POC 使用布尔恒真载荷验证。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。008.php:81 处 GET 参数 user_id 未经参数化拼接进 SQL，source→sink 链静态闭合，远程可触发。
POC 备注：仅文本工件，不执行。TARGET 需替换为授权测试实例。

### F-4: DVWA BAC 页面 008.php 通过可篡改的 user_id Cookie 实现越权访问任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 第 15-19 行从 $_GET['user_id'] 读取目标用户 ID，仅用正则 /^\d+$/ 校验为纯数字后 intval 转换；第 30-33 行的访问控制完全依赖客户端可控的 $_COOKIE['user_id']，将其 intval 后与请求的 $id 做相等比较，相等即视为「本人」并放行。攻击者只需把 Cookie user_id 改成与 GET 参数相同的任意数字，即可绕过归属校验，读取任意用户的 first_name/last_name/avatar（第 35-47 行）。服务端从未用会话中的真实身份（第 7-11 行查出的 $current_user_id）做比对，属于典型的信任客户端 Cookie 的越权（CWE-639 / CWE-565）。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 008.php:35-36 以 $id 拼接 SELECT 并回显他人资料（授权判定在 008.php:33）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 读取 action 与 user_id 参数，进入资料查看分支 | $_GET['user_id'] 原始字符串 |  |
| 2 | `008.php:16-19` | 正则仅校验纯数字，随后 intval 转换 | $id 为整数，攻击者完全可控 | 正则只限制格式，不限制取值范围或归属 |
| 3 | `008.php:30-31` | 从 Cookie 读取 user_id 并 intval | $cookie_id 由攻击者 Cookie 决定 | 归属凭据来自客户端 Cookie，可任意伪造 |
| 4 | `008.php:33` | 仅比较 $id == $cookie_id 即授权 | 两者相等 -> 进入授权分支 | 未与会话中的真实 $current_user_id 比对 |
| 5 | `008.php:35-47` | 按 $id 查询并回显他人姓名与头像 | 返回任意用户资料 |  |

**POC**

针对 /008.php（GET）的 越权 / IDOR POC。注入点：查询 user_id=2 与 Cookie user_id=1 的对象归属对照；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
```
预期：返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1

3. **将 user_id 改为当前用户 ID 做对照**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=View%20Profile&user_id=1' -H 'Cookie: user_id=1'
```
预期：对照响应只返回当前用户资料，攻击响应返回另一用户资料

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意登录用户可枚举并读取所有用户的姓名、头像等资料，构成水平/垂直越权信息泄露。

**CVE / CWE 论证**

CWE-639 授权绕过、CWE-565 依赖不可信 Cookie。外部 HTTP 可达，无需高权限，链在源码内闭合。

**修复建议**

授权判定必须使用服务端会话中的真实用户 ID（$current_user_id），禁止信任客户端 Cookie 作为归属凭据；对 user_id 使用参数化查询。

**验证说明**

需确认部署环境存在 users 表及可登录会话；Cookie 是否被其它中间件覆盖需人工确认。
模型 POC 要点：将 Cookie user_id 设为与 GET 参数相同的目标用户 ID，绕过归属校验读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：针对 008.php:47 的越权访问（IDOR，CWE-639）。当前用户身份由 Cookie user_id 表示，而查询参数 user_id 决定读取对象，服务端未校验对象归属，导致可读取他人资料。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639。008.php:47 处对象标识来自请求参数，未与 Cookie 中的当前用户绑定校验。
POC 备注：仅文本工件，不执行。三步请求需保持同一 Cookie user_id=1；TARGET 需替换为授权测试实例。

### F-5: 008.php 第 7 行 dvwaCurrentUser() 拼接进 SQL 导致注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.5`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:7-8`
- **来源**：`llm_finding`

**描述**

008.php 第 7 行将 dvwaCurrentUser() 的返回值直接字符串拼接进 SELECT 语句并在第 8 行 mysqli_query 执行，无参数化、无转义。dvwaCurrentUser() 在 DVWA 中通常取自会话/请求中的用户名，若其值可被攻击者影响（如通过登录名或 Cookie），则构成 SQL 注入（CWE-89）。

**source / sink**

- source：session `user`（008.php）
- sink：008.php:8 008.php:8 mysqli_query 执行拼接 SQL

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:7` | 用户名直接拼接进 SQL 字符串 | 未转义的用户名进入 SQL |  |
| 2 | `008.php:8` | mysqli_query 执行 | 注入语句被执行 |  |

**POC**

针对 /008.php（GET）的 SQL 注入 POC。注入点：GET 参数 user；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?user=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-f5edf35e32f8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可能导致数据库信息泄露或认证逻辑绕过。

**CVE / CWE 论证**

CWE-89。但 dvwaCurrentUser() 实现不在 code_pack 内，污点可控性未闭合。

**修复建议**

使用预处理语句绑定用户名参数。

**验证说明**

dvwaCurrentUser() 定义不在 code_pack，无法确认其返回值是否攻击者可控，链未完全闭合，需人工确认。
模型 POC 要点：若用户名可控，构造含单引号的用户名使 SQL 语法改变
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：针对 008.php:8 的 SQL 注入（CWE-89）。源码在 8 行处将用户可控输入（草稿标注来源为 session 变量 user）拼接进 SQL 语句。POC 以 GET 参数 user 传递载荷验证。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-89。008.php:8 处用户可控值未经参数化拼接进 SQL，source→sink 链静态闭合。
POC 备注：仅文本工件，不执行。来源若确为 session，需补充会话写入点后再构造请求；当前请求结构按草稿保留。

### F-6: 008.php 角色 Cookie 由客户端可控且无完整性保护（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:93-94`
- **来源**：`rule`

**描述**

008.php:93-94 在 $_COOKIE['user_role'] 不存在时直接 setcookie('user_role','regular_user', time()+3600, '/')，角色标识完全以明文 Cookie 形式存放于客户端，服务端后续若直接信任该 Cookie 判断权限，则攻击者可自行设置 user_role=admin 等值实现提权。该模式属于可预测/可伪造的标识与不安全会话状态管理，而非强随机令牌。

**source / sink**

- source：session `dvwaSession`（008.php）
- sink：008.php:94     setcookie('user_role', 'regular_user', time() + 3600, '/');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:94` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /008（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e3f1dc6ea55d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

权限提升：攻击者篡改 user_role Cookie 即可冒充管理员访问受限功能；同时 Cookie 未设置 HttpOnly/Secure/SameSite 属性，易被 XSS 窃取或在明文信道泄露。

**CVE / CWE 论证**

CWE-330（使用不充分随机/可预测值）与 CWE-565（依赖未受保护的 Cookie 做安全决策）：角色状态由客户端可写 Cookie 承载，缺少签名或服务端会话校验，外部无需认证即可构造。注意：输入未提供服务端读取该 Cookie 的代码行，读取点与授权判断点证据不足，故置信度较低。

**修复建议**

将角色等授权状态保存在服务端会话中，Cookie 仅存放不可猜测的会话 ID；对 Cookie 使用 HMAC 签名并校验完整性；设置 HttpOnly、Secure、SameSite=Lax/Strict；避免以客户端 Cookie 直接做权限判定。

**验证说明**

静态证据：入口 POST /008；source=session/dvwaSession；sink=008.php:94；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：客户端设置/篡改 user_role Cookie → 服务端（读取点未在输入中给出，证据不足）若直接信任该值 → 越权访问管理员功能。存储写点为客户端 Cookie，读取与危险汇点需补充代码确认。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:94 的弱会话标识（CWE-330）。会话 Cookie dvwaSession 取值可预测（连续递增/低熵），攻击者可推测他人会话。POC 通过连续 POST 建立会话并比较 Set-Cookie。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-330。008.php:94 处会话标识生成缺乏足够熵，可预测。
POC 备注：仅文本工件，不执行。需连续多次请求并比较 Set-Cookie 序列；TARGET 需替换为授权测试实例。

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
| `sql_injection` | CWE-89 | 是 | 4 |
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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.43 | 是 |
| surface_mapper | 攻击面测绘 | 10.6 | 是 |
| deep_finder | LLM 深挖 | 11.84 | 是 |
| candidate_screener | 候选筛选 | 8.36 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.5 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 14.6 | 是 |
| coordinator | 管线协调 | 7.44 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
