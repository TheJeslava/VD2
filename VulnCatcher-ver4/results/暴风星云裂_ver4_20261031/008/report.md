# 落日二号乙漏洞挖掘报告 — 20261031-163924-372531

- 生成时间：2026-10-31T08:40:24.832438+00:00
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

本次审计对象为单文件 PHP 脚本 008.php（96 行），共交付 5 条已去重发现：3 条 critical 级 SQL 注入（GEN-f0aa8e8c7f6b 用户存在性检查、GEN-efda4d219748 用户信息查询、GEN-31888d7d7e9c 日志写入语句，均位于 008.php，CWE-89），1 条 high 级 IDOR（LLM-be8d58eeb7fa，通过可篡改的 user_id Cookie 越权读取任意用户资料，008.php 第 47 行附近），1 条 high 级 weak_id（SEM-e3f1dc6ea55d，基于固定值的 user_role Cookie 权限标识，CWE-330/CWE-565，008.php 第 94 行附近）。最高危为三处 SQL 注入：参数从第 12 行附近入口几乎无净化直达 SQL 汇点，可导致数据库读取/篡改与认证绕过。5 条发现均带 POC 文本（has_poc=true），但均为静态构造的 HTTP 请求 POC，未做动态验证；weak_id 属配置/实现类证据，其 POC 为静态证据型，不能宣称可动态复现。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 008.php 的 1-65 行（共 96 行，66-96 行未送入）。发现一条闭合的水平越权链：授权判断依赖可篡改的 Cookie user_id（第 30-33 行），导致任意用户资料读取（第 35-47 行）。第 7 行 dvwaCurrentUser() 拼接 SQL 属框架内部函数，未在 code_pack 中给出实现，无法确认注入，未报告。第 60-65 行 bac_log 建表逻辑及 66-96 行未覆盖，可能存在其他问题但证据不足。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入 code_pack
- dvwaCurrentUser() 实现未知，第 7 行 SQL 拼接是否可注入无法确认
- 无认证/会话配置信息，无法确认匿名可达性

## 3. Findings

### F-1: 008.php 用户存在性检查处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 查询参数 user_id 提供输入，在 008.php:19 被读取并赋给 $id；该值未经任何转义或类型强制（无 intval、无 mysqli_real_escape_string、无预处理绑定）直接拼接进 008.php:22 的 SQL 字符串 "SELECT user_id FROM users WHERE user_id = $id"，随后在 008.php:23 由 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。由于 $id 处于数值上下文且无引号包裹，攻击者可提交如 1 OR 1=1、1 UNION SELECT ... 或基于布尔/时间的盲注载荷改变查询语义。校验无效的原因是该路径完全没有参数化或白名单化处理。

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

数据库查询逻辑可被任意篡改：可绕过用户存在性判断、通过 UNION 读取 users 表及其他表的任意列（如口令哈希、邮箱），并可结合报错/时间盲注逐字节提取数据；若数据库账户权限过高还可能写入文件或执行堆叠语句，导致敏感数据泄露与认证逻辑绕过。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP 查询参数 user_id，无需认证即可访问该脚本路径；利用链闭合：008.php:19 取值 → 008.php:22 字符串拼接 → 008.php:23 mysqli_query 执行，中间无净化函数，属典型一次注入。

**修复建议**

改用预处理语句并绑定参数，例如 $stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); 同时对 $id 做 intval() 强制类型转换与正整数白名单校验；数据库账户遵循最小权限，禁用 FILE 与堆叠查询。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 008.php?user_id=1 OR 1=1 → 008.php:19 读取参数赋给 $id → 008.php:22 拼接为 SELECT user_id FROM users WHERE user_id = 1 OR 1=1 → 008.php:23 mysqli_query 执行，返回全部用户，绕过存在性校验。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:23 的 SQL 注入 POC。注入点为 GET 参数 user_id，该参数被直接拼接进 SQL 查询；payload 使用 TARGET 占位符，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:23，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义净化，具备远程触发条件。
POC 备注：仅保留文本请求结构，不执行；TARGET 需替换为授权目标。禁止使用 DROP 等破坏性语句。

### F-2: 008.php 用户信息查询处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

同一外部输入 user_id 在 008.php:19 被读入 $id 后，于 008.php:35 被直接拼接进 "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;"，并在 008.php:36 通过 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。该语句位于“Access granted”分支内，说明前置检查可被同一注入点绕过（见 GEN-f0aa8e8c7f6b），从而直接进入此查询。$id 无引号包裹、无转义、无类型转换，攻击者可注入 UNION SELECT 读取任意表列。

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

可越权读取 users 表及其他表的任意字段（姓名、头像路径、口令哈希等），造成敏感数据泄露；结合前一处注入可完全绕过访问控制分支，使未授权用户获得“Access granted”路径的数据返回。

**CVE / CWE 论证**

CWE-89。外部可达性：HTTP 查询参数 user_id，无需认证；利用链闭合：008.php:19 → 008.php:35 拼接 → 008.php:36 mysqli_query，无净化。与前一 finding 为同一污点源在不同汇点的独立注入面。

**修复建议**

使用预处理语句绑定整型参数（bind_param('i', $id)），并对 $id 做 intval() 与范围校验；避免将用户输入直接内插到 SQL 文本；对返回字段做最小化授权。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 user_id=1 UNION SELECT username,password,1,1 FROM users → 008.php:19 读入 $id → 008.php:35 拼接查询 → 008.php:36 执行并回显结果，泄露凭据数据。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:36 的 SQL 注入 POC。注入点为 GET 参数 user_id，该处查询同样将外部输入拼接进 SQL；payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:36，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行；TARGET 为占位符。禁止破坏性 SQL 语句。

### F-3: 008.php 日志写入语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

008.php:79-80 构造 INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')，其中 {$target_id} 与 {$ip} 均以字符串内插方式进入 SQL，且 $ip 仅用单引号包裹而无转义。$target_id 来源于同一外部 user_id 输入链路（008.php:19 的 $id 派生），$ip 通常取自 REMOTE_ADDR 等请求上下文。由于缺少 mysqli_real_escape_string 或参数绑定，攻击者可通过 target_id 注入数值型载荷，或通过可伪造的 IP 来源（如代理头）注入引号闭合载荷，在 008.php:81 的 mysqli_query 执行时改变语句语义。

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

可向 bac_log 表写入伪造记录、通过子查询/UNION 读取其他表数据，或利用报错注入提取信息；日志表被污染还会影响后续审计与基于日志的安全判断，造成审计数据完整性与机密性受损。

**CVE / CWE 论证**

CWE-89。外部可达性：target_id 源自 HTTP 参数 user_id 链路，ip 源自请求上下文，均无需认证；利用链闭合：008.php:19 → 008.php:79-80 拼接 → 008.php:81 mysqli_query，无净化。

**修复建议**

对 INSERT 使用预处理语句并绑定 (user_id, target_id, ip_address) 三个参数；$target_id 强制 intval()，$ip 使用 filter_var($ip, FILTER_VALIDATE_IP) 校验后再绑定；不要信任 X-Forwarded-For 等可伪造头。

**验证说明**

静态证据：入口 GET /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 user_id=1); INSERT/子查询载荷 → 008.php:19 读入并派生 $target_id → 008.php:79-80 拼接进 INSERT 语句 → 008.php:81 执行，污染日志表或借子查询外带数据。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:81 的 SQL 注入 POC。注入点为 GET 参数 user_id，该行附近查询将外部输入拼入 SQL；payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于 008.php:81，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行；TARGET 为占位符。禁止破坏性 SQL 语句。

### F-4: DVWA BAC 页面通过可篡改的 user_id Cookie 实现越权访问任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-47`
- **来源**：`llm_finding`

**描述**

008.php 在读取用户资料前，仅将客户端 Cookie `user_id` 与请求参数 `user_id` 做相等比较（第 30-33 行），而 Cookie 完全由攻击者控制。攻击者只需把 Cookie `user_id` 设置为目标用户 ID，并请求相同的 `user_id` 参数，即可通过 `$id == $cookie_id` 校验，读取任意用户的 first_name/last_name/avatar（第 35-47 行）。服务端从未校验当前登录会话与目标用户 ID 的归属关系，属于典型的水平越权（IDOR）。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:47 mysqli_query 查询 users 表并回显 first_name/last_name/avatar

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 入口读取 GET 参数 action 与 user_id | 外部可控字符串 |  |
| 2 | `008.php:16-19` | preg_match 仅校验 user_id 为纯数字，随后 intval 转换 | 整数型 user_id | 数字格式校验不限制取值范围，任意用户 ID 均通过 |
| 3 | `008.php:30-33` | 读取 Cookie user_id 并与参数比较，二者均由攻击者控制 | 攻击者令 cookie_id == id | 授权判断依据是客户端 Cookie，而非服务端会话身份 |
| 4 | `008.php:35-47` | 以 $id 查询并回显目标用户资料 | 目标用户敏感字段输出到页面 |  |

**POC**

针对 /008.php?action=view&user_id=<id>（GET）的 越权 / IDOR POC。注入点：查询 user_id=2 与 Cookie user_id=1 的对象归属对照；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008.php?action=view&user_id=<id>'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=view&user_id=<id>&action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
```
预期：返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1

3. **将 user_id 改为当前用户 ID 做对照**

```http
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=view&user_id=<id>&action=View%20Profile&user_id=1' -H 'Cookie: user_id=1'
```
预期：对照响应只返回当前用户资料，攻击响应返回另一用户资料

- payload：`2`
- POC 目录：`poc/LLM-be8d58eeb7fa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意已认证用户可读取全部用户的名字、姓氏、头像等资料，造成水平越权与隐私泄露。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）。外部 HTTP 可达，仅需低权限账户，授权判断依赖客户端 Cookie，链路闭合。

**修复建议**

授权判断必须基于服务端会话中的当前用户 ID（如 $current_user_id），禁止使用客户端 Cookie 作为身份依据；对目标资源做归属校验。

**验证说明**

需确认 DVWA 会话中 $current_user_id 与 Cookie 的实际关系；动态验证越权读取是否成功。
模型 POC 要点：将 Cookie user_id 设为受害者 ID，同时请求相同 user_id 参数，绕过归属校验读取他人资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php?action=view&user_id=<id>）：针对 008.php:47 的越权/IDOR POC。服务端以 Cookie user_id 标识当前用户，但查询参数 user_id 决定读取对象，未做归属校验；通过将查询 user_id 改为他人 ID 读取他人资料。
PocWriter 建议（未采纳，缺少端点 /008.php?action=view&user_id=<id>）：符合 CWE-639。漏洞位于 008.php:47，外部输入来自查询参数 user_id 与 Cookie user_id，服务端未校验对象归属，具备远程触发条件。
POC 备注：仅文本工件，不执行；TARGET 为占位符。原始 endpoint 中重复的 action/user_id 参数已整理为单一参数，注入通道（查询 user_id 与 Cookie user_id）保持不变。

### F-5: 008.php 基于固定值的 user_role Cookie 权限标识（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:93-94`
- **来源**：`rule`

**描述**

008.php:93-94 在 $_COOKIE['user_role'] 未设置时，通过 setcookie('user_role', 'regular_user', time() + 3600, '/') 下发角色标识。该 Cookie 的值为硬编码常量 'regular_user'，不含任何随机性或服务端签名，且后续逻辑显然以该 Cookie 作为角色判断依据。攻击者可自行构造 user_role=admin 之类的值直接提交，服务端无法区分合法下发与伪造值。候选将其归类为“弱 ID/可预测会话标识”，但代码证据显示问题实质是角色标识可预测且缺乏完整性保护（CWE-330 可预测值 + CWE-565 依赖不可信 Cookie），而非时间派生会话 ID。

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
curl -sS -i -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -X POST 'http://TARGET:8080/008' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现 1、2、3 等递增/可预测序列，或可重放访问

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e3f1dc6ea55d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可通过修改 user_role Cookie 提升为管理员等高权限角色，实现水平/垂直越权，访问本应受限的功能与数据；由于无签名校验，任何客户端均可任意设定角色。

**CVE / CWE 论证**

CWE-330（使用不充分的随机值）/CWE-565（依赖 Cookie 而未验证完整性）。外部可达性：Cookie 由客户端完全可控，无需认证即可伪造；配置/实现型弱点，不依赖 source→sink 污点链，证据为 008.php:93-94 的 setcookie 硬编码值与缺失签名。

**修复建议**

不要在客户端 Cookie 中存放可决定权限的角色值；角色应保存在服务端会话中并以服务端状态为准。若必须使用 Cookie，需使用 HMAC 签名并校验完整性，设置 HttpOnly、Secure、SameSite 属性，并对每次请求做服务端授权检查。

**验证说明**

静态证据：入口 POST /008；source=session/dvwaSession；sink=008.php:94；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：服务端在 008.php:94 下发 user_role=regular_user → 攻击者本地改为 user_role=admin 并重放请求 → 服务端读取 $_COOKIE['user_role'] 作为角色依据且无签名校验 → 获得管理员权限。
PocWriter 建议（未采纳，缺少端点 /008）：针对 008.php:94 的弱会话标识 POC。会话 Cookie dvwaSession 取值可预测（如递增整数），攻击者可猜测/重放他人会话。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-330。漏洞位于 008.php:94，会话标识 dvwaSession 生成逻辑可预测，属配置/逻辑型弱随机问题，具备远程触发条件。
POC 备注：仅文本工件，不执行；TARGET 为占位符。比较 Cookie 序列即可，无需暴力枚举真实会话。

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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.95 | 是 |
| surface_mapper | 攻击面测绘 | 8.62 | 是 |
| deep_finder | LLM 深挖 | 7.63 | 是 |
| candidate_screener | 候选筛选 | 6.2 | 是 |
| vulnerability_analyzer | 漏洞分析 | 14.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 12.18 | 是 |
| coordinator | 管线协调 | 7.77 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
