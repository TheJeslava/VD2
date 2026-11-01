# 落日二号乙漏洞挖掘报告 — 20261031-011443-5346f0

- 生成时间：2026-10-30T17:15:46.983721+00:00
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

本次汇总基于单文件 PHP 脚本 008.php（96 行）的静态审计结果，共 6 条已去重 findings，全部带 POC（6/6）。最高危为 008.php 中三处 SQL 注入（CWE-89，critical）：用户存在性检查（约第 23 行）、用户信息查询（约第 36 行）、日志写入 INSERT（约第 81 行），均为规则命中、有 HTTP 型 POC 文本。其次为 high 级越权与身份伪造：通过可篡改 user_id Cookie 越权读取任意用户资料（IDOR，约第 36 行），以及基于 Cookie 的角色标识可被客户端伪造（weak_id，CWE-330/CWE-565，约第 94 行）。另有 medium 级存储型 XSS（用户资料字段未编码直接输出，约第 47 行）。POC 齐全但均为静态构造文本，未做任何动态验证；SQL 注入与 XSS 属 HTTP 型 POC，weak_id 属会话/配置语义型 POC，不能宣称可动态复现。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3377 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 008.php 的 1-65 行（共 96 行，66-96 行未送入）。发现：1) 基于可篡改 Cookie 的 IDOR，可越权读取任意用户资料，链闭合；2) 资料字段未编码输出导致的存储型 XSS，依赖 code_pack 外的资料编辑入口。第 7 行 dvwaCurrentUser() 拼接进 SQL，但该函数返回值来自会话用户名，非直接请求参数，未确认可控，未单独立项。第 60-65 行 bac_log 建表逻辑为固定 SQL，无注入。weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret 在可见 1-65 行内均未出现对应调用，未报告。

未覆盖 / 证据缺口：
- 008.php 第 66-96 行未送入 code_pack，日志写入逻辑未审计
- dvwaCurrentUser() 实现不在 code_pack，无法确认其返回值是否可被用户名注入 SQL
- 资料编辑入口与 users 表写入过滤逻辑不在 code_pack
- 无 Web 服务器配置，无法确认 008.php 是否需认证

## 3. Findings

### F-1: 008.php 用户存在性检查处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:21-23`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求参数 user_id 提供输入（008.php:19 读取 query `user_id`），该值未做类型转换或参数化，直接拼接进 $check_query = "SELECT user_id FROM users WHERE user_id = $id"（008.php:22），随后在 008.php:23 交给 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。代码中未见 intval/类型转换、mysqli_real_escape_string 或预处理语句，因此数字型上下文可被 `1 OR 1=1`、`1 UNION SELECT ...` 等载荷突破，校验无效。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:23 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `008.php:23` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY 方法）的 SQL 注入 POC。注入点为查询参数 user_id，位于 008.php:23 的 SQL 拼接汇点；payload 使用 TARGET 占位符，仅限授权测试。

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

数据库查询逻辑被篡改：可绕过用户存在性判断、枚举/读取 users 表及其他表数据（如凭据、个人信息），在数据库权限允许时可进一步读写文件或堆叠查询，造成数据泄露与认证逻辑绕过。

**CVE / CWE 论证**

CWE-89：外部可控参数 user_id 未经参数化直接进入 SQL 语句并执行，属典型一次注入；入口为公开 HTTP 参数，无需认证即可触发，source（008.php:19）到 sink（008.php:23）链路闭合。

**修复建议**

改用预处理语句：$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id FROM users WHERE user_id = ?"); mysqli_stmt_bind_param($stmt, 'i', $id); 并对 $id 做 intval 白名单校验；禁止字符串拼接 SQL。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:23；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 user_id → 008.php:19 读取为 $id → 008.php:22 字符串拼接进 $check_query → 008.php:23 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于可交付代码 008.php:23，外部输入来自 query 参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；poc.sh 与 request.http 仅为文本工件，不执行、不联网。SQL 注入 POC 不使用 DROP 等破坏性语句。

### F-2: 008.php 用户信息查询处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:34-36`
- **来源**：`rule`

**描述**

同一外部输入 user_id（008.php:19）在通过存在性检查后继续被使用，在 008.php:35 拼接为 $query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = $id;"，并于 008.php:36 由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。该路径同样没有参数化或转义，前置检查（008.php:22-23）本身也可被注入绕过，因此校验不构成有效防护。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:36 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `008.php:36` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY 方法）的 SQL 注入 POC。注入点为查询参数 user_id，位于 008.php:36 的 SQL 拼接汇点；payload 使用 TARGET 占位符，仅限授权测试。

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

可注入 UNION/布尔/报错载荷读取 users 表字段（姓名、头像路径、user_id）乃至其他表数据，导致敏感数据泄露；结合前置检查绕过可访问本不应返回的用户记录。

**CVE / CWE 论证**

CWE-89：source 为公开参数 user_id，sink 为 008.php:36 的 mysqli_query，中间无有效净化，外部可达且无需认证，利用链闭合。

**修复建议**

使用 mysqli_prepare + bind_param('i', $id) 参数化查询；对 $id 强制整数化并校验范围；统一封装数据库访问层，禁止拼接。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:36；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 user_id → 008.php:19 $id → 008.php:35 拼接 $query → 008.php:36 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于可交付代码 008.php:36，外部输入来自 query 参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-3: 008.php 日志写入 INSERT 处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:79-81`
- **来源**：`rule`

**描述**

008.php:79-80 构造 $log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')"，其中 $target_id 与 $ip 等值来源于请求上下文（与 008.php:19 的 user_id 输入同源链路），未做整数化或转义即拼接，随后在 008.php:81 由 mysqli_query($GLOBALS["___mysqli_ston"], $log_query) 执行。$ip 位于单引号字符串内但未转义，可用引号闭合注入；$target_id 为数字上下文可直接注入。

**source / sink**

- source：query `user_id`（008.php:19）
- sink：008.php:81 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:19` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `008.php:81` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /008（ANY 方法）的 SQL 注入 POC。注入点为查询参数 user_id，位于 008.php:81 的 SQL 拼接汇点；payload 使用 TARGET 占位符，仅限授权测试。

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

可向 bac_log 写入伪造记录或通过 UNION/子查询读取其他表数据，污染审计日志、掩盖攻击痕迹，并可能造成数据泄露；若数据库账户权限过高还可扩展为文件写入。

**CVE / CWE 论证**

CWE-89：外部输入经变量拼接进入 INSERT 语句并在 008.php:81 执行，无参数化/转义，公开可达、无需认证，链路闭合。

**修复建议**

对 $current_user_id、$target_id 使用 intval 强制整数；对 $ip 使用预处理占位符或 mysqli_real_escape_string；整体改为 mysqli_prepare + bind_param 的参数化 INSERT。

**验证说明**

静态证据：入口 ANY /008；source=query/user_id；sink=008.php:81；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求输入（user_id 链路及 target_id/ip）→ 008.php:79-80 字符串拼接 $log_query → 008.php:81 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-89。漏洞位于可交付代码 008.php:81，外部输入来自 query 参数 user_id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-4: DVWA BAC 页面通过可篡改的 user_id Cookie 实现越权访问任意用户资料

- **类型**：`idor` / CWE-639
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:30-36`
- **来源**：`llm_finding`

**描述**

008.php 第 15-19 行从 $_GET['user_id'] 读取目标用户 ID，仅用 preg_match('/^\d+$/') 与 intval 做格式校验；第 30-33 行的“访问控制”完全依赖客户端可控的 $_COOKIE['user_id']，只要把 Cookie 中的 user_id 改成与请求参数相同的值，$id == $cookie_id 恒成立，即可读取任意用户（含管理员）的 first_name/last_name/avatar。服务端从未把请求参数与当前登录会话的真实用户 ID（第 7-11 行查出的 $current_user_id）做比对，属于典型的信任客户端 Cookie 的越权访问。

**source / sink**

- source：cookie `user_id`（008.php:15）
- sink：008.php:36 mysqli_query 执行 SELECT first_name,last_name,user_id,avatar FROM users WHERE user_id = $id 并回显到页面

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:15` | 从 $_GET 读取 action 与 user_id，进入分支 | 攻击者可控字符串 |  |
| 2 | `008.php:16` | preg_match('/^\d+$/') 仅校验纯数字格式，不校验归属 | 纯数字字符串，通过校验 | 只做格式白名单，未做对象归属校验 |
| 3 | `008.php:19` | intval 转换为整数 $id | 整数，攻击者指定任意用户 ID |  |
| 4 | `008.php:30` | 读取客户端 Cookie user_id | 攻击者可控 Cookie 值 |  |
| 5 | `008.php:31` | intval 转换 Cookie 值 | 整数 |  |
| 6 | `008.php:33` | $id == $cookie_id 比较，攻击者令二者相等即通过 | 条件恒真 | 访问控制依据客户端 Cookie，可任意伪造 |
| 7 | `008.php:35` | 拼接并执行查询目标用户资料 | SQL 已执行 |  |
| 8 | `008.php:43` | 将 first_name/last_name/avatar 回显到页面 | 敏感数据泄露 |  |

**POC**

针对 /008.php（GET）的越权/IDOR POC。注入点为 Cookie user_id，位于 008.php:36 附近的对象标识使用点；通过修改 Cookie 中的 user_id 访问他人对象，payload 使用 TARGET 占位符，仅限授权测试。

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
- POC 目录：`poc/LLM-207aeb80f46b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录低权限用户可越权读取所有用户（含管理员）的姓名、头像等个人信息，构成水平/垂直越权与信息泄露。

**CVE / CWE 论证**

CWE-639 授权绕过（IDOR）。外部 HTTP 可达，仅需低权限账户，访问控制依赖客户端 Cookie，链完全闭合。

**修复建议**

服务端应使用会话中的真实用户 ID（$current_user_id）与请求参数比对，禁止信任客户端 Cookie 做授权判断；对管理员资料访问增加角色校验。

**验证说明**

需确认 DVWA 会话中 user_id Cookie 是否由应用自行设置（若不存在则攻击者可直接添加该 Cookie，仍可利用）；需动态确认页面回显字段。
模型 POC 要点：伪造 user_id Cookie 与请求参数一致，读取任意用户资料
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /008.php）：符合 CWE-639。漏洞位于可交付代码 008.php:36，外部输入来自 cookie user_id，source→sink 链静态闭合，未发现有效归属校验，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。

### F-5: 008.php 基于 Cookie 的角色标识可被客户端伪造（CWE-330/CWE-565）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`008.php:93-94`
- **来源**：`rule`

**描述**

008.php:93-94 在 $_COOKIE['user_role'] 不存在时执行 setcookie('user_role', 'regular_user', time() + 3600, '/')，即用户角色这一安全相关标识完全由客户端 Cookie 承载，且未签名、未与服务器端会话绑定。攻击者可直接构造 Cookie user_role=admin 之类的值提交，服务端若直接信任该 Cookie 判断权限即被绕过。注意：输入证据仅显示写入默认值，未给出读取该 Cookie 做鉴权的具体行号，故“服务端信任该值”的部分属推断，需结合未提供的鉴权代码复核。

**source / sink**

- source：request `session cookie`（008.php）
- sink：008.php:94     setcookie('user_role', 'regular_user', time() + 3600, '/');

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:94` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /008（ANY 方法）的弱 ID/可预测会话标识 POC。证据位于 008.php:94 附近的会话标识生成逻辑；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/008'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/008?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e3f1dc6ea55d`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若下游逻辑依据 user_role Cookie 做授权判断，攻击者可将其改为管理员角色实现垂直越权，访问管理功能或他人数据；同时该标识可预测/可枚举，缺乏完整性保护。

**CVE / CWE 论证**

CWE-330（使用不充分随机/可预测值）与 CWE-565（依赖未受保护的 Cookie 做安全决策）：安全相关标识由客户端可控 Cookie 承载，无签名或服务端校验，外部无需认证即可设置。

**修复建议**

不要在 Cookie 中存放角色等授权信息；角色应保存在服务端会话（$_SESSION）中，Cookie 仅保存不可猜测的会话 ID（session_regenerate_id、HttpOnly/Secure/SameSite 标志）；对任何客户端提交的权限相关值做服务端校验与签名。

**验证说明**

静态证据：入口 ANY /008；source=request/session cookie；sink=008.php:94；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：客户端请求 → 008.php:93 检测 $_COOKIE['user_role'] → 008.php:94 写入默认角色 Cookie；攻击者可直接伪造该 Cookie 值，若服务端据此鉴权则越权（读取点未在证据中给出，属推断）。
PocWriter 建议（未采纳，缺少端点 /008）：符合 CWE-330。证据位于 008.php:94 附近的会话标识生成逻辑，属配置/算法型候选，需结合会话证据确认。
POC 备注：原 POC 的注入通道写法（query 参数 'session cookie'）与源码语义不完全一致，实际应为会话标识生成逻辑；此处保留原请求结构并注明需人工核实。脚本仅为文本工件，不执行、不联网。

### F-6: 008.php 用户资料字段未编码直接输出导致存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.65`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`008.php:40-47`
- **来源**：`llm_finding`

**描述**

第 40-47 行将数据库中的 first_name、last_name、avatar 直接拼接进 HTML 输出，未做 htmlspecialchars 编码。若攻击者能控制自身资料字段（DVWA 用户资料可编辑），则可注入脚本，当管理员通过越权/正常访问查看该用户资料时在管理员浏览器执行，窃取会话。

**source / sink**

- source：repository `first_name`（008.php）
- sink：008.php:47 字符串拼接进 $html 后输出到页面

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `008.php:35` | 查询目标用户资料 | 从数据库取出字段 |  |
| 2 | `008.php:39` | mysqli_fetch_assoc 取行 | 字段值未编码 |  |
| 3 | `008.php:44` | 将 first_name/last_name 直接拼入 HTML | 原始 HTML 片段 | 无 htmlspecialchars 编码 |
| 4 | `008.php:45` | avatar 字段同样直接输出 | 原始 HTML |  |

**POC**

针对 008.php:47 的 XSS 静态证据型 POC。该处将数据库字段（user_id/first_name/last_name/avatar）直接拼接进 HTML 输出，未做 HTML 编码；若这些字段可被用户写入，则构成存储型 XSS。payload 使用 TARGET 占位符，仅限授权测试。

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

存储型 XSS，可在管理员上下文执行脚本，窃取会话或执行敏感操作。

**CVE / CWE 论证**

CWE-79。外部可达，需用户资料写入能力与受害者访问，链基本闭合但依赖资料编辑入口（不在 code_pack 内）。

**修复建议**

输出前对所有数据库字段使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码。

**验证说明**

资料编辑入口（profile.php）不在 code_pack，需确认字段可由用户控制且未在写入时过滤。
模型 POC 要点：在自身资料字段写入脚本，诱导管理员查看
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：原 POC 为静态证据型；此处补充了写入→渲染的验证思路，但写入入口未在 code_pack 中确认，属 llm_inferred 推断，需人工核实。脚本仅为文本工件，不执行、不联网。

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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 9.61 | 是 |
| deep_finder | LLM 深挖 | 11.59 | 是 |
| candidate_screener | 候选筛选 | 8.55 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 13.07 | 是 |
| coordinator | 管线协调 | 7.9 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
