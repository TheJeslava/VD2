# 落日二号乙漏洞挖掘报告 — 20261031-172533-a174d4

- 生成时间：2026-10-31T09:26:38.185722+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
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

本次汇总 4 条已去重 findings，全部集中在单文件 PHP 脚本 011.php（32 行）。最高危为 LLM-c969ca7950b6：登录接口 username 参数 SQL 注入（critical，可绕过认证，行 1-13）；其次 SEM-bb3630458a80 登录接口缺少暴力破解防护（high，CWE-307）。另有 SEM-2ea8df0ef3b9 使用 MD5 处理口令（medium，按 CWE-328 应归 weak_hash，当前类型标注为 weak_crypto，需在交付时纠正类型标签）与 LLM-996252269452 登录成功页 username 反射型 XSS（medium，行 22）。4 条均带 POC：SQL 注入与 XSS 为 HTTP 型 POC 文本，可静态复现路径；MD5 弱哈希与暴力破解属静态/配置型证据 POC，不能宣称可动态复现。未发现二次注入链（仅单文件，无跨文件存储读写点）。所有结论均为源码审计推断（llm_inferred / rule），未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 011.php（32 行），已逐行审计。确认两条闭合链：(1) username 参数 SQL 注入（011.php:5→12→13→15），可绕过登录并读取 users 表；(2) 登录成功页 username 反射型 XSS（011.php:5→21），需配合注入或有效凭据触发。password 参数经 md5() 处理为固定长度十六进制，不构成注入点。第 22 行 avatar 字段拼入 img src 存在潜在存储型 XSS，但 CODE PACK 内无 avatar 写入点，二次注入三要素（写点/读点/汇点）不完整，未单独立项。weak_hash（md5 用于口令，011.php:9）属设计缺陷但单独不构成可利用链，未达 CVE 门槛，仅作线索记录。未发现命令执行、文件包含、SSRF、反序列化等其它 sink。未覆盖范围：无 php.ini/Web 服务器配置、无部署与认证前置信息、无其它文件，无法评估跨文件二次注入与运行环境对可利用性的影响。

未覆盖 / 证据缺口：
- 无 php.ini/服务器配置，无法确认错误回显与 open_basedir 等设置
- 无 avatar 字段写入点，存储型 XSS 链不完整
- 无部署/认证前置信息，无法评估实际暴露面
- 仅单文件，无法评估跨文件二次注入

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行在 $_GET['Login'] 存在时进入登录逻辑，第 5 行直接取 $_GET['username'] 赋给 $user，未做任何转义或参数化；第 12 行将 $user 直接字符串拼接进 SELECT 语句，第 13 行通过 mysqli_query 执行。攻击者可在 username 中注入 SQL 语法（如 ' OR '1'='1' -- -）改变 WHERE 条件，使查询恒真并返回 users 表首行，从而在不知道口令的情况下通过第 15 行 mysqli_num_rows == 1 的判定，进入“password protected area”。password 参数虽经 md5() 处理（第 9 行），但 md5 输出为固定 32 位十六进制，无法注入，因此注入点唯一在 username。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行拼接后的 SQL

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 检测到 GET 参数 Login 存在，进入登录分支 | 外部请求进入登录逻辑 |  |
| 2 | `011.php:5` | 直接读取 username 参数赋给 $user，无过滤 | $user = 攻击者完全可控字符串 |  |
| 3 | `011.php:12` | 将 $user 拼接进 SQL 的 user = '$user' 单引号字符串中 | SQL 语法被攻击者输入改写 |  |
| 4 | `011.php:13` | mysqli_query 执行被污染的查询 | 数据库执行恒真条件，返回 users 首行 |  |
| 5 | `011.php:15` | mysqli_num_rows == 1 成立，判定登录成功并输出受保护区域 | 认证被绕过 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可直接绕过登录进入受保护区域，并可进一步通过 UNION/布尔盲注读取 users 表全部用户名与口令哈希，导致账户接管与数据泄露。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 未经转义直接拼接进 SQL 并由 mysqli_query 执行，无需认证即可触发，利用链在 CODE PACK 内完全闭合（011.php:5 → 12 → 13 → 15）。

**修复建议**

使用预处理语句（mysqli_prepare + bind_param）绑定 username 与 password；对输入做类型与长度校验；关闭 die() 中的数据库错误回显以避免信息泄露。

**验证说明**

需动态确认数据库为 MySQL/MariaDB 且注释语法可用；需确认 users 表非空。代码层面注入链已闭合。
模型 POC 要点：利用 username 注入恒真条件绕过登录校验
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：针对 011.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username，源码 011.php:13 将该参数直接拼入 SQL 查询，未做参数化/转义。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于 011.php:13，外部输入来自 GET 参数 username，source→sink 链在给定代码范围内静态闭合，未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：仅文本工件，不执行、不联网。所有请求使用 TARGET 占位符；如需脚本化，请人工替换 TARGET 并在授权环境手动运行，禁止自动化批量攻击。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 通过 `isset($_GET['Login'])` 进入登录流程，011.php:5 读取 `username`、011.php:8 读取 `password`，随后直接查询比对。代码中未见失败计数、账户锁定、验证码、速率限制或延迟机制，攻击者可对同一接口无限次提交口令猜测。证据为 011.php:2-3 的登录入口与后续无防护的查询逻辑；运行时是否另有网关限流证据不足。

**source / sink**

- source：query `Login`（011.php）
- sink：011.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

暴力破解防护缺失 POC：011.php:3 处理登录逻辑（GET 参数 Login 作为提交按钮），未见失败计数、锁定、速率限制或验证码。注意：本候选 endpoint 写作 /011，与源码文件名 011.php 不一致，实际请求路径应以 011.php 为准。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-bb3630458a80`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对已知用户名进行在线口令爆破或撞库，配合 MD5 弱哈希（见 SEM-2ea8df0ef3b9）显著提高成功率，最终导致账户接管。

**CVE / CWE 论证**

CWE-307：认证接口缺乏尝试次数限制。外部可达性：登录入口为公开 GET 请求，无需认证；利用链为重复请求 011.php:3 的登录分支。注意：本项为语义模式命中，缺少运行时限流证据，置信度较低。

**修复建议**

引入失败计数与指数退避/临时锁定；增加验证码或 MFA；对同一 IP/账户做速率限制；记录并告警异常登录尝试；统一失败提示避免用户名枚举。

**验证说明**

静态证据：入口 GET /011；source=query/Login；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者反复向 011.php 发送带 `Login`、`username`、`password` 的 GET 请求，011.php:3 每次均进入登录分支并执行查询，无任何计数或锁定，攻击者可无限次尝试直至口令命中。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。证据位于 011.php:3 登录处理逻辑，未见失败计数/锁定/限速机制。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：仅文本工件，不执行。多请求问题需保持同一会话并比较响应；endpoint 中 /011 与源码 011.php 不符，已在 preconditions 标注需确认路由。禁止自动化批量爆破。

### F-3: 011.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 GET 参数 `password` 读取明文口令，011.php:9 直接调用 md5($pass) 生成摘要后用于 011.php:12 的登录比对。MD5 为快速、无盐、抗碰撞性已被攻破的哈希算法，用于口令存储/校验属安全用途误用。此处为配置/实现型弱点，不依赖 HTTP 污点链，证据为 011.php:9 的 `md5(` 调用原文。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型发现：011.php:9 使用 md5() 对用户口令做哈希（$pass = md5($pass)），属弱哈希算法。注意：MD5 应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327），本候选类型标注需修正。无需发送 HTTP 请求即可确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 011.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ea8df0ef3b9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若数据库泄露，攻击者可用彩虹表/GPU 高速爆破快速还原用户口令；MD5 无盐导致相同口令产生相同摘要，可做批量比对与撞库，进而横向登录其他系统。

**CVE / CWE 论证**

CWE-328（弱哈希），非 CWE-327（后者指 DES/ECB 等加密算法误用）。外部可达性：登录接口公开，攻击者提交任意口令即触发 md5 计算；弱点根因在 011.php:9 的算法选择，无需额外前置条件。

**修复建议**

改用专为口令设计的慢哈希算法（bcrypt/Argon2id/PBKDF2），并为每个用户生成独立随机盐；迁移时对存量 MD5 摘要做透明升级；禁止在安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 GET /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 GET `password` → 011.php:8 赋值 $pass → 011.php:9 md5($pass) → 011.php:12 拼入查询与库中摘要比对。攻击者无需注入即可利用该弱哈希：一旦获取摘要即可离线高速破解。
POC 备注：仅文本工件，不执行。类型应从 weak_crypto 更正为 weak_hash。

### F-4: 011.php 登录成功页 username 反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:21-22`
- **来源**：`llm_finding`

**描述**

第 21 行将 $user（来自 $_GET['username']，第 5 行）直接拼接进 HTML 输出 $html，未做 htmlspecialchars 等输出编码。虽然进入该分支需要 SQL 查询成功（可通过同文件的 SQL 注入使条件恒真），但一旦查询返回一行，攻击者控制的 username 原样反射到页面，形成反射型 XSS。此外第 22 行将数据库 avatar 字段拼入 img src，若 avatar 可被低权限用户写入则存在存储型风险，但 CODE PACK 内无写入点证据，故仅报告 username 反射链。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:22 $html 输出到响应页面（HTML 上下文）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | 读取 username 参数 | $user = 攻击者可控字符串 |  |
| 2 | `011.php:12` | username 进入 SQL；配合注入使查询返回一行 | 查询成功 |  |
| 3 | `011.php:15` | num_rows == 1 成立进入成功分支 | 进入输出逻辑 |  |
| 4 | `011.php:21` | $user 未编码直接拼入 HTML 段落 | HTML 标签被注入 |  |
| 5 | `011.php:21` | $html 输出到响应 | 浏览器解析执行脚本 |  |

**POC**

针对 /011.php（GET）的 跨站脚本 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-996252269452`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器上下文执行任意 JS，窃取会话或发起 CSRF 式操作；结合 SQL 注入可稳定触发。

**CVE / CWE 论证**

CWE-79 反射型 XSS。username 从 GET 参数到 HTML 输出无编码，链在 CODE PACK 内闭合（011.php:5 → 21）。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；对 avatar 做 URL 白名单校验。

**验证说明**

XSS 触发依赖查询成功分支，需配合 SQL 注入或已知有效凭据；需确认响应 Content-Type 为 text/html 且无 CSP 阻断。
模型 POC 要点：通过 SQL 注入使查询成功，同时 username 携带 XSS payload 反射执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：针对 011.php（GET）的反射型 XSS POC。注入点为 GET 参数 username，源码 011.php:22 将其输出到响应而未做 HTML 编码。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于 011.php:22，外部输入来自 GET 参数 username，source→sink 链在给定代码范围内静态闭合，未见有效编码；具备远程触发条件。证据等级：llm_inferred。
POC 备注：仅文本工件，不执行、不联网。请求使用 TARGET 占位符；payload 使用 alert(document.domain) 作为无害验证，禁止用于真实攻击。

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
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
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
| `weak_crypto` | CWE-327 |  | 1 |
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
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.21 | 是 |
| surface_mapper | 攻击面测绘 | 10.29 | 是 |
| deep_finder | LLM 深挖 | 12.76 | 是 |
| candidate_screener | 候选筛选 | 5.17 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.4 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 15.1 | 是 |
| coordinator | 管线协调 | 7.61 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
