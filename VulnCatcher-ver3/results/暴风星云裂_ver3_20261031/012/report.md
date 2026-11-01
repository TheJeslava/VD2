# 落日二号乙漏洞挖掘报告 — 20261031-005847-2ab156

- 生成时间：2026-10-30T16:59:38.214050+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

本次汇总 4 条已去重 findings，全部集中在单文件 PHP 程序 012.php（35 行）。最高危为 GEN-3b547dba7a60：012.php 第 15 行登录查询 SQL 注入（critical，CWE-89），有 POC；其次 SEM-536ee862bb25 登录接口缺少暴力破解防护（high，CWE-307），有 POC。另有 SEM-0ce3358fa05b 使用 MD5 存储口令（medium，CWE-328，注意类型应为 weak_hash 而非 weak_crypto，建议人工纠正分类）与 LLM-a7383455f404 登录成功页反射型 XSS（medium，username 经 mysqli_real_escape_string 后拼入 HTML，属 llm_inferred 推断）。4 条均标记 has_poc=true，但其中 MD5 口令项仅为静态证据 POC，不具备 HTTP 动态复现语义；SQL 注入与 XSS 为 HTTP POC，暴力破解为请求层 POC。所有结论均为源码审计推断，未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 012.php（35 行）。发现：1) 第 5/6/23 行 username 参数经 SQL 转义后直接拼入 HTML，构成反射型 XSS（需登录成功分支，置信度 0.7）。2) 第 9/10/11/14 行 password 经 mysqli_real_escape_string 后 md5 再拼入 SQL，mysqli_real_escape_string 已做 SQL 转义，未发现可闭合的 SQL 注入（宽字节注入需确认连接字符集，证据不足未报告）。3) 第 11 行 md5 用于口令哈希属 weak_hash（CWE-328），但为登录校验用途且无独立可利用链，未单独立 finding。4) 第 24 行 $avatar 来自数据库，若数据库内容可控则存在存储型 XSS，但 avatar 写入点不在 code_pack 内，链不闭合。5) 第 15 行 die(mysqli_error) 泄露 SQL 错误信息，属信息泄露，价值低未报告。未覆盖：无配置文件、无依赖清单、无端点清单，无法评估部署环境与第三方组件。

未覆盖 / 证据缺口：
- avatar 字段的写入点不在 code_pack，存储型 XSS 链不闭合
- 数据库连接字符集未知，无法确认宽字节 SQL 注入
- 无 php.ini/Web 服务器配置，无法确认错误显示与部署方式
- 无认证/会话机制证据

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 `username`（012.php:5 读取）提交任意字符串，该值被直接拼进 012.php:14 的 SQL 语句 `SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';`，随后在 012.php:15 交给 mysqli_query 执行。代码中仅对 `$pass` 调用了 mysqli_real_escape_string（012.php:10），`$user` 没有任何转义、类型约束或参数化处理，因此单引号可闭合字符串字面量，注入任意 SQL 片段（例如 `username=' OR '1'='1' -- ` 绕过认证，或使用 UNION/布尔/时间盲注读取 users 表）。查询失败时 012.php:15 的 die() 还会把 mysqli_error 原文回显到页面，构成报错型注入的信息泄露通道。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /012（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-3b547dba7a60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证、读取/篡改 users 表中的账号与口令哈希（口令为 MD5，见 SEM-0ce3358fa05b，可离线破解），并借助报错回显获取数据库结构信息；若数据库账号权限过高，可进一步读写其他表数据。

**CVE / CWE 论证**

CWE-89：外部可控输入 `username` 未经参数化即拼入 SQL 并在 012.php:15 执行，属典型一次注入。攻击面为公开的登录入口（012.php:3 仅判断 `$_GET['Login']` 是否存在），无需认证即可触发；source（012.php:5）→ 拼接（012.php:14）→ sink（012.php:15）链路在单文件内闭合，无净化环节。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param，或 PDO 的 prepare/execute），彻底移除字符串拼接；对 `username` 做长度与字符白名单校验；关闭错误详情回显，将 mysqli_error 写入服务端日志而非响应体；数据库账号按最小权限授予，仅允许对必要表执行 SELECT。

**验证说明**

静态证据：入口 ANY /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单/请求中提交 `username` 参数（012.php:5）→ 变量 `$user` 未做任何转义 → 012.php:14 将其拼入 WHERE 子句 → 012.php:15 mysqli_query 执行被篡改的 SQL → 结果用于认证判断并可能通过 die(mysqli_error) 回显数据库错误。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:15 的 SQL 注入 POC。源码中 username 参数经 mysqli_real_escape_string 处理后仍被拼接进 SQL 查询（第 15 行），构成 CWE-89。注入点为 query 参数 username，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原请求结构；仅补充说明与预期结果。脚本仅作文本参考，禁止自动执行；目标统一使用 TARGET。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 通过 `if( isset( $_GET[ 'Login' ] ) )` 进入登录处理，随后在 012.php:14-15 校验用户名与口令。整个流程中未见失败次数计数、账号/IP 锁定、验证码、指数退避或速率限制等任何反暴力破解机制，且登录凭据通过 GET 参数传递（`username`、`password`），便于脚本化批量重放。

**source / sink**

- source：request `login/password`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /012（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-536ee862bb25`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对任意已知或枚举出的用户名进行在线口令爆破/撞库，配合 SEM-0ce3358fa05b 的弱哈希与 GEN-3b547dba7a60 的注入绕过，可高效获取有效账号，造成账户接管。

**CVE / CWE 论证**

CWE-307（Improper Restriction of Excessive Authentication Attempts）：认证入口 012.php:3 对外公开、无需前置认证，且无任何尝试次数约束；证据为 012.php:2-3 的登录分支与 012.php:14-15 的校验逻辑中不存在计数/锁定代码。该结论基于源码静态观察，实际限流可能由前置网关提供，属证据缺口。

**修复建议**

在服务端按账号与来源 IP 实施失败计数与临时锁定/指数退避；引入验证码或二次验证；将登录改为 POST 并配合 CSRF Token，避免凭据出现在 URL 与日志中；对登录失败统一返回模糊提示，避免用户名枚举；集中记录并告警异常登录频率。

**验证说明**

静态证据：入口 ANY /012；source=request/login/password；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者反复向 012.php 提交带 `Login` 参数的请求（012.php:3）→ 每次都以 012.php:14-15 校验一组 `username`/`password` → 因无失败计数与锁定，可无限次尝试直至命中正确口令。
PocWriter 建议（未采纳，缺少端点 /012）：暴力破解防护缺失 POC（CWE-307）。012.php:3 处理登录相关参数 login/password，未见速率限制或锁定机制。注意：原草稿将参数名写成 login/password，需人工核对源码中实际参数名后再定稿；此处保留原结构并标注待确认。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。漏洞位于 012.php:3，需人工确认参数名与登录逻辑后定稿；当前证据为静态推断。
POC 备注：保留原请求结构；参数名 login/password 需与源码核对。脚本仅作文本参考，禁止自动执行；目标统一使用 TARGET。

### F-3: 012.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:11 执行 `$pass = md5( $pass );`，将用户口令以无盐 MD5 单轮哈希形式处理，随后在 012.php:14 的查询中与数据库中的口令值比较。MD5 属已被证明存在实用碰撞且计算速度极快的哈希算法，用于口令存储时无法抵抗离线暴力破解与彩虹表攻击；代码中未见盐值（salt）或迭代（如 bcrypt/Argon2/PBKDF2）等加固措施。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：012.php:11 使用 md5() 对密码 $pass 做哈希，属弱哈希（CWE-328），无需发送请求。注意：该问题本质为弱哈希而非弱加密，归类应以 CWE-328 为准。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 012.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0ce3358fa05b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

一旦数据库泄露（可经 GEN-3b547dba7a60 的 SQL 注入读取 users 表），攻击者可用彩虹表或 GPU 高速枚举在短时间内还原大量用户明文口令，进而横向登录其他系统（口令复用场景）。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 被用于口令这一安全用途，属弱哈希而非弱加密算法（非 CWE-327）。该弱点为配置/实现型，不依赖 HTTP 污点链；证据为 012.php:11 的 `md5( $pass )` 原文调用，且 012.php:10 仅做转义、未引入盐或迭代。外部可达性体现在登录流程每次都会以 MD5 处理口令。

**修复建议**

改用专为口令设计的慢哈希：PHP 的 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）配合 password_verify()，自动生成随机盐；迁移期可对存量 MD5 值在用户下次登录时透明重算；禁止在任何新代码中使用 md5()/sha1() 处理口令或令牌。

**验证说明**

静态证据：入口 ANY /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:10 仅做 mysqli_real_escape_string → 012.php:11 以无盐 MD5 计算摘要 → 012.php:14 将摘要拼入查询与库中值比较；由于算法弱且无盐，库中摘要一旦外泄即可被快速离线还原。
POC 备注：纯静态证据，无 HTTP 请求；不执行任何命令。

### F-4: 012.php 登录成功页反射型 XSS：username 参数经 mysqli_real_escape_string 后直接拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.65`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-23`
- **来源**：`llm_finding`

**描述**

012.php 第 5 行从 $_GET['username'] 读取用户输入，第 6 行仅用 mysqli_real_escape_string 做 SQL 转义（该函数只转义 SQL 特殊字符，不处理 HTML 元字符 < > " '），第 23 行将 $user 直接拼接进 HTML 字符串 "<p>Welcome to the password protected area {$user}</p>" 并输出。攻击者可构造含 HTML/JS 的 username，在登录成功后于受害者浏览器执行脚本。注意：该 XSS 仅在登录成功分支（第 17 行 mysqli_num_rows==1）触发，需要有效凭据或 SQL 注入配合，因此利用条件受限。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:23 第 23 行 $html .= "<p>Welcome to the password protected area {$user}</p>" 输出到响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 $_GET['username'] 读取攻击者输入 | 原始字符串 |  |
| 2 | `012.php:6` | mysqli_real_escape_string 仅做 SQL 转义，不处理 HTML 元字符 | SQL 转义后的字符串，HTML 元字符原样保留 | 该函数不是 HTML 编码，<script> 等标签不受影响 |
| 3 | `012.php:23` | 拼接进 HTML 并输出 | 含未编码 HTML 的响应体 |  |

**POC**

针对 /012.php（GET）的 跨站脚本 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/012.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-a7383455f404`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JS，可窃取会话或发起操作；但需登录成功分支，实际影响中等

**CVE / CWE 论证**

CWE-79 反射型 XSS，外部可达，但触发依赖登录成功，链不完全闭合于未认证场景

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8') 编码

**验证说明**

需确认登录成功分支可达（有效凭据或 SQL 注入配合），以及响应是否直接回显 $html
模型 POC 要点：使用有效凭据登录，username 填入 XSS payload，登录成功后页面回显执行脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /012.php）：针对 012.php:23 的反射型 XSS POC。GET 参数 username 未经编码直接输出到响应（第 23 行），构成 CWE-79。注入点为 query 参数 username，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-79。漏洞位于 012.php:23，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原请求结构；仅补充说明与预期结果。脚本仅作文本参考，禁止自动执行；目标统一使用 TARGET。

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
| safety_guard | 安全防护 | 3.5 | 是 |
| surface_mapper | 攻击面测绘 | 7.65 | 是 |
| deep_finder | LLM 深挖 | 6.8 | 是 |
| candidate_screener | 候选筛选 | 6.05 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.45 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.55 | 是 |
| coordinator | 管线协调 | 6.44 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
