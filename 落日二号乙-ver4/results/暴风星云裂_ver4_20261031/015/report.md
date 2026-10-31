# 落日二号乙漏洞挖掘报告 — 20261031-164052-f3662f

- 生成时间：2026-10-31T08:41:56.902598+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\015.zip`
- 输入模式：`zip`
- SHA256：`24ec46248538ba08d8e8eb94c82934ecea9f754341b0de0a93fec8dda6a387c2`
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

本次审计对象为单文件 PHP 脚本 015.php（83 行），共交付 6 条去重后 finding，全部带 POC（with_poc=6）。最高危为 015.php 第 69 行附近的修改密码处 SQL 注入（GEN-c00a42452f04，critical，CWE-89），属 HTTP 可复现类 POC。其次为两条验证码绕过（LLM-795a4853ea15 与 SEM-2b846713ecdc，high，CWE-804），二者描述同一 step 状态机缺陷，属同一根因的规则与模型双报，建议合并为一条交付。中危包括两条 CSRF（LLM-db88415cbc34 / SEM-bb70b3793387，均指向修改密码接口无 token，同为重复根因）与一条口令 MD5 存储（SEM-81919fa4d087）。需特别说明：该条被标为 weak_crypto，但证据指向 MD5 口令哈希，按分类规则应归 weak_hash（CWE-328），且只有静态证据 POC，不能宣称可动态复现。POC 齐全度：6/6 有 POC，但其中 weak_hash 一条为静态 POC，其余 5 条为 HTTP POC。所有结论均为源码静态推断，未经动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 015.php（DVWA CAPTCHA 改密模块，83 行），已逐行审计。核心问题：改密状态机 step=2 分支仅信任客户端 passed_captcha 字段（第 55 行），不校验 CAPTCHA 令牌与会话状态，可绕过 CAPTCHA 直接改密；同时整个改密流程无 CSRF token。第 64 行对 password_new 做了 mysqli_real_escape_string，第 68 行 UPDATE 语句中 user 来自 dvwaCurrentUser() 而非直接请求参数，故未构成 SQL 注入。第 65 行使用 md5() 存储密码属 weak_hash（CWE-328），但为 DVWA 教学环境既定实现，单独价值有限，未单独立项。未发现命令执行、文件包含、SSRF、反序列化等汇点。未覆盖：Web 服务器配置、包含链、PHP 版本与 php.ini、recaptcha_check_answer 实现、dvwaCurrentUser 实现，均在 code_pack 之外。

未覆盖 / 证据缺口：
- 无端点清单与部署配置，无法确认 015.php 是否直接对外暴露
- recaptcha_check_answer 与 dvwaCurrentUser 实现不在 code_pack
- PHP 版本/php.ini 未知
- 无数据库 schema 与连接配置

## 3. Findings

### F-1: 015.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（015.php:8 读取，015.php:51 处进入 $pass_new）提交恶意字符串。该值在 015.php:64 仅经过 mysqli_real_escape_string 转义，随后在 015.php:68 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 015.php:69 交给 mysqli_query 执行。由于拼接发生在转义之后（转义只处理引号等字符，无法阻止已转义内容被再次放入 SQL 文本），且未使用参数化查询，攻击者可构造闭合单引号并注入任意 SQL 片段。注意：015.php:65 的 md5() 只改变值的表示形式，不构成 SQL 层面的净化。

**source / sink**

- source：query `password_new`（015.php:51）
- sink：015.php:69 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `015.php:69` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /015（POST）的 SQL 注入 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-c00a42452f04`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 users 表中任意用户（含 admin）的 password 字段，实现账户接管/越权登录；结合报错回显（mysqli_error 输出到页面）可进行报错型注入读取数据库结构与其他表数据，造成敏感数据泄露。

**CVE / CWE 论证**

CWE-89：外部可控输入（$_POST['password_new']）未经参数化直接拼入 SQL 并在 mysqli_query 执行，外部 HTTP 可达、无需额外权限即可触发（需处于已登录的修改密码流程），利用链闭合。

**修复建议**

改用预处理语句与绑定参数（mysqli_prepare + bind_param 或 PDO prepared statement），禁止字符串拼接 SQL；对输入做长度与字符白名单校验；关闭向页面回显数据库错误信息（移除 or die(mysqli_error(...))），统一记录到服务端日志。

**验证说明**

静态证据：入口 POST /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 $pass_new → 015.php:51 赋值 → 015.php:64 mysqli_real_escape_string → 015.php:65 md5 → 015.php:68 字符串拼接进 $insert → 015.php:69 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:69 的 SQL 注入 POC。源码中 POST 参数 password_new 经 mysqli_real_escape_string 后仍被拼入 UPDATE/密码修改 SQL（第 64-69 行），注入点为 POST 参数 password_new，payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。漏洞位于 015.php:69，外部输入来自 POST 参数 password_new，source→sink 链静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；替换 TARGET 后手动在授权环境验证。request.http 中 Content-Length 需按实际编码长度调整。

### F-2: DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-72`
- **来源**：`llm_finding`

**描述**

脚本用两阶段状态机实现改密：step=1 校验 reCAPTCHA，成功后渲染隐藏表单，其中包含 step=2、passed_captcha=true。step=2 分支（第 46-81 行）仅检查 $_POST['passed_captcha'] 是否为真（第 55 行），完全不校验 CAPTCHA 令牌、不校验会话中是否真的通过过 step=1、也没有任何一次性 nonce/服务端状态。攻击者可直接构造 step=2 请求并自带 passed_captcha=true，跳过第三方 CAPTCHA 校验，直接进入改密逻辑（第 62-72 行），把当前登录用户密码改为任意值。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:72 第 68-69 行 UPDATE users SET password 的 mysqli_query 执行（改密副作用）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口判断 step==2 即进入第二阶段，无需先经过 step=1 | 攻击者完全控制 step 值 |  |
| 2 | `015.php:55` | 唯一门槛是 $_POST['passed_captcha'] 为真，该值由客户端提交，无服务端会话/令牌绑定 | passed_captcha=true 直接满足 | CAPTCHA 校验只存在于 step=1 分支（第 12-23 行），step=2 分支不重新校验，也无一次性令牌 |
| 3 | `015.php:62` | 两次密码相等即通过 | password_new==password_conf |  |
| 4 | `015.php:68` | 拼接 UPDATE 语句并执行，修改当前用户密码 | md5 后的密码写入 users 表 |  |

**POC**

针对 /vulnerabilities/captcha/ (015.php)（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-795a4853ea15`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

绕过人机校验，配合 CSRF 可对已登录用户静默改密，导致账户接管；CAPTCHA 保护形同虚设。

**CVE / CWE 论证**

CWE-804/841（状态机与认证因素绕过）。外部可直接 POST 触发，无需通过 CAPTCHA，链闭合。

**修复建议**

在服务端会话中记录 step=1 已通过 CAPTCHA 的一次性令牌，step=2 校验该令牌并立即失效；不要信任客户端 passed_captcha 字段。

**验证说明**

需确认 015.php 是否被直接暴露、recaptcha_check_answer 是否真实生效；状态机绕过逻辑本身在源码中确定。
模型 POC 要点：跳过 CAPTCHA 直接提交第二阶段改密请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:72 的验证码绕过 POC。源码在密码修改流程中依赖 passed_captcha / g-recaptcha-response 判断，但可通过省略或置空验证码字段直接进入 step=2 完成修改，注入点为 POST 参数 Change 与验证码字段。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-804。漏洞位于 015.php:72，验证码校验缺失/可绕过，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；替换 TARGET 后手动在授权环境验证。

### F-3: 015.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 仅以 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) 作为进入修改口令逻辑的条件，验证码阶段由客户端提交的 step 值控制（step=1 表示跳过验证码直接进入修改）。攻击者可直接提交 Change=1&step=1 及 password_new/password_conf，跳过验证码校验环节，验证码形同虚设。

**source / sink**

- source：request `captcha/step`（015.php）
- sink：015.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2b846713ecdc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

验证码保护失效，可被用于自动化批量修改口令/暴力尝试，配合 CSRF 或撞库放大攻击效果。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/验证码绕过：验证码状态由客户端可控参数 step 决定，服务端未强制校验验证码答案，外部 HTTP 可达且无需认证前置条件（在会话内即可），利用链闭合。

**修复建议**

验证码校验必须在服务端完成并与会话绑定，不得由客户端 step 参数决定是否校验；一次性使用并在校验后立即失效；对修改口令等敏感操作增加频率限制与失败锁定。

**验证说明**

静态证据：入口 POST /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST Change=1&step=1&password_new=...&password_conf=... → 015.php:3 条件成立，跳过验证码分支 → 015.php:8-9 读取参数 → 015.php:68-69 执行口令更新。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:3 的验证码绕过 POC。密码修改流程中验证码校验可被省略/置空绕过，直接进入 step=2 完成修改。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。漏洞位于 015.php:3，验证码校验缺失/可绕过，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；替换 TARGET 后手动在授权环境验证。

### F-4: 015.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.86`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式计算后写入数据库（015.php:68 的 UPDATE 语句）。MD5 属于快速、无盐、已被证明存在碰撞的哈希算法，不适合口令等安全用途；攻击者一旦获取数据库（例如通过同文件中的 SQL 注入或备份泄露），可用彩虹表/GPU 高速爆破还原明文口令。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：015.php:65 使用 md5() 对密码做哈希，属弱哈希（CWE-328），无需发送请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 015.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-81919fa4d087`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令哈希可被离线快速破解，导致用户口令泄露与跨系统撞库；由于未加盐，相同口令产生相同哈希，可批量识别弱口令账户。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：md5() 用于口令存储这一安全用途，属实现型弱点，无需 HTTP 污点链即可成立；外部可达性体现在修改密码接口 015.php:3 的 POST 处理路径。

**修复建议**

改用专为口令设计的慢哈希算法（bcrypt/Argon2id/PBKDF2），使用 password_hash()/password_verify() 并配合每用户随机盐与合适的工作因子；对历史 MD5 记录在用户下次登录时透明升级。

**验证说明**

静态证据：入口 POST /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 → 015.php:64 转义 → 015.php:65 md5() 无盐哈希 → 015.php:68 写入 users.password，弱哈希落库。
POC 备注：仅静态证据，不执行、不联网。

### F-5: 密码修改接口无 CSRF token，可跨站强制改密

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

改密流程（step=1/step=2）仅依赖 POST 参数，无任何 anti-CSRF token，也无 Origin/Referer 校验。攻击者可构造自动提交表单，诱导已登录用户访问，从而把其密码改为攻击者已知值。step=2 分支还可直接携带 passed_captcha=true 绕过 CAPTCHA，使 CSRF 更易成功。

**source / sink**

- source：body `*`（015.php）
- sink：015.php:69 第 68-69 行 UPDATE users 改密

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 服务端仅凭 POST 参数执行改密，无 token 校验 | 跨站请求参数 |  |
| 2 | `015.php:55` | passed_captcha 由请求体提供，可伪造 | true |  |
| 3 | `015.php:68` | 执行 UPDATE 修改受害者密码 | 写入攻击者指定密码 |  |

**POC**

针对 /vulnerabilities/captcha/ (015.php)（POST）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-db88415cbc34`
- 风险提示：请求未体现 HTTP 方法 POST, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

账户接管：攻击者将受害者密码改为已知值后登录。

**CVE / CWE 论证**

CWE-352。改密为敏感状态变更且无 token，外部可触发。

**修复建议**

引入每会话 CSRF token 并在服务端校验；校验 Origin/Referer；改密要求重新输入旧密码。

**验证说明**

需确认 DVWA 全局是否已有 CSRF 防护（本文件内未见），以及 SameSite Cookie 配置。
模型 POC 要点：诱导受害者访问含自动提交表单的页面
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:69 的 CSRF POC。密码修改请求无 CSRF token 校验，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-352。漏洞位于 015.php:69，密码修改流程缺少 CSRF token 校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；poc.html 为自动提交表单文本，需在授权环境手动验证。

### F-6: 015.php 修改密码接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:3 在检测到 $_POST['Change'] 与 $_POST['step']=='1' 后即处理状态变更，015.php:8-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf']，整个流程未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造自动提交的表单，诱导已登录受害者在不知情下把口令改为攻击者指定值。

**source / sink**

- source：query `Change`（015.php）
- sink：015.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/015?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-bb70b3793387`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

账户接管：受害者在已登录状态下访问恶意页面即可被静默修改口令，攻击者随后用新口令登录其账户。

**CVE / CWE 论证**

CWE-352：状态改变请求（UPDATE users SET password）无不可预测令牌校验，外部站点可跨站发起，利用链闭合；前提是受害者浏览器携带有效会话。

**修复建议**

为表单引入每会话/每请求的随机 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；修改口令等敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /015；source=query/Change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：恶意页面自动 POST Change=1&step=1&password_new=...&password_conf=... → 015.php:3 通过判断 → 015.php:8-9 读取参数 → 015.php:68-69 更新口令，无令牌校验故请求被接受。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:8 的 CSRF POC。密码修改入口缺少 CSRF token，GET/POST 均可触发状态变更。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。漏洞位于 015.php:8，密码修改流程缺少 CSRF token 校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网；替换 TARGET 后手动在授权环境验证。

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
| `xss` | CWE-79 | 是 | 0 |
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 0 |
| `csrf` | CWE-352 |  | 2 |
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
| `captcha_bypass` | CWE-804 |  | 2 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.43 | 是 |
| surface_mapper | 攻击面测绘 | 9.82 | 是 |
| deep_finder | LLM 深挖 | 11.43 | 是 |
| candidate_screener | 候选筛选 | 7.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.71 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.22 | 是 |
| coordinator | 管线协调 | 8.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
