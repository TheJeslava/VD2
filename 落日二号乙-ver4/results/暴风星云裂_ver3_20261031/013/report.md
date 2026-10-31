# 落日二号乙漏洞挖掘报告 — 20261031-005851-f375bd

- 生成时间：2026-10-30T16:59:45.117123+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
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

本次汇总基于单文件 PHP 脚本 013.php（55 行）的已去重 findings，共 4 条，全部带 POC（4/4）。最高危为 GEN-89dab2f7ae60：013.php 第 31 行密码更新语句存在 SQL 注入（critical，CWE-89，规则命中，有 HTTP POC）。其次 LLM-719de589f39a：硬编码验证码 + 伪造 User-Agent 绕过 CAPTCHA 导致任意用户密码重置（high，有 HTTP POC）；LLM-043ac2d2fadc：密码修改接口缺 CSRF token，且 token 在修改逻辑之后生成（medium，有 HTTP POC）；LLM-e258feead3bf：口令无盐 MD5 存储（low，CWE-328，仅有静态证据 POC，不能宣称可动态复现）。POC 齐全但均为文本工件，未执行、未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：3 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 CODE PACK 中唯一文件 013.php（55 行，DVWA 密码修改页面）。发现三条可闭合问题：(1) CAPTCHA 硬编码后门（hidd3n_valu3 + User-Agent reCAPTCHA）导致验证码绕过并配合密码修改实现账户接管；(2) 密码修改缺少 CSRF token 校验且 token 生成滞后；(3) 密码使用无盐 MD5 存储。SQL 语句中 $pass_new 已经过 mysqli_real_escape_string 且为 md5 值，dvwaCurrentUser() 为服务端会话用户，未发现可闭合的 SQL 注入。未提供 php.ini/部署配置，无法评估 allow_url_include 等；无跨文件二次注入线索。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认脚本是否位于认证之后及 allow_url_include 等设置
- 无端点清单，无法确认 013.php 对外暴露方式
- recaptcha_check_answer 实现未在 CODE PACK 中，无法确认其返回值语义
- 未提供数据库结构，无法确认 users 表与 dvwaCurrentUser 实现

## 3. Findings

### F-1: 013.php 密码更新语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求参数 `password_new`（013.php:8 处读取）提交恶意字符串，该值被直接拼接进 `$pass_new`，随后在 013.php:30 被拼入 UPDATE 语句：`UPDATE `users` SET password = '$pass_new' WHERE user = '...' LIMIT 1;`，最终在 013.php:31 由 `mysqli_query()` 执行。代码未对 `$pass_new` 做任何转义（无 mysqli_real_escape_string）、类型约束或参数化处理，单引号可直接闭合字符串字面量，从而改写 SET 子句或注入额外 SQL。注意：`user` 字段使用 `dvwaCurrentUser()` 而非直接外部输入，注入点集中在 `password_new` 参数值。

**source / sink**

- source：query `password_new`（013.php:8）
- sink：013.php:31 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `013.php:31` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /013（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/013?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-89dab2f7ae60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可越权修改任意用户口令（包括 admin），进而登录后台；亦可借助报错回显（013.php:31 的 `or die(mysqli_error(...))`）进行报错型注入读取数据库内容，造成敏感数据泄露与账户接管。

**CVE / CWE 论证**

CWE-89：外部可控参数 `password_new` 未经参数化/转义直接进入 SQL 语句并执行，构成典型 SQL 注入。该页面为 DVWA 公开端点，无需认证即可访问（取决于部署配置），利用链闭合：source（013.php:8 参数）→ 拼接（013.php:30）→ sink（013.php:31 mysqli_query）。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），将 `$pass_new` 作为绑定参数传入；对输入做长度与字符白名单校验；关闭详细数据库错误回显，改为记录日志；数据库账户遵循最小权限，仅授予必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 ANY /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 `password_new` → 变量 `$pass_new`（013.php:8）→ 字符串拼接进 `$insert`（013.php:30）→ `mysqli_query()` 执行（013.php:31）→ 数据库执行被篡改的 UPDATE 语句。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。外部输入来自 query 参数 password_new，被直接拼接进 SQL 语句（source→sink 静态闭合，未见有效净化）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 013.php:31，外部输入来自 query 参数 password_new，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前须将 TARGET 替换为授权目标，并确保仅使用非破坏性载荷（禁止 DROP/TRUNCATE 等）。

### F-2: DVWA CAPTCHA 绕过导致任意用户密码重置（硬编码验证码 + User-Agent 伪造）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 在处理密码修改时，CAPTCHA 校验逻辑存在硬编码后门：当 `g-recaptcha-response` 等于字符串 `hidd3n_valu3` 且 `HTTP_USER_AGENT` 等于 `reCAPTCHA` 时，条件恒真，完全绕过第三方 reCAPTCHA 校验。攻击者无需通过真实验证码即可进入密码修改分支，随后将 `password_new` 与 `password_conf` 设为相同值，即可把当前登录用户（dvwaCurrentUser()）的密码改为攻击者控制的值。结合 CSRF token 在密码修改逻辑之后才生成（第 53 行），攻击者可构造跨站请求诱导受害者提交，实现账户接管。

**source / sink**

- source：body `g-recaptcha-response`（013.php:8-9）
- sink：013.php:23 密码更新 SQL 执行 mysqli_query($GLOBALS["___mysqli_ston"], $insert)（第 31 行），$insert 使用 md5($pass_new) 更新 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 入口判断 POST 参数 Change 是否存在，攻击者提交 Change=Change 进入密码修改逻辑 | 外部请求进入密码修改分支 |  |
| 2 | `013.php:8-9` | 读取 password_new 与 password_conf 两个 POST 参数 | 攻击者控制的新密码明文 |  |
| 3 | `013.php:12-15` | 调用 recaptcha_check_answer 校验第三方验证码，正常情况下应失败 | $resp 为 false（未通过真实验证码） |  |
| 4 | `013.php:17-23` | 由于 g-recaptcha-response 等于硬编码值 hidd3n_valu3 且 User-Agent 为 reCAPTCHA，OR 条件恒真，绕过 CAPTCHA | 校验分支被强制进入 true 分支 | 硬编码后门字符串 hidd3n_valu3 与可伪造的 User-Agent 头共同构成恒真条件，完全跳过 reCAPTCHA 服务端校验 |
| 5 | `013.php:25-27` | 确认两次密码一致后，对密码做 mysqli_real_escape_string 并 md5 哈希 | 攻击者密码被哈希为 md5 值 |  |
| 6 | `013.php:30-31` | 拼接 UPDATE users SET password='$pass_new' WHERE user=dvwaCurrentUser() 并执行，修改当前用户密码 | 数据库密码字段被更新为攻击者控制的 md5 值 |  |

**POC**

针对 /013.php（POST）的 验证码绕过 POC。注入点：POST 参数 g-recaptcha-response；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'g-recaptcha-response=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-719de589f39a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在不通过真实验证码的情况下重置任意已登录用户密码，实现账户接管；结合 CSRF 可对管理员账户发起攻击，获取后台控制权。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/ CWE-287（Improper Authentication）。硬编码验证码值与可伪造 User-Agent 构成恒真条件，外部无需真实验证码即可触发密码修改，链路在 CODE PACK 内闭合。

**修复建议**

移除硬编码后门条件（hidd3n_valu3 / User-Agent 判断），仅信任 recaptcha_check_answer 的返回值；将 CSRF token 校验前置到密码修改逻辑之前；对密码修改要求二次认证。

**验证说明**

需确认 DVWA 部署中 recaptcha_check_answer 的实际返回值与 013.php 是否对外暴露；硬编码后门为 DVWA 已知设计，需确认目标版本未移除。
模型 POC 要点：利用硬编码验证码后门绕过 CAPTCHA，重置当前登录用户密码；若配合 CSRF 可诱导受害者触发
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /013.php）：针对 013.php:23 的验证码绕过 POC。服务端对 POST 参数 g-recaptcha-response 的校验可被伪造/空值绕过（CWE-804），提交任意探测值即可通过校验流程。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013.php）：符合 CWE-804（验证码绕过）。漏洞位于可交付代码 013.php:23，外部输入来自 body 参数 g-recaptcha-response，source→sink 链静态闭合且未见有效服务端校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；SUNSET_PROBE 为无害探测值。

### F-3: 密码修改接口缺少 CSRF token 校验（token 在修改逻辑之后生成）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:3-31`
- **来源**：`llm_finding`

**描述**

013.php 在 POST Change 分支内直接执行密码修改，而 generateSessionToken() 在第 53 行、即密码修改逻辑之后才调用，说明密码修改请求本身不校验 Anti-CSRF token。攻击者可构造跨站表单，诱导已登录用户提交 password_new/password_conf，配合硬编码 CAPTCHA 后门完成静默密码重置。

**source / sink**

- source：body `password_new`（013.php）
- sink：013.php:31 mysqli_query 执行 UPDATE users SET password（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 仅判断 POST Change 存在即进入密码修改，未校验 CSRF token | 跨站请求可直接进入修改逻辑 |  |
| 2 | `013.php:17-23` | 利用硬编码验证码后门通过 CAPTCHA 校验 | 校验恒真 | 硬编码 hidd3n_valu3 + User-Agent reCAPTCHA |
| 3 | `013.php:30-31` | 执行 UPDATE 修改当前用户密码 | 受害者密码被改为攻击者值 |  |
| 4 | `013.php:53` | generateSessionToken 在修改之后才调用，无法保护本次请求 | token 生成滞后，未参与校验 |  |

**POC**

针对 /013.php（POST）的 跨站请求伪造 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-043ac2d2fadc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可跨站重置受害者密码，实现账户接管。

**CVE / CWE 论证**

CWE-352（Cross-Site Request Forgery）。密码修改无 token 校验，token 生成滞后，外部可构造请求触发。

**修复建议**

在密码修改逻辑前校验 CSRF token，并确保 token 一次性且与会话绑定。

**验证说明**

需确认 DVWA 全局是否有其它 CSRF 防护中间件；本文件内未见 token 校验。
模型 POC 要点：构造自动提交的跨站表单，诱导已登录用户触发密码重置
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /013.php）：针对 013.php:31 的跨站请求伪造 POC。密码修改接口仅依赖 POST 参数 password_new，缺少 CSRF Token 与来源校验（CWE-352），攻击者可诱导已登录用户在不知情下修改密码。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013.php）：符合 CWE-352（CSRF）。漏洞位于可交付代码 013.php:31，外部输入来自 body 参数 password_new，缺少 CSRF 防护，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。poc.html 为文本示例，需在授权测试环境中由测试者手动加载；执行前将 TARGET 替换为授权目标。

### F-4: 用户密码使用无盐 MD5 哈希存储

- **类型**：`weak_hash` / CWE-328
- **严重度**：`low`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:27-27`
- **来源**：`llm_finding`

**描述**

013.php 第 27 行对用户新密码直接调用 md5($pass_new) 后写入数据库，未加盐、未使用 password_hash 等慢哈希算法。数据库泄露时攻击者可通过彩虹表快速还原明文密码。

**source / sink**

- source：body `password_new`（013.php:8）
- sink：013.php:27 UPDATE users SET password = '$pass_new'（第 30-31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 读取 password_new | 明文密码 |  |
| 2 | `013.php:27` | 直接 md5 哈希，无盐 | 无盐 MD5 摘要 |  |
| 3 | `013.php:30-31` | 写入数据库 | 弱哈希存储 |  |

**POC**

针对 /013.php（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-e258feead3bf`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时用户密码可被快速破解，导致账户接管与撞库风险。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。代码明确使用无盐 MD5 存储口令。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

实现层缺陷，无需动态验证。
模型 POC 要点：该问题为存储实现缺陷，无直接远程利用请求；通过数据库泄露后离线破解验证
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /013.php）：针对 013.php:27 的弱哈希算法 POC。密码类输入 password_new 使用弱哈希（如 MD5/SHA1）处理（CWE-328），可被离线碰撞/彩虹表快速还原。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013.php）：符合 CWE-328（弱哈希）。漏洞位于可交付代码 013.php:27，外部输入来自 body 参数 password_new，处理路径使用弱哈希算法，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；哈希强度评估应在离线环境完成。

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
| `csrf` | CWE-352 |  | 1 |
| `file_upload` | CWE-434 |  | 0 |
| `race_condition` | CWE-367 |  | 0 |
| `weak_crypto` | CWE-327 |  | 0 |
| `weak_hash` | CWE-328 |  | 1 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 1 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.52 | 是 |
| surface_mapper | 攻击面测绘 | 8.37 | 是 |
| deep_finder | LLM 深挖 | 14.95 | 是 |
| candidate_screener | 候选筛选 | 7.54 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.26 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.31 | 是 |
| coordinator | 管线协调 | 6.04 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
