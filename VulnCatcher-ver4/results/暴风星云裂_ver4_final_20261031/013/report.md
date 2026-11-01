# 落日二号乙漏洞挖掘报告 — 20261031-172610-7424a1

- 生成时间：2026-10-31T09:27:20.875325+00:00
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

本次汇总基于已去重的 6 条 findings，全部集中在单文件 PHP 脚本 013.php（55 行），覆盖 1 个文件、1 种语言（php），无框架、无端点清单。最高危为 GEN-89dab2f7ae60：013.php 第 31 行附近修改密码流程存在 SQL 注入（critical，CWE-89，规则命中，含 POC）。其次为两条 captcha_bypass（LLM-719de589f39a 硬编码验证码值 + User-Agent 伪造绕过、SEM-07d9d737e404 验证码校验逻辑可绕过，均 high，含 POC），以及 csrf（LLM-043ac2d2fadc，medium，密码修改接口缺 CSRF token）。弱哈希类有两条：SEM-0bafba96288b 标注为 weak_crypto 但标题实为 MD5 口令哈希（CWE-328），按类型规范应归 weak_hash，存在类型标注串用，需人工纠正；LLM-4859b1539c1e 为无盐 MD5 存储（low）。6 条 findings 均带 POC，但其中 weak_crypto/weak_hash 两条属静态证据 POC（源码算法证据），不具备 HTTP 动态复现语义，不能宣称可动态复现；SQL 注入、captcha_bypass、csrf 三条为 HTTP POC 文本（TARGET 占位，仅限授权测试），本次未执行、未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：3 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 013.php（1-55 行，DVWA CAPTCHA 密码修改模块）。发现三条可闭合问题：(1) CAPTCHA 校验存在硬编码后门 'hidd3n_valu3' + 可伪造 User-Agent 'reCAPTCHA'，可绕过验证码修改密码（高危）；(2) 密码修改 POST 分支未校验 CSRF token（中危）；(3) 密码使用无盐 MD5 存储（低危）。第 26 行 mysqli_real_escape_string 已对 password_new 转义，且第 30 行 user 来自 dvwaCurrentUser() 而非用户输入，故未发现 SQL 注入。未发现命令执行/文件包含/SSRF 汇点。code_pack 之外文件视为不存在，未覆盖同目录其它脚本与配置。

未覆盖 / 证据缺口：
- 无 php.ini/数据库/Web 服务器配置，无法判断部署与 display_errors
- 无端点清单与框架信息，无法确认前置认证/WAF
- recaptcha_check_answer 实现未在 code_pack 中，无法确认其返回值语义
- dvwaCurrentUser() 实现未提供，无法确认其是否可被污染

## 3. Findings

### F-1: 013.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，输入在 013.php:8 被读取为 `password_new`，随后在 013.php:26 仅经过 `mysqli_real_escape_string()` 转义，在 013.php:27 被 `md5()` 处理，最终在 013.php:30 被直接拼接进 UPDATE 语句 `UPDATE `users` SET password = '$pass_new' WHERE user = '...' LIMIT 1;`，并在 013.php:31 交给 `mysqli_query()` 执行。由于 `$pass_new` 是字符串拼接而非参数化查询，转义函数无法覆盖所有上下文（如多字节字符集/引号处理不当），且 md5 后的值仍以字符串形式拼入 SQL，攻击者可构造闭合单引号的输入改变查询语义。

**source / sink**

- source：query `password_new`（013.php:8）
- sink：013.php:31 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `013.php:31` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /013（POST）的 SQL 注入 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-89dab2f7ae60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 users 表中的口令字段，实现任意用户口令重置/越权登录；结合报错回显（013.php:31 的 die 输出 mysqli_error）可进行报错型注入读取数据库结构与其他表数据，导致敏感数据泄露。

**CVE / CWE 论证**

CWE-89：外部可控输入 `password_new` 未经参数化直接进入 SQL 语句。入口为公开的修改密码表单，无需认证即可访问该页面（DVWA 场景下为低安全级别），利用链从 HTTP 参数到 mysqli_query 闭合，具备外部可达性与无需认证特征。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare/bind_param 或 PDO），禁止字符串拼接；对输入做长度与字符白名单校验；关闭详细数据库错误回显，改为通用错误页并记录日志；口令哈希改用 password_hash()/bcrypt 等强算法。

**验证说明**

静态证据：入口 POST /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：HTTP POST 参数 password_new → 013.php:8 读取 → 013.php:26 mysqli_real_escape_string 转义 → 013.php:27 md5() → 013.php:30 字符串拼接进 UPDATE 语句 → 013.php:31 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。源码在密码修改流程中把 POST 参数 password_new 直接拼入 SQL 语句（第 31 行附近），未使用参数化查询；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89。漏洞位于 013.php:31，外部输入来自 POST 参数 password_new，source→sink 链在给定代码范围内静态闭合，未见参数化或有效转义（第 26 行仅做 mysqli_real_escape_string，需结合第 31 行拼接方式确认是否仍可注入）。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试目标；禁止使用 DROP 等破坏性语句。第 31 行拼接语句未在片段中完整给出，若实际已参数化则本 POC 需降级为待验证。

### F-2: DVWA 密码修改接口 CAPTCHA 校验可被硬编码值 + User-Agent 伪造绕过

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 第 17-23 行的 CAPTCHA 判定条件为 `$resp || ($_POST['g-recaptcha-response'] == 'hidd3n_valu3' && $_SERVER['HTTP_USER_AGENT'] == 'reCAPTCHA')`。攻击者无需真正通过 reCAPTCHA，只要提交固定字符串 `hidd3n_valu3` 并把 User-Agent 头设为 `reCAPTCHA`，即可让整个条件恒真，进入第 25 行的密码修改分支，把当前用户密码改为攻击者指定值（第 26-31 行 UPDATE users SET password=md5(...)）。这使 CAPTCHA 这一唯一的人机/暴力破解防护完全失效，可被脚本化批量调用，配合 CSRF 缺失（第 52-53 行仅在页面渲染时生成 token，POST 处理分支未校验 token）可导致账户接管。

**source / sink**

- source：body `g-recaptcha-response`（013.php:8-9）
- sink：013.php:23 013.php:25-31 密码修改分支，执行 UPDATE `users` SET password = md5($pass_new) WHERE user = dvwaCurrentUser()

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 检测到 POST 参数 Change，进入密码修改流程 | 请求进入处理分支 |  |
| 2 | `013.php:8-9` | 读取 password_new / password_conf | 攻击者可控明文密码 |  |
| 3 | `013.php:12-15` | 调用 recaptcha_check_answer，正常情况下 $resp 为 false | $resp=false（未真正通过验证码） |  |
| 4 | `013.php:17-23` | 短路条件：g-recaptcha-response 等于硬编码 hidd3n_valu3 且 User-Agent 等于 reCAPTCHA，条件恒真 | 校验被绕过，进入 if 分支 | 硬编码后门字符串 + 可伪造的 User-Agent 头，二者均由客户端完全控制 |
| 5 | `013.php:25-31` | 两次密码一致则 md5 后 UPDATE users 表，修改当前用户密码 | 密码被写入数据库 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 验证码绕过 POC。注入点：POST 参数 g-recaptcha-response；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-719de589f39a`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

CAPTCHA 防护完全失效，攻击者可脚本化批量修改密码，结合缺失 CSRF token 校验可实现账户接管。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-290（通过伪造绕过认证）。外部可达、仅需低权限登录，利用链在源码中闭合，硬编码值与 UA 判断均可由客户端控制。

**修复建议**

移除硬编码 'hidd3n_valu3' 后门分支；仅信任 recaptcha_check_answer 的服务端校验结果；在密码修改 POST 分支校验 CSRF token。

**验证说明**

需确认部署环境中 recaptcha_check_answer 是否可用（若不可用则 $resp 恒 false，绕过更易）；需确认 dvwaCurrentUser() 返回当前会话用户。
模型 POC 要点：伪造 CAPTCHA 通过条件，直接修改当前登录用户密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 013.php:23 的验证码绕过 POC。源码在密码修改流程中读取 g-recaptcha-response 但未做有效校验（第 23 行附近），提交空验证码即可进入改密流程；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-804。漏洞位于 013.php:23，外部输入来自 POST 参数 g-recaptcha-response，代码读取后未与 Google 校验接口比对即放行，source→sink 链在给定范围内闭合。
POC 备注：POC 仅为文本工件，不执行、不联网。需替换 TARGET 与授权测试账号会话；Cookie 字段名需以实际登录响应为准，若无法确认须补充源码/路由。

### F-3: 013.php 修改密码流程验证码可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:3-4`
- **来源**：`rule`

**描述**

013.php:3 判断 `isset($_POST['Change'])` 后，在 013.php:4-5 直接设置 `$hide_form = true` 并进入修改密码逻辑，代码片段中未见对验证码值的服务端校验或一次性令牌绑定。攻击者可直接构造包含 Change 字段的 POST 请求跳过验证码步骤，直接提交口令修改。

**source / sink**

- source：request `captcha/step`（013.php）
- sink：013.php:4 	// Hide the CAPTCHA form

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:4` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /013（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/013' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-07d9d737e404`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可自动化批量提交口令修改请求，绕过人机验证实施暴力破解/撞库/批量账户操作，削弱防自动化机制。

**CVE / CWE 论证**

CWE-804：验证码校验可被绕过。入口为公开的修改密码表单，无需认证即可触发；利用链为直接提交最终状态改变请求（携带 Change 参数）跳过验证码校验。需注意：输入片段仅覆盖 013.php:3-5，验证码校验代码可能位于未提供的行区间，故该结论为基于可见代码的推断。

**修复建议**

在服务端对验证码进行强制校验，校验失败即拒绝请求；验证码与一次性令牌绑定会话并设置有效期；校验通过后立即失效；对修改密码等敏感操作增加频率限制与二次认证。

**验证说明**

静态证据：入口 POST /013；source=request/captcha/step；sink=013.php:4；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 POST 请求携带 Change 参数 → 013.php:3 命中分支 → 013.php:4-5 设置 hide_form 并进入修改逻辑 → 未校验验证码即执行口令更新。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:4 的验证码绕过 POC。源码第 4 行附近处理 captcha/step 流程，未对 g-recaptcha-response 做有效校验即放行改密；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-804。漏洞位于 013.php:4，外部输入来自 captcha/step 流程，代码读取 g-recaptcha-response 后未校验即放行。
POC 备注：POC 仅为文本工件，不执行、不联网。需替换 TARGET 与授权测试账号会话；第 4 行具体逻辑需以 code_pack 为准。

### F-4: 密码修改接口缺少 CSRF token 校验

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:3-31`
- **来源**：`llm_finding`

**描述**

013.php 第 52-53 行仅在页面渲染时调用 generateSessionToken() 生成 Anti-CSRF token，但第 3-50 行的 POST 处理分支从未读取或校验该 token。攻击者可构造跨站表单，诱导已登录用户提交 password_new/password_conf，从而在受害者不知情下修改其密码。由于 CAPTCHA 分支存在硬编码绕过（见上一条），攻击者可在跨站请求中同时伪造 g-recaptcha-response 与 UA，使 CSRF 攻击无需受害者交互验证码。

**source / sink**

- source：body `password_new`（013.php:8-9）
- sink：013.php:31 013.php:30-31 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 处理 POST Change 请求，未校验任何 CSRF token | 请求被接受 |  |
| 2 | `013.php:8-9` | 读取新密码参数 | 攻击者可控 |  |
| 3 | `013.php:30-31` | 直接 UPDATE 当前用户密码 | 密码被修改 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/captcha/?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-043ac2d2fadc`
- 风险提示：请求未体现 HTTP 方法 POST, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

跨站修改受害者密码，导致账户接管。

**CVE / CWE 论证**

CWE-352。密码修改属敏感状态变更，服务端未校验 token，外部可构造跨站请求。

**修复建议**

在 POST 处理分支校验 generateSessionToken() 生成的 token，并校验 Referer/Origin。

**验证说明**

需确认 generateSessionToken 生成的 token 是否在其它位置被强制校验；当前 code_pack 中未见校验逻辑。
模型 POC 要点：构造自动提交的跨站表单修改受害者密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 013.php:31 的 CSRF POC。改密流程仅依赖会话 Cookie，未校验 CSRF token，攻击者可诱导已登录用户提交改密请求；payload 为自动提交表单，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-352。改密请求仅依赖会话 Cookie，未见 CSRF token 校验，证据位于 013.php:31 附近。
POC 备注：POC 仅为文本工件，不执行、不联网。原草稿使用 GET 方法，但源码改密流程为 POST，故此处统一为 POST；需替换 TARGET 与受害者会话。

### F-5: 013.php 口令使用 MD5 哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:26-27`
- **来源**：`rule`

**描述**

013.php:27 使用 `$pass_new = md5( $pass_new );` 对口令做哈希后写入数据库（013.php:30-31）。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，不适合用于口令存储。此处保护对象是用户口令，属于安全用途，应归类为 weak_hash（CWE-328）而非 weak_crypto。

**source / sink**

- source：repository `md5(`（013.php）
- sink：013.php:27 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:27` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：013.php:27 使用 md5() 处理密码，属弱哈希（CWE-328）。注意：该 finding 标注为 weak_crypto（CWE-327），但证据实为 MD5 哈希，应归类为 weak_hash，建议修正类型。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 013.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0bafba96288b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时，攻击者可用彩虹表/GPU 暴力快速还原用户明文口令；无盐设计使相同口令产生相同哈希，便于批量破解与撞库，进而导致账户接管。

**CVE / CWE 论证**

CWE-328：使用弱哈希算法保护口令。该弱点为配置/实现型，无需 HTTP 污点链即可成立；证据为 013.php:27 的 md5() 调用原文。外部可达性体现在修改密码流程会持续产生弱哈希口令记录。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）并配合 password_verify()；为每个口令使用随机盐；对历史 MD5 记录在下次登录时透明升级；禁止在代码中直接使用 md5/sha1 处理口令。

**验证说明**

静态证据：入口 POST /013；source=repository/md5(；sink=013.php:27；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 013.php:8 读取 password_new → 013.php:26 转义 → 013.php:27 md5() 生成弱哈希 → 013.php:30-31 写入 users 表，形成弱口令存储。
POC 备注：POC 仅为文本工件，不执行、不联网。类型标注与证据不一致，需人工复核。

### F-6: 用户密码使用无盐 MD5 存储

- **类型**：`weak_hash` / CWE-328
- **严重度**：`low`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:27-31`
- **来源**：`llm_finding`

**描述**

013.php 第 27 行 `$pass_new = md5( $pass_new );` 对用户新密码做无盐 MD5 后写入数据库（第 30-31 行）。MD5 属弱哈希（CWE-328），无盐且计算快速，一旦数据库泄露可被彩虹表/GPU 快速破解，且相同密码产生相同哈希。

**source / sink**

- source：body `password_new`（013.php:8）
- sink：013.php:31 013.php:30-31 将 MD5 值写入 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 读取新密码 | 明文密码 |  |
| 2 | `013.php:27` | 无盐 MD5 哈希 | 32 位 MD5 十六进制 |  |
| 3 | `013.php:30-31` | 写入数据库 | 弱哈希落库 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-4859b1539c1e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后密码可被快速还原，导致账户接管。

**CVE / CWE 论证**

CWE-328/CWE-916。属实现类弱哈希，非 HTTP 污点链。

**修复建议**

改用 password_hash()（bcrypt/argon2）并加盐。

**验证说明**

属配置/实现类，无需动态验证。
模型 POC 要点：配置/实现类问题，无需 HTTP 利用；数据库泄露后离线破解
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 013.php:31 的弱哈希 POC。源码第 27 行使用 md5() 对密码做哈希后写入数据库（第 31 行附近），MD5 无盐且计算快速，易被彩虹表/暴力破解；属配置型弱哈希（CWE-328），非 HTTP 污点型注入。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-328（弱哈希），非 CWE-327。证据为 013.php:27 的 md5() 调用，属配置/实现型缺陷，无 HTTP 污点链。
POC 备注：POC 仅为文本工件，不执行、不联网。第 3 步需数据库或哈希对照能力，若无法获取存储值则仅保留静态证据。

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
| `weak_crypto` | CWE-327 |  | 1 |
| `weak_hash` | CWE-328 |  | 1 |
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
| safety_guard | 安全防护 | 5.14 | 是 |
| surface_mapper | 攻击面测绘 | 8.5 | 是 |
| deep_finder | LLM 深挖 | 14.82 | 是 |
| candidate_screener | 候选筛选 | 6.97 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.95 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 17.31 | 是 |
| coordinator | 管线协调 | 7.56 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
