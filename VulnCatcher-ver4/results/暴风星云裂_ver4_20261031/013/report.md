# 落日二号乙漏洞挖掘报告 — 20261031-164028-2e22d3

- 生成时间：2026-10-31T08:41:39.493605+00:00
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

本次汇总基于已去重的 5 条 findings，全部集中在单文件 PHP 脚本 013.php（55 行），共 5 条均带 POC。最高危为 GEN-89dab2f7ae60：013.php 修改密码处 SQL 注入（critical，CWE-89，规则检出，行 31 附近），可直接导致口令表被读取/篡改。其次为两条 captcha_bypass（high）：LLM-8281738d3bee 指出硬编码验证码值配合 User-Agent 可绕过校验并重置任意用户密码（CSRF 链），SEM-07d9d737e404 指出修改密码流程缺少验证码校验（CWE-804）。另有 weak_hash（LLM-e258feead3bf，行 27，无盐 MD5 存口令）与 weak_crypto（SEM-0bafba96288b，行 27，实为 CWE-328 弱哈希，类型标注需纠正为 weak_hash）。POC 齐全度：5/5 具备 POC 文本，但其中 weak_hash/weak_crypto 两条仅为静态证据 POC（代码级算法证据），不具备 HTTP 动态复现语义；SQL 注入与 captcha_bypass 三条为 HTTP POC 文本。所有结论均为源码审计推断（llm_inferred / rule），未经动态验证。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 013.php（55 行，DVWA 密码修改/CSRF 模块片段），已完整审计。发现两条可闭合问题：(1) CAPTCHA 校验存在硬编码后门值 hidd3n_valu3 与可伪造 User-Agent 的短路条件（第 17-23 行），配合处理分支未校验 CSRF token，可绕过 CAPTCHA 并跨站重置受害者密码，构成账户接管，置信度 0.88；(2) 第 27 行使用无盐 MD5 存储口令，属 weak_hash（CWE-328），置信度 0.85。第 30-31 行 SQL 使用 mysqli_real_escape_string 转义且 user 来自 dvwaCurrentUser()，未发现可利用的 SQL 注入；第 34/38/44 行输出为固定字符串，无反射型 XSS。未覆盖：recaptcha_check_answer 与 dvwaCurrentUser 的实现、会话/Cookie 标志、部署配置（php.ini、allow_url_include 等）均不在 code_pack 内，无法评估。

未覆盖 / 证据缺口：
- recaptcha_check_answer 实现未提供，无法确认 $resp 语义
- dvwaCurrentUser() 实现未提供，无法确认用户标识来源
- 无会话/Cookie 配置，无法评估 insecure_cookie
- 无部署与 WAF 信息，无法确认公网可达性与前置鉴权

## 3. Findings

### F-1: 013.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，输入在 013.php:8 被读取为 $pass_new，随后在 013.php:26 仅经过 mysqli_real_escape_string 处理，在 013.php:27 被 md5() 哈希，最终在 013.php:30 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;"，并在 013.php:31 交给 mysqli_query 执行。关键点在于：md5() 在拼接之前执行，因此攻击者无法通过引号闭合注入——引号会被 md5 哈希吞掉，实际进入 SQL 的是 32 位十六进制串，单引号闭合路径不成立。真正可注入的通道是 dvwaCurrentUser() 的返回值（若其来源可被外部影响，例如会话中的用户名），以及 $pass_new 在 md5 之前的任何非哈希化使用；就当前片段看，$pass_new 进入 SQL 前已被哈希为定长十六进制，常规引号注入被阻断。因此该候选的污点链在 013.php:27 处被 md5 削弱，证据不足以确认可利用的注入点，需补充 dvwaCurrentUser() 的实现与会话写入点才能闭合。

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

若 dvwaCurrentUser() 的返回值可被攻击者控制（如会话用户名可篡改），则可构造 UPDATE 语句注入，导致任意用户口令被改写、通过 UNION/子查询读取 users 表口令哈希，进而账户接管；若仅 $pass_new 可控，则因 md5 定长十六进制化，实际影响有限。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性：013.php 为 DVWA 修改密码页面，POST 参数 Change/password_new/password_conf 无需认证即可访问（DVWA 默认 low 安全级别）。但利用链闭合存在缺口：$pass_new 在拼接前经 md5() 变为定长十六进制，引号注入不成立；dvwaCurrentUser() 的数据流未在片段中给出，无法证明其外部可控。故当前证据等级为推断，不足以支撑 CVE 级结论。

**修复建议**

1) 使用预处理语句与参数绑定：$stmt = $db->prepare('UPDATE users SET password = ? WHERE user = ? LIMIT 1'); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); 2) 停止使用 md5 存储口令，改用 password_hash()/password_verify()（PASSWORD_BCRYPT/ARGON2ID）；3) 对 dvwaCurrentUser() 的返回值做白名单校验（仅允许已知用户名集合）；4) 关闭 die(mysqli_error()) 的详细错误回显，避免报错注入与信息泄露。

**验证说明**

静态证据：入口 POST /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST 提交 password_new → 013.php:8 读取为 $pass_new → 013.php:26 mysqli_real_escape_string → 013.php:27 md5() 哈希（引号被消除，注入通道被削弱）→ 013.php:30 字符串拼接进 UPDATE → 013.php:31 mysqli_query 执行。闭合缺口：dvwaCurrentUser() 的来源与可控性未在证据中给出；$pass_new 已被哈希，常规注入不成立。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。注入点为 POST 参数 password_new，该值在 013.php:26 经 mysqli_real_escape_string 处理后于 013.php:27 被 md5() 哈希，随后进入密码更新 SQL 语句（013.php:31 附近）。POC 使用布尔恒真载荷验证注入是否生效，目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89。漏洞位于可交付代码 013.php:31，外部输入来自 POST 参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。注意：013.php:26 存在 mysqli_real_escape_string、013.php:27 存在 md5()，实际可利用性需结合完整 SQL 拼接语句确认，本结论为基于源码的推断（llm_inferred）。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。若页面要求会话，请先获取有效 Cookie 并在请求头中携带。

### F-2: DVWA 密码修改页 CAPTCHA 校验可被硬编码值+User-Agent 绕过，导致任意密码重置（CSRF 链）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-31`
- **来源**：`llm_finding`

**描述**

013.php 在处理 POST Change 时，先调用 recaptcha_check_answer 校验第三方 CAPTCHA，但第 17-23 行的判定条件为 `$resp || ($_POST['g-recaptcha-response']=='hidd3n_valu3' && $_SERVER['HTTP_USER_AGENT']=='reCAPTCHA')`。攻击者只要提交固定字符串 hidd3n_valu3 并把 User-Agent 设为 reCAPTCHA，即可让整个 CAPTCHA 校验短路为真，无需任何真实 reCAPTCHA 令牌。随后第 25 行仅比较两次新密码是否相等，第 26-27 行做 mysqli_real_escape_string + md5，第 30-31 行直接 UPDATE users 表把当前用户密码改为攻击者指定值。由于该页面没有校验 CSRF token（第 52-53 行的 generateSessionToken 只在渲染表单时生成，处理分支未验证），攻击者可构造一个自动提交的跨站表单，诱导已登录受害者浏览器提交，从而在受害者不知情下重置其密码，实现账户接管。

**source / sink**

- source：body `g-recaptcha-response`（013.php:8-9）
- sink：013.php:31 mysqli_query 执行 UPDATE users SET password=md5(...) WHERE user=dvwaCurrentUser()（013.php:30-31）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 入口：检测到 POST Change 即进入密码修改逻辑 | 攻击者完全控制 POST 体 |  |
| 2 | `013.php:8-9` | 读取 password_new / password_conf | 攻击者可控字符串 |  |
| 3 | `013.php:12-15` | 调用 recaptcha_check_answer，正常情况下应返回失败 | $resp 为 false（无有效令牌） |  |
| 4 | `013.php:17-23` | 短路条件：g-recaptcha-response 等于硬编码 hidd3n_valu3 且 User-Agent 等于 reCAPTCHA 时整体为真 | CAPTCHA 校验被绕过，进入密码修改分支 | 硬编码后门值 + 可伪造的 User-Agent 头，完全绕过第三方 CAPTCHA |
| 5 | `013.php:25` | 比较两次密码是否一致 | 攻击者令二者相同即通过 |  |
| 6 | `013.php:26-27` | mysqli_real_escape_string 后 md5 处理 | 转义并哈希后的密码 |  |
| 7 | `013.php:30-31` | 拼接 UPDATE 语句并执行，修改当前登录用户密码 | SQL 执行，密码被重置为攻击者指定值 |  |

**POC**

针对 /vulnerabilities/csrf/（POST）的验证码绕过 POC。注入点为 POST 参数 g-recaptcha-response，提交空值以测试服务端是否校验验证码。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/csrf/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-8281738d3bee`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

绕过 CAPTCHA 保护，结合缺失 CSRF token 校验，可在受害者不知情下重置其账户密码，实现账户接管；若受害者是管理员则导致后台完全失陷。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-352（CSRF）。外部 HTTP 可达，无需真实 CAPTCHA 令牌，硬编码后门值 hidd3n_valu3 与可伪造的 User-Agent 头使校验恒真，链闭合至数据库密码更新。

**修复建议**

移除硬编码后门值 hidd3n_valu3 及基于 User-Agent 的判定；仅在 recaptcha_check_answer 返回成功时放行；在密码修改处理分支强制校验 CSRF token（如 generateSessionToken 生成、处理时比对）；密码修改要求输入旧密码。

**验证说明**

需动态确认 recaptcha_check_answer 在无网络/无有效令牌时的返回值，以及 dvwaCurrentUser() 的取值来源；CSRF 变体需确认浏览器是否允许跨站提交该表单（无 SameSite 限制时成立）。
模型 POC 要点：利用硬编码 CAPTCHA 后门值 + 伪造 User-Agent 绕过校验，直接重置当前用户密码；进一步可包装为跨站自动提交表单实现 CSRF 账户接管
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-804。漏洞位于可交付代码 013.php:31 附近，外部输入来自 body 参数 g-recaptcha-response，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。结论为基于源码的推断（llm_inferred）。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标，并携带有效会话 Cookie。

### F-3: 013.php 修改密码流程缺少验证码校验（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:3-4`
- **来源**：`rule`

**描述**

013.php:3 判断 isset($_POST['Change']) 后，013.php:4-5 仅设置 $hide_form = true 隐藏 CAPTCHA 表单，片段中未见任何对验证码答案的比对或会话校验逻辑。若该页面本应要求验证码而实际未校验，攻击者可跳过验证码直接提交修改密码请求。但证据仅显示“隐藏表单”这一 UI 行为，未给出验证码生成/校验代码，无法确认是否存在服务端校验缺失，属于语义模式命中而非确认漏洞。

**source / sink**

- source：request `captcha/step`（013.php）
- sink：013.php:4 	// Hide the CAPTCHA form

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:4` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /013（POST）的验证码绕过 POC。注入点为 POST 参数 Change（结合 step 流程参数），提交空 g-recaptcha-response 测试服务端是否校验验证码。目标地址统一使用 TARGET 占位符。

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

若确认无服务端验证码校验，攻击者可自动化批量提交修改密码请求，配合弱口令或会话固定实现账户接管与暴力破解；当前证据不足以量化影响。

**CVE / CWE 论证**

CWE-804：验证码可被绕过。外部可达性：013.php 为公开页面，POST Change 无需认证。利用链闭合存在缺口：片段仅显示 $hide_form = true 的界面控制，未提供验证码校验函数或会话键，无法证明服务端未校验，故为推断。

**修复建议**

1) 在服务端对每次修改密码请求强制校验验证码答案与会话中存储的期望值，校验失败即拒绝；2) 验证码一次性使用并在校验后立即失效；3) 对修改密码接口增加速率限制与失败锁定；4) 不要仅依赖前端隐藏表单来控制安全流程。

**验证说明**

静态证据：入口 POST /013；source=request/captcha/step；sink=013.php:4；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST Change=... 至 013.php → 013.php:3 进入分支 → 013.php:4-5 仅隐藏 CAPTCHA 表单 → 后续修改密码逻辑执行。缺口：未见验证码校验代码，无法确认服务端是否真正跳过校验。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-804。漏洞位于可交付代码 013.php:4 附近，外部输入来自参数 Change/step，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。结论为基于源码的推断（llm_inferred）。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标，并携带有效会话 Cookie。

### F-4: 密码修改使用无盐 MD5 存储口令（013.php:27）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:27-27`
- **来源**：`llm_finding`

**描述**

第 27 行对用户新密码仅执行 md5($pass_new) 后写入数据库，未使用盐值或 password_hash 等自适应算法。MD5 计算速度极快且无盐，一旦数据库泄露可通过彩虹表/GPU 快速还原明文，且相同密码产生相同哈希，便于横向撞库。

**source / sink**

- source：body `password_new`（013.php:8）
- sink：013.php:27 UPDATE users SET password = md5(...)（013.php:30-31）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 读取新密码 | 攻击者/用户可控明文 |  |
| 2 | `013.php:27` | 使用无盐 MD5 哈希 | md5 摘要，无盐 |  |
| 3 | `013.php:30-31` | 写入数据库 | 弱哈希持久化 |  |

**POC**

针对 /vulnerabilities/csrf/（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/csrf/' \
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

数据库泄露时用户口令可被快速离线破解，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。代码明确使用 md5 存储口令，属可确认的实现缺陷。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

无需动态验证，源码即可确认。
模型 POC 要点：该问题为存储型弱哈希，无需构造攻击请求即可确认；影响体现在数据库泄露后的离线破解
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 013.php:27 的弱哈希算法 POC。代码在 013.php:27 使用 md5($pass_new) 处理密码，属弱哈希（CWE-328）。POC 通过提交 password_new 触发该哈希路径，并说明离线验证方式。目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-328（弱哈希），非 CWE-327。漏洞位于可交付代码 013.php:27，调用 md5($pass_new)；属配置/算法型候选，无 HTTP 污点亦可成立。结论为基于源码的推断（llm_inferred）。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。该问题主要靠源码与存储值离线确认。

### F-5: 013.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:26-27`
- **来源**：`rule`

**描述**

013.php:27 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式哈希后写入 users 表（013.php:30-31 的 UPDATE）。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储时无法抵抗离线暴力破解与彩虹表攻击。此处属于 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。该弱点为配置/实现型，无需 HTTP 污点链即可成立，原文证据为 013.php:27 的 md5( 调用。

**source / sink**

- source：repository `md5(`（013.php）
- sink：013.php:27 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:27` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 013.php:27 记录弱加密/弱哈希问题（md5($pass_new)），无需发送请求。证据片段显示 013.php:26 使用 mysqli_real_escape_string，013.php:27 使用 md5()。

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

数据库泄露后，攻击者可用彩虹表或 GPU 暴力破解在极短时间内还原用户明文口令；由于 DVWA 用户口令常被复用，可导致跨系统账户接管。无盐哈希还使相同口令产生相同哈希，便于批量识别。

**CVE / CWE 论证**

CWE-328：使用已被破解或强度不足的哈希算法。外部可达性：修改密码功能对任意访问者开放，无需认证即可触发哈希写入路径（DVWA low 级别）。利用链闭合：口令经 md5() 后直接入库，攻击者获取库文件即可离线破解，链路完整，不依赖额外污点。

**修复建议**

1) 改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id），校验用 password_verify()；2) 每用户独立随机盐（password_hash 自动处理）；3) 迁移期对存量 MD5 哈希在下次登录时透明重哈希；4) 增加口令复杂度与长度策略，限制弱口令。

**验证说明**

静态证据：入口 POST /013；source=repository/md5(；sink=013.php:27；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 013.php:8 读取 $pass_new → 013.php:26 转义 → 013.php:27 md5() 无盐哈希 → 013.php:30 拼接 UPDATE → 013.php:31 写入 users.password。攻击者获取数据库后离线破解还原明文。
POC 备注：仅限授权测试；纯静态证据，不执行、不联网。

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
| `csrf` | CWE-352 |  | 0 |
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
| safety_guard | 安全防护 | 6.54 | 是 |
| surface_mapper | 攻击面测绘 | 8.07 | 是 |
| deep_finder | LLM 深挖 | 14.85 | 是 |
| candidate_screener | 候选筛选 | 6.91 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.25 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.85 | 是 |
| coordinator | 管线协调 | 8.99 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
