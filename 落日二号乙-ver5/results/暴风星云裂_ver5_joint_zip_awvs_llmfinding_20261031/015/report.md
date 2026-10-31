# 落日二号乙漏洞挖掘报告 — 20261031-214206-cbf507

- 生成时间：2026-10-31T13:43:15.569384+00:00
- 输入：`$WORKSPACE\暴风星云裂\015.zip`
- 输入模式：`zip`
- SHA256：`24ec46248538ba08d8e8eb94c82934ecea9f754341b0de0a93fec8dda6a387c2`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于单文件 PHP 项目 015.php（83 行）的已去重 findings，共 6 条，全部带 POC（6/6）。最高危为 015.php:69 修改密码处的 SQL 注入（GEN-c00a42452f04，critical，CWE-89），污点路径短、利用门槛低，属本次首要处置项。其次为两条验证码绕过（LLM-795a4853ea15 与 SEM-2b846713ecdc，high，CWE-804），二者描述同一 step 状态机缺陷，建议合并为一条修复项处理。中危包括无盐 MD5 口令存储（LLM-1c448a06ff3b 与 SEM-81919fa4d087 实为同一 MD5 问题，分别以 weak_hash/weak_crypto 标注，按 CWE-328 归为 weak_hash 更准确）与修改密码缺少 CSRF 防护（SEM-bb70b3793387）。POC 齐全但性质不同：SQL 注入、验证码绕过、CSRF 属 HTTP 可复现类；MD5 口令存储仅有静态证据 POC，不能宣称可动态复现。所有结论均为源码审计推断，未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 015.php（1-83 行，DVWA CAPTCHA 改密模块）。发现两条可闭合链：(1) CAPTCHA 状态机绕过——step=2 分支仅信任客户端 passed_captcha 字段，可跳过 recaptcha 直接改密，结合无 CSRF token 可致账户接管（high）；(2) 口令无盐 MD5 存储（medium）。第 68-69 行 SQL 使用 mysqli_real_escape_string 转义且 user 来自 dvwaCurrentUser()，未发现可利用 SQL 注入；第 32-33 行隐藏字段回显 $pass_new/$pass_conf 未做 HTML 编码，但为自回显且需先过 CAPTCHA，未构成可申报 XSS，仅作线索。未提供 php.ini/部署配置，无法确认 allow_url_include 等条件。

未覆盖 / 证据缺口：
- 无端点清单与 HTTP 方法记录，路由按 DVWA 惯例推断
- 未提供配置文件，无法确认运行环境安全开关
- 第 32-33 行隐藏字段回显未编码，潜在反射型 XSS 但利用条件不足未单列

## 3. Findings

### F-1: 015.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者在修改密码表单的 password_new 参数（015.php:8 通过 $_POST['password_new'] 读取）提交恶意字符串。该值在 015.php:64 仅经过 mysqli_real_escape_string 转义，随后在 015.php:65 被 md5() 处理，最终在 015.php:68 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 015.php:69 交给 mysqli_query 执行。由于 md5() 会把输入规整为 32 位十六进制串，password_new 本身在进入 SQL 前已被哈希，单次注入路径实际被 md5 截断，普通引号注入难以闭合；真正可注入面取决于 dvwaCurrentUser() 的返回值是否可控（本片段未给出其实现，证据不足）。因此该候选的污点链在 md5 处被削弱，需结合 dvwaCurrentUser() 实现复核才能确认可利用性。

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

若 dvwaCurrentUser() 返回值可被外部影响，则可构造 UPDATE 语句注入，篡改 users 表中任意用户口令或读取数据库内容（数据泄露/越权改密）。就当前片段而言，password_new 经 md5 后无法直接闭合引号，实际可利用性证据不足。

**CVE / CWE 论证**

CWE-89：SQL 语句由字符串拼接构造（015.php:68），未使用参数化查询，汇点为 mysqli_query（015.php:69）。外部可达性：password_new 来自 POST 表单，无需额外权限即可提交；但利用链在 md5()（015.php:65）处被削弱，闭合条件依赖 dvwaCurrentUser() 的返回值，当前证据不足以判定链完全闭合。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO），彻底移除字符串拼接；对 dvwaCurrentUser() 的返回值同样参数化；口令哈希改用 password_hash()/password_verify()（bcrypt/Argon2）替代 md5；关闭 die(mysqli_error(...)) 的详细错误回显，避免报错注入与信息泄露。

**验证说明**

静态证据：入口 POST /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new（015.php:8）→ mysqli_real_escape_string（015.php:64）→ md5()（015.php:65）→ 字符串拼接进 $insert（015.php:68）→ mysqli_query 执行（015.php:69）。关键削弱点：md5 将输入规整为十六进制，普通注入载荷无法保留引号；剩余注入面仅在 dvwaCurrentUser() 拼接处，需其实现证据。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:69 的 SQL 注入 POC。源码在 POST 参数 password_new 上拼接 SQL（Change 分支），未做参数化；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。证据位于 015.php:69，外部输入来自 POST 参数 password_new，source→sink 链静态闭合，未见有效净化。
POC 备注：仅文本工件，不执行、不联网；TARGET 需替换为授权目标。POC 未使用 DROP 等破坏性语句。

### F-2: DVWA 密码修改功能 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-72`
- **来源**：`llm_finding`

**描述**

脚本用两阶段状态机实现“先过 CAPTCHA 再改密码”：step=1 时调用 recaptcha_check_answer 校验，通过后渲染隐藏表单，其中包含 step=2、passed_captcha=true。但 step=2 分支（第 46-81 行）只检查 $_POST['passed_captcha'] 是否为真（第 55 行），完全不校验该值是否由服务端签发、也不校验 CAPTCHA 是否真的通过。攻击者无需任何 CAPTCHA 令牌，直接 POST step=2&passed_captcha=true&password_new=X&password_conf=X 即可进入第 62-72 行的改密逻辑，把当前登录用户的密码改为任意值。若配合 CSRF（改密请求无 token），可对已登录管理员发起跨站改密，导致账户接管。

**source / sink**

- source：body `passed_captcha`（015.php:55）
- sink：015.php:72 第 68-69 行 UPDATE users SET password 的 mysqli_query 执行（改密业务动作）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口判断：只要 POST 带 Change 且 step==2 即进入第二阶段，无需先经过 step=1 | 攻击者完全控制 step 取值 |  |
| 2 | `015.php:55` | 唯一“CAPTCHA 已通过”的校验是读取客户端提交的 passed_captcha 布尔值 | passed_captcha=true 由攻击者直接伪造 | 服务端未保存/校验 CAPTCHA 通过状态，仅信任客户端隐藏字段 |
| 3 | `015.php:62` | 两次密码一致即进入改密分支 | password_new == password_conf |  |
| 4 | `015.php:64-65` | 密码经 mysqli_real_escape_string 转义后 md5 哈希 | 明文 -> 转义 -> md5 |  |
| 5 | `015.php:68-69` | 拼接 UPDATE 语句并执行，修改当前用户密码 | 哈希值写入 users.password |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

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
- POC 目录：`poc/LLM-795a4853ea15`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

无需通过 CAPTCHA 即可修改账户密码；结合无 CSRF token 的改密请求，可对管理员实施跨站请求伪造，实现账户接管。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-602（客户端强制服务端安全）；外部 HTTP 可达，仅需普通登录态，链闭合。

**修复建议**

在服务端 session 中记录 CAPTCHA 校验通过状态与一次性 nonce，step=2 时校验服务端状态而非客户端 passed_captcha；改密请求加入 CSRF token 并在使用后失效。

**验证说明**

需动态确认 step=2 分支在未过 CAPTCHA 时确实执行改密；确认 dvwaCurrentUser() 返回当前会话用户。
模型 POC 要点：跳过 CAPTCHA 直接提交第二阶段表单修改当前登录用户密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:72 的验证码绕过 POC。源码依据 passed_captcha 判断是否通过验证，未真正校验 reCAPTCHA 结果；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-804。证据位于 015.php:72，外部输入来自 body 的 passed_captcha 判断逻辑，未见有效校验。
POC 备注：仅文本工件，不执行；会话 Cookie 由测试者提供，不使用抽象占位符替代真实字段名。

### F-3: 015.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 以 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) 作为进入改密逻辑的唯一门槛，step 完全由客户端 POST 控制。攻击者可直接提交 Change=1&step=1 跳过验证码展示/校验阶段，直接进入 015.php:8 起的改密流程。片段中未见任何服务端验证码答案比对或一次性令牌校验，验证码形同虚设。

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

攻击者可自动化、无限制地提交改密请求，绕过人机校验，配合暴力破解或 CSRF 扩大账户接管面。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/验证码绕过：流程状态由客户端 step 参数决定，服务端未校验验证码答案。外部可达性：直接 POST 即可，无需认证以外的条件；链闭合于 015.php:3 的条件判断。

**修复建议**

验证码答案在服务端会话中保存并强制比对，校验通过后发放一次性令牌；流程状态由服务端维护而非客户端 step 参数；限制单位时间尝试次数并对失败计数锁定。

**验证说明**

静态证据：入口 POST /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST Change=1&step=1 → 015.php:3 条件成立，跳过验证码 → 015.php:8-9 读取新口令 → 执行改密。根因为服务端缺少验证码答案校验与状态机控制。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:3 的验证码绕过 POC。源码在改密流程中未有效校验验证码；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。证据位于 015.php:3，验证码校验缺失。
POC 备注：仅文本工件，不执行；会话 Cookie 由测试者提供。

### F-4: 密码使用无盐 MD5 存储（015.php:65）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:64-68`
- **来源**：`llm_finding`

**描述**

改密逻辑在第 65 行对用户口令直接调用 md5() 且未加盐，随后写入 users 表。MD5 为快速哈希，易被彩虹表/GPU 暴力破解，一旦数据库泄露可快速还原明文口令。

**source / sink**

- source：body `password_new`（015.php:51）
- sink：015.php:68 第 65 行 md5() 哈希后写入数据库

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 读取新密码 | 明文口令 |  |
| 2 | `015.php:65` | 无盐 MD5 哈希 | md5 摘要 |  |
| 3 | `015.php:68-69` | 写入 users.password | 弱哈希落库 |  |

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
- POC 目录：`poc/LLM-1c448a06ff3b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可被快速离线破解，导致账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）/CWE-916；配置型缺陷，无需 HTTP 污点即可确认。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

确认存储字段确为 md5 输出且无额外盐处理。
模型 POC 要点：提交改密后观察数据库存储值为 32 位 MD5
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:68 的弱哈希 POC。源码对 password_new 使用 md5() 存储，属弱哈希（CWE-328）；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-328。证据位于 015.php:68，md5() 用于口令存储。
POC 备注：仅文本工件，不执行；属配置/算法型证据，需结合部署确认。

### F-5: 015.php 修改密码缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:3 在收到 POST 参数 Change 且 step=='1' 时进入改密流程，015.php:8-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf']，整个片段中未见任何 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面自动向该端点提交 password_new/password_conf/Change/step 表单，使已登录受害者在不知情下被改密。是否可利用还取决于会话 Cookie 的 SameSite 属性与目标端点是否要求已认证会话（本片段未包含会话校验代码，证据不足）。

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

登录用户被静默改密，攻击者随后可用新口令接管账户（账户接管/越权）。

**CVE / CWE 论证**

CWE-352：状态改变请求（UPDATE users 口令）无不可预测令牌校验，参数全部来自可伪造的 POST 表单。外部可达性：攻击者只需诱导受害者访问恶意页面即可发起跨站请求，无需受害者交互以外的条件；链闭合依赖会话 Cookie 是否随跨站请求发送（SameSite 配置未在片段中体现）。

**修复建议**

为改密表单引入每会话随机 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；改密等敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /015；source=query/Change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动提交 POST（Change=1, step=1, password_new=..., password_conf=...）→ 015.php:3 条件成立 → 015.php:8-9 读取参数 → 后续 UPDATE 改密。缺少 token 校验是根因；SameSite 与会话校验证据不足。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:8 的 CSRF POC。改密请求无 CSRF token 校验，可被跨站伪造；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。证据位于 015.php:8，改密请求缺少 CSRF token 校验。
POC 备注：仅文本工件，不执行；poc.html 为文本示例，需受害者浏览器访问才生效。

### F-6: 015.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式处理后写入数据库（015.php:68-69 的 UPDATE users SET password）。MD5 属快速哈希，易受彩虹表与 GPU 暴力破解，且此处未见盐值或迭代。该弱点为配置/实现型，无需 HTTP 污点链即可成立。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 015.php:65 的弱加密/弱哈希静态证据。源码使用 md5() 处理口令，属弱哈希（CWE-328），非 CWE-327；无需发送请求。

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

数据库泄露时攻击者可快速还原用户明文口令（凭据泄露），并可能在其他系统复用导致横向扩散。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：口令等安全用途使用 MD5，属弱哈希而非弱加密算法（非 CWE-327）。外部可达性：任何注册/改密请求都会触发该哈希路径；无需特殊权限。

**修复建议**

改用 password_hash()（bcrypt/Argon2id）并配合 password_verify()；为每个口令生成独立盐；必要时增加迭代成本参数；迁移期可对旧 MD5 值做透明升级。

**验证说明**

静态证据：入口 POST /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new（015.php:8）→ 转义（015.php:64）→ md5()（015.php:65）→ 拼接写入 users.password（015.php:68-69）。根因为弱哈希算法选择，与注入链相互独立。
POC 备注：仅文本工件，不执行；类型已按规则修正为 weak_hash。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.94 | 是 |
| surface_mapper | 攻击面测绘 | 8.48 | 是 |
| deep_finder | LLM 深挖 | 12.33 | 是 |
| candidate_screener | 候选筛选 | 8.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.03 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 14.01 | 是 |
| coordinator | 管线协调 | 8.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
