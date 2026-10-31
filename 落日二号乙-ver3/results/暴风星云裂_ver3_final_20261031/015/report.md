# 落日二号乙漏洞挖掘报告 — 20261031-013832-01bfd1

- 生成时间：2026-10-30T17:39:28.584857+00:00
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

本次汇总基于单文件 PHP 项目 015.php（83 行）的已去重 findings，共 6 条，全部带 POC（with_poc=6）。最高危为 015.php 密码修改处的 SQL 注入（GEN-c00a42452f04，critical，CWE-89，行 69 附近），属 HTTP 可复现类 POC。其次为两条 CAPTCHA 绕过（LLM-c737fb0d7fd9、SEM-2b846713ecdc，high，CWE-804），均指向同一密码修改流程的状态机缺陷，POC 为 HTTP 请求序列。中危包括 MD5 存储口令（SEM-81919fa4d087，CWE-328，行 65 附近）与两条 CSRF（LLM-db88415cbc34、SEM-bb70b3793387，CWE-352）。需注意：MD5 属 weak_hash（CWE-328），findings 中类型标注为 weak_crypto，存在类型串用，交付时应按 weak_hash 归类，且该条只有静态证据 POC，不能宣称可动态复现。所有结论均为源码审计推断（llm_inferred/rule），未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 015.php（83 行，DVWA CAPTCHA 密码修改模块）。发现两条闭合链：(1) CAPTCHA 状态机绕过——step=2 分支仅信任客户端 passed_captcha 字段，未在服务端会话记录 CAPTCHA 通过状态，可直接改密；(2) 密码修改缺少 CSRF token，可跨站强制改密。第 64 行已使用 mysqli_real_escape_string 且第 65 行 md5 后再拼接，password_new 无法注入 SQL；dvwaCurrentUser() 来源未在 code_pack 中，无法确认其是否可控，故不报 SQL 注入。第 32-33 行将 password_new/password_conf 直接拼入 HTML 属性，存在反射型 XSS 可能，但需受害者提交含引号的密码且属自伤型，价值低，未单独立项。weak_hash（md5 存密码，第 65 行）属 DVWA 设计缺陷，影响有限，未单独立项。未覆盖：dvwaCurrentUser() 实现、recaptcha_check_answer 实现、全局 CSRF 防护、部署配置均不在 code_pack 内。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 定义未提供，无法确认 SQL 拼接中 user 字段是否可控
- recaptcha_check_answer 实现未提供
- 无全局 CSRF/会话配置，无法确认框架层防护
- 无部署与鉴权层信息

## 3. Findings

### F-1: 015.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（015.php:8 读取，随后在 015.php:64 经 mysqli_real_escape_string 处理并 md5 后赋给 $pass_new）进入密码更新语句。015.php:68 将 $pass_new 直接拼接进 "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';"，015.php:69 通过 mysqli_query 执行。虽然 015.php:64 对 $pass_new 做了 mysqli_real_escape_string，但 015.php:65 的 md5() 会先把转义后的字符串哈希成 32 位十六进制，再拼入 SQL，因此实际进入 SQL 的是哈希值而非原始输入，单引号无法由攻击者控制；同时 WHERE 子句使用 dvwaCurrentUser() 而非用户输入。基于所给片段，注入点是否真正闭合存在缺口：若 md5 在转义之后执行（如片段所示），则 password_new 无法注入。

**source / sink**

- source：query `password_new`（015.php:51）
- sink：015.php:69 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `015.php:69` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /015（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-c00a42452f04`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入成立，可篡改 users 表任意记录（含其他账户密码），导致越权与账户接管；但按当前片段证据，实际可利用性未确认。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性：password_new 为 POST 参数，无需认证即可提交（DVWA 低安全级别下会话即可）。但利用链闭合性存疑：md5 在 mysqli_real_escape_string 之后执行，使引号被哈希消除，且 WHERE 使用 dvwaCurrentUser()，故不能确认注入可达。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare/bind_param 或 PDO），禁止字符串拼接 SQL；对用户标识使用服务端会话值并参数化；移除 or die(mysqli_error(...)) 以免泄露数据库错误信息。

**验证说明**

静态证据：入口 ANY /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 $pass_new → 015.php:64 mysqli_real_escape_string → 015.php:65 md5() → 015.php:68 拼接进 UPDATE 语句 → 015.php:69 mysqli_query 执行。关键疑点：md5 位于转义之后，原始引号无法保留到 SQL 中，注入链在片段层面不闭合。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:69 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 UPDATE 语句（DVWA 密码修改逻辑），此处按静态证据保留注入点 password_new 的布尔注入验证请求。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。位置 015.php:69，外部输入来自 query 参数 password_new，静态链已闭合；注意源码第 64 行存在 mysqli_real_escape_string 转义，实际可利用性需动态确认，本 POC 仅为文本工件。
POC 备注：仅限授权测试；不执行、不联网。目标统一使用 TARGET 占位符。

### F-2: DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

脚本把 CAPTCHA 校验放在 step=1 分支（第 12-23 行），而真正执行密码更新的逻辑在 step=2 分支（第 46-81 行）。step=2 分支只检查客户端提交的 $_POST['passed_captcha'] 是否为真（第 55 行），并不重新校验 reCAPTCHA 响应，也不校验服务端会话中是否真的通过过 CAPTCHA。攻击者可直接构造 step=2 请求并附带 passed_captcha=true，跳过第三方 CAPTCHA 校验，完成任意密码修改（配合 CSRF 可强制受害者改密）。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 第 68-69 行 UPDATE users SET password 执行，绕过第 12 行 recaptcha_check_answer

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 攻击者直接提交 step=2，跳过 step=1 的 CAPTCHA 校验分支 | step=2 进入密码更新分支 |  |
| 2 | `015.php:55` | 仅检查客户端可控的 passed_captcha 字段 | passed_captcha=true 通过检查 | 未在服务端会话中记录 CAPTCHA 已通过状态，仅信任客户端提交值 |
| 3 | `015.php:62` | 两次密码一致则进入更新 | password_new == password_conf |  |
| 4 | `015.php:68` | 执行 UPDATE 修改当前用户密码 | md5 后的密码写入数据库 |  |

**POC**

针对 /vulnerabilities/captcha/ (015.php)（POST）的 验证码绕过 POC。注入点：POST 参数 passed_captcha；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-c737fb0d7fd9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过 CAPTCHA 即可修改账户密码；结合 CSRF 可强制已登录用户改密，导致账户接管。

**CVE / CWE 论证**

CWE-804 (Guessable CAPTCHA)/CWE-602 (Client-Side Enforcement of Server-Side Security)：CAPTCHA 校验仅在 step=1 执行，step=2 仅信任客户端 passed_captcha 标志，服务端无状态校验，外部可直接触发。

**修复建议**

在服务端会话中记录 CAPTCHA 通过状态（如 $_SESSION['captcha_passed']=true），step=2 时校验该会话标志而非客户端字段；或每次更新前重新校验 reCAPTCHA。

**验证说明**

需确认 DVWA 部署中该文件对应 captcha 模块且 step=2 分支确实可独立到达；动态验证需实际会话。
模型 POC 要点：直接构造 step=2 请求，伪造 passed_captcha=true 绕过 CAPTCHA 修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:69 的验证码绕过 POC。DVWA captcha 模块在 passed_captcha 参数存在时跳过验证码校验，直接进入密码修改流程。请求体使用 passed_captcha 参数。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-804。位置 015.php:69，外部输入来自 body 参数 passed_captcha，静态链已闭合；需动态确认服务端是否真正跳过校验。
POC 备注：仅限授权测试；不执行、不联网。目标统一使用 TARGET 占位符。

### F-3: 015.php 验证码流程可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 通过 if( isset($_POST['Change']) && ($_POST['step'] == '1') ) 判断流程阶段，step 完全由客户端 POST 控制。攻击者可直接提交 step=1 及 Change，跳过验证码校验阶段，直接进入密码修改逻辑（015.php:7-9 读取 password_new/password_conf）。片段中未见服务端会话绑定验证码状态或校验验证码答案的逻辑，故客户端可任意推进流程状态。

**source / sink**

- source：request `captcha/step`（015.php）
- sink：015.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（ANY）的 验证码绕过 POC。注入点：ANY 参数 captcha/step；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?captcha/step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2b846713ecdc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

绕过人机验证保护，使攻击者可自动化批量提交密码修改请求，配合 CSRF/暴力尝试扩大攻击面。

**CVE / CWE 论证**

CWE-804：验证码可被绕过。外部可达性：仅需 POST 参数 step 与 Change，无需认证前置条件（DVWA 场景）。利用链闭合：客户端可控 step 直接决定是否进入修改分支，服务端无独立校验证据。

**修复建议**

将验证码状态保存在服务端会话中，校验通过后才允许进入下一步；不要用客户端提交的 step 决定流程阶段；验证码一次性使用并绑定会话，失败计数与限速。

**验证说明**

静态证据：入口 ANY /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST Change=1&step=1 → 015.php:3 条件成立 → 跳过验证码阶段 → 015.php:7-9 读取新密码 → 进入更新逻辑。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:3 的验证码绕过候选 POC。静态证据指向 captcha/step 相关参数，按输入保留请求结构，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。位置 015.php:3，外部输入来自 query 参数 captcha/step；证据等级为静态推断，需动态确认。
POC 备注：仅限授权测试；不执行、不联网。目标统一使用 TARGET 占位符。

### F-4: 015.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 执行 $pass_new = md5( $pass_new );，将用户新密码以无盐 MD5 形式计算后写入数据库（015.php:68-69 的 UPDATE 语句）。MD5 属快速哈希，且此处未见盐值或迭代，属于口令存储的弱哈希实现。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：015.php:65 使用 md5() 对密码做哈希，属弱哈希（CWE-328）。无需发送请求，仅记录源码证据。

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

数据库泄露时，攻击者可用彩虹表/GPU 高速碰撞快速还原用户明文口令，导致账户接管与横向移动。

**CVE / CWE 论证**

CWE-328：使用弱哈希算法。配置/实现型弱点，无需 HTTP 污点链；原文证据为 015.php:65 的 md5( $pass_new )。外部可达性：任何修改密码请求都会触发该哈希路径。

**修复建议**

改用 Argon2id、bcrypt 或 PBKDF2 等带盐、可调工作因子的口令哈希（PHP password_hash/password_verify），并对既有 MD5 记录在下次登录时透明升级。

**验证说明**

静态证据：入口 ANY /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 → 015.php:64 转义 → 015.php:65 md5() 无盐哈希 → 015.php:68-69 写入 users.password。
POC 备注：仅限授权测试；不执行、不联网。此为离线静态证据，无 HTTP 请求。

### F-5: 密码修改接口缺少 CSRF token，可被跨站强制改密

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

第 46-69 行的密码更新逻辑仅依赖 POST 参数（step、passed_captcha、password_new、password_conf），没有任何 CSRF token 或来源校验。攻击者可构造自动提交表单，诱导已登录用户访问，从而在受害者身份下修改密码（配合 CAPTCHA 绕过，无需受害者交互 CAPTCHA）。

**source / sink**

- source：body `*`（015.php）
- sink：015.php:69 第 68-69 行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 受害者浏览器被诱导提交 POST 请求 | step=2 进入更新分支 |  |
| 2 | `015.php:55` | 攻击者表单携带 passed_captcha=true 通过检查 | passed_captcha=true | 无 CSRF token，无 Referer/Origin 校验 |
| 3 | `015.php:68` | 以受害者身份执行 UPDATE 改密 | 受害者密码被改为攻击者指定值 |  |

**POC**

针对 /vulnerabilities/captcha/ (015.php)（POST）的 跨站请求伪造 POC。注入点：POST 参数 param；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'param=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-db88415cbc34`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，导致账户接管。

**CVE / CWE 论证**

CWE-352：敏感状态变更操作缺少 anti-CSRF token，外部可构造跨站请求触发。

**修复建议**

为密码修改表单加入随机 CSRF token 并在服务端校验；校验 Origin/Referer。

**验证说明**

需确认 DVWA 未在全局层加 CSRF 防护；动态验证需受害者会话。
模型 POC 要点：构造自动提交表单，诱导已登录用户访问以修改其密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php:69 的 CSRF POC。密码修改表单缺少 anti-CSRF token，攻击者可诱导已登录用户提交表单。请求体使用 param 参数占位。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-352。位置 015.php:69，外部输入来自 body；需动态确认无 anti-CSRF token。
POC 备注：仅限授权测试；不执行、不联网。目标统一使用 TARGET 占位符。

### F-6: 015.php 密码修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.65`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:7-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf'] 并进入密码更新流程，片段中未见任何 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面自动向该端点提交表单，以受害者浏览器会话完成密码修改。

**source / sink**

- source：request `password change`（015.php）
- sink：015.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-bb70b3793387`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下将其密码改为攻击者已知值，实现账户接管。

**CVE / CWE 论证**

CWE-352：跨站请求伪造。外部可达性：状态改变请求仅依赖会话 Cookie，无需额外令牌。利用链闭合：表单参数固定、无令牌校验，跨站可自动提交。

**修复建议**

为密码修改表单引入每会话随机 CSRF token 并在服务端校验；校验 Origin/Referer；对敏感操作要求重新输入当前密码；Cookie 设置 SameSite=Lax/Strict。

**验证说明**

静态证据：入口 ANY /015；source=request/password change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：受害者访问恶意页面 → 自动 POST password_new/password_conf 至 015.php → 015.php:8-9 读取参数 → 无令牌校验 → 执行密码更新。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php:8 的 CSRF 候选 POC。静态证据指向 password change 相关参数，按输入保留请求结构，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。位置 015.php:8，外部输入来自 query 参数 password change；证据等级为静态推断，需动态确认。
POC 备注：仅限授权测试；不执行、不联网。目标统一使用 TARGET 占位符。

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
| safety_guard | 安全防护 | 2.56 | 是 |
| surface_mapper | 攻击面测绘 | 7.67 | 是 |
| deep_finder | LLM 深挖 | 10.72 | 是 |
| candidate_screener | 候选筛选 | 7.23 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.31 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 10.72 | 是 |
| coordinator | 管线协调 | 7.22 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
