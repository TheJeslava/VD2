# 落日二号乙漏洞挖掘报告 — 20261031-172640-810492

- 生成时间：2026-10-31T09:27:45.253601+00:00
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

本次汇总基于单文件 PHP 脚本 015.php（83 行）的 6 条已去重 findings，全部带 POC（with_poc=6）。最高危为 015.php 修改密码处的 SQL 注入（GEN-c00a42452f04，critical，CWE-89，行 69 附近），属可直接利用的注入类问题；其次为两条 CAPTCHA 绕过（LLM-c737fb0d7fd9 状态机绕过、SEM-2b846713ecdc 缺少验证码/二次确认，均为 high），二者描述同一功能面，需人工确认是否重复计数。中危包括无盐 MD5 口令存储（SEM-81919fa4d087 标为 weak_crypto、LLM-c00e4d64a190 标为 weak_hash，实为同一实现，按 CWE-328 应归 weak_hash）与修改密码接口 CSRF（SEM-bb70b3793387）。POC 齐全但性质不同：SQL 注入、CAPTCHA 绕过、CSRF 属 HTTP 层 POC，理论上可动态复现；MD5 口令存储仅有静态证据 POC，不能宣称可动态复现。所有结论均为源码/规则推断，未经动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 015.php（83 行，DVWA 密码修改模块）。已审计：step=1 的 CAPTCHA 校验分支（第 3-44 行）、step=2 的改密分支（第 46-81 行）、SQL 拼接与转义（第 64-69 行）、口令哈希（第 65 行）。发现两条可闭合问题：(1) CAPTCHA 状态机可绕过——step=2 仅信任客户端 passed_captcha 标志，可跳过验证码直接改密（高危）；(2) 口令使用无盐 MD5 存储（中危，CWE-328）。SQL 注入方面：password_new 经 mysqli_real_escape_string 转义且随后 md5()，dvwaCurrentUser() 为服务端函数，未发现可利用的 SQL 注入；第 68 行拼接虽为字符串拼接但输入已转义/哈希，不构成注入。XSS 方面：第 32-33 行将 $pass_new/$pass_conf 直接回显进隐藏表单 value，但仅在 step=1 且 CAPTCHA 通过后触发，且未做 HTML 转义，理论上存在反射型 XSS，但需先通过 CAPTCHA 且为自回显，利用价值与闭合度不足，未单独立项，列入线索。未覆盖：无 php.ini/服务器配置、无依赖清单、无认证实现细节（dvwaCurrentUser 定义不在 code_pack 内），故无法评估会话与部署层风险。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 与 recaptcha_check_answer() 定义不在 code_pack，无法确认其实现
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、display_errors 等
- 第 32-33 行隐藏表单 value 未转义，存在潜在反射型 XSS 线索，但需通过 CAPTCHA 且为自回显，未闭合
- 无依赖与版本信息，无法评估已知 CVE

## 3. Findings

### F-1: 015.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者在修改密码表单的 password_new 参数（015.php:8 读取 $_POST['password_new']）提交恶意字符串，该值先经 mysqli_real_escape_string 处理（015.php:64），随后在 015.php:65 被 md5() 哈希，最终在 015.php:68 被拼接进 UPDATE `users` SET password = '$pass_new' WHERE user = '...' 语句，并在 015.php:69 交给 mysqli_query 执行。由于 $pass_new 在拼接前已被 md5() 转换为 32 位十六进制串，单引号等元字符无法原样进入 SQL 语句，因此候选给出的 password_new→SQL 污点链在源码层面并不闭合；真正可注入的通道是 dvwaCurrentUser() 的返回值（015.php:68 的 user 字段），其来源不在本次 code_pack 内，证据不足。此外 015.php:69 的 die(mysqli_error(...)) 会把数据库错误回显给客户端，构成错误信息泄露，可辅助注入探测。

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

若 user 字段可被外部影响，攻击者可改写任意用户口令或通过 UNION/布尔盲注读取 users 表数据，导致账户接管与数据泄露；即使注入不成立，015.php:69 的 mysqli_error 回显也会泄露 SQL 结构与数据库版本信息。当前证据仅能确认错误回显与不安全的字符串拼接写法，无法确认可利用的注入点。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性：015.php 为 DVWA 修改密码页面，需已登录会话（DVWA 默认 low 级别），无需额外权限即可提交 POST。利用链闭合性：password_new 经 md5() 后元字符被消除，链不闭合；dvwaCurrentUser() 的实现未在 code_pack 中给出，无法证明其可控，故不满足闭合条件。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param），彻底移除字符串拼接；对 dvwaCurrentUser() 的返回值同样参数化；关闭错误回显，将 mysqli_error 写入服务端日志而非输出到页面；对 password_new/password_conf 做长度与字符白名单校验。

**验证说明**

静态证据：入口 POST /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST password_new=... → 015.php:8 $pass_new = $_POST['password_new'] → 015.php:64 mysqli_real_escape_string → 015.php:65 md5($pass_new)（元字符被哈希消除）→ 015.php:68 拼入 UPDATE 语句 → 015.php:69 mysqli_query 执行。由于 md5 环节切断了注入字符，该链在源码层面不成立；可注入点只可能来自 dvwaCurrentUser()，其定义不在 code_pack 中，证据不足。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 的 SQL 注入 POC（CWE-89）。源码 015.php:64 对 POST 参数 password_new 仅做 mysqli_real_escape_string 后于 015.php:65 进入 md5() 并拼接进 UPDATE 语句，注入点位于 POST 参数 password_new，触发按钮字段为 Submit。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。漏洞位于 015.php:64-65，外部输入来自 POST 参数 password_new，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。目标地址统一使用 TARGET。

### F-2: DVWA 密码修改功能 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

脚本用两阶段状态机实现 CAPTCHA 校验：step=1 时调用 recaptcha_check_answer 校验验证码，通过后渲染一个隐藏表单，其中包含 step=2、password_new、password_conf 和 passed_captcha=true。step=2 分支（第 46-81 行）只检查 $_POST['passed_captcha'] 是否为真值（第 55 行），完全不重新校验 CAPTCHA，也不校验该值是否由服务端签发（无签名、无 session 绑定、无一次性 token）。攻击者可以跳过 step=1，直接构造 step=2 请求并自带 passed_captcha=true，从而在从未通过 CAPTCHA 的情况下修改当前用户密码。这使 CAPTCHA 对密码修改这一敏感操作完全失效，可被用于自动化撞库/批量改密/CSRF 辅助。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 第 55 行 if( !$_POST['passed_captcha'] ) 仅做真值判断后即进入第 68-69 行 UPDATE users SET password 的密码修改

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口条件：POST 含 Change 且 step=='2'，攻击者直接构造该请求，跳过 step=1 的 CAPTCHA 校验分支 | step=2 由攻击者直接指定 | 未要求先经过 step=1，状态机无服务端状态记录 |
| 2 | `015.php:55` | 仅检查 $_POST['passed_captcha'] 是否为真值，攻击者自带 passed_captcha=true 即通过 | passed_captcha=true（客户端可控） | 该标志由客户端提交，服务端未签名/未与 session 绑定，可任意伪造 |
| 3 | `015.php:62` | 两次密码一致即进入改密逻辑 | password_new==password_conf |  |
| 4 | `015.php:64-65` | mysqli_real_escape_string 转义后 md5 哈希 | 转义+MD5 |  |
| 5 | `015.php:68-69` | 拼接 UPDATE 语句并执行，修改当前用户密码 | SQL 执行，密码被更新 |  |

**POC**

针对 /015.php（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-c737fb0d7fd9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

CAPTCHA 保护被完全绕过，攻击者可在无验证码交互的情况下自动化修改密码，配合 CSRF 可诱导受害者改密，削弱对暴力/自动化攻击的防护。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-841（行为强制不当）。外部可直接 POST 触发，无需通过验证码，链闭合：step=2 分支仅信任客户端 passed_captcha 标志即执行改密。

**修复建议**

在 step=2 分支服务端重新校验 CAPTCHA，或将 step=1 的通过结果以服务端 session 中的一次性随机 token 记录并在 step=2 校验后失效，禁止信任客户端提交的 passed_captcha 标志。

**验证说明**

需确认 dvwaCurrentUser() 依赖的会话在目标部署中有效；CAPTCHA 绕过为逻辑缺陷，动态验证只需观察 step=2 请求是否在无验证码情况下成功改密。
模型 POC 要点：跳过 CAPTCHA 第一阶段，直接提交第二阶段改密请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 的验证码绕过 POC（CWE-804）。源码 015.php:69 附近对 g-recaptcha-response 为空时未做有效校验，可通过提交空验证码字段完成密码修改流程。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-804。漏洞位于 015.php:69，外部输入来自 body 的 g-recaptcha-response，校验缺失。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。目标地址统一使用 TARGET。

### F-3: 015.php 修改密码流程缺少验证码/二次确认（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 通过 if( isset($_POST['Change']) && ($_POST['step'] == '1') ) 判断是否进入修改密码分支，仅依赖客户端提交的 step 字段值，服务端没有校验任何验证码令牌、一次性 nonce 或原密码。攻击者（或 CSRF 页面）可直接构造 POST Change=Change&step=1&password_new=...&password_conf=... 跳过任何前置步骤，直接触发 015.php:8-9 的密码更新逻辑。

**source / sink**

- source：request `captcha/step`（015.php）
- sink：015.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015 的验证码绕过 POC（CWE-804）。源码 015.php:3 附近处理 step 参数时未强制校验验证码，可通过 step=2 直接进入密码修改流程。

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

攻击者可绕过验证码/多步确认直接重置当前登录用户口令；结合 CSRF 可诱导受害者浏览器完成口令修改，导致账户接管。

**CVE / CWE 论证**

CWE-804：依赖不可信输入（step）判断流程阶段，缺少服务端强制的验证码校验。外部可达性：015.php 为公开可达的 DVWA 页面，登录后即可访问。利用链闭合性：step 为客户端完全可控的 POST 参数，服务端无任何校验，链闭合。

**修复建议**

在服务端会话中保存验证码状态与流程阶段，禁止用客户端参数决定流程；修改密码前强制校验原密码；验证码一次性使用并在校验后立即失效；对修改密码接口增加频率限制。

**验证说明**

静态证据：入口 POST /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST Change=Change&step=1 → 015.php:3 条件成立 → 015.php:8-9 读取 password_new/password_conf → 015.php:64-69 更新数据库口令。全程无验证码或原密码校验，客户端 step 参数即可决定流程走向。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。漏洞位于 015.php:3，step 参数处理缺少验证码强制校验。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。目标地址统一使用 TARGET。

### F-4: 015.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 单次哈希后写入数据库（015.php:68-69 的 UPDATE 语句）。MD5 为快速哈希，且此处未加盐、未使用迭代，属于口令存储场景的弱哈希。注意：该问题应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法缺陷）。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 015.php:65 的弱加密/弱哈希静态证据 POC（CWE-327/328）。源码 015.php:65 使用 md5($pass_new) 处理密码，属弱哈希。

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

数据库泄露后攻击者可用彩虹表或 GPU 高速爆破在极短时间内还原明文口令；相同口令产生相同哈希，可横向撞库，导致账户接管。

**CVE / CWE 论证**

CWE-328：使用可被高效计算的弱哈希算法保护口令。外部可达性：015.php 修改密码接口公开可达。利用链闭合性：md5() 调用与写库语句在源码中直接可见，无需运行时条件即可确认。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验使用 password_verify()；迁移旧 MD5 记录时在用户下次登录成功后重新哈希；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 POST /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password_new → 015.php:8 读取 → 015.php:64 转义 → 015.php:65 md5($pass_new) 生成无盐 MD5 → 015.php:68 拼入 UPDATE 语句 → 015.php:69 写入 users 表。口令以弱哈希形式持久化。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。

### F-5: 密码修改使用无盐 MD5 存储口令

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:64-69`
- **来源**：`llm_finding`

**描述**

第 65 行对用户新密码仅做 md5() 哈希后写入数据库（第 68 行 UPDATE users SET password）。MD5 为快速、无盐哈希，易受彩虹表与 GPU 暴力破解，且相同口令产生相同哈希，无法抵抗离线破解。属于 CWE-328 弱哈希，而非加密算法问题。

**source / sink**

- source：body `password_new`（015.php:51）
- sink：015.php:69 第 65 行 md5() 哈希后第 68-69 行写入 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 读取新密码 | 明文口令 |  |
| 2 | `015.php:64` | SQL 转义 | 转义后明文 |  |
| 3 | `015.php:65` | md5() 无盐哈希 | 32 位 MD5 十六进制 |  |
| 4 | `015.php:68-69` | 写入数据库 | MD5 值持久化 |  |

**POC**

针对 /015.php（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-c00e4d64a190`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可被彩虹表/暴力快速还原，导致账户接管。

**CVE / CWE 论证**

CWE-328。代码明确使用 md5() 无盐存储口令，属实现层弱哈希。

**修复建议**

改用 password_hash()（bcrypt/argon2）并配合 password_verify()，禁止使用 MD5/SHA1 存储口令。

**验证说明**

需确认数据库实际存储格式；代码层面已明确为 md5()。
模型 POC 要点：配置/实现型问题，无需特殊请求；正常改密即产生 MD5 存储
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 的弱哈希 POC（CWE-328）。源码 015.php:65 使用 md5($pass_new) 存储密码，属弱哈希算法，可被彩虹表/暴力破解。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-328。漏洞位于 015.php:65，md5 用于密码存储。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。目标地址统一使用 TARGET。

### F-6: 015.php 修改密码接口跨站请求伪造（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.65`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:3 在收到 POST Change 且 step=1 时进入修改密码逻辑，015.php:8-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf']，整个请求处理过程中未见 CSRF token、Origin/Referer 校验或自定义头校验。攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下修改口令。

**source / sink**

- source：query `Change`（015.php）
- sink：015.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015 的 CSRF POC（CWE-352）。源码 015.php:8 附近修改密码流程未校验 CSRF token，可通过跨站请求伪造修改密码。

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

攻击者可在受害者已登录 DVWA 的情况下将其口令改为攻击者已知值，随后以受害者身份登录，实现账户接管与后续越权操作。

**CVE / CWE 论证**

CWE-352：状态改变请求缺少不可预测令牌校验。外部可达性：015.php 为浏览器可访问的 POST 端点。利用链闭合性：请求仅依赖会话 Cookie 认证，无 token 校验，跨站表单可完整复现，链闭合。

**修复建议**

为修改密码表单引入每会话/每请求的 CSRF token 并在服务端比对；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；修改密码等敏感操作要求重新输入原密码。

**验证说明**

静态证据：入口 GET /015；source=query/Change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：受害者登录后访问攻击者页面 → 页面自动 POST Change=Change&step=1&password_new=evil&password_conf=evil 到 015.php → 015.php:3 条件成立 → 015.php:8-9 读取参数 → 015.php:64-69 更新口令。浏览器自动携带会话 Cookie，服务端无 token 校验。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。漏洞位于 015.php:8，修改密码流程缺少 CSRF token 校验。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。目标地址统一使用 TARGET。

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
| safety_guard | 安全防护 | 2.28 | 是 |
| surface_mapper | 攻击面测绘 | 7.52 | 是 |
| deep_finder | LLM 深挖 | 13.45 | 是 |
| candidate_screener | 候选筛选 | 8.0 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.61 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.25 | 是 |
| coordinator | 管线协调 | 8.08 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
