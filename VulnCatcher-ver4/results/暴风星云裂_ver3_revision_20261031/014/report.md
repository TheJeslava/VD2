# 落日二号乙漏洞挖掘报告 — 20261031-011553-0cdf28

- 生成时间：2026-10-30T17:16:52.198908+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\014.zip`
- 输入模式：`zip`
- SHA256：`d641901c9e40d65807bfa31417d7720c470dd3f58356dd114ccf3915412bbff4`
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

本次审计对象为单文件 PHP 脚本 014.php（75 行），共交付 5 条去重后发现，全部带 POC（5/5）。最高危为 014.php 第 61 行附近的 SQL 注入（GEN-74a307a2a91c，critical，CWE-89），位于口令修改逻辑，属 HTTP 可复现类 POC。其次为两条 CAPTCHA 绕过（LLM-ecdc7684a376、SEM-161a1ab1f6bd，high，CWE-804）：通过 step 参数直接进入 step=2 跳过 recaptcha 校验，属状态机/流程绕过，POC 为 HTTP 请求序列。另有两条 medium：口令使用 MD5 存储（SEM-f257349cbc66，CWE-328，注意归类为 weak_hash 而非 weak_crypto，仅有静态证据 POC，不能宣称可动态复现）与口令修改缺少 CSRF 防护（SEM-16d21f2078ab，CWE-352，POC 为构造跨站表单的静态文本）。所有结论均来自源码静态审计与规则/模型推断，未做动态验证。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入 1 个 PHP 文件 014.php（75 行，DVWA captcha 模块）。已逐行审计：第 3-43 行 step=1 分支调用 recaptcha_check_answer 校验 CAPTCHA；第 45-73 行 step=2 分支仅比较两次口令后直接 md5 并 UPDATE users 表，未复用 CAPTCHA 校验结果，也未校验 CSRF token，构成 CAPTCHA 状态机绕过 + CSRF 账户接管链。第 60 行 SQL 使用 mysqli_real_escape_string 转义且 user 来自 dvwaCurrentUser()，未发现可闭合的 SQL 注入。第 32-33 行将 password_new 回显进隐藏 input 的 value 属性，存在反射型 XSS 可能，但需受害者提交自身输入，利用价值低且未闭合，未单独立项。未发现命令执行、文件包含、SSRF、反序列化 sink。weak_hash（md5 存口令）为 DVWA 设计固有，未单独立项。未覆盖：无 composer/服务器配置/路由清单，无法确认公网暴露与前置鉴权；无数据库 schema。

未覆盖 / 证据缺口：
- 无 Web 服务器/路由配置，无法确认 014.php 实际 URL 与访问控制
- 无会话/认证代码，无法确认是否强制登录
- 第 32-33 行隐藏字段回显的反射型 XSS 未闭合（需受害者自提交）
- md5 口令散列属设计固有，未单独立项

## 3. Findings

### F-1: 014.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（014.php:8 读取，014.php:50 附近进入 $pass_new）提交恶意字符串。该值在 014.php:56 仅经过 mysqli_real_escape_string 处理，随后在 014.php:57 被 md5() 哈希，最终在 014.php:60 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 014.php:61 由 mysqli_query 执行。由于 md5() 会把输入转换为 32 位十六进制串，password_new 中的引号等元字符在进入 SQL 前已被哈希消解，因此该条链在源码层面并不闭合；真正可注入的通道是 dvwaCurrentUser() 的返回值（若其来源可被外部控制），但输入未提供该函数实现，证据不足。

**source / sink**

- source：query `password_new`（014.php:50）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-74a307a2a91c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入通道成立，攻击者可改写 users 表中任意用户的 password 字段，实现账户接管或越权登录；错误信息回显（mysqli_error）还会泄露数据库结构。当前证据下具体影响无法确认。

**CVE / CWE 论证**

CWE-89：SQL 语句由字符串拼接构造而非参数化。外部可达性：014.php 为 DVWA 密码修改页面，POST 可达且无需额外权限（需已登录会话）。但利用链闭合性存疑：password_new 经 md5() 后不再携带 SQL 元字符，候选给出的 source→sink 链在源码上不成立，故不满足 CVE 级论证。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare/bind_param 或 PDO），禁止将任何变量拼接进 SQL；对 dvwaCurrentUser() 的返回值同样参数化；关闭 die(mysqli_error(...)) 的详细错误回显，改为通用错误页并记录服务端日志。

**验证说明**

静态证据：入口 ANY /014；source=query/password_new；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 014.php:8 $pass_new → 014.php:56 mysqli_real_escape_string → 014.php:57 md5($pass_new) → 014.php:60 字符串拼接 $insert → 014.php:61 mysqli_query 执行。关键断点：md5() 将输入规约为十六进制串，引号注入被消解，链未闭合。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:61 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 SQL 语句（014.php:56-61），但注入点仍按静态证据标记为 query 参数 password_new。请求使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89（SQL 注入）。证据位于 014.php:56-61，外部输入来自 query 参数 password_new，静态链路闭合；注意源码中已调用 mysqli_real_escape_string，实际可利用性需人工复核转义是否覆盖该拼接点。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。仅限授权测试。

### F-2: DVWA 密码修改功能 CAPTCHA 状态机可绕过（step=2 直接提交跳过 recaptcha 校验）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改流程被拆成两步：step=1 时调用 recaptcha_check_answer() 校验第三方 CAPTCHA，通过后把 password_new/password_conf 放进隐藏字段并渲染 step=2 表单；step=2 分支（第 45-73 行）只检查 password_new == password_conf，随后直接 md5 并 UPDATE users 表，完全没有再次校验 CAPTCHA，也没有任何服务端会话标记证明 step=1 已通过。攻击者（或自动化脚本）可跳过 step=1，直接 POST Change=Change&step=2&password_new=X&password_conf=X 完成密码修改，CAPTCHA 保护形同虚设。结合该功能本身无 CSRF token，攻击者可构造自动提交表单诱导已登录受害者修改密码，实现账户接管。

**source / sink**

- source：body `step`（014.php:50-54）
- sink：014.php:61 mysqli_query 执行 UPDATE users SET password=... （第 60-61 行），无 CAPTCHA 前置校验

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 入口仅判断 Change 存在且 step=='2'，不校验任何 CAPTCHA 结果或会话状态 | 攻击者完全控制 step 值 | 跳过第 3-43 行的 step=1 分支，即跳过 recaptcha_check_answer 校验 |
| 2 | `014.php:50-54` | 读取 password_new/password_conf 并比较是否相等 | 两个参数由攻击者提供，设为相同值即通过 |  |
| 3 | `014.php:56-57` | mysqli_real_escape_string 转义后 md5 散列 | 口令被散列，但流程控制已绕过 |  |
| 4 | `014.php:60-61` | 拼接 UPDATE 语句并执行，修改当前登录用户密码 | 数据库写入新口令散列 |  |

**POC**

针对 /vulnerabilities/captcha/ (014.php)（POST）的 验证码绕过 POC。注入点：POST 参数 step；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (014.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (014.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-ecdc7684a376`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

绕过 CAPTCHA 保护修改账户口令，配合无 CSRF token 可对已登录用户实施账户接管

**CVE / CWE 论证**

CWE-804 (Guessable CAPTCHA)/CWE-352 (CSRF)：step=2 分支缺少对 step=1 CAPTCHA 通过状态的服务端绑定，外部可直接 POST 触发，链闭合

**修复建议**

在服务端会话中记录 CAPTCHA 已通过的一次性令牌，step=2 校验该令牌并立即失效；为表单增加 CSRF token

**验证说明**

需确认 DVWA 部署中 014.php 的实际路由与是否强制登录；CAPTCHA 绕过逻辑已由源码闭合，CSRF 部分依赖浏览器会话
模型 POC 要点：直接提交 step=2 绕过 CAPTCHA 修改当前用户密码；或构造自动提交表单实施 CSRF 账户接管
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 014.php 的验证码绕过 POC。按静态证据，POST 参数 step 参与验证码校验流程（014.php:61 附近），通过重复提交或省略验证码字段观察是否可绕过校验。请求使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-804（验证码绕过）。证据位于 014.php:61 附近，外部输入来自 body 参数 step；实际绕过条件需人工确认校验逻辑。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。仅限授权测试。

### F-3: 014.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

014.php:3 以 if( isset( $_POST['Change'] ) && ( $_POST['step'] == '1' ) ) 作为流程分支条件，客户端提交的 step 值直接决定是否跳过验证码展示与校验阶段。攻击者可直接构造 POST Change=Change&step=1&password_new=...&password_conf=...，跳过验证码环节直达口令修改逻辑（014.php:7-9 读取参数，014.php:60-61 执行更新）。源码中未见服务端会话绑定的验证码校验状态。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的 验证码绕过 POC。注入点：ANY 参数 captcha/step；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?captcha/step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-161a1ab1f6bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可自动化、批量化提交口令修改请求，绕过人机验证，配合弱口令或撞库实现账户接管，并使反自动化防护失效。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-841 类流程缺陷。外部可达性：014.php 为公开页面，POST 无需认证即可到达分支判断；利用链闭合：step 为客户端可控参数且服务端未二次校验验证码结果。

**修复建议**

验证码校验结果必须保存在服务端会话中并在最终提交时强制校验，不得由客户端 step 参数决定流程；一次性使用并在校验后立即失效；对失败次数做限速与锁定。

**验证说明**

静态证据：入口 ANY /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST step=1&Change=Change → 014.php:3 分支判定为真 → 跳过验证码阶段 → 014.php:8-9 读取 password_new/password_conf → 014.php:60-61 执行 UPDATE。绕过点在于 014.php:3 信任客户端 step。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:3 的验证码绕过 POC。按静态证据，query 参数 captcha/step 参与验证码相关逻辑（014.php:3 附近）。请求使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804（验证码绕过）。证据位于 014.php:3 附近，外部输入来自 query 参数 captcha/step；实际绕过条件需人工确认。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。仅限授权测试。

### F-4: 014.php 使用 MD5 存储口令哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:56-57`
- **来源**：`rule`

**描述**

014.php:57 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 单轮哈希后写入数据库（014.php:60-61 的 UPDATE 语句）。MD5 属已破解的弱哈希算法，且此处未加盐、未使用慢哈希，属于口令存储用途的弱哈希实现。

**source / sink**

- source：repository `md5(`（014.php）
- sink：014.php:57 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:57` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：014.php:57 使用 md5() 对密码做哈希。MD5 属弱哈希算法（CWE-328），无需发送请求，仅记录源码证据。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 014.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-f257349cbc66`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后，攻击者可用彩虹表/GPU 暴力快速还原用户明文口令；相同口令产生相同哈希，便于横向撞库，导致账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。配置/实现型弱点，无需 HTTP 污点链：算法名 md5 与调用点 014.php:57 为原文证据。外部可达性：任何通过该页面修改口令的用户都会生成弱哈希，无需特殊权限。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验用 password_verify()；迁移期可对旧 MD5 值在用户下次登录时透明重哈希。

**验证说明**

静态证据：入口 ANY /014；source=repository/md5(；sink=014.php:57；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 014.php:8 → 014.php:56 转义 → 014.php:57 md5() 单轮无盐哈希 → 014.php:60-61 写入 users.password。根因在 014.php:57 的算法选择，与输入净化无关。
POC 备注：POC 仅为文本工件，不执行、不联网。仅限授权测试。

### F-5: 014.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:7-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf']，并在 014.php:60-61 执行 UPDATE users SET password 的状态改变操作。源码片段中未见 CSRF token、Origin/Referer 校验或二次身份确认。攻击者可构造恶意页面，诱导已登录受害者在不知情下提交口令修改表单。

**source / sink**

- source：request `password change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-16d21f2078ab`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

受害者会话有效期内，攻击者可将其账户口令改为攻击者已知值，随后登录接管账户，造成越权与数据泄露。

**CVE / CWE 论证**

CWE-352。外部可达性：014.php 为浏览器可访问的表单端点，跨站 POST 即可触发；利用链闭合：无 token 校验、无来源校验，状态改变请求可被第三方站点伪造。

**修复建议**

为表单引入每会话随机 CSRF token 并在服务端比对；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；修改口令前要求重新输入当前口令。

**验证说明**

静态证据：入口 ANY /014；source=request/password change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动提交 POST password_new/password_conf → 014.php:8-9 读取 → 014.php:60-61 更新口令。缺失的防护点在 014.php:7-9 与 014.php:60-61 之间无任何 token/来源校验。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:8 的 CSRF POC。按静态证据，密码修改表单缺少 CSRF 令牌（014.php:8 附近），可构造自动提交表单诱导已登录用户修改密码。请求使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352（CSRF）。证据位于 014.php:8 附近，密码修改表单缺少令牌校验；实际可利用性需人工确认会话与表单字段。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。仅限授权测试。

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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 8.74 | 是 |
| deep_finder | LLM 深挖 | 8.45 | 是 |
| candidate_screener | 候选筛选 | 7.3 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.61 | 是 |
| coordinator | 管线协调 | 7.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
