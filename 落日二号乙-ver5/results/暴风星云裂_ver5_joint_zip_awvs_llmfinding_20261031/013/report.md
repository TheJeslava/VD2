# 落日二号乙漏洞挖掘报告 — 20261031-214200-d4f43b

- 生成时间：2026-10-31T13:43:01.223536+00:00
- 输入：`$WORKSPACE\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
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

本次审计范围是单文件 PHP 脚本 013.php（55 行，无框架、无路由配置），共交付 4 条去重后的 findings，全部带 POC（4/4）。最高危的是 GEN-89dab2f7ae60：013.php 第 31 行附近的修改密码功能存在 SQL 注入（CWE-89，critical，规则命中，有 HTTP POC）。其次是两条 captcha_bypass（LLM-719de589f39a 与 SEM-07d9d737e404，均为 high，指向同一处验证码校验逻辑，分别从伪造请求头与流程缺陷角度描述，有 HTTP POC）。另有 SEM-0bafba96288b 记录 013.php 第 27 行使用 MD5 存储口令哈希，类型标注为 weak_crypto，但按 CWE-328 应归为 weak_hash，且只有静态证据 POC，不能宣称可动态复现。POC 齐全度：4 条均有 POC 文本，但其中 weak_crypto/weak_hash 一条属静态证据，其余 3 条为 HTTP POC；所有 POC 均为文本工件，未执行、未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 013.php（55 行，DVWA 密码修改页面）。已通读全部 55 行，审计了 CAPTCHA 校验、密码比较、SQL 更新与 md5 哈希等逻辑。发现 1 条闭合链：第17-23行 CAPTCHA 校验存在硬编码后门值 hidd3n_valu3 与可伪造 User-Agent 的短路分支，可绕过 CAPTCHA 修改密码。第26行 mysqli_real_escape_string 已对密码做转义，第30行 SQL 拼接的 user 来自 dvwaCurrentUser() 而非直接外部输入，未构成可闭合 SQL 注入。第27行 md5 用于密码存储属 weak_hash，但为 DVWA 既有设计且无独立可利用链，仅作线索记录，未单独立项。未提供部署配置、PHP 版本、disable_functions，无法评估运行时限制。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 disable_functions 与部署路径
- 无端点清单，013.php 实际 URL 与访问控制未确认
- md5 密码哈希（第27行）属 weak_hash 线索，未形成独立可利用链
- 无数据库/模板/前端文件，SQL 二次注入与 XSS 无法评估

## 3. Findings

### F-1: 013.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，输入在 013.php:8 处由 query `password_new` 读取并赋给 $pass_new；013.php:26 仅用 mysqli_real_escape_string 做转义，随后 013.php:27 对 $pass_new 做 md5() 处理，013.php:30 将结果直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;"，最终在 013.php:31 由 mysqli_query 执行。由于 md5() 会把输入规整为 32 位十六进制串，单看 $pass_new 位置难以注入；但同一语句中 dvwaCurrentUser() 的返回值未经参数化直接拼入 WHERE 子句，若该函数返回可被外部影响的值（如会话中的用户名），则构成注入通道。当前 code_pack 未提供 dvwaCurrentUser() 的实现，无法确认其返回值是否可控，因此该注入点的可利用性证据不足。

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

若 dvwaCurrentUser() 返回值可控，攻击者可构造 WHERE 子句注入，绕过 LIMIT 1 限制批量改写 users 表 password 字段，导致任意账户口令被重置（账户接管）；同时 013.php:31 的 die(mysqli_error(...)) 会把数据库错误信息回显到页面，造成数据库结构/版本等信息泄露。若仅 $pass_new 位置，因 md5 规整化实际不可注入。

**CVE / CWE 论证**

CWE-89：外部输入经字符串拼接进入 SQL 语句且未使用预处理语句。外部可达性：该逻辑位于 isset($_POST['Change']) 分支（013.php:3），为 Web 表单直接可达的修改密码接口，无需额外权限即可提交。利用链闭合性：source（表单参数）→ $pass_new / dvwaCurrentUser() → $insert 拼接 → mysqli_query 执行，链路在文件内闭合；但关键一环 dvwaCurrentUser() 的实现未在 code_pack 中给出，故按 llm_inferred 记录，未达外部验证级别。

**修复建议**

改用参数化查询：$stmt = $db->prepare('UPDATE users SET password = ? WHERE user = ? LIMIT 1'); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); $stmt->execute(); 禁止将任何变量（包括 dvwaCurrentUser() 返回值）拼接进 SQL；对用户名做白名单/长度校验；移除 die(mysqli_error(...)) 的详细错误回显，改为记录日志并返回通用错误；口令哈希改用 password_hash()/password_verify()（bcrypt/Argon2）替代 md5。

**验证说明**

静态证据：入口 POST /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码表单提交 Change 请求 → 013.php:8 读取 query `password_new` 到 $pass_new → 013.php:26 mysqli_real_escape_string 转义 → 013.php:27 md5() 规整 → 013.php:30 与 dvwaCurrentUser() 返回值一起拼接成 UPDATE 语句 → 013.php:31 mysqli_query 执行，错误经 die() 回显。注入可行性取决于 dvwaCurrentUser() 返回值是否外部可控，该实现不在 code_pack 内，证据不足。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。源码中 POST 参数 password_new 经 mysqli_real_escape_string 处理后进入 SQL 语句，注入点为 POST 参数 password_new，触发按钮字段为 Submit。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89（SQL 注入）。证据位于 013.php:31，外部输入来自 POST 参数 password_new，source→sink 链基于源码片段推断闭合（llm_inferred），未做动态验证。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例；禁止使用 DROP 等破坏性语句。

### F-2: DVWA 密码修改功能 CAPTCHA 校验可被伪造请求头绕过（013.php）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 在处理密码修改时，先调用 recaptcha_check_answer() 校验第三方 CAPTCHA，但随后在 if 条件中使用逻辑或 `$resp || (...)`，其中第二个分支仅要求 POST 参数 g-recaptcha-response 等于硬编码字符串 'hidd3n_valu3' 且 HTTP_USER_AGENT 等于 'reCAPTCHA'。攻击者无需真正通过 CAPTCHA，只要在请求中伪造这两个值即可让条件恒真，进入密码修改逻辑，从而在无有效 CAPTCHA 的情况下修改当前用户密码。该硬编码后门值（第20-21行）是根因，属于认证/校验机制绕过。

**source / sink**

- source：body `g-recaptcha-response`（013.php:14）
- sink：013.php:23 if 条件短路进入密码修改分支（第25-31行 UPDATE users SET password）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:14` | 从 POST 读取 g-recaptcha-response 传给 recaptcha_check_answer | 攻击者可控字符串 |  |
| 2 | `013.php:17-23` | if 条件使用逻辑或，第二分支仅比较硬编码值与 User-Agent | 攻击者将 g-recaptcha-response 设为 hidd3n_valu3、User-Agent 设为 reCAPTCHA 使条件为真 | 硬编码后门值 hidd3n_valu3 与可伪造的 User-Agent 头，绕过真实 CAPTCHA 校验 |
| 3 | `013.php:25-31` | 条件为真后比较两次密码并执行 UPDATE 修改密码 | 新密码经 md5 后拼入 SQL 执行 |  |

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

攻击者可在无有效 CAPTCHA 的情况下修改账户密码，绕过反自动化保护，配合 CSRF 可进一步扩大影响。

**CVE / CWE 论证**

CWE-804/CWE-287：硬编码后门校验值使 CAPTCHA 校验可被任意请求伪造绕过，外部可直接触发，链闭合。

**修复建议**

移除硬编码后门分支，仅依赖 recaptcha_check_answer 的真实返回值；不要信任客户端可伪造的 User-Agent 作为校验依据。

**验证说明**

需确认 recaptcha_check_answer 在无网络/无密钥时的返回值，以及 dvwaCurrentUser() 的会话依赖；后门分支本身已足以绕过。
模型 POC 要点：伪造 CAPTCHA 后门值与 User-Agent，提交密码修改请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /013.php）：针对 013.php:23 的验证码绕过 POC。源码在密码修改流程中读取 POST 参数 g-recaptcha-response，但未对空值/无效值做有效校验，导致可跳过验证码完成密码修改。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013.php）：符合 CWE-804（验证码绕过）。证据位于 013.php:23，外部输入来自 body 参数 g-recaptcha-response，source→sink 链基于源码片段推断（llm_inferred），未做动态验证。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 3 的登录字段名需按源码确认，若无法确认须标注“需补充源码/路由”，不得伪造。

### F-3: 013.php 修改密码流程验证码可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:3-4`
- **来源**：`rule`

**描述**

013.php:3 判断 isset($_POST['Change']) 后，013.php:4-5 直接设置 $hide_form = true 并进入修改密码逻辑，代码片段中未见任何对验证码字段的读取、比对或会话校验。候选将其标记为验证码绕过，但 code_pack 仅给出 013.php:3-5 片段，未提供验证码生成/校验代码，无法确认是否存在验证码机制及其校验位置。原文证据仅为 013.php:4 注释 `// Hide the CAPTCHA form` 与 013.php:5 `$hide_form = true;`。

**source / sink**

- source：request `captcha/step`（013.php）
- sink：013.php:4 	// Hide the CAPTCHA form

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:4` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /013（POST）的验证码绕过 POC。源码 013.php:4 附近处理 Change 提交与 step 流程，未对验证码做有效校验。目标地址使用 TARGET 占位符，仅限授权测试。

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

若确实缺少服务端验证码校验，攻击者可脚本化批量提交修改密码请求，对用户口令进行暴力枚举/自动化攻击，并配合本文件其他弱点放大危害。但当前证据仅显示表单隐藏标志，未证明存在可绕过的校验逻辑，影响范围证据不足。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/验证码校验缺失。外部可达性：修改密码接口为表单直接可达。利用链闭合性：证据不足——code_pack 未包含验证码生成与校验代码，无法确认“存在校验但可绕过”或“完全无校验”，故仅作低置信度记录。

**修复建议**

在服务端对每次修改密码请求强制校验一次性验证码（绑定会话、一次性使用、带过期时间），校验失败即拒绝；不要仅依赖前端隐藏表单（$hide_form）控制流程；对修改密码接口增加频率限制与失败锁定。

**验证说明**

静态证据：入口 POST /013；source=request/captcha/step；sink=013.php:4；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接 POST Change 请求 → 013.php:3 进入分支 → 013.php:4-5 设置 $hide_form 并继续执行修改逻辑。是否存在验证码校验及其绕过点未在 code_pack 中体现，链路不完整。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-804（验证码绕过）。证据位于 013.php:4，外部输入来自 POST 参数 Change/step，source→sink 链基于源码片段推断（llm_inferred），未做动态验证。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 3 登录字段名需按源码确认，无法确认时标注“需补充源码/路由”。

### F-4: 013.php 使用 MD5 存储口令哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.86`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:26-27`
- **来源**：`rule`

**描述**

013.php:27 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式计算后，于 013.php:30 拼入 UPDATE 语句写入 users 表 password 字段。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储属弱哈希实现。原文证据：013.php:27 `$pass_new = md5( $pass_new );`，写入点 013.php:30 `UPDATE `users` SET password = '$pass_new' ...`。

**source / sink**

- source：repository `md5(`（013.php）
- sink：013.php:27 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:27` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：013.php:27 使用 md5() 对密码进行哈希。MD5 属弱哈希算法（CWE-328），不应用于密码存储。无需发送请求，仅记录源码证据。

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

数据库泄露后，攻击者可用彩虹表/GPU 暴力快速还原用户明文口令（MD5 计算极快且无盐，相同口令哈希相同），导致账户接管；相同口令用户哈希一致还会暴露口令复用关系。属于配置/实现型弱点，不依赖 HTTP 污点链。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令等安全用途。外部可达性：修改密码接口（013.php:3 的 isset($_POST['Change']) 分支）直接可达，任意用户提交新口令即触发。无需认证前提之外的额外条件，利用链为“弱哈希写入存储 → 库泄露后离线破解”，闭合。

**修复建议**

使用 PHP 内置 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）生成带盐慢哈希，校验用 password_verify()；迁移期可对存量 MD5 在用户下次登录时透明重哈希；禁止在口令路径使用 md5/sha1。

**验证说明**

静态证据：入口 POST /013；source=repository/md5(；sink=013.php:27；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 013.php:8 读取 → 013.php:26 转义 → 013.php:27 md5() 无盐哈希 → 013.php:30 写入 users.password。攻击者获取数据库后离线破解还原明文口令。
POC 备注：纯静态证据，不执行任何命令；不生成可运行脚本。

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
| safety_guard | 安全防护 | 3.15 | 是 |
| surface_mapper | 攻击面测绘 | 8.38 | 是 |
| deep_finder | LLM 深挖 | 8.55 | 是 |
| candidate_screener | 候选筛选 | 6.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.77 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.99 | 是 |
| coordinator | 管线协调 | 9.05 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
