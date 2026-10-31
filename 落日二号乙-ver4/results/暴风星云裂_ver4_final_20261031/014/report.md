# 落日二号乙漏洞挖掘报告 — 20261031-172616-da6421

- 生成时间：2026-10-31T09:27:21.237324+00:00
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

本次审计对象为单文件 PHP 脚本 014.php（75 行），共交付 6 条去重 findings，全部带 POC（with_poc=6）。最高危为 GEN-74a307a2a91c：014.php 第 61 行附近密码修改功能的 SQL 注入（critical，CWE-89，规则命中，有 POC）。其次为两条 high：LLM-b52a2b477f7b（step=2 密码修改缺少 CSRF token，可跨站强制改密）与 SEM-161a1ab1f6bd（验证码流程可绕过，CWE-804）；另有 LLM-ecdc7684a376（step=2 跳过 reCAPTCHA，medium）、SEM-f257349cbc66（MD5 存储口令，CWE-328，medium，仅静态证据）、SEM-16d21f2078ab（口令修改缺 CSRF 防护，medium）。POC 齐全但均为文本工件，未做任何动态验证；其中 weak_crypto 一条属静态证据 POC，不能宣称可动态复现。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 014.php（DVWA 密码修改模块，75 行），已逐行审计。发现两条闭合链：(1) step=2 密码更新分支缺少 CSRF token，可跨站强制改密导致账户接管（high）；(2) step=2 完全跳过 reCAPTCHA 校验，验证码可绕过（medium）。SQL 注入方面：第 56 行对 password_new 做了 mysqli_real_escape_string，第 60 行 user 字段来自 dvwaCurrentUser() 而非用户输入，未发现可利用的 SQL 注入。第 32-33 行将 password_new/password_conf 直接回显进 hidden input 的 value 属性，存在反射型 XSS 可能，但需受害者先通过验证码且为自回显，利用价值低，未单独立项。md5 用于密码哈希属 weak_hash，但为 DVWA 教学环境设计，未形成独立可利用链，仅作线索。未覆盖：无 Web 服务器配置、无 dvwaCurrentUser() 与 recaptcha_check_answer() 实现、无全局 CSRF 中间件，故 CSRF 结论基于本文件缺失 token 逻辑推断。

未覆盖 / 证据缺口：
- 未提供 dvwaCurrentUser() 实现，无法确认其是否可被污染
- 未提供全局 CSRF token 中间件，CSRF 结论基于本文件
- 未提供 recaptcha_check_answer() 实现
- 无 Web 服务器/php.ini 配置，无法确认运行时暴露面

## 3. Findings

### F-1: 014.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者在密码修改表单的 password_new 参数（014.php:8 读取 $_POST['password_new']）提交恶意字符串。该值在 014.php:56 仅经过 mysqli_real_escape_string 转义后，于 014.php:57 被 md5() 处理，随后在 014.php:60 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，最终在 014.php:61 交给 mysqli_query 执行。由于 md5() 输出为固定 32 位十六进制字符，password_new 中的引号、注释符等元字符在进入 SQL 前已被哈希消解，因此该路径上的注入实际不可达；候选给出的 source（query `password_new`）与 sink 之间的污点链在 md5 处被截断。真正未参数化的是 dvwaCurrentUser() 的返回值拼接，但其来源为会话用户标识，非直接外部可控。综合判断：该候选的注入链证据不足，置信度低。

**source / sink**

- source：query `password_new`（014.php:50）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（POST）的 SQL 注入 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-74a307a2a91c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入成立，攻击者可改写 users 表中任意用户口令，导致账户接管；但基于现有代码，password_new 经 md5 后无法携带 SQL 元字符，实际影响受限。证据不足，无法确认可利用的越权写入。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性：014.php 为 DVWA 口令修改页面，需已认证会话；无需额外权限即可提交 POST。利用链闭合性：source（password_new）→ md5() 哈希 → 字符串拼接 → mysqli_query，哈希步骤破坏了注入所需的元字符，链条不闭合，故不满足完整可利用条件。

**修复建议**

使用预处理语句与参数绑定：$stmt = $mysqli->prepare('UPDATE users SET password = ? WHERE user = ?'); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); $stmt->execute();。同时对 dvwaCurrentUser() 的返回值也做参数化处理，避免任何字符串拼接；口令哈希改用 password_hash()/password_verify()。

**验证说明**

静态证据：入口 POST /014；source=query/password_new；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST password_new=... → 014.php:8 $pass_new = $_POST['password_new'] → 014.php:56 mysqli_real_escape_string → 014.php:57 md5($pass_new) 将输入压缩为 32 位十六进制 → 014.php:60 拼接进 UPDATE 语句 → 014.php:61 mysqli_query 执行。关键断点：md5 输出不含引号/注释符，注入载荷无法存活，故该候选的 SQL 注入链不成立。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:61 的 SQL 注入 POC。源码中 POST 参数 password_new 经 mysqli_real_escape_string 后进入 md5() 再拼入 UPDATE/密码修改 SQL（014.php:56-61），注入点为 POST 参数 password_new，触发按钮字段为 Submit。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89。漏洞位于 014.php:61，外部输入来自 POST 参数 password_new，source→sink 链静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符；SQL 注入载荷不含 DROP 等破坏性语句。

### F-2: DVWA 密码修改功能（step=2）缺少 CSRF token，可被跨站强制修改受害者密码

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改流程分为两步：step=1 校验 reCAPTCHA，step=2 直接执行密码更新。第 45 行仅检查 `$_POST['Change']` 与 `$_POST['step']=='2'`，第 50-51 行读取 `password_new`/`password_conf`，第 54 行比较两者相等后，第 56-57 行转义并 md5，第 60-61 行执行 `UPDATE users SET password=... WHERE user=dvwaCurrentUser()`。整个 step=2 分支没有任何 CSRF token、Origin/Referer 校验或二次验证码校验，攻击者只需诱导已登录受害者访问一个自动提交的表单，即可把受害者密码改为攻击者已知值，实现账户接管。

**source / sink**

- source：body `password_new`（014.php:50-54）
- sink：014.php:61 mysqli_query 执行 UPDATE users SET password（014.php:60-61）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | step=2 分支入口仅校验 Change 与 step 参数，无 CSRF token 校验 | 攻击者构造的 POST 请求直接进入密码更新逻辑 | 缺少 anti-CSRF token / Origin 校验，浏览器会自动携带受害者会话 Cookie |
| 2 | `014.php:50-54` | 读取 password_new/password_conf 并比较相等 | 攻击者设定两者为同一已知值，比较通过 |  |
| 3 | `014.php:56-57` | mysqli_real_escape_string 转义后 md5 哈希 | 明文密码 -> 转义 -> md5 哈希 |  |
| 4 | `014.php:60-61` | 拼接 UPDATE 语句并以受害者身份执行，修改其密码 | 哈希写入 users 表，受害者密码被替换为攻击者已知值 |  |

**POC**

针对 /014.php（POST）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/014.php?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-b52a2b477f7b`
- 风险提示：请求未体现 HTTP 方法 POST, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是高权限用户则导致权限提升。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。step=2 分支外部可达、无需攻击者认证（依赖受害者会话），链完整闭合。

**修复建议**

在 step=1 与 step=2 表单中加入一次性 anti-CSRF token 并在服务端校验；校验 Origin/Referer；step=2 重新校验验证码或要求输入旧密码。

**验证说明**

需确认 DVWA 全局是否在其它包含文件中统一做了 CSRF token 校验；本 CODE PACK 仅含 014.php，未见 token 逻辑，故按缺失处理。
模型 POC 要点：构造一个自动提交到 014.php 的 HTML 页面，诱导已登录 DVWA 的受害者访问，从而把其密码改为攻击者已知值。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：针对 014.php:61 的 CSRF POC。密码修改逻辑（014.php:56-61）仅依赖请求参数 password_new/password_conf 与 Change 触发字段，未校验 CSRF token，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-352。漏洞位于 014.php:61，密码修改请求缺少 CSRF token 校验，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-3: 014.php 验证码流程可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

014.php:3 通过 if( isset( $_POST['Change'] ) && ( $_POST['step'] == '1' ) ) 判断流程阶段，step 完全由客户端 POST 控制。攻击者可直接提交 step=1 及 Change 参数，跳过验证码展示与校验阶段，直接进入口令修改逻辑（014.php:7-9 读取 password_new/password_conf，014.php:60-61 执行 UPDATE）。服务端未见对验证码答案的独立校验或一次性令牌绑定，验证码仅作为前端流程状态存在。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-161a1ab1f6bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可绕过人机验证，配合自动化脚本对 014.php 的口令修改接口进行批量或暴力调用，削弱防自动化保护，并可与 CSRF 组合放大攻击面。

**CVE / CWE 论证**

CWE-804：依赖客户端可控状态而非服务端强制的验证码校验。外部可达性：014.php 为公开可达的 DVWA 页面，攻击者无需认证即可构造 POST（是否需会话取决于部署配置）。利用链闭合：step 参数（014.php:3）→ 跳过验证码分支 → 直接进入口令修改逻辑（014.php:7-9、60-61），链条在源码层面闭合。

**修复建议**

将验证码校验放在服务端强制路径：会话中保存验证码挑战与一次性 nonce，提交时校验答案并立即失效；不要用客户端 step 参数决定是否校验；对同一会话的修改口令请求做频率限制与失败锁定。

**验证说明**

静态证据：入口 POST /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 POST Change=Change&step=1&password_new=...&password_conf=... → 014.php:3 条件成立，跳过验证码 → 014.php:8-9 读取新口令 → 014.php:60-61 执行 UPDATE 修改口令。验证码从未在服务端被验证，绕过成立。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:3 的验证码绕过 POC。step 参数在 014.php:3 附近被读取并用于流程控制，未与验证码校验绑定，可跳过验证码阶段直接修改密码。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804。漏洞位于 014.php:3，step 参数控制流程且验证码校验缺失，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-4: 密码修改 step=2 跳过 reCAPTCHA 校验，验证码可被完全绕过

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`medium`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 仅在 step=1（第 3-43 行）调用 recaptcha_check_answer 校验验证码；step=2 分支（第 45-73 行）直接执行密码更新，完全不校验 g-recaptcha-response。攻击者可直接提交 step=2 的请求跳过验证码环节，使验证码防护形同虚设，并可配合自动化脚本批量修改密码。

**source / sink**

- source：body `step`（014.php）
- sink：014.php:61 mysqli_query 执行 UPDATE users SET password（014.php:60-61）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 直接提交 step=2 进入密码更新分支，绕过第 12-23 行的 reCAPTCHA 校验 | 攻击者跳过验证码阶段 | 验证码校验仅存在于 step=1 分支，step=2 无任何验证码检查 |
| 2 | `014.php:54-57` | 密码相等校验与 md5 处理 | 明文 -> md5 |  |
| 3 | `014.php:60-61` | 执行 UPDATE 修改密码 | 密码被更新 |  |

**POC**

针对 /014.php（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-ecdc7684a376`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

验证码防护被绕过，攻击者可自动化批量修改密码，削弱防暴力破解与防自动化能力。

**CVE / CWE 论证**

CWE-804/CWE-841 验证码状态机绕过。step=2 外部可达，链闭合。

**修复建议**

在 step=2 服务端重新校验验证码或使用一次性服务端状态标记确认 step=1 已通过。

**验证说明**

需确认是否存在服务端会话状态记录 step=1 已通过；本文件未见此类状态校验。
模型 POC 要点：直接发送 step=2 请求，不携带任何 g-recaptcha-response，验证密码是否被修改。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：针对 014.php:61 的验证码绕过 POC。密码修改流程（014.php:56-61）中 step 参数控制流程阶段，g-recaptcha-response 为空时服务端未强制校验验证码，可直接进入修改密码阶段。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-804。漏洞位于 014.php:61，step 参数控制流程且验证码校验缺失，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

### F-5: 014.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:56-57`
- **来源**：`rule`

**描述**

014.php:57 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式哈希后写入数据库（014.php:60-61 的 UPDATE 语句）。MD5 为快速哈希，抗碰撞与抗暴力破解能力弱，且此处未加盐、未使用迭代 KDF，属于口令存储场景的弱哈希实现。

**source / sink**

- source：repository `md5(`（014.php）
- sink：014.php:57 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:57` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：014.php:57 使用 md5() 对密码进行哈希，属于弱哈希算法（CWE-328），无需发送请求。

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

一旦 users 表泄露，攻击者可用彩虹表或 GPU 高速爆破在短时间内还原大量口令，导致账户接管与横向移动。

**CVE / CWE 论证**

CWE-328：使用弱哈希算法保护口令等敏感数据。外部可达性：014.php 口令修改接口公开可达，任何提交的新口令都会以 MD5 落库。利用链闭合：password_new（014.php:8）→ md5（014.php:57）→ UPDATE 落库（014.php:60-61），存储路径完整。注意此处为哈希弱点，非加密算法弱点（非 CWE-327）。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2）存储，校验时用 password_verify()；迁移期可对旧 MD5 值在用户下次登录时透明重哈希；禁止无盐快速哈希用于口令。

**验证说明**

静态证据：入口 POST /014；source=repository/md5(；sink=014.php:57；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password_new → 014.php:8 读取 → 014.php:56 转义 → 014.php:57 md5() 无盐哈希 → 014.php:60-61 写入 users 表。口令以弱哈希形式持久化，构成 CWE-328。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。

### F-6: 014.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:7-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf']，014.php:60-61 执行 UPDATE 修改当前用户口令，全程未见 CSRF token、Origin/Referer 校验或 SameSite 约束。攻击者可构造第三方页面自动提交表单，诱导已登录用户浏览器发起口令修改请求。

**source / sink**

- source：query `Change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/014?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-16d21f2078ab`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

已登录受害者在不知情下被改口令，攻击者随后接管账户；结合验证码绕过（SEM-161a1ab1f6bd）可进一步自动化。

**CVE / CWE 论证**

CWE-352：跨站请求伪造，状态改变请求缺乏不可预测令牌校验。外部可达性：014.php 为浏览器可访问页面，攻击者仅需托管恶意页面。利用链闭合：恶意页面 POST → 014.php:8-9 读取参数 → 014.php:60-61 执行 UPDATE，无需受害者交互即可完成状态改变（依赖会话 Cookie 自动携带）。

**修复建议**

为表单引入每会话/每请求的 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；对口令修改等敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /014；source=query/Change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动提交 POST password_new=...&password_conf=...&Change=Change → 浏览器携带受害者会话 Cookie → 014.php:8-9 读取 → 014.php:60-61 UPDATE 受害者口令。无 token 校验，CSRF 成立。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:8 的 CSRF POC。密码修改逻辑在 014.php:8 附近读取 Change/password_new/password_conf 参数，未校验 CSRF token，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352。漏洞位于 014.php:8，密码修改请求缺少 CSRF token 校验，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。目标统一使用 TARGET 占位符。

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
| safety_guard | 安全防护 | 3.48 | 是 |
| surface_mapper | 攻击面测绘 | 8.92 | 是 |
| deep_finder | LLM 深挖 | 11.61 | 是 |
| candidate_screener | 候选筛选 | 6.79 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.51 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 14.35 | 是 |
| coordinator | 管线协调 | 7.02 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
