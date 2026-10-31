# 落日二号乙漏洞挖掘报告 — 20261031-214417-35d923

- 生成时间：2026-10-31T13:45:27.592316+00:00
- 输入：`$WORKSPACE\暴风星云裂\023.zip`
- 输入模式：`zip`
- SHA256：`aada7600a62949bf4930c902cfe7f7a69ee803e85804c9c7ea164d938a3b0b7a`
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

本次汇总基于 6 条已去重 findings，全部集中在单文件 PHP 脚本 023.php（约 30 行），无框架、无路由清单。最高危为 GEN-2fcabc51c287（sql_injection，critical，023.php 第 17 行附近的口令修改逻辑），其次为 LLM-fb8cc628a9b1（csrf，high，可跨站强制改密导致账户接管）与 SEM-e5f2216eebb4（brute_force，high，口令修改流程缺少速率限制/失败锁定）。另有 3 条 medium：SEM-de6429df0eff 与 LLM-3fa1c975a8fc 实为同一问题（无盐 MD5 存储口令，CWE-328，应归为 weak_hash，SEM 条目类型标注为 weak_crypto 属类型串用，需人工归并），以及 SEM-b5cfc3d8dbaa（csrf，medium，与 high 级 CSRF 条目同源，属重复降级）。6 条均标记 has_poc=true，但其中 weak_hash/weak_crypto 两条只有静态证据 POC（代码/算法层面），不能宣称可动态复现；sql_injection、csrf、brute_force 三条为 HTTP 语义 POC，同样仅为文本工件，未执行、未动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 023.php（30 行，DVWA 密码修改模块）。已审计其唯一入口（$_GET['Change'] 分支）与唯一 sink（第 16-17 行 UPDATE 拼接执行）。发现两条可闭合问题：(1) 密码修改缺少 CSRF token 且接受 GET，可跨站强制改密导致账户接管（high）；(2) 密码使用无盐 MD5 存储（medium，CWE-328）。SQL 注入方面：password_new 经 mysqli_real_escape_string 转义后仅作为字符串值拼入，current_user 来自 dvwaCurrentUser() 服务端会话，未发现可改变 SQL 语法的外部可控拼接，故不报告 SQL 注入。XSS 方面：$html 仅拼接固定文案，未回显用户输入，不构成 XSS。未覆盖范围：无 php.ini/Web 服务器配置、无会话 Cookie 属性（SameSite/Secure）信息、无 dvwaCurrentUser() 实现，CSRF 实际可利用性依赖 Cookie SameSite 设置，需人工确认。

未覆盖 / 证据缺口：
- 缺少 dvwaCurrentUser() 实现，无法确认 current_user 是否可能被污染
- 缺少会话 Cookie 的 SameSite/Secure 配置，影响 CSRF 可利用性
- 无部署/认证前置信息，无法确认脚本是否对外暴露
- 无数据库 schema，MD5 存储为基于代码与 DVWA 惯例的推断

## 3. Findings

### F-1: 023.php 口令修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（023.php:5 `$pass_new = $_GET['password_new'];`）提交输入，与 password_conf 一起进入口令修改流程。023.php:11 仅用 mysqli_real_escape_string 处理 $pass_new，随后 023.php:12 对其做 md5()，因此进入 SQL 的值是 32 位十六进制串，单引号等元字符已被 md5 归一化，无法从 password_new 直接闭合 023.php:16 中 `password = '$pass_new'` 的引号。真正未经过滤拼接的是 023.php:16 的 `$current_user`（来自 dvwaCurrentUser()，023.php:15），它被直接拼进 `WHERE user = '...'`，最终在 023.php:17 由 mysqli_query 执行。因此候选标注的 source（password_new）与 sink 之间的污点链在源码层面并不闭合：password_new 经 md5 后不具备注入能力；可利用点取决于 dvwaCurrentUser() 的返回值是否可被外部影响（该函数定义不在本次 code_pack 中，证据不足）。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `023.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /023（GET）的 SQL 注入 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2fcabc51c287`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 $current_user 可被攻击者影响，则可篡改 UPDATE 语句的 WHERE 条件，批量改写 users 表中任意用户口令，导致账户接管；若仅 password_new 可控，则实际影响为口令被 md5 后写入，不构成 SQL 注入。当前证据下无法确认可利用性。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性成立（GET 参数、无需认证即可到达 023.php 的修改逻辑，认证条件取决于 DVWA 会话配置）；但利用链未闭合——password_new 经 md5() 后无法注入，唯一未净化拼接点为 $current_user，其可控性证据不足，故不满足 CVE 级论证。

**修复建议**

对 023.php:16 的 UPDATE 使用预处理语句并绑定参数（mysqli_prepare + bind_param），不要字符串拼接 $current_user；对 $current_user 做白名单校验（仅允许已登录会话中的用户名，且与 session 中的身份比对）；口令哈希改用 password_hash()/password_verify()（PASSWORD_DEFAULT），不要用 md5；同时移除 023.php:17 中把 mysqli_error 直接回显到页面的 die() 分支，避免报错信息泄露。

**验证说明**

静态证据：入口 GET /023；source=query/password_new；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：入口：GET password_new / password_conf（023.php:5-6）→ 023.php:11 mysqli_real_escape_string → 023.php:12 md5() 归一化为 32 位十六进制 → 023.php:16 拼入 `SET password = '$pass_new'`（此处已无注入能力）；另一路 dvwaCurrentUser()（023.php:15）未经处理拼入 `WHERE user = '...'` → 023.php:17 mysqli_query 执行。结论：候选给出的 password_new→sink 链在 md5 处断开，需补充 dvwaCurrentUser() 的实现才能判定是否构成真实注入。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php 的 SQL 注入 POC。源码 023.php:17 将 GET 参数 password_new 直接拼入 SQL 语句，未做参数化处理。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89。漏洞位于 023.php:17，外部输入来自 GET 参数 password_new，source→sink 链静态闭合，未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

### F-2: DVWA 密码修改功能（023.php）缺少 CSRF token，可被跨站强制修改受害者密码导致账户接管

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:3-17`
- **来源**：`llm_finding`

**描述**

023.php 在 `$_GET['Change']` 存在时直接读取 `password_new` 与 `password_conf`，仅校验两者相等（第 9 行），随后经 mysqli_real_escape_string + md5 后拼入 UPDATE 语句（第 16-17 行）修改当前登录用户密码。整个流程没有任何 CSRF token、Referer 校验、原密码确认或二次认证，且接受 GET 请求，因此攻击者只需诱导已登录受害者访问一个携带 `Change=Change&password_new=X&password_conf=X` 的链接/图片即可把受害者密码改为攻击者已知值，进而接管账户。

**source / sink**

- source：query `password_new`（023.php:5-6）
- sink：023.php:17 第 16-17 行拼接 UPDATE users SET password 并 mysqli_query 执行，修改当前会话用户密码

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 检测到 $_GET['Change'] 即进入密码修改分支，无任何来源/令牌校验 | 攻击者可控的 GET 请求 |  |
| 2 | `023.php:5-6` | 读取 password_new / password_conf | 攻击者指定新密码明文 |  |
| 3 | `023.php:9` | 仅比较两次输入是否相等，无原密码/CSRF token 校验 | 两值相等即通过 |  |
| 4 | `023.php:15-17` | 取当前登录用户并执行 UPDATE 修改其密码 | md5 后的新密码写入数据库 | 无 CSRF token、无 Referer 校验、接受 GET，跨站可触发 |

**POC**

针对 /023.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-fb8cc628a9b1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户的密码可被跨站静默修改，导致账户接管；若受害者是管理员则进一步扩大影响。

**CVE / CWE 论证**

CWE-352 跨站请求伪造：外部可触发、无需攻击者认证、仅依赖受害者会话，链完整闭合。

**修复建议**

为密码修改表单加入随机 CSRF token 并在服务端校验；改用 POST；要求输入原密码或二次认证；校验 Referer/Origin。

**验证说明**

需确认部署中 DVWA 会话 Cookie 的 SameSite 设置；若为 Lax/Strict 则跨站 GET 携带 Cookie 受限，需改用顶层导航或 POST 场景验证。
模型 POC 要点：构造一个自动发起 GET 请求的页面/图片，诱导已登录 DVWA 的受害者访问，将其密码改为攻击者已知值。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php 的 CSRF POC。修改密码操作通过 GET 请求完成，参数为 Change、password_new、password_conf，无 CSRF token 校验，可被跨站诱导触发。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-352。023.php:17 处理修改密码逻辑，无 token 校验，状态改变请求可被跨站伪造。
POC 备注：需受害者已登录会话；POC 为文本，不执行。目标使用 TARGET 占位符，仅限授权测试。

### F-3: 023.php 口令修改流程缺少速率限制/失败锁定（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

候选将 023.php:4-5 标注为登录流程并称缺少失败计数与锁定。但源码片段显示 023.php:5-6 读取的是 password_new / password_conf，属于口令修改（change password）功能，并非登录认证；该文件中未见用户名/口令校验逻辑，也未见失败计数、锁定或速率限制代码。由于 code_pack 未包含登录处理文件与 dvwaCurrentUser() 实现，无法确认是否存在独立的登录接口及其防护状态。因此「暴力破解防护缺失」在本文件范围内证据不足，且候选的 source 标注（query `Login`）与源码不符。

**source / sink**

- source：query `Login`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（GET）的 暴力破解防护缺失 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e5f2216eebb4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足：若确无速率限制，攻击者可对认证接口进行在线口令猜测；但在 023.php 中未观察到认证校验点，无法据此认定可利用。

**CVE / CWE 论证**

CWE-307：证据不足。023.php 片段中不存在登录认证逻辑，无法证明失败计数/锁定缺失；需补充登录处理文件与认证中间件代码后才能论证外部可达性与利用链闭合。

**修复建议**

在认证入口统一实施失败计数与指数退避、账户/IP 维度限流、验证码或 MFA；记录并告警异常登录；口令修改接口要求原口令校验。上述措施需落到实际登录处理文件中（本次未提供）。

**验证说明**

静态证据：入口 GET /023；source=query/Login；sink=023.php:5；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选声称：攻击者重复请求 023.php:5 的 Login 参数进行口令猜测。实际源码 023.php:5 为 `$_GET['password_new']`，属口令修改参数，非登录凭据；链条在源码层面不成立，需补充真实登录端点证据。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php 的暴力破解防护缺失 POC（源码 023.php:5 附近处理 Login 参数）。登录接口无锁定/速率限制/验证码。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-307。023.php:5 处理 Login 参数，无速率限制/锁定机制。
POC 备注：POC 为文本，不执行；目标使用 TARGET 占位符，仅限授权测试。

### F-4: 023.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:11-12`
- **来源**：`rule`

**描述**

023.php:12 `$pass_new = md5( $pass_new );` 对口令使用 MD5 做无盐单轮哈希，随后在 023.php:16-17 写入 users 表 password 字段。MD5 计算极快且无盐，攻击者一旦获取数据库（如通过备份泄露、SQL 注入或数据库直连），可用 GPU/彩虹表在极短时间内还原常见口令；相同口令产生相同哈希，也便于横向比对。注意：该问题本质是弱哈希（CWE-328），不是弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（023.php）
- sink：023.php:12 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:12` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：023.php:12 使用 md5() 对密码做哈希，属弱哈希算法（CWE-328），无需发送请求，仅源码审查。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 023.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-de6429df0eff`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可被快速离线爆破还原，导致用户账户接管；相同口令哈希一致，泄露用户间口令复用关系。属于配置/实现型弱点，无需 HTTP 污点链即可成立。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令这一安全用途，算法本身不具备口令哈希所需的慢速与加盐特性。外部可达性：任何能触发口令修改的请求都会写入 MD5 值；无需特殊权限即可观察到该实现（源码级）。利用链为「数据库读取 → 离线爆破 → 账户接管」，闭合性依赖数据库泄露前提。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）生成带盐慢哈希，校验用 password_verify()；迁移期可对存量 MD5 值在用户下次登录成功后透明重哈希；禁止在任何新代码中使用 md5()/sha1() 处理口令或令牌。

**验证说明**

静态证据：入口 GET /023；source=repository/md5(；sink=023.php:12；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：入口：GET password_new（023.php:5）→ 023.php:11 mysqli_real_escape_string → 023.php:12 md5() 生成无盐哈希 → 023.php:16-17 写入 users.password。根因在 023.php:12 的算法选择，与输入是否被转义无关。
POC 备注：纯静态证据，无网络请求；POC 为文本，不执行。

### F-5: 023.php 使用无盐 MD5 存储用户密码（CWE-328）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:12-17`
- **来源**：`llm_finding`

**描述**

第 12 行对用户新密码仅做 `md5($pass_new)` 后直接写入数据库（第 16-17 行），未使用盐值或慢哈希（bcrypt/argon2）。MD5 计算极快且无盐，一旦数据库泄露可通过彩虹表/暴力快速还原明文，且相同密码产生相同哈希，便于批量破解。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 第 16-17 行将 MD5 哈希写入 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 读取用户新密码 | 明文密码 |  |
| 2 | `023.php:12` | 无盐 MD5 哈希 | 32 位 MD5 十六进制 |  |
| 3 | `023.php:16-17` | 写入数据库 | 弱哈希持久化 |  |

**POC**

针对 /023.php（GET）的 弱哈希算法 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-3fa1c975a8fc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后用户密码可被快速破解，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328 弱哈希：无盐 MD5 用于密码存储，属可申报的实现缺陷。

**修复建议**

改用 password_hash()（bcrypt/argon2）并配合 password_verify()，为每个密码使用独立盐。

**验证说明**

需确认数据库中 password 字段确为 MD5 存储（DVWA 默认如此），以及是否存在其他加盐层。
模型 POC 要点：该问题为存储实现缺陷，无直接远程利用请求；演示哈希可被快速还原。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php 的弱哈希 POC。023.php:12 使用 md5() 处理 password_new，属弱哈希（CWE-328）。通过提交密码并观察存储/比对行为佐证。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-328。证据位于 023.php:12 的 md5() 调用。
POC 备注：POC 为文本，不执行；目标使用 TARGET 占位符，仅限授权测试。

### F-6: 023.php 口令修改接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:4-6 通过 GET 读取 password_new / password_conf 并直接进入口令修改流程，023.php:16-17 执行 UPDATE users SET password。整个流程未见 CSRF token 校验、Origin/Referer 校验，也未要求重新输入原口令。攻击者可构造 `<img src="http://TARGET/023.php?password_new=attacker&password_conf=attacker">` 诱导已登录受害者访问，从而在受害者会话下把其口令改为攻击者已知值。使用 GET 触发状态变更进一步放大了风险（可被图片标签、预取、日志回放触发）。

**source / sink**

- source：query `Change`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-b5cfc3d8dbaa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

已登录用户的账户口令被静默篡改，攻击者随后用新口令登录，实现账户接管；若受害者是高权限账户，则导致权限提升。

**CVE / CWE 论证**

CWE-352：状态改变请求缺少不可预测令牌与来源校验。外部可达性成立（任意第三方页面可发起跨站 GET）；无需认证即可投递请求，但需受害者处于已登录会话中，利用链为「诱导访问 → 会话携带 Cookie → 口令被改」，闭合。

**修复建议**

将口令修改改为 POST；在表单中引入每会话随机 CSRF token 并在服务端比对（hash_equals）；校验 Origin/Referer 与站点一致；为会话 Cookie 设置 SameSite=Lax/Strict；修改口令前要求输入当前口令做二次确认。

**验证说明**

静态证据：入口 GET /023；source=query/Change；sink=023.php:5；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面构造指向 023.php?password_new=...&password_conf=... 的 GET 请求 → 受害者浏览器携带 DVWA 会话 Cookie 访问 023.php:5-6 → 023.php:16-17 执行 UPDATE 改写口令。缺少 token 与来源校验是链条成立的关键。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php 的 CSRF POC（源码 023.php:5 附近处理 Change 参数）。修改密码通过 GET 完成，无 token 校验。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-352。023.php:5 处理 Change 参数，无 token 校验。
POC 备注：需受害者已登录会话；POC 为文本，不执行；目标使用 TARGET 占位符，仅限授权测试。

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
| `csrf` | CWE-352 |  | 2 |
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
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.93 | 是 |
| surface_mapper | 攻击面测绘 | 7.18 | 是 |
| deep_finder | LLM 深挖 | 12.3 | 是 |
| candidate_screener | 候选筛选 | 7.21 | 是 |
| vulnerability_analyzer | 漏洞分析 | 15.85 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.46 | 是 |
| coordinator | 管线协调 | 9.91 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
