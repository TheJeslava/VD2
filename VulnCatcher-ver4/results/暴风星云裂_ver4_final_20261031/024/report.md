# 落日二号乙漏洞挖掘报告 — 20261031-172852-4b1b38

- 生成时间：2026-10-31T09:30:02.894440+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\024.zip`
- 输入模式：`zip`
- SHA256：`a2013a4944c4a1abb5e6dc291bf1a235fbddea2e99f978d43092c691e46798f1`
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

本次汇总基于已去重的 5 条 findings，全部集中在单文件 PHP 脚本 024.php（37 行），共 5 条均带 POC（with_poc=5）。最高危为 GEN-cf38b1a2cb95：024.php 密码修改功能 SQL 注入（critical，CWE-89，规则检出，行 19 附近），污点路径极短（source 约第 5 行 → sink 约第 1/19 行），一旦参数未过滤即可直接利用。其次为 LLM-3eef1cf779fd：仅依赖 HTTP_REFERER 做来源校验的 CSRF（high，可导致账户接管）与 SEM-72b85cc24676：密码修改流程缺少暴力破解防护（high，CWE-307）。另有两条中危口令存储问题：LLM-7bbc11033fc9（weak_hash，无盐 MD5，CWE-328）与 SEM-23ce27f2da1c（weak_crypto，标题实为 MD5 弱哈希，类型标注与 CWE-328 存在串类，需人工归并）。POC 形式上：SQL 注入、CSRF、暴力破解为 HTTP 型 POC 文本；weak_hash / weak_crypto 仅有静态证据 POC，不能宣称可动态复现。所有 POC 均为文本工件，未执行、未搭建沙箱、未做动态验证。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 024.php（37 行，DVWA 密码修改模块）。已逐行审计：入口为 $_GET['Change'] 触发的密码修改流程，source 为 password_new/password_conf 与 Referer 头，sink 为第19行 mysqli_query 的 UPDATE 语句。发现两条可闭合问题：(1) 密码修改仅用 Referer 子串匹配做来源校验，无 CSRF token、无原密码确认，构成 CSRF 账户接管（高危）；(2) 密码使用无盐 MD5 存储（CWE-328，中危）。SQL 注入方面：password_new 经 mysqli_real_escape_string 转义后再 md5，且 md5 输出为固定十六进制，无法注入；current_user 来自 dvwaCurrentUser() 非攻击者直接可控，故不报 SQL 注入。XSS 方面：$html 仅拼接固定文案，未回显用户输入，不构成 XSS。文件包含/命令执行/SSRF/反序列化在该文件中无对应 sink。未覆盖：dvwaCurrentUser() 实现、登录/会话逻辑、部署配置（SERVER_NAME 取值、是否置于认证后）均不在 code_pack 内，无法确认。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 定义未提供，无法确认 current_user 是否可被间接污染
- 无登录/会话代码，无法确认认证前置条件
- 无部署配置，SERVER_NAME 与 Referer 行为需运行时确认
- 无端点清单与外部证据

## 3. Findings

### F-1: 024.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 password_new（024.php:7 `$pass_new = $_GET['password_new'];`）提交外部输入。该值在 024.php:13 仅经过 mysqli_real_escape_string 转义后，于 024.php:14 被 md5() 处理，随后在 024.php:18 被直接拼接进 SQL 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，最终在 024.php:19 交给 mysqli_query 执行。由于 md5() 的输出是 32 位十六进制字符串，正常情况下会消除引号等特殊字符，因此单看 password_new 这条链，实际可利用性存疑；但同一语句中拼接的 $current_user 来自 dvwaCurrentUser()（024.php:17），若该函数返回值可被攻击者影响（例如通过会话中的用户名），则同样会进入未参数化的 SQL 拼接。当前 code_pack 未提供 dvwaCurrentUser() 的实现，无法确认其是否可控，这是本 finding 的主要证据缺口。此外，024.php:19 在查询失败时通过 die() 输出 mysqli_error()，会把数据库错误信息回显给攻击者，为基于报错的注入探测提供了便利。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `024.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /024（GET）的 SQL 注入 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cf38b1a2cb95`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入点成立，攻击者可篡改 users 表中任意用户的 password 字段（包括 admin），实现账户接管与越权登录；错误回显还会泄露数据库结构信息。当前证据下，password_new 路径因 md5 归一化而难以直接注入，实际影响取决于 $current_user 的可控性，证据不足。

**CVE / CWE 论证**

CWE-89：外部可控输入未经参数化即拼接进 SQL 语句并在 024.php:19 执行。外部可达性：该逻辑位于 DVWA 的密码修改页面，通过 GET 参数 password_new/password_conf 直接触达，无需额外权限即可访问（DVWA 默认低安全级别）。利用链闭合度：source（024.php:7）→ 拼接（024.php:18）→ sink（024.php:19）在代码层面闭合，但中间 md5() 削弱了 password_new 的可注入性，$current_user 的可控性未在给定代码中证实，因此不能断言完整可利用。

**修复建议**

1) 使用预处理语句与参数绑定改写 024.php:18-19，例如 `$stmt = $mysqli->prepare("UPDATE users SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user);`；2) 不要依赖 md5 作为“净化”手段，转义与哈希都不应替代参数化；3) 将 024.php:19 的 die(mysqli_error(...)) 改为记录日志并返回通用错误页，避免数据库错误回显；4) 对 $current_user 做来源校验，确保其仅来自服务端会话且经过白名单约束。

**验证说明**

静态证据：入口 GET /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向密码修改端点发送 GET 请求，携带 password_new 参数（024.php:7）。该值在 024.php:13 经 mysqli_real_escape_string 转义、024.php:14 经 md5 哈希后，于 024.php:18 被字符串拼接进 UPDATE 语句，并在 024.php:19 由 mysqli_query 执行；失败时 die() 回显 mysqli_error。由于 md5 输出为固定十六进制串，password_new 路径的直接注入被削弱；同一语句中拼接的 $current_user（024.php:17，dvwaCurrentUser() 返回值）若可被外部影响，则构成实际注入通道，但其实现未包含在 code_pack 中，无法确认。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php 第 19 行附近密码修改逻辑的 SQL 注入 POC。源码将 GET 参数 password_new 直接拼入 UPDATE/查询语句（仅经 mysqli_real_escape_string 处理，未参数化），攻击者可通过布尔/报错注入改变 SQL 语义。目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89（SQL 注入）。证据位于 024.php:19，外部输入来自 GET 参数 password_new，source→sink 链在给定代码范围内静态闭合，仅使用 mysqli_real_escape_string 而未参数化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。所有请求中主机名使用 TARGET:8080 占位符，需在授权环境中替换后手动发送。禁止使用 DROP/TRUNCATE 等破坏性语句。

### F-2: DVWA 024.php 密码修改功能仅用 HTTP_REFERER 做来源校验，可被 CSRF 绕过并接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 在 `$_GET['Change']` 存在时执行密码修改：读取 `password_new`/`password_conf`（第7-8行），比较相等后 md5 并直接 UPDATE `users` 表当前用户密码（第18-19行）。唯一的“防护”是第5行 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false`，即只检查 Referer 中是否包含本站 SERVER_NAME 子串。Referer 是客户端完全可控的请求头：攻击者可构造 `Referer: http://TARGET/` 或 `Referer: http://attacker.com/?TARGET`（只要包含 SERVER_NAME 子串）即可通过校验；更常见的是攻击者页面通过 `<form>` 提交时浏览器会带上攻击者站点 Referer，但攻击者可用 `Referrer-Policy: no-referrer` 或中间跳转/`<meta name=referrer content=no-referrer>` 使 Referer 缺失——注意缺失时 `stripos(null, SERVER_NAME)` 返回 false 会失败，因此实际利用方式是让 Referer 包含 SERVER_NAME 子串（如 `http://TARGET/` 或 `http://evil/?TARGET`）。由于密码修改无 CSRF token、无原密码确认、无二次认证，攻击者诱导已登录管理员访问恶意页面即可把管理员密码改为攻击者已知值，实现账户接管。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 mysqli_query 执行 UPDATE users SET password=... WHERE user=当前用户（第19行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 检测到 $_GET['Change'] 存在，进入密码修改分支 | 攻击者控制 Change 参数 |  |
| 2 | `024.php:5` | 仅用 stripos 检查 Referer 是否包含 SERVER_NAME 子串作为来源校验 | Referer 头由客户端完全控制 | Referer 可伪造为包含 SERVER_NAME 子串的任意值（如 http://TARGET/ 或 http://evil/?TARGET），stripos 子串匹配不构成可信来源校验 |
| 3 | `024.php:7-8` | 读取新密码与确认密码 | 攻击者提供 password_new=password_conf |  |
| 4 | `024.php:11-14` | 两密码相等则 md5 处理 | md5(password) |  |
| 5 | `024.php:17-19` | 拼接 UPDATE 语句并执行，修改当前登录用户密码 | SQL 执行，密码被覆盖 |  |

**POC**

针对 /024.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-3eef1cf779fd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者已登录情况下静默修改其密码，实现账户接管；若受害者是管理员则接管后台。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。密码修改端点无 CSRF token、无原密码校验，仅依赖可伪造的 Referer 子串匹配，外部可达且链闭合。

**修复建议**

引入 CSRF token 并在服务端校验；要求提交原密码；不要依赖 Referer 做安全校验；密码修改使用 POST 并加 SameSite Cookie。

**验证说明**

需确认 DVWA 部署下 SERVER_NAME 取值及 Referer 伪造在目标浏览器/代理下是否被保留；缺失 Referer 时校验失败，需确保 Referer 含 SERVER_NAME 子串。
模型 POC 要点：诱导已登录用户（或直接以受害者会话）发起带伪造 Referer 的 GET 请求修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php 密码修改功能的 CSRF POC。修改口令的请求仅依赖 GET 参数（Change、password_new、password_conf），未校验 CSRF token，攻击者可诱导已登录用户浏览器发起请求从而静默修改其口令。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352（跨站请求伪造）。证据位于 024.php:19，口令修改逻辑直接消费 GET 参数且给定代码范围内未见 token/来源校验。
POC 备注：POC 为文本工件，不执行。HTML 片段仅用于说明攻击页面结构，需在授权测试环境中由测试者手动加载。主机名使用 TARGET 占位符。

### F-3: 024.php 密码修改流程缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:6-7`
- **来源**：`rule`

**描述**

024.php:6-8 直接读取 GET 参数 password_new 与 password_conf，随后在 024.php:17-19 执行口令更新，整个流程未见失败计数、账户锁定、速率限制、验证码或 CSRF 令牌等防护措施。需要说明：该文件实现的是“修改密码”而非“登录认证”，因此将其判定为登录暴力破解（CWE-307）在语义上并不完全吻合；更贴切的弱点是缺少 CSRF 防护与缺少对重复请求的节流。当前证据不足以确认存在可被暴力枚举的认证校验点。

**source / sink**

- source：query `Login`（024.php）
- sink：024.php:7 		$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /024（GET）的 暴力破解防护缺失 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-72b85cc24676`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若该端点可被匿名或低权限用户反复调用，攻击者可高频尝试/覆盖口令或进行自动化滥用；缺少 CSRF 令牌时，还可诱导已登录用户在其会话下被静默修改口令。具体影响受 DVWA 部署与认证前置条件约束，证据不足。

**CVE / CWE 论证**

CWE-307（对过度认证尝试的不当限制）：024.php:6-19 的流程中未见任何尝试计数、锁定或速率限制代码。但该端点本质是口令修改而非登录校验，是否构成“认证尝试”需结合未提供的会话/认证中间件判断，因此外部可达性与利用链闭合度证据不足，不能断言为已确认的暴力破解漏洞。

**修复建议**

1) 为该端点增加 CSRF 令牌校验（如 DVWA 的 generateSessionToken/checkToken）；2) 在网关或应用层对同一会话/IP 的密码修改请求实施速率限制与失败计数；3) 修改口令前要求验证当前口令；4) 记录并告警异常高频请求。

**验证说明**

静态证据：入口 GET /024；source=query/Login；sink=024.php:7；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 024.php 反复发送携带 password_new/password_conf 的 GET 请求（024.php:6-8），流程在 024.php:17-19 直接执行 UPDATE，未做任何节流或令牌校验。由于缺少认证上下文与中间件代码，无法确认该端点是否可被匿名高频调用，故仅作为待复核的防护缺失项。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php 登录/口令修改入口缺乏暴力破解防护的 POC。源码第 7 行附近处理登录参数，未见失败计数、锁定、速率限制或验证码机制，攻击者可高频尝试口令。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-307（认证尝试限制不当）。证据位于 024.php:7，登录处理逻辑在给定代码范围内未见限流或锁定。
POC 备注：POC 为文本工件，不执行。实际测试须严格控制请求频率与次数，避免对目标造成拒绝服务影响。

### F-4: 024.php 使用无盐 MD5 存储用户密码

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:14-19`
- **来源**：`llm_finding`

**描述**

第14行 `$pass_new = md5( $pass_new );` 将新密码直接做无盐 MD5 后写入 users 表（第18-19行）。MD5 属快速哈希，无盐、无迭代，易被彩虹表/GPU 暴力破解；一旦数据库泄露，用户口令可被快速还原。属 CWE-328 弱哈希，不是 weak_crypto。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 UPDATE users SET password = md5(...)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 读取新密码 | 明文口令 |  |
| 2 | `024.php:14` | 无盐 MD5 摘要 | md5 哈希，无盐无迭代 |  |
| 3 | `024.php:18-19` | 写入数据库 | 弱哈希存储 |  |

**POC**

针对 /024.php（GET）的 弱哈希算法 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-7bbc11033fc9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时用户口令可被快速破解，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328 使用弱哈希。代码明确使用无盐 MD5 存储口令，属可申报的弱口令存储缺陷。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

需确认 users 表确由该逻辑写入且无其他加盐环节。
模型 POC 要点：该问题为存储型弱哈希，利用依赖数据库泄露后离线破解
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php 口令存储使用 MD5 的弱哈希 POC。源码第 14 行 `$pass_new = md5($pass_new);` 将用户口令以无盐 MD5 存储，属于 CWE-328 弱哈希，可被彩虹表/GPU 快速破解。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-328（弱哈希）。证据位于 024.php:14，明确调用 md5() 且无盐值。
POC 备注：POC 为文本工件，不执行。哈希读取步骤需在授权测试环境内完成，不得对生产库操作。

### F-5: 024.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:13-14`
- **来源**：`rule`

**描述**

024.php:14 执行 `$pass_new = md5( $pass_new );`，将用户提交的新口令（024.php:7 的 password_new）以无盐 MD5 单轮哈希后写入 users 表（024.php:18-19 的 UPDATE 语句）。MD5 属于已破解的快速哈希算法，且此处未使用盐值或迭代拉伸，属于口令存储场景下的弱哈希实现。注意：该问题应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法缺陷）。

**source / sink**

- source：repository `md5(`（024.php）
- sink：024.php:14 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:14` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：024.php 第 14 行使用 md5() 处理口令，属于弱加密/弱哈希算法使用（CWE-327/328 交叉）。无需发送请求，通过源码审查即可确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 024.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-23ce27f2da1c`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后，攻击者可用彩虹表或 GPU 暴力快速还原用户明文口令；由于 DVWA 用户口令常被复用，可进一步导致账户接管。无盐设计还使相同口令产生相同哈希，便于批量识别。

**CVE / CWE 论证**

CWE-328：MD5 被用于口令等安全敏感用途。该弱点为配置/实现型，不依赖 HTTP 污点链；原文证据为 024.php:14 的 `md5( $pass_new )` 调用，且 024.php:18 的 UPDATE 语句表明其结果被持久化为用户口令。外部可达性：任何能访问密码修改功能的用户都会触发该哈希路径。

**修复建议**

改用专为口令设计的慢哈希算法，如 PHP 的 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2），校验时使用 password_verify；迁移期可对旧 MD5 值在用户下次登录时透明重哈希。禁止使用 md5/sha1 存储口令。

**验证说明**

静态证据：入口 GET /024；source=repository/md5(；sink=024.php:14；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户在密码修改页面提交 password_new（024.php:7），经 024.php:13 转义后在 024.php:14 被 md5() 单轮无盐哈希，随后在 024.php:18-19 写入 users 表。攻击者一旦获取数据库转储，即可对 MD5 值进行离线快速破解，还原明文口令。
POC 备注：纯静态证据，不执行任何请求。行号 14 来自输入提供的代码片段。

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
| safety_guard | 安全防护 | 4.31 | 是 |
| surface_mapper | 攻击面测绘 | 9.38 | 是 |
| deep_finder | LLM 深挖 | 12.82 | 是 |
| candidate_screener | 候选筛选 | 8.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.2 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 15.25 | 是 |
| coordinator | 管线协调 | 7.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
