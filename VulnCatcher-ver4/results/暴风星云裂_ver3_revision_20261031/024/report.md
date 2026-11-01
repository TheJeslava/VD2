# 落日二号乙漏洞挖掘报告 — 20261031-011811-8e2216

- 生成时间：2026-10-30T17:19:09.557490+00:00
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

本次审计范围是单文件 PHP 脚本 024.php（37 行），共交付 5 条去重后的 findings，全部带 POC（with_poc=5）。最高危的是 GEN-cf38b1a2cb95：024.php 第 19 行修改口令处存在 SQL 注入（critical，CWE-89），属于规则命中，有 HTTP POC。其次是 LLM-3eef1cf779fd：同一处仅依赖 HTTP_REFERER 校验，可被 CSRF 绕过并导致账户接管（high）；以及 SEM-72b85cc24676：口令修改流程缺少速率限制与失败锁定（high，CWE-307）。另有两条中危口令存储问题：SEM-23ce27f2da1c 与 LLM-7bbc11033fc9 实际指向同一事实（无盐 MD5 存储口令），类型标注不一致（weak_crypto 与 weak_hash），按 CWE-328 应归为 weak_hash，建议合并，避免重复计数。POC 齐全，但均为静态文本工件，未做动态验证；weak_hash 类只有静态证据 POC，不能宣称可动态复现。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 024.php（37 行，DVWA 密码修改模块）。已逐行审计：入口为 $_GET['Change'] 触发的密码修改流程，source 为 password_new/password_conf 与 HTTP_REFERER，sink 为 024.php:18-19 的 UPDATE 语句。发现两条可闭合问题：(1) 仅依赖可伪造的 HTTP_REFERER 做来源校验、无 CSRF token、无原密码验证，构成认证后 CSRF 账户接管（高危）；(2) 使用无盐 MD5 存储口令（中危，需数据库泄露前提）。SQL 注入方面：password_new 在第 13 行经 mysqli_real_escape_string 转义，current_user 来自 dvwaCurrentUser() 服务端函数，未发现可注入点，故不报告 sql_injection。未发现命令执行、文件包含、反序列化、SSRF、XSS 回显等 sink。未覆盖：无 php.ini/Web 服务器配置、无路由与认证配置、无依赖清单，无法评估部署开关与第三方组件；dvwaCurrentUser() 与数据库连接初始化代码不在 code_pack 内，其返回值是否可信未验证。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现未提供，无法确认 current_user 是否可能被污染
- 数据库连接与全局 ___mysqli_ston 初始化代码未提供
- 无部署配置，无法确认 register_globals/allow_url_include 等开关
- 无端点清单，实际 URL 路径与认证要求未确认

## 3. Findings

### F-1: 024.php 修改口令处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 password_new（024.php:7 `$pass_new = $_GET['password_new'];`）提交输入。该值在 024.php:13 仅经过 mysqli_real_escape_string 转义，随后在 024.php:14 被 md5() 处理，最终在 024.php:18 被直接拼接进 SQL 语句 `UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';`，并在 024.php:19 交给 mysqli_query 执行。由于 md5() 的输出是 32 位十六进制字符串，正常情况下会消除引号等元字符，因此单看 password_new 这条链，注入难以闭合；真正的风险点在于 024.php:18 中 $current_user 由 dvwaCurrentUser()（024.php:17）返回并直接拼接进 SQL，而该函数的值来源于会话中的用户名，属于可被攻击者间接影响的数据。此外，024.php:19 在查询失败时通过 die() 输出 mysqli_error，构成报错型注入的信息泄露通道。当前证据只能确认拼接与报错回显存在，尚未看到 dvwaCurrentUser() 的实现，无法确认其是否可被外部控制，因此该注入的可利用性证据不足。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `024.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /024（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/024?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cf38b1a2cb95`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 $current_user 可被攻击者影响（例如通过注册或修改用户名的功能写入恶意用户名），则可篡改 users 表中任意用户的 password 字段，导致账号接管；即使不能注入，024.php:19 的 mysqli_error 回显也会泄露 SQL 结构、表名与列名，为后续攻击提供信息。

**CVE / CWE 论证**

CWE-89：外部输入未经参数化即拼接进 SQL 并执行，且错误信息回显。外部可达性：024.php 为 DVWA 的 CSRF 模块页面，GET 参数可直接访问；无需认证即可到达代码路径（DVWA 默认低安全级别下会话可建立）。利用链闭合度：password_new 经 md5 后元字符被消除，注入闭合依赖 $current_user 的可控性，该环节证据不足，故不能断言完整可利用链。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('UPDATE users SET password = ? WHERE user = ?'); $stmt->bind_param('ss', $pass_new, $current_user);`；对 $current_user 做白名单校验（仅允许已存在用户名）；关闭错误回显，将 mysqli_error 写入服务端日志而非响应体；口令哈希改用 password_hash()/password_verify()。

**验证说明**

静态证据：入口 ANY /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 024.php:7 $pass_new → 024.php:13 mysqli_real_escape_string → 024.php:14 md5() → 024.php:18 字符串拼接进 UPDATE 语句（同时拼接 dvwaCurrentUser() 返回值）→ 024.php:19 mysqli_query 执行，失败时 die() 回显 mysqli_error。注入闭合的关键在于 $current_user 是否可控，当前证据不足。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:19 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 后仍被拼接进 UPDATE/密码变更 SQL（024.php:13-19），构成 CWE-89。注入通道为 query 参数 password_new，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89。漏洞位于 024.php:19，外部输入来自 query 参数 password_new，source→sink 链在给定代码片段内静态闭合，未见参数化查询或类型强制，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，管线不执行、不联网。执行前将 TARGET 替换为授权目标，禁止使用 DROP/破坏性语句。

### F-2: DVWA 密码修改功能仅依赖 HTTP_REFERER 校验，可被 CSRF 绕过实现账户接管

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 第 3 行通过 `$_GET['Change']` 触发密码修改流程，第 5 行仅用 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false` 判断请求来源，随后第 7-8 行直接读取 `password_new`/`password_conf`，第 11 行比较相等后在第 14 行 md5 并在第 18-19 行执行 UPDATE 修改当前用户密码。HTTP_REFERER 完全由客户端控制，攻击者可在恶意页面中构造 Referer 包含目标域名的请求，或直接省略/伪造该头，从而绕过唯一的“来源校验”。整个流程没有任何 CSRF token、没有对原密码的验证、没有二次确认，属于典型的认证后 CSRF 导致账户接管。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 024.php:18-19 拼接 UPDATE 语句并 mysqli_query 修改当前登录用户密码

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 攻击者诱导已登录受害者访问带 Change 参数的链接，触发密码修改分支 | $_GET['Change'] 存在即进入 |  |
| 2 | `024.php:5` | 仅用 stripos 判断 HTTP_REFERER 是否包含 SERVER_NAME，该头由客户端完全控制 | HTTP_REFERER 可任意伪造或省略 | Referer 是客户端可控头，攻击者页面可设置 Referer 含目标域名，或浏览器策略下省略 Referer 时 stripos 返回 false 但可通过伪造绕过；无 CSRF token |
| 3 | `024.php:7-8` | 读取新密码与确认密码参数 | 攻击者指定 password_new=password_conf=攻击者密码 |  |
| 4 | `024.php:11-14` | 两次密码相等则 md5 处理 | 明文密码 -> md5 哈希 |  |
| 5 | `024.php:17-19` | 以当前会话用户身份执行 UPDATE 修改密码 | 哈希写入 users 表 password 字段 |  |

**POC**

针对 /024.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-3eef1cf779fd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户的密码可被第三方静默修改，导致账户完全接管；若受害者是管理员则进一步控制整个应用。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。外部可达、无需知道原密码、仅依赖可伪造的 Referer 头作为防护，链完整闭合，属于 DVWA 已知 CSRF 漏洞模式。

**修复建议**

引入每个会话唯一的 CSRF token 并在服务端校验；修改密码前要求验证原密码；不要依赖 HTTP_REFERER 作为安全控制。

**验证说明**

需确认部署环境中浏览器是否发送 Referer 以及 stripos 判断的实际行为；动态验证需在授权环境构造跨站请求确认密码确实被修改。
模型 POC 要点：构造恶意页面，诱导已登录 DVWA 的受害者访问，自动提交修改密码请求，将受害者密码改为攻击者已知值，随后攻击者用新密码登录接管账户
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php:19 的 CSRF POC。密码变更逻辑仅依赖 GET/POST 参数 password_new/password_conf，未见 CSRF token 或 Origin/Referer 校验（024.php:7-19），构成 CWE-352。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352。024.php:19 的密码变更逻辑缺少反 CSRF token 与来源校验，具备远程触发条件。
POC 备注：仅限授权测试；poc.html 为文本工件，不自动执行。TARGET 为占位符，需替换为授权目标。

### F-3: 024.php 口令修改流程缺少速率限制与失败锁定（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:6-7`
- **来源**：`rule`

**描述**

024.php:6-8 直接读取 GET 参数 password_new 与 password_conf，代码中未见失败计数、账户锁定、验证码或速率限制逻辑。攻击者可在授权测试环境中对同一端点重复发起请求，进行口令猜测或批量尝试。需注意该页面为口令修改而非登录校验，暴力破解的实际收益取决于是否存在旧口令校验逻辑，当前片段未包含该逻辑，证据不足。

**source / sink**

- source：request `login/password`（024.php）
- sink：024.php:7 		$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /024（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/024?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-72b85cc24676`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该端点参与口令校验或可被用于枚举，则攻击者可高频尝试口令，配合弱哈希（见 SEM-23ce27f2da1c）加速离线/在线爆破，导致账号接管。

**CVE / CWE 论证**

CWE-307（Improper Restriction of Excessive Authentication Attempts）：认证相关流程缺少尝试次数限制。外部可达性：024.php 可直接通过 GET 访问；无需认证即可到达参数读取路径。利用链闭合度：片段中未见认证校验与失败分支，无法确认爆破目标，证据不足。

**修复建议**

在服务端引入按账户与按 IP 的失败计数与指数退避、临时锁定、验证码；记录并告警异常频率；结合强口令策略与 password_hash 存储。

**验证说明**

静态证据：入口 ANY /024；source=request/login/password；sink=024.php:7；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new/password_conf → 024.php:7-8 读取 → 后续处理（片段未展示校验与失败分支）→ 无速率限制即可重复请求。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:7 的暴力破解防护缺失 POC。登录/口令变更入口未见失败计数、锁定或速率限制（024.php:7-19），构成 CWE-307。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-307。024.php:7 起的认证逻辑缺少失败计数与限速。
POC 备注：仅限授权测试；请限制请求频率，避免造成拒绝服务。TARGET 为占位符。

### F-4: 024.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:13-14`
- **来源**：`rule`

**描述**

024.php:14 `$pass_new = md5( $pass_new );` 对口令使用 MD5 做单次无盐哈希，随后在 024.php:18-19 写入 users 表 password 字段。MD5 为快速哈希，抗碰撞与抗暴力破解能力不足，且未加盐，相同口令产生相同摘要，可被彩虹表与 GPU 离线爆破直接还原。该弱点为配置/实现型，无需 HTTP 污点链即可成立。

**source / sink**

- source：repository `md5(`（024.php）
- sink：024.php:14 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:14` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：024.php:14 使用 md5($pass_new) 处理口令，属弱哈希（CWE-328）。注意：本条原标注为 weak_crypto/CWE-327，但 md5 应归类为 weak_hash/CWE-328，建议修正分类。

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

数据库泄露后攻击者可离线快速还原用户明文口令；相同口令用户摘要一致，便于横向撞库，导致账号接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令等安全用途。外部可达性：024.php 为可直接访问的修改口令页面，任意用户提交口令即触发该哈希路径；无需特殊权限。利用链闭合：算法选择本身即缺陷，不依赖额外输入。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2）存储，校验使用 password_verify()；迁移期可对旧 MD5 摘要做二次哈希升级；禁止在安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /024；source=repository/md5(；sink=024.php:14；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 024.php:7 → 024.php:13 转义 → 024.php:14 md5() 单次无盐哈希 → 024.php:18 拼接 → 024.php:19 写入 users.password。
POC 备注：仅限授权测试；纯静态证据，无需发送请求。

### F-5: 密码修改使用无盐 MD5 存储口令

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:14-19`
- **来源**：`llm_finding`

**描述**

024.php 第 14 行对用户新密码执行 `md5($pass_new)` 后在第 18-19 行写入数据库，未使用盐值或慢哈希算法。MD5 属快速哈希，易被彩虹表与 GPU 暴力破解，一旦数据库泄露可快速还原明文口令。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 024.php:18-19 将 MD5 哈希写入 users 表

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 读取新密码 | 明文 |  |
| 2 | `024.php:14` | 无盐 MD5 哈希 | md5 哈希 |  |
| 3 | `024.php:18-19` | 写入数据库 | 存储的弱哈希 |  |

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

数据库泄露后口令可被快速离线破解，导致账户接管。

**CVE / CWE 论证**

CWE-328 使用弱哈希。属配置/实现型缺陷，需数据库泄露作为前提，单独利用链不完整，故置信度中等。

**修复建议**

改用 password_hash()/password_verify() 配合 bcrypt/argon2 并加盐。

**验证说明**

弱哈希本身不构成直接远程利用，需结合数据库泄露场景评估；确认生产环境是否沿用该代码。
模型 POC 要点：该问题为存储型弱哈希，需数据库泄露后离线破解；POC 展示哈希生成方式
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php:14 的弱哈希 POC。源码使用 md5($pass_new) 存储口令（024.php:14），属 CWE-328 弱哈希，可被彩虹表/高速爆破还原。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-328。024.php:14 使用 md5() 且无盐，属弱哈希算法。
POC 备注：仅限授权测试；离线比对不涉及网络。TARGET 为占位符。

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
| safety_guard | 安全防护 | 2.48 | 是 |
| surface_mapper | 攻击面测绘 | 7.62 | 是 |
| deep_finder | LLM 深挖 | 11.89 | 是 |
| candidate_screener | 候选筛选 | 6.48 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.33 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.01 | 是 |
| coordinator | 管线协调 | 7.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
