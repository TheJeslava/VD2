# 落日二号乙漏洞挖掘报告 — 20261031-014024-252388

- 生成时间：2026-10-30T17:41:18.361371+00:00
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

本次汇总基于 1 个文件（024.php，37 行 PHP 单文件脚本）的已去重 findings，共 4 条，全部带 POC（with_poc=4）。最高危为 GEN-cf38b1a2cb95：024.php 第 19 行密码修改处 SQL 注入（critical，CWE-89，规则命中，有 POC）；其次为 LLM-3eef1cf779fd：同一处仅依赖 HTTP_REFERER 校验导致 CSRF 可绕过并实现账户接管（high，模型推断，有 POC），以及 SEM-72b85cc24676：口令修改缺少暴力破解防护（high，CWE-307，有 POC）。另有 SEM-23ce27f2da1c 标注为 weak_crypto，但标题与描述实为 MD5 存储口令，按类型规范应归为 weak_hash（CWE-328），属类型标注偏差，需在交付时纠正；该条仅有静态证据 POC，不能宣称可动态复现。POC 形式上，SQL 注入与 CSRF 为 HTTP 型 POC 文本，brute_force 为请求序列型 POC 文本，weak_hash 为静态证据 POC；全部仅为文本工件，未执行、未搭建沙箱、未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 024.php（37 行，DVWA 密码修改模块）。已审计全部 37 行：入口为 $_GET['Change']/password_new/password_conf（024.php:3,7,8），来源校验仅用 HTTP_REFERER 子串匹配（024.php:5），随后 md5 后拼接 UPDATE 并 mysqli_query 执行（024.php:14,18,19）。password_new 在 024.php:13 经 mysqli_real_escape_string 转义，且 md5 后仅剩十六进制字符，SQL 注入链不成立，故未报 sql_injection。核心可闭合问题为 CSRF（Referer 可伪造 + 无 token + 无旧密码校验）导致账户接管。未覆盖：无 php.ini/Web 服务器配置、无端点清单、无部署信息，SameSite/路径等运行时条件需人工确认；weak_hash（md5 存密码，024.php:14）属实现弱点但单独不足以构成 CVE 级链，未单独立项。未发现 prompt_injection 迹象。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单，024.php 实际路由与认证要求未知
- 无 Web 服务器/php.ini 配置，SameSite、allow_url_include 等影响可利用性
- md5 存储密码（CWE-328）未单独立项，需结合整体认证设计评估
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 024.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（024.php:7 `$pass_new = $_GET['password_new'];`）提交输入。该值在 024.php:13 仅经过 mysqli_real_escape_string 转义，随后在 024.php:14 被 md5() 处理，再于 024.php:18 直接拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，最终在 024.php:19 交给 mysqli_query 执行。校验无效的原因：代码没有使用参数化查询或预处理语句，而是字符串拼接；虽然 mysqli_real_escape_string 能转义引号，但该转义发生在 md5() 之前，md5 会把转义后的字符串整体哈希为 32 位十六进制串，因此 password_new 实际进入 SQL 的是哈希值，注入面被 md5 削弱；真正未受控的是 $current_user（dvwaCurrentUser() 的返回值，024.php:17）被直接拼进 user 条件。若该值可被外部影响（如会话/用户名来源），则构成注入通道。当前证据显示 password_new 路径因 md5 前置而难以直接闭合注入，需结合 dvwaCurrentUser 的实现确认。

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

若注入链闭合，攻击者可改写 users 表中任意用户的 password 字段，实现账户接管/越权登录；错误信息经 die(mysqli_error(...)) 回显（024.php:19），可辅助报错注入与库结构泄露。

**CVE / CWE 论证**

CWE-89：外部可控数据未经参数化直接拼入 SQL 并在 mysqli_query 执行。外部可达性：password_new 为 GET 参数，无需认证即可到达该页面逻辑（DVWA 低安全级别下）。利用链闭合度：password_new 经 md5 后注入面受限，$current_user 来源需进一步确认，故当前为部分闭合，置信度中等。

**修复建议**

改用 mysqli 预处理语句与绑定参数（prepare + bind_param），对 user 条件同样参数化；移除 die(mysqli_error()) 的详细错误回显，改为通用错误页并记录日志；对 password_new/password_conf 做长度与字符白名单校验；确认 dvwaCurrentUser() 返回值来源并做服务端可信绑定，不直接拼接。

**验证说明**

静态证据：入口 ANY /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new（024.php:7）→ mysqli_real_escape_string（024.php:13）→ md5（024.php:14）→ 字符串拼接进 $insert（024.php:18，含未受控 $current_user）→ mysqli_query 执行（024.php:19）→ 失败时 mysqli_error 回显。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:19 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 SQL 语句，但该转义在特定字符集/上下文下仍可能被绕过；此处按静态证据给出布尔型注入载荷，用于验证 password_new 是否影响查询结果。目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89。证据位于 024.php:19，外部输入来自 query 参数 password_new，source→sink 链在给定代码范围内静态闭合；实际可利用性需结合数据库字符集与查询拼接方式确认，当前为 llm_inferred 级别。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。请手动替换 TARGET 后逐条发送，并保留基线/真/假三组响应用于对比。

### F-2: DVWA 密码修改功能仅依赖 HTTP_REFERER 校验，可被 CSRF 绕过实现账户接管

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 的密码修改逻辑在 024.php:3 通过 `$_GET['Change']` 触发，在 024.php:5 仅用 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false` 判断请求来源。HTTP_REFERER 完全由客户端控制，攻击者可在自己的页面中把 Referer 伪造成包含目标域名的字符串（例如 `http://TARGET/` 或 `http://evil.com/?TARGET`），从而通过该“防护”。通过后 024.php:7-8 直接读取 `password_new`/`password_conf`，024.php:11 仅比较两者相等，024.php:14 做 md5，024.php:18 拼接 UPDATE 语句，024.php:19 执行更新当前用户密码。整个流程没有任何 CSRF token、没有要求提交旧密码、没有二次确认，攻击者诱导已登录受害者访问恶意页面即可把受害者密码改成攻击者已知值，实现账户接管。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 mysqli_query 执行 UPDATE users SET password=... WHERE user=当前用户（024.php:19）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 攻击者构造带 Change=Change 的 GET 请求，触发密码修改分支 | 外部可控参数进入 |  |
| 2 | `024.php:5` | 仅用 stripos 检查 HTTP_REFERER 是否包含 SERVER_NAME，Referer 由客户端任意伪造 | Referer 可被攻击者设置为含目标域名的字符串 | HTTP_REFERER 是客户端可控头，攻击者页面可设置 Referer 为 http://TARGET/ 或包含 TARGET 的任意 URL，stripos 子串匹配即通过 |
| 3 | `024.php:7-8` | 读取 password_new / password_conf | 攻击者指定新密码 |  |
| 4 | `024.php:11` | 仅比较两次输入是否相等，无旧密码、无 token 校验 | 两值相等即通过 |  |
| 5 | `024.php:14` | 对新密码做 md5 | md5 哈希 |  |
| 6 | `024.php:18-19` | 拼接 UPDATE 语句并执行，修改当前登录用户密码 | 数据库写入，受害者密码被改为攻击者已知值 |  |

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

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是管理员则进一步控制后台。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。防护仅依赖可伪造的 HTTP_REFERER 子串匹配，且无 CSRF token、无旧密码校验，外部可经受害者浏览器触发，链闭合。

**修复建议**

引入随机 CSRF token 并在服务端校验；要求提交旧密码；不要依赖 Referer 做安全判断；密码修改使用 POST 并加二次确认。

**验证说明**

需确认 DVWA 部署下 024.php 的实际访问路径与受害者会话是否可跨站携带（SameSite 设置）；Referer 伪造依赖攻击页面域名包含目标 SERVER_NAME 子串，实际可利用性需按部署域名确认。
模型 POC 要点：诱导已登录 DVWA 的受害者访问攻击者页面，页面自动发起带伪造 Referer 的密码修改请求，将受害者密码改为攻击者已知值，随后攻击者用新密码登录接管账户。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php:19 的 CSRF POC。修改密码接口仅依赖 GET 参数 password_new，未见 CSRF token 或来源校验，攻击者可构造自动提交页面诱导已登录用户触发密码变更。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352。证据位于 024.php:19，password_new 通过 GET 直接进入密码修改逻辑，未见 token 校验；属 llm_inferred 级别，需结合会话机制确认。
POC 备注：仅限授权测试。HTML 表单为文本工件，不自动执行。请将 TARGET 替换为授权实例地址，并在隔离测试账号上验证。

### F-3: 024.php 口令修改缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:6-7`
- **来源**：`rule`

**描述**

024.php:6-8 直接读取 $_GET['password_new'] 与 $_GET['password_conf'] 并进入修改流程，代码中未见失败计数、账户锁定、验证码或速率限制逻辑。候选将其标注为暴力破解防护缺失。但需注意：该页面为口令修改而非登录认证，且当前片段未展示任何口令校验/比对逻辑，因此“可被暴力破解”的论证依赖跨文件（登录入口）与运行时行为，现有证据不足以确认攻击者可在此端点反复猜测并获知成功与否。

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

若存在可枚举的认证/校验端点且无速率限制，攻击者可离线或在线高速猜测口令，导致账户接管；但就本片段而言影响面证据不足。

**CVE / CWE 论证**

CWE-307：缺乏对过度认证尝试的限制。外部可达性：GET 参数可直接访问。利用链闭合度：本文件片段未包含认证比对与响应差异证据，需补充登录端点与限流实现后方可确认，故置信度低。

**修复建议**

在认证/口令修改端点引入失败计数与指数退避、账户临时锁定、CAPTCHA；记录并告警异常频率；对敏感操作要求当前口令二次确认并使用 POST + CSRF Token。

**验证说明**

静态证据：入口 ANY /024；source=request/login/password；sink=024.php:7；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new/password_conf（024.php:7-8）→ 进入修改流程（024.php:13-19），片段内未见任何限流/锁定/校验比对，暴力破解可行性需跨文件确认。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:7 的暴力破解防护缺失 POC。登录处理逻辑未见失败次数限制、账户锁定或速率限制，可对 login/password 参数进行高频尝试。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-307。证据位于 024.php:7，登录处理未见失败计数或限流逻辑；属 llm_inferred 级别，需结合部署层（如 WAF/反向代理）确认。
POC 备注：仅限授权测试。请勿对生产账号进行高频尝试；建议在隔离环境用测试账号验证，并遵守授权约定的请求速率。

### F-4: 024.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:13-14`
- **来源**：`rule`

**描述**

024.php:14 `$pass_new = md5( $pass_new );` 对用户新口令直接做单次 MD5 后写入 users 表（024.php:18-19 的 UPDATE）。MD5 为快速、无盐、无迭代的哈希，抗碰撞与抗暴力能力不足，且此处未见盐值或慢哈希（bcrypt/argon2/PBKDF2）替代。该弱点属实现型，无需 HTTP 污点链即可成立，证据为源码中明确的 md5( 调用。

**source / sink**

- source：repository `md5(`（024.php）
- sink：024.php:14 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:14` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：024.php:14 使用 md5() 对密码做哈希，属于弱哈希算法（CWE-328），无需发送请求即可确认。

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

数据库泄露时，攻击者可用彩虹表/GPU 高速离线爆破还原用户明文口令；相同口令产生相同哈希，便于横向撞库，导致账户接管。

**CVE / CWE 论证**

CWE-328（弱哈希），非 CWE-327（加密算法误用）。外部可达性：口令修改接口直接调用；无需认证即可触发哈希逻辑（取决于页面访问控制）。利用前提为哈希值泄露或可被读取，属配置/实现型弱点，不要求 source→sink 污点。

**修复建议**

改用 password_hash()（PASSWORD_DEFAULT/argon2id）生成带盐慢哈希，校验用 password_verify()；迁移期可对旧 MD5 值在用户下次登录时透明重哈希；禁止在 SQL 中直接拼接哈希值，配合参数化查询。

**验证说明**

静态证据：入口 ANY /024；source=repository/md5(；sink=024.php:14；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new（024.php:7）→ 转义（024.php:13）→ md5 单次哈希（024.php:14）→ 拼入 UPDATE 写入 users.password（024.php:18-19）。
POC 备注：仅限授权测试。本项为离线源码审查，不涉及网络请求。

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
| safety_guard | 安全防护 | 2.28 | 是 |
| surface_mapper | 攻击面测绘 | 7.41 | 是 |
| deep_finder | LLM 深挖 | 9.62 | 是 |
| candidate_screener | 候选筛选 | 5.9 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.18 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.34 | 是 |
| coordinator | 管线协调 | 7.22 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
