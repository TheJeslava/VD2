# 落日二号乙漏洞挖掘报告 — 20261031-164022-86e497

- 生成时间：2026-10-31T08:41:21.547918+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

本次汇总 4 条已去重 findings，全部集中在唯一文件 012.php（单文件 PHP 脚本，35 行）。最高危为 GEN-3b547dba7a60：012.php 第 15 行附近的登录查询 SQL 注入（CWE-89，critical，rule 来源，已有 POC）。其余为 SEM-536ee862bb25 登录接口缺少暴力破解防护（CWE-307，high）、SEM-0ce3358fa05b 使用 MD5 处理口令（CWE-328，medium，注意应归为 weak_hash 而非 weak_crypto）、LLM-a7383455f404 登录成功页 username 参数未转义拼入 HTML 的反射型 XSS（medium，llm_inferred）。4 条均标记 has_poc=true，但其中 MD5 一条属静态证据型 POC，不能宣称可动态复现；SQL 注入与 XSS 为 HTTP POC 文本，暴力破解为请求重放型 POC 文本，均未执行、未做动态验证。本次无二次注入链交付。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：1 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 012.php（35 行，已全量送入）。该脚本为登录逻辑：username/password 经 mysqli_real_escape_string 转义后拼入 SQL（第 14 行），由于使用了转义函数且未发现可绕过点，未确认 SQL 注入；password 经 md5 后比较（第 11 行），属 weak_hash 但仅用于口令摘要比对，未形成可利用链，未单独立项。确认的闭合链为第 23 行 username 反射型 XSS（需有效凭据进入成功分支）。第 24 行 avatar 属性注入为潜在存储型 XSS，但 CODE PACK 中无 avatar 写入点，写点未闭合，置信度 0.6。未覆盖：无 php.ini/Web 配置、无路由与部署信息、无依赖清单，无法评估 allow_url_include、公网可达性等。未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- avatar 字段写入点未在 CODE PACK 中出现，存储型 XSS 写点未闭合
- 无 Web 服务器/php.ini 配置，无法确认脚本暴露路径与认证前置
- 无依赖与部署信息

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 `username`（012.php:5 读取，随后赋给 `$user`）提交任意字符串。该值仅经过 mysqli_real_escape_string 处理（012.php:10 附近对 `$pass` 的处理），而 `$user` 在 012.php:14 被直接拼接进 SQL 语句：`$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`，随后在 012.php:15 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于查询使用单引号包裹字符串且未做参数化，攻击者可闭合引号注入布尔/联合语句，例如 `username=' OR '1'='1' -- -`，使 WHERE 条件恒真并绕过口令校验。校验无效的原因：代码只对 `$pass` 做了转义与 md5，未对 `$user` 做任何转义或白名单校验，也未使用预处理语句。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /012（GET）的 SQL 注入 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/012?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-3b547dba7a60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

认证绕过：攻击者无需知道任何口令即可登录任意/首个用户账户（如 admin），获取应用内权限；结合 UNION 注入还可读取 `users` 表及其他数据库内容，造成敏感数据泄露。若数据库账户权限过高，可能进一步读写文件。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 GET 参数 `username`，无需认证即可访问登录入口（012.php:3 判断 `$_GET['Login']`）。利用链闭合：`$_GET['username']` → `$user` → 字符串拼接 `$query`（012.php:14）→ `mysqli_query` 执行（012.php:15），中间无有效净化，构成完整 source→sink 链。

**修复建议**

改用参数化查询/预处理语句：`$stmt = $mysqli->prepare("SELECT * FROM users WHERE user = ? AND password = ?"); $stmt->bind_param('ss', $user, $pass);`，禁止将外部输入拼接进 SQL。同时对 `username` 做长度与字符白名单校验，关闭详细数据库错误回显（移除 `or die(mysqli_error(...))`），并为数据库账户授予最小权限。

**验证说明**

静态证据：入口 GET /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向登录端点发送 `?Login=1&username=' OR '1'='1' -- -&password=x`。012.php:5 读取 `username` 存入 `$user`；012.php:14 将其原样拼入 SELECT 语句，单引号被闭合，`-- -` 注释掉后续口令判断；012.php:15 执行该语句，WHERE 恒真返回用户记录，登录校验被绕过。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:15 的 SQL 注入 POC。注入点为 GET 参数 username，该值被直接拼接到 SQL 查询中执行；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自 GET 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原有请求结构；脚本仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 通过 `if( isset( $_GET[ 'Login' ] ) )` 进入登录处理流程，随后在 012.php:14-15 执行口令校验。代码中未见失败次数计数、账户锁定、验证码、延迟或速率限制等任何反暴力破解机制，攻击者可对同一账户无限次提交口令猜测。

**source / sink**

- source：query `Login`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 012.php:3 的暴力破解防护缺失 POC。登录入口 /012 使用 GET 参数 Login/username/password，未观察到锁定、速率限制或验证码；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/012?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/012?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-536ee862bb25`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对登录接口进行在线口令爆破或撞库，配合弱口令/弱散列（见 SEM-0ce3358fa05b）可高效猜解账户口令，导致账户接管。

**CVE / CWE 论证**

CWE-307（对过度认证尝试缺乏防护）。外部可达性：登录入口为 GET 参数 `Login`，无需认证即可反复调用。证据边界：本项为语义模式命中，输入中未提供失败计数/锁定相关代码，实际可利用性需在授权环境通过重复请求确认，故置信度较低。

**修复建议**

引入失败计数与账户/IP 维度限流（如 5 次失败后锁定或指数退避），增加验证码或二次验证；记录并告警异常登录尝试；避免通过 GET 提交登录凭据，改用 POST 并配合 CSRF 令牌。

**验证说明**

静态证据：入口 GET /012；source=query/Login；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环向 `?Login=1&username=admin&password=<猜测>` 发送请求 → 012.php:3 每次均进入校验分支 → 012.php:14-15 执行查询并返回结果，无任何次数限制，攻击者可无限次尝试直至命中正确口令。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。漏洞位于 012.php:3，登录处理缺少失败计数/限速机制，具备远程触发条件。
POC 备注：保留原有请求结构；脚本仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

### F-3: 012.php 使用 MD5 存储/校验口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:11 对用户口令执行 `$pass = md5( $pass );`，即使用 MD5 这一已被证明存在碰撞且计算速度极快的散列算法处理口令。该 md5 值随后在 012.php:14 被拼入登录查询与数据库中的口令值比较。MD5 无盐、无迭代、无慢哈希特性，属于口令存储/校验的安全用途误用。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：012.php:11 使用 md5() 对密码进行哈希，属于弱哈希算法（CWE-328），无需发送请求，仅需源码审查确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 012.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0ce3358fa05b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若数据库口令散列泄露，攻击者可用彩虹表或 GPU 高速暴力破解快速还原明文口令；MD5 碰撞特性也可能被用于构造等价散列，削弱口令校验强度，进而导致账户接管。

**CVE / CWE 论证**

CWE-328（使用弱散列算法）。属实现型弱点，无需 HTTP 污点链即可成立：证据为 012.php:11 的 `md5( $pass )` 直接用于口令校验路径（012.php:14 的 password 比较）。外部可达性：登录接口每次请求都会以 MD5 处理口令。

**修复建议**

改用专为口令设计的慢哈希算法，如 PHP `password_hash($pass, PASSWORD_ARGON2ID)` / `PASSWORD_BCRYPT` 并配合 `password_verify()` 校验；为每个口令使用唯一盐值；迁移期可对旧 MD5 值做一次再散列。

**验证说明**

静态证据：入口 GET /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:11 `md5($pass)` 生成无盐散列 → 012.php:14 与库中口令散列比较。攻击者一旦获取数据库，即可对 MD5 值进行离线高速破解或彩虹表查询还原明文。
POC 备注：纯静态证据，不涉及 HTTP 请求；不执行任何命令。

### F-4: 012.php 登录成功页反射型 XSS：username 参数未转义直接拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-23`
- **来源**：`llm_finding`

**描述**

012.php 在 `isset($_GET['Login'])` 时读取 `$_GET['username']`（第 5 行），仅用 `mysqli_real_escape_string` 做 SQL 转义（第 6 行），该函数只处理 SQL 特殊字符（引号、反斜杠、NUL 等），对 `<`、`>`、`"`、`'` 等 HTML 元字符不做任何处理。随后第 23 行将 `$user` 直接插入 `$html .= "<p>Welcome to the password protected area {$user}</p>"`，未调用 htmlspecialchars/htmlentities。攻击者可构造带 HTML/JS 的 username，在受害者浏览器中执行脚本，窃取会话或发起钓鱼。触发需要登录成功（`mysqli_num_rows($result) == 1`），因此攻击者需知道有效凭据或诱导已登录用户点击链接。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:23 第 23 行字符串拼接输出到 HTML 响应体 `$html .= "<p>Welcome to the password protected area {$user}</p>"`

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 $_GET['username'] 读取攻击者可控输入 | 原始字符串 |  |
| 2 | `012.php:6` | mysqli_real_escape_string 仅做 SQL 转义，不处理 HTML 元字符 | SQL 安全但 HTML 危险 | 该函数不是 HTML 编码函数，`<script>` 等标签原样保留 |
| 3 | `012.php:23` | 拼接进 HTML 响应，未做 htmlspecialchars | 注入到 HTML 上下文 |  |

**POC**

针对 /012.php（GET）的 跨站脚本 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/012.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-a7383455f404`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者浏览器执行任意 JS，窃取 Cookie/会话、发起 CSRF 或钓鱼。

**CVE / CWE 论证**

CWE-79。外部 GET 可达，链闭合；但需有效凭据才能进入成功分支，故定 medium。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；avatar 同样需转义。

**验证说明**

需确认成功分支可达（有效凭据）及响应是否直接回显 $html。
模型 POC 要点：使用有效凭据登录，username 中注入 script 标签
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
LLM 深挖重复命中（xss，conf=0.6）；保留首条候选，补充：第 19-20 行从数据库取出 `$row["avatar"]`，第 24 行直接拼入 `$html .= "<img src=\"{$avatar}\" />"`，未做 HTML 属性转义。若攻击者能控制 users 表中 avatar 字段（例如通过注册/资料修改功能，或该字段本身来自不可信来源），可注入 `"><
PocWriter 建议（未采纳，缺少端点 /012.php）：针对 012.php:23 的反射型 XSS POC。注入点为 GET 参数 username，其值未编码即输出到响应中；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-79。漏洞位于 012.php:23，外部输入来自 GET 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原有请求结构；脚本仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.28 | 是 |
| surface_mapper | 攻击面测绘 | 7.45 | 是 |
| deep_finder | LLM 深挖 | 10.55 | 是 |
| candidate_screener | 候选筛选 | 7.85 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.24 | 是 |
| coordinator | 管线协调 | 8.56 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
