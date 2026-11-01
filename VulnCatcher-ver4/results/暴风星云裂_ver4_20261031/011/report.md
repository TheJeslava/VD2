# 落日二号乙漏洞挖掘报告 — 20261031-163951-9ff72b

- 生成时间：2026-10-31T08:40:51.250206+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
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

本次审计对象为单文件 PHP 脚本 011.php（32 行），共交付 4 条已去重 findings，全部带 POC（4/4）。最高危为 LLM-c969ca7950b6：011.php 第 3 行附近 username 参数直接进入 SQL 拼接（第 13 行），可绕过登录认证，严重度 critical，属 HTTP 可复现 POC。其次为 SEM-bb3630458a80 登录接口缺少暴力破解防护（high，HTTP POC）、LLM-cdf654069098 登录成功页 username 反射型 XSS（medium，HTTP POC）、SEM-2ea8df0ef3b9 口令 MD5 哈希（medium，仅静态证据 POC，不可宣称动态复现）。需注意 SEM-2ea8df0ef3b9 标题写 weak_crypto，但描述为 MD5/CWE-328，按类型规范应归 weak_hash，建议人工校正类型标签。所有结论均为源码静态推断，未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 011.php（32 行，已全量审计）。发现两条闭合链：(1) username 参数 SQL 注入，可直接绕过登录认证（critical）；(2) 登录成功页 username 反射型 XSS（medium，依赖 $html 被输出）。password 经 md5() 处理属弱哈希（CWE-328），但仅用于口令比对且不构成独立可利用链，未单独立项。未发现命令执行、文件包含、SSRF、反序列化等汇点。未覆盖范围：无 php.ini/Web 服务器配置、无路由与认证上下文、无数据库结构，无法确认 011.php 是否公网暴露及 users 表列数；$html 的输出位置在 CODE PACK 外，XSS 需人工确认。

未覆盖 / 证据缺口：
- $html 最终输出点不在 CODE PACK 内，XSS 触发依赖外层输出
- 无数据库表结构，UNION 注入列数需实测
- 无部署/认证上下文，无法确认端点可达性与是否需要前置登录
- password 使用 md5() 属弱哈希，但未形成独立可利用链

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行通过 $_GET['Login'] 触发登录逻辑，第 5 行直接取 $_GET['username'] 赋给 $user，未做任何转义或参数化；第 12 行将 $user 直接拼接进 SQL 语句 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"，第 13 行交给 mysqli_query 执行。攻击者可在 username 中注入单引号闭合字符串，构造恒真条件（如 ' OR '1'='1' -- -），使查询返回任意一行用户记录，第 15 行 mysqli_num_rows == 1 成立即判定登录成功，从而绕过密码校验进入受保护区域。password 虽经 md5() 处理，但 md5 不是 SQL 转义，无法阻止注入。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 检测到 $_GET['Login'] 存在，进入登录处理分支 | 攻击者控制请求参数 |  |
| 2 | `011.php:5` | 直接读取 $_GET['username'] 赋给 $user，无任何过滤/转义 | 原始攻击者字符串 |  |
| 3 | `011.php:12` | $user 被单引号包裹拼接进 SQL 语句，未使用预处理或 mysqli_real_escape_string | 注入载荷进入 SQL 语法层 | md5() 仅作用于 password，对 username 无任何转义作用 |
| 4 | `011.php:13` | 拼接后的 SQL 交给 mysqli_query 执行 | 恶意 SQL 被执行 |  |
| 5 | `011.php:15` | mysqli_num_rows($result)==1 成立即视为登录成功，返回用户数据 | 认证被绕过 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username（源码 011.php:13 处将外部输入拼入 SQL 查询），payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

无需有效凭据即可绕过登录认证，并可进一步通过 UNION/报错注入读取数据库中的用户、口令哈希等敏感数据。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数直接拼接进 SQL 并执行，无需认证，利用链在 CODE PACK 内完整闭合（011.php:5→12→13→15）。

**修复建议**

使用 mysqli 预处理语句（prepare + bind_param）绑定 username/password；或至少对 $user 使用 mysqli_real_escape_string 并避免字符串拼接；同时移除 die() 中的数据库错误回显。

**验证说明**

需动态确认 011.php 实际可访问、users 表存在数据、mysqli 连接已建立（$GLOBALS["___mysqli_ston"]）；列数需按实际表结构调整 UNION 载荷。
模型 POC 要点：利用 username 参数注入恒真条件，绕过密码校验登录
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于可交付代码 011.php:13，外部输入来自 query 参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，需人工替换 TARGET 后手动执行，管线不执行、不联网。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 通过 if(isset($_GET['Login'])) 进入登录处理流程，随后在 011.php:5 读取 username、011.php:8 读取 password 并执行查询比对。代码中未见失败次数计数、账户锁定、验证码、延迟或速率限制等任何反暴力破解机制，攻击者可对同一接口无限次提交用户名/口令组合进行在线猜测。证据为 011.php:2-3 的登录入口与后续处理逻辑中缺失防护代码；该结论为基于源码的推断，实际速率限制可能由前置代理/WAF 提供，源码内不可见。

**source / sink**

- source：query `Login`（011.php）
- sink：011.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /011（GET）的暴力破解防护缺失 POC。登录入口为 GET 参数 Login（源码 011.php:3），连续错误登录无锁定/限速/验证码，payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-bb3630458a80`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对用户账户进行在线口令猜测，弱口令账户可被接管，进而访问系统内受保护资源。

**CVE / CWE 论证**

CWE-307（对过度认证尝试缺乏防护）。外部可达性：登录入口 011.php:3 为公开 GET 接口，无需认证；利用链为重复请求该接口进行口令枚举，源码层面无任何阻断逻辑。

**修复建议**

在登录失败路径引入按账户与按 IP 的失败计数与指数退避延迟，超过阈值后临时锁定或要求验证码；记录并告警异常登录频率；结合强口令策略与多因素认证。

**验证说明**

静态证据：入口 GET /011；source=query/Login；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者反复向 011.php 发送带 Login 参数及不同 username/password 组合的请求；011.php:3 每次均进入登录逻辑，011.php:5/8 读取凭据并查询比对，由于无失败计数或锁定，攻击者可无限次尝试直至命中正确口令。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。漏洞位于可交付代码 011.php:3，登录入口 Login 参数无防护，具备远程触发条件。
POC 备注：保留原确定性 POC 请求结构；重复请求需人工控制频率并遵守授权范围，脚本仅为文本工件，不自动执行。

### F-3: 011.php 口令使用 MD5 哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 $_GET['password'] 读取明文口令，011.php:9 调用 $pass = md5($pass); 将其转换为 MD5 摘要后用于 011.php:12 的登录比对。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储/校验属不安全实现；攻击者一旦获取数据库中的 MD5 值，可用彩虹表或 GPU 高速爆破还原明文。此处为配置/实现型弱点，不依赖 HTTP 污点链，证据为 011.php:9 的 md5( 调用原文。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：011.php:9 处对用户口令使用 md5() 进行哈希（$pass = md5($pass)），属弱哈希算法，无需发送请求即可确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 011.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ea8df0ef3b9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令摘要可被离线高速破解，导致用户口令泄露；若同一口令在其他系统复用，可造成横向账户接管。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。外部可达性：登录接口 011.php:3 公开可达，攻击者可通过正常登录流程触发该哈希逻辑；弱点根因在 011.php:9 的算法选择，无需认证即可观察/利用其后果（如配合 SQL 注入导出哈希后离线破解）。

**修复建议**

改用带盐的自适应口令哈希算法，如 PHP 的 password_hash($pass, PASSWORD_ARGON2ID) 与 password_verify()，或至少 bcrypt（PASSWORD_BCRYPT）；迁移时对存量 MD5 摘要在用户下次登录成功后透明重哈希；禁止在查询中直接比较 MD5 值。

**验证说明**

静态证据：入口 GET /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交登录请求，011.php:8 取得明文 password，011.php:9 用 md5() 生成摘要，011.php:12 将摘要拼入 SQL 与库中存储值比较；由于算法弱且无盐，攻击者获取摘要后可离线破解还原口令。
POC 备注：纯静态证据，无 HTTP 请求；不执行任何命令。

### F-4: 011.php 登录成功页 username 反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:21-21`
- **来源**：`llm_finding`

**描述**

第 5 行读取的 $user 来自 $_GET['username']，在第 21 行被直接拼接进 HTML 输出 "<p>Welcome to the password protected area {$user}</p>"，未做 htmlspecialchars 等 HTML 编码。当攻击者构造使登录成功的请求（例如配合 SQL 注入恒真条件，或使用合法账号）时，username 中的 HTML/JS 会被浏览器解析执行，构成反射型 XSS。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:21 $html 输出到响应页面（echo/print 由外层框架或页面输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | 读取 $_GET['username'] 赋给 $user，无编码 | 原始攻击者字符串 |  |
| 2 | `011.php:21` | $user 直接拼接进 HTML 段落，未做 HTML 实体编码 | HTML 上下文中的未转义字符串 | 无 htmlspecialchars/htmlentities 调用 |
| 3 | `011.php:15` | 需登录成功分支（num_rows==1）才会输出该段落，可配合 SQL 注入恒真条件触发 | XSS 载荷进入响应体 |  |

**POC**

针对 /011.php（GET）的反射型 XSS POC。注入点为 GET 参数 username（源码 011.php:21 处将外部输入未编码输出到响应），payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cdf654069098`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意 JS，窃取会话或发起 CSRF 操作；结合 SQL 注入可无需凭据触发。

**CVE / CWE 论证**

CWE-79 反射型 XSS。外部参数未编码直接输出到 HTML，链在 CODE PACK 内闭合（011.php:5→21）。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；avatar 属性同样应做属性上下文编码。

**验证说明**

需确认 $html 最终被输出到响应（CODE PACK 中未见 echo，可能由外层包含文件输出）；若 $html 未被输出则 XSS 不成立。
模型 POC 要点：通过 SQL 注入使登录成功，并在 username 中注入脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于可交付代码 011.php:21，外部输入来自 query 参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 请求结构；脚本仅为文本工件，需人工替换 TARGET 后手动执行，不自动运行。

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
| safety_guard | 安全防护 | 3.73 | 是 |
| surface_mapper | 攻击面测绘 | 8.66 | 是 |
| deep_finder | LLM 深挖 | 11.44 | 是 |
| candidate_screener | 候选筛选 | 6.4 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.88 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.1 | 是 |
| coordinator | 管线协调 | 7.21 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
