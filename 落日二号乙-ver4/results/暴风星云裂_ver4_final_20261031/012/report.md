# 落日二号乙漏洞挖掘报告 — 20261031-172605-3ab55c

- 生成时间：2026-10-31T09:27:00.933546+00:00
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

本次汇总基于单文件 PHP 脚本 012.php（35 行）的静态审计结果，共 4 条去重后 findings，全部带 POC（4/4）。最高危为 GEN-3b547dba7a60：012.php 第 15 行附近登录查询存在 SQL 注入（CWE-89，critical），属 HTTP 可复现类 POC。其次 SEM-536ee862bb25 登录接口缺少暴力破解防护（CWE-307，high），POC 为请求序列类文本工件。SEM-0ce3358fa05b 标题写 weak_crypto 但描述为 MD5 存储口令，按类型规则应归为 weak_hash（CWE-328），仅有静态证据 POC，不能宣称可动态复现。LLM-a7383455f404 为第 23 行 username GET 参数未编码回显的反射型 XSS（medium，llm_inferred，需人工确认输出上下文）。所有结论均为源码静态推断，未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 012.php（1-35 行）。发现两条可闭合链：第 5/23 行 username 反射型 XSS（中危，需登录成功分支），第 5/14/15 行 username SQL 注入（高危，转义依赖全局连接对象与字符集，存在绕过条件）。第 11 行对密码使用 md5() 属弱哈希（CWE-328），但单独不构成可申报 CVE 的利用链，仅作线索记录。第 24 行 $avatar 来自数据库并拼进 img src，若数据库内容可控则存在存储型 XSS，但写点不在 code_pack 内，三要素不闭合，未报告。无端点清单、无配置/依赖文件，部署形态与鉴权状态未知；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单，无法确认 012.php 实际路由与鉴权
- 无数据库 schema，无法确认 users 表与 avatar 字段可控性
- 无 php.ini/Web 服务器配置，无法确认连接字符集与错误显示
- 第 24 行 avatar 存储型 XSS 缺存储写点证据
- md5 弱哈希无完整利用链

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 Login 触发登录分支（012.php:3），随后 username 与 password 参数被读取（012.php:5 附近）。username 仅经过 mysqli_real_escape_string 处理（012.php:9），password 先经 mysqli_real_escape_string 再被 md5() 处理（012.php:10-11），因此 password 因哈希而失去注入能力，但 username 仍以原始字符串拼接进 SQL。012.php:14 构造 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"，012.php:15 直接调用 mysqli_query 执行。由于未使用参数化查询，且 mysqli_real_escape_string 在非 utf8/特定字符集或宽字节场景下可被绕过，同时该转义只处理引号而不改变拼接结构，攻击者可在 username 中闭合单引号注入任意 SQL 片段。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 012.php:15 的 SQL 注入 POC（GET 入口 /012）。注入点为 GET 参数 username，代码将外部输入拼接进 SQL 查询，未做有效参数化。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

可绕过登录认证（如 username 注入 ' OR '1'='1 使 WHERE 恒真），并可进一步通过 UNION/布尔/报错注入读取 users 表全部账号口令哈希，造成敏感数据泄露与认证绕过；错误信息经 die() 回显（012.php:15）为报错注入提供通道。

**CVE / CWE 论证**

CWE-89：外部可控的 GET 参数 username 未经参数化即拼接进 SQL 并在 012.php:15 执行，链路闭合、无需认证即可访问登录端点，属典型可远程利用的 SQL 注入。

**修复建议**

改用 PDO 或 mysqli 预处理语句（prepare + bind_param）绑定 username/password；对输入做长度与字符白名单校验；关闭错误详情回显，统一返回通用错误页；数据库账号遵循最小权限，禁止对 users 表以外的写权限。

**验证说明**

静态证据：入口 GET /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 请求携带 Login 与 username 参数 → 012.php:3 进入登录分支 → 012.php:5 读取 username → 012.php:9 仅做 mysqli_real_escape_string → 012.php:14 字符串拼接进 SELECT 语句 → 012.php:15 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。请求结构沿用输入草稿，仅补充基线与假条件对照步骤。仅限授权测试。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 通过 isset($_GET['Login']) 进入登录处理，012.php:14-15 直接校验用户名口令并返回结果，代码中未见失败次数计数、账号/IP 锁定、验证码、指数退避或速率限制等任何反暴力破解机制。攻击者可对同一端点无限次提交猜测。

**source / sink**

- source：query `Login`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 012.php:3 的暴力破解防护缺失 POC（GET 入口 /012）。登录处理位于 012.php:3，未见锁定、速率限制或验证码。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

攻击者可对已知或枚举出的用户名进行在线口令爆破/撞库，结合 MD5 无盐存储（见 SEM-0ce3358fa05b）进一步放大风险，最终导致账号接管与越权访问。

**CVE / CWE 论证**

CWE-307：认证端点缺少对过量尝试的限制，外部无需认证即可反复请求 012.php?Login=... 进行猜测，链路闭合。

**修复建议**

引入失败计数与账号/IP 维度锁定或指数退避；增加验证码或 MFA；记录并告警异常登录；统一失败响应避免用户名枚举；配合强口令策略与慢哈希存储。

**验证说明**

静态证据：入口 GET /012；source=query/Login；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环发送 GET 请求携带 Login 与猜测的 username/password → 012.php:3 每次进入登录分支 → 012.php:14-15 执行查询并返回成功/失败 → 无任何限速或锁定，可持续爆破直至命中。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。漏洞位于 012.php:3，登录处理未见锁定/限速/验证码；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。沿用输入草稿请求结构，补充基线与状态确认步骤。仅限授权测试。

### F-3: 012.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:11 对用户口令调用 md5($pass) 生成摘要，012.php:14 将该 MD5 值与数据库中的 password 字段直接比较完成认证。MD5 为快速、无盐、可碰撞的哈希算法，不适合口令等安全用途；代码中未见盐值或迭代加盐（如 password_hash/bcrypt/argon2）。注意：该问题本质是弱哈希（CWE-328），而非弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：012.php:11 使用 md5($pass) 对密码做哈希。MD5 属弱哈希算法（CWE-328），且无盐值，易被彩虹表/暴力破解。无需发送请求，仅做源码审查记录。

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

一旦 users 表泄露，攻击者可用彩虹表/GPU 高速爆破在极短时间内还原弱口令；无盐设计使相同口令产生相同摘要，便于批量破解与撞库，导致账号接管。

**CVE / CWE 论证**

CWE-328：MD5 被用于口令存储与校验这一安全用途，属可被离线加速破解的弱哈希实现；该弱点为配置/实现型，无需 HTTP 污点链即可成立，证据为 012.php:11 的 md5( $pass ) 原文。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）生成带盐慢哈希，校验使用 password_verify()；对存量 MD5 摘要在用户下次登录时透明升级；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 GET /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:10 转义 → 012.php:11 md5($pass) 生成无盐摘要 → 012.php:14 与库中 password 比较；库泄露后摘要可被离线高速破解。
POC 备注：纯静态证据，不执行、不联网。仅限授权审查。

### F-4: 012.php 登录成功页将 GET 参数 username 未编码回显导致反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-23`
- **来源**：`llm_finding`

**描述**

012.php 第 3 行以 $_GET['Login'] 存在为入口，第 5 行读取 $_GET['username'] 到 $user，第 6 行仅做 mysqli_real_escape_string（只转义 SQL 特殊字符，不转义 HTML），第 23 行把 $user 直接拼接进 HTML 输出 "<p>Welcome to the password protected area {$user}</p>"，未做 htmlspecialchars 等 HTML 编码。攻击者可构造带脚本的 username，并配合任意能通过登录校验的凭据（或利用第 14 行 SQL 注入使查询返回一行），使页面渲染攻击者脚本，造成反射型 XSS，可窃取会话或钓鱼。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:23 第 23 行字符串拼接输出到 HTML 响应 $html .= "<p>Welcome to the password protected area {$user}</p>"

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 检测到 $_GET['Login'] 存在，进入登录处理分支 | 攻击者控制请求参数 |  |
| 2 | `012.php:5` | 读取 $_GET['username'] 赋值给 $user | 原始攻击者字符串 |  |
| 3 | `012.php:6` | 仅调用 mysqli_real_escape_string 做 SQL 转义，不改变 HTML 元字符 < > " ' | 仍含 HTML/JS 元字符 |  |
| 4 | `012.php:23` | $user 直接拼接进 HTML 段落输出 | 未编码的脚本进入响应体 |  |

**POC**

针对 012.php:23 的反射型 XSS POC（GET 入口 /012.php）。注入点为 GET 参数 username，输入被未编码输出到响应。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS，可在受害者浏览器执行任意脚本，窃取 Cookie/会话或实施钓鱼。

**CVE / CWE 论证**

CWE-79：外部 GET 参数直达 HTML 输出且无 HTML 编码，链闭合；但需登录成功分支，故为中危。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8') 编码。

**验证说明**

需确认实际部署中登录成功分支可达（有效凭据或 SQL 注入配合），以及响应是否设置合适 Content-Type。
模型 POC 要点：构造 username 含脚本，并让登录查询返回一行以进入成功分支（可用 SQL 注入或已知凭据）
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-79。漏洞位于 012.php:23，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效编码；具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。沿用输入草稿请求结构，补充基线步骤。仅限授权测试。

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
| safety_guard | 安全防护 | 3.34 | 是 |
| surface_mapper | 攻击面测绘 | 7.09 | 是 |
| deep_finder | LLM 深挖 | 10.5 | 是 |
| candidate_screener | 候选筛选 | 5.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.82 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.17 | 是 |
| coordinator | 管线协调 | 7.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
