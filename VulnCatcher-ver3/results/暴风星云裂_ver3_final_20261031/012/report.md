# 落日二号乙漏洞挖掘报告 — 20261031-013810-831952

- 生成时间：2026-10-30T17:39:01.269282+00:00
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

本次审计对象为单文件 PHP 脚本 012.php（35 行），共交付 4 条已去重 findings，全部带 POC（4/4）。最高危为 GEN-3b547dba7a60：012.php 第 15 行登录查询存在 SQL 注入（critical，CWE-89，source→sink 短链路，HTTP POC 可复现）。其次为 SEM-536ee862bb25：登录接口缺少暴力破解防护（high，CWE-307，HTTP POC 为重复请求文本工件）。另有 SEM-0ce3358fa05b 使用 MD5 处理口令（medium，注意其类型标注为 weak_crypto，但按 CWE-328 应归为 weak_hash，仅静态证据 POC，不可宣称可动态复现）与 LLM-a7383455f404 登录成功页 username 未转义回显的反射型 XSS（medium，llm_inferred，HTTP POC 文本）。所有 POC 均为文本工件，未执行、未做动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 012.php（35 行）。已审计：GET 参数 username/password 的获取与处理、SQL 查询构造、登录成功/失败分支输出。发现 1 条可闭合的反射型 XSS（username 未做 HTML 转义即回显）。SQL 注入方面：username 与 password 均经 mysqli_real_escape_string 处理，password 还经 md5()，在 ___mysqli_ston 连接对象存在时参数化转义生效，未发现可绕过的注入链；若 ___mysqli_ston 未初始化则代码走 trigger_error 分支返回空串，不构成注入。weak_hash（md5 用于口令）属设计缺陷但无独立可利用链，未单独立项。未覆盖：无 composer/框架配置、无 php.ini/服务器配置、无路由与认证部署信息，无法判断该脚本是否对外暴露及 disable_functions 等开关。

未覆盖 / 证据缺口：
- 无部署/认证信息，无法确认脚本对外可达性
- 无 php.ini/服务器配置，无法确认 open_basedir/disable_functions
- 登录成功分支依赖数据库中存在匹配记录，动态可达性未验证

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 `username`（012.php:5 读取，`$_GET['username']`）提交输入，该值被直接拼接到 SQL 语句中：012.php:14 构造 `$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`，随后在 012.php:15 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。代码中仅对 `$pass` 调用了 `mysqli_real_escape_string`（012.php:10），`$user` 未见任何转义、类型约束或参数化处理，因此单引号可闭合 `user = '...'` 字面量，注入任意 SQL 片段（例如 `' OR '1'='1' -- ` 绕过认证，或 UNION/布尔盲注读取 `users` 表）。错误信息经 `or die('<pre>'.mysqli_error(...).'</pre>')` 回显，进一步为报错注入提供通道。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /012（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-3b547dba7a60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证（以任意用户身份进入），并可读取/篡改数据库中的 `users` 表（用户名、口令哈希等），造成敏感数据泄露与越权；结合堆叠/UNION 能力可进一步扩大至数据库层面的数据操纵。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可达（GET 参数 `username`，无需认证即可访问登录入口）、无需认证、利用链闭合（source 012.php:5 → 拼接 012.php:14 → 执行 012.php:15），且缺少参数化/转义，属典型注入。

**修复建议**

改用预处理语句与参数绑定（`mysqli_prepare` + `bind_param`，或 PDO 的 `prepare/execute`），彻底避免字符串拼接；对 `username` 做长度与字符白名单校验；关闭向客户端回显数据库错误（改为记录服务端日志并返回通用错误）；数据库账号遵循最小权限，仅授予必要的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单/请求中提交 `username` 参数（012.php:5）→ 该值未经转义进入 `$user` → 012.php:14 拼入 `SELECT * FROM users WHERE user = '$user' ...` → 012.php:15 `mysqli_query` 执行被污染的 SQL → 返回结果用于认证判断，攻击者以注入条件绕过口令校验或读取任意数据。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:15 的 SQL 注入 POC。源码中 `$username` 来自请求参数 `username`，未经参数化即拼入 SQL 查询（第 15 行），构成 CWE-89。注入点为 query 参数 `username`，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自 query 参数 `username`，source→sink 链在给定代码中静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。禁止使用 DROP/破坏性语句。执行前须替换 TARGET 并取得授权。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 以 `if( isset( $_GET[ 'Login' ] ) ) {` 进入登录处理流程，随后读取用户名/口令并执行查询。代码中未见失败次数计数、账号/IP 锁定、验证码、指数退避或速率限制等任何反暴力破解机制，攻击者可对同一账号无限次提交口令猜测。该弱点与同文件的 MD5 无盐哈希（012.php:11）叠加，进一步降低猜测与离线破解成本。

**source / sink**

- source：request `login/password`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /012（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-536ee862bb25`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对已知用户名进行在线口令爆破或撞库，最终实现账号接管；缺少锁定/限速也使攻击难以被察觉，可长期持续。

**CVE / CWE 论证**

CWE-307（对过度认证尝试缺乏防护）：外部可达的登录入口（012.php:3，GET 参数 `Login` 触发），无需认证即可反复请求，利用链为「重复提交口令 → 无任何阻断 → 命中正确口令」。

**修复建议**

在登录流程中引入失败计数与账号/IP 维度锁定或指数退避；加入验证码或二次验证；记录并告警异常登录频率；结合强口令策略与多因素认证；对登录响应时间做恒定化处理以减少时序侧信道。

**验证说明**

静态证据：入口 ANY /012；source=request/login/password；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者反复向 012.php 提交 `Login` 与猜测口令（012.php:3）→ 每次均执行 012.php:14/15 的查询比对 → 因无失败计数、锁定或限速，攻击者可无限次尝试直至命中，从而接管账号。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:3 的暴力破解防护缺失 POC。登录处理逻辑（第 3 行起）未体现速率限制/账户锁定/验证码等防护，构成 CWE-307。注意：源码中不存在名为 `login/password` 的参数，原草稿的注入点与源码不一致，此处按登录接口的实际参数（username/password）描述，需以实际部署路由为准。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。证据位于 012.php:3 的登录处理逻辑，未发现速率限制或锁定机制。证据等级：llm_inferred；原草稿参数 `login/password` 与源码不符，已按实际参数修正，需部署确认。
POC 备注：POC 仅为文本工件，不执行、不联网。禁止大规模自动化爆破；仅做少量请求验证防护是否存在。执行前须替换 TARGET 并取得授权。

### F-3: 012.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:11 执行 `$pass = md5( $pass );`，将用户提交的口令（012.php:10 经 `mysqli_real_escape_string` 处理后）以无盐 MD5 单轮哈希形式参与后续登录查询。MD5 属已破译的快速哈希算法，无盐、无迭代、无工作因子，无法抵抗离线暴力破解与彩虹表攻击。注意：该弱点本质是弱哈希（CWE-328），而非弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 012.php:11 的弱哈希 POC（静态证据型）。第 11 行 `$pass = md5($pass);` 使用 MD5 处理口令，属 CWE-328（弱哈希），而非 CWE-327 弱加密。无需发送请求，仅需源码审查确认。

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

一旦数据库（`users` 表）泄露，攻击者可用彩虹表或 GPU 高速碰撞在极短时间内还原用户明文口令；由于用户常跨站复用口令，可导致账号接管与横向渗透。

**CVE / CWE 论证**

CWE-328（弱哈希）：属实现型弱点，无需 HTTP 污点链即可成立；原文证据为 012.php:11 的 `md5( $pass )`，用于口令校验这一安全用途，外部可达（登录接口），无需认证。

**修复建议**

改用专为口令设计的慢哈希：PHP `password_hash($pass, PASSWORD_ARGON2ID)` 或 `PASSWORD_BCRYPT`（自带随机盐与工作因子），校验时用 `password_verify`；对存量 MD5 哈希在用户下次登录成功时透明升级；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:10 转义 → 012.php:11 `md5($pass)` 生成无盐摘要 → 摘要参与 012.php:14 的查询比对；攻击者获取数据库后对 MD5 摘要做离线破解即可还原明文口令。
POC 备注：静态证据，无需网络请求；不执行任何命令。

### F-4: 012.php 登录成功页将用户可控 username 未转义回显（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-23`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['username'] 取值，仅经 mysqli_real_escape_string 处理（该函数只针对 SQL 上下文转义，对 HTML 无任何作用），随后在登录成功分支直接拼接进 HTML 输出 `$html .= "<p>Welcome to the password protected area {$user}</p>"`，未调用 htmlspecialchars/htmlentities。攻击者可构造带脚本的 username，诱导受害者访问特制链接；若受害者已登录或攻击者能通过 SQL 注入/已知凭据使查询命中一行，脚本即被反射执行，可窃取会话或发起敏感操作。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:23 字符串拼接进 $html 输出（第 23 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 $_GET['username'] 读取用户输入 | 原始字符串 |  |
| 2 | `012.php:6` | 仅做 mysqli_real_escape_string（SQL 上下文转义），不改变 HTML 语义 | 仍含 < > " 等 HTML 元字符 | mysqli_real_escape_string 只转义 SQL 特殊字符，对 HTML 注入无效 |
| 3 | `012.php:23` | 登录成功分支将 $user 直接拼入 HTML 输出 | 未转义 HTML 片段 |  |

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

反射型 XSS，可在受害者浏览器上下文执行任意脚本，窃取 Cookie/会话、伪造操作。

**CVE / CWE 论证**

CWE-79：外部可控 GET 参数未经 HTML 编码进入响应，链闭合，无需认证即可投递。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；avatar 同样需转义并校验 URL scheme。

**验证说明**

需确认登录成功分支可达（需命中一行用户记录）；若无法命中则仅登录失败分支，XSS 不触发。
模型 POC 要点：构造含脚本的 username，使查询命中一行后回显执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /012.php）：针对 012.php:23 的反射型 XSS POC。源码中请求参数 `username` 未经 HTML 编码即输出到响应（第 23 行），构成 CWE-79。注入点为 GET 参数 `username`，目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-79。漏洞位于 012.php:23，外部输入来自 query 参数 `username`，source→sink 链在给定代码中静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前须替换 TARGET 并取得授权。

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
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 8.13 | 是 |
| deep_finder | LLM 深挖 | 6.36 | 是 |
| candidate_screener | 候选筛选 | 5.99 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.22 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.26 | 是 |
| coordinator | 管线协调 | 7.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
