# 落日二号乙漏洞挖掘报告 — 20261031-214157-939a93

- 生成时间：2026-10-31T13:42:52.631945+00:00
- 输入：`$WORKSPACE\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

共发现 4 条候选 finding，覆盖 4 种漏洞类型；4 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 012.php 全部 35 行。发现 username 参数在登录成功页未做 HTML 编码直接输出，构成反射型 XSS（依赖登录成功分支可达）。第 14 行 SQL 查询虽拼接 $user/$pass，但两者均经 mysqli_real_escape_string 转义，password 还经 md5，未发现可闭合的 SQL 注入链。第 24 行 avatar 来自数据库，非直接外部输入，未单独报告。未提供 php.ini/部署信息，运行环境与暴露面未确认。

未覆盖 / 证据缺口：
- 登录成功分支可达性未验证
- 无配置文件与部署信息
- avatar 字段来源（数据库写入点）不在 code_pack 内

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 Login 触发登录分支（012.php:3），随后从 query 参数 username 读取外部输入（012.php:5），该值被直接拼进 SQL 语句：012.php:14 构造 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"，其中 $user 未经参数化即进入字符串；012.php:15 通过 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。代码中仅对 $pass 调用了 mysqli_real_escape_string（012.php:10），对 $user 未见任何转义、白名单或类型校验，因此单引号可闭合 user 字面量，注入任意 SQL 片段（如 ' OR '1'='1 绕过认证，或 UNION 读取其他表）。错误信息还会经 die() 回显 mysqli_error，构成报错型注入的辅助通道。

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

可绕过登录认证（以任意已知/未知用户身份进入），并通过 UNION/布尔/报错注入读取 users 表及其他数据库内容，导致凭据与业务数据泄露；若数据库账号权限过高，还可能进一步读写数据。

**CVE / CWE 论证**

CWE-89：外部可控的 GET 参数 username 未经参数化直接拼接进 SQL 并执行，链路 012.php:5 → 012.php:14 → 012.php:15 闭合，无需认证即可访问登录端点触发，属典型可远程利用的 SQL 注入。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），将 user/password 作为参数传入而非字符串拼接；对 username 增加长度与字符白名单校验；关闭向客户端回显数据库错误（移除 die(mysqli_error(...))，改为记录服务端日志）；数据库账号遵循最小权限，禁止跨库访问。

**验证说明**

静态证据：入口 GET /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 012.php?Login=1&username=' OR '1'='1&password=x → 012.php:3 进入登录分支 → 012.php:5 读取 username 污点 → 012.php:14 拼接进 $query → 012.php:15 mysqli_query 执行被篡改的 SQL，返回全部用户行，认证被绕过。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:15 的 SQL 注入 POC。注入点为 GET 参数 username（源码中该参数被拼接入 SQL 查询），Submit 为触发提交按钮字段。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。目标地址统一使用 TARGET 占位符，仅限授权测试。布尔对照需人工比对响应差异。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 通过 if(isset($_GET['Login'])) 暴露登录处理流程，随后在 012.php:14-15 校验用户名/口令。代码中未见失败次数计数、账户锁定、验证码、延迟或速率限制等任何反暴力破解机制，攻击者可对同一端点无限次提交用户名/口令组合。结合 012.php:11 的 MD5 口令存储与 012.php:15 的 SQL 注入，攻击面进一步放大。

**source / sink**

- source：query `Login`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /012（GET）的 暴力破解防护缺失 POC。注入点：GET 参数 Login；payload 使用 TARGET 占位符。

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

攻击者可对登录端点进行在线口令爆破或撞库，成功后可接管账户；缺少锁定与限速也使攻击难以被检测和阻断。

**CVE / CWE 论证**

CWE-307：登录端点 012.php:3 外部可达且无需认证，认证失败路径无任何限速/锁定逻辑，构成可远程利用的暴力破解防护缺失。

**修复建议**

引入失败计数与账户/IP 维度锁定（如 5 次失败后指数退避或临时锁定）；增加验证码或 MFA；对登录请求做速率限制；记录并告警异常登录尝试；统一失败响应避免用户名枚举。

**验证说明**

静态证据：入口 GET /012；source=query/Login；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环请求 012.php?Login=1&username=admin&password=<猜测> → 012.php:3 进入登录分支 → 012.php:14-15 每次均执行校验且无失败计数/锁定 → 持续尝试直至口令命中。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:3 的暴力破解防护缺失 POC。登录入口使用 GET 参数 Login（提交按钮）、username、password，源码未见锁定/限速/验证码逻辑，目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。证据位于 012.php:3，登录处理逻辑未见失败计数/限速/锁定，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。多请求需人工比对响应与延迟，目标地址统一使用 TARGET 占位符，仅限授权测试。

### F-3: 012.php 口令使用 MD5 存储（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:11 对登录口令执行 $pass = md5($pass)，即使用无盐 MD5 处理用户口令（012.php:10 先做 mysqli_real_escape_string 再哈希）。MD5 属快速、无盐、已被证明存在碰撞的哈希算法，不适合口令等安全用途；攻击者一旦通过 SQL 注入或数据库泄露获取哈希值，可用彩虹表/GPU 暴力快速还原明文。注意此处根因是弱哈希（CWE-328），而非 DES/ECB 类加密算法问题（CWE-327）。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 012.php:11 的弱哈希静态证据 POC。源码使用 md5($pass) 处理口令，属于弱哈希（CWE-328），无需发送 HTTP 请求，仅做源码审查记录。

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

口令哈希可被离线快速破解，导致用户凭据泄露与撞库扩散；结合同文件 SQL 注入可进一步扩大账户接管范围。

**CVE / CWE 论证**

CWE-328：源码 012.php:11 明确使用 md5() 处理口令，属安全用途下的弱哈希；该弱点为配置/实现型，无需 HTTP 污点链即可成立，外部可达性体现在登录端点每次认证都会产生 MD5 哈希。

**修复建议**

改用带盐的自适应口令哈希，如 PHP password_hash($pass, PASSWORD_ARGON2ID) 或 PASSWORD_BCRYPT，并用 password_verify 校验；迁移期对存量 MD5 哈希在用户下次登录成功时透明重哈希；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 GET /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:10 转义 → 012.php:11 md5($pass) 生成无盐 MD5 → 与数据库存储值比较；数据库或注入结果泄露后，攻击者离线破解该 MD5 得到明文口令。
POC 备注：纯静态证据，不发送请求、不执行。仅限授权审查。

### F-4: 012.php 登录成功页反射型 XSS：username 参数未编码直接拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-23`
- **来源**：`llm_finding`

**描述**

012.php 第 5 行从 $_GET['username'] 读取用户输入，第 6 行仅用 mysqli_real_escape_string 做 SQL 转义（该函数只转义 SQL 特殊字符，不处理 HTML 元字符），第 23 行将 $user 直接拼接进 $html 的 <p> 标签中输出。攻击者可构造含 HTML/JS 的 username，在登录成功（或通过 SQL 注入使查询返回一行）时触发脚本执行，窃取会话或执行敏感操作。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:23 第 23 行 $html .= "<p>Welcome to the password protected area {$user}</p>" 输出到响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 读取 GET 参数 username 到 $user | 原始攻击者字符串 |  |
| 2 | `012.php:6` | mysqli_real_escape_string 仅做 SQL 转义，不处理 < > " 等 HTML 元字符 | SQL 转义后的字符串，HTML 元字符保留 | SQL 转义函数不提供 HTML 编码，无法阻止 XSS |
| 3 | `012.php:23` | 将 $user 直接拼接进 HTML 输出 | 未编码的 HTML 片段进入响应体 |  |

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

反射型 XSS，可窃取用户会话或在受害者浏览器执行操作

**CVE / CWE 论证**

CWE-79，外部 GET 参数直达 HTML 输出，无需认证即可构造

**修复建议**

输出前使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8') 编码

**验证说明**

需确认登录成功分支可达（存在有效账号或 SQL 注入配合）
模型 POC 要点：构造含脚本的 username，使登录查询返回一行后回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /012.php）：针对 012.php:23 的反射型 XSS POC。注入点为 GET 参数 username，其值被未编码输出到响应页面，目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-79。漏洞位于 012.php:23，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效编码，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。目标地址统一使用 TARGET 占位符，仅限授权测试。

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
| safety_guard | 安全防护 | 4.94 | 是 |
| surface_mapper | 攻击面测绘 | 7.76 | 是 |
| deep_finder | LLM 深挖 | 6.34 | 是 |
| candidate_screener | 候选筛选 | 6.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.4 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.35 | 是 |
| coordinator | 管线协调 | 7.48 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
