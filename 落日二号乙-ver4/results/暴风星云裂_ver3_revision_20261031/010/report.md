# 落日二号乙漏洞挖掘报告 — 20261031-011458-2a92ad

- 生成时间：2026-10-30T17:15:52.083805+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\010.zip`
- 输入模式：`zip`
- SHA256：`819467f4e89f5ccb8366890305cd0e83be79b38873b4535d43cf0f2c08e7c6c7`
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

本次汇总基于单文件 PHP 脚本 010.php（1-43 行）的静态审计结果，共 3 条去重后 findings，全部带 POC（3/3）。最高危为 GEN-7034f0a19983：010.php 第 20 行登录查询 SQL 注入（CWE-89，critical，规则命中，HTTP POC 可复现）。另有 SEM-949d40928ae7：010.php 第 16 行口令使用 MD5 哈希（CWE-328，medium，仅静态证据 POC，不能宣称可动态复现）；LLM-f803c7aea6a6：010.php 第 28 行登录成功后 $user 未编码拼入 $html 导致反射型 XSS（medium，模型推断，HTTP POC 文本存在但未动态验证）。注意类型标注：MD5 属 weak_hash（CWE-328），输入中该条被标为 weak_crypto，需在交付时纠正归类，避免与 CWE-327 混淆。所有结论均为源码推断或规则命中，未做动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：1 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 010.php（43 行）。已审计：第 3-5 行登录入口与 CSRF token 校验（checkToken 实现未给出）、第 8-16 行 username/password 读取与转义、第 19-20 行 SQL 查询、第 22-29 行登录成功回显、第 33 行 sleep(rand()) 失败延迟。SQL 注入方面：username/password 均经 mysqli_real_escape_string 转义，且 password 再经 md5，未发现可闭合的 SQL 注入链（checkToken 与 ___mysqli_ston 初始化不在 code_pack，无法完全排除）。发现两条 XSS 线索：username 回显（第 28 行）与 avatar 属性回显（第 29 行），均缺 HTML 编码。未闭合线索：checkToken/generateSessionToken 实现缺失，无法确认 CSRF token 校验是否可绕过；avatar 存储写点缺失；无 php.ini/部署配置，无法确认文件对外可达性。weak_hash（md5 用于口令，第 16 行）属设计缺陷但为常见口令哈希用法，未单独立 finding。

未覆盖 / 证据缺口：
- checkToken 与 generateSessionToken 实现未在 code_pack 中，CSRF 校验强度未知
- users.avatar 的存储写点不在 code_pack，存储型 XSS 链未闭合
- 无数据库 schema、无部署/Web 根配置，无法确认 010.php 对外可达性与认证前置条件
- ___mysqli_ston 全局连接初始化不在 code_pack

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username`（010.php:8 读取）提交任意字符串，该值被直接拼进 010.php:19 的 SQL 语句 `SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';`，随后在 010.php:20 交给 mysqli_query 执行。代码中仅对 `$pass` 做了 mysqli_real_escape_string（010.php:15），`$user` 没有任何转义、白名单或参数化处理，因此单引号可闭合字符串字面量，注入任意 SQL 片段（如 `' OR '1'='1` 绕过认证，或 UNION 读取其他表）。校验无效的根因是字符串拼接构造 SQL 且未使用预处理语句。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:20 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `010.php:20` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /010（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/010?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-7034f0a19983`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证（以任意已知用户身份登录）、读取 users 表及其他库表数据（凭据泄露）、在数据库权限允许时篡改或删除数据；错误信息经 die() 回显（010.php:20）还会泄露数据库结构与版本，为进一步利用提供信息。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `username`，无需认证即可访问登录接口；利用链闭合：010.php:8 读取输入 → 010.php:19 字符串拼接 → 010.php:20 mysqli_query 执行，全程无有效净化，攻击者可控完整 SQL 语义。

**修复建议**

改用参数化查询/预处理语句（mysqli_prepare + bind_param 或 PDO prepared statement），将 `$user` 与 `$pass` 作为绑定参数传入，禁止字符串拼接；对输入做长度与字符白名单校验；关闭错误详情回显（不要用 die(mysqli_error()) 输出到页面），改为记录服务端日志；数据库账号遵循最小权限，仅授予必要表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在请求中设置 `username` 参数（010.php:8）→ 值未经转义进入 `$user` → 010.php:19 拼接为 `WHERE user = '$user'` → 010.php:20 mysqli_query 执行 → 返回结果用于登录判定，攻击者通过布尔/UNION 注入控制查询结果或读取额外数据。
PocWriter 建议（未采纳，缺少端点 /010）：针对 010.php:20 的 SQL 注入 POC。注入点为查询参数 username（源码中通过 getParameter("username") 取值后拼接进 SQL 语句），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010）：符合 CWE-89。漏洞位于 010.php:20，外部输入来自查询参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。原始草稿中的 -X ANY 已规范为 GET（参数位于 query string）；如需 POST 形式，可将同一 payload 放入 application/x-www-form-urlencoded 请求体。禁止使用 DROP 等破坏性语句。

### F-2: 010.php 口令使用 MD5 哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:15-16`
- **来源**：`rule`

**描述**

010.php:16 对用户口令执行 `$pass = md5( $pass );`，将 MD5 用作口令存储/比对的哈希算法。MD5 为快速、无盐、抗碰撞性已被攻破的哈希，不适合口令等安全用途；代码中未见盐值或迭代（如 password_hash/PBKDF2/bcrypt/Argon2）。攻击者一旦获取 users 表（例如借助同文件 GEN-7034f0a19983 的 SQL 注入读取数据），可对 MD5 摘要进行高速字典/彩虹表破解，还原明文口令。

**source / sink**

- source：repository `md5(`（010.php）
- sink：010.php:16 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:16` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：010.php:16 使用 md5($pass) 对密码做哈希，属弱哈希（CWE-328），无需发送请求即可在源码层确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 010.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-949d40928ae7`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令摘要可被离线高速暴力破解或彩虹表命中，导致用户凭据泄露；结合 SQL 注入可批量导出并破解口令，进而横向登录其他系统（凭据复用）。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。属实现型弱点，无需 HTTP 污点链即可成立：证据为 010.php:16 明文调用 md5() 处理口令；外部可达性体现在登录流程对用户口令做 MD5 后比对，且摘要可经数据库泄露路径（同文件 SQL 注入）被外部获取。

**修复建议**

改用专为口令设计的慢哈希：PHP 的 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）配合 password_verify()，自动加盐并支持成本参数；迁移时对存量 MD5 摘要在用户下次登录成功后透明重哈希；禁止在口令路径使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /010；source=repository/md5(；sink=010.php:16；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 010.php:16 `md5($pass)` 生成无盐快速摘要 → 摘要参与 010.php:19 的登录查询/存储 → 攻击者通过 SQL 注入（010.php:20）导出摘要 → 离线高速破解还原明文口令。
POC 备注：本条为配置/代码型候选，无 HTTP 污点，source_kind=config 不代表误报。POC 仅为文本工件，不执行任何命令。

### F-3: 010.php 登录成功后用户名未编码回显导致反射型 XSS（$user 直接拼入 $html）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:8-28`
- **来源**：`llm_finding`

**描述**

010.php 第 8 行从 $_GET['username'] 读取用户名，仅经过 stripslashes 与 mysqli_real_escape_string（第 9-10 行），这两个函数只针对 SQL 上下文转义，不做 HTML 编码。第 22-29 行登录成功后，第 28 行把 $user 直接拼进 $html 的 <p> 标签中输出，未调用 htmlspecialchars/htmlentities，攻击者可在 username 中注入 HTML/JS，在受害者浏览器执行。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:28 第 28 行 $html .= "<p>Welcome to the password protected area {$user}</p>" 字符串拼接输出

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取攻击者可控输入 | 原始字符串 |  |
| 2 | `010.php:9` | stripslashes 去除反斜杠，不改变 HTML 语义 | 去反斜杠字符串 |  |
| 3 | `010.php:10` | mysqli_real_escape_string 仅做 SQL 转义，不编码 < > " 等 HTML 元字符 | SQL 转义但 HTML 未编码 |  |
| 4 | `010.php:28` | 登录成功后把 $user 拼入 $html 输出到页面 | 未编码 HTML 注入页面 | stripslashes 与 mysqli_real_escape_string 均非 HTML 编码，无法阻止标签注入 |

**POC**

针对 /010.php（GET）的 跨站脚本 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/010.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-f803c7aea6a6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可窃取会话 Cookie 或诱导管理员执行敏感操作

**CVE / CWE 论证**

CWE-79；外部 GET 可达，需有效登录凭据（降低可利用性），链闭合

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')

**验证说明**

需确认存在有效账号及 user_token 校验逻辑（checkToken 未在 code_pack 中给出），否则登录分支不可达
模型 POC 要点：构造合法登录凭据，username 填入 XSS payload，登录成功后回显触发
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
LLM 深挖重复命中（xss，conf=0.6）；保留首条候选，补充：第 24-25 行从数据库取出 $row['avatar'] 赋给 $avatar，第 29 行直接拼入 <img src="{$avatar}" /> 输出，未做 HTML 属性编码。若攻击者能控制 users 表中 avatar 字段（如通过注册/资料修改），可注入 " onerror=... 等属性逃逸 payl
PocWriter 建议（未采纳，缺少端点 /010.php）：针对 010.php:28 的反射型 XSS POC。注入点为 GET 参数 username，其值未经 HTML 编码即输出到响应页面，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-79。漏洞位于 010.php:28，外部输入来自查询参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。验证时建议使用无害 alert(document.domain)，不要使用窃取 Cookie 或外连的载荷。

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
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.93 | 是 |
| surface_mapper | 攻击面测绘 | 10.46 | 是 |
| deep_finder | LLM 深挖 | 10.15 | 是 |
| candidate_screener | 候选筛选 | 5.48 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.41 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.15 | 是 |
| coordinator | 管线协调 | 6.83 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
