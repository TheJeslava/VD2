# 落日二号乙漏洞挖掘报告 — 20261031-013722-7bdef8

- 生成时间：2026-10-30T17:38:08.777503+00:00
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

本次汇总 3 条已去重 findings，全部集中在单文件 PHP 脚本 010.php（43 行）。最高危为 GEN-7034f0a19983：010.php 第 20 行登录查询 SQL 注入（critical，CWE-89），由规则引擎产出，具备 HTTP POC。另有 LLM-f803c7aea6a6：第 28 行登录成功页 username 参数未编码直接拼入 HTML 的反射型 XSS（medium，具备 HTTP POC）；以及 SEM-949d40928ae7：第 16 行口令使用 MD5 哈希（medium，属 CWE-328 弱哈希，仅有静态证据 POC，不能宣称可动态复现）。3 条均带 POC，POC 齐全度为 3/3，但均为文本工件，未做动态验证。注意：该 weak_crypto 条目实际语义为弱哈希，类型标注与 CWE 归类存在偏差，需人工校正。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 010.php（43 行）。确认第 8 行 $_GET['username'] 经 stripslashes 与 mysqli_real_escape_string 后在第 28 行未编码拼入 HTML，构成反射型 XSS（链闭合，置信 0.8）。第 19-20 行 SQL 拼接存在注入可能，但 mysqli_real_escape_string 在正常连接下可防护，仅宽字节/字符集异常时可绕过，置信 0.6 且依赖部署配置，列为待核实。第 33 行 rand(0,3) 仅用于登录失败延时，非安全令牌，不构成 weak_random 漏洞。第 5 行 checkToken 做 CSRF 校验，未见绕过。未发现命令执行、文件包含、反序列化、SSRF 等汇点。无 composer/框架配置，第三方组件 CVE 无法评估；无服务器配置，LFI/SSRF 可利用性无法判定。

未覆盖 / 证据缺口：
- 无数据库连接字符集配置，SQL 注入可利用性未闭合
- 无 Web 服务器/php.ini 配置
- 无端点清单，实际暴露路径与认证要求未知
- 无依赖清单，第三方组件 CVE 未评估

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 010.php 提交登录参数，源码在 010.php:8 从请求中读取用户名（候选记为 query `username`），随后在 010.php:19 直接以字符串拼接方式构造 SQL：$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";，并在 010.php:20 交给 mysqli_query 执行。$user 在进入拼接前没有经过 mysqli_real_escape_string 或参数化处理（对比 010.php:15 仅对 $pass 做了 mysqli_real_escape_string，且随后在 010.php:16 被 md5() 覆盖），因此单引号可闭合 user 字面量，注入任意 SQL 片段。校验无效的原因是该查询完全依赖字符串拼接，没有使用 prepared statement，也没有对 $user 做转义或白名单校验。最终危险操作是 010.php:20 的 mysqli_query 执行被污染的 $query。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:20 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `010.php:20` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 010.php:20 的 SQL 注入 POC（入口 /010，方法 ANY）。注入点为查询参数 username，payload 使用 TARGET 占位符，仅限授权测试。

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

可绕过登录认证（例如 user 处注入 ' OR '1'='1 使 WHERE 恒真），并可进一步通过 UNION/布尔/报错注入读取 users 表及其他库表数据，造成账户凭据与业务数据泄露；若数据库账户权限过高，还可能读写文件或篡改数据。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：010.php 为登录入口，参数来自 HTTP 请求，无需认证即可触发；利用链闭合：010.php:8 外部输入 → 010.php:19 字符串拼接进 $query → 010.php:20 mysqli_query 执行，中间无有效净化，满足注入条件。

**修复建议**

改用 mysqli/PDO 预处理语句并绑定参数，例如 $stmt = $mysqli->prepare("SELECT * FROM users WHERE user = ? AND password = ?"); $stmt->bind_param('ss', $user, $passHash);；禁止将外部输入直接拼接进 SQL；对输入做长度与字符白名单校验；数据库账户遵循最小权限，关闭详细错误回显（当前 die(mysqli_error(...)) 会泄露 SQL 结构）。

**验证说明**

静态证据：入口 ANY /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单的用户名参数中提交带单引号的 payload（如 ' OR '1'='1' -- ），010.php:8 读取该值到 $user，010.php:19 将其原样拼入 SELECT 语句，010.php:20 由 mysqli_query 执行，从而改变查询语义，实现认证绕过或数据读取。
PocWriter 建议（未采纳，缺少端点 /010）：符合 CWE-89。漏洞位于 010.php:20，外部输入来自查询参数 username，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱；执行前须替换 TARGET 并取得授权。

### F-2: 010.php 登录成功页反射型 XSS：username 参数未编码直接拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:8-28`
- **来源**：`llm_finding`

**描述**

010.php 第 8 行从 $_GET['username'] 取用户输入，仅经过 stripslashes 与 mysqli_real_escape_string（后者只针对 SQL 上下文转义，对 HTML 无任何作用），随后在第 28 行被直接拼接进 $html 的 <p> 标签中输出。攻击者构造带 HTML/JS 的 username，在登录成功（或利用已知凭据）后即可在受害者浏览器执行脚本，窃取会话或发起 CSRF。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:28 010.php:28 $html .= "<p>Welcome to the password protected area {$user}</p>";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取攻击者可控输入 | 原始字符串 |  |
| 2 | `010.php:9` | stripslashes 仅去除反斜杠，不改变 HTML 语义 | 仍含 HTML 标签 |  |
| 3 | `010.php:10` | mysqli_real_escape_string 只转义 SQL 特殊字符，对 < > " 等 HTML 元字符无效 | HTML 元字符保留 |  |
| 4 | `010.php:28` | 登录成功后 $user 被直接拼入 HTML 输出 | 未编码 HTML 注入页面 | 无 htmlspecialchars 等输出编码 |

**POC**

针对 010.php:28 的反射型 XSS POC（入口 /010.php，方法 GET）。注入点为查询参数 username，payload 使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS，可在受害者浏览器执行任意 JS，窃取会话 Cookie、伪造请求。

**CVE / CWE 论证**

CWE-79；外部 GET 参数直达 HTML 输出，无需高权限，链闭合。

**修复建议**

输出前使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8') 编码。

**验证说明**

需确认登录成功路径可达（有效凭据）及响应是否直接回显 $html。
模型 POC 要点：使用有效凭据登录，username 参数注入脚本标签，登录成功后脚本在响应中执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-79。漏洞位于 010.php:28，外部输入来自查询参数 username，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱；执行前须替换 TARGET 并取得授权。

### F-3: 010.php 口令使用 MD5 哈希（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:15-16`
- **来源**：`rule`

**描述**

010.php:15 先对 $pass 做 mysqli_real_escape_string，随后在 010.php:16 调用 $pass = md5( $pass ); 对口令做哈希。MD5 属于快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储/校验属弱哈希实现。此处为配置/实现型弱点，不依赖 HTTP 污点链，证据为 010.php:16 的 md5() 调用原文。注意：该弱点类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。

**source / sink**

- source：repository `md5(`（010.php）
- sink：010.php:16 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:16` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：010.php:16 使用 md5() 对密码做哈希，属弱哈希（CWE-328），无需发送请求，仅做源码审查记录。

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

若数据库泄露，攻击者可用彩虹表或 GPU 高速爆破在极短时间内还原弱口令；无盐 MD5 还使相同口令产生相同摘要，便于批量撞库与横向扩散，削弱账户认证强度。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。外部可达性：口令哈希在登录处理路径 010.php:16 执行，任何登录请求都会触发；无需认证。利用前提是攻击者获得哈希值（如通过同文件 GEN-7034f0a19983 的 SQL 注入读取 users 表），两者可组合形成凭据泄露链。

**修复建议**

改用 password_hash($pass, PASSWORD_DEFAULT)（bcrypt/Argon2）生成带盐慢哈希，校验时用 password_verify()；迁移期可对旧 MD5 摘要在用户下次登录时透明重哈希；禁止在安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /010；source=repository/md5(；sink=010.php:16；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 010.php:15 转义 → 010.php:16 md5() 生成无盐摘要 → 与数据库存储值比较；由于算法快速且无盐，一旦摘要外泄即可被快速离线破解。
POC 备注：纯静态证据，无 HTTP 请求；管线不执行、不联网、不搭沙箱。

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
| safety_guard | 安全防护 | 2.4 | 是 |
| surface_mapper | 攻击面测绘 | 7.8 | 是 |
| deep_finder | LLM 深挖 | 9.96 | 是 |
| candidate_screener | 候选筛选 | 4.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.91 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.48 | 是 |
| coordinator | 管线协调 | 6.05 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
