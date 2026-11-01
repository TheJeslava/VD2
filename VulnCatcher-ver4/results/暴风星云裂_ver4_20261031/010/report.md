# 落日二号乙漏洞挖掘报告 — 20261031-163937-79462a

- 生成时间：2026-10-31T08:40:29.698198+00:00
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

本次汇总 3 条已去重 findings，全部集中在单文件 PHP 脚本 010.php（43 行）：最高危为 GEN-7034f0a19983 登录查询 SQL 注入（critical，CWE-89，第 20 行附近），其次为 SEM-949d40928ae7 口令 MD5 弱哈希（medium，第 16 行，实为 CWE-328 弱哈希而非弱加密）与 LLM-f803c7aea6a6 登录成功页反射型 XSS（medium，第 28 行，username 未转义拼入 HTML）。3 条均带 POC：SQL 注入与 XSS 为 HTTP 型 POC（目标以 TARGET 占位，仅限授权测试），MD5 弱哈希为静态证据 POC，不能宣称可动态复现。未发现二次注入链。整体攻击面为无框架、无路由清单的独立 PHP 页面，source 与 sink 同处一个短文件，污点链路极短。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：1 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 010.php（43 行全文）。该脚本为登录处理页：第 3 行判断 $_GET['Login']，第 5 行校验 CSRF token，第 8-16 行接收并处理 username/password（stripslashes + mysqli_real_escape_string + md5），第 19-20 行拼接 SQL 并执行，第 22-29 行登录成功回显 user 与 avatar，第 33 行失败时 sleep(rand(0,3))。SQL 注入方面：username/password 均经 mysqli_real_escape_string 转义，且 password 先 md5 再拼接，未发现可闭合的注入链（mysqli_real_escape_string 依赖 ___mysqli_ston 连接对象存在，若不存在则触发 E_USER_ERROR 返回空串，反而更安全）。命令执行/文件包含/反序列化 sink 均不存在。发现两处 XSS：username 反射型（第 28 行）与 avatar 属性注入（第 29 行，写入点不在 code_pack）。weak_hash（md5 口令）与 weak_random（sleep(rand)）属低价值，未单独立项。未覆盖：Web 服务器配置、php.ini、认证机制、avatar 写入接口、$html 最终输出位置（本文件无 echo，可能在包含模板中）。

未覆盖 / 证据缺口：
- $html 变量的最终输出语句不在 code_pack，XSS 回显依赖外部模板
- avatar 字段写入点不在 code_pack，存储型 XSS 链未完全闭合
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、open_basedir
- 无认证机制说明，无法确认脚本是否匿名可达
- 无 composer.json/版本信息

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求参数 `username`（010.php:8 读取）提交任意字符串，该值被直接拼进 010.php:19 的 SQL 语句 `SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';`，随后在 010.php:20 由 mysqli_query 执行。代码中仅对 `$pass` 调用了 mysqli_real_escape_string（010.php:15），`$user` 未做任何转义、白名单或参数化处理，因此单引号可闭合 `user = '...'` 字面量，注入任意 SQL 片段（如 `' OR '1'='1` 绕过认证，或 UNION 读取其他表）。校验无效的根因是字符串拼接构造 SQL 且 `$user` 完全未净化。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:20 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `010.php:20` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /010（GET）的 SQL 注入 POC。注入点为 GET 参数 username（源码 010.php:20 附近将 username 拼入 SQL 查询），payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/010?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-7034f0a19983`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证并以数据库连接账号权限读取/篡改 users 表及其他可访问表的数据（凭据泄露、越权登录）；若数据库账号权限较高，还可进一步读写文件或扩展影响。错误信息经 die(mysqli_error(...)) 回显，便于注入调试与数据回显。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP 请求参数 `username`，无需认证即可访问登录逻辑；利用链闭合：010.php:8 读取参数 → 010.php:19 字符串拼接 → 010.php:20 mysqli_query 执行，中间无有效净化（`$user` 未转义、未参数化）。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），彻底避免字符串拼接；对 `username` 做长度与字符白名单校验；移除 die(mysqli_error(...)) 的详细错误回显，改为记录日志并返回通用错误；数据库账号遵循最小权限，仅授予业务所需表的必要权限。

**验证说明**

静态证据：入口 GET /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单/请求中提交参数 `username`（010.php:8）→ 该值未经转义直接进入 010.php:19 的 SQL 字符串 → 010.php:20 通过 mysqli_query 执行 → 注入生效，返回被篡改的查询结果（如认证绕过或 UNION 数据泄露）。
PocWriter 建议（未采纳，缺少端点 /010）：符合 CWE-89。漏洞位于可交付代码 010.php:20，外部输入来自 GET 参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 并确认授权。request.http 中 Content-Length 仅作示例，实际以发送工具计算为准。

### F-2: 010.php 口令使用 MD5 哈希（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:15-16`
- **来源**：`rule`

**描述**

010.php:16 对用户口令执行 `$pass = md5( $pass );`，即使用 MD5 这一已被证明存在碰撞且计算速度极快的算法处理口令。该哈希值随后在 010.php:19 被拼入登录查询用于口令比对，说明 MD5 被用于安全用途（口令存储/校验）。MD5 无盐、无迭代、无慢哈希特性，攻击者一旦获取哈希即可通过彩虹表或高速暴力破解还原口令。此处属于弱哈希（CWE-328），而非加密算法误用（CWE-327）。

**source / sink**

- source：repository `md5(`（010.php）
- sink：010.php:16 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:16` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：010.php:16 使用 md5($pass) 对密码做哈希，属弱哈希（CWE-328），无需发送请求，仅做源码审查记录。

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

口令哈希泄露后可被快速离线破解，导致用户账户被接管；相同口令产生相同哈希，便于批量撞库与横向扩散。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。配置/实现型弱点，无需 HTTP 污点链即可成立；证据为 010.php:16 的 `md5( $pass )` 原文调用，且该值在 010.php:19 用于口令比对，属安全用途。外部可达性：登录接口对外暴露，攻击者可通过其他途径（如 SQL 注入、备份泄露）获取哈希后离线破解。证据等级为源码推断（llm_inferred）。

**修复建议**

改用专为口令设计的慢哈希算法，如 PHP 的 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）配合 password_verify() 校验；为每个口令使用独立随机盐；设定合理的工作因子；对历史 MD5 口令在用户下次登录时透明升级为强哈希。

**验证说明**

静态证据：入口 GET /010；source=repository/md5(；sink=010.php:16；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户口令在 010.php:16 经 md5() 处理 → 哈希值在 010.php:19 拼入登录查询用于比对 → 若哈希经注入或备份泄露，攻击者可离线高速破解还原明文口令。
POC 备注：纯静态证据，不发送任何请求；不执行、不联网。

### F-3: 010.php 登录成功页反射型 XSS：username 参数未转义直接拼入 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:8-28`
- **来源**：`llm_finding`

**描述**

脚本在 `$_GET['Login']` 存在时读取 `$_GET['username']`（第 8 行），仅做 stripslashes 与 mysqli_real_escape_string（第 9-10 行），这两者只针对 SQL 上下文，不做 HTML 转义。登录成功后第 28 行将 `$user` 直接拼入 `$html .= "<p>Welcome to the password protected area {$user}</p>"`，随后输出到页面，构成反射型 XSS。攻击者可构造带脚本的 username，诱导受害者点击链接，在目标域执行任意 JS，窃取会话或发起 CSRF 操作。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:28 第 28 行字符串拼接 $html .= "<p>Welcome to the password protected area {$user}</p>" 后输出

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取用户输入到 $user | 原始攻击者字符串 |  |
| 2 | `010.php:9-10` | stripslashes 与 mysqli_real_escape_string 处理，仅针对 SQL 上下文，不改变 HTML 元字符 | 仍含 < > " 等 HTML 元字符 | mysqli_real_escape_string 只转义 SQL 特殊字符，不转义 HTML |
| 3 | `010.php:28` | 登录成功后 $user 直接拼入 HTML 段落 | 未转义 HTML 片段 |  |

**POC**

针对 /010.php（GET）的反射型 XSS POC。注入点为 GET 参数 username（源码 010.php:28 附近将 username 未编码输出到响应），payload 使用 TARGET 占位符，仅限授权测试。

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

在目标域执行任意 JS，可窃取会话 Cookie、发起 CSRF、钓鱼

**CVE / CWE 论证**

CWE-79 反射型 XSS；外部 GET 可达，需有效凭据但凭据可被受害者自身持有，链闭合

**修复建议**

输出前使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8') 转义

**验证说明**

需确认登录成功路径可达（有效凭据）及 $html 最终被 echo 输出（本文件未见 echo，可能在包含模板中）
模型 POC 要点：使用合法凭据登录并在 username 中注入脚本，登录成功后回显执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
LLM 深挖重复命中（xss，conf=0.6）；保留首条候选，补充：第 25 行从数据库读取 `$row["avatar"]`，第 29 行直接拼入 `<img src="{$avatar}" />`，未做 HTML 属性转义。若攻击者能控制自身 avatar 字段（如注册/资料修改处写入 `"><script>...`），则形成存储型 XSS；即便仅反射，也可通过闭合引号注入事件处理
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-79。漏洞位于可交付代码 010.php:28，外部输入来自 GET 参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 并确认授权。request.http 中 Content-Length 仅作示例，实际以发送工具计算为准。

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
| safety_guard | 安全防护 | 3.35 | 是 |
| surface_mapper | 攻击面测绘 | 10.08 | 是 |
| deep_finder | LLM 深挖 | 10.16 | 是 |
| candidate_screener | 候选筛选 | 6.01 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 7.68 | 是 |
| coordinator | 管线协调 | 6.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
