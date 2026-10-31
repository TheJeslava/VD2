# 落日二号乙漏洞挖掘报告 — 20261031-005803-437da7

- 生成时间：2026-10-30T16:58:49.291029+00:00
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

本次审计范围仅限单文件 PHP 脚本 010.php（43 行），共交付 3 条去重后 finding，全部带 POC 文本（静态/HTTP 混合，未做动态验证）。最高危为 GEN-7034f0a19983：010.php 第 20 行附近登录查询存在 SQL 注入（critical，CWE-89），外部请求参数几乎未经处理即拼入 SQL，属可直接利用的高密度污点路径。其次为 LLM-8f91d878ba70：第 29 行登录成功页将用户名与数据库 avatar 字段未编码输出，构成反射型/存储型 XSS（medium）；以及 LLM-76f290c71ff5：第 19 行使用 MD5 对密码摘要后比对（low，CWE-328，属 weak_hash 而非 weak_crypto）。POC 齐全度为 3/3，但 SQL 注入与 XSS 的 POC 为基于源码构造的文本工件（TARGET 占位，仅限授权测试），未执行、未搭建沙箱、未动态复现；weak_hash 仅有静态证据 POC，不可宣称可动态复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中的 010.php（43 行）。该文件为 DVWA 风格登录脚本：第 3 行以 $_GET['Login'] 为入口，第 5 行做 CSRF token 校验，第 8-15 行读取 username/password 并做 stripslashes 与 mysqli_real_escape_string，第 19 行拼接 SQL 但已用 mysqli_real_escape_string 转义，未发现可闭合的 SQL 注入（转义覆盖了引号，且无二次注入证据）。发现两处问题：第 28-29 行用户名与 avatar 未做 HTML 编码直接输出，构成 XSS（需登录成功分支，confidence 0.72）；第 16 行使用 MD5 存储/比对口令，属 weak_hash（CWE-328）。第 33 行 sleep(rand(0,3)) 仅为失败延时，不构成可利用弱随机。未闭合线索：checkToken/generateSessionToken 定义不在 code_pack，无法确认 CSRF 防护强度；avatar 写入点未知，存储型 XSS 无法完全闭合；无服务器配置，无法确认危险函数开关。

未覆盖 / 证据缺口：
- checkToken/generateSessionToken 实现缺失
- avatar 字段写入点不在 code_pack
- 无 Web 服务器/php.ini 配置
- 无数据库 schema 与连接配置

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 010.php 提交登录参数，其中 username 参数（源码 010.php:8 读取，对应查询串 `username`）被直接拼接到 SQL 语句中。010.php:19 构造 `$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";`，$user 未经任何转义、类型约束或参数化即进入单引号字符串字面量；010.php:20 将该 $query 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于用户输入可闭合单引号并追加任意 SQL 片段（如 `' OR '1'='1` 或 UNION 查询），校验完全失效。此外 010.php:20 的 `or die(... mysqli_error(...) ...)` 会把数据库错误信息回显到页面，为报错型注入提供回显通道。

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

可绕过登录认证（以任意用户身份登录，包括管理员），并通过 UNION/报错注入读取 users 表及其他库表数据（口令哈希、账号信息），造成敏感数据泄露；若数据库账号权限较高，还可进一步读写数据甚至通过文件写入扩展影响服务器。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：010.php 为 Web 入口脚本，username 参数来自 HTTP 请求，无需认证即可访问登录页并提交；利用链闭合：010.php:8 外部输入 → 010.php:19 字符串拼接 → 010.php:20 mysqli_query 执行，中间无白名单、转义或预处理，且错误信息回显降低利用门槛。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare("SELECT * FROM users WHERE user = ? AND password = ?"); $stmt->bind_param('ss', $user, $pass); $stmt->execute();`；若必须拼接，使用 mysqli_real_escape_string 并配合严格白名单校验；关闭错误详情回显（生产环境不输出 mysqli_error），统一异常处理；数据库账号按最小权限授予，仅允许所需表的 SELECT。

**验证说明**

静态证据：入口 ANY /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在登录表单的 username 字段提交 `' OR '1'='1' -- ` 一类载荷 → 010.php:8 读取该参数到 $user → 010.php:19 直接拼入 `WHERE user = '$user'`，单引号被闭合、条件恒真 → 010.php:20 mysqli_query 执行被篡改的查询 → 返回首行用户记录，认证被绕过；若使用 UNION SELECT 或触发错误，则通过 010.php:20 的 die(mysqli_error(...)) 回显数据库内容。
PocWriter 建议（未采纳，缺少端点 /010）：针对 010.php:20 的 SQL 注入 POC。源码中外部输入来自查询参数 username，被直接拼接进 SQL 语句执行，未发现有效净化。POC 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010）：符合 CWE-89（SQL 注入）。漏洞位于 010.php:20，外部输入来自查询参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080 占位符，执行前需替换为授权目标。禁止使用 DROP 等破坏性语句。

### F-2: 010.php 登录成功页将用户名与数据库 avatar 字段未编码输出，形成反射型/存储型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.77`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:28-29`
- **来源**：`llm_finding`

**描述**

010.php 第 3 行在 $_GET['Login'] 存在时进入登录流程，第 8 行从 $_GET['username'] 读取用户名，仅做 stripslashes 与 mysqli_real_escape_string（只针对 SQL 上下文转义，对 HTML 上下文无效），第 28 行把 $user 直接拼进 HTML 字符串 $html 输出；第 25 行从数据库读取 $row['avatar']，第 29 行直接拼进 <img src="{$avatar}"> 属性。两处均无 htmlspecialchars 等 HTML 编码，攻击者可控的 username 或可写入的 avatar 字段可注入 HTML/JS。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:29 字符串拼接进 $html 输出（第 28、29 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取用户名 | 原始外部输入 |  |
| 2 | `010.php:9-10` | stripslashes 与 mysqli_real_escape_string 处理 | 仅做 SQL 上下文转义，HTML 元字符 < > " 未被编码 | mysqli_real_escape_string 只转义 SQL 特殊字符，不处理 HTML 标签 |
| 3 | `010.php:28` | 拼进 HTML 段落输出 | 未编码 HTML 输出 |  |

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
- POC 目录：`poc/LLM-8f91d878ba70`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意 JS，窃取会话或发起操作；avatar 字段若可被其他途径写入则为存储型 XSS

**CVE / CWE 论证**

CWE-79，外部 GET 参数直达 HTML 输出，无需高权限，链闭合；但需登录成功分支才回显，且依赖 user_token

**修复建议**

输出前使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')，avatar 同样编码或做 URL 白名单校验

**验证说明**

需确认登录成功分支可达及 user_token 校验逻辑；avatar 写入点不在 code_pack 内
模型 POC 要点：构造合法登录请求，使 username 含 HTML 标签，登录成功后回显触发
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /010.php）：针对 010.php:29 的反射型跨站脚本 POC。源码将查询参数 username 未编码地输出到 HTML 响应中，未发现有效净化。POC 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-79（跨站脚本）。漏洞位于 010.php:29，外部输入来自查询参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。主机统一为 TARGET:8080 占位符。载荷使用 alert(document.domain) 作为无害证明，避免破坏性操作。

### F-3: 010.php 使用 MD5 对密码做摘要后比对

- **类型**：`weak_hash` / CWE-328
- **严重度**：`low`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:16-19`
- **来源**：`llm_finding`

**描述**

第 16 行 $pass = md5($pass)，第 19 行将 MD5 值拼入 SQL 与数据库存储值比较。MD5 为已知弱哈希（CWE-328），无盐、快速，易被彩虹表/暴力破解，且若数据库泄露可直接碰撞。

**source / sink**

- source：query `password`（010.php:13）
- sink：010.php:19 md5() 摘要用于口令校验（第 16、19 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:13` | 读取 password 参数 | 明文口令 |  |
| 2 | `010.php:16` | MD5 摘要 | 无盐 MD5 值 |  |
| 3 | `010.php:19` | 拼入 SQL 比对 | 弱哈希比对 |  |

**POC**

针对 /010.php（GET）的 弱哈希算法 POC。注入点：GET 参数 password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/010.php?password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-76f290c71ff5`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可快速还原，导致账户接管

**CVE / CWE 论证**

CWE-328，源码明确使用 md5()，属配置/实现类弱点

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐

**验证说明**

需确认数据库实际存储格式是否为 MD5
模型 POC 要点：配置型弱点，无需请求构造；说明 MD5 可被离线破解
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /010.php）：针对 010.php:19 的弱哈希算法 POC。源码对 password 参数使用弱哈希（如 MD5/SHA1 类）处理，属于 CWE-328。该问题为配置/算法型缺陷，无典型 HTTP 污点链，验证以观察哈希输出特征为主。POC 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-328（使用弱哈希算法）。问题位于 010.php:19，属算法/配置型缺陷，依据源码中哈希调用判定，非普通参数值注入。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。主机统一为 TARGET:8080 占位符。验证以响应中的哈希特征为准，不进行离线破解。

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
| `weak_crypto` | CWE-327 |  | 0 |
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
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.59 | 是 |
| surface_mapper | 攻击面测绘 | 8.45 | 是 |
| deep_finder | LLM 深挖 | 9.05 | 是 |
| candidate_screener | 候选筛选 | 4.72 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.54 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.87 | 是 |
| coordinator | 管线协调 | 6.92 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
