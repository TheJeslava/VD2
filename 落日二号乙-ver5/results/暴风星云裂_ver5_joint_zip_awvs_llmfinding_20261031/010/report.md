# 落日二号乙漏洞挖掘报告 — 20261031-214058-2cee6d

- 生成时间：2026-10-31T13:41:59.979989+00:00
- 输入：`$WORKSPACE\暴风星云裂\010.zip`
- 输入模式：`zip`
- SHA256：`819467f4e89f5ccb8366890305cd0e83be79b38873b4535d43cf0f2c08e7c6c7`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 010.php（43 行，无框架、无路由）。最高危为 GEN-7034f0a19983：010.php 第 20 行附近的登录查询 SQL 注入（critical，CWE-89，规则命中，含 POC）；其次为 LLM-f803c7aea6a6：登录成功页将用户可控 username 未转义回显导致反射型 XSS（medium，第 28 行附近，含 POC）；以及 SEM-949d40928ae7：使用 MD5 处理口令（medium，第 16 行附近，含 POC）。3 条 finding 均标注 has_poc=true，但需注意：SQL 注入与 XSS 属 HTTP 型 POC，可描述为可动态复现路径；MD5 弱哈希属静态证据 POC（代码语义即可判定），不能宣称可动态复现。本次未发现二次注入链（无存储写点/读点证据），未发现 prompt_injection 诱导文本。所有结论均为源码/规则层面的静态推断，未经动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：1 条；安全校验拒绝：0 条

模型覆盖说明：CODE PACK 仅含单文件 010.php（43 行）。已审计：GET 参数 username/password 的取值与净化（stripslashes + mysqli_real_escape_string）、SQL 拼接（第 19-20 行，已用 mysqli_real_escape_string 且 password 经 md5，未发现可闭合的 SQL 注入）、登录成功/失败分支的 HTML 输出（第 28-29 行）、sleep(rand(0,3)) 弱随机（仅用于延迟，无安全语义，不单独立项）。发现两条 XSS 链：username 反射型（链闭合，但 CODE PACK 未见 echo $html，输出点属缺口）；avatar 存储型（读点/汇点闭合，存储写点缺失）。未闭合线索：checkToken/generateSessionToken 定义不在 CODE PACK，无法评估 CSRF 令牌强度；$html 最终输出语句缺失；无配置文件无法判断 allow_url_include 等；无端点清单。

未覆盖 / 证据缺口：
- $html 的最终 echo/输出语句不在 CODE PACK（1-43 行内未见），XSS 输出点需人工确认
- checkToken / generateSessionToken 函数定义缺失，无法评估令牌生成与校验
- avatar 字段的存储写点不在 CODE PACK，存储型 XSS 写点未证实
- 无 php.ini/Web 服务器配置，无法判断运行环境对可利用性的影响
- 无路由/包含链信息，无法确认是否存在前置认证或网关

## 3. Findings

### F-1: 010.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `username`（010.php:8 读取）提交任意字符串，该值被直接拼进 010.php:19 的 SQL 语句 `SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';`，随后在 010.php:20 由 mysqli_query 执行。代码中未见对 `$user` 的引号转义或参数化处理（对比 010.php:15 对 `$pass` 调用了 mysqli_real_escape_string，而 `$user` 没有同等处理），因此单引号可闭合字符串字面量，注入任意 SQL 片段。此外 010.php:20 的 `or die(... mysqli_error ...)` 会把数据库错误信息回显到响应中，为报错型注入和结构探测提供便利。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:20 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `010.php:20` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /010（GET）的 SQL 注入 POC。注入点：GET 参数 username；payload 使用 TARGET 占位符。

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

可绕过登录认证（如构造 `username=' OR '1'='1' -- ` 使 WHERE 恒真），并通过 UNION/布尔/报错注入读取 users 表及其他库表数据（口令哈希、用户信息），在数据库账号权限较高时还可能读写文件或进一步影响数据库主机；错误回显进一步降低利用门槛。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `username`，无需认证即可访问登录逻辑；利用链闭合：010.php:8 取参 → 010.php:19 字符串拼接 → 010.php:20 mysqli_query 执行，中间无有效净化或参数化，且错误信息回显（010.php:20）辅助确认注入。证据等级为源码推断，未做动态验证。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），彻底避免字符串拼接；对输入做类型/长度白名单校验；关闭数据库错误详情回显，改为记录服务端日志并返回通用错误；数据库账号遵循最小权限，禁止 FILE 等高风险权限。

**验证说明**

静态证据：入口 GET /010；source=query/username；sink=010.php:20；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在请求中设置 `username` 参数（010.php:8）→ 值未经转义进入 `$user` → 在 010.php:19 被拼入 SQL 文本 → 010.php:20 通过 mysqli_query 执行 → 结果/错误经 die() 回显，形成可闭合引号的注入链。

### F-2: 010.php 登录成功页将用户可控 username 未转义回显（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:8-28`
- **来源**：`llm_finding`

**描述**

脚本从 $_GET['username'] 取值，仅做 stripslashes 与 mysqli_real_escape_string 处理（后者只针对 SQL 上下文转义，对 HTML 上下文无效），随后在登录成功分支直接拼接进 HTML 输出：$html .= "<p>Welcome to the password protected area {$user}</p>"。攻击者可构造带 HTML/JS 的 username，诱导受害者点击链接；若受害者凭据有效（或攻击者自身登录成功），脚本将原样输出脚本标签，导致在站点源下执行任意 JS，可窃取会话或发起 CSRF 令牌读取等操作。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:28 $html .= "<p>Welcome to the password protected area {$user}</p>"（HTML 输出拼接）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取攻击者可控输入 | 原始字符串 |  |
| 2 | `010.php:9` | stripslashes 去除反斜杠 | 仍含 HTML/JS 字符 | stripslashes 不做 HTML 编码 |
| 3 | `010.php:10` | mysqli_real_escape_string 仅转义 SQL 特殊字符 | HTML 标签与引号保持不变 | SQL 转义对 HTML 上下文无效，< > " 不被处理 |
| 4 | `010.php:28` | 登录成功后把 $user 直接拼入 HTML 输出 | 未编码的 HTML 片段进入响应体 |  |

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

在站点源下执行任意 JavaScript，可窃取会话 Cookie、读取 CSRF token 并发起敏感操作，或对管理员实施钓鱼。

**CVE / CWE 论证**

CWE-79 反射型 XSS；外部 GET 可达，无需特殊权限（仅需有效凭据触发成功分支），source→sink 链在 CODE PACK 内闭合。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；avatar 输出同样应做属性编码与 URL 白名单校验。

**验证说明**

需确认登录成功分支在真实部署中可达（凭据有效），以及 $html 是否在脚本外被 echo 输出（CODE PACK 仅到 43 行，未见 echo $html，属缺口）。
模型 POC 要点：使用合法凭据登录，同时把 XSS payload 放入 username 参数，使成功分支回显未转义内容
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
LLM 深挖重复命中（xss，conf=0.6）；保留首条候选，补充：登录成功后从数据库读取 $row['avatar'] 并直接拼入 <img src="{$avatar}" />。若 avatar 字段可被用户控制（如注册/资料修改写入），则可注入 " onerror=... 等属性逃逸 payload，形成存储型 XSS。存储写点不在 CODE PACK 内，读点与危险汇点在 01

### F-3: 010.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`010.php:15-16`
- **来源**：`rule`

**描述**

010.php:16 执行 `$pass = md5( $pass );`，将用户提交的口令用 MD5 做单次无盐哈希后再用于 010.php:19 的登录比对。MD5 属于已破译的快速哈希算法，抗碰撞与抗暴力破解能力不足，且此处未见加盐或迭代（如 password_hash/bcrypt/Argon2）。注意：该弱点本质是弱哈希（CWE-328），不是加密算法模式问题（CWE-327）。

**source / sink**

- source：repository `md5(`（010.php）
- sink：010.php:16 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:16` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 `010.php:16` 记录问题，无需发送请求。

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

一旦 users 表口令哈希泄露（可与同文件 GEN-7034f0a19983 的 SQL 注入结合导出），攻击者可用彩虹表/GPU 暴力快速还原明文口令，导致账号接管；相同口令产生相同哈希也便于横向撞库。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。属实现/配置型弱点，不要求 HTTP 污点链；原文证据为 010.php:16 的 `md5( $pass )` 调用及 010.php:19 中该哈希参与口令比对。外部可达性体现在登录接口接受外部口令输入，无需认证。

**修复建议**

改用专为口令设计的慢哈希：PHP 的 password_hash()（PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID）配合 password_verify()，自动加盐并支持成本参数；对存量 MD5 哈希在用户下次登录成功时透明升级；强制口令复杂度并限制登录失败次数。

**验证说明**

静态证据：入口 GET /010；source=repository/md5(；sink=010.php:16；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 010.php:16 以 MD5 单次无盐哈希 → 哈希值在 010.php:19 拼入查询用于比对；哈希强度不足使离线破解可行，若与 SQL 注入结合可直接获取哈希并还原口令。

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
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.69 | 是 |
| surface_mapper | 攻击面测绘 | 11.09 | 是 |
| deep_finder | LLM 深挖 | 12.23 | 是 |
| candidate_screener | 候选筛选 | 5.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.26 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 12.33 | 否 |
| coordinator | 管线协调 | 7.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
