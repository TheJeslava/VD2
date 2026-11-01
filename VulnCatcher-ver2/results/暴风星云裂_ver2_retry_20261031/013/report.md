# 落日二号乙漏洞挖掘报告 — 20261031-001858-400795

- 生成时间：2026-10-30T16:19:40.218273+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总 2 条已去重 findings，均集中在单文件 PHP 脚本 013.php（55 行）：一条为 critical 级 SQL 注入（GEN-89dab2f7ae60，修改密码处，CWE-89，规则命中），一条为 high 级 auth_bypass（LLM-fbe117aea12d，CAPTCHA 校验可被伪造请求头绕过，含硬编码后门值）。最高危为 013.php 的 SQL 注入，位于密码修改逻辑，可导致凭据数据被读取或篡改。两条 finding 均标注 has_poc=true，POC 文本齐全，但均为静态源码推断产物，未做任何动态验证；auth_bypass 依赖硬编码后门值与会话语义，属静态证据 POC，不能宣称可动态复现。本次无二次注入链输入，未做二次注入判定。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 013.php（55 行，DVWA captcha 密码修改模块）。发现一条闭合的认证绕过链：CAPTCHA 校验存在硬编码后门值 hidd3n_valu3 与可伪造 User-Agent 条件，攻击者可绕过人机校验重置密码。第 26 行对 password_new 做了 mysqli_real_escape_string 后再 md5，SQL 注入链不成立（转义+哈希后进入 UPDATE，且 user 来自 dvwaCurrentUser() 非用户输入）。第 34/38/44 行 $html 拼接为固定字符串，无用户输入回显，反射型 XSS 不成立。未发现命令执行、文件包含、SSRF 汇点。未覆盖：无 composer/依赖清单、无服务器与 php.ini 配置、无路由与访问控制信息，无法评估部署层利用条件。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 recaptcha 行为与 allow_url_include 等
- 无路由与认证配置，无法确认该脚本真实 URL 与访问控制
- 无依赖清单，无法评估第三方库 CVE

## 3. Findings

### F-1: 013.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.53`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求提交参数 password_conf（013.php:9 读取），该值被赋给 $pass_new 后直接字符串拼接进 UPDATE 语句：013.php:30 构造 $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;"，其中 $pass_new 未做任何转义或参数化；随后 013.php:31 通过 mysqli_query($GLOBALS["___mysqli_ston"], $insert) 执行。由于单引号可被注入，攻击者可闭合 password 字段的字符串字面量，改写 SET 子句或追加条件，从而改变 UPDATE 语义。代码中未见 mysqli_real_escape_string、预处理语句或白名单校验，校验完全缺失。

**source / sink**

- source：query `password_conf`（013.php:9）
- sink：013.php:31 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:9` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `013.php:31` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /013（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_conf；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/013?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-89dab2f7ae60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可对 users 表执行任意 UPDATE 语义：篡改任意用户（含 admin）口令实现账户接管/越权登录，或通过布尔/时间盲注逐位读取数据库内容（凭据、用户表数据）造成数据泄露；错误信息经 die(mysqli_error(...)) 回显，进一步辅助报错注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达：013.php 为 Web 端点，参数 password_conf 由请求直接提供，无需认证即可到达 013.php:9→30→31 的完整链路；污点从 source 到 mysqli_query 汇点闭合，中间无净化函数，故成立。

**修复建议**

改用预处理语句：$stmt = $mysqli->prepare("UPDATE `users` SET password = ? WHERE user = ? LIMIT 1"); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); 并对 dvwaCurrentUser() 同样参数化；若必须拼接，使用 mysqli_real_escape_string 并配合最小权限数据库账户；关闭 die(mysqli_error()) 的详细错误回显，改为记录日志。

**验证说明**

静态证据：入口 ANY /013；source=query/password_conf；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 password_conf（013.php:9）→ $pass_new → 字符串拼接进 $insert（013.php:30）→ mysqli_query 执行（013.php:31）。注入点位于 password 字段的单引号字面量内，攻击者提交如 ' , user='admin' -- - 之类的值即可改变 WHERE 条件或 SET 目标，实现任意用户口令改写或注入子查询进行数据读取。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 password_conf，被拼接进 SQL 语句执行，未发现有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89（SQL 注入）。漏洞位于 013.php:31，外部输入来自查询参数 password_conf，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权测试环境地址，并确保已获授权。步骤 3 为对照验证，不涉及 DROP 等破坏性语句。

### F-2: DVWA 密码修改接口 CAPTCHA 校验可被伪造请求头绕过（硬编码后门值）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-31`
- **来源**：`llm_finding`

**描述**

013.php 在处理密码修改时，CAPTCHA 校验逻辑为 `if ($resp || ($_POST['g-recaptcha-response'] == 'hidd3n_valu3' && $_SERVER['HTTP_USER_AGENT'] == 'reCAPTCHA'))`。攻击者无需真正通过 reCAPTCHA，只需提交固定字符串 `hidd3n_valu3` 作为 g-recaptcha-response，并把 User-Agent 设为 `reCAPTCHA`，即可让整个条件恒真，进入密码修改分支。该分支随后用 md5 处理新密码并执行 UPDATE 语句修改当前用户密码，导致攻击者在不知道原密码、不通过人机校验的情况下重置账户密码，构成认证绕过/账户接管。

**source / sink**

- source：body `g-recaptcha-response`（013.php:8-9）
- sink：013.php:31 mysqli_query 执行 UPDATE users SET password=... （013.php:31）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 脚本检测到 POST 参数 Change 后进入密码修改流程 | 攻击者控制整个 POST 请求体 |  |
| 2 | `013.php:8-9` | 读取 password_new / password_conf 两个新密码参数 | 原始字符串，未净化 |  |
| 3 | `013.php:12-15` | 调用 recaptcha_check_answer 校验第三方 CAPTCHA，正常情况下应返回失败 | $resp 为 false（未通过真实 CAPTCHA） |  |
| 4 | `013.php:17-23` | 由于 $resp 为 false，进入 OR 的第二个条件；攻击者提交 g-recaptcha-response=hidd3n_valu3 且 User-Agent=reCAPTCHA，使条件恒真 | 布尔条件被攻击者控制为 true | 硬编码后门值 hidd3n_valu3 与可伪造的 User-Agent 头共同构成绕过条件，完全跳过真实 CAPTCHA 校验 |
| 5 | `013.php:25-27` | 两次密码一致时，对新密码做 mysqli_real_escape_string 后 md5 | 新密码被 md5 哈希 |  |
| 6 | `013.php:30-31` | 拼接 UPDATE 语句并执行，修改当前用户密码 | SQL 语句执行，密码被重置 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的认证绕过 POC（CWE-287）。服务端对 g-recaptcha-response 的校验可被伪造值绕过，从而以未授权身份通过验证流程。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'g-recaptcha-response=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-fbe117aea12d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过 CAPTCHA、无需知道原密码即可重置账户密码，导致账户接管；若结合 CSRF 可对受害者静默改密。

**CVE / CWE 论证**

CWE-287 认证机制不当 / CWE-798 硬编码凭据。外部可通过 HTTP 请求直接触发，条件恒真分支完全由攻击者可控输入决定，利用链闭合。

**修复建议**

移除硬编码后门值 hidd3n_valu3 及基于 User-Agent 的绕过分支，仅信任 recaptcha_check_answer 的真实返回结果；同时校验原密码。

**验证说明**

需确认部署中 recaptcha_check_answer 在无网络/无密钥时返回 false，从而确实走到 OR 第二分支；以及 dvwaCurrentUser() 返回当前会话用户。
模型 POC 要点：利用硬编码 CAPTCHA 后门值与伪造 User-Agent 绕过人机校验，重置当前登录用户密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-287（认证机制不当）。漏洞位于 013.php:31，外部输入来自 POST 参数 g-recaptcha-response，source→sink 链在给定代码范围内静态闭合，未发现有效校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权测试环境地址，并确保已获授权；payload 仅为占位伪造值，不含自动执行内容。

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
| `auth_bypass` | CWE-287 | 是 | 1 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 0 |
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
| `weak_hash` | CWE-328 |  | 0 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.74 | 是 |
| surface_mapper | 攻击面测绘 | 7.17 | 是 |
| deep_finder | LLM 深挖 | 9.0 | 是 |
| candidate_screener | 候选筛选 | 4.58 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.25 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.87 | 是 |
| coordinator | 管线协调 | 6.22 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
