# 落日二号乙漏洞挖掘报告 — 20261031-002050-35ce86

- 生成时间：2026-10-30T16:21:38.645087+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\024.zip`
- 输入模式：`zip`
- SHA256：`a2013a4944c4a1abb5e6dc291bf1a235fbddea2e99f978d43092c691e46798f1`
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

本次汇总 2 条已去重 findings，均集中在单文件 PHP 脚本 024.php：最高危为 GEN-cf38b1a2cb95（sql_injection，critical，CWE-89，024.php 第 19 行附近，规则命中，含 POC），其次为 LLM-a82244673cd8（business_logic，high，密码修改接口仅依赖可伪造的 HTTP_REFERER 做来源校验，可导致 CSRF 强制改密/账户接管，024.php 第 19 行附近，含 POC）。两条均带 POC，但均为静态/文本 POC，未做动态验证；其中 SQL 注入 POC 属 HTTP 型可复现文本，业务逻辑 POC 依赖浏览器/受害者会话语义，需人工确认。本次无二次注入链，无被隔离文件。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 024.php（37 行，DVWA 密码修改模块）。已逐行审计：第 3 行 Change 参数入口、第 5 行 Referer 来源校验、第 7-8 行密码参数读取、第 11 行相等比较、第 13 行 mysqli_real_escape_string、第 14 行 md5、第 18-19 行 UPDATE 拼接执行。结论：第 5 行的来源校验依赖可伪造的 HTTP_REFERER，且全程无 CSRF token、无旧密码校验，构成可导致账户接管的 CSRF 改密链（已报告）。SQL 注入方面，password_new 经 mysqli_real_escape_string 转义后再 md5，current_user 来自 dvwaCurrentUser() 而非直接请求参数，未发现可闭合的注入链；第 19 行 mysqli_error 回显属信息泄露，单独不足以申报。md5 用于口令存储属 weak_hash（CWE-328），但为 DVWA 教学代码固有设计，未单独立项。未提供 php.ini/路由/依赖清单，无法评估部署层风险；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 无端点清单，无法确认实际 URL 路径与是否强制登录
- 无 dvwaCurrentUser() 实现，无法确认 current_user 是否完全不可控
- 无 php.ini/服务器配置，无法评估 allow_url_include、display_errors 等
- md5 口令存储（weak_hash）未单独立项，仅作线索

## 3. Findings

### F-1: 024.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，该值在 024.php:8 被读取为 `password_conf`（源码片段中对应变量 `$pass_new`），随后在 024.php:18 被直接字符串拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';"`，未做任何转义或参数化。024.php:19 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $insert)` 执行该拼接语句，构成 source→sink 闭合链。由于 `$pass_new` 位于单引号字符串字面量内，攻击者提交含单引号的值即可闭合字面量并注入任意 SQL 片段（如 `' , user='admin' -- `），从而改写任意用户口令。`$current_user` 来自 `dvwaCurrentUser()`（024.php:17），属于会话派生值，不是本次注入主通道。

**source / sink**

- source：query `password_conf`（024.php:8）
- sink：024.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:8` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `024.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /024（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_conf；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/024?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cf38b1a2cb95`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入越权：攻击者可利用注入改写 `users` 表中任意账户（含 admin）的 password 字段，实现账户接管/提权；同时 024.php:19 的 `or die(... mysqli_error ...)` 会把数据库错误信息回显到页面，造成数据库结构与版本信息泄露，为进一步利用提供条件。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可控输入 `$pass_new` 未经参数化直接拼入 SQL 并在 024.php:19 执行；该功能为 Web 表单入口，无需认证即可到达注入点（若部署未强制登录），利用链 source→sink 完整闭合，属于典型的二阶写入型注入（存储写点 024.php:18/19，读取点为后续登录校验），可导致数据篡改与账户接管。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare("UPDATE users SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user); $stmt->execute();`；对 `$current_user` 同样使用绑定参数而非拼接；关闭 `mysqli_error` 的页面回显，改为记录服务端日志；对密码字段做长度与字符白名单校验，并在修改前校验旧口令与 CSRF token。

**验证说明**

静态证据：入口 ANY /024；source=query/password_conf；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在密码修改表单的 new password 字段提交 `' , user='admin' -- ` → 024.php:8 读取为 `$pass_new` → 024.php:18 字符串拼接生成 `UPDATE `users` SET password = '' , user='admin' -- ' WHERE user='...'` → 024.php:19 `mysqli_query` 执行，admin 口令被改写 → 攻击者以新口令登录 admin，完成账户接管。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:19 的 SQL 注入 POC（CWE-89）。外部输入来自请求参数 password_conf，未经有效净化即进入 SQL 查询汇点，可通过布尔条件改变查询结果。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89（SQL 注入）。漏洞位于 024.php:19，外部输入来自请求参数 password_conf，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：保留原有请求结构，仅补充基线与恒假对照步骤。脚本为文本工件，需人工替换 TARGET 后在授权环境手动执行；不包含任何自动执行或破坏性语句（无 DROP/rm 等）。

### F-2: DVWA 密码修改接口仅依赖可伪造的 HTTP_REFERER 做来源校验，导致 CSRF 强制改密/账户接管

- **类型**：`business_logic` / CWE-840
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 第 3 行在存在 GET 参数 Change 时进入改密流程；第 5 行用 stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false 判断请求来源，但 HTTP_REFERER 完全由客户端控制，攻击者只要在 Referer 中放入目标站点域名（如 TARGET 或 TARGET 的子串）即可通过校验。随后第 7-8 行直接读取 password_new/password_conf，第 11 行仅比较两次输入是否相等，第 14 行 md5 后在第 18-19 行拼入 UPDATE 语句修改当前用户密码。整个流程没有任何 CSRF token、没有旧密码校验、没有 Origin/Sec-Fetch-Site 校验，攻击者可诱导已登录受害者访问恶意页面，从而把受害者密码改为攻击者已知值，实现账户接管。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 024.php:19 mysqli_query 执行 UPDATE users SET password=... WHERE user=当前用户

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 检测到 GET 参数 Change 即进入改密分支，无需任何 token | 攻击者可控请求进入改密逻辑 |  |
| 2 | `024.php:5` | 用 stripos(HTTP_REFERER, SERVER_NAME) 判断来源，Referer 由客户端完全控制 | 攻击者构造 Referer 含目标域名即可通过 | HTTP_REFERER 可任意伪造，stripos 只做子串包含判断，无 Origin/CSRF token 校验 |
| 3 | `024.php:7-8` | 读取 password_new / password_conf | 攻击者指定新密码明文 |  |
| 4 | `024.php:11` | 仅比较两次输入是否相等，无旧密码校验 | 两次输入相同即通过 |  |
| 5 | `024.php:14` | 对新密码做 md5 | md5(新密码) |  |
| 6 | `024.php:18-19` | 拼接 UPDATE 语句并执行，修改当前登录用户密码 | 数据库密码被替换为攻击者已知值 |  |

**POC**

针对 /024.php（GET）的 业务逻辑漏洞 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 业务逻辑漏洞 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-a82244673cd8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是管理员则进一步控制整个应用。

**CVE / CWE 论证**

CWE-352（CSRF）/CWE-290（依赖可伪造来源做认证）。外部可达，无需认证即可构造请求，仅依赖受害者已登录状态；来源校验使用可伪造的 Referer，链完整闭合。

**修复建议**

引入 CSRF token 并在服务端校验；改密要求验证旧密码；使用 Origin/Sec-Fetch-Site 等不可伪造信号辅助判断，不要依赖 Referer。

**验证说明**

需确认 dvwaCurrentUser() 返回的是会话用户（决定是否为受害者自身账户被改），以及目标部署是否要求登录；Referer 伪造在浏览器场景下可通过攻击者页面设置或直接构造请求实现。
模型 POC 要点：诱导已登录 DVWA 的受害者访问攻击者页面，页面自动发起带伪造 Referer 的改密请求，将受害者密码改为攻击者已知值
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php:19 的业务逻辑漏洞 POC（CWE-840）。请求参数 password_new 在缺少身份校验/流程约束的情况下被处理，可能允许未授权修改口令或绕过业务校验。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-840（业务逻辑错误）。漏洞位于 024.php:19，外部输入来自请求参数 password_new，在给定代码范围内未见有效校验，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：保留原有请求结构，补充基线与对照步骤。脚本为文本工件，需人工替换 TARGET 后在授权环境手动执行；不包含自动执行或破坏性语句。

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
| `xss` | CWE-79 | 是 | 0 |
| `business_logic` | CWE-840 | 是 | 1 |
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
| safety_guard | 安全防护 | 2.96 | 是 |
| surface_mapper | 攻击面测绘 | 10.51 | 是 |
| deep_finder | LLM 深挖 | 9.39 | 是 |
| candidate_screener | 候选筛选 | 5.14 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.05 | 是 |
| coordinator | 管线协调 | 6.56 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
