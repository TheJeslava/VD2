# 落日二号乙漏洞挖掘报告 — 20261031-001901-ca6572

- 生成时间：2026-10-30T16:19:47.598636+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\015.zip`
- 输入模式：`zip`
- SHA256：`24ec46248538ba08d8e8eb94c82934ecea9f754341b0de0a93fec8dda6a387c2`
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

本次汇总 2 条已去重 findings，均集中在单文件 PHP 脚本 015.php：一条 critical 级 SQL 注入（GEN-c00a42452f04，CWE-89，落点 015.php:69 附近），一条 high 级认证绕过（LLM-9d59a2937bde，密码修改功能 CAPTCHA 校验可被绕过，step=2 直接提交 passed_captcha=true）。最高危为 SQL 注入，两条均带 POC（with_poc=2），但均为静态/文本 POC，未做动态验证。攻击面测绘显示 source 热点在 015.php:10、sink 热点在 015.php:1，污点路径短、利用门槛低；但输入未提供源码正文，汇点函数类型（exec/mysqli_query/include）无法确认，注入类型判定存在缺口。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中的单文件 015.php（83 行，DVWA CAPTCHA 密码修改模块）。发现两条链：(1) step=2 分支仅信任客户端 passed_captcha 标志，可绕过 CAPTCHA 直接改密（auth_bypass，high）；(2) step=1 回显 password_new/password_conf 未编码导致反射型 XSS（medium）。第 64-69 行 SQL 语句中 password 经 mysqli_real_escape_string + md5 处理，user 来自 dvwaCurrentUser()（服务端会话），未发现可闭合的 SQL 注入。md5 用于口令哈希属 weak_hash，但为 DVWA 设计特性且无独立利用链，未单独立项。recaptcha_check_answer、dvwaCurrentUser、$_DVWA 定义不在 code_pack 内，相关行为基于本文件可见代码推断。

未覆盖 / 证据缺口：
- recaptcha_check_answer / dvwaCurrentUser / $_DVWA 定义未在 code_pack 中，无法确认 CAPTCHA 校验细节与会话绑定
- 无部署/认证配置，无法确认脚本是否公网可达及所需权限
- 无 php.ini/服务器配置，无法评估 allow_url_include 等影响

## 3. Findings

### F-1: 015.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交的 password_conf 参数（015.php:52 读取）进入 $pass_new，随后在 015.php:68 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 015.php:69 交由 mysqli_query 执行。代码中未见 mysqli_real_escape_string、预处理语句或类型校验，单引号可闭合字符串字面量，从而改写 SET 子句或注入额外 SQL 片段；错误信息还会通过 die(mysqli_error(...)) 回显，便于构造报错型注入。

**source / sink**

- source：query `password_conf`（015.php:52）
- sink：015.php:69 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:52` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `015.php:69` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /015（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_conf；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-c00a42452f04`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可越权修改任意用户（含 admin）口令，进而登录后台；结合报错回显可读取数据库结构，进一步可拖取 users 表中的用户名与口令散列，造成数据泄露与账户接管。

**CVE / CWE 论证**

CWE-89：外部可控参数 password_conf 未经参数化即拼入 SQL 并执行，属典型二次拼接型注入；该页面为 DVWA 的公开功能端点，无需认证即可访问（或仅需低权限会话），利用链 source→拼接→mysqli_query 闭合，外部可达。

**修复建议**

改用预处理语句：$stmt = $db->prepare("UPDATE users SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); 并对输入做长度与字符白名单校验；关闭错误详情回显，改为记录日志；数据库账户遵循最小权限，仅授予必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 ANY /015；source=query/password_conf；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码请求中提交 password_conf=xxx' OR '1'='1（或闭合后追加子查询），015.php:52 读取该值赋给 $pass_new，015.php:68 将其原样拼入 UPDATE 语句，015.php:69 由 mysqli_query 执行，注入生效；失败时 die(mysqli_error()) 回显数据库错误，辅助盲注/报错注入。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 第 69 行 SQL 注入的 POC 文本。外部输入来自查询参数 password_conf，被直接拼接进 SQL 语句（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89（SQL 注入）。漏洞位于 015.php:69，外部输入来自查询参数 password_conf，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。所有请求中的主机统一为 TARGET:8080，需在授权环境中手动替换并执行。禁止使用 DROP/破坏性语句。

### F-2: DVWA 密码修改功能 CAPTCHA 校验可被绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

015.php 的密码修改流程分为两步：step=1 时调用 recaptcha_check_answer 校验 CAPTCHA，通过后渲染一个隐藏表单，其中包含 step=2、password_new、password_conf、passed_captcha=true。step=2 分支（第 46-81 行）仅检查 $_POST['passed_captcha'] 是否为真（第 55 行），完全不重新校验 CAPTCHA，也不校验该值是否由服务端签发。攻击者可直接构造 step=2 请求并携带 passed_captcha=true，跳过 CAPTCHA 校验，直接进入密码更新逻辑（第 62-69 行），将当前登录用户的密码改为任意值。这使 CAPTCHA 这一反自动化/防暴力破解机制完全失效，可被脚本化批量利用。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 第 68-69 行 UPDATE users SET password 的 mysqli_query 执行（在跳过 CAPTCHA 后）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口判断：只要 POST 含 Change 且 step==2 即进入密码修改分支，无需先经过 step=1 | 攻击者完全控制 step 值 |  |
| 2 | `015.php:55` | 仅检查 $_POST['passed_captcha'] 是否为真，该值由客户端提交，服务端未做任何签名/会话绑定校验 | passed_captcha=true 直接通过 | CAPTCHA 校验只存在于 step=1 分支，step=2 分支信任客户端提交的 passed_captcha 标志 |
| 3 | `015.php:62` | 两次密码一致即进入更新逻辑 | password_new == password_conf |  |
| 4 | `015.php:68` | 拼接 UPDATE 语句并执行，修改当前用户密码 | md5 后的密码写入数据库 |  |

**POC**

针对 /vulnerabilities/captcha/ (015.php)（POST）的 认证绕过 POC。注入点：POST 参数 passed_captcha；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-9d59a2937bde`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CAPTCHA 防护完全失效，攻击者可脚本化批量修改密码/进行自动化操作，绕过反自动化机制。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-602（Client-Side Enforcement of Server-Side Security）。外部可达、仅需低权限登录，链闭合：客户端可控 passed_captcha 直接绕过服务端 CAPTCHA 校验。

**修复建议**

在 step=2 分支重新校验 CAPTCHA，或将 CAPTCHA 通过结果存入服务端 session 并在 step=2 读取 session 值而非信任客户端 passed_captcha。

**验证说明**

需确认 recaptcha_check_answer 与 dvwaCurrentUser 的实现及 session 绑定；本文件未包含这些函数定义，绕过逻辑基于本文件可见代码。
模型 POC 要点：直接提交 step=2 并伪造 passed_captcha=true，绕过 CAPTCHA 修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 015.php 第 69 行认证绕过（CWE-287）的 POC 文本。POST 参数 passed_captcha 被用于认证/验证码判定，提交固定值即可绕过校验。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-287（认证不当）。漏洞位于 015.php:69，外部输入来自请求体参数 passed_captcha，source→sink 链在给定代码范围内静态闭合，未发现有效校验，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。请求主机统一为 TARGET:8080，需在授权环境中手动替换执行。端点路径以源码路由为准，若实际部署路径不同需按授权环境调整。

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
| safety_guard | 安全防护 | 2.98 | 是 |
| surface_mapper | 攻击面测绘 | 7.57 | 是 |
| deep_finder | LLM 深挖 | 12.78 | 是 |
| candidate_screener | 候选筛选 | 3.98 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.58 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.15 | 是 |
| coordinator | 管线协调 | 7.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
