# 落日二号乙漏洞挖掘报告 — 20261031-010117-3a4126

- 生成时间：2026-10-30T17:02:12.433977+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\024.zip`
- 输入模式：`zip`
- SHA256：`a2013a4944c4a1abb5e6dc291bf1a235fbddea2e99f978d43092c691e46798f1`
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

本次汇总基于单文件 PHP 脚本 024.php（37 行）的已去重 findings，共 3 条，全部带 POC（3/3）。最高危为 GEN-cf38b1a2cb95：024.php 第 19 行密码修改功能的 SQL 注入（critical，CWE-89，规则命中），数据流短、可利用性高。其次为 LLM-3eef1cf779fd：同一功能仅用 HTTP_REFERER 子串校验，可被 CSRF 绕过并导致账户接管（high）。第三为 LLM-93afb8856d1f：口令以无盐 MD5 存储（medium，weak_hash/CWE-328）。POC 齐全，但 SQL 注入与 CSRF 为 HTTP 型 POC（可动态复现），weak_hash 仅有静态证据 POC，不能宣称可动态复现。所有结论均为源码审计与规则/模型推断，未经动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 024.php（1-37 行全量）。该脚本为 DVWA 密码修改页面：入口为 GET 参数 Change/password_new/password_conf，来源校验仅用 stripos 比对 HTTP_REFERER 与 SERVER_NAME（可绕过），随后 md5 哈希并拼接 SQL 执行 UPDATE。发现两条可闭合问题：(1) CSRF——缺少 token、无原密码校验、Referer 假防护可绕过，可导致账户接管（high）；(2) 无盐 MD5 存储口令（medium，CWE-328）。SQL 拼接处 password_new 已经 mysqli_real_escape_string 转义，current_user 来自 dvwaCurrentUser() 非直接用户输入，未构成 SQL 注入。未覆盖：dvwaCurrentUser() 定义、数据库连接初始化、Web 服务器配置（allow_url_include 等）均不在 code_pack 内，无法评估；无端点清单，实际 URL 以 /024.php 推断。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现未提供，无法确认 current_user 是否可被污染
- 数据库连接与 ___mysqli_ston 初始化不在 code_pack
- 无 Web 服务器/php.ini 配置，无法评估部署层可利用性
- 无端点清单，URL 与参数名基于源码推断

## 3. Findings

### F-1: 024.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.53`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过密码修改表单提交新口令，该值在 024.php:7 被读入变量 $pass_new（候选 source 记为 query `password_new`）。024.php:18 用字符串拼接把 $pass_new 直接嵌入 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";，其中 $current_user 来自 dvwaCurrentUser()（024.php:17）。024.php:19 将该拼接串交给 mysqli_query($GLOBALS["___mysqli_ston"], $insert) 执行，全程未见 mysqli_real_escape_string、预处理语句或类型白名单，单引号可闭合 password 字面量，从而改写 WHERE 子句或追加语句。注意：候选给出的 source 名称 `password_new` 与代码片段中出现的变量 $pass_new 存在命名差异，具体表单字段名在给定片段中未直接出现，需以 024.php:7 的实际读取语句为准。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `024.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 024.php 第 19 行（端点 /024，方法 ANY）的 SQL 注入 POC。外部输入来自 query 参数 password_new，被直接拼入 SQL 语句，未发现有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/024?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cf38b1a2cb95`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写操作被劫持：攻击者可利用 UPDATE 语句的注入点改写 users 表中任意用户（含 admin）的 password 字段，实现账户接管与越权登录；配合错误回显（024.php:19 的 die(mysqli_error(...))）可泄露库名、表结构与数据，属于数据篡改与敏感信息泄露。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：该逻辑位于 DVWA 的密码修改页面，登录用户通过 HTTP 表单即可触达；利用链闭合：外部输入 $pass_new（024.php:7）→ 字符串拼接 $insert（024.php:18）→ mysqli_query 执行（024.php:19），中间无参数化或转义，且错误信息直接回显，便于注入验证。无需额外权限即可在已认证会话内完成注入。

**修复建议**

改用预处理语句与参数绑定：$stmt = $db->prepare("UPDATE users SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user); $stmt->execute();。若必须拼接，至少对 $pass_new 使用 mysqli_real_escape_string 并配合白名单校验；同时移除 024.php:19 中把 mysqli_error 直接输出到页面的 die 分支，改为记录日志并返回通用错误。

**验证说明**

静态证据：入口 ANY /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在密码修改表单提交含单引号的 password_new 值 → 024.php:7 读入 $pass_new → 024.php:18 拼接进 UPDATE `users` SET password = '$pass_new' WHERE user = '...' → 024.php:19 mysqli_query 执行被篡改的 SQL → 改写任意用户口令或通过错误回显读取数据库信息。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 024.php:19，外部输入来自 query 参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止使用 DROP 等破坏性语句。request.http 中 Content-Length 按 body 字节数填写，实际发送时以工具自动计算为准。

### F-2: DVWA 密码修改功能仅依赖 HTTP_REFERER 子串校验，可被 CSRF 绕过并接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 的密码修改逻辑在 `isset($_GET['Change'])` 时执行，用 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false` 判断请求来源，随后直接读取 `password_new`/`password_conf` 并执行 `UPDATE users SET password=...`。Referer 头完全由客户端控制，攻击者只需让 Referer 包含目标主机名（例如 `http://TARGET/...` 或 `http://evil.com/?TARGET`）即可通过校验；同时该操作没有任何 CSRF token、没有要求提交原密码、也没有二次确认，属于典型的认证后状态改变缺少 token 的 CSRF。攻击者可诱导已登录受害者访问恶意页面，自动发起 GET 请求把受害者密码改为攻击者已知值，从而接管账户。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 024.php:18-19 拼接 SQL 并 mysqli_query 执行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 攻击者构造带 Change 参数的 GET 请求，触发密码修改分支 | 外部请求进入脚本 |  |
| 2 | `024.php:5` | 用 stripos 判断 Referer 是否包含 SERVER_NAME，仅做子串匹配，未校验来源页面真实性 | Referer 由攻击者控制，可包含目标主机名 | stripos 子串匹配可被 `http://evil.com/?TARGET` 或 `http://TARGET.evil.com` 形式绕过，且 Referer 可被攻击者页面任意设置 |
| 3 | `024.php:7-8` | 读取 password_new / password_conf | 攻击者指定新密码 |  |
| 4 | `024.php:11-14` | 两次密码相等则 md5 处理 | 新密码哈希 |  |
| 5 | `024.php:17-19` | 取当前登录用户并执行 UPDATE 修改其密码 | 受害者账户密码被改为攻击者已知值 |  |

**POC**

针对 024.php 第 19 行（端点 /024.php，方法 GET）的 CSRF POC。修改密码等状态变更操作通过 GET 参数 password_new 传递且缺少 CSRF token 校验，可被跨站自动提交表单触发。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-3eef1cf779fd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户可被跨站请求伪造修改密码，导致账户接管；若受害者是管理员则进一步控制后台。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。外部可达（GET 请求），无需原密码，仅依赖受害者已登录会话；Referer 校验为可绕过的假防护，链闭合。

**修复建议**

引入 CSRF token 并在服务端校验；要求提交原密码；将状态改变操作改为 POST；不要依赖 Referer 做安全判断。

**验证说明**

需确认 DVWA 部署中 SERVER_NAME 与受害者访问主机名一致，以及浏览器是否发送 Referer；逻辑链在源码层面完整。
模型 POC 要点：诱导已登录 DVWA 的受害者访问攻击者页面，页面自动发起带正确 Referer 的 GET 请求修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352（跨站请求伪造）。漏洞位于可交付代码 024.php:19，状态变更通过 GET 参数 password_new 传递且缺少反 CSRF 机制，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。poc.html 需由授权测试人员在受控环境手动托管并访问；TARGET 需手动替换。原草稿中把说明文字当作参数值发送的请求仅作占位，实际验证应以 poc.html 自动提交表单为准。

### F-3: 密码修改使用无盐 MD5 存储口令

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:14-18`
- **来源**：`llm_finding`

**描述**

024.php 第 14 行对用户新密码执行 `md5($pass_new)` 后直接写入 users 表。MD5 为快速哈希且未加盐，攻击者一旦获取数据库即可通过彩虹表/暴力破解快速还原明文口令，属于 CWE-328 弱哈希。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:18 024.php:14 md5 哈希后写入数据库

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 读取新密码 | 明文口令 |  |
| 2 | `024.php:14` | 使用无盐 MD5 哈希 | MD5 摘要 |  |
| 3 | `024.php:18-19` | 写入 users 表 | 弱哈希存储 |  |

**POC**

针对 024.php 第 18 行（端点 /024.php，方法 GET）的弱哈希算法 POC。代码对 password_new 使用弱哈希（如 MD5/SHA1 类）处理口令，未加盐或使用慢哈希，可被离线暴力/彩虹表破解。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-93afb8856d1f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可被快速破解，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328 弱哈希。源码明确使用 md5 且无盐，属配置/实现型缺陷，无需 HTTP 污点即可成立。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

需确认 users 表实际存储格式确为 MD5；源码层面已明确。
模型 POC 要点：该问题为存储实现缺陷，无直接远程利用请求；通过数据库泄露后离线破解验证
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-328（使用弱哈希算法）。漏洞位于可交付代码 024.php:18，password_new 进入弱哈希处理路径，属配置/算法型缺陷，不依赖 HTTP 污点闭合。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。TARGET 需由授权测试人员手动替换；本类为配置型候选，验证重点在算法与盐值，而非响应差异。

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
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 0 |
| `csrf` | CWE-352 |  | 1 |
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
| safety_guard | 安全防护 | 2.51 | 是 |
| surface_mapper | 攻击面测绘 | 9.09 | 是 |
| deep_finder | LLM 深挖 | 12.04 | 是 |
| candidate_screener | 候选筛选 | 7.3 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.65 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.99 | 是 |
| coordinator | 管线协调 | 6.5 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
