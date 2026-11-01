# 落日二号乙漏洞挖掘报告 — 20261030-224810-565c95

- 生成时间：2026-10-30T14:48:54.571387+00:00
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

本次汇总基于单文件 PHP 脚本 024.php（37 行）的源码审计结果，共交付 2 条高危发现，均带 POC 文本（静态构造，未执行、未动态验证）。最高危的是 024.php 第 19 行密码修改 UPDATE 语句中 $current_user 未转义直接拼接导致的 SQL 注入（LLM-166d7112dfbf），可导致任意 SQL 语义执行；同一行附近还存在仅依赖 HTTP_REFERER 校验的鉴权/信任边界缺陷（LLM-0441c3f5ab3e），伪造 Referer 即可绕过并修改当前用户密码，二者可组合利用。POC 齐全度为 2/2，但均为文本工件，SQL 注入 POC 使用 TARGET 占位且不含破坏性语句，auth_bypass POC 依赖伪造请求头，均需在授权环境人工复现确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 CODE PACK 中唯一文件 024.php（1-37 行）。确认一条闭合链：密码修改功能仅用可伪造的 HTTP_REFERER 做来源校验（第 5 行），无 CSRF token、无旧密码校验，攻击者可伪造 Referer 修改当前用户密码，构成认证绕过/CSRF（高危，置信度 0.85）。另发现第 18 行 $current_user 未转义拼接进 UPDATE 语句，但 dvwaCurrentUser() 实现不在 CODE PACK，无法确认可控性，作为低置信候选（0.6）上报。password_new 在第 13 行已 mysqli_real_escape_string 且第 14 行 md5，不构成注入。第 14 行使用 md5 属 weak_hash（CWE-328），但仅用于密码存储且无进一步利用链，未单独立项。未发现命令执行、文件包含、SSRF、反序列化、XSS 回显（$html 仅输出固定文案）等其它闭合链。配置型候选（weak_random/insecure_cookie/hardcoded_secret/trust_boundary）在 37 行内未见相关调用。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现不在 CODE PACK，SQL 注入链未闭合
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、open_basedir 等
- 无端点/路由与认证信息，无法确认 024.php 实际访问路径与前置防护
- 无数据库 schema，SQL 注入最终影响面无法评估

## 3. Findings

### F-1: DVWA 密码修改功能仅依赖 HTTP_REFERER 校验，可伪造 Referer 绕过并任意修改当前用户密码（CSRF/信任边界缺陷）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 的密码修改逻辑（第 3-35 行）在修改密码前只做了一次来源校验：第 5 行用 stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false 判断请求是否来自本站。HTTP_REFERER 完全由客户端控制，攻击者只要在请求头中带上包含本站域名的 Referer 即可通过校验。校验通过后第 7-8 行直接读取 $_GET['password_new'] / $_GET['password_conf']，第 11 行比较相等后第 13 行做 mysqli_real_escape_string、第 14 行 md5 哈希，第 18 行拼接 UPDATE 语句、第 19 行执行，把当前用户（第 17 行 dvwaCurrentUser()）的密码改为攻击者指定值。由于没有 CSRF token、没有二次身份确认（旧密码），攻击者可构造恶意页面诱导已登录用户提交，或直接伪造 Referer 自行提交，实现账户接管。

**source / sink**

- source：header `Referer`（024.php:7-8）
- sink：024.php:19 第 19 行 mysqli_query 执行第 18 行拼接的 UPDATE users SET password=... 语句

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 检测到 GET 参数 Change 存在即进入密码修改分支 | 攻击者控制是否进入分支 |  |
| 2 | `024.php:5` | 用 stripos 判断 HTTP_REFERER 是否包含 SERVER_NAME，作为唯一来源校验 | Referer 头原样参与字符串匹配 | HTTP_REFERER 由客户端完全控制，只要包含本站域名（如 http://TARGET/）即返回非 false，校验形同虚设；且无 CSRF token |
| 3 | `024.php:7-8` | 读取 password_new / password_conf 参数 | 攻击者可控字符串 |  |
| 4 | `024.php:11` | 比较两次输入是否相等 | 相等则继续 |  |
| 5 | `024.php:13-14` | mysqli_real_escape_string 转义后 md5 哈希 | 转义并哈希后的密码 |  |
| 6 | `024.php:17-19` | 取当前用户并拼接 UPDATE 语句执行，修改密码 | 写入数据库的最终密码哈希 |  |

**POC**

针对 /024.php（GET）的认证绕过 POC。注入点为请求头 Referer，payload 使用 TARGET 占位符；仅限授权测试，POC 为文本工件，不执行。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php' \
  -H 'Referer: admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-0441c3f5ab3e`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可绕过来源校验修改任意已登录用户（含管理员）的密码，实现账户接管；结合 CSRF 可诱导管理员在不知情下改密。

**CVE / CWE 论证**

CWE-290 认证绕过（依赖可伪造的 Referer 头）/ CWE-352 CSRF。外部可达，无需旧密码，链闭合：Referer 伪造 → 参数读取 → UPDATE 执行。

**修复建议**

移除基于 Referer 的校验；引入 CSRF token 并在服务端校验；修改密码前要求验证旧密码；对 password_new 使用参数化查询（prepared statement）而非字符串拼接。

**验证说明**

需确认 dvwaCurrentUser() 的实现与登录态绑定方式；需确认部署环境是否强制校验 Referer（一般不会）。
模型 POC 要点：伪造 Referer 头指向本站，提交 Change=Change 与两次相同的新密码，即可把当前登录用户密码改为攻击者指定值。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-287。漏洞位于可交付代码 024.php:19，外部输入来自请求头 Referer，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；poc.sh 仅为文本，需人工替换 TARGET 后手动执行，管线不执行、不联网。

### F-2: 024.php 密码修改 UPDATE 语句中 $current_user 未转义直接拼接导致 SQL 注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:17-19`
- **来源**：`llm_finding`

**描述**

第 18 行将 $current_user（来自第 17 行 dvwaCurrentUser()）直接拼进 UPDATE 语句，未做任何转义或参数化；第 19 行 mysqli_query 执行。虽然 password_new 在第 13 行经过 mysqli_real_escape_string，但 $current_user 完全没有处理。若 dvwaCurrentUser() 的返回值可受攻击者影响（例如来源于会话中的用户名、Cookie 或可注册的用户名），则可注入任意 SQL。该链的闭合依赖 dvwaCurrentUser() 的实现，而该函数不在 CODE PACK 中，因此作为候选上报并标注需人工确认。

**source / sink**

- source：session `*`（024.php:17）
- sink：024.php:19 第 19 行 mysqli_query 执行拼接后的 UPDATE 语句

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:17` | 获取当前用户名 | 字符串，来源未在 CODE PACK 中展示 |  |
| 2 | `024.php:18` | 将 $current_user 直接拼入 SQL，无转义 | 未净化字符串进入 SQL |  |
| 3 | `024.php:19` | mysqli_query 执行 | 最终 SQL 语句 |  |

**POC**

针对 /024.php（GET）的 SQL 注入 POC。注入点为 GET 参数 param，payload 使用 TARGET 占位符；仅限授权测试，POC 为文本工件，不执行。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?param=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-166d7112dfbf`
- 执行状态：未执行（`executed=False`）

**影响**

潜在可篡改任意用户密码或读取数据库信息。

**CVE / CWE 论证**

CWE-89。但 $current_user 来源未在 CODE PACK 中闭合，属推断，置信度较低。

**修复建议**

对 $current_user 同样使用 mysqli_real_escape_string 或改用参数化查询。

**验证说明**

关键缺口：dvwaCurrentUser() 实现不在 CODE PACK，无法确认其返回值是否可被攻击者控制；若其来源于服务端会话且不可控，则不构成注入。
模型 POC 要点：若 dvwaCurrentUser() 返回可控用户名（如注册时含单引号），可在 WHERE 子句注入。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-89。漏洞位于可交付代码 024.php:19，外部输入来自 GET 参数 param，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；poc.sh 仅为文本，需人工替换 TARGET 后手动执行，管线不执行、不联网。request.http 中 Content-Length 与 GET 无 body 不一致，实际以 URL 查询串为准。

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
| safety_guard | 安全防护 | 4.27 | 是 |
| surface_mapper | 攻击面测绘 | 9.39 | 是 |
| deep_finder | LLM 深挖 | 13.68 | 是 |
| candidate_screener | 候选筛选 | 5.38 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.3 | 是 |
| coordinator | 管线协调 | 6.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
