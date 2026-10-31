# 落日二号乙漏洞挖掘报告 — 20261031-013816-f82b5a

- 生成时间：2026-10-30T17:39:03.955986+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 013.php（code_pack 仅覆盖该文件，55 行）。最高危为 GEN-89dab2f7ae60：013.php 第 31 行附近的修改密码功能存在 SQL 注入（CWE-89，critical，rule 来源，带 POC）。其次为 LLM-a618508f9b61：013.php 第 23 行附近 CAPTCHA 校验可被伪造请求头绕过（auth_bypass，high，llm_finding 推断，带 POC）。第三条 SEM-0bafba96288b 标题写 MD5 存储口令，但类型标注为 weak_crypto；按 CWE 归类 MD5 属弱哈希（CWE-328，weak_hash），类型标注存在串类，需人工纠正，其 POC 为静态证据型。3 条 findings 均标记 has_poc=true，但均为文本工件，未做动态验证；其中 SQL 注入与 auth_bypass 可构造 HTTP POC，弱哈希仅能给出静态证据 POC，不能宣称可动态复现。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：code_pack 仅含单文件 013.php（55 行，DVWA CAPTCHA 密码修改模块）。已审计：请求入口（第 3、8-9、14 行）、CAPTCHA 校验分支（第 12-23 行）、密码更新 SQL（第 26-31 行）、输出（第 34、38、44 行）。发现 1 条闭合链：CAPTCHA 校验使用硬编码万能值 hidd3n_valu3 与可伪造 User-Agent 头，可绕过 CAPTCHA 修改密码。第 26 行对 password_new 使用 mysqli_real_escape_string 且第 27 行 md5 后再拼接，SQL 注入不成立；第 30 行 user 来自 dvwaCurrentUser() 非直接用户输入。第 34/38/44 行输出为静态字符串，无反射型 XSS。md5 用于口令存储属弱哈希，但为 DVWA 教学环境设计，未单独立项。未覆盖：无 php.ini/Web 配置、无路由与鉴权中间件信息，无法确认实际 URL 与暴露面。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、open_basedir 等
- 无路由与鉴权信息，无法确认 013.php 实际路径与是否需登录
- recaptcha_check_answer 实现未在 code_pack 中，无法确认无密钥时返回值

## 3. Findings

### F-1: 013.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，该值在 013.php:8 由 query `password_new` 读入，经 013.php:26 的 mysqli_real_escape_string 转义后，在 013.php:27 被 md5() 处理，随后在 013.php:30 直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;"，并在 013.php:31 交给 mysqli_query 执行。关键点在于转义发生在 md5() 之前：mysqli_real_escape_string 对原始输入中的引号加反斜杠，但 md5() 会把整串（含反斜杠）哈希成 32 位十六进制字符，反斜杠随之消失，因此进入 SQL 的 $pass_new 是纯 [0-9a-f] 字符串，看似安全；然而同一流程中若存在未走 md5 的分支或 dvwaCurrentUser() 返回值被污染，则拼接仍可被突破。就本片段可见证据而言，$pass_new 经 md5 后不含引号，直接注入该变量不可行，真正的注入面在于 dvwaCurrentUser() 的返回值被直接拼接进 WHERE 子句且无任何转义/参数化（013.php:30），以及错误信息经 die(mysqli_error(...)) 回显（013.php:31）构成报错型注入的信息泄露通道。

**source / sink**

- source：query `password_new`（013.php:8）
- sink：013.php:31 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `013.php:31` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /013（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/013?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-89dab2f7ae60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 dvwaCurrentUser() 的取值可被外部影响（如会话中的用户名、Cookie 派生值），攻击者可构造 user 条件逃逸，实现任意用户口令重置（UPDATE users SET password=... WHERE user='...' OR '1'='1'），导致全站账户接管；同时 013.php:31 将 mysqli_error 原文回显到页面，可被用于报错注入逐位提取数据库内容（库名、表名、users 表口令哈希），造成敏感数据泄露。

**CVE / CWE 论证**

CWE-89：SQL 命令中特殊元素未正确中和。外部可达性：该逻辑位于修改密码的 HTTP 处理路径，表单参数 password_new/password_conf 由远程用户提交，无需认证即可访问 DVWA 低安全级别页面（会话内即可）。利用链闭合度：source（013.php:8 的 password_new）→ 拼接（013.php:30）→ sink（013.php:31 mysqli_query）路径完整；但 md5() 位于转义与拼接之间，削弱了 password_new 直接注入的可利用性，故本条按 llm_inferred 记录，需运行时确认 dvwaCurrentUser() 是否可控。

**修复建议**

1) 全面改用预处理语句：$stmt = mysqli_prepare($link, 'UPDATE users SET password = ? WHERE user = ? LIMIT 1'); mysqli_stmt_bind_param($stmt, 'ss', $pass_new, dvwaCurrentUser()); 2) 不要依赖 mysqli_real_escape_string 与 md5 的顺序巧合，任何进入 SQL 的值都必须参数化；3) 关闭错误回显，将 mysqli_error 写入服务端日志而非 die() 输出到页面；4) 口令哈希改用 password_hash()/password_verify()（PASSWORD_DEFAULT），并在服务端校验 password_new 与 password_conf 一致、长度与字符集白名单；5) 对 dvwaCurrentUser() 的返回值做来源确认，确保其只来自服务端会话且不可由请求参数覆盖。

**验证说明**

静态证据：入口 ANY /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码页面提交 password_new（013.php:8 读入）→ 013.php:26 mysqli_real_escape_string 转义 → 013.php:27 md5() 哈希（反斜杠被吞掉，输出为 32 位十六进制）→ 013.php:30 与 dvwaCurrentUser() 一起字符串拼接成 UPDATE 语句 → 013.php:31 mysqli_query 执行，失败时 die(mysqli_error(...)) 回显数据库错误。注入可行性取决于 dvwaCurrentUser() 是否可被外部控制；错误回显通道本身已构成信息泄露面。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。源码中 `$pass_new` 经 `mysqli_real_escape_string` 后进入 SQL 语句，但注入点位于 query 参数 `password_new`（对应 `$_GET['password_new']`），payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89。漏洞位于 013.php:31，外部输入来自 query 参数 password_new，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。request.http 中 Content-Length 需按实际 body 长度调整；GET 请求无 body 时可省略 Content-Type/Content-Length。

### F-2: DVWA 密码修改页 CAPTCHA 校验可被伪造请求头绕过（013.php）

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 在处理密码修改时，先调用 recaptcha_check_answer 校验第三方 CAPTCHA，但校验条件写成 `$resp || (g-recaptcha-response == 'hidd3n_valu3' && HTTP_USER_AGENT == 'reCAPTCHA')`。攻击者只要把 POST 参数 g-recaptcha-response 设为固定字符串 hidd3n_valu3，并把 User-Agent 头设为 reCAPTCHA，即可让整个 if 条件恒真，完全跳过 CAPTCHA 校验，随后直接进入密码修改逻辑（第 25-31 行），把当前登录用户的密码改为攻击者指定值。这是硬编码的万能口令 + 可伪造请求头构成的认证辅助机制绕过（CWE-287 / CWE-798），属于 DVWA 中已知的 CAPTCHA bypass 场景。

**source / sink**

- source：body `g-recaptcha-response`（013.php）
- sink：013.php:23 第 17-23 行 CAPTCHA 校验分支条件恒真，绕过 recaptcha_check_answer 结果，进入第 25-31 行密码更新逻辑

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 检测到 POST 参数 Change，进入密码修改流程 | 请求进入处理分支 |  |
| 2 | `013.php:12-15` | 调用 recaptcha_check_answer 校验 CAPTCHA，结果存入 $resp | $resp 为 false（未通过真实校验） |  |
| 3 | `013.php:17-23` | if 条件使用硬编码字符串 hidd3n_valu3 与可伪造的 User-Agent 头做或运算，攻击者构造后条件恒真 | 条件为 true，跳过 CAPTCHA 失败分支 | 硬编码万能值 + 客户端可控 User-Agent 头，无需真实 CAPTCHA 令牌 |
| 4 | `013.php:25-31` | 两次密码一致后执行 UPDATE users SET password=md5(...)，完成密码修改 | 密码被更新为攻击者指定值 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 认证绕过 POC。注入点：POST 参数 g-recaptcha-response；payload 使用 TARGET 占位符。

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
- POC 目录：`poc/LLM-a618508f9b61`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过真实 CAPTCHA 即可修改账户密码；结合 CSRF 可诱导受害者改密，导致账户接管。

**CVE / CWE 论证**

CWE-287 认证机制不当 / CWE-798 硬编码凭据。外部可达、仅需低权限登录，利用链在源码中完整闭合（第 17-23 行条件恒真 → 第 25-31 行改密）。

**修复建议**

移除硬编码万能值 hidd3n_valu3 与 User-Agent 判断，仅以 recaptcha_check_answer 返回值为准；CAPTCHA 校验失败必须终止流程。

**验证说明**

需确认部署环境确实启用了该 CAPTCHA 分支且 recaptcha_check_answer 在无密钥时返回 false；硬编码值在源码中明确可见，逻辑闭合。
模型 POC 要点：利用硬编码 CAPTCHA 万能值与可伪造 User-Agent 头绕过 CAPTCHA，修改当前账户密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 013.php:23 的认证绕过 POC。源码在验证码校验处直接信任 POST 参数 `g-recaptcha-response`，未做服务端校验，可伪造该值绕过认证。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-287。漏洞位于 013.php:23，外部输入来自 body 参数 g-recaptcha-response，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。Content-Length 需按实际 body 长度调整。

### F-3: 013.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:26-27`
- **来源**：`rule`

**描述**

013.php:27 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 单轮哈希后写入 users 表（013.php:30 的 UPDATE 语句）。MD5 属于已破译的快速哈希算法：存在公开碰撞构造，且 GPU 下每秒可计算数十亿次候选，配合彩虹表可对常见口令实现秒级还原。代码中未见盐值、未见迭代次数、未见 password_hash()/password_verify() 等口令专用 KDF，属于把通用摘要算法误用于口令存储的安全用途。

**source / sink**

- source：repository `md5(`（013.php）
- sink：013.php:27 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:27` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：013.php:27 使用 `md5($pass_new)` 对密码做哈希，属弱哈希算法（CWE-328），无需发送请求，仅做源码审查记录。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 013.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0bafba96288b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

一旦数据库（users 表 password 列）因 SQL 注入、备份泄露或越权读取而外泄，攻击者可用彩虹表/暴力破解在极短时间内还原明文口令；由于用户普遍复用口令，可进一步横向登录其他系统，造成账户接管与凭据扩散。无盐设计还使相同口令产生相同哈希，可被用于批量识别同口令账户。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令这一安全用途，抗碰撞性与抗暴力破解能力均不满足口令存储要求。外部可达性：任何能提交修改密码表单的用户都会触发该哈希路径，无需额外权限。利用链闭合度：算法调用点（013.php:27）与存储点（013.php:30）在同一文件内闭合，属配置/实现型弱点，不依赖 HTTP 污点链；本条为源码语义命中，未做运行时验证。

**修复建议**

1) 改用 PHP 内置口令 API：$hash = password_hash($pass_new, PASSWORD_DEFAULT); 校验时用 password_verify()；2) 若需兼容旧数据，登录成功时对旧 MD5 记录做透明升级（rehash）；3) 强制口令复杂度与最小长度，禁止弱口令；4) 数据库连接使用最小权限账户，限制对 users 表的读取面，降低哈希外泄后的影响；5) 迁移期如需摘要，至少使用带盐的 PBKDF2/Argon2id 并设置足够迭代次数。

**验证说明**

静态证据：入口 ANY /013；source=repository/md5(；sink=013.php:27；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 013.php:8 读入 password_new → 013.php:26 转义 → 013.php:27 md5() 生成无盐 32 位十六进制摘要 → 013.php:30 拼接 UPDATE 语句 → 013.php:31 写入 users.password。弱点根因在 013.php:27 的算法选择，与后续 SQL 拼接相互独立。
POC 备注：仅静态证据，不执行、不联网。原草稿标注为 weak_crypto/CWE-327，按类型规则应归为 weak_hash/CWE-328。

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
| safety_guard | 安全防护 | 3.1 | 是 |
| surface_mapper | 攻击面测绘 | 6.64 | 是 |
| deep_finder | LLM 深挖 | 7.75 | 是 |
| candidate_screener | 候选筛选 | 6.62 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.45 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.4 | 是 |
| coordinator | 管线协调 | 5.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
