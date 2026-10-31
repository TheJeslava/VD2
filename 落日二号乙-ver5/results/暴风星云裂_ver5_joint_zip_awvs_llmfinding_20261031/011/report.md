# 落日二号乙漏洞挖掘报告 — 20261031-214100-39cf3e

- 生成时间：2026-10-31T13:42:04.780160+00:00
- 输入：`$WORKSPACE\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
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

本次审计对象为单文件 PHP 脚本 011.php（32 行），共交付 4 条已去重 findings，全部带 POC（4/4）。最高危为 LLM-c969ca7950b6：011.php 第 3 行接收的 username 参数在第 13 行附近直接拼接进 SQL 查询，可绕过登录认证并拖库（critical，HTTP POC 可复现）。其次为 SEM-bb3630458a80 登录接口缺少暴力破解防护（high，HTTP POC）。另有 SEM-2ea8df0ef3b9 口令使用 MD5 哈希（medium，注意其类型标注为 weak_crypto，但按 CWE-328 应归为 weak_hash，属静态证据类 POC，不能宣称可动态复现）与 LLM-996252269452 登录成功后 username 反射型 XSS（medium，HTTP POC）。未发现二次注入链。所有结论均为源码审计推断（llm_inferred / 规则命中），未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅有一个 PHP 文件 011.php（32 行），已完整审计。发现两条闭合链：(1) username 参数 SQL 注入（第 5→12→13 行），可绕过登录并拖库，置信度高；(2) 登录成功后 username 反射型 XSS（第 21 行），依赖 SQL 注入使分支可达，置信度中等。password 经 md5() 处理属 weak_hash（CWE-328），但单独不构成可利用链，仅作为修复建议提及，未单独立项。第 22 行 $avatar 来自数据库，若存在写入点可构成存储型 XSS，但代码包内无写入证据，未报告。未覆盖：无 php.ini/Web 服务器配置、无 composer 依赖、无路由与认证上下文，无法确认 011.php 是否公网暴露及 disable_functions 是否禁用相关函数；无数据库连接信息，SQL 注入可达性依赖运行时环境。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认暴露面与 disable_functions
- 无数据库连接与 users 表结构，UNION 列数需运行时确认
- 未显示 $html 的最终输出语句（echo/print），XSS 输出点依赖外层模板
- avatar 字段写入点不在代码包内，存储型 XSS 无法确认

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证并拖库）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.95`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行通过 $_GET['Login'] 触发登录分支，第 5 行直接取 $_GET['username'] 赋给 $user，未做任何转义/参数化；第 12 行把 $user 直接拼接进 SELECT 语句，第 13 行交给 mysqli_query 执行。password 虽经 md5() 处理（第 9 行），但 username 完全可控，攻击者可用 ' OR '1'='1 之类的 payload 改变 SQL 语法，绕过密码校验以任意用户（含管理员）身份登录，或用 UNION/布尔/报错注入读取 users 表全部数据。第 13 行的 die(mysqli_error(...)) 还会把数据库错误回显到页面，构成报错注入通道。

**source / sink**

- source：query `username`（011.php）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行拼接后的 SQL

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 检测到 GET 参数 Login 存在，进入登录处理分支 | 外部请求进入登录逻辑 |  |
| 2 | `011.php:5` | 直接把 $_GET['username'] 赋给 $user，无任何过滤或转义 | $user = 攻击者原始字符串 | 无 mysqli_real_escape_string、无预处理语句、无白名单 |
| 3 | `011.php:9` | password 被 md5() 处理，但 username 未处理，注入点仍在 username | $pass = md5(输入)，$user 保持原样 |  |
| 4 | `011.php:12` | 用单引号包裹 $user 拼进 SELECT 语句，攻击者可用单引号闭合 | $query = "SELECT * FROM `users` WHERE user = '<payload>' AND password = '<md5>';" | 字符串拼接构造 SQL，未参数化 |
| 5 | `011.php:13` | mysqli_query 执行被污染的 SQL；失败时 die 回显 mysqli_error，形成报错注入 | SQL 语法被攻击者改变并执行 |  |
| 6 | `011.php:15` | mysqli_num_rows($result)==1 成立即视为登录成功，返回用户 avatar 与欢迎信息 | 认证判定被注入结果操纵 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。源码 011.php:13 将 GET 参数 username 直接拼入 SQL 查询，未做参数化/转义。注入点为 query 参数 username，payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可绕过登录认证以任意用户身份进入受保护区域，并通过 UNION/报错注入读取 users 表全部账号密码哈希，进而横向接管账户；若数据库账号权限较高，还可进一步读取其他库数据。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 未经转义直接拼接进 SQL 并由 mysqli_query 执行，链路在单文件内闭合，无需认证即可触发，属于典型可申报 CVE 的注入漏洞。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param 或 PDO 参数绑定）；对 username 做类型与长度校验；关闭 die(mysqli_error()) 的错误回显，改为记录日志并返回通用错误；密码校验应使用 password_hash/password_verify 而非 md5。

**验证说明**

需动态确认：011.php 是否对外暴露、MySQL 是否允许 UNION/报错注入（版本与权限）、users 表列数以便调整 UNION payload；md5 密码字段长度需匹配。
模型 POC 要点：利用 username 参数闭合单引号，构造恒真条件绕过密码校验；或使用 UNION 读取 users 表数据。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于可交付代码 011.php:13，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原请求结构；仅补充基线/真/假三步对比。脚本为文本工件，需人工替换 TARGET 后手动执行，禁止自动运行。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 通过 isset($_GET['Login']) 进入登录流程，读取 username/password 并查询数据库，但代码中未见失败计数、账户锁定、验证码、延迟或速率限制。攻击者可对同一接口高频提交用户名/口令组合进行在线爆破。需说明：该结论基于源码静态观察，未做运行时验证；且由于 GEN-1a5cef9ca4a7 的 SQL 注入可绕过认证，爆破的实际必要性下降，但防护缺失本身仍成立。

**source / sink**

- source：query `Login`（011.php）
- sink：011.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /011（GET）的暴力破解防护缺失 POC。源码 011.php:3 处理登录逻辑，未见锁定/速率限制/验证码。注入点为 GET 参数 Login（触发按钮）及 username/password，payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/011?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-bb3630458a80`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可对弱口令账户进行在线口令猜测，导致账户接管；结合无锁定机制可长期持续尝试而不被阻断。

**CVE / CWE 论证**

CWE-307：认证接口缺少对过度认证尝试的限制；入口为公开 GET 参数 Login，无需认证即可反复调用，外部可达。

**修复建议**

引入失败计数与指数退避、账户/IP 维度限流、必要时验证码；登录失败返回统一提示避免用户名枚举；结合强口令策略与多因素认证。

**验证说明**

静态证据：入口 GET /011；source=query/Login；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET Login=1&username=...&password=... → 011.php:3 进入登录逻辑 → 011.php:12/13 查询校验 → 无任何限流/锁定，可无限次尝试。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。漏洞位于可交付代码 011.php:3，登录处理缺少防暴力破解机制。
POC 备注：保留原请求结构；补充基线/首次失败/重复失败三步。脚本为文本工件，需人工替换 TARGET 后手动执行，禁止自动循环爆破。

### F-3: 011.php 口令使用 MD5 哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 $_GET['password'] 读取口令，011.php:9 直接调用 md5($pass) 生成摘要，并在 011.php:12 的 SQL 中与数据库存储值比较。MD5 为快速、无盐、无迭代的弱哈希，用于口令存储/校验属不安全实现；攻击者获取数据库后可借助彩虹表或 GPU 高速碰撞还原口令。注意：此处是哈希算法强度问题（CWE-328），不是加密算法模式问题。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 finding：011.php:9 使用 md5() 对用户口令做哈希（$pass = md5($pass)）。MD5 属弱哈希算法，应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327）。无需发送请求，仅做源码审查。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 011.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2ea8df0ef3b9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令摘要可被离线快速破解，导致用户口令泄露；若用户跨系统复用口令，可进一步横向利用。

**CVE / CWE 论证**

CWE-328：MD5 被用于口令等安全用途，算法本身抗碰撞与抗暴力能力不足；该弱点为代码实现型，无需 HTTP 污点链即可成立，证据为 011.php:9 的 md5( $pass ) 原文。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）生成带盐慢哈希，校验用 password_verify()；迁移期可对旧 MD5 值做一次重哈希升级；禁止在 SQL 中直接比较明文或裸 MD5。

**验证说明**

静态证据：入口 GET /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password → 011.php:8 $pass → 011.php:9 md5($pass) → 011.php:12 拼入 SQL 比较；弱哈希使存储口令易被离线破解。
POC 备注：纯静态证据，无 HTTP 请求；类型应从 weak_crypto 更正为 weak_hash。

### F-4: 011.php 登录成功后 username 反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:21-22`
- **来源**：`llm_finding`

**描述**

登录成功后，第 21 行把 $user（来自 $_GET['username']，第 5 行）直接插入 HTML 字符串 $html 并输出，未做 htmlspecialchars 等编码。虽然要走到该分支需先通过第 15 行的 mysqli_num_rows==1 判定，但结合上面的 SQL 注入（username 用 ' OR '1'='1 使查询返回行），攻击者可让 $user 携带 HTML/JS 片段并被原样渲染，形成反射型 XSS。第 22 行 $avatar 来自数据库，若 avatar 字段可被写入也可形成存储型 XSS，但当前代码包无法确认写入点。

**source / sink**

- source：query `username`（011.php）
- sink：011.php:22 $html 输出到响应页面（未编码）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | $_GET['username'] 赋给 $user，无编码 | $user = 攻击者 HTML/JS 片段 |  |
| 2 | `011.php:12` | $user 拼入 SQL，配合注入使查询返回行 | SQL 被注入，结果集非空 | 利用 SQL 注入绕过登录判定 |
| 3 | `011.php:15` | mysqli_num_rows==1 成立，进入成功分支 | 进入 XSS 输出路径 |  |
| 4 | `011.php:21` | $user 原样拼进 <p> 标签输出 | HTML 中嵌入未编码的用户输入 | 无 htmlspecialchars 编码 |

**POC**

针对 /011.php（GET）的反射型 XSS POC。源码 011.php:22 将 GET 参数 username 未编码输出到响应，注入点为 query 参数 username，payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-996252269452`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可在受害者浏览器执行任意 JS，窃取会话/凭据或发起 CSRF 操作；若管理员访问该链接可导致后台被操控。

**CVE / CWE 论证**

CWE-79 反射型 XSS。username 未编码输出到 HTML，链路依赖 SQL 注入使登录分支可达，整体在单文件内闭合。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；对 avatar 做 URL/属性编码校验；修复 SQL 注入以消除前置条件。

**验证说明**

需确认成功分支确实输出 $html（代码包未显示 echo，可能由外层模板输出）；需确认 SQL 注入可用以进入该分支。
模型 POC 要点：用 SQL 注入使登录判定通过，同时在 username 中注入脚本。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于可交付代码 011.php:22，外部输入来自 query 参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原请求结构；补充基线/攻击/对比三步。脚本为文本工件，需人工替换 TARGET 后手动执行。

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
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.92 | 是 |
| surface_mapper | 攻击面测绘 | 8.04 | 是 |
| deep_finder | LLM 深挖 | 15.3 | 是 |
| candidate_screener | 候选筛选 | 8.07 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.8 | 是 |
| coordinator | 管线协调 | 6.43 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
