# 落日二号乙漏洞挖掘报告 — 20261031-011508-27a460

- 生成时间：2026-10-30T17:16:10.495146+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
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

本次审计范围仅覆盖单文件 PHP 脚本 011.php（32 行），共交付 4 条已去重 findings，全部带 POC（4/4）。最高危为 LLM-c969ca7950b6：011.php 第 3 行取参的 username 直接进入登录 SQL 拼接（line_end=13），可绕过认证，严重度 critical，属 HTTP 可复现类 POC。其次为 SEM-bb3630458a80 登录接口缺少暴力破解防护（high，CWE-307），POC 为请求序列文本，属 HTTP 类。SEM-2ea8df0ef3b9 标注为 weak_crypto 但标题与描述实为 MD5 口令存储/比对，按类型规范应归 weak_hash（CWE-328），仅有静态证据 POC，不能宣称可动态复现。LLM-996252269452 为登录成功页 username 反射型 XSS（medium），HTTP POC 存在。整体污点面窄（source 位于 011.php:3，sink 热点 1 处），但配置/实现类弱点与信任边界问题无法仅凭清单排除。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 011.php（32 行），已逐行审计。确认两条闭合链：(1) 第 5 行 $_GET['username'] 未转义直达第 12/13 行 mysqli_query，构成 SQL 注入，可绕过登录并导出数据（critical）；(2) 第 21 行 $user 未 HTML 编码反射输出，构成反射型 XSS（medium，依赖登录成功分支）。password 经 md5() 处理为固定长度十六进制，不可注入；md5 用于口令存储属 weak_hash（CWE-328），但无独立可利用链，仅作线索记录于 gaps。未发现命令执行、文件包含、反序列化、SSRF、Cookie 标志或硬编码密钥证据。输入中未出现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- password 使用 md5() 存储属弱哈希（CWE-328），但无独立可利用链，未单独立项
- 无 php.ini/Web 服务器配置，无法判断 display_errors、WAF 等影响利用条件的环境项
- 无端点/路由清单，无法确认该脚本是否被其他页面 include 或存在前置认证
- 无依赖清单，无法评估第三方库 CVE
- 未发现 setcookie/session 配置，insecure_cookie 无法确认
- 未发现 rand/mt_rand 或加密实现，weak_random/weak_crypto 无法确认

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行以 $_GET['Login'] 存在为条件进入登录逻辑，第 5 行直接取 $_GET['username'] 赋给 $user，未做任何转义/参数化；第 12 行将 $user 直接拼接进 SELECT 语句，第 13 行通过 mysqli_query 执行。攻击者可在 username 中注入 SQL 语法（如 ' OR '1'='1' -- -）改变查询语义，绕过密码校验以任意用户（含管理员）身份登录，或通过 UNION/布尔盲注读取 users 表全部数据。password 虽经 md5() 处理，但 md5 输出为固定 32 位十六进制，无法注入，故注入点唯一为 username。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行拼接后的 SQL

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 判断 $_GET['Login'] 是否存在，存在即进入登录分支，无认证前置 | 攻击者控制请求参数存在性 |  |
| 2 | `011.php:5` | 直接读取 $_GET['username'] 赋给 $user，无 trim/转义/白名单 | 原始攻击者字符串 |  |
| 3 | `011.php:12` | 将 $user 用单引号包裹拼入 SELECT 语句，未使用预处理或 mysqli_real_escape_string | 注入 payload 进入 SQL 语法层 |  |
| 4 | `011.php:13` | mysqli_query 执行拼接语句，返回结果集 | SQL 语句被执行 |  |
| 5 | `011.php:15` | mysqli_num_rows($result)==1 成立即视为登录成功，输出欢迎信息与 avatar | 认证判定被注入结果操纵 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username（源码 011.php:13 将外部输入拼入 SQL 查询），payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可直接绕过登录认证进入受保护区域，并可进一步通过 UNION/盲注导出 users 表全部账号与口令哈希，导致账户接管与数据泄露。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 未经任何转义直达 mysqli_query，链路在 CODE PACK 内完整闭合，无需认证，利用门槛极低，符合 CVE/赏金平台接收标准。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param）绑定 username/password；或至少对 $user 使用 mysqli_real_escape_string 并配合白名单校验；同时避免将数据库错误信息直接输出到页面。

**验证说明**

需动态确认 users 表存在记录以使恒真条件返回行；UNION 列数需按实际表结构调整；需确认无 WAF 拦截单引号。
模型 POC 要点：利用 username 注入恒真条件使查询返回一行，绕过密码校验登录；或使用 UNION 读取数据
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于 011.php:13，外部输入来自 GET 参数 username，source→sink 链在给定代码中静态闭合，未见有效参数化或转义；具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；建议先做真/假布尔对照再判定，避免把缓存差异误判为注入。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 通过 `isset($_GET['Login'])` 进入登录流程，读取 `username`/`password` 后直接查询数据库并返回结果。代码中未见失败计数、账户锁定、验证码、延迟或速率限制逻辑，攻击者可对同一账户无限次提交口令猜测。证据为 011.php:2-3 的登录入口判断及后续无任何限流代码；该结论为基于源码的推断，未做运行时验证。

**source / sink**

- source：request `login/password`（011.php）
- sink：011.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /011（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/011?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-bb3630458a80`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可对已知用户名进行在线口令爆破或撞库，最终获得账户访问权限；结合本文件的口令以 MD5 存储（011.php:9），一旦数据库泄露可进一步离线破解。

**CVE / CWE 论证**

CWE-307（对过度认证尝试缺乏防护）。外部可达性：登录入口 011.php:3 无需认证。利用链：重复 GET 请求携带不同 `password` 即可持续尝试，源码中无任何阻断点。证据等级为推断，需授权环境实测确认无上游 WAF/限流。

**修复建议**

在服务端实现按账户与按 IP 的失败计数与指数退避、临时锁定；引入验证码或二次验证；记录并告警异常登录；对登录响应时间做恒定化处理以减少时序侧信道。

**验证说明**

静态证据：入口 ANY /011；source=request/login/password；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环发送 `011.php?Login=1&username=admin&password=<猜测>`，011.php:3 每次均进入登录逻辑，011.php:12-13 执行查询并返回成功/失败，无计数或锁定，攻击者可无限次尝试直至命中。
PocWriter 建议（未采纳，缺少端点 /011）：暴力破解防护缺失的静态/半静态证据 POC：011.php:3 附近存在登录/口令处理逻辑，未见失败次数限制、锁定或速率限制。原草稿中的参数名 login/password 与源码取值方式不一致，需以实际参数名为准（源码 011.php:8 使用 $_GET['password']）。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。证据位于 011.php:3 附近登录逻辑，缺少失败计数/锁定/限速；需结合部署确认实际暴露面。
POC 备注：仅文本工件，不执行、不联网。原草稿参数 login/password 与源码 $_GET['password'] 不符，已按源码修正为 password；请勿对生产环境做高频请求。

### F-3: 011.php 使用 MD5 存储/比对口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 GET 参数 `password` 读取明文口令，011.php:9 调用 `md5($pass)` 生成摘要，随后在 011.php:12 的 SQL 中与数据库 `password` 字段比对。MD5 为快速、无盐、可碰撞的哈希算法，用于口令等安全用途时无法抵抗离线暴力破解与彩虹表攻击。此处为配置/实现型弱点，不依赖 HTTP 污点链，证据为 011.php:9 的 `md5(` 调用原文。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：011.php:9 使用 md5() 对用户口令做哈希（011.php:8 从 $_GET['password'] 取值），属弱哈希算法使用，无需发送请求即可在源码层确认。

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

若数据库泄露，攻击者可用彩虹表或 GPU 高速爆破在极短时间内还原用户明文口令；相同口令产生相同摘要，便于批量撞库与横向移动。注意：该弱点本身不直接导致 RCE，但会放大凭据泄露后果。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。外部可达性：登录接口 011.php:3 无需认证即可触发哈希计算路径。利用链：011.php:8 取明文 → 011.php:9 `md5()` → 011.php:12 与库中摘要比对，属口令安全用途，符合 weak_hash 判定边界（非 CWE-327 加密算法问题）。

**修复建议**

改用专为口令设计的慢哈希算法，如 `password_hash()`（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）并配合 `password_verify()`；为每个口令使用独立随机盐；迁移期可对旧 MD5 摘要做二次加盐哈希；强制口令复杂度与长度策略。

**验证说明**

静态证据：入口 ANY /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 `password` → 011.php:8 赋值 `$pass` → 011.php:9 `md5($pass)` 生成无盐摘要 → 011.php:12 拼接进 SQL 与 `users.password` 比对。攻击者获取数据库后对 MD5 摘要做离线破解即可还原口令。
POC 备注：纯静态证据，不执行任何命令。原草稿中的 grep 命令仅作说明用途，管线不运行。

### F-4: 011.php 登录成功页 username 反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:21-22`
- **来源**：`llm_finding`

**描述**

第 21 行将 $user（来自 $_GET['username']，第 5 行未做 HTML 编码）直接拼入 $html 输出到页面：$html .= "<p>Welcome to the password protected area {$user}</p>"。虽然进入该分支需登录成功（依赖 SQL 注入或有效凭据），但一旦通过注入恒真条件使查询返回行，攻击者可控的 username 会原样反射到 HTML，形成反射型 XSS，可用于钓鱼或结合社工窃取会话。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:22 $html 输出到响应页面（未编码）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | 读取 $_GET['username'] 赋给 $user，无 HTML 编码 | 原始攻击者字符串 |  |
| 2 | `011.php:15` | 借助 SQL 注入恒真条件使 mysqli_num_rows==1 成立，进入成功分支 | 条件被注入操纵为真 | 通过 username 注入 ' OR '1'='1' -- - 绕过密码校验 |
| 3 | `011.php:21` | $user 直接插入 <p> 标签输出，未 htmlspecialchars | payload 作为 HTML 进入响应 |  |

**POC**

针对 /011.php（GET）的反射型 XSS POC。注入点为 GET 参数 username（源码 011.php:22 将输入输出到响应且未编码），payload 使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS，可在受害者浏览器执行任意脚本，窃取 Cookie/会话或进行钓鱼，需结合注入或有效凭据触发。

**CVE / CWE 论证**

CWE-79。username 未编码直达 HTML 输出，链路在 CODE PACK 内闭合，但触发依赖登录成功分支，故定为 medium。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；avatar 同样需编码并校验来源。

**验证说明**

需确认成功分支可达（依赖注入或有效凭据）；需确认响应未设置 CSP 等缓解措施。
模型 POC 要点：结合 SQL 注入使登录成功，并在 username 中携带 XSS payload 反射执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于 011.php:22，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效输出编码；具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。验证时优先用无害 alert(document.domain)，避免使用会外发数据的 payload。

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
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 5.51 | 是 |
| surface_mapper | 攻击面测绘 | 8.52 | 是 |
| deep_finder | LLM 深挖 | 12.44 | 是 |
| candidate_screener | 候选筛选 | 4.71 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.55 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.54 | 是 |
| coordinator | 管线协调 | 6.75 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
