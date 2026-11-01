# 落日二号乙漏洞挖掘报告 — 20261031-013729-5e9b35

- 生成时间：2026-10-30T17:38:30.273470+00:00
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

本次汇总基于单文件 PHP 脚本 011.php（32 行）的静态源码审计，共交付 4 条已去重 findings，全部带 POC 文本（4/4）。最高危为 LLM-c969ca7950b6：011.php 第 3 行读取的 username 参数未经参数化直接进入 SQL 查询（第 13 行附近），可绕过登录认证，严重度 critical，属 HTTP 可复现类 POC。其余为 SEM-bb3630458a80 登录接口缺少暴力破解防护（high，HTTP POC）、SEM-2ea8df0ef3b9 使用 MD5 处理口令（medium，注意其类型标注为 weak_crypto，但按 CWE-328 应归为 weak_hash，仅静态证据 POC，不可宣称动态复现）、LLM-996252269452 登录成功页 username 反射型 XSS（medium，HTTP POC）。本次未收到二次注入链输入，故不涉及存储写点/读点/汇点三元组结论。所有结论均为静态推断（llm_inferred / rule），未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 011.php（1-32 行，完整展示）。确认一条闭合的 SQL 注入链：GET 参数 username 在 011.php:5 读取，011.php:12 直接拼接进 SELECT，011.php:13 由 mysqli_query 执行，且 die(mysqli_error) 回显错误，可未授权绕过登录并读取任意数据。同时发现 username 在 011.php:21 未编码输出，构成反射型 XSS（成功分支可借 SQL 注入保证命中）。password 参数经 md5 后拼接，虽不可直接注入但 md5 属弱哈希，仅作线索不单独立项。未发现命令执行、文件包含、反序列化、SSRF 等汇点；无 setcookie/session_start，故 insecure_cookie 无证据；无 rand/mt_rand、无硬编码密钥。输入中未出现 prompt_injection 诱导文本。未覆盖范围：无 composer 依赖、无 Web 服务器/php.ini 配置、无部署暴露面信息，实际可利用性（错误回显是否开启、表结构列数）需动态确认。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 display_errors 与错误回显
- 无 users 表结构，UNION 列数需实测
- 无部署信息，无法确认公网可达性与前置鉴权/WAF
- 无依赖清单，无法评估第三方库 CVE

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

脚本在 `isset($_GET['Login'])` 成立时，直接读取 `$_GET['username']` 与 `$_GET['password']`，仅对 password 做 md5，username 未做任何转义或参数化，直接以单引号拼接进 SELECT 语句，随后交给 mysqli_query 执行。攻击者可在 username 中注入 SQL 语法，构造恒真条件绕过密码校验，或使用 UNION 读取任意表数据。查询失败时 mysqli_error 被 die() 直接回显，构成报错型注入，便于快速提取数据。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)（011.php:13）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 判断 GET 参数 Login 是否存在，作为进入登录逻辑的开关 | $_GET['Login'] 存在即进入分支 |  |
| 2 | `011.php:5` | 从 GET 读取 username 到 $user，无任何过滤/转义 | $user = 攻击者原始字符串 |  |
| 3 | `011.php:12` | 将 $user 以单引号包裹拼接进 SQL 语句，password 部分为 md5 后的定值 | $query 中包含攻击者注入的 SQL 片段 |  |
| 4 | `011.php:13` | 执行拼接后的 SQL；失败时 mysqli_error 被 die() 回显 | 注入语句在数据库执行，错误信息回显到响应 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。源码 011.php:8 通过 $_GET['password'] 取值，011.php:13 处将外部输入拼接进 SQL 查询（username 参数路径），未使用参数化/转义，构成 CWE-89。注入点为 GET 参数 username，目标地址统一使用 TARGET 占位符。

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

未授权攻击者可绕过登录进入受保护区域，并通过 UNION/报错注入读取 users 表及其它任意表数据（含口令哈希），进而横向渗透。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 未经转义直接拼接进 SQL 并执行，链路在 011.php:5→12→13 完整闭合，无需认证，属典型可申报 CVE 的注入漏洞。

**修复建议**

使用预处理语句（mysqli_prepare + bind_param）绑定 username 与 password；对输入做类型与长度校验；关闭 die(mysqli_error) 的详细错误回显，改为记录日志并返回通用错误。

**验证说明**

需确认后端表 users 的列数以便构造 UNION；需确认 display_errors/错误回显在生产环境是否开启；恒真注入依赖 MySQL 对 -- 后需空格的注释语法，已用 -- - 规避。
模型 POC 要点：利用 username 注入恒真条件绕过密码校验，并用 UNION 读取任意数据；报错回显可用于盲注替代
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于 011.php:13，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效净化；具备远程触发条件。
POC 备注：仅限授权测试。保留原请求结构，仅补充基线/对照步骤；不生成自动执行脚本，不写真实 IP/域名。

### F-2: 011.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:2-3`
- **来源**：`rule`

**描述**

011.php:3 通过 `isset($_GET['Login'])` 判定登录请求，随后在 011.php:5/8 读取 `username`/`password` 并直接查询校验。代码中未见失败计数、账户锁定、验证码、速率限制或延迟等任何反暴力机制，攻击者可对同一账号无限次提交口令猜测。

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

可对已知用户名进行在线口令爆破或撞库，最终导致账户接管；结合 MD5 弱哈希与 SQL 注入，攻击面进一步放大。

**CVE / CWE 论证**

CWE-307（对过量认证尝试缺乏限制）。外部可达性：登录入口为公开 GET 接口，无需认证；利用链为重复请求 011.php:3 的登录分支。注意：本项为语义模式命中，未在源码中看到限流实现，但运行时/部署层（如 WAF、反向代理）是否另有防护证据不足。

**修复建议**

引入按账号与按 IP 的失败计数与指数退避、临时锁定、验证码；记录并告警异常登录；将登录改为 POST 并加 CSRF 令牌；配合强口令哈希与多因素认证。

**验证说明**

静态证据：入口 ANY /011；source=request/login/password；sink=011.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者反复请求 `011.php?Login=...&username=X&password=guess` → 011.php:3 进入登录分支 → 011.php:12/13 校验 → 无失败限制使猜测可持续进行。
PocWriter 建议（未采纳，缺少端点 /011）：暴力破解防护缺失（CWE-307）静态/半动态证据：011.php:3 附近为登录/口令处理入口，未见失败次数限制、账户锁定或速率限制。原草稿将注入点写成 query 参数 `login/password`，该写法不符合源码参数命名，需人工核对实际参数名（源码中可见口令参数为 password，见 011.php:8）。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /011）：符合 CWE-307。证据位于 011.php:3 附近登录逻辑，未见失败计数/锁定机制；需人工确认部署层是否已有 WAF/限速补偿。
POC 备注：仅限授权测试。原草稿参数名 `login/password` 与源码不符，已改为源码可见的 password 参数；不生成自动爆破脚本，仅描述人工少量验证步骤。

### F-3: 011.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`011.php:8-9`
- **来源**：`rule`

**描述**

011.php:8 从 `$_GET['password']` 取口令，011.php:9 直接调用 `md5($pass)` 生成摘要后用于与数据库中的口令值比较。MD5 为快速、无盐的通用哈希，抗碰撞与抗暴力能力均已失效，且此处未见盐值或迭代（如 bcrypt/Argon2/PBKDF2）。注意：该问题本质是弱哈希（CWE-328），而非弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（011.php）
- sink：011.php:9 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:9` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型弱哈希问题：011.php:8 从 $_GET['password'] 取值，011.php:9 使用 md5() 对密码做哈希。MD5 属弱哈希算法（CWE-328），若用于口令存储/校验则易被彩虹表与碰撞攻击。注意：该问题类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327）。无需发送请求，仅做源码审查。

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

一旦数据库泄露，攻击者可用彩虹表/GPU 高速离线爆破还原用户明文口令；相同口令产生相同摘要，便于横向撞库。影响范围为用户凭据机密性。

**CVE / CWE 论证**

CWE-328（可逆单向哈希函数使用不当）。该弱点为配置/实现型，无需 HTTP 污点链即可成立；证据为 011.php:9 的 `md5(` 调用原文。外部可达性体现在登录接口对任意提交口令执行该哈希。

**修复建议**

改用带盐的自适应口令哈希：PHP `password_hash($pass, PASSWORD_ARGON2ID)` 与 `password_verify()`；迁移存量 MD5 摘要时在用户下次登录成功后重算；禁止对安全用途使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /011；source=repository/md5(；sink=011.php:9；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET `password` → 011.php:8 `$pass` → 011.php:9 `md5($pass)` → 摘要参与登录比对/存储，弱哈希使离线还原可行。
POC 备注：仅限授权测试。纯静态证据，无 HTTP 请求；不执行任何命令。

### F-4: 011.php 登录成功页 username 反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:21-22`
- **来源**：`llm_finding`

**描述**

登录成功后，脚本将用户可控的 $user 直接拼入 HTML 输出 `<p>Welcome to the password protected area {$user}</p>`，未做 htmlspecialchars 等编码。虽然该分支要求查询命中一行，但结合上一条 SQL 注入（username 注入恒真条件）即可让任意 username 内容进入成功分支，从而在响应中执行脚本；即便不依赖注入，若存在同名用户亦可直接触发。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:22 $html 拼接输出到响应（011.php:21）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:5` | 读取 username 到 $user，无编码 | $user = 攻击者 HTML/JS 片段 |  |
| 2 | `011.php:15` | 查询命中一行进入成功分支（可借 SQL 注入恒真条件保证命中） | $result 非空且行数为 1 |  |
| 3 | `011.php:21` | $user 未编码直接拼入 HTML 段落 | $html 含未转义的脚本标签 |  |
| 4 | `011.php:21` | $html 输出到响应体，浏览器解析执行 | 反射型 XSS 触发 |  |

**POC**

针对 /011.php（GET）的反射型 XSS POC。011.php:22 处将外部输入（username 参数）未编码输出到响应，构成 CWE-79。注入点为 GET 参数 username，目标地址使用 TARGET 占位符。

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

可在受害者浏览器上下文执行任意 JS，窃取会话或发起 CSRF 式操作；结合 SQL 注入可稳定触发。

**CVE / CWE 论证**

CWE-79 反射型 XSS。username 未编码输出到 HTML，链路 011.php:5→21 闭合；成功分支可通过同文件 SQL 注入保证命中，外部可达且无需认证。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；对 avatar 属性值做 URL/属性编码或白名单校验。

**验证说明**

XSS 触发依赖进入成功分支，需确认 SQL 注入恒真条件在该环境可用；若无法注入则需存在与 payload 同名的用户记录。
模型 POC 要点：借助 SQL 注入使查询恒真，将含脚本的 username 反射到成功页
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-79。漏洞位于 011.php:22，外部输入来自 GET 参数 username，source→sink 链静态闭合，未见有效编码/净化。
POC 备注：仅限授权测试。保留原请求结构，补充浏览器验证步骤；不生成自动执行脚本。

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
| safety_guard | 安全防护 | 4.03 | 是 |
| surface_mapper | 攻击面测绘 | 9.6 | 是 |
| deep_finder | LLM 深挖 | 12.33 | 是 |
| candidate_screener | 候选筛选 | 5.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.08 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.51 | 是 |
| coordinator | 管线协调 | 7.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
