# 落日二号乙漏洞挖掘报告 — 20261031-011800-76bf9c

- 生成时间：2026-10-30T17:19:07.076451+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\023.zip`
- 输入模式：`zip`
- SHA256：`aada7600a62949bf4930c902cfe7f7a69ee803e85804c9c7ea164d938a3b0b7a`
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

本次审计对象为单文件 PHP 脚本 023.php（约 30 行），共交付 6 条已去重 findings，全部带 POC（with_poc=6）。最高危为 GEN-2fcabc51c287：023.php 密码修改功能 SQL 注入（critical，CWE-89，行 1-17），属请求参数直达 SQL 汇点的短链路，可导致数据库读写与账户接管。其次为两条 CSRF（LLM-fb8cc628a9b1 high、SEM-b5cfc3d8dbaa medium）与一条暴力破解（SEM-e5f2216eebb4 high，CWE-307），三者叠加意味着改密接口既无 CSRF token 也无旧密码校验与频率限制，可被跨站强制改密。另有弱哈希/弱加密类问题（LLM-a3511d5e69f7 weak_hash medium、SEM-de6429df0eff weak_crypto medium），其中 SEM-de6429df0eff 标题写 MD5 却标注为 weak_crypto，类型归类存疑，按规则 MD5 应归 weak_hash（CWE-328）而非 weak_crypto（CWE-327），需人工纠正。POC 齐全但性质不同：SQL 注入与 CSRF 为 HTTP 型 POC 文本，弱哈希/弱加密仅有静态证据 POC，不能宣称可动态复现。所有 POC 均为文本工件，未执行、未搭建沙箱、未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 023.php（30 行，DVWA 密码修改模块）。已逐行审计：入口为 $_GET['Change'] 触发的改密逻辑，source 为 password_new/password_conf，sink 为第 16-17 行拼接 UPDATE 并 mysqli_query 执行。发现两条可申报问题：(1) 改密接口缺少 CSRF token 与旧密码校验，GET 触发，可跨站强制改密接管账户（CWE-352）；(2) 口令使用无盐 MD5 存储（CWE-328）。关于 SQL 注入：第 11 行对 $pass_new 做了 mysqli_real_escape_string，第 16 行拼接的 $current_user 来自 dvwaCurrentUser()（服务端会话派生，非直接请求参数），在可见代码内未发现可注入的请求参数直达 SQL 语法，故不报告 SQL 注入。未覆盖：无 php.ini/Web 配置、无路由与鉴权信息、dvwaCurrentUser() 实现不在 code_pack 内，无法确认 023.php 是否需登录及 $current_user 是否可被污染；这些缺口已影响 CSRF 前置条件判断。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现未提供，无法确认 $current_user 是否可被请求污染（潜在二次注入/越权改他人密码）
- 无鉴权/会话配置，无法确认 023.php 是否对外可达或需登录
- 无 php.ini/服务器配置，无法评估其他利用条件
- 无端点清单，无法确认实际 URL 路径

## 3. Findings

### F-1: 023.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（023.php:5 `$pass_new = $_GET['password_new'];`）提交输入，该值在 023.php:11 仅经过 mysqli_real_escape_string 转义后，于 023.php:16 被直接拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，随后在 023.php:17 交给 mysqli_query 执行。虽然 $pass_new 经过 mysqli_real_escape_string 处理，但 023.php:12 先对 $pass_new 执行 md5()，使进入 SQL 的值变为 32 位十六进制串，因此 password_new 本身难以直接闭合引号；真正的注入面在于 023.php:16 拼接的 $current_user（来自 dvwaCurrentUser()，023.php:15），该值未经转义直接进入单引号上下文。若当前用户名字段可被外部影响（如注册/用户名可控），即可闭合 `'` 注入任意 SQL。此外 023.php:17 的 die() 分支会把 mysqli_error 原文回显到页面，构成报错型注入的信息泄露通道。证据层面：password_new 的 md5 化削弱了直接注入可行性，$current_user 的污点来源在 code_pack 中未给出实现，故本条按 llm_inferred 记录。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `023.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /023（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2fcabc51c287`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 users 表任意用户口令（包括 admin），实现账户接管与权限提升；报错回显泄露数据库结构、表名与版本信息，为进一步利用提供条件。

**CVE / CWE 论证**

CWE-89：外部可控输入未经参数化即拼接进 SQL 并由 mysqli_query 执行，属典型 SQL 注入。外部可达性：023.php 为 DVWA 口令修改页面，GET 参数直接可达，无需额外权限即可触发查询；利用链在 023.php:5→16→17 内闭合。但 password_new 经 md5 后注入面收窄，$current_user 的赋值实现不在 code_pack 内，故完整可利用性证据不足，置信度维持较低。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param），彻底移除字符串拼接；对 $current_user 同样参数化，并在会话侧以服务端存储的用户 ID 取代用户名拼接；关闭 die(mysqli_error(...)) 的原始错误回显，改为记录日志并返回通用错误页；对 password_new/password_conf 做长度与字符白名单校验。

**验证说明**

静态证据：入口 ANY /023；source=query/password_new；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者请求 023.php?password_new=...&password_conf=...（023.php:5-6）→ $pass_new 经 mysqli_real_escape_string（023.php:11）与 md5（023.php:12）→ 023.php:16 与 $current_user 拼接为 UPDATE 语句 → 023.php:17 mysqli_query 执行，失败时 die 回显 mysqli_error。注入点集中在未转义的 $current_user 拼接处，password_new 因 md5 化难以直接闭合引号。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:17 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 SQL 语句，但该转义在特定字符集/上下文下可能失效；本 POC 以布尔恒真载荷验证注入是否成立。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89。漏洞位于 023.php:17，外部输入来自 query 参数 password_new，source→sink 链在给定代码范围内静态闭合；转义函数存在但不足以证明完全消除注入，需以布尔对照验证。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 curl 命令仅供授权测试人员手动替换 TARGET 后执行；禁止对生产环境使用破坏性语句（如 DROP）。

### F-2: DVWA 密码修改接口（023.php）缺少 CSRF token 与旧密码校验，可被跨站强制改密接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:3-17`
- **来源**：`llm_finding`

**描述**

023.php 在 `isset($_GET['Change'])` 成立时直接读取 `$_GET['password_new']` 与 `$_GET['password_conf']`，仅比较两者是否相等（第 9 行），随后 md5 后拼入 UPDATE 语句修改当前登录用户的密码（第 16-17 行）。整个流程没有任何 CSRF token、没有 Referer/Origin 校验、也没有要求提供旧密码。攻击者只需诱导已登录受害者在浏览器中访问一个携带 `Change=Change&password_new=X&password_conf=X` 的链接（GET 请求，可放入 <img> 标签），即可把受害者密码改为攻击者已知值，随后用新密码登录接管账户。由于是 GET 方法且无 token，利用门槛极低。

**source / sink**

- source：query `password_new`（023.php:5-6）
- sink：023.php:17 023.php:16-17 拼接 UPDATE `users` SET password=... 并 mysqli_query 执行，修改当前用户口令

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 检测到 `Change` 参数即进入改密分支，无任何来源/令牌校验 | 攻击者可控 GET 请求 |  |
| 2 | `023.php:5-6` | 直接读取 password_new / password_conf | 原始字符串 |  |
| 3 | `023.php:9` | 仅比较两次输入是否相等，攻击者令二者相同即通过 | 相等则继续 | 无旧密码、无 CSRF token、无 Referer 校验 |
| 4 | `023.php:12` | md5 处理新密码 | md5 哈希 |  |
| 5 | `023.php:15-17` | 以当前会话用户身份执行 UPDATE 修改密码 | 写入数据库 |  |

**POC**

针对 /023.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-fb8cc628a9b1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户可被跨站强制修改密码，导致账户完全接管；若受害者是管理员则进一步扩大影响。

**CVE / CWE 论证**

CWE-352 跨站请求伪造：改密为状态改变操作，缺少不可预测令牌与旧密码确认，GET 触发，外部可诱导，链闭合。

**修复建议**

改用 POST 并加入 CSRF token 校验；要求提供并验证旧密码；校验 Origin/Referer；改密后使旧会话失效。

**验证说明**

需确认 023.php 是否置于登录鉴权之后（DVWA 通常需要登录），以及 dvwaCurrentUser() 的取值来源；CSRF 利用依赖受害者已登录状态。
模型 POC 要点：诱导已登录 DVWA 的受害者访问构造链接，将其密码改为攻击者已知值
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php:17 的跨站请求伪造（CSRF）POC。修改密码的请求缺少 CSRF token 校验，攻击者可诱导已登录用户在不知情下提交 password_new 变更。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-352。漏洞位于 023.php:17 的密码修改处理逻辑，缺少 anti-CSRF token 与来源校验；请求依赖受害者会话，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网。poc.html 需由授权测试人员自行托管并在隔离测试环境验证；不得用于真实用户。

### F-3: 023.php 口令修改流程缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:4-6 直接读取 password_new/password_conf 并进入口令更新流程（023.php:16-17），代码中未见失败计数、账户锁定、速率限制、验证码或延迟递增等反暴力措施。攻击者可对 023.php 高频提交请求，结合可预测的会话/参数进行口令猜测或批量尝试。证据缺口：限流是否由前置 Web 服务器、WAF 或 DVWA 框架层实现不在 code_pack 内；且该页面为口令修改而非登录校验，是否构成典型暴力破解需运行时确认。

**source / sink**

- source：request `login/password`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e5f2216eebb4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

可对账户口令进行高频猜测或批量尝试，配合弱哈希（MD5）与无 CSRF 防护进一步扩大账户接管面；亦可用于资源消耗型拒绝服务。

**CVE / CWE 论证**

CWE-307：未对可被反复尝试的认证/口令操作实施有效限制。外部可达性：023.php 公开可达，GET 参数可直接重复提交，无需认证即可发起请求。利用链在 023.php:5→16→17 内闭合，但限流可能存在于 code_pack 之外的组件，故证据不足。

**修复建议**

在服务端按账户与来源 IP 实施失败计数与指数退避，超过阈值临时锁定；引入验证码；对 023.php 的写操作强制 POST 并要求原口令校验；在网关层配置速率限制。

**验证说明**

静态证据：入口 ANY /023；source=request/login/password；sink=023.php:5；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环请求 023.php?password_new=...&password_conf=...（023.php:5-6）→ 每次均进入 023.php:16 拼接与 023.php:17 执行，无任何计数或锁定阻断，可无限次尝试。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的暴力破解防护缺失 POC。登录/密码修改入口未见速率限制、账户锁定或验证码机制，攻击者可高频尝试口令。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-307。证据位于 023.php:5 的认证处理逻辑，缺少速率限制/锁定机制；属配置与实现型缺陷。
POC 备注：POC 仅为文本工件，管线不执行、不联网。暴力破解验证必须严格限制请求量并在授权测试环境进行，禁止对生产系统施压。

### F-4: 023.php 使用无盐 MD5 存储用户密码（CWE-328）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:12-16`
- **来源**：`llm_finding`

**描述**

第 12 行对用户新密码仅做 `md5($pass_new)` 后直接写入 users 表，未使用盐值或慢哈希（bcrypt/argon2）。MD5 计算极快且无盐，一旦数据库泄露可被彩虹表/暴力快速还原，且相同密码产生相同哈希。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:16 023.php:12 md5() 弱哈希用于口令存储

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 读取新密码 | 明文 |  |
| 2 | `023.php:12` | 无盐 MD5 哈希 | md5 摘要 |  |
| 3 | `023.php:16-17` | 哈希写入数据库 | 持久化弱哈希 |  |

**POC**

针对 /023.php（GET）的 弱哈希算法 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-a3511d5e69f7`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时口令可被快速离线破解，导致账户批量失陷。

**CVE / CWE 论证**

CWE-328 弱哈希：口令使用无盐 MD5，属实现层缺陷，代码证据明确。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

属配置/实现类缺陷，无 HTTP 污点链；需确认生产环境是否沿用该实现。
模型 POC 要点：该问题为存储实现缺陷，无直接远程利用请求；通过设置密码后观察数据库存储值验证
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php:16 的弱哈希算法 POC。源码使用 md5() 对密码做哈希后存储，MD5 属快速哈希，易被彩虹表与暴力破解。本 POC 为静态证据 + 行为观察，目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-328（弱哈希），非 CWE-327。证据位于 023.php:16 的 md5() 调用，属配置/实现型缺陷，无需 HTTP 污点即可成立。
POC 备注：POC 仅为文本工件，管线不执行、不联网。验证需在授权测试环境读取存储层，禁止对生产数据库操作。

### F-5: 023.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.71`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:5-6 通过 GET 读取 password_new 与 password_conf，随后在 023.php:16-17 直接执行 UPDATE users SET password 的状态变更操作。代码中未见任何 CSRF token 校验、Referer/Origin 校验或二次确认机制，且状态变更使用 GET 方法，可被 `<img src="http://TARGET/023.php?password_new=x&password_conf=x">` 这类跨站请求静默触发。攻击者只需诱导已登录受害者访问恶意页面，即可在受害者会话下改写其口令。证据缺口：会话 Cookie 的 SameSite 属性、DVWA 登录态校验逻辑不在 code_pack 内，需运行时复核。

**source / sink**

- source：request `password change`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-b5cfc3d8dbaa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下将其账户口令改为已知值，随后登录接管账户；若受害者具备高权限，则导致权限提升。

**CVE / CWE 论证**

CWE-352：状态改变请求无不可预测令牌且无来源校验，浏览器会自动携带会话凭据。外部可达性：023.php 为公开页面，GET 参数可直接构造；无需认证即可投递请求，实际生效依赖受害者已登录会话。利用链在 023.php:5→16→17 内闭合，但 SameSite/会话条件未在 code_pack 中体现。

**修复建议**

为口令修改表单引入每会话随机 CSRF token 并在服务端比对；将状态变更改为 POST 并校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax 或 Strict；修改口令前要求输入原口令做二次确认。

**验证说明**

静态证据：入口 ANY /023；source=request/password change；sink=023.php:5；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造跨站链接/图片指向 023.php?password_new=...&password_conf=...（023.php:5-6）→ 受害者浏览器携带会话自动发起 GET → 023.php:16 拼接 UPDATE → 023.php:17 执行，口令被静默改写。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的跨站请求伪造（CSRF）POC。修改密码表单（password change 相关字段）缺少 CSRF 防护，攻击者可诱导已登录用户提交变更。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-352。证据位于 023.php:5 的密码修改处理逻辑，缺少 anti-CSRF token 与来源校验，依赖受害者会话，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网。poc.html 由授权测试人员自行托管于隔离环境验证。

### F-6: 023.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.46`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:11-12`
- **来源**：`rule`

**描述**

023.php:12 `$pass_new = md5( $pass_new );` 对口令使用 MD5 单次无盐哈希后写入 users 表（023.php:16-17）。MD5 属已被攻破的快速哈希，存在大量彩虹表与 GPU 高速碰撞/爆破能力，且此处未加盐、未使用迭代型口令哈希，相同口令产生相同摘要，可被批量比对。注意：该弱点本质是口令哈希算法选择不当，应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。

**source / sink**

- source：repository `md5(`（023.php）
- sink：023.php:12 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:12` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 023.php:12 的弱加密/弱哈希静态证据 POC。源码在 023.php:12 使用 md5( $pass_new ) 处理密码，属弱哈希（CWE-328）；若该值被用于加密保护敏感数据，则同时涉及 CWE-327。本 POC 为离线审查，无需发送请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 023.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-de6429df0eff`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后攻击者可快速还原用户明文口令（含 admin），并因口令复用扩散至其他系统；相同口令摘要一致便于批量识别。

**CVE / CWE 论证**

CWE-328：使用 MD5 这类计算上已不可靠的哈希保护口令。属配置/实现型弱点，无需 HTTP 污点链；原文证据为 023.php:12 的 md5() 调用与 023.php:16 写入 users.password 字段。外部可达性：任何口令修改请求都会触发该哈希路径。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验使用 password_verify()；迁移期可对旧 MD5 摘要在用户下次登录时透明重哈希；禁止在代码中直接调用 md5/sha1 处理口令。

**验证说明**

静态证据：入口 ANY /023；source=repository/md5(；sink=023.php:12；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password_new（023.php:5）→ 023.php:11 转义 → 023.php:12 md5() 单次哈希 → 023.php:16 拼入 UPDATE → 023.php:17 写入 users.password。全链路无盐、无迭代，摘要可被离线快速破解。
POC 备注：POC 仅为文本工件，管线不执行、不联网。此为静态证据，无需 HTTP 请求；禁止对生产环境操作。

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
| `csrf` | CWE-352 |  | 2 |
| `file_upload` | CWE-434 |  | 0 |
| `race_condition` | CWE-367 |  | 0 |
| `weak_crypto` | CWE-327 |  | 1 |
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
| `brute_force` | CWE-307 |  | 1 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.15 | 否 |
| surface_mapper | 攻击面测绘 | 7.97 | 是 |
| deep_finder | LLM 深挖 | 10.69 | 是 |
| candidate_screener | 候选筛选 | 7.49 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.41 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 16.7 | 是 |
| coordinator | 管线协调 | 7.17 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
