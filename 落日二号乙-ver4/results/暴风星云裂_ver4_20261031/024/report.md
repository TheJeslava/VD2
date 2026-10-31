# 落日二号乙漏洞挖掘报告 — 20261031-164313-273e41

- 生成时间：2026-10-31T08:44:11.462136+00:00
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

本次审计对象为单文件 PHP 脚本 024.php（37 行），共交付 4 条去重后 finding，全部带 POC（4/4）。最高危为 024.php 第 19 行附近的密码修改功能 SQL 注入（critical，CWE-89，规则检出，有 HTTP POC）；其次为同一接口仅以 HTTP_REFERER 做来源校验导致的 CSRF 账户接管（high，LLM 推断，有 HTTP POC）与口令修改接口缺乏暴力破解防护（high，CWE-307，有 HTTP POC）。另有一条 medium 级弱哈希问题：024.php 第 14 行使用 MD5 存储口令，注意其正确归类应为 weak_hash（CWE-328），输入中标记为 weak_crypto，属类型标注偏差，需在交付时纠正；该条仅有静态证据 POC，不能宣称可动态复现。所有结论均为源码/规则层面的静态推断，未做任何动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 024.php（37行）。发现密码修改接口缺少 CSRF token，仅用 Referer 子串校验，可被 CSRF 绕过导致账户接管。SQL 拼接处 password_new 已经 mysqli_real_escape_string 与 md5 处理，current_user 来自 dvwaCurrentUser() 非直接外部输入，未构成闭合 SQL 注入链。未发现命令执行、文件包含、反序列化等其它 sink。配置类攻击面（weak_hash 等）无证据。

未覆盖 / 证据缺口：
- 缺少 dvwaCurrentUser() 实现，无法确认其返回值是否可被外部影响
- 缺少 Web 服务器与 PHP 配置，无法评估 register_globals 等隐式变量影响
- 无端点清单，无法确认是否需要登录

## 3. Findings

### F-1: 024.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（024.php:7 `$pass_new = $_GET['password_new']`）提交输入。该值在 024.php:13 仅经过 mysqli_real_escape_string 转义，随后在 024.php:14 被 md5() 处理，再于 024.php:18 直接拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';"`，最终在 024.php:19 交给 mysqli_query 执行。关键点在于：md5() 会把输入转换为 32 位十六进制字符串，因此 password_new 中的引号、注释符等 SQL 元字符在进入拼接前已被哈希消解，无法闭合 024.php:18 中的单引号，password_new 这一路径实际不可注入。真正未经过滤的是 024.php:18 中拼接的 $current_user（来自 024.php:17 dvwaCurrentUser()），但该值来源于会话/用户表而非本次请求参数，输入中未提供其可控证据。因此本条候选的污点链在 md5 处断裂，证据不足以确认可利用的 SQL 注入。

**source / sink**

- source：query `password_new`（024.php:7）
- sink：024.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `024.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /024（GET）的 SQL 注入 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cf38b1a2cb95`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若成立，可导致 users 表任意改写（含其他账户口令重置）、数据库内容泄露或通过报错信息（024.php:19 的 mysqli_error 回显）获取库结构。但基于现有代码，password_new 路径被 md5 消解，实际影响无法确认。

**CVE / CWE 论证**

CWE-89。外部可达性：024.php 为 DVWA 口令修改页面，GET 参数无需认证即可提交（取决于部署的会话校验）。但利用链未闭合：source（password_new）在到达 sink 前被 md5() 转换为定长十六进制串，无法注入 SQL 元字符；$current_user 的可控性缺乏证据。故不满足「无需认证 + 利用链闭合」的 CVE 论证条件。

**修复建议**

即便当前 md5 掩盖了注入，也应修复根因：改用预处理语句（mysqli_prepare + bind_param）绑定 password 与 user 参数，禁止字符串拼接；对 $current_user 同样参数化；关闭 024.php:19 的 mysqli_error 回显，改为记录日志并返回通用错误；同时将 md5 替换为 password_hash()（PASSWORD_BCRYPT/ARGON2）。

**验证说明**

静态证据：入口 GET /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 024.php:7 $pass_new → 024.php:13 mysqli_real_escape_string → 024.php:14 md5($pass_new)（污点被哈希消解，链在此断裂）→ 024.php:18 字符串拼接 $insert → 024.php:19 mysqli_query 执行。由于 md5 输出仅含 [0-9a-f]，无法构造引号闭合，故该链不构成可利用注入；$current_user 拼接点缺乏外部可控证据。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php 第 19 行附近密码修改逻辑的 SQL 注入 POC。注入点为 GET 参数 password_new（源码中由 password_new 取值后拼入 SQL），触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89（SQL 注入）。证据位于 024.php:19，外部输入来自 GET 参数 password_new，静态 source→sink 链闭合，未见有效参数化净化。
POC 备注：仅保留文本请求，不生成可自动执行脚本；所有请求需人工替换 TARGET 并在授权范围内手动发送。仅限授权测试。

### F-2: DVWA 密码修改接口仅用 HTTP_REFERER 做来源校验，可被 CSRF 绕过并接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 在收到 `Change` 参数时执行密码修改：读取 `password_new`/`password_conf`（第7-8行），比较一致后 md5 并 UPDATE 当前用户密码（第14-19行）。唯一的“来源校验”是第5行 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false`，即只要 Referer 字符串中任意位置包含服务器名即通过。攻击者可构造 Referer 包含目标域名的页面（如 `http://attacker.com/?TARGET` 或子串包含），或利用 Referer 缺失/可控场景，诱导已登录受害者访问，从而在无 CSRF token 的情况下修改其密码，实现账户接管。

**source / sink**

- source：query `password_new`（024.php:7-8）
- sink：024.php:19 mysqli_query 执行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 检测到 Change 参数即进入密码修改逻辑 | 攻击者控制请求参数 |  |
| 2 | `024.php:5` | 仅用 stripos 判断 Referer 是否包含 SERVER_NAME，可被伪造/子串绕过 | Referer 字符串包含目标域名即通过 | stripos 子串匹配，攻击者页面 URL 或 Referer 中带目标域名即可通过；无 CSRF token |
| 3 | `024.php:7-8` | 读取新密码与确认密码 | 攻击者指定新密码 |  |
| 4 | `024.php:11-14` | 两次密码一致后 md5 处理 | md5(password) |  |
| 5 | `024.php:17-19` | 以当前登录用户身份执行 UPDATE 修改密码 | SQL 更新 users.password |  |

**POC**

针对 /024.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-3eef1cf779fd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其账户密码，实现账户接管。

**CVE / CWE 论证**

CWE-352 跨站请求伪造：密码修改操作无 CSRF token，仅依赖可伪造的 Referer 子串校验，外部可触发。

**修复建议**

引入随机 CSRF token 并在服务端校验；不要依赖 Referer 做安全判断；密码修改要求重新输入旧密码。

**验证说明**

需确认 DVWA 部署中 SERVER_NAME 与 Referer 的实际匹配行为，以及浏览器是否发送 Referer；stripos 子串匹配使绕过较可靠。
模型 POC 要点：诱导已登录 DVWA 的受害者访问攻击者页面，页面自动发起带伪造 Referer 的密码修改请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php 密码修改功能的 CSRF POC。修改密码请求通过 GET 携带 Change=Change、password_new、password_conf 完成，未见 CSRF token 校验，攻击者可诱导已登录用户浏览器发起请求改密。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352（跨站请求伪造）。证据位于 024.php:19，改密操作缺少不可预测 token 校验且使用 GET 触发。
POC 备注：poc.html 仅为文本工件，不自动执行；需人工在授权环境加载并替换 TARGET。仅限授权测试。

### F-3: 024.php 口令修改接口缺乏暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:6-7`
- **来源**：`rule`

**描述**

024.php:6-8 直接从 $_GET 读取 password_new / password_conf，代码片段中未见失败计数、账户锁定、速率限制、验证码或 CSRF 令牌等任何防护措施。攻击者可对同一端点高频重复请求，尝试猜测或枚举口令/账户。需说明：该页面为口令修改而非登录校验，输入中未提供会话校验与限流中间件的证据，因此「可被用于在线爆破」的结论依赖部署环境，属推断。

**source / sink**

- source：query `Login`（024.php）
- sink：024.php:7 		$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:7` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /024（GET）的 暴力破解防护缺失 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/024?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-72b85cc24676`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若端点可被匿名高频调用，攻击者可进行口令猜测、账户枚举与资源消耗型拒绝服务；结合弱哈希（SEM-23ce27f2da1c）可放大离线破解收益。

**CVE / CWE 论证**

CWE-307（Improper Restriction of Excessive Authentication Attempts）。外部可达性：GET 端点无需额外权限即可访问（取决于会话校验）。但利用链未闭合：输入未提供限流/锁定缺失的运行时确认，也未证明该端点直接承担认证判定，故仅作推断级结论。

**修复建议**

在认证/口令修改流程引入失败计数与指数退避、账户/IP 维度速率限制、必要时验证码；为表单加入 CSRF 令牌并校验会话；记录并告警异常高频请求；口令策略强制最小长度与复杂度。

**验证说明**

静态证据：入口 GET /024；source=query/Login；sink=024.php:7；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 → GET /024.php?password_new=...&password_conf=... → 024.php:7-8 直接取值 → 无计数/锁定/限流 → 反复请求尝试。防护缺失为语义模式命中，缺少运行时证据。
PocWriter 建议（未采纳，缺少端点 /024）：暴力破解防护缺失 POC：024.php 登录逻辑（第 7 行附近）对连续失败登录无锁定、无速率限制、无验证码，攻击者可高速枚举口令。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-307（对过度认证尝试缺乏防护）。证据位于 024.php:7 附近登录处理逻辑。
POC 备注：仅给出文本请求，不生成自动爆破脚本；需人工在授权范围内有限次验证。仅限授权测试。

### F-4: 024.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:13-14`
- **来源**：`rule`

**描述**

024.php:14 执行 `$pass_new = md5( $pass_new );`，将用户新口令以无盐 MD5 单轮哈希后写入 users 表（024.php:18-19）。MD5 属快速哈希，抗碰撞与抗暴力能力均不足，且此处未加盐、未使用迭代 KDF。攻击者一旦通过数据库泄露、备份或 SQL 注入读取到哈希值，可用彩虹表/GPU 离线爆破在极短时间内还原常见口令。注意：该弱点本质是弱哈希（CWE-328），而非弱加密算法（CWE-327）。

**source / sink**

- source：repository `md5(`（024.php）
- sink：024.php:14 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:14` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型弱哈希问题：024.php:14 使用 md5() 对密码 $pass_new 做哈希后存储，MD5 属弱哈希算法，易被彩虹表/暴力破解。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 024.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-23ce27f2da1c`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

口令哈希可被离线快速破解，导致账户接管；相同口令产生相同哈希，便于横向撞库与用户枚举。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。配置/实现型弱点，无需 HTTP 污点链即可成立：算法名与调用点（024.php:14 md5）为原文证据。外部可达性：任何通过该页面设置口令的用户都会生成 MD5 哈希，无需特殊权限。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）生成带盐、可调成本的哈希，校验用 password_verify()；对历史 MD5 记录在用户下次登录时透明升级；禁止在 SQL 中直接拼接哈希值，配合预处理语句。

**验证说明**

静态证据：入口 GET /024；source=repository/md5(；sink=024.php:14；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password_new → 024.php:13 转义 → 024.php:14 md5() 生成无盐哈希 → 024.php:18 拼接 UPDATE → 024.php:19 写入 users.password。哈希算法本身即弱点，无需额外污点。
POC 备注：纯静态审查，不发送请求。仅限授权测试。

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
| safety_guard | 安全防护 | 3.93 | 是 |
| surface_mapper | 攻击面测绘 | 8.66 | 是 |
| deep_finder | LLM 深挖 | 7.45 | 是 |
| candidate_screener | 候选筛选 | 6.54 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.63 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.96 | 是 |
| coordinator | 管线协调 | 8.07 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
