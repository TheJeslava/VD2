# 落日二号乙漏洞挖掘报告 — 20261031-164254-f9ce35

- 生成时间：2026-10-31T08:44:04.107788+00:00
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

本次审计仅覆盖单文件 PHP 脚本 023.php（30 行），共交付 6 条去重 findings，全部带 POC（6/6）。最高危为 GEN-2fcabc51c287：023.php 第 17 行口令更新语句存在 SQL 注入（CWE-89，critical），属规则命中，链路为第 3 行请求参数直入更新语句，中间无净化，可导致数据库读写与口令篡改。其次为两条 CSRF（LLM-fb8cc628a9b1 high、SEM-b5cfc3d8dbaa medium，均指向 023.php 第 5/17 行口令修改接口无 token）与一条暴力破解（SEM-e5f2216eebb4，第 5 行无速率限制/失败锁定），三者叠加可形成「跨站强制改密 + 在线爆破」的账户接管路径。另有 weak_hash（LLM-3fa1c975a8fc）与 weak_crypto（SEM-de6429df0eff）指向 023.php 第 12/17 行无盐 MD5 存储口令，注意二者实为同一 MD5 用法，按 CWE-328 归类应合并为 weak_hash，weak_crypto 标签属类型串用，需人工归并。POC 齐全但性质不同：SQL 注入、CSRF、暴力破解为 HTTP 型 POC 文本（目标以 TARGET 占位，仅限授权测试）；weak_hash/weak_crypto 仅有静态证据 POC，不可宣称可动态复现。所有结论均为源码审计推断，未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 023.php（30 行，DVWA CSRF 模块）。已逐行审计：入口为 $_GET['Change'] 触发的改密逻辑，password_new/password_conf 经相等校验后 mysqli_real_escape_string + md5，再以 dvwaCurrentUser() 拼接 UPDATE 执行。SQL 注入方面：password_new 已转义且被 md5 化，current_user 来自服务端会话函数，未发现可闭合的 SQL 注入链，故不报告。主要问题为缺少 CSRF 防护的改密接口（高危，可账户接管）与无盐 MD5 存储（中危）。未覆盖：dvwaCurrentUser() 实现、数据库 schema、部署路径与运行时配置均不在 code_pack 内，无法确认；无端点清单，路由为按 DVWA 惯例推断。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 定义未提供，无法确认其是否可被污染
- 无 composer/配置/部署信息
- 无端点清单，路由为推断
- 未提供 users 表结构与其他密码写入路径

## 3. Findings

### F-1: 023.php 口令更新语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（023.php:5 `$pass_new = $_GET['password_new'];`）提交输入。该值在 023.php:11 仅经过 mysqli_real_escape_string 处理，随后在 023.php:16 被直接拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，并在 023.php:17 交给 mysqli_query 执行。由于拼接发生在字符串构造阶段而非参数化绑定，引号转义无法阻止注入语义（例如在已转义引号之外利用注释符/多语句或改变 WHERE 条件），且 023.php:17 的 die(mysqli_error(...)) 会把数据库错误回显给攻击者，构成报错型注入辅助通道。注意：候选给出的 source 描述为“query `password_new`”，实际注入点是 GET 参数 password_new，POC 应使用该参数名。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `023.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /023（GET）的 SQL 注入 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2fcabc51c287`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可越权修改 users 表中任意用户（含 admin）的 password 字段，实现账户接管；借助报错回显可逐步枚举数据库结构，进一步读取其他表数据（数据泄露）。

**CVE / CWE 论证**

CWE-89：外部可控输入未经参数化直接进入 SQL 语句。攻击面为 HTTP GET 参数，无需认证即可构造请求（是否要求已登录取决于部署，但注入点本身不依赖任何权限校验），利用链闭合：$_GET['password_new'] → $pass_new → $insert 字符串拼接 → mysqli_query 执行。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），彻底移除字符串拼接；对 password_new 做长度与字符白名单校验；关闭生产环境的 mysqli_error 回显，改为记录服务端日志；数据库账户遵循最小权限，仅授予必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 GET /023；source=query/password_new；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 GET 请求，password_new 携带注入载荷 → 023.php:5 读入 $pass_new → 023.php:11 mysqli_real_escape_string 仅做引号转义，未阻断注入语义 → 023.php:16 拼入 UPDATE 语句 → 023.php:17 mysqli_query 执行，错误经 die() 回显。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:17 的 SQL 注入 POC。源码中 `$pass_new = $_GET['password_new']` 经 `mysqli_real_escape_string` 后进入 `UPDATE users SET password='$pass_new'` 语句；注入点为 GET 参数 `password_new`，触发按钮字段为 `Submit=Submit`。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89（SQL 注入）。证据位于 023.php:17，外部输入来自 GET 参数 `password_new`，source→sink 链在给定代码片段内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例；步骤 2/3 需人工比对响应，禁止使用 DROP/破坏性语句。

### F-2: DVWA 密码修改接口（023.php）缺少 CSRF token，可被跨站强制改密导致账户接管

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:3-17`
- **来源**：`llm_finding`

**描述**

023.php 在 `isset($_GET['Change'])` 成立时直接读取 `$_GET['password_new']` 与 `$_GET['password_conf']`，仅校验两次输入相等（第 9 行），随后做 mysqli_real_escape_string + md5（第 11-12 行），并以 `dvwaCurrentUser()` 拼出 UPDATE 语句更新当前用户密码（第 15-17 行）。整个流程没有任何 CSRF token、Referer/Origin 校验、二次确认或旧密码校验，且使用 GET 方法，攻击者只需诱导已登录受害者在浏览器中访问一个含 `<img src=...>` 的页面即可在受害者会话下完成改密，随后用自己设定的密码登录接管账户。

**source / sink**

- source：query `password_new`（023.php:5-6）
- sink：023.php:17 023.php:17 mysqli_query 执行 UPDATE users SET password=... WHERE user=当前登录用户

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 入口仅判断 Change 参数是否存在，未校验任何防 CSRF 令牌 | 攻击者完全可控的 GET 请求 |  |
| 2 | `023.php:5-6` | 直接读取 password_new / password_conf | 原始字符串 |  |
| 3 | `023.php:9` | 仅比较两次输入是否相等，攻击者令二者相同即通过 | 相等校验通过 |  |
| 4 | `023.php:11-12` | 转义后 md5 哈希，不影响攻击者预设密码 | md5(攻击者密码) |  |
| 5 | `023.php:15-17` | 以受害者会话身份执行 UPDATE 修改其密码 | 数据库写入新密码 | 无 CSRF token、无 Origin/Referer 校验、GET 方法可被 <img>/<script> 跨站触发 |

**POC**

针对 /vulnerabilities/csrf/（GET）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/csrf/?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-fb8cc628a9b1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意已登录用户可被跨站强制修改密码，导致账户完全接管；若管理员被诱导访问则影响后台。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。外部可达、无需攻击者认证（仅需受害者会话）、链路在源码中完整闭合（第 3→17 行）。

**修复建议**

为改密表单引入并校验 CSRF token；改用 POST；校验旧密码；校验 Origin/Referer。

**验证说明**

需确认部署路径与 DVWA 版本；动态验证需在授权环境用真实会话复现。
模型 POC 要点：构造恶意页面，诱导已登录 DVWA 的受害者访问，从而把其密码改为攻击者已知值
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 023.php:17 密码修改逻辑的 CSRF POC。源码在修改密码时未校验 CSRF token，仅依赖 GET 参数 `password_new`/`password_conf` 与 `Change=Change` 提交按钮，攻击者可诱导已登录用户浏览器发起请求完成密码重置。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-352（跨站请求伪造）。证据位于 023.php:17，密码修改逻辑缺少 token 校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 2 需在受害者已登录会话上下文中发起；Cookie 需替换为授权测试账号的真实会话，不得伪造。

### F-3: 023.php 口令修改流程缺少速率限制与失败锁定（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:4-6 直接读取 password_new/password_conf 并进入更新逻辑，代码中未见失败计数、账户锁定、验证码或速率限制机制。攻击者可对同一端点高频重复提交请求，用于口令猜测、枚举或配合 CSRF 进行批量尝试。需说明：本文件片段未包含登录校验逻辑，是否构成完整“暴力破解”取决于同目录其他文件（如 login.php）的会话校验实现，该部分不在本次 code_pack 范围内，属证据缺口。

**source / sink**

- source：query `Login`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（GET）的 暴力破解防护缺失 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e5f2216eebb4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在缺少限速的情况下，攻击者可对账户口令进行高频猜测或对接口进行资源耗尽式滥用，提高账户被攻破概率。

**CVE / CWE 论证**

CWE-307：认证/敏感操作缺乏尝试次数限制。外部可达（HTTP 请求即可），无需认证；但利用链的完整性依赖未提供的登录校验代码，故置信度较低。

**修复建议**

在口令修改与登录端点实施基于账户与 IP 的速率限制与指数退避；连续失败达阈值后临时锁定并要求二次验证；记录并告警异常高频请求；结合 CSRF token 防止跨站批量触发。

**验证说明**

静态证据：入口 GET /023；source=query/Login；sink=023.php:5；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 023.php 高频发送携带 password_new/password_conf 的请求 → 023.php:5-6 读取参数 → 023.php:16-17 执行更新，全程无失败计数或锁定阻断。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的暴力破解防护缺失 POC。源码在登录/密码修改处理中未实现失败计数、锁定或速率限制，攻击者可高频尝试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-307（认证尝试限制不当）。证据位于 023.php:5，登录逻辑缺少失败限制。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 2 需人工重复发起并记录，禁止自动化大规模爆破；参数名需与源码核对后再执行。

### F-4: 023.php 使用无盐 MD5 存储用户密码

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:12-17`
- **来源**：`llm_finding`

**描述**

第 12 行 `$pass_new = md5( $pass_new );` 将用户新密码以无盐 MD5 存储到 users 表（第 16-17 行）。MD5 属快速哈希，无盐且无迭代，一旦数据库泄露可被彩虹表/GPU 快速还原，且相同密码产生相同哈希。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 023.php:17 将 md5 值写入 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 读取新密码 | 明文 |  |
| 2 | `023.php:12` | 无盐 MD5 哈希 | md5 摘要 |  |
| 3 | `023.php:16-17` | 写入数据库作为密码凭据 | 弱哈希存储 |  |

**POC**

针对 /vulnerabilities/csrf/（GET）的 弱哈希算法 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/csrf/?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-3fa1c975a8fc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时用户口令可被快速还原，且相同口令哈希相同，扩大横向影响。

**CVE / CWE 论证**

CWE-328 使用弱哈希算法。源码直接可见，属实现层弱点。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

需确认 users 表密码字段确由该路径写入且无其他加盐环节。
模型 POC 要点：该问题为存储实现弱点，无直接远程利用请求；通过数据库泄露场景体现风险
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 023.php:12 的弱哈希 POC。源码 `$pass_new = md5( $pass_new );` 使用 MD5 存储密码，属 CWE-328 弱哈希，可被彩虹表/高速爆破还原。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-328（弱哈希）。证据位于 023.php:12，md5() 无盐单次哈希用于密码存储。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 3 为离线计算，不涉及目标交互；需授权测试账号。

### F-5: 023.php 口令修改接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:4-6 直接从 $_GET 读取 password_new 与 password_conf 并据此执行口令更新（023.php:16-17 的 UPDATE users SET password），整个流程未见任何 CSRF token、Origin/Referer 校验或二次确认。攻击者可诱导已登录受害者的浏览器发起跨站请求（例如 <img src="http://TARGET/023.php?password_new=xxx&password_conf=xxx">），在受害者不知情下把其口令改为攻击者已知值。使用 GET 方法执行状态变更进一步降低了利用门槛。

**source / sink**

- source：query `Change`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-b5cfc3d8dbaa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

账户接管：受害者口令被静默重置为攻击者控制的值，攻击者随后可直接登录受害者账户（若为 admin 则获得管理权限）。

**CVE / CWE 论证**

CWE-352：状态改变操作缺乏不可预测令牌与来源校验。外部可达（普通 HTTP 请求即可触发），无需攻击者持有凭据，仅需受害者已登录会话；利用链闭合：跨站请求 → 023.php:5-6 读取参数 → 023.php:16-17 执行 UPDATE。

**修复建议**

为口令修改表单引入一次性 CSRF token 并在服务端校验；将状态变更改为 POST 并校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /023；source=query/Change；sink=023.php:5；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造指向 023.php 的跨站请求，携带 password_new/password_conf → 受害者浏览器自动附带会话 Cookie → 023.php:5-6 读取参数 → 023.php:16-17 更新口令，无任何令牌校验阻断。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的 CSRF POC。源码在 023.php:5 处处理 `Change` 参数时未校验 CSRF token，攻击者可诱导已登录用户提交密码修改请求。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-352。证据位于 023.php:5，`Change` 分支缺少 token 校验。
POC 备注：POC 仅为文本工件，不执行、不联网。Cookie 需替换为授权测试账号真实会话。

### F-6: 023.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:11-12`
- **来源**：`rule`

**描述**

023.php:12 `$pass_new = md5( $pass_new );` 对口令使用 MD5 做单次无盐哈希后写入 users 表。MD5 属于已破解的快速哈希算法，存在大量彩虹表与 GPU 高速碰撞/暴力破解能力，且此处未加盐，相同口令产生相同摘要，可被批量比对。该弱点为配置/实现型，不依赖 HTTP 污点链，证据为 023.php:12 的算法调用原文。

**source / sink**

- source：repository `md5(`（023.php）
- sink：023.php:12 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:12` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 023.php:12 的弱加密/弱哈希静态证据 POC。源码 `$pass_new = md5( $pass_new );` 使用 MD5 处理密码，属 CWE-327/328 范畴的弱算法使用；本项为静态证据型，无需发送请求。

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

一旦数据库泄露（可与本文件 SQL 注入/报错回显结合），攻击者可在极短时间内还原用户明文口令，导致账户接管与口令复用扩散。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令这一安全用途。外部可达性体现在口令经 023.php:5 输入并在 023.php:12 哈希后落库；无需认证即可通过注入读取摘要，利用链闭合。注意此处归类为 weak_hash 而非 weak_crypto（后者指 DES/ECB 等加密算法缺陷）。

**修复建议**

改用 Argon2id、bcrypt 或 PBKDF2 等带盐、可调工作因子的口令哈希算法（PHP 可用 password_hash/password_verify）；迁移时对存量 MD5 摘要在下次登录时透明重哈希；禁止在任何新代码中使用 md5/sha1 处理口令。

**验证说明**

静态证据：入口 GET /023；source=repository/md5(；sink=023.php:12；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交 password_new → 023.php:5 读入 → 023.php:11 转义 → 023.php:12 md5() 单次无盐哈希 → 023.php:16-17 写入数据库；数据库泄露或注入读取后即可离线高速破解。
POC 备注：POC 仅为文本工件，不执行、不联网；本项为离线静态证据。

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
| safety_guard | 安全防护 | 3.12 | 是 |
| surface_mapper | 攻击面测绘 | 7.98 | 是 |
| deep_finder | LLM 深挖 | 10.97 | 是 |
| candidate_screener | 候选筛选 | 7.32 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 18.06 | 是 |
| coordinator | 管线协调 | 9.5 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
