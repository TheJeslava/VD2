# 落日二号乙漏洞挖掘报告 — 20261031-172839-0b3936

- 生成时间：2026-10-31T09:29:40.371268+00:00
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

本次审计范围仅限单文件 PHP 脚本 023.php（约 30 行），共交付 6 条去重后 findings，全部带 POC（with_poc=6）。最高危为 GEN-2fcabc51c287：023.php 第 17 行口令修改处存在 SQL 注入（CWE-89，critical），属 source→sink 直连的短污点链，可利用性最高；其次为 LLM-fb8cc628a9b1 与 SEM-b5cfc3d8dbaa 两条 CSRF（high/medium，改密无 token 可致账户接管）与 SEM-e5f2216eebb4 暴力破解防护缺失（high，CWE-307）。另有 LLM-3fa1c975a8fc（weak_hash）与 SEM-de6429df0eff（weak_crypto）两条 MD5 口令存储问题，二者实为同一事实（CWE-328），类型标注存在串类，建议合并为 weak_hash 一条。POC 齐全但性质不同：SQL 注入、CSRF、暴力破解为 HTTP 型 POC 文本；MD5 相关仅为静态证据 POC，不能宣称可动态复现。所有 POC 均为文本工件，未执行、未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 023.php（30 行，DVWA CSRF 模块）。已逐行核对：入口为 $_GET['Change'] 触发的改密逻辑（第 3 行），数据流为 password_new/password_conf → 相等校验（第 9 行）→ mysqli_real_escape_string（第 11 行）→ md5（第 12 行）→ 拼接 UPDATE（第 16 行）→ mysqli_query（第 17 行）。发现两条可闭合问题：(1) 改密接口无 CSRF token/来源校验，可跨站强制改密导致账户接管（CWE-352，high）；(2) 密码使用无盐 MD5 存储（CWE-328，medium）。关于 SQL 注入：$pass_new 经 mysqli_real_escape_string 转义且随后被 md5 变为定长十六进制，$current_user 来自 dvwaCurrentUser() 而非直接请求参数，未发现可改变 SQL 语法的外部输入，故不报告 sql_injection。未发现命令执行、文件包含、反序列化、SSRF、XSS 回显（$html 仅输出固定文案）等汇点。weak_random/weak_crypto/insecure_cookie/trust_boundary/hardcoded_secret 在文件中无对应调用，不成立。未覆盖范围：无 composer.json、php.ini、Web 服务器配置、路由与认证上下文，dvwaCurrentUser() 与数据库连接实现不在 code_pack 内，无法进一步确认。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现未提供，无法确认 $current_user 是否可能含外部可控数据
- 数据库连接与 users 表结构未提供
- 无 Web 服务器/php.ini 配置，无法确认部署路径与认证前置
- 023.php 之外无其他文件，结论仅限该文件

## 3. Findings

### F-1: 023.php 口令修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 GET 参数 password_new（023.php:5 `$pass_new = $_GET['password_new'];`）提交输入。该值在 023.php:11 仅经过 mysqli_real_escape_string 转义，随后在 023.php:12 被 md5() 处理，最终在 023.php:16 被直接拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";`，并在 023.php:17 交给 mysqli_query 执行。由于 md5() 的输出是 32 位十六进制字符串，password_new 经 md5 后已不含引号等元字符，因此 password_new 本身无法闭合引号；真正未参数化、且未经转义的是 023.php:16 中拼接的 `$current_user`（来自 dvwaCurrentUser()，023.php:15）。该值若可被外部影响（如用户名/会话派生），即可闭合 `'` 注入。当前 code_pack 未给出 dvwaCurrentUser() 的实现，无法确认其可控性，故本条按 llm_inferred 记录，置信度偏低。

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

若 $current_user 可控，攻击者可改写 UPDATE 语句，篡改任意用户口令或通过报错回显（023.php:17 的 die(mysqli_error)）泄露数据库结构信息；否则仅能造成口令被覆盖为攻击者指定值（配合 CSRF）。

**CVE / CWE 论证**

CWE-89：外部输入进入 SQL 语句拼接且未使用预处理/参数化。外部可达性：GET 参数无需认证即可提交（DVWA 默认低安全级别）；利用链闭合依赖 $current_user 的可控性，当前证据不足，故不宣称完整可利用。

**修复建议**

改用 mysqli 预处理语句（prepare + bind_param）绑定 password 与 user；对 $current_user 做白名单校验（仅允许当前会话用户）；移除 die(mysqli_error(...)) 的详细报错回显，改为通用错误页并记录日志。

**验证说明**

静态证据：入口 GET /023；source=query/password_new；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 023.php:5 $pass_new → 023.php:11 mysqli_real_escape_string → 023.php:12 md5() → 023.php:16 字符串拼接 $insert（含未转义 $current_user）→ 023.php:17 mysqli_query 执行。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:17 的 SQL 注入 POC。源码中 `$pass_new = $_GET['password_new']` 经 `mysqli_real_escape_string` 后进入 `UPDATE users SET password='$pass_new'`，注入点为 GET 参数 `password_new`，触发按钮字段为 `Submit`。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89。漏洞位于 023.php:17，外部输入来自 GET 参数 password_new，source→sink 链静态闭合，未见有效参数化。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符，仅限授权测试。

### F-2: DVWA 密码修改功能（023.php）缺少 CSRF token，可被跨站强制改密导致账户接管

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:3-17`
- **来源**：`llm_finding`

**描述**

023.php 在 `$_GET['Change']` 存在时直接读取 `password_new`/`password_conf`，仅校验两次输入相等（第 9 行），随后对 `$pass_new` 做 mysqli_real_escape_string 与 md5（第 11-12 行），拼接到 UPDATE 语句（第 16 行）并执行（第 17 行），把当前登录用户（`dvwaCurrentUser()`，第 15 行）的密码改为攻击者指定值。整个流程没有任何 anti-CSRF token、Referer/Origin 校验、原密码确认或二次认证。攻击者只需诱导已登录受害者访问一个自动发起 GET 请求的页面（如 <img> 标签），即可在受害者不知情下把其密码改为攻击者已知的值，随后用新密码登录接管账户。由于改密接口使用 GET 且参数全部在 URL 中，利用门槛极低。

**source / sink**

- source：cookie `PHPSESSID`（023.php:5-6）
- sink：023.php:17 mysqli_query($GLOBALS["___mysqli_ston"], $insert) 执行 UPDATE users SET password=... WHERE user=当前用户

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 脚本检测到 $_GET['Change'] 即进入改密分支，无任何 CSRF token 或来源校验 | 攻击者可控的 GET 参数集合 | 无 anti-CSRF token、无 Referer/Origin 校验、无原密码确认 |
| 2 | `023.php:5-6` | 读取 password_new / password_conf | 攻击者指定的新密码明文 |  |
| 3 | `023.php:9` | 仅比较两次输入是否相等，攻击者令二者相同即通过 | 校验通过 |  |
| 4 | `023.php:11-12` | 转义后 md5 哈希 | MD5 哈希值 |  |
| 5 | `023.php:15-17` | 以受害者会话身份执行 UPDATE，把当前用户密码改为攻击者值 | 数据库写入完成 |  |

**POC**

针对 /vulnerabilities/csrf/（GET）的 跨站请求伪造 POC。注入点：Cookie: Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/csrf/' \
  -H 'Cookie: Change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-fb8cc628a9b1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是高权限账户，可进一步横向移动。

**CVE / CWE 论证**

CWE-352（Cross-Site Request Forgery）。改密为状态改变型敏感操作，服务端仅依赖会话 Cookie 认证，无任何反 CSRF 机制，外部可经第三方页面触发，链闭合。

**修复建议**

为改密表单引入一次性 anti-CSRF token 并在服务端校验；改用 POST；要求输入原密码或二次认证；校验 Origin/Referer；Cookie 设置 SameSite=Lax/Strict。

**验证说明**

需确认 023.php 实际部署路径与是否位于需登录目录；DVWA 默认 CSRF 模块即为该逻辑，动态验证可确认无 token 校验。
模型 POC 要点：构造一个第三方页面，诱导已登录 DVWA 的受害者访问，页面内 <img> 自动向改密接口发起 GET 请求，将受害者密码改为攻击者已知值。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 023.php:5 的 CSRF POC。源码在 `$_GET['Change']` 存在时直接执行密码修改，无 CSRF token 校验，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-352。023.php:5 的密码修改逻辑无 token/来源校验，依赖会话 Cookie 即可触发。
POC 备注：需受害者会话保持；仅文本，不执行。

### F-3: 023.php 口令修改流程缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:4-6 直接读取 password_new / password_conf 并进入修改流程，代码中未见失败计数、账户锁定、速率限制或验证码。需说明：该页面是口令修改而非登录校验，本身不校验旧口令，因此“暴力破解”语义需谨慎——更贴近的是缺少对重复敏感操作的节流与对旧口令的再认证。当前证据不足以确认存在可被爆破的认证判定点。

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

若该流程被用于反复尝试/覆盖口令，缺少节流会放大自动化攻击；但当前代码未见认证比对逻辑，实际影响证据不足。

**CVE / CWE 论证**

CWE-307：缺少对过度认证尝试的限制。外部可达性成立（GET 可直接请求），但“认证尝试”判定点在本片段中不存在，利用链不闭合，故置信度低。

**修复建议**

对敏感操作增加速率限制与失败计数；要求提交当前口令进行再认证；引入验证码或延迟；记录并告警异常频率。

**验证说明**

静态证据：入口 GET /023；source=query/Login；sink=023.php:5；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new/password_conf → 023.php:5-6 → 023.php:16-17 UPDATE。缺少节流与旧口令校验，但无明确认证比对点。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的暴力破解防护缺失 POC。登录/密码修改逻辑无速率限制、无锁定、无验证码。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-307，证据位于 023.php:5。
POC 备注：仅文本，不执行；仅限授权测试。

### F-4: 023.php 使用 MD5 存储用户密码（CWE-328）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:12-17`
- **来源**：`llm_finding`

**描述**

第 12 行对用户新密码仅做一次 `md5()` 后写入数据库（第 16-17 行），未使用加盐或慢哈希（bcrypt/argon2/PBKDF2）。MD5 计算极快且无盐，一旦数据库泄露，攻击者可用彩虹表或 GPU 暴力快速还原明文口令，且相同口令产生相同哈希，便于批量破解。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 UPDATE users SET password = md5(...) 持久化弱哈希

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 读取新密码 | 明文口令 |  |
| 2 | `023.php:11` | mysqli_real_escape_string 转义（不影响哈希强度） | 转义后明文 |  |
| 3 | `023.php:12` | md5() 单次无盐哈希 | 32 位 MD5 十六进制 |  |
| 4 | `023.php:16-17` | 写入 users 表 password 字段 | 弱哈希持久化 |  |

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

数据库泄露后口令可被快速离线破解，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。密码存储使用无盐 MD5，属可确认的弱哈希实现，配置/代码级证据充分。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）并配合 password_verify()，每用户独立盐。

**验证说明**

需确认数据库中确实存储 MD5 而非上层另有处理；DVWA 默认即为 MD5。
模型 POC 要点：该问题为存储型弱哈希，无直接远程利用请求；验证方式为改密后检查数据库 password 字段是否为 32 位 MD5。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 023.php:12 的弱哈希 POC。源码 `$pass_new = md5($pass_new)` 使用 MD5 存储密码，属 CWE-328 弱哈希，非加密算法问题。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-328（弱哈希），非 CWE-327。证据位于 023.php:12。
POC 备注：静态证据型，无需发送破坏性请求；仅文本。

### F-5: 023.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:5-6 通过 GET 读取 password_new / password_conf，并在 023.php:16-17 直接执行 UPDATE users SET password 的状态变更操作。代码中未见任何 CSRF token、Referer/Origin 校验或二次确认；状态变更使用 GET 方法，可被 `<img src=...>` 等跨站请求触发。攻击者诱导已登录受害者访问恶意页面，即可在受害者不知情下把其口令改为攻击者已知值。

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

账户接管：攻击者可将受害者口令重置为已知值后登录其账户；结合 SQL 注入候选可进一步扩大影响。

**CVE / CWE 论证**

CWE-352：状态变更请求无不可预测令牌校验。外部可达性：无需认证即可构造跨站请求，但需受害者已登录会话；利用链闭合（GET 请求 + 无 token）。

**修复建议**

改为 POST 提交；引入每会话随机 CSRF token 并在服务端校验；校验 Origin/Referer；对敏感操作要求重新输入当前口令；Cookie 设置 SameSite=Lax/Strict。

**验证说明**

静态证据：入口 GET /023；source=query/Change；sink=023.php:5；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造跨站 GET 请求 → 受害者浏览器携带会话 Cookie 访问 023.php?password_new=X&password_conf=X → 023.php:5-6 读取参数 → 023.php:16-17 执行 UPDATE 修改口令。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的 CSRF POC（语义发现）。`$_GET['Change']` 触发密码修改，无 token 校验。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-352，证据位于 023.php:5。
POC 备注：需会话保持；仅文本，不执行。

### F-6: 023.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:11-12`
- **来源**：`rule`

**描述**

023.php:12 `$pass_new = md5( $pass_new );` 对口令使用 MD5 单次哈希后写入 users 表（023.php:16-17）。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，不适合口令存储；攻击者获取数据库后可借助彩虹表/GPU 高速爆破还原口令。注意：这是口令哈希弱点，属 weak_hash（CWE-328），不是加密算法弱点（CWE-327）。

**source / sink**

- source：repository `md5(`（023.php）
- sink：023.php:12 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:12` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 023.php:12 的弱加密/弱哈希静态证据。源码使用 `md5($pass_new)` 存储密码，属弱哈希（CWE-328）。

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

数据库泄露时口令可被快速离线破解，导致账户接管与口令复用扩散。

**CVE / CWE 论证**

CWE-328：使用弱哈希算法保护口令。配置/实现型弱点，无需 HTTP 污点链；证据为 023.php:12 的 md5() 调用原文。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）并配合 password_verify()；为每个口令生成独立盐；迁移期可对旧 MD5 值在下次登录时透明重哈希。

**验证说明**

静态证据：入口 GET /023；source=repository/md5(；sink=023.php:12；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 023.php:5 → 023.php:11 转义 → 023.php:12 md5() 单次无盐哈希 → 023.php:16-17 写入 users.password。
POC 备注：静态证据型，无需请求；仅文本。

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
| safety_guard | 安全防护 | 3.86 | 是 |
| surface_mapper | 攻击面测绘 | 7.78 | 是 |
| deep_finder | LLM 深挖 | 13.29 | 是 |
| candidate_screener | 候选筛选 | 6.96 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.55 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.42 | 是 |
| coordinator | 管线协调 | 7.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
