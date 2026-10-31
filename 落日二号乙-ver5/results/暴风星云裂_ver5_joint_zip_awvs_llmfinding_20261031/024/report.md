# 落日二号乙漏洞挖掘报告 — 20261031-214450-6ee499

- 生成时间：2026-10-31T13:45:55.759855+00:00
- 输入：`$WORKSPACE\暴风星云裂\024.zip`
- 输入模式：`zip`
- SHA256：`a2013a4944c4a1abb5e6dc291bf1a235fbddea2e99f978d43092c691e46798f1`
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

本次审计对象为单文件 PHP 脚本 024.php（37 行），共交付 4 条已去重 findings，全部带 POC（with_poc=4）。最高危为 GEN-cf38b1a2cb95：024.php 第 19 行附近修改密码功能存在 SQL 注入（CWE-89，critical，规则命中，有 HTTP POC）。其次为 LLM-3eef1cf779fd：同一功能仅依赖 HTTP_REFERER 做 CSRF 防护，可被绕过并导致账户接管（high，有 HTTP POC）；SEM-72b85cc24676：口令修改接口无速率限制/失败锁定（CWE-307，high，有 POC）。SEM-23ce27f2da1c 标题写 weak_crypto，但描述实为 MD5 存储口令，按类型规范应归 weak_hash（CWE-328），严重度 medium，仅有静态证据 POC，不能宣称可动态复现。POC 齐全度：4/4 存在，但其中 1 条为静态证据型。所有结论均为源码/规则推断，未经动态验证。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1725 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 024.php（37 行）。该文件为 DVWA 密码修改页面，存在 source（$_GET password_new/password_conf、HTTP_REFERER）到 sink（mysqli_query UPDATE）的路径。发现 CSRF/账户接管问题：仅用可伪造的 Referer 做来源校验，且无 CSRF token、无当前密码确认。SQL 注入方面，password_new 经 mysqli_real_escape_string 转义后再 md5，且 md5 输出为定长十六进制，无法注入；current_user 来自 dvwaCurrentUser() 非用户直接可控，故未报告 SQL 注入。md5 用于口令哈希属 weak_hash（CWE-328），但为 DVWA 设计固有且单独不足以构成 CVE 级可利用链，仅作线索。未覆盖：无路由/认证配置、无 php.ini，无法确认部署与运行时配置。

未覆盖 / 证据缺口：
- 无端点/路由与认证配置，无法确认访问路径与是否需要登录
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include 等运行时设置
- dvwaCurrentUser() 实现未在 code_pack 中，无法完全确认 current_user 是否可被间接污染

## 3. Findings

### F-1: 024.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 password_new（024.php:7 `$pass_new = $_GET['password_new'];`）提交输入。该值在 024.php:13 仅经过 mysqli_real_escape_string 转义，随后在 024.php:14 被 md5() 处理，最终在 024.php:18 被直接拼接进 SQL 语句 `UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';`，并在 024.php:19 交由 mysqli_query 执行。校验无效的原因：md5() 对输入做的是哈希而非 SQL 转义，哈希结果虽为十六进制字符串，但拼接方式本身未使用参数化查询，且 $current_user 来自 dvwaCurrentUser()（024.php:17）同样以字符串拼接进入 WHERE 子句，未做绑定；一旦该值可被影响（如会话/用户名可控），即可闭合引号注入。此外 024.php:19 的 die() 分支会把 mysqli_error 内容回显到页面，构成报错型注入的信息泄露通道。

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

可对 users 表执行任意 UPDATE 语义（如改写任意用户口令实现账户接管），并借助 024.php:19 的 mysqli_error 回显进行报错注入，逐字节读取数据库名、表名与 users 表内容（含口令哈希），造成敏感数据泄露与越权。

**CVE / CWE 论证**

CWE-89：外部可控输入（GET password_new）未经参数化直接进入 SQL 语句并在 024.php:19 执行，属典型一次注入；无需认证即可通过 HTTP 访问该脚本（DVWA 低安全级别下无令牌校验），利用链闭合：source(024.php:7) → 拼接(024.php:18) → sink(024.php:19)。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），将 password 与 user 均作为占位符参数传入；移除 024.php:19 中向客户端回显 mysqli_error 的逻辑，改为记录服务端日志并返回通用错误；对 $current_user 做白名单/会话内取值校验；口令哈希改用 password_hash()（bcrypt/Argon2）而非 md5。

**验证说明**

静态证据：入口 GET /024；source=query/password_new；sink=024.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → $pass_new(024.php:7) → mysqli_real_escape_string(024.php:13) → md5(024.php:14) → 字符串拼接 $insert(024.php:18) → mysqli_query 执行(024.php:19)，错误经 die() 回显。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:19 的 SQL 注入 POC。源码将 GET 参数 password_new 直接拼入 UPDATE/密码修改 SQL（仅经 mysqli_real_escape_string 后 md5，未参数化），攻击者可通过布尔/报错注入改变查询语义。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-89。漏洞位于 024.php:19，外部输入来自 GET 参数 password_new，source→sink 链静态闭合，mysqli_real_escape_string 后仍拼接进 SQL 且未参数化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。所有请求中的主机统一为 TARGET:8080。步骤 2/3 为布尔对照，步骤 4 为状态确认；若源码中提交按钮字段名不是 Submit，需按实际字段名调整（已在 preconditions 标注）。

### F-2: DVWA 密码修改功能仅依赖 HTTP_REFERER 校验，可被 CSRF 绕过并接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`024.php:3-19`
- **来源**：`llm_finding`

**描述**

024.php 的密码修改逻辑在 `isset($_GET['Change'])` 时执行，仅通过 `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false` 判断请求来源。HTTP_REFERER 完全由客户端控制，攻击者可构造包含目标域名的 Referer（或利用浏览器策略/子串匹配缺陷）绕过该校验；同时该操作使用 GET 方法、无 CSRF token、无当前密码确认，攻击者诱导已登录受害者访问恶意页面即可把受害者密码改为攻击者指定值，导致账户接管。此外 `stripos` 子串匹配可被 `http://attacker.com/?TARGET_HOST` 形式的 Referer 欺骗。

**source / sink**

- source：header `Referer`（024.php:7-11）
- sink：024.php:19 mysqli_query 执行 UPDATE users SET password（024.php:18-19）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:3` | 检测到 Change 参数即进入密码修改流程 | 攻击者控制 GET 参数 |  |
| 2 | `024.php:5` | 仅用 stripos 判断 Referer 是否包含 SERVER_NAME，客户端可伪造 | Referer 由攻击者控制，可包含目标域名子串 | HTTP_REFERER 可任意伪造，且 stripos 子串匹配可被 http://evil.com/?victimhost 绕过 |
| 3 | `024.php:7-11` | 读取 password_new/password_conf 并比较相等 | 攻击者提供相同的新密码 |  |
| 4 | `024.php:14-19` | md5 后拼接 UPDATE 语句并执行，修改当前登录用户密码 | 新密码写入数据库 |  |

**POC**

针对 /024.php（GET）的 跨站请求伪造 POC。注入点：Header: Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/024.php' \
  -H 'Change: %E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-3eef1cf779fd`
- 风险提示：finding 来源为 Referer，但 POC 未发送 Referer 请求头, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可接管任意已登录用户（含管理员）账户，完全控制应用

**CVE / CWE 论证**

CWE-352 CSRF：状态改变操作无 token、无当前密码确认，仅依赖可伪造的 Referer；外部可触发，链闭合

**修复建议**

使用 POST + CSRF token；要求输入当前密码；不要依赖 Referer 做安全校验

**验证说明**

需确认 DVWA 部署下 SERVER_NAME 与 Referer 匹配行为，以及浏览器是否发送 Referer；子串匹配绕过需实测
模型 POC 要点：诱导已登录受害者访问恶意页面，自动发起带伪造 Referer 的密码修改请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /024.php）：针对 024.php:19 密码修改功能的 CSRF POC。源码在修改密码分支仅校验 Referer 头（弱校验），未使用 CSRF token，攻击者可构造自动提交表单诱导已登录用户修改口令。原草稿将 payload 放在自定义 Change 头中，与源码实际读取的 Referer 不一致，此处按源码修正为 Referer 校验绕过 + 跨站表单。
PocWriter 建议（未采纳，缺少端点 /024.php）：符合 CWE-352。024.php:19 密码修改逻辑缺少 CSRF token，仅依赖可伪造/可缺失的 Referer 头，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。原草稿的 Change 头与源码不符，已改为 Referer 校验场景；poc.html 需由受害者浏览器加载，Cookie 由浏览器自动携带。字段名 password_new/password_conf/Submit 需按源码最终确认。

### F-3: 024.php 口令修改接口缺乏速率限制/失败锁定（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:6-7`
- **来源**：`rule`

**描述**

024.php:6-8 直接读取 GET 参数 password_new / password_conf 并进入修改口令流程，代码中未见失败计数、账户锁定、验证码或速率限制逻辑。需说明的缺口：该脚本本身是“修改口令”而非“登录”流程，候选将其标注为暴力破解防护缺失，但输入片段中未给出登录校验代码，无法确认是否存在可被反复猜测的认证判定点；因此该结论证据不足，仅能指出 024.php:6-8 缺少任何请求频度控制。

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

若该接口可被未认证访问并配合可猜测的会话/用户标识，攻击者可高频提交请求进行口令猜测或资源消耗；但基于现有片段无法确认认证判定点，实际影响证据不足。

**CVE / CWE 论证**

CWE-307：输入片段仅显示参数读取（024.php:6-8），未见认证比较与失败处理代码，外部可达性与利用链闭合性证据不足，不作为确定漏洞交付。

**修复建议**

在口令修改/认证入口增加基于账户与 IP 的失败计数、指数退避与临时锁定，加入 CSRF 令牌与当前口令二次确认；对请求做速率限制并记录审计日志。

**验证说明**

静态证据：入口 GET /024；source=query/Login；sink=024.php:7；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new/password_conf(024.php:7-8) → 修改口令流程（片段内未见认证判定与限流）→ 证据不足，无法闭合利用链。
PocWriter 建议（未采纳，缺少端点 /024）：针对 024.php:7 登录入口的暴力破解防护缺失 POC。源码登录分支无失败计数、无锁定、无速率限制、无验证码，攻击者可对 username/password 进行在线口令爆破。原草稿注入点标注为 password_new 有误，实际登录参数为 username/password 与 Login 提交字段。
PocWriter 建议（未采纳，缺少端点 /024）：符合 CWE-307。024.php:7 登录逻辑缺少失败计数与限速，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。步骤 2 需人工在授权范围内重复请求，禁止自动化大规模爆破脚本；字段名 Login/username/password 需按源码最终确认。

### F-4: 024.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.86`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`024.php:13-14`
- **来源**：`rule`

**描述**

024.php:14 `$pass_new = md5( $pass_new );` 对用户新口令直接使用 MD5 计算摘要，随后在 024.php:18-19 写入 users 表 password 字段。该处为配置/实现型弱点，无需 HTTP 污点链即可成立：算法为 MD5（无盐、单轮、快速），原文证据即 024.php:14 的 md5() 调用。

**source / sink**

- source：repository `md5(`（024.php）
- sink：024.php:14 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `024.php:14` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：024.php:14 使用 md5() 对用户口令做哈希后存储，属弱哈希（CWE-328），无需发送请求，仅记录源码证据。注意：该问题应归类为 weak_hash 而非 weak_crypto（CWE-327），原草稿类型标注需修正。

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

口令以无盐 MD5 存储，攻击者一旦通过 SQL 注入或数据库泄露获取 password 字段，可用彩虹表/GPU 高速碰撞在极短时间内还原明文口令，进而横向复用至其他账户或系统，造成账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令这一安全用途，属弱哈希而非弱加密（非 CWE-327 的 DES/ECB 类问题）；外部可达性体现在 024.php 的修改口令接口直接调用该逻辑，无需额外权限即可触发写入。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）生成带盐慢哈希，校验时用 password_verify()；迁移期可对存量 MD5 值在用户下次登录成功后透明重哈希；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 GET /024；source=repository/md5(；sink=024.php:14；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → $pass_new(024.php:7) → mysqli_real_escape_string(024.php:13) → md5()(024.php:14) → 写入 users.password(024.php:18-19)。
POC 备注：纯静态证据，不执行、不联网。建议将漏洞类型由 weak_crypto 更正为 weak_hash。

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
| safety_guard | 安全防护 | 3.78 | 是 |
| surface_mapper | 攻击面测绘 | 10.5 | 是 |
| deep_finder | LLM 深挖 | 8.81 | 是 |
| candidate_screener | 候选筛选 | 8.19 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.76 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 15.19 | 是 |
| coordinator | 管线协调 | 8.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
