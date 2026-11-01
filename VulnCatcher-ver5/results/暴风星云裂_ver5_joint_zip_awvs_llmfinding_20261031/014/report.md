# 落日二号乙漏洞挖掘报告 — 20261031-214202-2e1e27

- 生成时间：2026-10-31T13:43:09.071842+00:00
- 输入：`$WORKSPACE\暴风星云裂\014.zip`
- 输入模式：`zip`
- SHA256：`d641901c9e40d65807bfa31417d7720c470dd3f58356dd114ccf3915412bbff4`
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

本次审计范围是单文件 PHP 项目 014.php（75 行），共交付 6 条去重后的 findings，全部带 POC（with_poc=6）。最高危的是 014.php 修改口令处的 SQL 注入（GEN-74a307a2a91c，critical，CWE-89，sink 位于 014.php:61 附近），其次是同一处 step=2 密码修改流程缺少 CSRF token 导致可被跨站强制改密并接管账户（LLM-b52a2b477f7b，high），以及 step 参数绕过验证码流程（SEM-161a1ab1f6bd，high，CWE-804）。另有 3 条中危：无盐 MD5 存储口令（LLM-75da972f9cc2 / SEM-f257349cbc66，同一问题被 LLM 与规则各报一次，属 weak_hash CWE-328，不应归为 weak_crypto CWE-327）与规则侧 CSRF（SEM-16d21f2078ab）。POC 齐全但性质不同：SQL 注入、CSRF、验证码绕过具备 HTTP 请求语义，可写成 HTTP POC 文本；MD5 弱哈希只有静态代码证据 POC，不能宣称可动态复现。本次未做任何动态验证，所有结论均为源码推断（llm_inferred / rule）。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 014.php（75 行，DVWA CSRF 模块）。发现两条链：(1) step=2 密码修改分支缺少 CSRF token 且可跳过 CAPTCHA，构成 CSRF 账户接管（高危，链闭合）；(2) 密码以无盐 MD5 存储（中危，配置型）。SQL 注入方面：第 56 行对 $pass_new 做了 mysqli_real_escape_string，且第 60 行 user 来自 dvwaCurrentUser() 而非直接用户输入，未发现可闭合的 SQL 注入。第 32-33 行将 $pass_new/$pass_conf 反射进 HTML，但值来自用户自身提交且未跨用户持久化，XSS 价值低未单列。未覆盖：无 composer/依赖、无 php.ini、无路由与认证配置，无法评估第三方库与部署层风险；dvwaCurrentUser()、recaptcha_check_answer()、$_DVWA 定义不在 code_pack 内，视为外部依赖。

未覆盖 / 证据缺口：
- dvwaCurrentUser()/recaptcha_check_answer()/$_DVWA 定义不在 code_pack
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include 等
- 无数据库 schema 与连接配置
- 无认证/会话代码，越权与 trust_boundary 未评估

## 3. Findings

### F-1: 014.php 修改口令处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（014.php:8 读取 $_POST['password_new']）提交口令，代码在 014.php:56 仅用 mysqli_real_escape_string 处理，随后 014.php:57 做 md5，再在 014.php:60 以字符串拼接方式构造 UPDATE `users` SET password = '$pass_new' WHERE user = '...'，最终在 014.php:61 交给 mysqli_query 执行。由于 $pass_new 是 md5 后的 32 位十六进制串，正常情况下无法携带引号等元字符，因此该路径的注入可行性依赖 md5 之前/之后是否存在可绕过转义的分支（例如 dvwa 低安全级别下 md5 与转义顺序差异），当前 code_pack 仅给出 56-61 行，无法确认是否存在未转义分支，故按 llm_inferred 记录。

**source / sink**

- source：query `password_new`（014.php:50）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（POST）的 SQL 注入 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-74a307a2a91c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若注入成立，攻击者可改写 users 表中任意用户（含 admin）的 password 字段，实现账户接管/越权登录；错误信息经 die() 回显（014.php:61）还会泄露数据库结构与 SQL 语句细节。

**CVE / CWE 论证**

CWE-89：外部可控输入进入 SQL 语句拼接且未使用参数化查询。外部可达性：014.php 为 Web 入口，POST 参数无需额外权限即可提交（需已登录会话，属 DVWA 设计前提）；利用链为 password_new → $pass_new → $insert → mysqli_query，链路在文件内闭合。但 md5 归一化削弱了元字符可控性，故置信度偏低。

**修复建议**

改用预处理语句：$stmt = mysqli_prepare($link, 'UPDATE users SET password = ? WHERE user = ?'); mysqli_stmt_bind_param($stmt, 'ss', $pass_new, dvwaCurrentUser()); 并移除 die(mysqli_error()) 的详细错误回显，改为记录日志并返回通用错误；口令哈希改用 password_hash()。

**验证说明**

静态证据：入口 POST /014；source=query/password_new；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new（014.php:8）→ mysqli_real_escape_string（014.php:56）→ md5（014.php:57）→ 字符串拼接 $insert（014.php:60）→ mysqli_query 执行（014.php:61）。校验无效点在于使用转义而非参数化，且转义与哈希顺序可能使转义失效；最终危险操作是数据库 UPDATE 语句执行。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:61 的 SQL 注入 POC。源码中 POST 参数 password_new 经 mysqli_real_escape_string 后进入 md5()，随后拼入 UPDATE 语句（014.php:56-61），注入点为 POST 参数 password_new，触发按钮字段为 Submit。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89。漏洞位于 014.php:61，外部输入来自 POST 参数 password_new，source→sink 链静态闭合，未发现有效净化。
POC 备注：仅文本工件，不执行；TARGET 为占位符；仅限授权测试。

### F-2: DVWA CSRF 模块：step=2 密码修改缺少 CSRF token，可被跨站强制改密并接管账户

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改流程分为 step=1（校验 CAPTCHA）与 step=2（实际写库）。step=2 分支（第 45-73 行）只检查 $_POST['Change'] 与 $_POST['step']=='2'，随后直接读取 $_POST['password_new']/$_POST['password_conf']，两者相等即执行 UPDATE users SET password=md5(...) WHERE user=dvwaCurrentUser()。整个 step=2 分支没有任何 CSRF token、Referer/Origin 校验或二次身份确认；CAPTCHA 只在 step=1 校验，攻击者可完全跳过 step=1 直接提交 step=2。攻击者构造一个自动提交的跨站表单，诱导已登录受害者访问，即可把受害者密码改为攻击者已知值，随后用新密码登录接管账户。

**source / sink**

- source：body `step`（014.php:50-54）
- sink：014.php:61 014.php:60-61 拼接 UPDATE users SET password=md5(...) 并 mysqli_query 执行

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | step=2 分支仅以 $_POST['Change'] 存在且 step=='2' 作为进入条件，无任何 CSRF token 校验 | 攻击者完全控制 POST 体，无需经过 step=1 的 CAPTCHA | CAPTCHA 校验位于 step=1 分支（第 12-23 行），step=2 分支不重复校验，直接跳过 |
| 2 | `014.php:50-54` | 读取 password_new/password_conf 并比较是否相等 | 攻击者令两者相同即可通过 |  |
| 3 | `014.php:57` | 对密码做 md5 后拼入 SQL | md5(攻击者密码) |  |
| 4 | `014.php:60-61` | 以当前会话用户身份执行 UPDATE，修改其密码 | 受害者账户密码被改为攻击者已知值 | 无 token/Origin 校验，浏览器自动携带受害者会话 Cookie |

**POC**

针对 /vulnerabilities/csrf/ (014.php)（POST）的 跨站请求伪造 POC。注入点：GET 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/ (014.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/csrf/ (014.php)?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-b52a2b477f7b`
- 风险提示：请求未体现 HTTP 方法 POST, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是管理员则导致后台失陷。

**CVE / CWE 论证**

CWE-352 跨站请求伪造。step=2 分支无 token/Origin 校验，CAPTCHA 可被跳过，外部可触发，链闭合。

**修复建议**

为密码修改表单引入一次性 CSRF token 并在服务端校验；校验 Origin/Referer；step=2 重新要求当前密码或 CAPTCHA。

**验证说明**

需确认部署中该脚本 URL 与 DVWA 会话机制；CAPTCHA 跳过依赖 step=2 分支独立可达，源码已证实。
模型 POC 要点：构造自动提交的跨站 HTML 表单，诱导已登录 DVWA 的受害者访问，直接提交 step=2 修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 014.php:61 的 CSRF POC。密码修改流程（password_new/password_conf/Change）缺少 CSRF token 校验，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-352。漏洞位于 014.php:61，密码修改流程无 CSRF token 校验。
POC 备注：仅文本工件，不执行；TARGET 为占位符；仅限授权测试。

### F-3: 014.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

014.php:3 以 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) 作为流程分支，step 完全由客户端 POST 控制；攻击者可直接提交 step=1 及最终口令字段，跳过验证码展示/校验阶段，直接进入 014.php:8 起的改密逻辑。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（POST）的 验证码绕过 POC。注入点：POST 参数 Change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-161a1ab1f6bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

验证码保护形同虚设，可被脚本化批量提交改密请求，配合 CSRF 或暴力尝试放大危害。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/流程状态由客户端控制。外部可达性：POST 参数 step 无需认证即可设置；利用链为 step → 分支跳过 → 014.php:8 取值 → 014.php:61 执行。当前片段未展示验证码校验代码，故为推断。

**修复建议**

将验证码校验放在服务端会话状态机中，不信任客户端 step；验证码一次性使用并在校验后立即失效；对改密接口做频率限制与失败计数。

**验证说明**

静态证据：入口 POST /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST step=1 + Change=Change（014.php:3）→ 跳过验证码阶段 → 014.php:8-9 读取新口令 → 014.php:60-61 更新数据库。校验无效点在于流程状态由请求参数决定，最终危险操作是未经验证码的口令变更。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:3 的验证码绕过 POC。密码修改流程未强制校验 g-recaptcha-response，可提交空验证码完成修改。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804。漏洞位于 014.php:3，验证码校验缺失。
POC 备注：仅文本工件，不执行；TARGET 为占位符；仅限授权测试。

### F-4: 密码使用无盐 MD5 存储（014.php:57）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:57-60`
- **来源**：`llm_finding`

**描述**

第 57 行 $pass_new = md5($pass_new) 后写入 users.password。MD5 为快速哈希且无盐，一旦数据库泄露可被彩虹表/GPU 快速破解，且相同密码产生相同哈希。

**source / sink**

- source：body `password_new`（014.php:50）
- sink：014.php:60 014.php:60-61 将 md5 值写入 users.password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 读取新密码 | 明文密码 |  |
| 2 | `014.php:57` | 无盐 MD5 | md5 哈希 |  |
| 3 | `014.php:60-61` | 写入数据库 | 弱哈希持久化 |  |

**POC**

针对 /vulnerabilities/csrf/ (014.php)（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csrf/ (014.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/csrf/ (014.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-75da972f9cc2`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后密码可被快速还原，导致账户接管扩散。

**CVE / CWE 论证**

CWE-328 使用弱哈希。源码明确使用无盐 md5 存储密码。

**修复建议**

改用 password_hash()/password_verify()（bcrypt/argon2）并加盐。

**验证说明**

属配置/算法型，需确认生产是否沿用该存储方式。
模型 POC 要点：配置型弱哈希，无独立 HTTP 利用；证据为存储算法本身
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：针对 014.php:60 的弱哈希 POC。源码在 014.php:57 使用 md5($pass_new) 存储密码，属弱哈希（CWE-328）。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csrf/）：符合 CWE-328。漏洞位于 014.php:60，md5() 用于密码存储。
POC 备注：仅文本工件，不执行；TARGET 为占位符；仅限授权测试。

### F-5: 014.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:56-57`
- **来源**：`rule`

**描述**

014.php:57 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式写入 users.password（014.php:60-61 的 UPDATE）。该值随后用于口令校验，属于安全用途的弱哈希，而非加密算法误用。

**source / sink**

- source：repository `md5(`（014.php）
- sink：014.php:57 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:57` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：014.php:57 使用 md5($pass_new) 处理密码，属弱加密/弱哈希（CWE-327/328）。无需发送请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 014.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-f257349cbc66`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

无盐 MD5 可被彩虹表/GPU 暴力快速还原，数据库泄露后用户口令近乎明文暴露；相同口令产生相同哈希，便于横向撞库。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash），不是 CWE-327。证据为 014.php:57 的 md5() 调用原文；属实现型弱点，无需 HTTP 污点链即可成立。外部可达性体现在任意口令修改请求都会生成 MD5 摘要落库。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）存储，校验使用 password_verify()；对历史 MD5 记录在用户下次登录时透明升级；禁止在代码中直接调用 md5/sha1 处理口令。

**验证说明**

静态证据：入口 POST /014；source=repository/md5(；sink=014.php:57；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new（014.php:8）→ 转义（014.php:56）→ md5()（014.php:57）→ 拼入 UPDATE 写入 users.password（014.php:60-61）。根因是哈希算法选择不当，与注入链相互独立。
POC 备注：仅文本工件，不执行；仅限授权测试。

### F-6: 014.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:3 仅校验 isset($_POST['Change']) 与 $_POST['step']=='1'，随后 014.php:8-9 直接读取 $_POST['password_new'] / $_POST['password_conf'] 并执行口令更新，全程未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造自动提交表单，诱导已登录受害者在不知情下把口令改为攻击者指定值。

**source / sink**

- source：query `Change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/014?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-16d21f2078ab`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

账户接管：受害者会话有效时被静默改密，攻击者随后用新口令登录；若受害者为管理员则导致整站失陷。

**CVE / CWE 论证**

CWE-352：状态改变请求缺乏不可预测令牌与来源校验。外部可达性：任意第三方页面可向 014.php 发起跨站 POST；无需认证即可投递请求，仅依赖受害者浏览器携带会话 Cookie。利用链在文件内闭合（无 token 校验点）。

**修复建议**

在表单中引入每会话随机 CSRF token 并在服务端比对（hash_equals），同时校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；改密等敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /014；source=query/Change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面自动提交 POST（Change=Change, step=1, password_new=..., password_conf=...）→ 014.php:3 通过条件判断 → 014.php:8-9 取值 → 014.php:60-61 更新数据库。校验无效点在于无 token/来源校验，最终危险操作是口令字段被改写。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php:8 的 CSRF POC。密码修改流程缺少 CSRF token，攻击者可诱导已登录用户提交修改密码请求。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352。漏洞位于 014.php:8，密码修改流程无 CSRF token 校验。
POC 备注：仅文本工件，不执行；TARGET 为占位符；仅限授权测试。

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
| `captcha_bypass` | CWE-804 |  | 1 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.15 | 是 |
| surface_mapper | 攻击面测绘 | 7.88 | 是 |
| deep_finder | LLM 深挖 | 12.22 | 是 |
| candidate_screener | 候选筛选 | 7.32 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.52 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 13.46 | 是 |
| coordinator | 管线协调 | 9.38 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
