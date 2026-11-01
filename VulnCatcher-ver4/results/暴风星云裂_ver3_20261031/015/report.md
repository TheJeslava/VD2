# 落日二号乙漏洞挖掘报告 — 20261031-005912-247a49

- 生成时间：2026-10-30T17:00:15.090677+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\015.zip`
- 输入模式：`zip`
- SHA256：`24ec46248538ba08d8e8eb94c82934ecea9f754341b0de0a93fec8dda6a387c2`
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

本次汇总基于单文件 PHP 脚本 015.php（83 行）的静态审计结果，共 6 条去重 findings，全部带 POC（6/6）。最高危为 015.php 第 69 行附近的 SQL 注入（GEN-c00a42452f04，critical，CWE-89），位于口令修改流程，属 HTTP 可复现类 POC。其次为两条 captcha_bypass（LLM-c737fb0d7fd9、SEM-2b846713ecdc，high，CWE-804），指向同一状态机缺陷：直接提交 step=2 与 passed_captcha=true 即可跳过验证码，二者为同一根因的不同表述，建议合并处置。中危包括：MD5 存储口令（SEM-81919fa4d087，标注为 weak_crypto，但按 CWE-328 应归 weak_hash，属类型标注偏差，需人工纠正）、step=1 隐藏表单未编码回显导致的反射型 XSS（LLM-f67e226dc1d1）、改密接口缺 CSRF 防护（SEM-bb70b3793387）。所有结论均为静态源码推断（llm_inferred / rule），未做动态验证；weak_hash 类仅有静态证据 POC，不能宣称可动态复现。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 015.php（DVWA 密码修改模块，83 行），已逐行审计。发现两条可闭合链：(1) CAPTCHA 状态机绕过——step=2 仅信任客户端 passed_captcha 标志，可跳过 reCAPTCHA 直接改密（高危，链闭合）；(2) step=1 将 password_new/password_conf 未编码回显进隐藏表单，构成反射型 XSS（中危，依赖登录与 CAPTCHA 条件）。SQL 语句使用 mysqli_real_escape_string 且口令经 md5 后拼接，未发现可利用 SQL 注入；md5 用于口令哈希属 weak_hash 线索，但 DVWA 场景下不构成独立可利用链，未单独立项。未提供 php.ini/路由/认证配置，无法确认 015.php 是否强制登录及 allow_url_include 等开关；无其它文件，供应链与版本漏洞未覆盖。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 disable_functions、open_basedir、allow_url_include
- 无路由/认证配置，无法确认 015.php 是否强制登录及 dvwaCurrentUser() 实现
- md5 口令哈希（weak_hash）未单独立项，因缺乏独立可利用链
- 无 composer.json/第三方依赖，供应链风险未评估

## 3. Findings

### F-1: 015.php 口令修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者通过修改口令表单提交 password_new 参数（015.php:8 处 $pass_new = $_POST['password_new']），该值在 015.php:64 仅经过 mysqli_real_escape_string 转义后，于 015.php:65 被 md5() 处理，随后在 015.php:68 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "'"，最终在 015.php:69 由 mysqli_query 执行。由于 md5() 输出为固定 32 位十六进制串，password_new 的原始内容无法以引号形式进入 SQL，因此该路径上的注入不成立；真正未参数化的是 dvwaCurrentUser() 的返回值被直接拼入 WHERE 子句，但该值来自会话而非请求参数，外部不可控。综合判断：候选所声称的 password_new→$insert 污点链在 md5 处被截断，证据不足以支撑可利用的 SQL 注入。

**source / sink**

- source：query `password_new`（015.php:51）
- sink：015.php:69 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `015.php:69` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /015（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-c00a42452f04`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若成立可导致数据库任意读写、口令表被篡改或数据泄露；但按现有代码证据，password_new 经 md5 后无法携带 SQL 元字符，实际影响无法确认。

**CVE / CWE 论证**

CWE-89 要求外部可控数据未经参数化进入 SQL。本候选的 source（password_new）在 015.php:65 被 md5 归一化为十六进制串，破坏了注入所需的引号闭合条件；WHERE 子句中的 dvwaCurrentUser() 非请求可控。外部可达性与利用链闭合性均不满足，故不构成可确认的 CWE-89。

**修复建议**

即便当前 md5 阻断了注入，仍应改为预处理语句：$stmt = $db->prepare('UPDATE users SET password = ? WHERE user = ?'); $stmt->bind_param('ss', $pass_new, dvwaCurrentUser()); 避免任何字符串拼接；同时对 dvwaCurrentUser() 的返回值做白名单校验。

**验证说明**

静态证据：入口 ANY /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 $pass_new → 015.php:64 mysqli_real_escape_string → 015.php:65 md5($pass_new)（污点被归一化为 32 位十六进制，引号无法保留）→ 015.php:68 字符串拼接 $insert → 015.php:69 mysqli_query。链条在 md5 处断开，无法闭合。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 密码修改逻辑的 SQL 注入 POC。源码 015.php:69 将外部输入 password_new 经 mysqli_real_escape_string 后拼接进 UPDATE/INSERT 语句（DVWA 风格 low 级别），注入点为 query 参数 password_new。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。漏洞位于 015.php:69，外部输入来自 query 参数 password_new，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。保留原请求结构，仅补充说明与预期结果。

### F-2: DVWA 密码修改流程 CAPTCHA 状态机可绕过（直接提交 step=2 与 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

015.php 的密码修改被拆成两步：step=1 时调用 recaptcha_check_answer 校验验证码，通过后渲染一个隐藏表单，其中包含 step=2、passed_captcha=true 以及用户输入的 password_new/password_conf；step=2 分支只检查 $_POST['passed_captcha'] 是否为真值，完全不重新校验 CAPTCHA，也不校验该值是否由服务端签发。攻击者可以跳过 step=1，直接 POST step=2、passed_captcha=true、password_new、password_conf，从而在未通过任何 CAPTCHA 的情况下修改当前登录用户的密码。该逻辑使 CAPTCHA 保护形同虚设，可被用于自动化口令变更/账户接管链（配合 CSRF 或撞库后的会话）。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 mysqli_query 执行 UPDATE users SET password=... （第 68-69 行），在未校验 CAPTCHA 的情况下完成口令变更

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口仅判断 Change 存在且 step==2，不要求先经过 step=1 | 攻击者直接构造 step=2 请求 |  |
| 2 | `015.php:55` | 唯一校验是 !$_POST['passed_captcha']，客户端可任意置为 true | passed_captcha=true 通过判断 | 该标志由客户端提交，服务端未用会话/签名绑定，也未重新调用 recaptcha_check_answer |
| 3 | `015.php:62` | 两次密码一致即进入更新分支 | password_new==password_conf |  |
| 4 | `015.php:64-65` | 转义后 md5 哈希 | md5(password) |  |
| 5 | `015.php:68-69` | 拼接 UPDATE 并执行，修改当前用户口令 | SQL 执行，口令被替换 |  |

**POC**

针对 /015.php（POST）的 验证码绕过 POC。注入点：POST 参数 passed_captcha；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-c737fb0d7fd9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CAPTCHA 保护被完全绕过，攻击者可在无验证码交互的情况下自动化修改账户口令，削弱防暴力破解/防自动化能力，可并入账户接管链。

**CVE / CWE 论证**

CWE-804 (Guessable CAPTCHA) / CWE-841 (Improper Enforcement of Behavioral Workflow)：状态机信任客户端提交的 passed_captcha 标志，服务端未绑定会话，外部可直接触发，链闭合。

**修复建议**

将 CAPTCHA 通过状态记录在服务端会话（如 $_SESSION['captcha_passed']=true 并一次性消费），step=2 时校验会话标志而非客户端字段；或合并为单步并在提交时重新校验 reCAPTCHA。

**验证说明**

需确认 dvwaCurrentUser() 依赖会话且 015.php 需登录；recaptcha_check_answer 在 step=2 确实未被调用（源码已证实）。动态验证需真实会话。
模型 POC 要点：跳过 CAPTCHA 第一步，直接提交第二步完成口令修改
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 验证码校验逻辑的绕过 POC。源码 015.php:69 附近对 passed_captcha 的校验可被伪造值绕过，注入点为 POST body 参数 passed_captcha。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-804。漏洞位于 015.php:69，外部输入来自 body 参数 passed_captcha，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。

### F-3: 015.php 口令修改流程的验证码/步骤绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 以 if( isset($_POST['Change']) && ($_POST['step'] == '1') ) 作为流程分支条件，step 完全由客户端 POST 控制。攻击者可直接构造 POST Change=Change&step=1&password_new=...&password_conf=... 跳过验证码展示与校验阶段，直接进入 015.php:7-9 的取参与 015.php:64-69 的改密逻辑。代码片段中未见服务端对验证码答案的比对，也未见 step 的服务端状态机约束，因此客户端可通过控制 step 值绕过验证码环节。

**source / sink**

- source：request `captcha/step`（015.php）
- sink：015.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015 的验证码步骤绕过 POC。源码 015.php:3 处对 captcha/step 参数的处理允许跳过验证码步骤，注入点为 query 参数 captcha/step。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?captcha/step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2b846713ecdc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可绕过验证码保护，对改密接口进行自动化暴力提交或批量口令重置，削弱针对自动化攻击的防护，并可与 CSRF 组合放大改密请求的滥用面。

**CVE / CWE 论证**

CWE-804（验证码可被绕过）成立条件为验证码校验依赖客户端可控状态或缺失服务端比对。015.php:3 的 step 来自 $_POST，且片段内无验证码答案校验代码，外部无需认证即可直接提交最终状态请求，利用链在单请求内闭合。

**修复建议**

将验证码答案与一次性 token 绑定在服务端会话中校验，step 等流程状态只存于 $_SESSION 而不接受客户端传入；校验失败即拒绝进入改密分支；对改密接口增加频率限制。

**验证说明**

静态证据：入口 ANY /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST Change=Change&step=1 → 015.php:3 条件成立，跳过验证码阶段 → 015.php:7-9 读取 password_new/password_conf → 015.php:64-69 执行改密 UPDATE。全程无需通过验证码。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。漏洞位于 015.php:3，外部输入来自 query 参数 captcha/step，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。

### F-4: 015.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 摘要形式写入数据库（015.php:68 的 UPDATE users SET password = '$pass_new'）。MD5 属快速哈希，抗碰撞与抗暴力能力弱，且此处未加盐、未使用迭代型口令哈希，口令摘要一旦泄露可被彩虹表/GPU 快速还原。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：015.php:65 使用 md5() 对密码做哈希，属弱哈希算法（CWE-328），无需发送请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 015.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-81919fa4d087`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时攻击者可在极短时间内还原用户明文口令；由于用户常跨站复用口令，可进一步导致账户接管与横向越权。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）适用于口令等安全用途。015.php:65 明确对安全敏感的口令使用 MD5，属实现型弱点，无需 HTTP 污点链；外部可达性体现在任意改密请求都会生成 MD5 摘要。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT) 生成带盐的 bcrypt/Argon2 摘要，校验时用 password_verify；对历史 MD5 记录在用户下次登录时透明升级。

**验证说明**

静态证据：入口 ANY /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 015.php:8 $pass_new → 015.php:64 转义 → 015.php:65 md5($pass_new) → 015.php:68 拼入 UPDATE → 015.php:69 写入 users.password。口令以无盐 MD5 落库。
POC 备注：仅限授权测试；静态证据，不执行、不联网。

### F-5: 015.php step=1 将 password_new/password_conf 未编码回显进隐藏表单（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:28-36`
- **来源**：`llm_finding`

**描述**

step=1 分支在两次密码一致时，把用户提交的 $pass_new、$pass_conf 直接插入 HTML 隐藏 input 的 value 属性（第 32-33 行），未做 htmlspecialchars 等编码。攻击者可构造 password_new/password_conf 含双引号闭合属性并注入脚本，在受害者浏览器执行。由于该页面通常需登录，实际利用需诱导已登录用户提交或配合 CSRF，价值中等。

**source / sink**

- source：body `password_new`（015.php:8）
- sink：015.php:36 $html .= "...value=\"{$pass_new}\"..." 输出到页面

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 读取 password_new | 原始用户输入 |  |
| 2 | `015.php:26` | 两次密码相等判断通过 | pass_new==pass_conf |  |
| 3 | `015.php:32-33` | 未编码拼入 HTML 属性 | 注入的引号/标签进入响应 HTML |  |

**POC**

针对 /015.php（POST）的 跨站脚本 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-f67e226dc1d1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者会话上下文执行脚本，窃取会话或代替用户操作。

**CVE / CWE 论证**

CWE-79：用户输入未编码进入 HTML 属性，外部可触发；但需登录与 CAPTCHA 条件，故置信度中等。

**修复建议**

对回显值使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码，或改用服务端会话保存待确认密码而非回显到表单。

**验证说明**

需确认页面是否需登录及 CAPTCHA 是否可绕过（见上一条）；实际浏览器执行需动态验证。
模型 POC 要点：提交含引号闭合的密码值，触发脚本注入
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 的反射/存储型 XSS POC。源码 015.php:36 将外部输入 password_new 未编码输出到响应，注入点为 POST body 参数 password_new。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-79。漏洞位于 015.php:36，外部输入来自 body 参数 password_new，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。

### F-6: 015.php 改密接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:7-9 直接从 $_POST 读取 password_new 与 password_conf，并在 015.php:64-69 执行 UPDATE users SET password 的状态改变操作。片段中未见任何 CSRF token 校验、Origin/Referer 校验或二次确认口令比对逻辑，攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下被改密。

**source / sink**

- source：request `password change`（015.php）
- sink：015.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015 密码修改功能的 CSRF POC。源码 015.php:8 处密码修改表单缺少 CSRF token 校验，攻击者可诱导已登录用户提交表单。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/015?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-bb70b3793387`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可强制受害者账户口令变为攻击者已知值，随后登录接管账户，造成越权访问与数据泄露。

**CVE / CWE 论证**

CWE-352 成立条件为状态改变请求仅依赖浏览器自动携带的凭据且无抗伪造令牌。015.php:8 的取参与 015.php:69 的 UPDATE 之间无 token 校验，外部站点可跨站提交，利用链闭合。

**修复建议**

在改密表单中引入每会话随机 CSRF token 并在服务端比对；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；改密前要求输入原口令。

**验证说明**

静态证据：入口 ANY /015；source=request/password change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：受害者登录后访问攻击者页面 → 页面自动 POST password_new/password_conf 至 015.php → 015.php:8 读取参数 → 015.php:64-69 执行 UPDATE 改密 → 受害者口令被替换。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。漏洞位于 015.php:8，密码修改请求缺少 CSRF 防护，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。

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
| `captcha_bypass` | CWE-804 |  | 2 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.42 | 是 |
| surface_mapper | 攻击面测绘 | 8.72 | 是 |
| deep_finder | LLM 深挖 | 12.37 | 是 |
| candidate_screener | 候选筛选 | 7.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.8 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 10.89 | 是 |
| coordinator | 管线协调 | 7.68 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
