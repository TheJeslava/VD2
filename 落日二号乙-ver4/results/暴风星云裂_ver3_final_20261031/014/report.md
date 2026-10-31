# 落日二号乙漏洞挖掘报告 — 20261031-013820-490c46

- 生成时间：2026-10-30T17:39:15.442551+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\014.zip`
- 输入模式：`zip`
- SHA256：`d641901c9e40d65807bfa31417d7720c470dd3f58356dd114ccf3915412bbff4`
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

本次审计对象为单文件 PHP 脚本 014.php（75 行），共交付 5 条去重后 findings，全部带 POC（5/5）。最高危为 captcha_bypass（high，2 条：LLM-d070f9edd828 与 SEM-161a1ab1f6bd，均指向 014.php 的 step 参数状态机，可跳过 recaptcha 校验直接进入密码修改流程，CWE-804），两条为同一缺陷的模型发现与规则发现，属重复表述而非两个独立漏洞。中危包括 weak_hash（LLM-75da972f9cc2，014.php:57-60 无盐 MD5 存口令，CWE-328）、weak_crypto（SEM-f257349cbc66，同一 MD5 用法被规则侧标为 CWE-328，类型标注与 weak_hash 重叠，建议合并为 weak_hash）与 csrf（SEM-16d21f2078ab，014.php 密码修改接口无 CSRF 令牌）。POC 齐全但性质不同：captcha_bypass 与 csrf 具备 HTTP 请求语义，可作 HTTP POC 文本；weak_hash/weak_crypto 仅有静态代码证据 POC，不能宣称可动态复现。所有结论均为源码推断（llm_inferred / rule），未经动态验证。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 014.php（1-75 行全量）。该文件为 DVWA 密码修改模块：第 3-43 行为 step=1（含 recaptcha_check_answer 校验），第 45-73 行为 step=2（执行 UPDATE）。发现两条可闭合问题：(1) step=2 分支缺少 CAPTCHA 通过状态的服务端校验，可绕过 CAPTCHA 直接改密（captcha_bypass，高危）；(2) 口令以无盐 MD5 存储（weak_hash，中危）。SQL 注入方面：第 56 行 mysqli_real_escape_string 已对 password_new 转义，第 60 行 user 来自 dvwaCurrentUser() 而非直接请求参数，未发现可闭合的 SQL 注入链；第 32-33 行将 $pass_new/$pass_conf 回显进隐藏表单 HTML，但值来自用户自身提交且未做 HTML 编码，属自 XSS，不构成跨用户攻击，未单独立项。未发现命令执行、文件包含、反序列化、SSRF 等汇点。未覆盖范围：无 composer.json/php.ini/Web 服务器配置，无法确认 open_basedir、错误显示与 014.php 是否被 include 或直接暴露；无数据库 schema，无法确认 users 表结构与 dvwaCurrentUser() 实现；无前端模板，XSS 上下文无法判定。

未覆盖 / 证据缺口：
- 缺少 dvwaCurrentUser() 实现，无法确认 user 字段是否可能被污染
- 缺少 recaptcha_check_answer() 实现，无法确认其返回值语义
- 无 Web 服务器/php.ini 配置，运行时约束未知
- 无数据库 schema，SQL 注入可达性无法进一步确认
- 无端点清单，014.php 是否直接对外暴露未知

## 3. Findings

### F-1: DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交跳过 recaptcha 校验）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-64`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改被拆成两步：step=1 时调用 recaptcha_check_answer() 校验第三方 CAPTCHA（第 12-23 行），校验通过后把 password_new/password_conf 放进隐藏表单，step=2 时执行真正的 UPDATE（第 45-64 行）。但第 45 行的分支条件只检查 $_POST['Change'] 与 $_POST['step']=='2'，完全没有校验 CAPTCHA 结果、也没有任何服务端会话标记（如 $_SESSION['captcha_passed']）来证明 step=1 曾经成功。攻击者可以完全跳过 step=1，直接 POST step=2 完成密码修改，CAPTCHA 保护形同虚设。结合 DVWA 的 CSRF 场景，攻击者可构造自动提交表单让已登录受害者改密，实现账户接管。

**source / sink**

- source：body `step`（014.php:50-51）
- sink：014.php:64 第 60-61 行 UPDATE users SET password=... 直接执行，无 CAPTCHA 前置校验

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 入口仅判断 Change 存在且 step=='2'，未检查任何 CAPTCHA 通过标记 | 攻击者直接构造 step=2 请求 | 跳过第 12-23 行的 recaptcha_check_answer 校验分支 |
| 2 | `014.php:50-51` | 读取 password_new/password_conf | 攻击者完全可控的明文口令 |  |
| 3 | `014.php:54` | 两次口令相等判断 | 相等则继续 |  |
| 4 | `014.php:56-57` | mysqli_real_escape_string 转义后 md5 散列 | 转义+MD5，SQL 注入被阻断，但口令仍为攻击者所控 |  |
| 5 | `014.php:60-61` | 拼接 UPDATE 语句并执行，修改当前登录用户口令 | 写入数据库 |  |

**POC**

针对 /014.php（POST）的验证码绕过 POC。源码 014.php:64 处对 POST 参数 step 的处理缺少有效校验，攻击者可通过控制 step 参数绕过验证码流程。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-d070f9edd828`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

绕过 CAPTCHA 保护修改账户口令；配合 CSRF 可对已登录管理员实施账户接管。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/CWE-841（行为强制不当）。外部无需认证即可构造请求（受害者会话场景），状态机缺少服务端校验标记，链闭合。

**修复建议**

在 step=1 校验通过后写入 $_SESSION['captcha_passed']=true 并绑定一次性 token，step=2 必须校验该标记与 token 后立即失效；同时对改密操作增加 CSRF token 与旧口令确认。

**验证说明**

需确认部署环境中 step=2 分支是否被其他 include 逻辑额外保护；DVWA 原生实现即存在此缺陷，动态验证可直接复现。
模型 POC 要点：直接提交 step=2 绕过 CAPTCHA 修改当前登录用户口令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-804（验证码绕过）。漏洞位于 014.php:64，外部输入来自 body 参数 step，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 并取得授权。

### F-2: 014.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

攻击者通过 POST 提交 `Change` 与 `step` 参数（014.php:3 `isset($_POST['Change']) && $_POST['step']=='1'`）直接进入密码修改分支，跳过验证码校验环节。代码中验证码的展示/校验依赖客户端可控的 `step` 状态值，服务端未在会话中绑定验证码一次性令牌，也未校验验证码答案与当前会话的一致性，因此攻击者只需把 `step` 置为 `1` 即可绕过验证码。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的验证码绕过 POC。源码 014.php:3 处对 query 参数 captcha/step 缺少有效校验，攻击者可控制该参数绕过验证码。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?captcha/step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-161a1ab1f6bd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

验证码防护失效，攻击者可对密码修改接口进行自动化/批量尝试，配合弱口令或撞库实现账户接管；验证码作为反自动化与防暴力破解的唯一屏障被移除。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）类弱点：验证码状态由客户端 `step` 参数决定，服务端未做会话绑定与一次性校验，外部无需认证即可通过构造 POST 请求绕过，利用链闭合（请求 → step 判断 → 进入密码修改逻辑）。

**修复建议**

将验证码答案与一次性 nonce 存入服务端会话，提交时校验会话中的答案并立即失效；不要用客户端可控的 `step` 决定是否校验验证码；对密码修改接口增加频率限制与失败锁定。

**验证说明**

静态证据：入口 ANY /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST `Change=...&step=1&password_new=...&password_conf=...` → 014.php:3 条件成立 → 跳过验证码校验 → 直接执行密码更新逻辑。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804（验证码绕过）。漏洞位于 014.php:3，外部输入来自 query 参数 captcha/step，静态证据闭合。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，管线不执行、不联网。执行前须替换 TARGET 并取得授权。

### F-3: 密码使用无盐 MD5 存储（014.php:57）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:57-60`
- **来源**：`llm_finding`

**描述**

第 57 行对用户新口令仅做 md5() 后写入 users.password，未使用盐值或 password_hash()/bcrypt/argon2。MD5 计算速度快、易被彩虹表与 GPU 暴力破解，一旦数据库泄露口令可被快速还原。

**source / sink**

- source：body `password_new`（014.php:50）
- sink：014.php:60 UPDATE users SET password = md5(...)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 读取新口令 | 明文 |  |
| 2 | `014.php:56` | SQL 转义 | 转义后明文 |  |
| 3 | `014.php:57` | md5 无盐散列 | 32 位 MD5 摘要 |  |
| 4 | `014.php:60-61` | 写入数据库 | 弱散列持久化 |  |

**POC**

针对 /014.php（POST）的弱哈希算法 POC。源码 014.php:60 处对 POST 参数 password_new 使用弱哈希（MD5）处理口令，攻击者可离线快速碰撞/破解。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014.php' \
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

数据库泄露后口令可被离线快速破解，导致账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。代码直接可见，无需认证即可确认实现方式。

**修复建议**

改用 password_hash($pass, PASSWORD_DEFAULT) 与 password_verify()，并迁移历史 MD5 记录。

**验证说明**

实现级缺陷，源码即可确认；无需动态验证。
模型 POC 要点：该问题为存储实现缺陷，无需构造注入；通过正常改密流程即可产生 MD5 口令记录
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-328（弱哈希）。漏洞位于 014.php:60，外部输入来自 body 参数 password_new，静态证据闭合。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，管线不执行、不联网。执行前须替换 TARGET 并取得授权。

### F-4: 014.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:56-57`
- **来源**：`rule`

**描述**

014.php:57 `$pass_new = md5( $pass_new );` 对新口令仅做单次 MD5 摘要后写入数据库（前置 56 行仅做 mysqli_real_escape_string 转义）。MD5 为快速、无盐、可并行化的哈希，不适用于口令存储。

**source / sink**

- source：repository `md5(`（014.php）
- sink：014.php:57 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:57` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：014.php:57 处使用 md5() 对 $pass_new 进行哈希，属弱哈希算法（CWE-328）。无需发送请求，通过源码审查即可确认。

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

数据库泄露后攻击者可用彩虹表/GPU 暴力快速还原用户明文口令；相同口令产生相同摘要，可横向撞库，导致账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令等安全用途，算法本身抗碰撞与抗暴力能力不足，且未见加盐与迭代；属于实现型弱点，无需 HTTP 污点链即可成立。

**修复建议**

改用 password_hash()（bcrypt/Argon2id）并配合 password_verify()；为每个口令生成独立随机盐；迁移期可对旧 MD5 值在用户下次登录时透明升级。

**验证说明**

静态证据：入口 ANY /014；source=repository/md5(；sink=014.php:57；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 014.php:8 读取 `password_new` → 56 行转义 → 57 行 `md5()` 单次摘要 → 写入数据库，弱哈希成为口令存储的唯一保护。
POC 备注：纯静态证据，无需执行任何请求。

### F-5: 014.php 密码修改接口缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:8-9 直接从 `$_POST['password_new']` / `$_POST['password_conf']` 读取新口令并执行修改，未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下修改口令。

**source / sink**

- source：request `password change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的跨站请求伪造 POC。源码 014.php:8 处口令修改流程缺少 CSRF 令牌校验，攻击者可诱导已登录用户提交伪造请求完成口令变更。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-16d21f2078ab`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

已认证用户被诱导访问恶意页面即可被静默改密，攻击者随后用新口令登录，实现账户接管。

**CVE / CWE 论证**

CWE-352（Cross-Site Request Forgery）：状态改变请求无不可预测令牌校验，外部站点可跨域触发；利用链为恶意页面 → 受害者浏览器携带会话 Cookie → 014.php 密码修改分支。

**修复建议**

在表单中引入与会话绑定的随机 CSRF token 并在服务端比对；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；修改口令要求输入原口令。

**验证说明**

静态证据：入口 ANY /014；source=request/password change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：受害者登录后访问攻击者页面 → 页面自动 POST `Change=Change&password_new=X&password_conf=X` → 014.php:8 读取参数 → 执行改密，全程无 token 校验。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352（CSRF）。漏洞位于 014.php:8，口令变更流程无 CSRF 令牌。证据等级：llm_inferred。
POC 备注：POC 仅为文本工件，管线不执行、不联网。poc.html 为说明性表单，需替换 TARGET 并在授权环境手动验证。

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
| `sql_injection` | CWE-89 | 是 | 0 |
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
| `weak_hash` | CWE-328 |  | 1 |
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
| safety_guard | 安全防护 | 2.59 | 是 |
| surface_mapper | 攻击面测绘 | 7.88 | 是 |
| deep_finder | LLM 深挖 | 11.59 | 是 |
| candidate_screener | 候选筛选 | 7.27 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.21 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.55 | 是 |
| coordinator | 管线协调 | 7.97 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
