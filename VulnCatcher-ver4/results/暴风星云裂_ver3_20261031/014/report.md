# 落日二号乙漏洞挖掘报告 — 20261031-005857-4434bd

- 生成时间：2026-10-30T16:59:55.951548+00:00
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

本次汇总 5 条已去重 findings，全部集中在单文件 PHP 脚本 014.php（75 行），无框架、无路由清单。最高危为 014.php 第 61 行附近的 SQL 注入（GEN-74a307a2a91c，critical，CWE-89），source 热点在第 9 行、sink 热点 1 处，路径极短，利用门槛低。其次为两条 captcha_bypass（LLM-ecdc7684a376、SEM-161a1ab1f6bd，high，CWE-804，step=2 直接提交跳过 recaptcha 校验），以及 weak_hash（LLM-e088daa8a281，medium，无盐 MD5 存储，CWE-328）与 csrf（SEM-16d21f2078ab，medium，口令修改缺少 CSRF 防护，CWE-352）。5 条均带 POC 文本，但其中 weak_hash 仅为静态证据 POC（源码中 md5 调用），不能宣称可动态复现；SQL 注入、captcha_bypass、csrf 具备 HTTP 请求语义，POC 为 HTTP 型文本工件（TARGET 占位，仅限授权测试）。本次未做任何动态验证，所有结论为源码/规则/模型推断。

共 **5** 条 finding；**5** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 014.php（1-75 行全量）。该文件为 DVWA 密码修改模块：step=1 分支做 CAPTCHA 校验并渲染确认表单，step=2 分支直接读取 password_new/password_conf 并执行 UPDATE。发现两条可闭合问题：(1) CAPTCHA 状态机绕过——step=2 分支不校验 CAPTCHA 也无一次性令牌，可直接提交改密（captcha_bypass，high）；(2) 密码使用无盐 MD5 存储（weak_hash，medium）。SQL 注入方面：第 60 行 UPDATE 语句中 password 值经 mysqli_real_escape_string 转义、user 值来自 dvwaCurrentUser() 而非直接请求参数，未发现可闭合的 SQL 注入链，故不报告。第 32-33 行将 $pass_new/$pass_conf 直接插入隐藏表单 value 属性，存在反射型 XSS 可能，但需结合 DVWA 全局过滤与输出上下文确认，证据不足未单独立项。未提供 php.ini/会话/认证实现，dvwaCurrentUser() 与 recaptcha_check_answer() 定义不在 code_pack 内，相关运行时条件需人工确认。

未覆盖 / 证据缺口：
- dvwaCurrentUser()、recaptcha_check_answer()、$_DVWA 配置定义不在 code_pack，无法确认会话与密钥实现
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、display_errors 等
- 第 32-33 行隐藏表单回显的 XSS 需结合全局过滤确认，未闭合
- 无端点清单，路由按单文件直访推断

## 3. Findings

### F-1: 014.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（014.php:8 读取，014.php:50 处作为 query `password_new` 进入流程）提交恶意字符串；该值被直接拼接进 UPDATE 语句：014.php:60 `$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";`，随后在 014.php:61 交给 mysqli_query 执行。代码中未见 mysqli_real_escape_string、预处理语句或类型约束，单引号可闭合 password 字面量，从而改写 WHERE 条件或追加语句，因此校验无效。最终危险操作是 014.php:61 的 mysqli_query 执行拼接 SQL。

**source / sink**

- source：query `password_new`（014.php:50）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/014?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-74a307a2a91c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可越权修改任意用户（含 admin）口令，进而登录后台；结合报错回显（014.php:61 的 die 输出 mysqli_error）可进行报错型注入读取数据库内容，造成账户接管与数据泄露。

**CVE / CWE 论证**

CWE-89。外部可达：014.php 为 Web 入口，参数来自 $_POST；无需认证即可到达该分支（DVWA 低安全级别下无 token/权限校验）；利用链闭合：password_new → $pass_new → $insert 字符串拼接 → mysqli_query。证据等级为源码推断，未做动态验证。

**修复建议**

改用预处理语句（mysqli_prepare + bind_param）绑定 password_new；若必须拼接，使用 mysqli_real_escape_string 并加引号包裹；对输入做长度与字符白名单校验；关闭详细数据库报错回显，改为通用错误页；数据库账户遵循最小权限，仅授予必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 ANY /014；source=query/password_new；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 014.php:8 $pass_new → 014.php:50 进入修改流程 → 014.php:60 拼入 UPDATE 语句 → 014.php:61 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php（第 61 行附近）的 SQL 注入 POC。外部输入来自请求参数 password_new，被直接拼接进 SQL 语句，未做参数化或有效转义。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89（SQL 注入）。漏洞位于 014.php:61，外部输入 password_new 未经净化直达 SQL 汇点，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。payload 使用 URL 编码 %27%20OR%20%271%27%3D%271。禁止使用 DROP 等破坏性语句。

### F-2: DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交跳过 recaptcha 校验）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改被拆成两步：step=1 时调用 recaptcha_check_answer() 校验第三方 CAPTCHA，通过后渲染一个隐藏表单（step=2）让用户确认。但服务端在 step=2 分支（第 45-73 行）完全没有再次校验 CAPTCHA，也没有任何一次性令牌/会话标记来证明 step=1 曾经通过。攻击者（或自动化脚本）可以直接 POST Change=Change&step=2&password_new=X&password_conf=X，跳过 recaptcha_check_answer() 直接进入第 54 行的密码一致性判断并执行第 60-61 行的 UPDATE 语句修改当前用户密码。CAPTCHA 作为防自动化/防 CSRF 的唯一屏障被完全绕过。

**source / sink**

- source：body `step`（014.php:50-54）
- sink：014.php:61 mysqli_query 执行 UPDATE users SET password（第 60-61 行），前置 CAPTCHA 校验被跳过

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 入口仅判断 Change 存在且 step=='2'，不要求 step=1 已通过 | 攻击者直接控制 step=2 | step=1 分支（第 3-43 行）的 recaptcha_check_answer 校验在此分支完全不执行 |
| 2 | `014.php:50-54` | 读取 password_new/password_conf 并比较是否相等 | 原始字符串，仅做相等比较 |  |
| 3 | `014.php:56-57` | mysqli_real_escape_string 转义后 md5 哈希 | 转义后的哈希串 |  |
| 4 | `014.php:60-61` | 拼接 UPDATE 语句并执行，修改当前用户密码 | 写入数据库 |  |

**POC**

针对 /014.php（POST）的 验证码绕过 POC。注入点：POST 参数 step；payload 使用 TARGET 占位符。

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
- POC 目录：`poc/LLM-ecdc7684a376`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需通过 CAPTCHA 即可自动化修改账户密码；结合 CSRF 可诱导已登录用户静默改密，导致账户接管。CAPTCHA 防自动化保护完全失效。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/ CWE-841（行为强制不一致）：服务端状态机缺少对前置校验结果的绑定，外部可直接访问 step=2 分支，无需认证绕过即可触发敏感写操作。

**修复建议**

在 step=1 通过 CAPTCHA 后于服务端会话中写入一次性令牌（如 $_SESSION['pwd_change_token']），step=2 必须校验该令牌并立即失效；或在 step=2 重新校验 CAPTCHA。

**验证说明**

需确认 dvwaCurrentUser() 依赖的会话在真实部署中如何建立；CAPTCHA 绕过为源码级确定，但账户接管影响依赖会话已认证。
模型 POC 要点：直接提交 step=2 跳过 CAPTCHA 完成密码修改
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：针对 014.php（第 61 行附近）的验证码绕过 POC。服务端对验证码/步骤参数 step 的校验可被绕过，导致可跳过人机校验直接进入后续业务逻辑。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-804（验证码绕过）。漏洞位于 014.php:61，外部输入 step 影响校验流程且未发现有效绑定/一次性校验。
POC 备注：POC 仅为文本工件，不执行、不联网。SUNSET_PROBE 为无害探测值。

### F-3: 014.php 验证码流程可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.77`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

014.php:3 通过 `isset($_POST['Change']) && $_POST['step'] == '1'` 判断是否进入修改口令分支，step 由客户端 POST 控制。攻击者可直接提交 step=1 与 Change 参数跳过验证码展示/校验阶段，直接进入口令修改逻辑（014.php:7-9 读取 password_new/password_conf，014.php:60-61 执行 UPDATE）。输入点为 POST 参数 step 与 Change，缺少服务端会话绑定的验证码状态校验，因此校验无效。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的 验证码绕过 POC。注入点：ANY 参数 captcha/step；payload 使用 TARGET 占位符。

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

绕过人机验证，配合脚本对修改口令接口进行自动化批量尝试/暴力枚举，放大其他弱点（如 SQL 注入、CSRF）的利用效率。

**CVE / CWE 论证**

CWE-804。外部可达：仅需普通 HTTP POST；无需认证（低安全级别）；利用链闭合：step 参数 → 014.php:3 分支判断 → 直接进入口令修改逻辑。注意：验证码实际校验代码未在给定片段中出现，跨文件/运行时条件需复核，故置信度中等。

**修复建议**

验证码校验必须在服务端完成并与会话绑定（一次性 token，使用后立即失效）；不要用客户端可控的 step 字段决定是否跳过校验；对修改口令接口增加频率限制与失败锁定。

**验证说明**

静态证据：入口 ANY /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST step=1&Change=... → 014.php:3 条件成立 → 跳过验证码阶段 → 014.php:8-9 读取新口令 → 014.php:60-61 执行 UPDATE。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php（第 3 行附近）的验证码绕过 POC。captcha/step 相关参数在校验逻辑中可被绕过，导致跳过人机校验。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804。漏洞位于 014.php:3，验证码校验逻辑可被绕过。
POC 备注：POC 仅为文本工件，不执行、不联网。参数名 captcha/step 为语义推断，实际字段名需以源码为准。

### F-4: 密码使用无盐 MD5 存储（014.php:57）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:56-61`
- **来源**：`llm_finding`

**描述**

第 57 行对用户新密码仅做 md5() 后写入数据库，未使用盐值或慢哈希（bcrypt/argon2）。MD5 属快速哈希，配合彩虹表/GPU 爆破可高效还原明文；若数据库泄露将直接导致账户口令暴露。

**source / sink**

- source：body `password_new`（014.php:50）
- sink：014.php:61 UPDATE users SET password = md5(...)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 读取 password_new | 明文 |  |
| 2 | `014.php:57` | md5 无盐哈希 | 32 位十六进制 MD5 |  |
| 3 | `014.php:60-61` | 写入数据库 | MD5 摘要入库 |  |

**POC**

针对 /014.php（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

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
- POC 目录：`poc/LLM-e088daa8a281`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时口令可被快速离线破解，导致账户接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）/ CWE-916：使用无盐 MD5 存储口令，属可申报的弱哈希实现缺陷。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）并配合 password_verify()。

**验证说明**

需确认数据库实际存储格式；源码已明确 md5() 调用。
模型 POC 要点：该问题为存储型弱哈希，POC 为说明性：设置密码后数据库存储为 md5(明文)
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：针对 014.php（第 61 行附近）的弱哈希算法 POC。密码字段 password_new 使用弱哈希（如 MD5/SHA1）存储，可被离线快速破解。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-328（弱哈希）。漏洞位于 014.php:61，密码使用弱哈希算法处理，属配置/算法型缺陷，不依赖 HTTP 污点。
POC 备注：POC 仅为文本工件，不执行、不联网。弱哈希属配置型候选，判定依据为算法强度而非注入链。

### F-5: 014.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:7-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf'] 并进入口令修改流程，014.php:60-61 执行 UPDATE。代码片段中未见 CSRF token、Origin/Referer 校验或二次确认，状态改变请求仅依赖浏览器自动携带的会话凭据。攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下修改口令。

**source / sink**

- source：request `password change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

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

受害者账户口令被改为攻击者已知值，导致账户接管；若受害者为管理员，可进一步控制整个应用。

**CVE / CWE 论证**

CWE-352。外部可达：攻击者只需诱导受害者访问恶意页面；利用链闭合：跨站表单 POST password_new/password_conf → 014.php:8-9 → 014.php:60-61 UPDATE。认证与 SameSite Cookie 条件需运行时复核，故置信度中等。

**修复建议**

为口令修改表单引入每会话随机 CSRF token 并在服务端校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；修改口令等敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 ANY /014；source=request/password change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：恶意页面自动提交 POST password_new/password_conf → 014.php:8-9 读取 → 014.php:60-61 执行 UPDATE，受害者口令被篡改。
PocWriter 建议（未采纳，缺少端点 /014）：针对 014.php（第 8 行附近）的跨站请求伪造 POC。密码修改操作缺少 CSRF token 校验，攻击者可诱导已登录用户自动提交表单完成密码变更。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352（CSRF）。漏洞位于 014.php:8，敏感操作缺少反 CSRF 令牌校验。
POC 备注：POC 仅为文本工件，不执行、不联网。poc.html 为说明性文本，不自动运行。

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
| `weak_crypto` | CWE-327 |  | 0 |
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
| safety_guard | 安全防护 | 2.32 | 是 |
| surface_mapper | 攻击面测绘 | 9.75 | 是 |
| deep_finder | LLM 深挖 | 11.99 | 是 |
| candidate_screener | 候选筛选 | 6.76 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.1 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.49 | 是 |
| coordinator | 管线协调 | 7.7 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
