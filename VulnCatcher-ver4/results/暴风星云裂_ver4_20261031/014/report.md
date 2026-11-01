# 落日二号乙漏洞挖掘报告 — 20261031-164032-6be19b

- 生成时间：2026-10-31T08:41:36.292891+00:00
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

本次审计对象为单文件 PHP 脚本 014.php（75 行），共交付 6 条去重后 findings，全部带 POC（with_poc=6）。最高危为 GEN-74a307a2a91c：014.php 第 61 行附近口令修改逻辑存在 SQL 注入（CWE-89，critical），数据流短、可利用性高。其次为验证码绕过（SEM-161a1ab1f6bd 规则命中 step 参数绕过、LLM-ecdc7684a376 指出 step=2 阶段完全跳过 CAPTCHA）与 CSRF（LLM-b52a2b477f7b、SEM-16d21f2078ab），均为 high/medium，可组合成“绕过验证码 + 跨站强制改密”的攻击链。另有 SEM-f257349cbc66 使用 MD5 存储口令，类型应为 weak_hash（CWE-328），当前被标为 weak_crypto，属类型标注偏差，需在交付时纠正。POC 齐全度：6/6 有 POC，但其中 MD5 一条仅为静态证据 POC，不具备 HTTP 动态复现语义；SQL 注入、验证码绕过、CSRF 三条具备 HTTP 请求级 POC 形态。所有结论均为源码审计与规则/模型推断，未经动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3053 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 014.php（75 行，DVWA 密码修改练习页）。发现两条闭合链：1) step=2 分支完全跳过 CAPTCHA 校验（captcha_bypass）；2) 改密接口无 CSRF token（csrf）。两者均可在已登录会话下外部触发。第 56 行 mysqli_real_escape_string 已对 password_new 转义，且第 60 行 user 来自 dvwaCurrentUser() 而非用户输入，故未发现 SQL 注入。第 32-33 行把 password_new 回填进隐藏字段存在反射型 XSS 可能，但需 step=1 通过 CAPTCHA 且为自 XSS，价值低，未单独立项。weak_hash（md5 存密码）属 DVWA 设计缺陷，未形成独立可利用链，仅作线索。未覆盖：无 composer/php.ini/Web 配置，无法确认部署与全局 CSRF 防护。

未覆盖 / 证据缺口：
- 无 Web 服务器/框架配置，无法确认全局 CSRF token 与 CAPTCHA 状态管理
- 无端点清单，无法确认 014.php 实际 URL 与访问控制
- 第 32-33 行隐藏字段回填的反射型 XSS 未单独立项（需 CAPTCHA 通过，价值低）

## 3. Findings

### F-1: 014.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:59-61`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（014.php:8 读取，014.php:50 附近进入 $pass_new）提交恶意字符串。该值在 014.php:56 仅经过 mysqli_real_escape_string 处理，随后在 014.php:57 被 md5() 哈希，最终在 014.php:60 被拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";，并在 014.php:61 由 mysqli_query 执行。由于 md5() 会把注入载荷转成 32 位十六进制串，常规引号注入在哈希后失效，因此该候选的污点链在 014.php:57 处被哈希截断，证据不足以证明存在可闭合的注入路径；仅当存在未哈希分支或哈希前拼接时才成立。当前证据等级为推断，需复核 014.php:50-61 完整代码确认是否存在绕过 md5 的路径。

**source / sink**

- source：query `password_new`（014.php:50）
- sink：014.php:61 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:50` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `014.php:61` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /014（POST）的 SQL 注入 POC。注入点为 POST 参数 password_new，该值在 014.php:56 经 mysqli_real_escape_string 处理后于 014.php:57 被 md5() 哈希，随后进入密码更新 SQL 语句（014.php:61 附近）。payload 使用 TARGET 占位符，仅限授权测试。

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

若成立，可篡改 users 表任意用户口令（含管理员），导致账户接管；当前证据下影响待确认。

**CVE / CWE 论证**

CWE-89：外部可控输入进入 SQL 语句拼接。外部可达性：password_new 为 POST 参数，无需额外权限即可提交；但利用链在 md5() 处不闭合，故不满足完整可利用性论证。

**修复建议**

使用预处理语句（mysqli_prepare + bind_param）绑定 password 与 user；对 dvwaCurrentUser() 同样参数化；避免将哈希结果直接拼接进 SQL；对输入做长度与字符白名单校验。

**验证说明**

静态证据：入口 POST /014；source=query/password_new；sink=014.php:61；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 014.php:8 $pass_new → 014.php:56 mysqli_real_escape_string → 014.php:57 md5()（污点被哈希破坏）→ 014.php:60 字符串拼接 $insert → 014.php:61 mysqli_query 执行。哈希环节使注入载荷不可控，链条未闭合。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-89。漏洞位于可交付代码 014.php:61，外部输入来自 POST 参数 password_new，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：保留原有请求结构；脚本仅为文本工件，不自动执行、不联网。执行前须替换 TARGET 并确认授权。

### F-2: DVWA 密码修改功能 step=2 阶段完全跳过 CAPTCHA 校验，可绕过验证码直接改密

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的密码修改流程被拆成两步：step=1 时调用 recaptcha_check_answer() 校验验证码（第 12-23 行），校验通过后把 password_new/password_conf 以隐藏字段回填到 step=2 表单（第 28-35 行）。但 step=2 分支（第 45-73 行）只检查 isset($_POST['Change']) && $_POST['step']=='2'，随后直接比较两次密码并执行 UPDATE users SET password（第 54-61 行），完全没有再次校验 CAPTCHA，也没有任何服务端状态标记证明 step=1 曾经通过。攻击者可以跳过 step=1，直接构造 step=2 请求修改当前登录用户的密码，验证码保护形同虚设。

**source / sink**

- source：body `step`（014.php:50-54）
- sink：014.php:61 014.php:60-61 mysqli_query 执行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 攻击者直接提交 step=2 与 Change，绕过 step=1 的 CAPTCHA 分支 | $_POST['step']='2'，未经过 recaptcha_check_answer |  |
| 2 | `014.php:50-54` | 读取 password_new/password_conf 并比较是否相等 | 两次密码相同即进入改密分支 |  |
| 3 | `014.php:56-57` | mysqli_real_escape_string 转义后 md5 哈希 | 明文密码 -> md5 哈希 |  |
| 4 | `014.php:60-61` | 拼接 UPDATE 语句并执行，修改当前用户密码 | 哈希写入 users 表 |  |

**POC**

针对 /014.php（POST）的验证码绕过 POC。入口在 014.php:3 附近处理 step 与 g-recaptcha-response，未对验证码响应做有效校验即进入密码修改流程（014.php:61 附近）。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/014.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'Change=Change&step=2&password_new=SUNSET_NEW&password_conf=SUNSET_NEW&g-recaptcha-response='
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-ecdc7684a376`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

验证码保护被完全绕过，攻击者（在已劫持会话或 CSRF 场景下）可直接修改账户密码，导致账户接管。

**CVE / CWE 论证**

CWE-804/841（验证码状态机绕过）。step=2 分支缺少对 step=1 通过状态的校验，外部可直接触发，链闭合。

**修复建议**

在服务端会话中记录 step=1 已通过 CAPTCHA 的状态，step=2 时校验该状态并在使用后清除；或把 CAPTCHA 校验合并进最终改密请求。

**验证说明**

需确认 DVWA 外层是否对 014.php 有额外 CSRF token 或 step 状态校验；本文件内未见。
模型 POC 要点：跳过验证码阶段，直接以 step=2 提交改密请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-804。漏洞位于可交付代码 014.php:61，外部输入来自 body 参数 step，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：保留原有请求结构，补充会话 Cookie 前置条件；脚本仅为文本工件，不自动执行、不联网。

### F-3: DVWA 密码修改接口缺少 CSRF token，可跨站强制改密

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`014.php:45-61`
- **来源**：`llm_finding`

**描述**

014.php 的改密逻辑仅依赖 $_POST['Change'] 与 $_POST['step']，未校验任何 CSRF token 或来源。step=2 分支（第 45-61 行）在密码匹配后直接执行 UPDATE users SET password。攻击者可构造自动提交表单，诱导已登录用户访问，从而把受害者密码改为攻击者指定值，实现账户接管。

**source / sink**

- source：body `step`（014.php）
- sink：014.php:61 014.php:60-61 mysqli_query 执行 UPDATE users SET password

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:45` | 受害者浏览器被诱导提交伪造 POST，携带 step=2 | 攻击者控制的 password_new/password_conf |  |
| 2 | `014.php:54-57` | 服务端比较并哈希密码 | 明文 -> md5 |  |
| 3 | `014.php:60-61` | 执行 UPDATE 修改受害者密码 | 写入 users 表 |  |

**POC**

针对 /014.php 的跨站请求伪造 POC。密码修改流程（014.php:61 附近）缺少 CSRF token 校验，攻击者可诱导已登录用户提交伪造请求。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/014.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/014.php?Change=Change&password_new=SUNSET_NEW&password_conf=SUNSET_NEW'
```
预期：状态改变请求被接受或进入下一步流程

3. **读取账户状态/重新登录确认状态确实改变**
预期：密码或业务状态已改变；请求无需 CSRF token/有效验证码

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-b52a2b477f7b`
- 风险提示：请求未体现 HTTP 方法 POST, POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

跨站请求伪造导致受害者账户密码被篡改，攻击者可用新密码登录接管账户。

**CVE / CWE 论证**

CWE-352。改密接口无 CSRF token，外部可触发，链闭合。

**修复建议**

为改密表单加入随机 CSRF token 并在服务端校验；校验 Origin/Referer；改密要求输入旧密码。

**验证说明**

需确认 DVWA 全局是否注入 CSRF token 校验；本文件内未见任何 token 逻辑。
模型 POC 要点：构造自动提交的 HTML 表单，诱导已登录用户访问
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /014.php）：符合 CWE-352。漏洞位于可交付代码 014.php:61，外部输入来自 body 参数 step，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：原草稿使用 GET 请求，但源码入口为 POST 表单，故以 POST 自动提交表单形式呈现；脚本仅为文本工件，不自动执行、不联网。

### F-4: 014.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:2-3`
- **来源**：`rule`

**描述**

014.php:3 通过 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) 判断流程阶段，客户端完全控制 POST 参数 step。攻击者可直接提交 step=1 与 Change，跳过验证码展示/校验阶段，直接进入口令修改逻辑（014.php:7-9 读取 password_new/password_conf，014.php:57 哈希，014.php:60-61 更新）。服务端未见对验证码答案的独立校验或会话绑定，故验证码保护可被绕过。

**source / sink**

- source：request `captcha/step`（014.php）
- sink：014.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014（POST）的验证码绕过 POC。入口在 014.php:3 附近处理 step 与 g-recaptcha-response，未对验证码响应做有效校验即进入密码修改流程。payload 使用 TARGET 占位符，仅限授权测试。

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

攻击者可自动化批量提交口令修改请求，绕过人机校验，配合 CSRF 可对受害者发起无感知的口令变更。

**CVE / CWE 论证**

CWE-804（Guessable CAPTCHA）/流程状态由客户端控制。外部可达性：仅需 POST Change 与 step=1，无需认证前置条件（取决于部署），利用链闭合于 014.php:3 的分支判断。

**修复建议**

将验证码校验结果保存在服务端会话中，流程阶段由服务端状态机推进，禁止客户端通过 step 参数决定是否校验；验证码一次性使用并绑定会话。

**验证说明**

静态证据：入口 POST /014；source=request/captcha/step；sink=014.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST Change + step=1 → 014.php:3 条件成立 → 跳过验证码 → 014.php:8-9 读取新口令 → 014.php:57 md5 → 014.php:60-61 更新数据库。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-804。漏洞位于可交付代码 014.php:3，外部输入来自参数 captcha/step，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：保留原有请求结构，补充会话 Cookie 前置条件；脚本仅为文本工件，不自动执行、不联网。

### F-5: 014.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:56-57`
- **来源**：`rule`

**描述**

014.php:57 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式哈希后写入数据库（014.php:60-61 的 UPDATE 语句）。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，不适合口令存储；攻击者一旦获取数据库即可通过彩虹表/GPU 暴力快速还原口令。该弱点为配置/实现型，无需 HTTP 污点链，证据为源码中明确的 md5( 调用。

**source / sink**

- source：repository `md5(`（014.php）
- sink：014.php:57 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:57` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：014.php:57 使用 md5() 对密码做哈希，属弱哈希算法（CWE-328），无需发送请求即可确认。

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

数据库泄露时口令可被快速离线破解，导致用户账户乃至复用口令的其他系统被接管。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。外部可达性：口令修改接口对已认证用户开放；无需特殊权限即可产生弱哈希记录，属实现缺陷而非输入校验问题。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）并配合 password_verify()；为每个口令生成独立盐；迁移旧 MD5 记录时在用户下次登录时透明重哈希。

**验证说明**

静态证据：入口 POST /014；source=repository/md5(；sink=014.php:57；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST password_new → 014.php:8 → 014.php:56 转义 → 014.php:57 md5() 生成无盐摘要 → 014.php:60-61 写入 users.password。根因为弱哈希算法选择。
POC 备注：纯静态证据，不涉及网络请求；不执行任何命令。

### F-6: 014.php 口令修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`014.php:7-8`
- **来源**：`rule`

**描述**

014.php:7-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf'] 并进入口令更新流程（014.php:57 哈希、014.php:60-61 UPDATE），代码片段中未见 CSRF token、Origin/Referer 校验或 SameSite Cookie 约束。攻击者可构造第三方页面自动提交表单，使已登录受害者在不知情下修改口令。

**source / sink**

- source：query `Change`（014.php）
- sink：014.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `014.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /014 的跨站请求伪造 POC。密码修改流程（014.php:8 附近）缺少 CSRF token 校验，攻击者可诱导已登录用户提交伪造请求。payload 使用 TARGET 占位符，仅限授权测试。

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

受害者账户口令被改为攻击者已知值，导致账户接管；若为管理员账户则影响整站。

**CVE / CWE 论证**

CWE-352。外部可达性：攻击者仅需诱导受害者访问恶意页面；无需认证即可发起跨站请求，利用链依赖受害者已登录会话。

**修复建议**

为表单引入随机 CSRF token 并在服务端会话中校验；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict；敏感操作要求重新输入当前口令。

**验证说明**

静态证据：入口 GET /014；source=query/Change；sink=014.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：恶意页面自动 POST Change/password_new/password_conf → 014.php:8-9 读取 → 014.php:57 md5 → 014.php:60-61 更新受害者口令。缺少 token 校验使跨站请求被接受。
PocWriter 建议（未采纳，缺少端点 /014）：符合 CWE-352。漏洞位于可交付代码 014.php:8，外部输入来自参数 Change，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：原草稿使用 GET 请求，但源码入口为 POST 表单，故以 POST 自动提交表单形式呈现；脚本仅为文本工件，不自动执行、不联网。

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
| safety_guard | 安全防护 | 3.7 | 是 |
| surface_mapper | 攻击面测绘 | 8.26 | 是 |
| deep_finder | LLM 深挖 | 11.15 | 是 |
| candidate_screener | 候选筛选 | 8.59 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.36 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.3 | 是 |
| coordinator | 管线协调 | 8.47 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
