# 落日二号乙漏洞挖掘报告 — 20261031-011612-2171d5

- 生成时间：2026-10-30T17:17:13.801433+00:00
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

本次汇总 6 条已去重 findings，全部集中在唯一源文件 015.php（83 行单页 PHP 脚本）。最高危为 GEN-c00a42452f04：015.php 第 69 行附近密码修改处 SQL 注入（critical，CWE-89，规则命中，有 POC）。其次为两条 captcha_bypass（LLM-c737fb0d7fd9 与 SEM-2b846713ecdc，high）：验证码状态机可被 step 参数直接跳过（passed_captcha=true），二者指向同一流程，属同一缺陷的规则与模型双视角。中危为改密流程无盐 MD5 存储口令（LLM-1c448a06ff3b / SEM-81919fa4d087，同一 MD5 事实被分别归为 weak_hash 与 weak_crypto，需按 CWE-328 统一口径）、以及密码修改缺少 CSRF 防护（SEM-bb70b3793387）。6 条均带 POC，但其中 weak_hash/weak_crypto 只有静态证据 POC（源码中 md5 调用），不能宣称可动态复现；SQL 注入、captcha_bypass、csrf 的 POC 为 HTTP 形态，目标统一以 TARGET 占位，仅限授权测试，本次未执行、未做动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3350 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 015.php（83 行，DVWA 改密模块）。已逐行审计第 1-83 行：确认两条闭合链——(1) CAPTCHA 状态机绕过：step=2 分支仅信任客户端 passed_captcha 字段（第 55 行），可直接改密（第 68-69 行 UPDATE 落库），高危；(2) 口令使用无盐 md5 存储（第 65 行），中危。第 68 行 SQL 拼接中 $pass_new 已经 mysqli_real_escape_string 转义且随后被 md5 固定为 32 位十六进制，dvwaCurrentUser() 为服务端函数，未构成可利用 SQL 注入，故不报告。第 32-33 行将 $pass_new/$pass_conf 原样回显进隐藏 input 的 value 属性，存在反射型 XSS 可能，但需受害者提交含引号的口令且属自伤型回显，利用价值低，未达 CVE 门槛，仅作线索记录。未发现命令执行、文件包含、反序列化、SSRF 汇点。未覆盖：无 php.ini/路由/依赖清单，无法确认部署与运行时配置；无端点元数据，POC 参数名按 DVWA 约定推断。

未覆盖 / 证据缺口：
- 无运行时配置（allow_url_include、open_basedir 等）
- 无路由/端点清单，参数名与访问路径为推断
- 第 32-33 行口令回显进 HTML 属性的反射型 XSS 未单独立项（利用价值低）
- dvwaCurrentUser() 与数据库连接实现不在 code_pack 内，无法确认其行为

## 3. Findings

### F-1: 015.php 密码修改处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:67-69`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 password_new（015.php:8 读取，经 015.php:64 的 mysqli_real_escape_string 转义后赋给 $pass_new）进入密码更新语句。015.php:68 用字符串拼接构造 `UPDATE `users` SET password = '$pass_new' WHERE user = '...'`，015.php:69 直接交给 mysqli_query 执行。虽然 $pass_new 在 64 行做了 mysqli_real_escape_string，但该转义依赖连接字符集；若连接字符集为 GBK 等宽字节字符集，可用 %bf%27 之类的宽字节序列绕过转义闭合单引号，从而在 UPDATE 语句中注入任意 SQL（例如改写 WHERE 条件或追加子查询）。此外 69 行的 die() 会把 mysqli_error 原文回显到页面，为报错型注入提供回显通道。

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

可越权修改任意用户的 password 字段（包括 admin），或通过报错/布尔差异枚举数据库内容，导致账户接管与数据泄露；结合 MySQL 权限可能进一步读写文件。

**CVE / CWE 论证**

CWE-89：外部可控输入（POST password_new）未经参数化即拼入 SQL 并在 015.php:69 执行，属典型 SQL 注入。外部可达：该逻辑位于密码修改表单处理分支，任何能访问该页面的用户均可提交；利用链闭合：source(015.php:8) → 转义(015.php:64，宽字节可绕过) → 拼接(015.php:68) → 执行(015.php:69)。是否需要认证取决于部署配置，证据不足，但页面本身为公开 DVWA 模块。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），彻底移除字符串拼接；显式设置连接字符集为 utf8mb4（mysqli_set_charset）；关闭错误详情回显，改为记录日志并返回通用错误页；对 password_new 做长度与字符白名单校验。

**验证说明**

静态证据：入口 ANY /015；source=query/password_new；sink=015.php:69；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在密码修改表单提交 password_new=%bf%27 OR 1=1 -- -（宽字节场景）→ 015.php:8 读入 $pass_new → 015.php:64 mysqli_real_escape_string 因字符集问题未能正确转义 → 015.php:68 拼入 UPDATE 语句 → 015.php:69 mysqli_query 执行被篡改的 SQL，错误信息经 die() 回显。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 的 SQL 注入 POC（CWE-89）。注入点为查询参数 password_new，其值被直接拼入 SQL 语句（015.php:69 附近），未做有效参数化。payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-89。漏洞位于 015.php:69，外部输入来自查询参数 password_new，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。脚本中的 curl 命令需人工替换 TARGET 并在授权环境手动运行；禁止对生产环境使用。

### F-2: DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:46-69`
- **来源**：`llm_finding`

**描述**

脚本用两阶段状态机实现改密：step=1 校验 reCAPTCHA 后输出隐藏表单，step=2 才真正执行 UPDATE。但 step=2 分支只检查客户端提交的 $_POST['passed_captcha'] 是否为真值（第 55 行），完全不校验服务端会话中是否真的通过过 CAPTCHA，也不校验 step=1 是否执行过。攻击者可直接构造 step=2 请求并自带 passed_captcha=true，跳过第三方 CAPTCHA 校验，完成对当前登录用户口令的修改。结合第 68 行 UPDATE 语句与第 69 行 mysqli_query，改密动作真实落库。

**source / sink**

- source：body `passed_captcha`（015.php）
- sink：015.php:69 第 68-69 行 UPDATE users SET password=... 经 mysqli_query 执行

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:46` | 入口条件仅要求 POST Change 存在且 step=='2'，不要求先经过 step=1 | 攻击者完全控制 step 取值 | 状态机阶段判断只依赖客户端参数 step |
| 2 | `015.php:55` | CAPTCHA 校验被替换为对客户端字段 passed_captcha 的真值判断 | $_POST['passed_captcha']='true' 为真值，条件 !$_POST[...] 为假，不 return | 服务端未保存/未读取任何 CAPTCHA 通过状态，客户端自报即通过 |
| 3 | `015.php:62` | 两次口令一致即进入改密分支 | password_new == password_conf |  |
| 4 | `015.php:64-65` | 口令经 mysqli_real_escape_string 转义后 md5 哈希 | 明文口令 -> 转义 -> 32 位 md5 |  |
| 5 | `015.php:68-69` | 拼接 UPDATE 语句并执行，修改当前用户口令 | 哈希写入 users.password | 无 CSRF token、无 CAPTCHA 服务端状态校验 |

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

绕过 CAPTCHA 人机校验，对当前会话用户实施口令重置；若配合 CSRF（本页无 token）可诱导受害者改密，导致账户接管。

**CVE / CWE 论证**

CWE-804/ CWE-602（客户端安全控制）。第 55 行仅信任客户端字段，服务端无 CAPTCHA 通过状态，外部可直接构造请求，链闭合。

**修复建议**

在 step=1 通过 CAPTCHA 后将会话标记（如 $_SESSION['captcha_passed']=true 并绑定一次性 nonce），step=2 校验该服务端状态并消费 nonce；同时加入 CSRF token。

**验证说明**

需确认 dvwaCurrentUser() 与数据库连接在目标环境可用；CAPTCHA 绕过逻辑本身由源码直接支撑。
模型 POC 要点：跳过 reCAPTCHA，直接以 step=2 提交改密请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 的验证码绕过 POC（CWE-804）。服务端仅依据客户端提交的 passed_captcha 参数判断验证码是否通过（015.php:69 附近），未做服务端校验，可被直接伪造。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-804。漏洞位于 015.php:69，外部输入来自请求体 passed_captcha，source→sink 链静态闭合，未见服务端校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。需人工替换 TARGET 并在授权环境手动运行。

### F-3: 015.php 验证码流程可被 step 参数绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.77`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:2-3`
- **来源**：`rule`

**描述**

015.php:3 仅以 `isset($_POST['Change']) && $_POST['step']=='1'` 判断是否进入密码修改分支，验证码校验状态完全由客户端提交的 step 字段决定，服务端没有独立的、不可伪造的验证码校验结果（如 session 中一次性标记）。攻击者可直接构造 POST 请求携带 Change=Change 与 step=1，跳过验证码展示与校验阶段，直接执行密码修改逻辑。

**source / sink**

- source：request `captcha/step`（015.php）
- sink：015.php:3 if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:3` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（ANY）的 验证码绕过 POC。注入点：ANY 参数 captcha/step；payload 使用 TARGET 占位符。

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

绕过人机验证保护，使攻击者可自动化、批量地调用密码修改接口，配合 CSRF 或暴力枚举扩大攻击面。

**CVE / CWE 论证**

CWE-804：验证码校验依赖客户端可控状态而非服务端会话状态。外部可达：POST 请求即可触发；无需认证的前提取决于部署，但该分支本身不校验验证码答案。利用链闭合：source(POST step) → 015.php:3 分支判断 → 直接进入 015.php:8 起的密码修改逻辑。

**修复建议**

将验证码校验结果保存在服务端 session 中，并在密码修改前强制校验；验证码一次性使用、校验后立即失效；不要用客户端提交的 step 字段作为流程控制依据；对密码修改接口增加频率限制。

**验证说明**

静态证据：入口 ANY /015；source=request/captcha/step；sink=015.php:3；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接 POST Change=Change&step=1&password_new=...&password_conf=... → 015.php:3 条件成立 → 跳过验证码阶段 → 进入 015.php:8 的密码修改流程。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 的验证码绕过 POC（CWE-804）。captcha/step 参数（015.php:3 附近）被用于控制验证码流程，可被篡改以跳过校验。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-804。漏洞位于 015.php:3，外部输入来自查询参数 captcha/step，source→sink 链静态闭合，未见有效校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。需人工替换 TARGET 并在授权环境手动运行。

### F-4: 改密流程使用无盐 MD5 存储口令（015.php:65）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`015.php:64-68`
- **来源**：`llm_finding`

**描述**

第 65 行对用户新口令仅做 md5() 后写入 users.password，未使用盐值或慢哈希（bcrypt/argon2）。MD5 计算极快且可彩虹表/GPU 爆破，一旦数据库泄露口令可被快速还原；同时无盐导致相同口令哈希相同，可做批量比对。

**source / sink**

- source：body `password_new`（015.php:51）
- sink：015.php:68 第 68 行写入 users.password 的 md5 摘要

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:51` | 读取新口令 | 明文口令 |  |
| 2 | `015.php:65` | 仅 md5 哈希，无盐无迭代 | 32 位十六进制 md5 |  |
| 3 | `015.php:68` | 哈希写入数据库 | 弱哈希落库 |  |

**POC**

针对 /015.php（POST）的 弱哈希算法 POC。注入点：POST 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-1c448a06ff3b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后口令可被快速离线破解，导致账户接管扩散。

**CVE / CWE 论证**

CWE-328/ CWE-916。源码直接可见 md5() 无盐，属实现类缺陷。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/ARGON2ID）并 password_verify() 校验。

**验证说明**

属实现类问题，无需动态验证；需确认生产环境是否沿用该脚本。
模型 POC 要点：配置/实现类问题，无需构造注入请求；通过正常改密即可观察到存储值为无盐 md5
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /015.php）：针对 015.php 的弱哈希算法 POC（CWE-328）。密码经 md5() 处理后存储（015.php:65-68 附近），MD5 属弱哈希，易被彩虹表/暴力破解。
PocWriter 建议（未采纳，缺少端点 /015.php）：符合 CWE-328。漏洞位于 015.php:65-68，密码经 md5() 处理，属弱哈希算法，具备静态证据。
POC 备注：POC 仅为文本工件，不执行、不联网。需人工替换 TARGET 并在授权环境手动运行。

### F-5: 015.php 密码修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:7-8`
- **来源**：`rule`

**描述**

015.php:8-9 直接读取 $_POST['password_new'] 与 $_POST['password_conf'] 并执行密码更新，整个状态改变请求未见 CSRF token、Origin/Referer 校验或二次确认。攻击者可构造恶意页面，诱导已登录用户浏览器自动提交该表单，从而在用户不知情下修改其密码。

**source / sink**

- source：request `password change`（015.php）
- sink：015.php:8 	$pass_new  = $_POST[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:8` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /015（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

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

已登录用户在访问攻击者页面时密码被静默修改，导致账户被攻击者接管（账户劫持）。

**CVE / CWE 论证**

CWE-352：状态改变操作无防伪令牌。外部可达：跨站表单 POST 即可触发；利用链闭合：攻击者页面 → 受害者浏览器携带会话 Cookie 提交 POST → 015.php:8 读取参数 → 015.php:69 执行 UPDATE。SameSite 等运行时缓解措施证据不足。

**修复建议**

为密码修改表单引入随机 CSRF token 并在服务端 session 中校验；校验 Origin/Referer；对敏感操作要求重新输入当前密码；将会话 Cookie 设置为 SameSite=Lax/Strict。

**验证说明**

静态证据：入口 ANY /015；source=request/password change；sink=015.php:8；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：受害者登录后访问攻击者构造的自动提交表单页面 → 浏览器携带会话 Cookie 向 015.php 提交 password_new/password_conf → 015.php:8 读取参数 → 015.php:69 更新密码。
PocWriter 建议（未采纳，缺少端点 /015）：针对 015.php 的跨站请求伪造 POC（CWE-352）。密码修改流程（015.php:8 附近）缺少 CSRF token 校验，可被第三方页面自动提交表单触发。
PocWriter 建议（未采纳，缺少端点 /015）：符合 CWE-352。漏洞位于 015.php:8，密码修改流程缺少 CSRF token 校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。poc.html 需人工部署并在授权环境测试；禁止对生产环境使用。

### F-6: 015.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.46`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`015.php:64-65`
- **来源**：`rule`

**描述**

015.php:65 对新密码执行 `$pass_new = md5($pass_new)`，随后在 015.php:68 写入 users 表 password 字段。MD5 为快速、无盐的弱哈希，用于口令存储时易受彩虹表与 GPU 暴力破解；且此处未见每用户随机盐值。

**source / sink**

- source：repository `md5(`（015.php）
- sink：015.php:65 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `015.php:65` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（CWE-327/328）。015.php:65 使用 md5() 处理密码，属弱哈希算法，无需发送请求即可确认。

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

数据库泄露后攻击者可快速还原用户明文口令，并利用口令复用横向接管其他系统账户。

**CVE / CWE 论证**

CWE-328：使用 MD5 这一已破解的弱哈希保护口令。属配置/实现型弱点，无需 HTTP 污点链；原文证据为 015.php:65 的 md5( $pass_new ) 调用与 015.php:68 的 password 字段写入。外部可达性体现在密码修改接口对任意用户开放。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验使用 password_verify()；对历史 MD5 记录在用户下次登录时透明升级；禁止在任何安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /015；source=repository/md5(；sink=015.php:65；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新密码 → 015.php:8 读取 password_new → 015.php:64 转义 → 015.php:65 md5() 计算 → 015.php:68 拼接 UPDATE → 015.php:69 写入数据库，口令以无盐 MD5 形式持久化。
POC 备注：POC 仅为文本工件，不执行、不联网。仅需源码审查。

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
| safety_guard | 安全防护 | 2.6 | 是 |
| surface_mapper | 攻击面测绘 | 8.9 | 是 |
| deep_finder | LLM 深挖 | 12.58 | 是 |
| candidate_screener | 候选筛选 | 6.96 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.29 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 11.62 | 是 |
| coordinator | 管线协调 | 7.4 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
