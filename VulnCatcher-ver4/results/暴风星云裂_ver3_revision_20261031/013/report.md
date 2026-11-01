# 落日二号乙漏洞挖掘报告 — 20261031-011548-fd3a66

- 生成时间：2026-10-30T17:16:45.058608+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\013.zip`
- 输入模式：`zip`
- SHA256：`c79a98517aa6ef490facce4e07350a32f2516ff99bcb58570c7b55f84a352bbe`
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

本次审计对象为单文件 PHP 脚本 013.php（55 行，约 1.8KB），共交付 4 条去重后的 findings，全部带 POC（4/4）。最高危为 GEN-89dab2f7ae60：013.php 第 31 行附近修改密码流程存在 SQL 注入（critical，CWE-89），污点路径极短、无框架中间层，属可直接利用面。其余三条集中在同一修改密码页：LLM-a618508f9b61 与 SEM-07d9d737e404 分别从 LLM 与规则视角描述验证码/鉴权可绕过（high，CWE-804），二者高度重叠，建议合并复核；SEM-0bafba96288b 为口令使用 MD5 哈希（medium，CWE-328，注意属 weak_hash 而非 weak_crypto）。POC 齐全但均为静态文本工件，未做任何动态验证；其中 MD5 一条只有静态证据 POC，不能宣称可动态复现。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2150 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 013.php（DVWA captcha 密码修改模块，55 行）。已审计：CAPTCHA 校验逻辑（第 17-23 行）、密码比较与更新（第 25-31 行）、SQL 拼接（第 30 行）。发现 1 条闭合链：硬编码 CAPTCHA 值 + 伪造 User-Agent 绕过校验。第 30 行 SQL 使用 mysqli_real_escape_string 转义且 user 来自 dvwaCurrentUser()，未构成注入；第 27 行 md5 用于口令哈希属 weak_hash 线索，但为 DVWA 教学环境既定实现，未单独立项。未覆盖：无 php.ini/部署配置、无路由与依赖清单，无法评估文件包含、会话固定等其它面。

未覆盖 / 证据缺口：
- 无 php.ini/register_globals/allow_url_include 配置
- 无路由与部署信息
- md5 口令哈希（weak_hash）未单独立项
- 无数据库 schema 与连接配置

## 3. Findings

### F-1: 013.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.53`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:29-31`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交新口令，输入在 013.php:8 被读取为 $pass_new（候选 source 记为 query `password_new`），随后在 013.php:26 仅经过 mysqli_real_escape_string 处理，在 013.php:27 被 md5() 哈希，最终在 013.php:30 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "' LIMIT 1;"，并在 013.php:31 交给 mysqli_query 执行。校验无效的原因：代码未使用预处理/参数化查询，且 md5() 只改变输入形态、不消除 SQL 元字符；mysqli_real_escape_string 在 013.php:26 的调用被包在 isset($GLOBALS["___mysqli_ston"]) && is_object(...) 的三元分支中，若连接对象不可用则走 trigger_error 分支返回空串，转义并不保证生效，因此注入面仍然存在。危险操作是 013.php:31 的 mysqli_query 执行拼接后的 UPDATE 语句。

**source / sink**

- source：query `password_new`（013.php:8）
- sink：013.php:31 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:8` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `013.php:31` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /013（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/013?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-89dab2f7ae60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 users 表中任意用户的 password 字段（越权改密/账户接管），并可通过报错回显（013.php:31 的 die(mysqli_error(...))）泄露数据库结构与数据；结合 LIMIT 1 与 WHERE 条件可构造布尔/联合语义读取其他表内容。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为修改密码表单参数，属 Web 可达入口；无需认证即可到达该处理逻辑（DVWA 低安全级别下无令牌/权限校验）；利用链闭合：外部参数 → $pass_new → md5 → 字符串拼接 $insert → mysqli_query 执行，中间无有效参数化或白名单。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与绑定参数（mysqli_prepare + bind_param 或 PDO prepared statement），彻底移除字符串拼接；对 user 字段使用 dvwaCurrentUser() 的服务端会话值而非拼接；移除 die(mysqli_error(...)) 的详细报错回显，改为通用错误页并记录服务端日志；口令哈希改用 password_hash()/password_verify()（bcrypt/Argon2）替代 md5。

**验证说明**

静态证据：入口 ANY /013；source=query/password_new；sink=013.php:31；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码表单提交 password_new 参数 → 013.php:8 读入 $pass_new → 013.php:26 mysqli_real_escape_string（条件分支，可能不生效）→ 013.php:27 md5($pass_new) → 013.php:30 拼接进 UPDATE 语句 → 013.php:31 mysqli_query 执行，注入生效并可经报错回显泄露信息。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:31 的 SQL 注入 POC。源码中 `$pass_new` 来自请求参数 `password_new`，经 `mysqli_real_escape_string` 后进入 `md5()` 并拼接进 UPDATE 语句（DVWA 风格改密逻辑），注入点参数名为 `password_new`。POC 使用布尔恒真载荷验证注入是否生效，目标地址统一为 TARGET。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-89。证据位于 013.php:31，外部输入来自 query 参数 `password_new`，source→sink 链在给定代码片段内静态闭合，未见参数化查询或白名单校验。
POC 备注：仅限授权测试。脚本为文本工件，不自动执行；执行前将 TARGET 替换为授权目标。若应用要求 POST 或 CSRF token，请按实际表单调整方法与字段，但注入参数名必须保持 `password_new`。

### F-2: DVWA 密码修改页 CAPTCHA 校验可被硬编码值 + User-Agent 伪造绕过

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`013.php:17-23`
- **来源**：`llm_finding`

**描述**

013.php 第 17-23 行的 CAPTCHA 校验条件为 `$resp || ($_POST['g-recaptcha-response']=='hidd3n_valu3' && $_SERVER['HTTP_USER_AGENT']=='reCAPTCHA')`。攻击者无需真正通过 reCAPTCHA，只要提交固定字符串 `hidd3n_valu3` 并把 User-Agent 头设为 `reCAPTCHA`，即可让整个条件恒真，进入密码修改分支（第 25-31 行），在仅需已登录会话的情况下把当前用户密码改为任意值。这是硬编码后门式校验，属于认证/校验机制绕过（CWE-287 / CWE-798 硬编码凭据）。

**source / sink**

- source：body `g-recaptcha-response`（013.php:8-9）
- sink：013.php:23 第 25-31 行密码更新分支：`UPDATE users SET password = md5($pass_new) WHERE user = dvwaCurrentUser()`

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:3` | 检测到 POST 参数 Change，进入密码修改流程 | 请求进入处理分支 |  |
| 2 | `013.php:8-9` | 读取 password_new / password_conf | 攻击者可控明文密码 |  |
| 3 | `013.php:12-15` | 调用 recaptcha_check_answer，正常情况下应返回失败 | $resp 为 false |  |
| 4 | `013.php:17-23` | 短路条件被硬编码值 hidd3n_valu3 与伪造 UA reCAPTCHA 满足，整体为真 | 校验通过（绕过） | 硬编码字符串 + 可伪造的 User-Agent 头，无需真实 CAPTCHA 令牌 |
| 5 | `013.php:25-31` | 两次密码一致后执行 UPDATE 修改当前用户密码 | 密码被 md5 后写入数据库 |  |

**POC**

针对 /vulnerabilities/captcha/（POST）的 认证绕过 POC。注入点：POST 参数 g-recaptcha-response；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'g-recaptcha-response=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`admin`
- POC 目录：`poc/LLM-a618508f9b61`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在不通过 CAPTCHA 的情况下修改账户密码，配合 CSRF 可导致账户接管；硬编码值本身即为后门。

**CVE / CWE 论证**

CWE-287 认证机制不当 / CWE-798 硬编码凭据。外部可达，仅需普通登录会话，链闭合。

**修复建议**

移除硬编码 hidd3n_valu3 与 User-Agent 判断，仅信任 recaptcha_check_answer 的真实返回；对 User-Agent 等客户端头不得用于安全判定。

**验证说明**

需确认 recaptcha_check_answer 在失败时确实返回 false，以及部署环境是否启用该模块。
模型 POC 要点：已登录用户伪造 CAPTCHA 校验并修改密码
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：针对 013.php:23 的认证/验证码绕过 POC。源码在验证码校验分支中直接使用请求体参数 `g-recaptcha-response` 作为判断依据，未做服务端校验，攻击者可提交任意值通过校验。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/captcha/）：符合 CWE-287/CWE-804。证据位于 013.php:23，外部输入来自 body 参数 `g-recaptcha-response`，在给定代码片段内未见服务端校验逻辑。
POC 备注：仅限授权测试。脚本为文本工件，不自动执行；执行前将 TARGET 替换为授权目标。若目标使用真实 reCAPTCHA 服务端校验，此 POC 不适用，需以源码证据为准。

### F-3: 013.php 修改密码流程验证码可绕过（CWE-804）

- **类型**：`captcha_bypass` / CWE-804
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:3-4`
- **来源**：`rule`

**描述**

013.php:3 判断 if( isset( $_POST[ 'Change' ] ) )，随后 013.php:4-5 直接注释「Hide the CAPTCHA form」并置 $hide_form = true，说明服务端在收到 Change 提交后即进入改密逻辑，未在服务端校验验证码答案。候选 source 记为 request `captcha/step`，但源码片段中未见对验证码值/会话状态的比对代码，仅见隐藏表单的展示控制。校验无效的原因：验证码仅作为前端展示/隐藏状态，服务端未强制校验，攻击者可直接提交最终状态（Change）请求跳过验证码步骤。

**source / sink**

- source：request `captcha/step`（013.php）
- sink：013.php:4 	// Hide the CAPTCHA form

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:4` | 验证码流程存在可控 step/client 状态；需直接提交最终状态改变请求复核 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /013（ANY）的 验证码绕过 POC。注入点：ANY 参数 captcha/step；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/013'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/013?captcha/step=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-07d9d737e404`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可自动化批量提交改密请求，绕过人机验证进行口令爆破/批量改密，配合 GEN-89dab2f7ae60 的 SQL 注入可放大自动化攻击规模。

**CVE / CWE 论证**

CWE-804（对关键操作缺少或不正确的验证码校验）。外部可达性：改密表单为 Web 可达入口；无需认证即可提交；利用链闭合：直接 POST Change 参数 → 013.php:3 进入处理分支 → 013.php:4-5 隐藏验证码表单并继续改密，服务端无验证码比对。证据等级为源码推断（llm_inferred），片段仅覆盖 013.php:3-5，验证码生成/校验的完整实现未在输入中给出，属证据缺口。

**修复建议**

在服务端对验证码答案进行强制校验（与会话中存储的验证码值比对，一次性使用并立即失效）；校验失败即中止改密流程并返回错误；对改密接口增加频率限制与 CSRF 令牌；不要仅依赖前端隐藏表单控制流程。

**验证说明**

静态证据：入口 ANY /013；source=request/captcha/step；sink=013.php:4；规则 php-captcha-state。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接 POST Change 参数 → 013.php:3 isset($_POST['Change']) 为真 → 013.php:4-5 隐藏验证码表单并置 $hide_form=true → 继续执行改密逻辑，服务端未比对验证码，验证码被绕过。
PocWriter 建议（未采纳，缺少端点 /013）：针对 013.php:4 的验证码绕过 POC。源码在验证码流程中依据请求参数 `captcha/step` 控制步骤状态，未在服务端绑定会话状态，攻击者可跳过验证码步骤。
PocWriter 建议（未采纳，缺少端点 /013）：符合 CWE-804。证据位于 013.php:4，外部输入来自 query 参数 `captcha/step`，在给定代码片段内未见服务端状态绑定校验。
POC 备注：仅限授权测试。脚本为文本工件，不自动执行；执行前将 TARGET 替换为授权目标。参数名 `captcha/step` 含斜杠，需按源码实际解析方式确认编码。

### F-4: 013.php 口令使用 MD5 哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.81`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`013.php:26-27`
- **来源**：`rule`

**描述**

013.php:27 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式存储（随后在 013.php:30-31 写入 users.password）。这是配置/实现型弱点，不依赖 HTTP 污点链：算法名为 MD5，属快速哈希，无盐、无迭代、无工作因子，原文证据即 013.php:27 的 md5( $pass_new ) 调用。注意该弱点类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。

**source / sink**

- source：repository `md5(`（013.php）
- sink：013.php:27 			$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `013.php:27` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：013.php:27 使用 `md5($pass_new)` 对用户口令做哈希后存储，属于弱哈希算法（无盐、快速哈希），可被彩虹表/GPU 暴力破解。无需发送请求，仅需源码审查。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 013.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0bafba96288b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露后攻击者可用彩虹表/GPU 暴力快速还原弱口令，导致账户接管；相同口令产生相同哈希，便于横向撞库与离线比对。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。外部可达性：口令修改流程直接调用该哈希；无需认证即可触发（DVWA 低安全级别）；利用链闭合：外部口令 → md5 → 写入 users.password，攻击者获取库后离线破解。证据等级为源码推断（llm_inferred）。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）并配合 password_verify() 校验；为每个口令生成独立盐（password_hash 自动处理）；如需兼容旧数据，登录成功时透明升级哈希；禁止在安全用途使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /013；source=repository/md5(；sink=013.php:27；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 013.php:8 读入 $pass_new → 013.php:26 转义 → 013.php:27 md5($pass_new) 生成无盐快速哈希 → 013.php:30-31 写入 users.password；库泄露后离线破解还原口令。
POC 备注：仅限授权测试。本条为静态证据，不产生网络请求；不要对生产数据库执行破解操作。

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
| `auth_bypass` | CWE-287 | 是 | 1 |
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
| `csrf` | CWE-352 |  | 0 |
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
| safety_guard | 安全防护 | 2.95 | 是 |
| surface_mapper | 攻击面测绘 | 9.72 | 是 |
| deep_finder | LLM 深挖 | 6.67 | 是 |
| candidate_screener | 候选筛选 | 6.62 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.4 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.57 | 是 |
| coordinator | 管线协调 | 7.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
