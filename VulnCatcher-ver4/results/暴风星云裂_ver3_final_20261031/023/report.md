# 落日二号乙漏洞挖掘报告 — 20261031-014013-938ad3

- 生成时间：2026-10-30T17:41:17.373154+00:00
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

本次汇总基于已去重的 6 条 findings，全部集中在单文件 023.php（约 30 行），覆盖 sql_injection、csrf、brute_force、weak_hash、weak_crypto 五类。最高危为 GEN-2fcabc51c287（sql_injection，critical，023.php 第 17 行附近，密码修改流程参数直接进入 SQL 拼接），其次为 LLM-fb8cc628a9b1（csrf，high，密码修改接口无 token）与 SEM-e5f2216eebb4（brute_force，high，口令修改流程无速率限制/失败锁定）。6 条 findings 均标记 has_poc=true，但需区分：sql_injection 与 csrf 属 HTTP 型 POC（可构造请求复现，目标用 TARGET 占位，仅限授权测试）；weak_hash（LLM-3fa1c975a8fc）与 weak_crypto（SEM-de6429df0eff）为静态证据 POC，仅说明算法选择缺陷，不能宣称可动态复现；brute_force 的 POC 为请求序列模板，未做动态验证。注意 SEM-de6429df0eff 标题为 MD5 存储口令，按类型规范应归 weak_hash（CWE-328）而非 weak_crypto（CWE-327），存在类型标注串用，需人工纠正后再定级。所有结论均为源码/规则推断（llm_inferred / rule），未经动态验证。

共 **6** 条 finding；**6** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 023.php（30 行，DVWA 密码修改练习页）。已审计其全部入口（$_GET['Change']/password_new/password_conf）与唯一 sink（mysqli_query 执行 UPDATE users）。发现两条可闭合问题：(1) 密码修改缺少 CSRF 防护，可跨站强制改密并接管账户（高危）；(2) 使用无盐 MD5 存储口令（中危，CWE-328）。关于 SQL 注入：password_new 经 mysqli_real_escape_string 转义后再 md5，已不可注入；$current_user 来自 dvwaCurrentUser() 而非请求参数，code_pack 内无证据表明其可控，故不报告 SQL 注入。未覆盖：dvwaCurrentUser() 实现、登录校验逻辑、会话 Cookie 标志（SameSite/HttpOnly）、php.ini 与部署配置均不在 code_pack 内，无法评估；这些缺口可能影响 CSRF 的实际可利用性。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 定义未提供，无法确认 $current_user 是否可被污染
- 登录/会话校验文件未提供，无法确认 md5 存储与登录比较一致性
- 无 Cookie 标志与 SameSite 配置，CSRF 可利用性依赖浏览器默认行为
- 无 php.ini/Web 服务器配置，无法确认 023.php 是否在认证后暴露

## 3. Findings

### F-1: 023.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 password_new（023.php:5 `$pass_new = $_GET['password_new'];`）提交输入。该值在 023.php:11 仅经过 mysqli_real_escape_string 转义后，于 023.php:12 被 md5() 处理，随后在 023.php:16 被直接拼接进 SQL 语句 `UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';`，最终在 023.php:17 由 mysqli_query 执行。由于 md5() 的输出是 32 位十六进制字符串，password_new 中的引号、注释符等元字符在进入 SQL 前已被哈希消解，因此该参数本身无法闭合引号完成注入；真正未参数化拼接的是 $current_user（来自 dvwaCurrentUser()，023.php:15），其是否可控取决于该函数实现，而该实现不在本次 code_pack 范围内。故本条按规则命中，但利用链在已给代码内不闭合。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `023.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /023（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-2fcabc51c287`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若 $current_user 可被外部影响（如会话用户名可控），则可篡改任意用户口令或读取数据库内容；在现有证据下，password_new 路径因 md5 前置处理无法注入，实际影响证据不足。

**CVE / CWE 论证**

CWE-89：SQL 语句由字符串拼接构造而非参数化。外部可达性：GET 参数 password_new 无需认证即可到达 023.php:5（是否要求登录取决于未给出的会话校验）。利用链闭合性：password_new 经 md5 后失去注入能力，$current_user 来源未在 code_pack 中给出，链条不闭合，故不满足 CVE 级论证。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO），对 $current_user 同样参数化；不要依赖 mysqli_real_escape_string 拼接；对用户标识做白名单校验；数据库账户最小权限。

**验证说明**

静态证据：入口 ANY /023；source=query/password_new；sink=023.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 023.php:5 $pass_new → 023.php:11 mysqli_real_escape_string → 023.php:12 md5()（元字符被消解）→ 023.php:16 字符串拼接 $insert → 023.php:17 mysqli_query。注入点在 md5 之后失效，$current_user 的可控性未在给定代码中体现，链条中断。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:17 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 SQL 语句，但该转义在特定字符集/上下文下仍可能被绕过；本 POC 以布尔恒真载荷验证注入是否生效。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-89。漏洞位于 023.php:17，外部输入来自 query 参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并手动运行；禁止对生产库使用破坏性语句。

### F-2: DVWA 密码修改接口（023.php）缺少 CSRF token，可被跨站强制修改受害者密码

- **类型**：`csrf` / CWE-352
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:3-17`
- **来源**：`llm_finding`

**描述**

023.php 在 `isset($_GET['Change'])` 成立时直接读取 `$_GET['password_new']` 与 `$_GET['password_conf']`，两者相等即执行 `UPDATE users SET password=md5(...) WHERE user=dvwaCurrentUser()`。整个流程没有任何 CSRF token、Referer/Origin 校验或二次确认，且使用 GET 方法，攻击者只需诱导已登录受害者访问一个带图片/链接的页面即可把其密码改为攻击者已知值，随后用新密码登录接管账户。

**source / sink**

- source：query `password_new`（023.php:5-6）
- sink：023.php:17 mysqli_query 执行 UPDATE users SET password=... WHERE user=dvwaCurrentUser()（023.php:16-17）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 攻击者构造带 Change=Change&password_new=X&password_conf=X 的 URL，受害者浏览器携带会话 Cookie 发起请求 | 外部 GET 参数进入脚本 |  |
| 2 | `023.php:5-6` | 读取 password_new / password_conf | 原始字符串 |  |
| 3 | `023.php:9` | 仅比较两次输入是否相等，无 CSRF token / Origin 校验 | 相等即通过 |  |
| 4 | `023.php:12` | md5 处理后拼入 UPDATE 语句 | md5 哈希 |  |
| 5 | `023.php:16-17` | 以受害者身份执行 UPDATE，密码被改为攻击者已知值 | 数据库写入 |  |

**POC**

针对 /023.php（GET）的 跨站请求伪造 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/LLM-fb8cc628a9b1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者不知情下修改其密码，实现账户接管；若受害者是管理员则影响整个应用。

**CVE / CWE 论证**

CWE-352 跨站请求伪造：敏感状态变更（密码修改）无 anti-CSRF token，使用 GET 且无 Origin/Referer 校验，外部可触发，链闭合。

**修复建议**

改为 POST 并加入一次性 CSRF token 校验；校验 Origin/Referer；修改密码前要求输入旧密码。

**验证说明**

需确认部署环境未额外加 CSRF 防护（如框架中间件），以及 dvwaCurrentUser() 依赖的会话是否可被跨站携带（SameSite 设置）。
模型 POC 要点：诱导已登录 DVWA 的受害者访问恶意页面，自动提交修改密码请求
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php:17 的 CSRF POC。密码修改接口仅依赖 GET 参数 password_new，未校验 CSRF token 或来源，攻击者可诱导已登录用户浏览器发起请求完成密码变更。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-352。漏洞位于 023.php:17，状态变更接口缺少反 CSRF 令牌与来源校验，具备远程触发条件。
POC 备注：poc.html 为文本工件，需受害者浏览器访问才生效；管线不执行、不联网。仅限授权测试环境使用。

### F-3: 023.php 口令修改流程缺少速率限制与失败锁定（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:5-6 直接读取 password_new/password_conf 并进入修改流程，代码中未见失败计数、账户锁定、验证码或速率限制逻辑。但该文件本身是口令修改功能，并非登录认证入口，是否构成可被枚举的认证面取决于未给出的登录模块与会话校验，故按现有证据只能判定为防护缺失而非可直接利用的暴力破解。

**source / sink**

- source：request `login/password`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e5f2216eebb4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该端点可被未认证或低权限用户反复调用，则可被用于口令猜测或资源消耗；在现有证据下具体影响证据不足。

**CVE / CWE 论证**

CWE-307：缺少对连续失败尝试的节流与锁定。外部可达性：端点可达，但认证前置条件未在 code_pack 中体现。利用链闭合性：缺少登录失败判定逻辑，无法证明可被用于口令枚举，链条不闭合。

**修复建议**

在认证与口令修改入口实施按账户与按 IP 的速率限制、指数退避与临时锁定；引入验证码；记录并告警异常尝试；修改口令要求验证原口令。

**验证说明**

静态证据：入口 ANY /023；source=request/login/password；sink=023.php:5；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：外部请求 → 023.php:5-6 读取参数 → 023.php:16-17 执行更新。缺少失败计数与锁定是根因，但缺少认证失败判定环节，无法闭合为可枚举攻击。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的暴力破解防护缺失 POC。登录/口令校验流程未见失败计数、锁定或速率限制，攻击者可对 login/password 参数进行高频猜测。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-307。证据位于 023.php:5 的认证处理路径，缺少失败计数与限速机制。
POC 备注：POC 仅为文本工件；实际测试须严格控制频率并获授权，避免造成拒绝服务；管线不执行、不联网。

### F-4: 023.php 使用无盐 MD5 存储用户密码（CWE-328）

- **类型**：`weak_hash` / CWE-328
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:12-17`
- **来源**：`llm_finding`

**描述**

密码修改逻辑在 023.php:12 使用 `md5($pass_new)` 生成口令摘要并直接写入 users.password（023.php:16-17）。MD5 为快速、无盐散列，攻击者一旦通过 SQL 注入/数据库泄露获得哈希，可用彩虹表或 GPU 暴力快速还原明文，且相同密码产生相同哈希，便于横向撞库。

**source / sink**

- source：query `password_new`（023.php:5）
- sink：023.php:17 UPDATE users SET password = md5(...)（023.php:16-17）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 读取新密码 | 明文 |  |
| 2 | `023.php:12` | 无盐 MD5 散列 | md5 哈希 |  |
| 3 | `023.php:16-17` | 哈希写入数据库，成为口令存储格式 | 持久化弱哈希 |  |

**POC**

针对 /023.php（GET）的 弱哈希算法 POC。注入点：GET 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱哈希算法 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-3fa1c975a8fc`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

口令存储强度不足，数据库泄露后用户口令可被快速还原，导致账户接管与撞库扩散。

**CVE / CWE 论证**

CWE-328 弱散列：使用 MD5 且无盐存储口令，属可申报的加密实现缺陷。

**修复建议**

改用 password_hash()（bcrypt/argon2）并配合 password_verify()，每用户独立盐。

**验证说明**

需确认登录校验端同样使用 md5 比较（本 code_pack 未包含登录文件），以证明存储格式确为无盐 MD5。
模型 POC 要点：该问题为存储实现缺陷，利用需先获得哈希（如配合 SQL 注入或数据库泄露），再离线破解
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：针对 023.php:12 的弱哈希 POC。源码使用 md5($pass_new) 存储密码，MD5 无盐且计算快速，易被彩虹表与 GPU 暴力破解。本 POC 为静态证据型，辅以一次请求确认哈希写入路径。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-328（弱哈希），非 CWE-327。证据位于 023.php:12 的 md5() 调用，属配置/实现型缺陷，需结合数据敏感度评估。
POC 备注：静态证据型 POC，无需发送破坏性请求；管线不执行、不联网。第 3 步需在授权范围内访问数据库。

### F-5: 023.php 使用 MD5 存储口令（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:11-12`
- **来源**：`rule`

**描述**

023.php:12 `$pass_new = md5( $pass_new );` 对口令使用无盐 MD5 摘要后写入 users 表（023.php:16-17）。MD5 属快速哈希，抗碰撞与抗暴力能力均不足，且此处未见每用户随机盐或迭代拉伸，相同口令产生相同摘要，可被彩虹表与 GPU 高速枚举还原。

**source / sink**

- source：repository `md5(`（023.php）
- sink：023.php:12 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:12` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 023.php:12 的弱加密/弱哈希静态证据 POC。源码对密码使用 md5() 处理，属弱哈希实现；本条目按输入标注为 weak_crypto，但实际算法证据指向 CWE-328 弱哈希，需在报告中区分。

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

数据库泄露后攻击者可快速还原用户明文口令；相同摘要暴露口令复用关系，进而用于撞库与横向移动。

**CVE / CWE 论证**

CWE-328（弱哈希），非 CWE-327 加密算法问题。外部可达性：口令经 023.php:5 进入并在 023.php:12 哈希后落库，属安全用途。利用链闭合性：弱点为算法与实现本身，无需额外污点链即可成立。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验用 password_verify()；对历史 MD5 摘要在用户下次登录时透明升级；禁止在日志或响应中输出摘要。

**验证说明**

静态证据：入口 ANY /023；source=repository/md5(；sink=023.php:12；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET password_new → 023.php:5 → 023.php:11 转义 → 023.php:12 md5() 无盐摘要 → 023.php:16-17 写入 users.password。根因为弱哈希算法与缺少盐/拉伸。
POC 备注：静态证据型，无需发送请求；管线不执行、不联网。

### F-6: 023.php 密码修改缺少 CSRF 防护（CWE-352）

- **类型**：`csrf` / CWE-352
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`023.php:4-5`
- **来源**：`rule`

**描述**

023.php:5-6 通过 GET 读取 password_new 与 password_conf，并在 023.php:16-17 直接执行 UPDATE users SET password 的状态变更操作。代码中未见任何 CSRF token 校验、Origin/Referer 校验，也未将请求方法限制为 POST，因此第三方站点可构造 `<img src="TARGET/023.php?password_new=X&password_conf=X">` 诱导已登录用户浏览器发起请求。是否真正可利用还取决于会话 Cookie 的 SameSite 属性与登录态校验，这两点在 code_pack 中未给出。

**source / sink**

- source：request `password change`（023.php）
- sink：023.php:5 	$pass_new  = $_GET[ 'password_new' ];

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:5` | 状态改变请求未见 CSRF token/Origin 校验；需复核认证与 SameSite 条件 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /023（ANY）的 跨站请求伪造 POC。注入点：ANY 参数 password change；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站请求伪造 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/023?password change=%E8%87%AA%E5%8A%A8%E6%8F%90%E4%BA%A4%E8%A1%A8%E5%8D%95%EF%BC%88%E8%A7%81%20poc.html%EF%BC%89'
```
预期：受害者在已登录状态下自动提交表单，服务端接受状态变更。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`自动提交表单（见 poc.html）`
- POC 目录：`poc/SEM-b5cfc3d8dbaa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者已登录且会话 Cookie 随跨站请求发送的前提下，攻击者可将其账户口令改为已知值，进而接管账户；若目标为高权限账户则导致权限提升。

**CVE / CWE 论证**

CWE-352：状态改变操作无一次性令牌与来源校验，且使用 GET 便于跨站触发。外部可达性：无需攻击者持有凭据，仅需受害者访问恶意页面。利用链闭合性：依赖 SameSite 配置与登录校验，属未在 code_pack 中确认的运行时条件，故为条件性成立。

**修复建议**

改为 POST 并在服务端校验每会话一次性 CSRF token；校验 Origin/Referer；会话 Cookie 设置 SameSite=Lax/Strict 与 Secure；修改口令前要求重新输入原口令。

**验证说明**

静态证据：入口 ANY /023；source=request/password change；sink=023.php:5；规则 php-state-change-no-token。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者页面 → 受害者浏览器携带会话 Cookie 请求 TARGET/023.php?password_new=...&password_conf=... → 023.php:5-6 读取参数 → 023.php:16-17 执行 UPDATE 修改口令。缺少 token 与来源校验是根因。
PocWriter 建议（未采纳，缺少端点 /023）：针对 023.php:5 的 CSRF POC。密码修改表单在页面渲染阶段（第 5 行附近）未嵌入 CSRF token，提交处理缺少来源校验，攻击者可跨站诱导已登录用户提交变更。
PocWriter 建议（未采纳，缺少端点 /023）：符合 CWE-352。证据位于 023.php:5 的表单渲染与提交处理，缺少反 CSRF 机制。
POC 备注：poc.html 为文本工件，需受害者浏览器触发；管线不执行、不联网。仅限授权测试。

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
| safety_guard | 安全防护 | 2.93 | 是 |
| surface_mapper | 攻击面测绘 | 8.35 | 是 |
| deep_finder | LLM 深挖 | 10.66 | 是 |
| candidate_screener | 候选筛选 | 7.54 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.62 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 14.76 | 是 |
| coordinator | 管线协调 | 7.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
