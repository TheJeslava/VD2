# 落日二号乙漏洞挖掘报告 — 20261031-011536-792c55

- 生成时间：2026-10-30T17:16:19.897426+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 012.php（35 行，无框架、无路由配置）。最高危为 GEN-3b547dba7a60：012.php 登录表单 SQL 注入（critical，CWE-89，行 1-15），其次为 SEM-536ee862bb25 登录接口缺少暴力破解防护（high，CWE-307，行 1-3），以及 SEM-0ce3358fa05b 使用 MD5 存储口令（medium，CWE-328 弱哈希，行 1-11）。3 条 finding 均标注 has_poc=true，POC 齐全；但需注意 SQL 注入与暴力破解属 HTTP 类 POC，MD5 弱哈希仅为静态证据 POC，不能宣称可动态复现。所有结论均为源码/规则推断（llm_inferred / rule），未做任何动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 012.php（1-35 行，完整未截断）。该脚本为 DVWA 风格的登录片段：入口为 GET 参数 Login/username/password（第 3、5、9 行）。username 与 password 均经 mysqli_real_escape_string 转义（第 6、10 行），password 再经 md5（第 11 行），随后拼接进 SELECT 查询（第 14 行）并由 mysqli_query 执行（第 15 行）。由于两个可控参数都经过 mysqli_real_escape_string 处理，且查询为单引号包裹的字符串字面量，未发现可闭合的 SQL 注入链（引号、反斜杠均被转义，无法逃逸字面量）。第 23 行 $user 回显到 HTML，但 $user 已经过 mysqli_real_escape_string，该函数会转义 ' " \ 及 NUL，虽非 HTML 编码，但无法注入 < > 标签，反射型 XSS 链不闭合。第 24 行 $avatar 来自数据库行（$row["avatar"]），属于存储型数据，但 code_pack 中不存在写入 avatar 的代码（无 INSERT/UPDATE），无法确认攻击者可控，二次注入/存储型 XSS 的存储写点缺失，按规则不报告。第 11 行 md5 用于口令哈希，属 weak_hash（CWE-328）线索，但该脚本仅做校验比对，未生成令牌或会话，且无注册/改密逻辑，单独不构成可申报 CVE 的利用链，仅记录为线索。第 28 行 sleep(2) 为登录失败延时，可作时序枚举线索，但无用户枚举差异证据，不报告。未发现命令执行、文件包含、反序列化、SSRF、路径穿越等 sink。未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 display_errors、magic_quotes 等运行时设置对转义的影响
- 无数据库 schema 与写入 avatar 的代码，存储型 XSS/二次注入的存储写点无法确认
- 无认证/会话代码，无法评估登录成功后的会话固定或权限提升
- md5 口令哈希（第 11 行）为 weak_hash 线索，但缺少注册/改密/令牌生成上下文，利用链不闭合
- sleep(2) 登录失败延时（第 28 行）为时序侧信道线索，缺少用户存在性差异证据

## 3. Findings

### F-1: 012.php 登录表单 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 参数 `username`（以及同表单的 `password`）提交输入。012.php:5 从请求中读取 `username` 到 `$user`，012.php:10 仅对 `$pass` 调用 mysqli_real_escape_string，而 `$user` 未见任何转义或参数化处理；012.php:14 将 `$user` 与 `$pass` 直接拼接进 SQL 语句 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"，012.php:15 通过 mysqli_query 执行该语句。由于 `$user` 未经转义即进入单引号字符串上下文，攻击者可闭合引号注入任意 SQL 片段（如 `' OR '1'='1' -- `），校验完全失效。此外 012.php:15 的 die() 分支会把 mysqli_error 的数据库错误信息回显到页面，构成报错型注入的辅助信息泄露通道。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /012（ANY）的 SQL 注入 POC。注入点：ANY 参数 username；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-3b547dba7a60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可绕过登录认证（以任意用户身份登录，包括管理员）；可借助 UNION/布尔/报错注入读取 `users` 表及其他库表数据（口令哈希、用户信息），在数据库账号权限较高时可进一步读写文件或造成数据篡改，属于认证绕过与敏感数据泄露。

**CVE / CWE 论证**

CWE-89：外部可控输入 `username` 未经参数化或转义即拼接到 SQL 语句并在 012.php:15 执行，污点链闭合。该入口为 GET 参数，无需认证即可访问登录页触发，远程可利用；错误信息回显进一步降低利用门槛。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param 或 PDO prepared statement），彻底避免字符串拼接；对 `username`/`password` 做长度与字符白名单校验；关闭数据库错误详情回显，改为记录服务端日志并返回通用错误页；数据库账号遵循最小权限，禁止 FILE 等特权。

**验证说明**

静态证据：入口 ANY /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：GET 请求携带 `username` → 012.php:5 读取到 `$user` → 012.php:14 直接拼接进 SQL → 012.php:15 mysqli_query 执行 → 返回结果用于登录判定，注入生效。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:15 的 SQL 注入 POC。源码中外部输入来自查询参数 username，未经有效净化即拼接进 SQL 语句（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于 012.php:15，外部输入来自查询参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。目标地址使用 TARGET 占位符，仅限授权测试。

### F-2: 012.php 登录接口缺少暴力破解防护（CWE-307）

- **类型**：`brute_force` / CWE-307
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:2-3`
- **来源**：`rule`

**描述**

012.php:3 通过 `isset( $_GET[ 'Login' ] )` 判定登录请求，随后在 012.php:5 读取 `username`、012.php:10-11 处理 `password` 并查询数据库。整个流程中未见失败计数、账号锁定、验证码、延迟或速率限制逻辑，攻击者可对同一账号无限次提交口令猜测。需说明：该结论基于本文件可见代码，若存在上游 WAF/网关限流则实际风险降低，属证据不足部分。

**source / sink**

- source：request `login/password`（012.php）
- sink：012.php:3 if( isset( $_GET[ 'Login' ] ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 登录流程未见失败计数、锁定或速率限制；需授权环境重复请求确认 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /012（ANY）的 暴力破解防护缺失 POC。注入点：ANY 参数 login/password；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-536ee862bb25`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

可对已知用户名进行在线口令爆破或撞库，配合弱口令与无盐 MD5 存储（见 SEM-0ce3358fa05b）显著提高账号接管成功率；亦可作为用户名枚举通道（不同响应差异）。

**CVE / CWE 论证**

CWE-307：登录端点缺少对过量认证尝试的限制。入口为 GET 参数 `Login`/`username`/`password`，无需认证即可反复调用，外部可达。

**修复建议**

引入按账号+IP 的失败计数与指数退避、临时锁定、验证码；统一失败响应避免用户名枚举；记录并告警异常登录频率；结合强口令策略与多因素认证。

**验证说明**

静态证据：入口 ANY /012；source=request/login/password；sink=012.php:3；规则 php-login-no-throttle。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者循环发送带 `Login`、`username`、`password` 的 GET 请求 → 012.php:3 进入登录分支 → 012.php:14-15 每次执行口令校验 → 无任何计数/锁定阻断，可持续猜测直至命中。
PocWriter 建议（未采纳，缺少端点 /012）：针对 012.php:3 的暴力破解防护缺失 POC（CWE-307）。登录相关参数 login/password 缺乏速率限制/锁定机制。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-307。漏洞位于 012.php:3，登录参数 login/password 缺乏防护机制，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构；脚本仅为文本工件，不执行、不联网。目标地址使用 TARGET 占位符，仅限授权测试。

### F-3: 012.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:10-11`
- **来源**：`rule`

**描述**

012.php:10 先对 `$pass` 做 mysqli_real_escape_string，随后 012.php:11 执行 `$pass = md5( $pass );`，将用户口令以无盐 MD5 形式参与后续 SQL 比较（012.php:14 的 password 字段）。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，用于口令存储/校验属安全用途误用。注意：此处应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。

**source / sink**

- source：repository `md5(`（012.php）
- sink：012.php:11 	$pass = md5( $pass );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:11` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：012.php:11 使用 md5() 对密码进行哈希（CWE-328 弱哈希，非 CWE-327 弱加密）。无需发送请求，仅需源码审查确认。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 012.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-0ce3358fa05b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

一旦 `users` 表泄露（可与本文件 SQL 注入叠加），攻击者可用彩虹表/GPU 高速爆破在极短时间内还原弱口令，导致账号接管；无盐设计使相同口令产生相同哈希，便于批量破解与撞库。

**CVE / CWE 论证**

CWE-328：012.php:11 明确对安全敏感数据（登录口令）使用 MD5。该弱点为配置/实现型，不依赖 HTTP 污点链，但可通过登录接口与数据库读取路径被外部间接利用。

**修复建议**

改用 password_hash()（PASSWORD_BCRYPT/Argon2id）生成带盐慢哈希，校验使用 password_verify()；对历史 MD5 记录在用户下次登录成功时透明升级；禁止在任何新代码中使用 md5()/sha1() 处理口令或令牌。

**验证说明**

静态证据：入口 ANY /012；source=repository/md5(；sink=012.php:11；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交口令 → 012.php:10 转义 → 012.php:11 md5() 计算 → 012.php:14 与库中 password 字段比较；库中存储的即为无盐 MD5，泄露即可离线高速破解。
POC 备注：纯静态证据，不发送任何请求；不执行、不联网。

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
| safety_guard | 安全防护 | 2.34 | 是 |
| surface_mapper | 攻击面测绘 | 9.47 | 是 |
| deep_finder | LLM 深挖 | 3.91 | 是 |
| candidate_screener | 候选筛选 | 4.1 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.95 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.03 | 是 |
| coordinator | 管线协调 | 6.91 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
