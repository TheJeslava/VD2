# 落日二号乙漏洞挖掘报告 — 20261031-010042-430238

- 生成时间：2026-10-30T17:01:24.183998+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\022.zip`
- 输入模式：`zip`
- SHA256：`c1663891c5c6246a5a3ae32f77dbdd64dbfc5609548a3320760271ea88e17c1b`
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

本次汇总基于单文件 PHP 脚本 022.php（69 行）的静态审计结果，共 3 条去重后 findings，全部带 POC 文本（静态工件，未执行、未动态验证）。最高危为 GEN-e38e01cf9ba5：022.php 第 44 行附近修改密码逻辑存在 SQL 注入（critical，CWE-89），污点路径短、可利用性判断依赖完整源码复核。其次 GEN-1ab8921b1132 被规则标记为 path_traversal（high），但标题与证据显示其实际是第 8 行读取 JSON 请求体被误判为路径穿越，属规则误报，建议降级或撤销，不应作为高危交付。GEN-f7415d28d8c9 为第 39 行使用 MD5 处理口令，属 CWE-328 弱哈希，类型应归 weak_hash 而非 weak_crypto，仅有静态证据 POC，不能宣称可动态复现。POC 齐全度为 3/3，但均为文本工件，无任何动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 022.php 的可见范围（第 1-57 行，共 69 行，第 58-69 行未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token / password_new / password_conf / Change；第 31-33 行在 $change 为真时调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验；第 36 行比较两次密码；第 38 行对 $pass_new 调用 mysqli_real_escape_string；第 39 行 md5 哈希；第 43 行拼接 UPDATE 语句，第 44 行 mysqli_query 执行。逐条核对后未形成可闭合的高危链：(1) SQL 注入不成立——$pass_new 先经 mysqli_real_escape_string 转义再 md5，进入 SQL 的只是 32 位十六进制哈希；$current_user 来自 dvwaCurrentUser()（服务端会话派生，非本次输入可控），且该函数定义不在 code_pack 内，无法证明其受外部控制。(2) 命令执行/文件包含/路径穿越不成立——文件内无 exec/system/shell_exec/passthru/include/require/file_get_contents(用户路径)/readfile 等汇点，第 8 行的 file_get_contents('php://input') 是固定流路径，不含用户输入。(3) 反射型 XSS 不成立——可见范围内无 echo/print 输出 $pass_new/$token 等用户数据，仅赋值 $return_message 字符串常量，输出点应在未送入的第 58-69 行，无法确认是否转义，故不报告。(4) CSRF 不成立——第 33 行存在 checkToken 服务端令牌校验，且 token 取自 $_REQUEST/HTTP_USER_TOKEN 后与 $_SESSION['session_token'] 比对，未见绕过证据；checkToken 与 generateSessionToken 的实现不在 code_pack 内，无法进一步判定。(5) 认证/越权不成立——密码更新目标用户由 dvwaCurrentUser() 决定而非客户端参数，未见 IDOR 证据。surface_notes 中提到的 new File(param,...)、Runtime.exec(args,env)、getParameterNames() 等形态在本文件

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未包含在 code_pack（shown_ranges 仅 1-57），输出/回显逻辑无法审计
- checkToken()、generateSessionToken()、dvwaCurrentUser() 的实现不在 code_pack 内，无法确认令牌校验强度与当前用户来源
- $GLOBALS['___mysqli_ston'] 数据库连接初始化与 dvwa 配置文件未提供，无法确认部署配置与 PHP 版本
- 无路由/端点清单，无法确认 022.php 是否被其他页面包含或存在前置鉴权/WAF

## 3. Findings

### F-1: 022.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过请求参数 `password_new`（022.php:25 读取）提交恶意字符串，该值先经 `mysqli_real_escape_string` 转义（022.php:38），随后被 `md5()` 处理（022.php:39），再拼接到 UPDATE 语句 `$insert` 中（022.php:43），最终在 022.php:44 由 `mysqli_query($GLOBALS["___mysqli_ston"], $insert)` 执行。校验无效的原因：`mysqli_real_escape_string` 只对引号等字符做转义，但拼接方式本身未使用参数化查询，且 `$current_user`（022.php:42，来自 `dvwaCurrentUser()`）同样直接拼入 SQL；一旦转义上下文与字符集/连接状态不匹配，或后续代码路径对 `$pass_new` 做二次处理（如 md5 前的转义顺序），转义即失效。危险操作是数据库 UPDATE 语句执行，可被注入改写 WHERE 条件或追加语句。

**source / sink**

- source：query `password_new`（022.php:25）
- sink：022.php:44 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:25` | 从 query `password_new` 读取外部输入 | 污点进入 insert |  |
| 2 | `022.php:44` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /022（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_new；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/022'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/022?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-e38e01cf9ba5`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可越权修改任意用户（含 admin）的密码，导致账户接管；结合堆叠/联合查询可读取 `users` 表中的用户名与口令哈希，造成敏感数据泄露。

**CVE / CWE 论证**

CWE-89：外部可控参数 `password_new` 未经参数化直接进入 SQL 语句并执行，攻击者无需认证即可通过 HTTP 请求触达（DVWA 模块页面），利用链闭合：source（022.php:25）→ 拼接（022.php:43）→ sink（022.php:44）。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param），将 `$pass_new` 与 `$current_user` 作为参数传入；对 `$current_user` 使用服务端会话身份而非请求数据；对输入做长度与字符白名单校验；数据库账户最小权限，禁止多语句执行。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码表单提交 `password_new` 参数（022.php:25）→ 值经 `mysqli_real_escape_string`（022.php:38）与 `md5`（022.php:39）处理后进入 `$insert` 字符串拼接（022.php:43）→ 在 022.php:44 通过 `mysqli_query` 执行，注入内容随 UPDATE 语句进入数据库。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC（CWE-89）。注入点为查询参数 password_new，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89；漏洞位于 022.php:44，外部输入来自查询参数 password_new，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；执行前须替换为授权测试地址。

### F-2: 022.php JSON 请求体读取被误判为路径穿越（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 `json_decode(file_get_contents('php://input'), true)` 标记为路径穿越汇点。实际分析：`file_get_contents` 的参数是固定字符串 `php://input`，并非由外部输入拼接而成；外部 JSON 数据仅作为 `json_decode` 的输入进入 `$data`，未参与任何文件路径构造。因此不存在攻击者可控路径到达文件读写操作，该候选不成立。

**source / sink**

- source：body `*`（022.php:8）
- sink：022.php:8 $data = json_decode(file_get_contents('php://input'), true);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:8` | 从 body `*` 读取外部输入 | 污点进入 data |  |
| 2 | `022.php:8` | 危险汇点：$data = json_decode(file_get_contents('php://input'), true); | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /022（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 param；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/022'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/022?param=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN1ab89.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN1ab89.txt`
- POC 目录：`poc/GEN-1ab8921b1132`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足：未发现可控文件路径进入文件系统操作，无法论证任意文件读取/写入。

**CVE / CWE 论证**

证据不足。CWE-22 要求外部输入影响文件路径并到达文件操作；本处路径为常量 `php://input`，不满足污点条件。

**修复建议**

无需针对此点修复；若后续代码使用 `$data` 中的字段构造文件路径，应对其做规范化（realpath）与白名单目录校验，拒绝 `..` 与绝对路径。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求体 JSON（022.php:8）→ `json_decode` 得到 `$data`，未流向任何文件路径参数；`file_get_contents` 的实参为常量 `php://input`，链路在解码处终止，未到达可控文件操作。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越/任意文件读写 POC（CWE-22）。注入点为查询参数 param，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22；漏洞位于 022.php:8，外部输入来自请求参数，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET 占位符；执行前须替换为授权测试地址。

### F-3: 022.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:39 对用户新口令执行 `$pass_new = md5( $pass_new );`，将 MD5 作为口令存储前的唯一变换。MD5 为快速、无盐、已被证明存在碰撞的哈希算法，不适合口令保护；攻击者获取数据库后可用彩虹表/GPU 暴力快速还原口令。注意：该弱点类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法缺陷）。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：022.php:39 使用 md5() 对密码做哈希（CWE-328 弱哈希）。无需发送请求，仅记录源码证据。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 022.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-f7415d28d8c9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

数据库泄露时口令可被高效离线破解，导致账户接管与横向移动；同一口令在不同用户间产生相同哈希，暴露口令复用。

**CVE / CWE 论证**

CWE-328：口令使用 MD5 单次无盐哈希，属实现型弱点，无需 HTTP 污点链；证据为 022.php:39 的 `md5( $pass_new )` 原文。

**修复建议**

改用 `password_hash()`（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验使用 `password_verify()`；迁移期可对旧 MD5 值在用户下次登录时重算升级；禁止在日志或响应中输出哈希。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 022.php:38 转义 → 022.php:39 `md5()` 计算 → 结果写入 `users.password`（022.php:43-44）；存储值为无盐 MD5，离线破解成本极低。
POC 备注：仅文本工件，不执行、不联网；本项为离线源码审查，无 HTTP 请求。

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
| `path_traversal` | CWE-22 | 是 | 1 |
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
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.64 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 4.96 | 是 |
| candidate_screener | 候选筛选 | 4.51 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.2 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.28 | 是 |
| coordinator | 管线协调 | 6.43 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
