# 落日二号乙漏洞挖掘报告 — 20261031-014008-84a8b0

- 生成时间：2026-10-30T17:40:51.787339+00:00
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

本次汇总基于单文件 PHP 脚本 022.php（69 行）的源码审计结果，共交付 2 条 findings，均带 POC。最高危为 022.php 第 44 行附近的修改密码功能 SQL 注入（CWE-89，critical，rule 来源），污点从请求参数直接流入 SQL 语句，单文件内路径极短；另一条为 022.php 第 39 行附近使用 MD5 存储口令（CWE-328 弱哈希，medium）。需注意：该条被归类为 weak_crypto，但按类型规范 MD5/SHA1 应归 weak_hash（CWE-328），建议在交付时校正类型标签。POC 齐全度为 2/2，但其中 SQL 注入为 HTTP 型 POC（目标以 TARGET 占位，仅限授权测试），弱哈希条目仅有静态证据 POC，不能宣称可动态复现。本次无二次注入链、无被隔离文件、无 prompt_injection 诱导文本。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 022.php 的 1-57 行（共 69 行，58-69 未送入）。该文件是 DVWA 风格的密码修改片段：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token/password_new/password_conf/Change；第 33 行调用 checkToken() 做 Anti-CSRF 校验（函数体不在 code_pack 内，无法确认其实现是否可绕过）；第 36 行比较两次密码；第 38 行 mysqli_real_escape_string 转义后第 39 行 md5 哈希，第 43 行拼接 UPDATE 语句、第 44 行 mysqli_query 执行。审计结论：(1) SQL 注入不成立——进入拼接的 $pass_new 已经过 mysqli_real_escape_string 且随后被 md5() 转为 32 位十六进制，$current_user 来自 dvwaCurrentUser()（服务端会话派生，非请求参数），两者均无法改变 SQL 语法；(2) 命令/代码/文件/包含类 sink 在该片段中不存在，无 system/exec/eval/include/file_get_contents(路径) 等调用；(3) 无 echo/print 输出点，反射型 XSS 不成立；(4) 未见 setcookie/session_set_cookie_params/rand/mt_rand/openssl_encrypt/硬编码凭据，配置型候选（weak_hash 之外的 weak_random/weak_crypto/insecure_cookie/hardcoded_secret）在本片段内无证据；md5 用于口令存储属 weak_hash(CWE-328)，但这是 DVWA 教学靶场的既有设计、无独立可利用链，且缺少注册/校验侧代码，不足以申报 CVE，故不单独立项。未闭合线索：checkToken() 与 generateSessionToken()、dvwaCurrentUser() 的实现均在 code_pack 之外（第 58-69 行及被 include 的公共库未提供），无法判断 CSRF token 校验是否可绕过、会话令牌是否弱随机；若后续能提供这些实现，应重新评估 CSRF 与 weak_random。

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入 code_pack
- checkToken()/generateSessionToken()/dvwaCurrentUser() 的实现不在 code_pack 内，无法评估 token 校验强度与会话令牌随机性
- 无端点清单、无部署配置，无法确认脚本对外暴露面与认证要求
- 无数据库 schema 与其他 DVWA 模块代码，无法评估跨模块利用链

## 3. Findings

### F-1: 022.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 022.php 提交修改密码表单，其中 password_new 参数（022.php:25 读取）进入 $pass_new。代码在 022.php:38 仅用 mysqli_real_escape_string 对 $pass_new 做转义，随后在 022.php:39 执行 $pass_new = md5($pass_new)，把转义后的字符串整体哈希成 32 位十六进制串。哈希结果只含 [0-9a-f]，因此后续拼接进 SQL 时不再携带任何引号或元字符，单看 $pass_new 这一路，转义加哈希实际上阻断了注入。真正的注入点在 022.php:43 的拼接语句：$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';"; 其中 $current_user 由 022.php:42 的 dvwaCurrentUser() 取得，直接以字符串拼接方式进入 SQL，未做参数化或转义，最终在 022.php:44 由 mysqli_query 执行。若 dvwaCurrentUser() 的返回值可被攻击者影响（例如来源于会话中可写字段、Cookie 或请求头映射的用户名），则可在 user 条件处闭合引号注入任意 SQL。需要说明：本次输入未提供 dvwaCurrentUser() 的实现，该函数的可控性证据不足，因此该链的闭合性属于推断而非已验证。

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

若 $current_user 可控，攻击者可构造 user 条件注入，篡改 users 表中任意账号（含 admin）的 password 字段，实现账号接管与越权登录；也可借助 UPDATE 语句的布尔/时间盲注逐位读取数据库内容（如其他用户口令哈希、会话数据），造成敏感数据泄露。由于该语句本身是 UPDATE，注入还可扩展为堆叠或多条件更新，破坏数据完整性。

**CVE / CWE 论证**

CWE-89：SQL 语句由字符串拼接构造（022.php:43），外部可控数据（$current_user，经 dvwaCurrentUser()）未经参数化即进入 mysqli_query（022.php:44）。外部可达性：022.php 为 DVWA 的 Web 端点，修改密码表单无需额外权限即可提交，属远程可达；无需认证的前提取决于部署配置（DVWA 默认需登录，低安全级别下会话即可触达），因此“无需认证”应表述为“在已获得普通会话的前提下无需更高权限”。利用链闭合性：source（请求参数/会话用户标识）→ $current_user → 字符串拼接 → mysqli_query 的路径在源码中成立，但 dvwaCurrentUser() 的具体数据来源未在证据中给出，闭合性为 llm_inferred。

**修复建议**

1) 将 022.php:43-44 改为预处理语句：$stmt = $GLOBALS["___mysqli_ston"]->prepare("UPDATE `users` SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user); $stmt->execute(); 彻底消除拼接。2) 对 $current_user 做服务端白名单校验（仅允许已认证会话绑定的用户名），不要从请求可控字段推导当前用户。3) 保留 mysqli_real_escape_string 仅作为纵深防御，不作为主要防护。4) 数据库账号遵循最小权限，仅授予 users 表必要列的 UPDATE 权限。5) 修改密码操作增加 CSRF token 与旧密码校验。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码请求中影响当前用户标识（如会话/Cookie 映射的用户名）→ 022.php:42 dvwaCurrentUser() 返回该值存入 $current_user → 022.php:43 以字符串拼接构造 UPDATE 语句，$current_user 未参数化 → 022.php:44 mysqli_query 执行 → 注入生效，篡改任意用户口令或盲注读取数据。注意 $pass_new 一路因 022.php:39 的 md5 哈希而失去注入能力，注入面集中在 $current_user。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 password_new，被直接拼入 SQL 语句，未做有效净化。请求方法按源码入口记为 ANY（实际以 GET 查询串投递）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89（SQL 注入）。漏洞位于 022.php:44，外部输入来自查询参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。保留原确定性 POC 的请求结构，仅补充基线/对照步骤与预期结果。POC 中禁止使用 DROP 等破坏性语句；目标地址一律写 TARGET。原 poc.sh 中的 curl 命令仅作参考文本，管线不运行。

### F-2: 022.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:38 先用 mysqli_real_escape_string 处理 $pass_new，随后 022.php:39 执行 $pass_new = md5( $pass_new );，把用户新口令以无盐 MD5 单轮哈希形式写入数据库（022.php:43 的 UPDATE 语句将 password 列设为该哈希值）。MD5 属于已破译的快速哈希算法，存在已知碰撞攻击，且对高速 GPU 暴力破解与彩虹表几乎无抵抗力；此处未使用盐值、未使用慢哈希（bcrypt/scrypt/Argon2），保护对象是用户登录口令这一安全敏感数据。该弱点为配置/实现型，不依赖 HTTP 污点链，证据即 022.php:39 的 md5( 调用原文。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：022.php:39 使用 md5() 对密码 $pass_new 做哈希。MD5 属弱哈希算法（CWE-328），不应用于口令存储。本项为配置/代码型候选，无 HTTP 污点，无需发送请求。

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

数据库一旦泄露（如通过同文件 GEN-e38e01cf9ba5 的 SQL 注入读取 users 表），攻击者可用彩虹表或 GPU 集群在极短时间内还原大量用户明文口令，进而横向登录其他系统；相同口令产生相同哈希，也便于批量撞库与用户画像关联。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于口令存储，属安全用途的弱哈希，而非 CWE-327 的加密算法误用。外部可达性：口令哈希在用户注册/改密时生成并持久化，攻击者通过数据库泄露或注入读取即可离线攻击，无需在线交互；无需认证即可对已获取的哈希进行离线破解。利用链闭合性：022.php:39 的 md5() 调用与 022.php:43 的写入路径在源码中直接可见，闭合性成立；实际破解难度取决于口令强度，属推断。

**修复建议**

1) 改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2id）生成带盐慢哈希，校验用 password_verify。2) 迁移期可对存量 MD5 哈希在用户下次登录成功后透明重哈希升级。3) 强制口令复杂度与长度下限，禁止常见弱口令。4) 数据库连接与备份加密，限制 users 表读取权限，降低哈希外泄面。5) 结合 GEN-e38e01cf9ba5 的修复，阻断通过注入批量导出哈希的路径。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户在 022.php 修改密码 → 022.php:25 读取 password_new → 022.php:38 转义 → 022.php:39 md5() 生成无盐弱哈希 → 022.php:43-44 写入 users.password。攻击者通过数据库泄露或 SQL 注入取得哈希后离线彩虹表/暴力破解还原明文口令。
POC 备注：纯静态证据，不发送任何请求，不执行脚本。poc_readme.md 仅记录文件、行号与代码片段，供人工复核。

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
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.32 | 是 |
| surface_mapper | 攻击面测绘 | 7.74 | 是 |
| deep_finder | LLM 深挖 | 3.9 | 是 |
| candidate_screener | 候选筛选 | 4.22 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.88 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.37 | 是 |
| coordinator | 管线协调 | 5.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
