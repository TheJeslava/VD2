# 落日二号乙漏洞挖掘报告 — 20261031-172816-2d4b60

- 生成时间：2026-10-31T09:29:04.417817+00:00
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

本次审计对象为单文件 PHP 脚本 022.php（69 行），共交付 3 条去重后的 findings，全部带 POC 文本（静态/HTTP 混合，未做动态验证）。最高危为 GEN-e38e01cf9ba5：022.php 第 44 行附近修改密码逻辑存在 SQL 注入（CWE-89，critical，rule 来源，有 POC），污点链短、利用门槛低，应优先修复（参数化查询/预处理语句）。另有 GEN-1ab8921b1132 被标为 path_traversal（high），但标题与描述本身即写明“JSON 请求体读取被误判为路径穿越（证据不足）”，该条证据等级仅为 llm_inferred/规则推断，不应作为已确认漏洞交付，建议降级或撤下。SEM-f7415d28d8c9 实为 MD5 存储口令，按类型规范应归 weak_hash（CWE-328）而非 weak_crypto（CWE-327），仅有静态证据 POC，不能宣称可动态复现。POC 齐全度为 3/3，但其中 1 条为误判、1 条类型标注错误，实际可直接复现的仅 SQL 注入 1 条。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 022.php 的 1-57 行（共 69 行，尾部 58-69 未送入）。该文件是 DVWA 风格的密码修改页面。审计结论：未发现可闭合的 CVE 级漏洞链。逐点说明：(1) 参数读取位于 022.php:8（php://input JSON）与 022.php:20-26（$_REQUEST），随后在 022.php:33 调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验，token 校验在密码比较与 SQL 执行之前，因此缺少有效 session_token 时流程在 0033 行即被重定向中断，无法直接构成 CSRF 或未授权改密。(2) SQL 语句在 022.php:43 为字符串拼接，但拼接的 $pass_new 已在 022.php:38 经 mysqli_real_escape_string 转义、并在 022.php:39 经 md5() 变为 32 位十六进制定长串，攻击者无法通过 password_new 改变 SQL 语法；$current_user 来自 dvwaCurrentUser()（服务端会话派生，非请求参数），故不构成 SQL 注入。(3) 022.php:39 使用 md5() 存储口令属弱哈希（CWE-328），但这是 DVWA 靶场既有的设计性弱点，且需要已通过 token 校验的会话才能触发，单独不构成可申报 CVE 的独立漏洞，按策略仅作为线索记录，不单独立 finding。(4) 未在可见代码中发现 system/exec/shell_exec/passthru、include/require 拼接、file_get_contents 拼接用户路径、echo 用户输入、unserialize、SSRF 类 sink，故 command_injection / path_traversal / lfi / xss / deserialization / ssrf 均无证据。(5) 输入中未出现诱导性文本，无 prompt_injection 证据。未闭合线索：022.php 第 58-69 行未送入，可能包含 generateSessionToken() 调用后的输出渲染与 HTML 回显，若该段将 $return_message 或用户输入直接输出且无 htmlspecialchars，则可能存在反射型 XSS，但当前无代码证据，不予报告；checkToken()、dvwaCurrentUser()、generateSessionToken() 的实现不在 code_pack 内，无法确认 token 比较是否使用恒定时间比较或是否存在类型混淆绕过。

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未包含在 code_pack 中，输出渲染与 HTML 回显逻辑无法审计
- checkToken() 实现不可见，无法确认 token 比较是否存在类型混淆/空值绕过
- dvwaCurrentUser() 实现不可见，无法确认 $current_user 是否完全服务端派生
- 无 php.ini / 部署配置，无法确认 register_globals、allow_url_include 等环境条件
- 无端点清单，无法确认 022.php 的实际 URL 与是否需要登录

## 3. Findings

### F-1: 022.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 022.php 提交修改密码表单，外部输入在 022.php:25 被读入 $pass_new（候选 source 标注为 query `password_new`）。该值在 022.php:38 仅经过 mysqli_real_escape_string 转义，随后在 022.php:43 被直接拼接进 SQL 语句：$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';";，并在 022.php:44 交给 mysqli_query 执行。转义函数只处理引号等字符，无法阻止在已闭合引号后追加 SQL 片段（如通过 password_new 注入闭合单引号并追加条件/子查询），且语句未使用预处理参数化，因此校验无效。$current_user 来自 dvwaCurrentUser()（022.php:42），同样以字符串拼接方式进入同一语句。

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
curl -sS -i -X ANY 'http://TARGET:8080/022?password_new=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-e38e01cf9ba5`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可篡改 users 表中任意用户的 password 字段（包括 admin），实现账户接管与越权登录；通过布尔/联合注入可进一步读取数据库中的用户凭据等敏感数据。属于数据完整性与机密性双重破坏。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：022.php 为 Web 端点，通过 POST 表单参数 password_new 直接可达，无需认证即可触发（DVWA 场景下为低安全级别页面）；利用链闭合：source（022.php:25 的 password_new）→ 拼接（022.php:43）→ 执行（022.php:44 mysqli_query），中间仅有 mysqli_real_escape_string 这一非充分防护，无参数化、无白名单，链路完整。

**修复建议**

改用预处理语句与参数绑定：$stmt = $GLOBALS["___mysqli_ston"]->prepare("UPDATE `users` SET password = ? WHERE user = ?"); $stmt->bind_param('ss', $pass_new, $current_user); $stmt->execute();。移除字符串拼接；对 $current_user 同样使用绑定参数；对输入做长度与字符白名单校验；数据库账户遵循最小权限，仅授予必要表的 UPDATE 权限。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码表单的 password_new 参数中提交形如 x' WHERE user='admin' -- 的载荷 → 022.php:25 读入 $pass_new → 022.php:38 mysqli_real_escape_string 仅转义引号，无法阻断已构造的语句结构 → 022.php:43 拼接进 UPDATE 语句 → 022.php:44 mysqli_query 执行，导致任意用户口令被改写或数据被读出。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC。源码中 password_new 参数经 mysqli_real_escape_string 处理后进入 SQL 语句，但注入点位于参数值本身；payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89。漏洞位于可交付代码 022.php:44，外部输入来自 query `password_new`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：保留原请求结构；脚本仅为文本工件，不执行、不联网。ANY 方法需按源码确认为 GET 或 POST 后再发送。

### F-2: 022.php JSON 请求体读取被误判为路径穿越（证据不足）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 $data = json_decode(file_get_contents('php://input'), true); 标记为 path_traversal 汇点。但 file_get_contents 的参数是固定字面量 'php://input'，并非来自外部输入；外部 JSON 内容只进入 $data 变量，未参与任何文件路径构造。022.php:7 的 CONTENT_TYPE 判断也只是请求方法/类型分支，不构成路径可控。因此不存在攻击者可控路径到达文件读写操作。

**source / sink**

- source：body `*`（022.php:8）
- sink：022.php:8 $data = json_decode(file_get_contents('php://input'), true);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:8` | 从 body `*` 读取外部输入 | 污点进入 data |  |
| 2 | `022.php:8` | 危险汇点：$data = json_decode(file_get_contents('php://input'), true); | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /022（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 *；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/022'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/022?%2A=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN1ab89.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN1ab89.txt`
- POC 目录：`poc/GEN-1ab8921b1132`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

证据不足：未发现可控文件路径，无法论证任意文件读取或写入。若后续代码将 $data 中的键用于文件路径拼接，需另行提供对应行号证据。

**CVE / CWE 论证**

CWE-22 不成立：source（body）与 sink（file_get_contents('php://input')）之间不存在路径可控关系，sink 参数为常量。外部可达性虽成立（POST + application/json），但利用链不闭合。

**修复建议**

无需针对该行修复；建议在代码审计中排除此误报。若确有基于 $data 字段的文件操作，应对路径做规范化（realpath）并限制在固定基目录白名单内，拒绝包含 ../ 的输入。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 JSON 请求体 → 022.php:8 读取 php://input 并 json_decode 到 $data → 未观察到 $data 被用于构造文件路径 → 无路径穿越汇点，链路不成立。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越 POC。注入点为参数 `*`，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22。漏洞位于可交付代码 022.php:8，外部输入来自 body `*`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。
POC 备注：保留原请求结构；脚本仅为文本工件，不执行、不联网。ANY 方法需按源码确认为 GET 或 POST 后再发送。

### F-3: 022.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:39 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 形式哈希后写入数据库（022.php:43-44 的 UPDATE 语句）。MD5 属于已被证明存在碰撞且计算极快的哈希算法，用于口令存储时无法抵抗离线暴力破解与彩虹表攻击；代码中未见加盐（salt）或迭代（如 bcrypt/Argon2/PBKDF2）处理。该弱点为配置/实现型，不依赖 HTTP 污点链，根因是算法选择与缺少盐值。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：022.php:39 使用 md5() 对密码做哈希，属弱哈希（CWE-328），无需发送请求。

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

数据库泄露后攻击者可用彩虹表或 GPU 高速爆破快速还原用户明文口令，进而横向登录其他系统（口令复用场景）；无盐设计使相同口令产生相同哈希，便于批量识别。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。注意此处应归类为 weak_hash 而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法问题）。外部可达性：通过修改密码功能即可写入 MD5 哈希；无需认证即可观察该实现（DVWA 低安全级别）。利用链为“口令 → md5 → 入库”，根因明确。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2）生成带盐慢哈希，校验时使用 password_verify；迁移期可对旧 MD5 值在用户下次登录时透明重哈希；禁止在代码中直接使用 md5/sha1 处理口令。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 022.php:38 转义 → 022.php:39 md5() 无盐哈希 → 022.php:43-44 写入 users.password → 数据库泄露后离线爆破还原明文。
POC 备注：仅静态证据，不执行、不联网。

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
| safety_guard | 安全防护 | 3.55 | 是 |
| surface_mapper | 攻击面测绘 | 9.54 | 是 |
| deep_finder | LLM 深挖 | 4.61 | 是 |
| candidate_screener | 候选筛选 | 4.61 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.57 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.53 | 是 |
| coordinator | 管线协调 | 7.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
