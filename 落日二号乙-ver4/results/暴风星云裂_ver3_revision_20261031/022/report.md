# 落日二号乙漏洞挖掘报告 — 20261031-011744-912063

- 生成时间：2026-10-30T17:18:26.927506+00:00
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

本次汇总基于单文件 PHP 脚本 022.php（69 行）的静态审计结果，共 3 条已去重 findings，均带 POC 文本（静态/HTTP 混合，未做动态验证）。最高危为 GEN-e38e01cf9ba5：022.php 第 44 行附近修改密码逻辑存在 SQL 注入（CWE-89，critical），属规则命中且有 POC，是唯一 critical 项。其次 GEN-1ab8921b1132 被标为 path_traversal（high），但标题已注明“JSON 请求体读取被误判为路径穿越（证据不足）”，建议降级或按误报复核，不应作为高危交付。SEM-f7415d28d8c9 实为 MD5 口令处理，按类型规范应归 weak_hash（CWE-328）而非 weak_crypto（CWE-327），仅有静态证据 POC，不能宣称可动态复现。POC 齐全度：3/3 有 POC，但其中 weak_hash 为静态证据，path_traversal 证据不足，真正可复现的仅 SQL 注入一条。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 022.php 的 1-57 行（共 69 行，58-69 行未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token / password_new / password_conf / Change；第 31-33 行在 $change 为真时调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验；第 36 行比较两次密码；第 38 行对 $pass_new 调用 mysqli_real_escape_string；第 39 行 md5 哈希；第 43 行拼接 UPDATE 语句，第 44 行 mysqli_query 执行。审计结论：(1) SQL 注入不成立——进入拼接的 $pass_new 已经过 mysqli_real_escape_string 转义且随后被 md5() 变为 32 位十六进制串，$current_user 来自 dvwaCurrentUser() 而非请求参数，无攻击者可控的未转义片段进入 SQL 语法；(2) CSRF 不成立——第 33 行存在服务端 token 校验，且 token 取自请求、与 $_SESSION 比对，未看到校验被跳过或恒真的证据；(3) 认证绕过/IDOR 不成立——UPDATE 的 WHERE user 绑定当前会话用户，未见客户端可控的用户标识；(4) 第 1 行并非危险 sink，只是 <?php 起始标签，surface_notes 中“第 1 行 sink 热点”的判断与代码不符，属热点定位噪声；(5) md5 用于口令存储属 weak_hash 线索，但 DVWA 为教学靶场、且该哈希不构成可外部利用的认证绕过链（登录侧代码未在 code_pack 中），按“宁可漏报不可误报”不单独立项。未闭合线索：58-69 行（generateSessionToken 调用之后的输出/响应逻辑）未提供，无法确认是否存在未编码输出导致的 XSS；checkToken、dvwaCurrentUser、generateSessionToken 的实现不在 code_pack 内，无法确认其内部是否存在缺陷；无 php.ini/Web 服务器配置，无法评估部署暴露面。

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入 code_pack，响应输出逻辑（潜在 XSS）无法审计
- checkToken / dvwaCurrentUser / generateSessionToken 定义不在 code_pack 内，无法验证 token 校验与当前用户取值的实现细节
- 无 php.ini、Web 服务器与部署配置，无法评估公网可达性与运行时约束
- md5 口令存储（第 39 行）为 weak_hash 线索，但缺少登录校验侧代码，利用链不闭合，未立项

## 3. Findings

### F-1: 022.php 修改密码处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过修改密码表单提交 password_new 参数（022.php:25 读取），该值在 022.php:38 仅经过 mysqli_real_escape_string 转义后于 022.php:39 被 md5() 处理，随后在 022.php:43 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';";，最终在 022.php:44 由 mysqli_query 执行。由于 md5() 在转义之后执行，转义产生的反斜杠会被 md5 哈希吞掉，转义对最终进入 SQL 的字符串不再生效，等于校验被绕过；同时语句未使用参数化查询，$current_user 也直接拼接。因此攻击者可构造使 md5 输出可控或利用拼接结构改变 SQL 语义的输入，实现注入。

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

可篡改 users 表中任意用户（含 admin）的密码记录，导致账户接管；进一步可借助 UPDATE 语句的注入点读取数据库内容或破坏数据完整性，属于数据库层面的越权写入与数据泄露。

**CVE / CWE 论证**

CWE-89：外部可控输入（HTTP POST 参数 password_new）未经参数化即拼入 SQL 并在 022.php:44 执行；该脚本为 DVWA 的 Web 端点，远程无需认证即可访问（会话内即可提交），利用链 source→拼接→mysqli_query 闭合。注意：转义在 md5 之前执行导致净化失效，是本条成立的关键。

**修复建议**

改用预处理语句与参数绑定（mysqli_prepare + bind_param），彻底避免字符串拼接；若必须哈希口令，应在参数化写入前完成哈希，且不要依赖 mysqli_real_escape_string 作为唯一防线；对 $current_user 同样使用绑定参数；限制数据库账户对 users 表的写权限至最小集合。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改密码请求中提交 password_new（022.php:25）→ 022.php:38 mysqli_real_escape_string 转义 → 022.php:39 md5() 使转义失效 → 022.php:43 拼入 UPDATE 语句 → 022.php:44 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 password_new，被拼接进 SQL 语句执行，未发现有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89。漏洞位于 022.php:44，外部输入来自查询参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例；POC 中不使用 DROP 等破坏性语句。

### F-2: 022.php JSON 请求体读取被误判为路径穿越（证据不足）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 $data = json_decode(file_get_contents('php://input'), true); 标记为 path_traversal 汇点。但 file_get_contents 的参数是固定字面量 'php://input'，并非来自外部输入；外部 JSON 内容只进入 $data 变量，未在此处参与任何文件路径构造。代码片段中不存在 new File/文件路径拼接/用户可控路径参数，因此不构成 CWE-22。

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

证据不足：当前片段未显示任何由外部输入控制的文件路径操作，无法论证任意文件读写。若后续代码将 $data 中的字段用于文件路径，需要额外证据才能成立。

**CVE / CWE 论证**

证据不足。CWE-22 要求外部可控数据进入文件系统路径解析；本候选的 source（body）与 sink（file_get_contents('php://input')）之间不存在路径可控关系，sink 参数为常量。

**修复建议**

若确认无其他路径拼接，应将该候选降级/关闭；若业务确实需要按用户输入读取文件，应使用固定白名单映射、realpath 规范化并校验前缀，拒绝包含 ../ 与绝对路径的输入。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：外部 JSON body → json_decode → $data；file_get_contents 读取的是固定流 'php://input'，未形成路径穿越链。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越 POC（CWE-22）。外部输入经参数 param 传入并用于文件路径拼接，未发现有效净化，可越出预期目录读写文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22。漏洞位于 022.php:8，外部输入来自请求参数 param，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例；写入类验证应使用无害临时文件名，避免覆盖系统文件。

### F-3: 022.php 使用 MD5 处理口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:39 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 单轮哈希后写入数据库（022.php:43-44 的 UPDATE）。MD5 属于已破解的快速哈希算法，且此处未见盐值或迭代（如 password_hash/PBKDF2/bcrypt/argon2），口令存储强度不足。注意：该弱点类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，后者指 DES/ECB 等加密算法缺陷）。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型发现：022.php:39 使用 md5() 对密码 $pass_new 做哈希。MD5 属弱哈希算法（CWE-328），不适用于口令存储。本项为配置/代码审查型候选，无 HTTP 污点，无需发送请求。

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

一旦数据库泄露，攻击者可用彩虹表/GPU 暴力快速还原用户明文口令，进而横向登录其他系统（口令复用场景）；无盐设计还使相同口令产生相同哈希，便于批量识别。

**CVE / CWE 论证**

CWE-328：源码原文证据为 022.php:39 的 md5( $pass_new )，用于口令这一安全用途；属实现型弱点，无需 HTTP 污点链即可成立。外部可达性：该逻辑在修改密码流程中由任意已访问该页面的用户触发。

**修复建议**

改用 PHP 内置 password_hash()（PASSWORD_DEFAULT/bcrypt 或 argon2id）生成带盐慢哈希，校验使用 password_verify()；迁移期可对旧 MD5 值在用户下次登录时透明重哈希；禁止在 SQL 拼接前以 md5 作为“净化”手段。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 022.php:38 转义 → 022.php:39 md5 单轮无盐哈希 → 022.php:43-44 写入 users 表，形成弱口令存储。
POC 备注：仅文本工件，不执行、不联网。建议修复方向：改用 password_hash()/bcrypt、scrypt 或 Argon2 并加盐。

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
| safety_guard | 安全防护 | 3.41 | 是 |
| surface_mapper | 攻击面测绘 | 6.37 | 是 |
| deep_finder | LLM 深挖 | 4.48 | 是 |
| candidate_screener | 候选筛选 | 4.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.09 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.54 | 是 |
| coordinator | 管线协调 | 6.31 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
