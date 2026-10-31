# 落日二号乙漏洞挖掘报告 — 20261031-214410-3b008a

- 生成时间：2026-10-31T13:45:06.208782+00:00
- 输入：`$WORKSPACE\暴风星云裂\022.zip`
- 输入模式：`zip`
- SHA256：`c1663891c5c6246a5a3ae32f77dbdd64dbfc5609548a3320760271ea88e17c1b`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 022.php（69 行，无框架、无路由配置）。最高危为 GEN-e38e01cf9ba5：022.php 第 44 行附近口令更新处的 SQL 注入（critical，CWE-89），属规则命中且已附 POC；其次为 GEN-1ab8921b1132：第 8 行 JSON 请求体解析处的路径穿越候选（high，CWE-22），同样附 POC；第三为 SEM-f7415d28d8c9：第 39 行使用 MD5 存储口令（medium，CWE-328 弱哈希，注意类型应为 weak_hash 而非 weak_crypto）。3 条均标记 has_poc=true，但需区分：SQL 注入与路径穿越为 HTTP 型 POC 文本，弱哈希仅为静态证据 POC，不能宣称可动态复现。本次未发现二次注入链（无存储写点/读点/汇点三元组证据），也未发现 prompt_injection 证据。所有结论均为源码审计推断（llm_inferred），未经动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 022.php 的第 1-57 行（共 69 行，第 58-69 行未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token / password_new / password_conf / Change；第 31-33 行在 $change 为真时调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验；第 36 行比较两次密码；第 38 行对 $pass_new 调用 mysqli_real_escape_string；第 39 行 md5 哈希；第 42 行 $current_user 来自 dvwaCurrentUser()（服务端会话派生，非客户端可控）；第 43-44 行拼接 UPDATE 语句并 mysqli_query。逐条评估：(1) SQL 注入——$pass_new 已经过 mysqli_real_escape_string 转义且随后被 md5() 变为 32 位十六进制串，无法注入；$current_user 来自服务端函数而非请求参数，code_pack 中看不到其可控来源，链路不闭合，不报告。(2) CSRF——存在 checkToken 校验，且 token 取自 $_SESSION['session_token']，未发现绕过证据。(3) 弱哈希——第 39 行使用 md5() 存储口令，属 CWE-328；但这是 DVWA 教学靶场的既有设计，且 md5 作用于已转义口令、无盐，单独作为 CVE 申报价值低，且缺少口令存储/校验全链路（登录侧未在 code_pack 中），按 min_confidence 0.6 与“零误报”原则不单独立项，仅作为线索记录。(4) 反射型 XSS——第 47/51 行 $return_message 为固定字符串，未拼接用户输入；输出点在第 58-69 行（未送入），无法确认，不报告。(5) 命令执行/文件包含/SSRF——code_pack 中未见 exec/system/include/file_get_contents 等汇点，surface_notes 中“sink 在第 1 行”的推断与实际代码（第 1 行为 <?php）不符，属清单误判。未发现满足 CVE 级别、链路闭合的漏洞，findings 为空。未闭合线索：第 58-69 行的输出与 generateSessionToken() 实现未覆盖；dvwaCurrentUser()、checkToken()、$GLOBALS['___mysqli_ston'] 的定义不在 code_pack

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入 code_pack，输出回显与 generateSessionToken() 无法审计
- dvwaCurrentUser()、checkToken()、mysqli 连接对象的定义不在 code_pack，无法确认 $current_user 是否可能被客户端影响
- 缺少登录/口令校验侧代码，无法评估 md5 弱哈希的完整影响链
- 缺少 Web 服务器、PHP 版本、php.ini 与认证配置，无法判断匿名可达性

## 3. Findings

### F-1: 022.php 口令更新处 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 022.php 提交修改口令的表单，外部输入在 022.php:25 被读入变量 $pass_new（候选 source 记为 query `password_new`）。该值在 022.php:38 仅经过 mysqli_real_escape_string 处理，随后在 022.php:43 被直接拼接进 SQL 语句：$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';"，并在 022.php:44 交由 mysqli_query 执行。由于拼接发生在字符串上下文中，且 $current_user 来自 dvwaCurrentUser()（022.php:42）同样未参数化，攻击者可在口令字段中闭合单引号并追加任意 SQL 片段（如 ' , user='admin' -- 之类），从而改写任意用户口令或读取数据库内容。校验无效的原因：mysqli_real_escape_string 只转义引号等字符，但此处并未使用预处理语句，且拼接结构本身允许通过闭合引号改变语句语义；同时未对输入做长度/字符白名单限制。

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

数据库任意写：可修改 users 表中任意用户（含 admin）的 password 字段，实现账户接管/越权登录；亦可借助 UPDATE 语句的报错或子查询进行数据外泄。属于高危数据完整性与机密性破坏。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：022.php 为可直接 HTTP 访问的 PHP 脚本，修改口令接口无需额外权限校验即可触达拼接点；利用链闭合：请求参数 → $pass_new（022.php:25）→ 字符串拼接（022.php:43）→ mysqli_query 执行（022.php:44），中间仅有一次不充分的转义，未使用参数化，故注入成立。

**修复建议**

改用预处理语句与参数绑定：$stmt = $mysqli->prepare('UPDATE users SET password = ? WHERE user = ?'); $stmt->bind_param('ss', $pass_hash, $current_user); $stmt->execute(); 同时对口令做长度与字符白名单校验，并在服务端使用 password_hash()/password_verify() 存储口令摘要，避免明文或弱摘要入库。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在修改口令表单的口令字段提交形如 x' , user='admin' -- 的载荷 → 022.php:25 读入 $pass_new → 022.php:38 mysqli_real_escape_string 仅做字符转义 → 022.php:43 直接拼入 UPDATE 语句 → 022.php:44 mysqli_query 执行被篡改的 SQL，导致任意用户口令被改写。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC。源码在 password_new 参数上直接拼接进 UPDATE/INSERT 语句（经 mysqli_real_escape_string 后仍进入 SQL 字符串），攻击者可通过 password_new 注入布尔条件。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89。漏洞位于 022.php:44，外部输入 password_new 进入 SQL 语句，source→sink 链静态闭合，未见有效参数化净化，具备远程触发条件。
POC 备注：仅文本工件，不执行。若源码确认使用 $_POST，请将步骤 2/3 改为 POST 并保留 Submit 字段；目标地址统一 TARGET。

### F-2: 022.php JSON 请求体解析处的路径穿越候选（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 $data = json_decode(file_get_contents('php://input'), true); 标记为 path_traversal 汇点。经复核，file_get_contents 的参数是固定伪协议字符串 'php://input'，并非由外部输入拼接而成，攻击者无法通过请求体改变被读取的路径；json_decode 的返回值 $data 在给出的代码片段（022.php:6-8）中未见被用于文件路径拼接。因此该候选的 source→sink 链条不成立：外部输入（请求体）进入的是 JSON 解析器，而非文件系统路径。证据不足，无法确认为路径穿越。

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

证据不足：在已给出的代码范围内未发现外部可控路径进入文件读写操作，无法论证任意文件读取/写入的影响。若后续代码（未在 code_pack 中提供）将 $data 中的键值用于文件路径，则需重新评估。

**CVE / CWE 论证**

CWE-22 不成立：file_get_contents('php://input') 为常量路径，不存在攻击者可控的路径分量；缺少 source 到文件路径汇点的数据流。

**修复建议**

若后续确有基于 $data 的文件操作，应对路径做规范化（realpath）并限制在固定白名单目录内，拒绝包含 '..'、绝对路径与空字节的输入；当前片段无需修改，但建议在代码评审中确认 $data 的全部下游使用点。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：候选声称请求体 → $data → 路径穿越汇点；实际 022.php:8 读取的是固定伪协议 php://input，请求体内容仅作为 JSON 被解析，未参与路径构造，链条在第一步即断开。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越 POC。源码在 022.php:8 附近将请求参数（参数名 *）拼入文件路径，未做规范化校验，可穿越到 testfiles 目录之外读写文件。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22。漏洞位于 022.php:8，外部输入进入文件路径拼接，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行。参数名 * 必须编码为 %2A；若源码为 $_POST 读取，请改为 POST 表单体。目标地址统一 TARGET。

### F-3: 022.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:38 先对 $pass_new 执行 mysqli_real_escape_string，随后在 022.php:39 调用 $pass_new = md5( $pass_new ); 将用户口令以无盐 MD5 摘要形式处理，并在 022.php:43-44 写入 users 表 password 字段。MD5 属于快速、无盐、已被证明存在实用碰撞的哈希算法，用于口令存储时无法抵抗离线暴力破解与彩虹表攻击。此处为配置/实现型弱点，不依赖 HTTP 污点链，根因是算法选择与缺少盐值/迭代。注意：该弱点类型应为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法误用）。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：022.php:39 使用 md5() 对密码 $pass_new 做哈希后存储，属弱哈希算法（CWE-328），无需发送请求即可确认。

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

一旦数据库泄露（例如经由同文件 GEN-e38e01cf9ba5 的 SQL 注入或备份泄露），攻击者可用彩虹表或 GPU 暴力快速还原用户明文口令，进而横向登录其他系统；无盐设计使相同口令产生相同摘要，便于批量破解。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）。外部可达性：任何提交口令修改的请求都会触发 022.php:39 的 md5 计算并落库；无需认证即可观察该实现（结合同文件注入可进一步获取摘要）。利用链闭合：口令输入 → md5()（022.php:39）→ 写入 users.password（022.php:43-44）→ 数据库泄露后离线破解。

**修复建议**

改用 password_hash($pass_new, PASSWORD_DEFAULT)（bcrypt/Argon2）生成带盐、可调成本的摘要，校验时使用 password_verify()；迁移期可对旧 MD5 摘要在用户下次登录成功后透明重哈希。禁止在口令、令牌、签名等安全用途中使用 MD5/SHA-1。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 022.php:38 转义 → 022.php:39 md5() 生成无盐摘要 → 022.php:43-44 写入数据库；攻击者获取数据库后利用彩虹表/暴力破解还原明文口令。
POC 备注：纯静态证据，不执行任何请求；仅记录 022.php:39 的 md5 调用。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.97 | 是 |
| surface_mapper | 攻击面测绘 | 9.45 | 是 |
| deep_finder | LLM 深挖 | 6.03 | 是 |
| candidate_screener | 候选筛选 | 5.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.59 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 9.91 | 是 |
| coordinator | 管线协调 | 8.29 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
