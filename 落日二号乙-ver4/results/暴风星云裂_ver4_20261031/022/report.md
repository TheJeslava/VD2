# 落日二号乙漏洞挖掘报告 — 20261031-164234-c28225

- 生成时间：2026-10-31T08:43:24.880897+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 022.php（69 行，无框架、无路由清单）。最高危为 GEN-e38e01cf9ba5：022.php 修改密码功能存在 SQL 注入（CWE-89，critical，行 44 附近），参数被直接拼接进查询，具备完整 HTTP POC。其次 GEN-1ab8921b1132 被规则标为 path_traversal（high，行 8），但标题与证据指向 JSON 请求体读取，类型标注存疑，需人工确认是否应改判为普通输入读取或其它类型，其 POC 为静态/请求构造型，动态可利用性未验证。SEM-f7415d28d8c9 为 MD5 存储口令（medium），实际属 weak_hash（CWE-328）而非 weak_crypto（CWE-327），仅有静态证据 POC，不能宣称可动态复现。3 条 finding 均带 POC 文本，但均为静态构造，未做任何动态验证。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到 022.php 的 1-57 行（共 69 行，尾部 58-69 未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 读取 user_token/password_new/password_conf/Change；第 31-33 行在改动前调用 checkToken($token, $_SESSION['session_token'], 'index.php') 做 Anti-CSRF 校验；第 36 行比较两次密码；第 38 行对 $pass_new 调用 mysqli_real_escape_string；第 39 行 md5() 后在第 43 行拼入 UPDATE 语句，第 44 行 mysqli_query 执行。审计结论：(1) SQL 注入不成立——$pass_new 经 mysqli_real_escape_string 转义且随后被 md5() 变为 32 位十六进制，$current_user 来自 dvwaCurrentUser() 而非请求参数，拼接值不可控语法；(2) CSRF 不成立——checkToken 在写库前执行，token 缺失/错误会跳转 index.php；(3) md5 用于口令存储属 weak_hash(CWE-328)，但该文件为 DVWA 教学靶场代码，且 md5 前已做转义，无法构成可申报 CVE 的外部可利用链，按“宁漏勿误”不单独立项，仅作线索记录；(4) 未发现命令执行、文件包含、反序列化、SSRF、路径穿越等汇点。未闭合线索：checkToken()、generateSessionToken()、dvwaCurrentUser() 的实现位于 58-69 行或其它未送入文件，无法确认 token 比较是否使用恒定时间比较、session_token 生成是否使用弱随机（weak_random 可能性存在但无证据）；若后续能提供 58-69 行及 DVWA 公共函数文件，可复核 weak_random / weak_hash 配置型候选。

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入，checkToken/generateSessionToken 调用后的逻辑不可见
- checkToken()、generateSessionToken()、dvwaCurrentUser() 的实现不在 code_pack 中，无法评估 token 比较与随机数强度
- 无 php.ini/Web 配置，无法确认 allow_url_include、open_basedir 等开关
- 无端点清单与部署信息，无法确认该页面是否对外暴露及认证要求

## 3. Findings

### F-1: 022.php 修改密码功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 022.php 的修改密码功能提交 password_new 参数（022.php:25 读取），该值在 022.php:38 仅经过 mysqli_real_escape_string 转义后，于 022.php:39 被 md5() 处理，随后在 022.php:43 被直接拼接进 UPDATE 语句：$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';"，并在 022.php:44 交给 mysqli_query 执行。由于 md5() 的输出是 32 位十六进制字符串，正常情况下会消除引号等元字符，因此单看 password_new 路径，注入被 md5 输出字符集限制；但同一 UPDATE 语句还拼接了 $current_user（022.php:42 由 dvwaCurrentUser() 取得），该值未经参数化即进入 SQL。校验无效的原因在于整条语句采用字符串拼接而非预处理语句，任何进入拼接的变量都缺少类型/白名单约束。最终危险操作是 mysqli_query 执行被拼接的 UPDATE 语句。

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

若 $current_user 或其它拼接变量可被外部影响，攻击者可改写 UPDATE 语句结构，实现越权修改任意用户口令（包括 admin）、绕过认证或通过报错/布尔差异枚举数据库内容，导致账户接管与数据泄露。就 password_new 单一路径而言，md5 输出字符集显著限制了注入可行性，实际可利用性取决于 $current_user 的来源是否可控。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可达（022.php 为 Web 入口，POST 参数 password_new 直接读取）、无需认证即可访问该脚本（DVWA 低安全级别下无令牌/权限校验），利用链为 022.php:25 读取参数 → 022.php:43 字符串拼接 → 022.php:44 mysqli_query 执行。需注意 md5 对 password_new 的字符集收敛作用，因此该链的闭合程度依赖 $current_user 的可控性，证据等级为源码推断。

**修复建议**

改用参数化查询（mysqli_prepare + bind_param 或 PDO 预处理），将 password 与 user 作为绑定参数；对 $current_user 使用会话内服务端取值并做白名单校验，禁止从请求派生；对 password_new 做长度与字符集校验；移除对 SQL 语句的手工拼接，统一使用 ORM/查询构造器。

**验证说明**

静态证据：入口 ANY /022；source=query/password_new；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 022.php 提交修改密码请求 → 022.php:25 读取 password_new → 022.php:38 mysqli_real_escape_string 转义 → 022.php:39 md5() 哈希（收敛字符集）→ 022.php:43 与 $current_user 一同拼接进 UPDATE 语句 → 022.php:44 mysqli_query 执行。注入面主要落在未经参数化的 $current_user 拼接处，password_new 路径受 md5 输出限制。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC。源码在 password_new 参数上拼接 SQL（未参数化），攻击者可通过布尔/报错注入改变查询语义。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89。漏洞位于 022.php:44，外部输入 password_new 经拼接进入 SQL 语句，source→sink 链静态闭合，未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。草稿中的 ANY 方法与 query 传参需按源码核对：若源码为 $_POST 读取，应使用 POST 表单体；Submit 字段名需与源码表单核对后再定稿。

### F-2: 022.php JSON 请求体读取被误标为路径穿越（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 $data = json_decode(file_get_contents('php://input'), true); 标记为路径穿越汇点。实际分析：file_get_contents 的参数是固定字面量 'php://input'，不包含任何来自请求的路径片段；外部输入是请求体内容，经 json_decode 解析为数组 $data，属于数据解析而非文件路径选择。因此不存在攻击者可控路径进入文件系统 API 的链路，不满足 CWE-22 的构成要件。022.php:7 仅校验 REQUEST_METHOD 为 POST 且 CONTENT_TYPE 为 application/json，属于内容类型分支，与路径无关。

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

证据不足，无法确认路径穿越影响。若强行按原候选描述，会错误声称可任意文件读写，但源码中不存在可控路径参数，故不成立。

**CVE / CWE 论证**

不满足 CWE-22：source 为请求体内容而非路径字符串，sink 的路径参数为常量 'php://input'，无污点从外部输入流向文件路径。外部可达性成立但利用链不闭合，判定为误报。

**修复建议**

无需针对路径穿越修复。建议保留对 JSON 解析结果的字段级校验（类型、长度、允许键白名单），并对 json_decode 失败情况返回 400；如后续引入基于 $data 中字段的文件操作，必须使用 basename/realpath 规范化并限制在固定根目录内。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求体 → 022.php:8 file_get_contents('php://input')（常量路径）→ json_decode 得到 $data。路径参数不可控，链路在第一步即断开，未到达任何文件系统路径汇点。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越 POC。源码将外部输入用于文件路径拼接，未做规范化/白名单校验，攻击者可用 ../ 序列访问 testfiles 目录之外的文件。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22。漏洞位于 022.php:8，外部输入进入文件路径 sink，source→sink 链静态闭合，未见有效净化。
POC 备注：POC 仅为文本工件，不执行、不联网。草稿使用 ANY 方法与 query 传参，需按源码核对实际参数名与读取方式（$_GET 或 $_POST）后再定稿。

### F-3: 022.php 使用 MD5 存储口令（CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:38-39`
- **来源**：`rule`

**描述**

022.php:39 执行 $pass_new = md5( $pass_new );，将用户新口令以无盐 MD5 单轮哈希后写入 users 表 password 字段（022.php:43-44 的 UPDATE 语句）。保护对象是账户口令这一安全敏感数据，属于口令存储用途。MD5 计算极快且无盐，攻击者一旦通过数据库泄露、备份泄露或 SQL 注入读取到哈希值，可用彩虹表或 GPU 暴力在极短时间内还原常见口令；相同口令产生相同哈希，便于横向比对。此处应归类为 weak_hash（CWE-328），而非 weak_crypto（CWE-327，指 DES/ECB 等加密算法缺陷）。

**source / sink**

- source：repository `md5(`（022.php）
- sink：022.php:39 		$pass_new = md5( $pass_new );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:39` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：022.php:39 使用 md5() 对密码做哈希。MD5 属弱哈希算法（CWE-328），不应用于口令存储。无需发送请求，仅需源码审查确认。

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

口令哈希可被离线快速破解，导致账户接管；无盐导致相同口令哈希一致，泄露用户间口令复用关系；若与前述 SQL 注入结合，攻击者可直接读取或覆写哈希，进一步扩大账户沦陷范围。

**CVE / CWE 论证**

CWE-328（使用弱哈希算法）：配置/实现型弱点，无需 HTTP 污点链即可成立。原文证据为 022.php:39 的 md5( $pass_new ) 调用，作用于口令字段；外部可达性体现在任何触发修改密码流程的请求都会生成该哈希，无需额外认证条件即可观察到该实现。

**修复建议**

改用 password_hash()（PASSWORD_ARGON2ID 或 PASSWORD_BCRYPT）生成带盐慢哈希，校验使用 password_verify()；迁移期可对旧 MD5 值在用户下次登录成功后透明重哈希；禁止在任何新代码中使用 md5/sha1 处理口令、令牌或签名。

**验证说明**

静态证据：入口 ANY /022；source=repository/md5(；sink=022.php:39；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：用户提交新口令 → 022.php:38 转义 → 022.php:39 md5() 单轮无盐哈希 → 022.php:43 拼接 UPDATE → 022.php:44 写入 users.password。哈希算法本身即弱点根因，无需外部污点即可判定。
POC 备注：静态证据型，无 HTTP 请求。POC 仅为文本工件，不执行、不联网。

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
| safety_guard | 安全防护 | 4.04 | 是 |
| surface_mapper | 攻击面测绘 | 8.34 | 是 |
| deep_finder | LLM 深挖 | 4.0 | 是 |
| candidate_screener | 候选筛选 | 4.88 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.43 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.96 | 是 |
| coordinator | 管线协调 | 6.37 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
