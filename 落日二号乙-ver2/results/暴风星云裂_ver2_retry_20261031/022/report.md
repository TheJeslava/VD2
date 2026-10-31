# 落日二号乙漏洞挖掘报告 — 20261031-002020-ce8655

- 生成时间：2026-10-30T16:21:01.117176+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\022.zip`
- 输入模式：`zip`
- SHA256：`c1663891c5c6246a5a3ae32f77dbdd64dbfc5609548a3320760271ea88e17c1b`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于单文件 PHP 脚本 022.php（69 行）的已去重 findings。最高危为 GEN-e38e01cf9ba5：022.php 第 44 行附近密码修改功能的 SQL 注入（CWE-89，critical，rule 来源，已有 POC）。另一条 GEN-1ab8921b1132 被标注为 path_traversal（high），但其标题与描述明确写为「JSON 请求体读取被误判为路径穿越（证据不足）」，属于规则误报候选，建议降级或人工复核后再决定是否交付，不应作为已确认高危对外呈现。两条 finding 均标记 has_poc=true，但 POC 均为静态文本工件，未做动态验证；SQL 注入 POC 属 HTTP 类可复现文本，路径穿越一条因证据不足，其 POC 不具备可信复现基础。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2141 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 022.php 的 1-57 行（共 69 行，尾部 58-69 未送入）。该文件是 DVWA 风格的密码修改页面：第 7-29 行从 JSON body（php://input）或 $_REQUEST 接收 user_token / password_new / password_conf / Change；第 33 行调用 checkToken() 做 Anti-CSRF 校验（函数体不在 code_pack 内，无法确认其实现是否可绕过）；第 36 行比较两次密码；第 38 行对 password_new 调用 mysqli_real_escape_string 转义；第 39 行 md5 摘要；第 43 行拼接 UPDATE 语句，第 44 行 mysqli_query 执行。审计结论：(1) SQL 注入不成立——password_new 在拼接前经 mysqli_real_escape_string 转义，且随后被 md5() 转为 32 位十六进制，注入字符无法存活；current_user 来自 dvwaCurrentUser()（函数体不在 code_pack），非直接请求参数，无法证明外部可控。(2) 第 39 行 md5() 用于口令摘要属 weak_hash（CWE-328），但该脚本为 DVWA 教学靶场代码，且 md5 结果仅用于与库中既有哈希比对，未构成可申报 CVE 的独立利用链，按 min_severity=high 不单独立项，仅作线索记录。(3) 第 33 行 checkToken 的 CSRF 防护实现不可见，若其比较逻辑存在缺陷可能形成 CSRF 改密，但缺少函数体证据，链不闭合，不报告。(4) 未发现命令执行、文件包含、反序列化、SSRF、路径穿越等 sink；第 1 行热点实为 <?php 起始标记，非危险函数。未发现 prompt_injection 诱导文本。因缺少 58-69 行（含 generateSessionToken 等）及 checkToken/dvwaCurrentUser 实现，相关线索未闭合。

未覆盖 / 证据缺口：
- 022.php 第 58-69 行未送入 code_pack，无法审计 generateSessionToken 及后续输出逻辑
- checkToken() 函数体缺失，无法判断 Anti-CSRF 校验是否可绕过
- dvwaCurrentUser() 函数体缺失，无法确认 $current_user 是否可被外部影响
- $GLOBALS['___mysqli_ston'] 数据库连接初始化代码缺失
- 无 php.ini / Web 服务器配置，无法评估部署与暴露面

## 3. Findings

### F-1: 022.php 密码修改功能 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:42-44`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 022.php 提交修改密码的表单，外部输入在 022.php:26 处被读取为 `password_conf`（密码确认字段），随后在 022.php:43 被直接字符串拼接进 UPDATE 语句：`$insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';"`，其中 `$pass_new` 来自该外部输入，未做 mysqli_real_escape_string 转义、未使用预处理语句、也未做类型/白名单校验；`$current_user` 由 dvwaCurrentUser() 提供（022.php:42）。拼接完成的 `$insert` 在 022.php:44 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $insert)` 执行，污点从输入到 SQL 执行汇点全程无有效净化，构成一次注入。

**source / sink**

- source：query `password_conf`（022.php:26）
- sink：022.php:44 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `022.php:26` | 从 query `password_conf` 读取外部输入 | 污点进入 insert |  |
| 2 | `022.php:44` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /022（ANY）的 SQL 注入 POC。注入点：ANY 参数 password_conf；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/022'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/022?password_conf=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-e38e01cf9ba5`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造 `$pass_new` 闭合单引号并注入任意 SQL，从而改写 users 表中任意用户（含 admin）的密码、读取数据库内容或通过堆叠/子查询扩展影响范围，导致账户接管与数据库数据泄露；由于该语句本身即 UPDATE，注入可直接造成持久化数据篡改。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：022.php 为 Web 可访问脚本，输入来自请求参数 `password_conf`，无需认证即可到达拼接点（若部署在 DVWA 中则受其登录态约束，但代码层面无鉴权与转义）。利用链闭合：source（022.php:26 `password_conf`）→ 拼接（022.php:43 `$insert`）→ sink（022.php:44 `mysqli_query`），中间无参数化、无转义、无白名单，链路完整。

**修复建议**

改用参数化查询（mysqli_prepare + bind_param 或 PDO 预处理），将 `$pass_new` 与 `$current_user` 作为绑定参数传入；对密码字段做长度与字符集白名单校验；对 `$current_user` 使用会话内服务端取值而非可拼接字符串；数据库账户遵循最小权限，禁止多语句执行（关闭 mysqli 多语句）。

**验证说明**

静态证据：入口 ANY /022；source=query/password_conf；sink=022.php:44；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 `password_conf` 在 022.php:26 被读入 `$pass_new` → 022.php:43 以字符串拼接方式构造 UPDATE 语句 `$insert`，未转义 → 022.php:44 `mysqli_query(...)` 执行拼接后的 SQL，注入生效。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:44 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 password_conf，被拼接进 SQL 语句执行，未发现有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-89（SQL 注入）。漏洞位于 022.php:44，外部输入来自查询参数 password_conf，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例地址；建议先做基线对比再判定，避免把正常差异误判为注入。

### F-2: 022.php JSON 请求体读取被误判为路径穿越（证据不足）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`022.php:6-8`
- **来源**：`rule`

**描述**

候选将 022.php:8 的 `$data = json_decode(file_get_contents('php://input'), true);` 标记为 path_traversal 汇点。但该处 `file_get_contents` 的参数是固定字面量 `php://input`，并非来自外部输入的可控路径；外部输入是 POST body 内容，经 `json_decode` 解析为数组 `$data`，不构成对文件系统路径的控制。022.php:7 仅校验请求方法为 POST 且 CONTENT_TYPE 为 application/json。因此 source（body `*`）到 sink（固定 `php://input` 读取）之间不存在路径可控的污点链，该候选不成立。

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

证据不足：当前代码片段中不存在由外部输入控制文件路径并到达文件读写操作的链路，无法论证任意文件读取/写入影响。若后续代码（022.php:8 之后）将 `$data` 中的键值用于拼接文件路径，需另行提供对应行号证据方可成立。

**CVE / CWE 论证**

CWE-22 不成立：sink 处路径为常量 `php://input`，攻击者无法改变读取目标；缺少“外部可控路径 → 文件操作”的必要环节，利用链不闭合。

**修复建议**

无需针对该行修复路径穿越；建议保留对 JSON 解析失败与字段类型的校验，并在后续若使用 `$data` 中的值构造文件路径时，采用白名单文件名、basename() 规范化与固定根目录拼接。

**验证说明**

静态证据：入口 ANY /022；source=body/*；sink=022.php:8；规则 php-file。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST body 内容 → 022.php:8 `file_get_contents('php://input')`（路径为常量）→ `json_decode` 得到 `$data`；路径不可控，链路在 sink 处断开。
PocWriter 建议（未采纳，缺少端点 /022）：针对 022.php:8 的路径穿越 / 任意文件读写 POC（CWE-22）。外部输入来自请求参数 param，被用于构造文件路径，未发现有效净化，可穿越出预期目录。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /022）：符合 CWE-22（路径穿越）。漏洞位于 022.php:8，外部输入来自请求参数 param，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例地址；写入测试请使用无害临时文件名，测试后由授权方清理，避免破坏目标系统。

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
| `weak_crypto` | CWE-327 |  | 0 |
| `weak_hash` | CWE-328 |  | 0 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.46 | 是 |
| surface_mapper | 攻击面测绘 | 7.78 | 是 |
| deep_finder | LLM 深挖 | 4.15 | 是 |
| candidate_screener | 候选筛选 | 3.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.21 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.18 | 是 |
| coordinator | 管线协调 | 6.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
