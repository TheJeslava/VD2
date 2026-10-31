# 落日二号乙漏洞挖掘报告 — 20261031-213948-301e8d

- 生成时间：2026-10-31T13:40:41.712526+00:00
- 输入：`$WORKSPACE\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 003.php。最高危为 LLM-1e0cbcf971b5：003.php 第 31 行附近将 $_SERVER['REQUEST_URI'] 未编码直接拼入内联 <script> 的 JS 字符串，构成反射型 XSS（high，llm_inferred，附 POC）；另一条 SEM-b5ee97e20ce3 为基于 REQUEST_URI 的路径处理与 API 信息暴露（CWE-200，high，规则命中，附 POC）。两条均带 POC，但均为静态/文本 POC，未做动态验证。攻击面测绘指出 source 与 sink 同文件各 2 处，属直连型高价值面，但除上述两条外，命令执行、路径穿越、SQL、配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均无 findings 覆盖，需人工复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 003.php（98 行），已逐行审计。确认一条闭合链：$_SERVER['REQUEST_URI']（003.php:3）经 str_replace 弱过滤（003.php:4）后直接拼入内联 <script> 的 JS 字符串（003.php:31、003.php:51），构成反射型 XSS。文件中未出现 system/exec/shell_exec、SQL 查询、文件读写、include/require、反序列化、setcookie、md5/sha1、rand 等汇点，故 command_injection、sql_injection、path_traversal、weak_hash、weak_random、insecure_cookie 等攻击面无证据，不报告。第 83 行 $_SERVER['PHP_SELF'] 拼入 form action 亦为潜在反射点，但同样受限于路径可控性，未单独成链。未闭合线索：无 Web 服务器配置、无路由/鉴权信息，无法确认 003.php 实际暴露路径与是否存在前置鉴权；无依赖清单，第三方组件 CVE 无法评估。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 register_globals、allow_url_include 及前置鉴权
- 无路由与部署信息，无法确认 003.php 对外访问路径
- 无依赖清单，第三方组件漏洞无法评估
- 无数据库使用证据，SQL 注入面无法确认

## 3. Findings

### F-1: 003.php 反射型 XSS：REQUEST_URI 未编码直接拼入内联 <script> 的 JS 字符串

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:3-31`
- **来源**：`llm_finding`

**描述**

脚本在第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行仅用 str_replace 删除字面量 "/vulnerabilities/api/"，随后在第 31 行与第 51 行把结果 $stripped_url 直接拼接进内联 <script> 中的单引号 JS 字符串（const url = '" . $stripped_url . "/vulnerabilities/api/v2/user/2';）。全程没有 htmlspecialchars、json_encode、urlencode 或任何 JS 字符串转义。攻击者只要在请求 URI 中放入单引号即可闭合 JS 字符串并注入任意 JavaScript，脚本在页面加载时（第 94 行 get_user()）即执行，构成反射型 XSS。由于该页面本身是 API 用户管理界面（可 PUT 修改用户 name/level），XSS 可用于以受害者身份调用 /vulnerabilities/api/v2/user/2 提权或窃取数据。

**source / sink**

- source：path `REQUEST_URI`（003.php:3）
- sink：003.php:31 003.php:31 与 003.php:51 内联 <script> 中的 JS 字符串拼接（const url = '...'），最终由浏览器执行

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:3` | 从 $_SERVER['REQUEST_URI'] 读取完整请求 URI，包含攻击者可控的路径与查询串 | 原始未过滤字符串，含单引号等特殊字符 |  |
| 2 | `003.php:4` | str_replace 仅删除字面量 "/vulnerabilities/api/"，不处理引号、尖括号、反斜杠等，无法阻断 JS 字符串逃逸 | 仍含攻击者可控单引号/换行等字符 | str_replace 是纯字符串替换，不是编码或白名单，单引号原样保留 |
| 3 | `003.php:31` | 把 $stripped_url 直接拼进内联 <script> 的单引号 JS 字符串 | 注入点：单引号闭合字符串后可写任意 JS |  |
| 4 | `003.php:94` | 页面末尾调用 get_user()，浏览器解析并执行被注入的脚本 | JavaScript 在受害者浏览器上下文执行 |  |

**POC**

针对 /003.php（GET）的 跨站脚本 POC。注入点：URL path；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/003.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/003.php'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-1e0cbcf971b5`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者（含管理员）浏览器上下文执行任意 JS，可读取/篡改用户信息、调用同源 API 将自身提权为 admin（level 0）、窃取会话数据

**CVE / CWE 论证**

CWE-79 反射型 XSS。外部无需认证即可通过 URL 触发，source→sink 链在单文件内闭合，无任何输出编码防护

**修复建议**

对 $stripped_url 使用 json_encode() 输出到 JS 上下文，或对 HTML 输出使用 htmlspecialchars(..., ENT_QUOTES)；更佳做法是不把请求 URI 回显进脚本，改用相对路径常量

**验证说明**

需确认 Web 服务器是否把路径中的单引号原样传入 REQUEST_URI（多数服务器会保留），以及是否存在前置 URL 重写/鉴权中间件改变 REQUEST_URI 内容
模型 POC 要点：在请求路径中注入单引号闭合 JS 字符串并执行任意脚本；仅限授权测试
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /003.php）：针对 003.php（GET）的反射型 XSS POC。源码 003.php:3 读取 $_SERVER['REQUEST_URI'] 到 $request_url，003.php:4 用 str_replace 去掉 "/vulnerabilities/api/" 前缀得到 $stripped_url，003.php:31 将该值输出到响应（未做 HTML 实体编码），因此请求 URI 中的脚本片段会原样进入页面。注入通道是 URL 路径/查询串（REQUEST_URI），不是某个具名参数；payload 放在路径段中即可。目标统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /003.php）：符合 CWE-79（跨站脚本）。source 为 003.php:3 的 $_SERVER['REQUEST_URI']，sink 为 003.php:31 的响应输出，中间仅经 003.php:4 的 str_replace 前缀替换，不构成 HTML 编码净化，source→sink 链静态闭合，具备远程触发条件。证据等级：llm_inferred（基于给定源码片段推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。payload 位于 URL 路径段，实际发送时需对 < > 等字符做 URL 编码（如 %3Cscript%3E...），服务端解码后 REQUEST_URI 仍保留原始形态；若目标对路径做规范化，可改用查询串 ?x=<script>... 观察是否同样进入 REQUEST_URI。禁止对非授权目标使用。

### F-2: 003.php 基于 REQUEST_URI 的路径处理与 API 信息暴露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`003.php:3-4`
- **来源**：`rule`

**描述**

证据仅覆盖 003.php 第 3-4 行：第 3 行 `$request_url = $_SERVER['REQUEST_URI'];` 把客户端可控的请求 URI（含路径与查询串）读入变量；第 4 行 `$stripped_url = str_replace("/vulnerabilities/api/", "", $request_url);` 仅做一次字面量字符串替换，把 `/vulnerabilities/api/` 从 URI 中删除，结果存入 `$stripped_url`。输入中未提供第 4 行之后如何使用 `$stripped_url`（是否拼接文件路径、是否回显、是否用于路由分发或日志），因此从 source 到危险汇点的链路在证据层面是断开的。可确认的技术事实是：该端点以请求 URI 作为唯一输入，且只做非规范化、非白名单的字面量替换，未对 `..`、URL 编码（`%2e%2e%2f`）、重复斜杠、大小写变体做规范化处理，也未做任何鉴权判断的可见代码。攻击者输入点：HTTP 请求行中的 URI（路径段与查询串）。经过变量：`$_SERVER['REQUEST_URI']` → `$request_url` → `str_replace` → `$stripped_url`。校验为何无效：`str_replace` 是纯文本替换，不是路径规范化，无法阻止编码绕过或前缀伪造；且替换后剩余内容未做任何合法性校验。最终危险操作：证据不足——第 4 行之后的下游使用未在 code_pack 中给出，无法确认是文件读取、响应回显还是路由跳转。

**source / sink**

- source：repository `API response user object`（003.php）
- sink：003.php:4 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:4` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型候选：003.php:3-4 将 $_SERVER['REQUEST_URI'] 直接用于 str_replace 处理，属于对请求 URI 的路径/前缀处理逻辑，被标记为 api_info_disclosure（CWE-200）候选。当前给定代码片段仅显示 URI 读取与前缀剥离，未显示任何硬编码凭据、密钥或敏感配置输出，因此该候选的证据强度不足，需补充源码确认是否存在敏感信息回显或凭据硬编码。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 003.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-b5ee97e20ce3`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /003, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若下游把 `$stripped_url` 用于文件定位或响应输出，可能导致 API 内部路径/字段结构泄露（信息泄露，CWE-200），严重时可延伸为路径穿越读取。但基于当前仅有的 2 行证据，实际影响为「证据不足」，不能断言数据泄露已闭合。

**CVE / CWE 论证**

CWE-200（向未授权方暴露信息）。外部可达性：该脚本直接读取 `$_SERVER['REQUEST_URI']`，属 Web 可达入口，无需认证即可触发（代码中未见鉴权分支）。但利用链未闭合：缺少 `$stripped_url` 的下游汇点，无法证明敏感信息实际被返回或写入。因此当前只能作为语义模式候选，不足以支撑 CVE 级结论。

**修复建议**

1) 不要用 `str_replace` 处理 URI，改用 `parse_url()` 提取 path 后与白名单路由表精确匹配；2) 对路径做 `rawurldecode` 后再规范化（折叠 `..`、重复斜杠），并拒绝包含 `..`、空字节、编码斜杠的请求；3) 在路由分发前加入统一鉴权与授权检查，未认证请求直接 401；4) API 响应只返回白名单字段，避免把内部路径、堆栈、版本号回显给客户端；5) 对异常 URI 记录审计日志而非回显。

**验证说明**

静态证据：入口 GET /003；source=repository/API response user object；sink=003.php:4；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造形如 `GET /vulnerabilities/api/../../<内部路径>?x=1` 或使用 `%2e%2e%2f` 编码变体的请求 → 第 3 行 `$_SERVER['REQUEST_URI']` 取得完整原始 URI → 第 4 行 `str_replace` 只删除字面量 `/vulnerabilities/api/`，编码或变体形式不被识别，`$stripped_url` 保留攻击者可控内容 → 后续使用点（证据不足，未在 code_pack 中提供）若将其用于文件定位或直接回显，则形成信息泄露/路径穿越。当前链路在「后续使用点」处断开，故置信度维持低位。
POC 备注：仅文本工件，不执行。步骤 2 的 API 路径依据 003.php:4 中被剥离的字符串 "/vulnerabilities/api/" 推断，属推测性路由，需源码确认；未确认前不应作为确定性 POC 使用。

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
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 1 |
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
| `api_info_disclosure` | CWE-200 |  | 1 |
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
| safety_guard | 安全防护 | 3.85 | 是 |
| surface_mapper | 攻击面测绘 | 10.5 | 是 |
| deep_finder | LLM 深挖 | 9.38 | 是 |
| candidate_screener | 候选筛选 | 5.01 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.98 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.5 | 是 |
| coordinator | 管线协调 | 6.34 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
