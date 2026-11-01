# 落日二号乙漏洞挖掘报告 — 20261031-011403-99a1e1

- 生成时间：2026-10-30T17:14:39.596336+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

共发现 1 条候选 finding，覆盖 1 种漏洞类型；1 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，未截断）。该脚本为纯前端渲染型 PHP 页面：第 6-7 行 POST 分支为空，无任何参数读取；第 9-10 行仅取 REQUEST_URI 并做 str_replace 后拼入第 47 行 JS 字符串常量（const url = '...'），未进入任何服务端 sink（无 exec/system/include/fopen/SQL/echo 用户输入）。第 12-119 行全部为静态 HTML/JS 字符串拼接，第 34、81、94 行 innerHTML 赋值的数据来自 fetch 返回的 JSON（服务端 API 响应），而非本脚本的请求参数，本文件内不存在攻击者可控 source 到该 DOM sink 的链路，故不构成可申报的反射型/存储型 XSS。未发现命令注入、路径穿越、SQL 注入、文件包含、反序列化、SSRF、硬编码凭据、弱哈希/弱随机、Cookie 标志位等可利用链。surface_notes 中列出的 source 热点 2 处 / sink 热点 4 处无法在本文件正文中对应到任何真实危险调用，属推断性提示，不构成证据。未闭合线索：第 47 行拼接的 $stripped_url 若含引号可闭合 JS 字符串，但 REQUEST_URI 由 Web 服务器规范化，且该值仅用于构造同源 fetch URL，未观察到可执行脚本注入的实际路径，证据不足，不报告。未覆盖范围：无 php.ini/.htaccess/路由/依赖清单，无法评估部署与前置 WAF；被 policy 抑制的候选未在本文件中出现。

未覆盖 / 证据缺口：
- 无端点/路由元数据，无法确认实际 URL 参数名与请求方法
- 无 Web 服务器与 PHP 配置，无法确认 allow_url_include、open_basedir 等开关
- 第 47 行 $stripped_url 拼入 JS 字符串的潜在注入未取得可执行证据，未闭合
- innerHTML 数据源为外部 API 响应，该 API 实现不在 code_pack 内，无法评估其 XSS/越权

## 3. Findings

### F-1: 002 API 信息泄露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`002.php:9-10`
- **来源**：`rule`

**描述**

证据仅覆盖 002.php 第 9-10 行：第 9 行从 $_SERVER['REQUEST_URI'] 读取完整请求 URI 到 $request_url，第 10 行用 str_replace("/vulnerabilities/api/", "", $request_url) 把路径前缀剥离后存入 $stripped_url。输入中未提供 $stripped_url 的后续使用点（是否回显、是否拼入响应体、是否用于路由分发或文件包含），也未提供鉴权判断、版本号/用户对象字段的返回代码。因此攻击者输入点可确认为请求 URI（路径部分），但“经过哪些变量到达哪个危险操作”的链条在给定片段内不闭合：只能确认 URI 被读取并做字符串替换，无法确认其被输出或用于敏感操作。校验无效性同样无法论证——片段中不存在任何校验逻辑，属于“未见校验”而非“校验可绕过”。

**source / sink**

- source：request `API version/user object`（002.php）
- sink：002.php:10 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `002.php:10` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /002（ANY）的 API 信息泄露 POC。注入点：ANY 参数 API version/user object；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/002'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 API 信息泄露 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/002?API version/user object=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-05c645928db9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

证据不足。基于现有两行代码只能判断请求 URI 被读取并做前缀剥离，无法证明版本信息、用户对象或内部字段被返回给未授权方。若后续代码将 $stripped_url 直接回显或用于错误页/调试输出，则可能泄露 API 结构信息（CWE-200），但该后果在输入中无代码支撑，不应作为已确认影响陈述。

**CVE / CWE 论证**

证据不足，不满足 CVE 论证条件。CWE-200 要求证明敏感信息被未授权方获取；当前仅有 $_SERVER['REQUEST_URI'] 读取与 str_replace 处理（002.php:9-10），缺少：外部可达的具体路由、无需认证的证明、返回敏感字段的响应构造代码、以及 $stripped_url 到输出/危险汇点的数据流。外部可达性可部分推断（REQUEST_URI 由 HTTP 请求控制），但利用链不闭合。

**修复建议**

1) 若 $stripped_url 后续用于输出，改为白名单映射：仅允许预定义的 API 路径枚举值，未匹配则返回统一 404，不回显原始 URI；2) 对输出到响应体的任何请求派生值做 HTML/JSON 编码，避免反射内容进入响应；3) 生产环境关闭详细错误与调试信息，统一错误响应体，去除版本号、内部路径、堆栈；4) 对 API 端点统一施加认证与授权检查，敏感字段按最小必要原则裁剪；5) 补充对 002.php 第 10 行之后代码的审计以确认 $stripped_url 的真实汇点，再决定是否升级为正式漏洞。

**验证说明**

静态证据：入口 ANY /002；source=request/API version/user object；sink=002.php:10；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 HTTP 请求，其 URI 路径包含 "/vulnerabilities/api/" 前缀（或任意路径），服务器在 002.php:9 通过 $_SERVER['REQUEST_URI'] 取得完整 URI 赋给 $request_url；002.php:10 用 str_replace 剥离该前缀得到 $stripped_url。链条在此中断：输入未给出 $stripped_url 被回显、拼接到响应、用于路由或文件操作的任何代码，因此无法说明攻击者最终获得何种敏感信息。当前证据等级为规则语义命中（origin=rule，confidence=0.4），属于待复核候选而非闭合漏洞。
PocWriter 建议（未采纳，缺少端点 /002）：针对 002.php:10 的 API 信息泄露（CWE-200）POC 文本。外部输入来自查询参数 `API version/user object`，在 002.php 第 10 行附近被直接使用/回显，未发现有效净化，导致接口版本与用户对象等内部信息可能被未授权读取。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /002）：符合 CWE-200（Exposure of Sensitive Information）。漏洞位于可交付代码 002.php:10，外部输入来自查询参数 `API version/user object`，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件；证据等级为 llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试实例地址，并手动逐条发送。原始草稿中的 `-X ANY` 不是合法 HTTP 方法，实际发送时请按目标路由支持的方法（GET/POST 等）替换；请求行中的方法名 ANY 仅表示“任意方法”的占位说明。禁止对生产环境或未授权目标使用。

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
| safety_guard | 安全防护 | 2.52 | 是 |
| surface_mapper | 攻击面测绘 | 8.57 | 是 |
| deep_finder | LLM 深挖 | 3.98 | 是 |
| candidate_screener | 候选筛选 | 2.89 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.61 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.31 | 是 |
| coordinator | 管线协调 | 5.91 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
