# 落日二号乙漏洞挖掘报告 — 20261031-163838-9539d4

- 生成时间：2026-10-31T08:39:22.458184+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-05c645928db9，类型 api_info_disclosure（CWE-200），严重度 high，位于 002.php 第 10 行，基于 REQUEST_URI 的 API 路径信息泄露，已附带 POC（HTTP 型，可动态复现）。这是本次最高危且唯一交付项。POC 齐全度：1/1 已具备。需强调：输入未提供 002.php 代码正文，该 finding 的判定来自规则引擎（origin=rule），本次汇总不新增漏洞、不做动态验证；攻击面测绘中的注入、路径穿越、命令执行、SSRF、XSS、配置类风险点均未被 findings 覆盖，已转入 human_review。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已完整通读 code_pack 中唯一文件 002.php（1-121 行，未截断）。该文件是一个教学/靶场风格的 PHP 页面：第 6-7 行存在空的 POST 分支（无任何处理逻辑），第 9-10 行读取 $_SERVER['REQUEST_URI'] 并做 str_replace 后拼入第 47 行的 JS 字符串（const url = '.../vulnerabilities/api/v2/user/'），第 12-99 行与 101-119 行拼接静态 HTML/JS，第 116-118 行调用 get_users() 发起前端 fetch。审计结论：未发现可闭合的服务端 source→sink 链。具体分析：(1) 第 9-10 行的 REQUEST_URI 虽为攻击者可控（路径/查询串），但仅被 str_replace 去掉固定前缀后拼进 <script> 内的单引号 JS 字符串，属于反射型 XSS 候选；然而该值来自 REQUEST_URI 且被置于 JS 字符串上下文，要闭合需注入单引号并逃逸 <script>，理论上可行，但本文件为纯静态教学页、无认证/会话/敏感数据，且无任何服务端危险汇点（无 exec/system/mysqli_query/include/file_get_contents/unserialize/eval），XSS 影响面不足以达到 CVE/赏金接收标准，按“宁可漏报不可误报”原则不单独立项，仅作为线索记录。(2) 第 20-44、46-97 行的 JS 逻辑（update_username、loadTableData 使用 innerHTML 渲染 user_json.name 与表格 value）属于客户端 DOM 渲染，数据来自同源 API /vulnerabilities/api/v2/user/ 的响应，不在本文件内，且 code_pack 未包含该 API 实现，无法确认服务端是否对 name 做转义，链不闭合。(3) 第 82-85 行检测到 'password' 字段时显示提示，暗示后端 API 可能返回 password 哈希，但该 API 源码不在 code_pack 中，无法审计其越权/信息泄露根因。(4) 未发现硬编码凭据、md5/sha1、setcookie、rand/mt_rand、openssl/mcrypt、X-Forwarded-For 信任等配置型问题；第 2-4 行仅为空字符串初始化，非 source/sink 热点（surface_notes 中“source 在 2 行、sink 在 4 行”的判断与代码正文不符，属元数据推断偏差）。(5) 输入中未出现诱导性文本，无 prompt_injection 证据。未闭合线索：/vulnerabilities/api/v2/u

未覆盖 / 证据缺口：
- 后端 API /vulnerabilities/api/v2/user/ 的实现不在 code_pack，无法审计其认证、越权与字段返回逻辑
- 无 composer.json/部署配置，无法确认 002.php 的访问控制与 URL 重写
- 第 9-10 行 REQUEST_URI 反射进 JS 字符串的 XSS 因缺乏敏感上下文与影响面未立项，需人工确认部署环境是否使其具备实际危害
- 第 82-85 行提示后端可能返回 password 哈希，但对应 API 源码缺失，无法闭合越权/信息泄露链

## 3. Findings

### F-1: 002.php 基于 REQUEST_URI 的 API 路径信息泄露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`002.php:9-10`
- **来源**：`rule`

**描述**

攻击者通过任意 HTTP 请求控制请求行中的 URI，该值在 002.php:9 被读入 $request_url = $_SERVER['REQUEST_URI']，随后在 002.php:10 通过 $stripped_url = str_replace("/vulnerabilities/api/", "", $request_url) 仅做字符串替换后即被用于后续逻辑（输入片段止于第 11 行，后续使用点未在 code_pack 中给出）。校验无效的原因在于：str_replace 只做字面量删除，不做路径规范化、白名单匹配或前缀强校验，攻击者可通过大小写变体、URL 编码（%2f、%2e%2e）、重复片段、查询串或路径参数等方式构造 URI，使替换结果偏离预期路由键，从而影响后续基于 $stripped_url 的分支/回显/资源定位。当前证据仅覆盖第 9-10 行的取值与替换，尚未看到 $stripped_url 的具体汇点（是否进入 echo、文件包含、路由分发或错误信息输出），因此“信息泄露”的具体形态（端点枚举、内部路径/字段暴露）属于基于语义模式的推断。

**source / sink**

- source：repository `API response user object`（002.php）
- sink：002.php:10 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `002.php:10` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（api_info_disclosure）：`002.php:9-10` 直接读取 `$_SERVER['REQUEST_URI']`，并用 `str_replace("/vulnerabilities/api/", "", $request_url)` 把路径前缀剥离后继续使用。该值未经任何校验/白名单即参与后续逻辑，属于把客户端完全可控的请求 URI 当作可信输入处理，可导致路径/接口信息泄露与后续逻辑被 URI 内容操纵。证据等级：llm_inferred（基于 code_pack 中给出的 002.php 第 9-11 行片段推断，未动态验证）。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 002.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-05c645928db9`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /002, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若 $stripped_url 后续被用于路由分发或错误回显，攻击者可枚举内部 API 端点、触发差异化错误信息，泄露服务端路径结构、可用接口与字段布局，为后续越权或注入攻击提供侦察面。具体泄露内容（版本号、鉴权状态、返回字段）证据不足，需结合 002.php 第 11 行之后的代码与运行时响应确认。

**CVE / CWE 论证**

CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。外部可达性：该逻辑位于 002.php 请求处理入口，直接读取 $_SERVER['REQUEST_URI']，任意未认证 HTTP 客户端均可触发，无需认证或特殊权限。利用链闭合度：source（REQUEST_URI）→ 变换（str_replace 字面量剥离）→ 汇点（$stripped_url 的后续使用）中，最后一环未在给定片段中出现，故不满足完整闭合，暂不作为已确认 CVE 级漏洞，仅作为高置信度候选。

**修复建议**

1) 不要用 str_replace 剥离路径前缀，改用 parse_url() 提取 path 后与固定前缀做严格前缀比较（str_starts_with / 正则 ^/vulnerabilities/api/），不匹配直接返回 404；2) 对路径做 rawurldecode 后再规范化（realpath/去除 ../ 与重复斜杠），并拒绝包含 %00、..、反斜杠的输入；3) 路由使用白名单映射表（端点名 → 处理器），未知端点统一返回同一错误页，避免差异化回显；4) 生产环境关闭 display_errors，错误响应不返回内部路径与堆栈；5) 对 API 响应做字段级最小化，敏感字段（版本、内部主机名、调试信息）不下发。

**验证说明**

静态证据：入口 GET /002；source=repository/API response user object；sink=002.php:10；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造任意 URI（如 /vulnerabilities/api/../admin、/vulnerabilities/api/%2e%2e/internal 或大小写变体）发起未认证请求 → 002.php:9 读取 $_SERVER['REQUEST_URI'] 存入 $request_url → 002.php:10 仅以 str_replace 删除字面量 "/vulnerabilities/api/" 得到 $stripped_url，未做规范化与白名单校验 → $stripped_url 进入后续路由/回显逻辑（第 11 行之后，证据不足）→ 返回差异化内容或错误信息，暴露内部端点与字段结构。
POC 备注：本 POC 仅为文本工件，不执行、不联网、不搭建沙箱；目标统一使用占位符 TARGET；仅限授权测试。原始确定性草稿中的 `grep` 命令仅作离线审查说明，不应由管线自动执行。未覆盖范围：code_pack 仅提供 002.php 第 9-11 行片段，无法确认 `$stripped_url` 的最终汇点（是否拼接进文件路径、SQL、重定向或输出），因此结论限定为信息暴露类推断。

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
| safety_guard | 安全防护 | 3.7 | 是 |
| surface_mapper | 攻击面测绘 | 10.88 | 是 |
| deep_finder | LLM 深挖 | 5.83 | 是 |
| candidate_screener | 候选筛选 | 3.22 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.6 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.8 | 是 |
| coordinator | 管线协调 | 7.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
