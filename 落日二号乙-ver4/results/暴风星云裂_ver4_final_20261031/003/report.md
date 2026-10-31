# 落日二号乙漏洞挖掘报告 — 20261031-172423-5ad0d0

- 生成时间：2026-10-31T09:25:04.675572+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\003.zip`
- 输入模式：`zip`
- SHA256：`06085614e8d510ff9f2f368ced0a790b64e5926adc00f379d25132aa3a2a79d0`
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

本次汇总仅含 1 条已去重 finding：SEM-b5ee97e20ce3，类型 api_info_disclosure（CWE-200），严重度 high，位于 003.php 第 4 行附近，基于 REQUEST_URI 的路径处理导致 API 信息暴露，已附带 POC（HTTP 型，可动态复现）。最高危即此条，也是唯一交付项。POC 齐全度：1/1 有 POC，无缺失。二次注入链：无。需强调：本次仅覆盖 003.php 单文件（98 行），无端点清单、无配置、无依赖清单，surface_notes 中列出的注入/文件包含/XSS/配置型风险点均未被 findings 覆盖，已转入 human_review，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次审计范围严格限于 code_pack 中唯一文件 003.php（98 行）。该文件是一个纯前端渲染型 PHP 页面：第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行用 str_replace 去掉固定前缀 "/vulnerabilities/api/" 得到 $stripped_url，随后在第 31、51 行把 $stripped_url 拼接进 <script> 内的 JS 字符串常量（const url = '...'），并在第 83 行把 $_SERVER['PHP_SELF'] 拼接进 form 的 action 属性。<br><br>逐条核对攻击面后未形成可闭合的 CVE 级利用链：<br>1) 反射型 XSS 线索（未闭合）：$stripped_url 源自 REQUEST_URI，未做 JS 字符串转义即进入 <script> 上下文（003.php:31、003.php:51）。但第 4 行 str_replace 只删除固定子串，攻击者仍可在 URI 中注入单引号/换行闭合 JS 字符串。然而该脚本本身无认证、无会话、无敏感数据，且注入点位于页面自身脚本内，属于典型的“自 XSS/无受害者”场景；同时缺少部署信息（是否有网关/WAF、是否被其他页面 include、实际 URL 路径），无法确认受害者上下文与可利用性，证据不足以支撑 CVE 级结论，故不申报。<br>2) $_SERVER['PHP_SELF'] 进入 form action（003.php:83）：PHP_SELF 在多数 SAPI 下为脚本路径，PATH_INFO 注入需特定服务器配置（如 Apache AcceptPathInfo），且同样缺少部署证据，未闭合。<br>3) 文件包含/路径穿越、命令执行、SQL 注入、反序列化、SSRF、文件上传、弱哈希/弱加密/弱随机、insecure_cookie、硬编码凭据：003.php 全文未出现 include/require、system/exec/shell_exec、mysqli_query/PDO、unserialize、curl/file_get_contents、move_uploaded_file、md5/sha1/rand、setcookie/session_* 等任何对应 sink 或配置项，均不成立。<br>4) 第 80 行注释“exploit it to elevate your user to admin”属于不可信数据中的诱导性文本，仅描述业务意图，不构成漏洞证据；真正的提权逻辑位于被 fetch 调用的 /vulnerabilities/api/v2/user/2 后端接口，该后端代码不在 code_pack 中，视为不存在，无法审计。<br><br>未覆盖范

未覆盖 / 证据缺口：
- 后端接口 /vulnerabilities/api/v2/user/2 的实现不在 code_pack，无法确认 PUT 是否接受 level 字段导致越权提权
- 无服务器配置，无法确认 PHP_SELF/PATH_INFO 注入与 disable_functions 状态
- 无端点清单与实际 URL 路径，无法确认 003.php 是否被其他页面 include 或前置 WAF
- REQUEST_URI 注入 JS 上下文的反射型 XSS 因缺少受害者上下文与部署证据未闭合

## 3. Findings

### F-1: 003.php 基于 REQUEST_URI 的路径处理与 API 信息暴露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`003.php:3-4`
- **来源**：`rule`

**描述**

证据仅覆盖 003.php 第 3-4 行：第 3 行 `$request_url = $_SERVER['REQUEST_URI'];` 把客户端可控的请求 URI（含路径与查询串）读入变量；第 4 行 `$stripped_url = str_replace("/vulnerabilities/api/", "", $request_url);` 仅做一次字面量字符串替换，把 `/vulnerabilities/api/` 前缀从 URI 中剥离，得到 `$stripped_url`。输入中未提供第 5 行之后的代码，因此无法确认 `$stripped_url` 最终被用于路由分发、文件包含、数据库查询还是直接回显到响应体，也无法确认是否存在鉴权判断与返回字段白名单。就现有证据而言，能确认的只是：一个对外可达的 API 入口把原始 REQUEST_URI 作为后续逻辑的输入，且处理方式为朴素字符串替换而非规范化解析。所谓“API 信息泄露”的具体泄露字段、泄露对象与触发条件在给定片段中均无直接证据，属于规则语义命中，需运行时响应对比（版本号、鉴权差异、返回字段集合）才能坐实。

**source / sink**

- source：repository `API response user object`（003.php）
- sink：003.php:4 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:4` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

003.php:3-4 将 $_SERVER['REQUEST_URI'] 直接取出并做 str_replace 去掉前缀 "/vulnerabilities/api/"，得到 $stripped_url。该值来自客户端可控的请求行（Request-URI），未经白名单校验或规范化，后续若用于路由分发、文件包含、日志或响应回显，会把攻击者构造的路径/查询串带入敏感上下文，构成 API 路径信息泄露/路径处理缺陷。当前证据仅覆盖第 3-4 行的取值与字符串替换，未给出 $stripped_url 的下游汇点，因此本条按“静态证据 + 待确认汇点”交付。

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

证据不足。若后续代码将 `$stripped_url` 直接回显或用于拼接响应/错误信息，可能向未授权访问者泄露内部路径结构、API 版本或后端路由信息（信息泄露，CWE-200）；若用于文件或路由解析，还可能延伸为路径处理类问题。但在仅有两行代码的前提下，无法确认泄露的具体数据内容与影响面，不应据此断言高危。

**CVE / CWE 论证**

CWE-200（Exposure of Sensitive Information to an Unauthorized Actor）。外部可达性：`$_SERVER['REQUEST_URI']` 表明该脚本由 HTTP 请求直接触发，攻击者无需认证即可构造任意 URI 路径与查询串。但利用链未闭合：缺少 `$stripped_url` 的下游使用点、鉴权分支与响应构造代码，无法证明敏感信息确实被返回给未授权方。因此当前不满足 CVE 级别的“可达 + 泄露内容明确 + 无需认证”三要素，置信度维持低位。

**修复建议**

1) 不要用 `str_replace` 处理 URI 前缀，改用 `parse_url()` 拆分 path/query 后再按白名单匹配路由段；2) 对 API 响应实施字段白名单，禁止把内部路径、版本号、堆栈或后端地址写入响应体；3) 在入口处统一做鉴权与授权校验，未认证请求返回统一的最小化错误响应；4) 对 `REQUEST_URI` 做长度与字符集限制，避免异常输入进入下游逻辑；5) 补充该文件第 5 行之后的代码以便复核下游汇点。

**验证说明**

静态证据：入口 GET /003；source=repository/API response user object；sink=003.php:4；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 `/vulnerabilities/api/...` 发起任意 HTTP 请求 → 003.php:3 读取 `$_SERVER['REQUEST_URI']` 到 `$request_url` → 003.php:4 用 `str_replace` 剥离固定前缀得到 `$stripped_url` → （下游使用点未在证据中给出，链路在此中断）。由于缺少 `$stripped_url` 到响应输出/文件/查询的汇点证据，无法确认信息泄露的实际发生，仅能确认输入可控与处理方式粗糙。
POC 备注：POC 为纯文本工件，不执行、不联网、不搭建沙箱。所有请求中主机名统一为 TARGET。步骤 2 的 %00 与 ../ 仅用于探测服务端规范化行为，禁止对生产环境使用。若需最终定级，必须补充 003.php 第 5 行之后 $stripped_url 的使用位置（include/echo/header/路由表），否则本条应标记为“证据不足，待补充源码”。

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
| safety_guard | 安全防护 | 3.06 | 是 |
| surface_mapper | 攻击面测绘 | 8.89 | 是 |
| deep_finder | LLM 深挖 | 6.09 | 是 |
| candidate_screener | 候选筛选 | 2.96 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.56 | 是 |
| coordinator | 管线协调 | 5.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
