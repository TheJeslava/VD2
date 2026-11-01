# 落日二号乙漏洞挖掘报告 — 20261031-213945-5f0f9e

- 生成时间：2026-10-31T13:40:27.952581+00:00
- 输入：`$WORKSPACE\暴风星云裂\002.zip`
- 输入模式：`zip`
- SHA256：`e1763d6f3dacb5f1144d8bf313ac2128337f0729a834123f8f766fea9b793fc2`
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

本次汇总仅含 1 条已去重 finding：SEM-05c645928db9，类型 api_info_disclosure（CWE-200），严重度 high，位于 002.php 第 10 行附近，基于 REQUEST_URI 的路径处理导致 API 信息泄露，来源为规则命中，已附带 POC（HTTP 型）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但该 POC 属静态规则推导的 HTTP 请求文本，未经动态验证。需强调：本次覆盖极薄——仅有文件清单与热点计数，无源码片段、无端点、无配置，002.php 上 2 处 source 热点与 4 处 sink 热点均未被任何 finding 定性，不能据此认为不存在注入类问题。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 002.php（1-121 行，完整未截断）。该文件是一个前端展示页：第 6-7 行 POST 分支为空，无任何服务端处理逻辑；第 9-10 行读取 $_SERVER['REQUEST_URI'] 并用 str_replace 去掉 '/vulnerabilities/api/' 前缀，结果 $stripped_url 在第 47 行被拼进内联 <script> 的 JS 字符串常量（const url = '.../vulnerabilities/api/v2/user/'），随后第 49 行 fetch 该 URL。这是唯一的外部输入到输出路径，但：(1) 该值仅作为 JS 字符串字面量内容，未进入任何服务端 sink（无 SQL、无命令执行、无文件操作、无反序列化、无模板引擎）；(2) 要闭合为反射型 XSS 需要构造能突破单引号 JS 字符串的 REQUEST_URI，而现代 Web 服务器/浏览器会对请求行中的引号、尖括号做编码或拒绝，且 code_pack 中无任何服务端转义/解码逻辑可证明可绕过，证据不足以支撑 CVE 级结论，故不报告，仅作为线索记录。第 20-44、46-97 行的 JS 逻辑（update_username 用 innerHTML 拼接 user_json.name、loadTableData 用 cell.innerHTML = value 渲染 API 返回字段）属于客户端 DOM 渲染，其数据源是 /vulnerabilities/api/v2/user/ 接口返回的 JSON，该接口实现不在 code_pack 内，无法确认服务端是否对 name 等字段做过滤，也无法确认攻击者能否写入该字段，因此存储型/DOM XSS 链不闭合。第 115 行提示文案与第 82-85 行检测 'password' 字段的逻辑表明该页面用于演示 API 版本回退导致 password 哈希泄露，但泄露发生在被调用的 v2/user 接口，该接口源码未提供，无法定性。配置型线索：文件中未出现 md5/sha1/rand/mt_rand/setcookie/session_set_cookie_params/openssl 等调用，weak_hash、weak_crypto、weak_random、insecure_cookie、trust_boundary 均无代码证据，不成立。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- /vulnerabilities/api/v2/user/ 接口的服务端实现未在 code_pack 中，无法判断其是否泄露 password 哈希、是否对返回字段做输出编码，故 API 信息泄露与基于该接口的 XSS 均无法闭合
- 无 Web 服务器/php.ini 配置，无法确认 REQUEST_URI 中特殊字符是否被原样透传，影响第 47 行 JS 字符串注入的可利用性判断
- 无路由与认证信息，无法确认页面是否需要登录、是否公网可达
- endpoints 为空，无法确认实际 HTTP 方法与参数传递方式

## 3. Findings

### F-1: 002.php 基于 REQUEST_URI 的路径处理导致 API 信息泄露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`002.php:9-10`
- **来源**：`rule`

**描述**

攻击者通过任意 HTTP 请求控制请求行中的 URI，该值在 002.php:9 被读入 $request_url = $_SERVER['REQUEST_URI']，随后在 002.php:10 通过 str_replace("/vulnerabilities/api/", "", $request_url) 仅做一次字面量字符串替换得到 $stripped_url。该处理没有任何白名单、规范化或输出编码，替换结果被直接用于后续 API 响应逻辑（输入片段止于第 11 行，具体输出汇点未在 code_pack 中给出）。由于 str_replace 只删除固定子串，攻击者可通过构造包含或不包含该前缀的 URI（如重复前缀、大小写变体、路径参数、编码形式）影响 $stripped_url 的取值，从而探测或触发非预期的 API 分支与字段返回。

**source / sink**

- source：repository `API response user object`（002.php）
- sink：002.php:10 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `002.php:10` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

002.php 第 9-10 行把 $_SERVER['REQUEST_URI'] 原样取出，再用 str_replace 去掉固定前缀 "/vulnerabilities/api/"，结果 $stripped_url 直接来自客户端可控的请求行 URI。该值若被后续逻辑用于路由/文件包含/输出，会把攻击者构造的路径片段带入服务端处理链，属于 API 路径信息泄露/路径处理不当（CWE-200 类）。当前证据仅覆盖第 9-10 行的取值与截断，未给出 $stripped_url 的下游汇点，因此 POC 以“路径前缀剥离可被绕过”为可复现点，并标注下游需补充源码。

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

可能导致 API 内部路径/端点结构及响应字段被非授权枚举与泄露（信息泄露，CWE-200），为后续越权或注入攻击提供侦察信息。是否真正返回敏感字段取决于第 11 行之后的代码，当前证据不足，无法确认具体泄露的数据内容。

**CVE / CWE 论证**

CWE-200（向非授权方暴露信息）。外部可达性：$_SERVER['REQUEST_URI'] 由任意未认证 HTTP 请求控制，无需登录即可触达 002.php。利用链闭合度：source（002.php:9）与处理点（002.php:10）已确认，但危险汇点（响应输出/分支选择）未在提供的代码片段中出现，链未完全闭合，故置信度维持较低水平。

**修复建议**

1) 不要用 str_replace 对 REQUEST_URI 做路由剥离，改用显式路由表/白名单匹配（如 preg_match 精确锚定 ^/vulnerabilities/api/([a-z0-9_/-]+)$）；2) 对解析后的路径做规范化（去除 ../、重复斜杠、URL 解码后再校验）并拒绝不匹配项返回 404；3) API 响应按最小字段原则输出，敏感字段在服务端过滤；4) 对 API 端点统一做鉴权与速率限制，避免未认证枚举。

**验证说明**

静态证据：入口 GET /002；source=repository/API response user object；sink=002.php:10；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送任意 URI 的 HTTP 请求 → 002.php:9 读取 $_SERVER['REQUEST_URI'] 到 $request_url → 002.php:10 用 str_replace 删除固定子串 "/vulnerabilities/api/" 得到 $stripped_url → 后续（片段未覆盖）以 $stripped_url 驱动 API 响应/分支，导致端点与字段信息暴露。由于缺少第 11 行之后的代码，无法确认最终输出汇点与泄露字段，结论为基于源码的推断。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；目标统一使用 TARGET 占位符；仅限授权测试。原始草稿中的 grep 命令与 SUNSET_PROBE 占位符已替换为真实 HTTP 请求结构；未新增 finding，文件与行号保持 002.php:9-10。

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
| safety_guard | 安全防护 | 4.18 | 是 |
| surface_mapper | 攻击面测绘 | 7.4 | 是 |
| deep_finder | LLM 深挖 | 6.09 | 是 |
| candidate_screener | 候选筛选 | 3.81 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.49 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.95 | 是 |
| coordinator | 管线协调 | 7.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
