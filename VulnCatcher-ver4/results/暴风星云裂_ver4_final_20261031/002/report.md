# 落日二号乙漏洞挖掘报告 — 20261031-172422-dc1dde

- 生成时间：2026-10-31T09:25:02.184658+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-05c645928db9（api_info_disclosure，high，002.php 第 10 行附近，基于 REQUEST_URI 字符串替换构造路径，CWE-200），已附带 POC（属静态/HTTP 待定，未做动态验证）。最高危即该条 high 信息泄露/路径处理缺陷。POC 齐全度为 1/1，但全部为文本工件，未经动态复现。需强调：surface_notes 明确说明输入只给了文件清单与热点计数（002.php 上 source 热点 2 处、sink 热点 4 处），未提供任何代码行内容，因此 sink 的具体函数名、行号与数据流连通性均无法确认；本次 findings 覆盖面远小于测绘出的攻击面，其余高风险面（命令/文件/包含类 sink、路径穿越、硬编码凭据、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）均未形成 finding，需人工按代码复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3749 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 002.php（121 行，已完整送入，未截断）。逐行审计结果：脚本无任何数据库/命令/文件/反序列化/eval 类 sink 调用；唯一的服务端外部输入是第 9 行 $_SERVER['REQUEST_URI']，经第 10 行 str_replace 去掉前缀后在第 47 行拼进前端 JS 字符串常量（const url = '...'），属于反射到客户端脚本上下文，但该值仅作为 fetch 的 URL 前缀使用，未进入 innerHTML 等 DOM 汇点，且缺少可确认的注入闭合条件（需构造引号逃逸，但 REQUEST_URI 在多数服务器下会被规范化/编码，无法在无运行时证据下确认可利用），证据不足以构成闭合链，按“宁可漏报不可误报”原则不申报。第 6-7 行 POST 分支为空，无处理逻辑。第 20-97 行、116-118 行为前端 JS：update_username 与 loadTableData 使用 innerHTML 渲染 user_json.name 与 Object.entries 的 value（第 34、81、94 行），但数据来源是同源 API /vulnerabilities/api/v2/user/ 的响应，属于该靶场（DVAPI 风格）自身设计的客户端渲染，攻击者无法从本文件外部控制该响应内容，不构成本文件内的存储型/反射型 XSS 闭合链。surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 六类配置型候选，在 002.php 中均无对应代码（无 md5/sha1、无 openssl/mcrypt、无 rand/uniqid、无 setcookie/session_set_cookie_params、无 X-Forwarded-For 信任、无内联凭据），全部不成立。未发现 prompt_injection 诱导文本。结论：本 code_pack 内无可申报 CVE 的闭合漏洞链。

未覆盖 / 证据缺口：
- 第 47 行 $stripped_url 反射进 JS 字符串的引号逃逸可行性依赖 Web 服务器对 REQUEST_URI 的规范化行为，无运行时证据，未闭合
- 第 34/81/94 行 innerHTML 渲染的数据源为同源 API 响应，该 API 实现不在 code_pack 内，无法判断是否存在服务端可控注入点
- 无 php.ini / Web 服务器配置，无法评估 allow_url_include、open_basedir 等利用条件
- 无路由与部署信息，无法确认脚本实际 URL 与网络暴露面

## 3. Findings

### F-1: 002.php 通过 REQUEST_URI 字符串替换构造路径，存在信息泄露/路径处理缺陷（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`002.php:9-10`
- **来源**：`rule`

**描述**

证据仅覆盖 002.php 第 9-10 行：第 9 行 `$request_url = $_SERVER['REQUEST_URI'];` 把客户端可控的请求 URI（含查询串）读入变量；第 10 行 `$stripped_url = str_replace("/vulnerabilities/api/", "", $request_url);` 用固定字面量做一次性字符串替换，得到 `$stripped_url`。该替换不是规范化解析：它只删除首次出现的固定子串，不校验前缀、不做路径归一化、不区分大小写与编码变体，也不剥离查询串。攻击者可通过构造 REQUEST_URI（例如在路径中重复或变形 `/vulnerabilities/api/` 片段、附加查询参数）使 `$stripped_url` 偏离预期值。但输入中未提供 `$stripped_url` 的下游使用点（是否进入文件读取、include、路由分发或响应回显），因此“最终到达哪个危险操作”这一环证据不足，无法确认泄露的具体数据对象。

**source / sink**

- source：repository `API response user object`（002.php）
- sink：002.php:10 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `002.php:10` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

002.php 第 9-10 行直接读取 $_SERVER['REQUEST_URI'] 并用 str_replace 去掉前缀 "/vulnerabilities/api/"，把结果作为后续 API 路由/资源标识使用（第 10 行 $stripped_url）。该值完全由客户端请求行控制，未经白名单校验或规范化，属于 API 路径/资源标识未受控导致的 API 信息暴露面（CWE-200 类）。本 POC 为静态证据 + 请求构造文本，不执行。

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

若 `$stripped_url` 后续被用于文件/模板定位或直接回显，可能导致服务器路径、内部文件结构或 API 元信息泄露（信息泄露，CWE-200）；若用于路由分发则可能造成非预期端点访问。当前证据仅能确认输入可控与处理方式不当，具体影响面证据不足。

**CVE / CWE 论证**

CWE-200（向未授权方暴露信息）。外部可达性：`$_SERVER['REQUEST_URI']` 由任意 HTTP 请求控制，无需认证即可触达第 9-10 行。但利用链未闭合——缺少 `$stripped_url` 的消费点证据，无法证明敏感信息实际被返回，故不满足 CVE 级别的完整论证。

**修复建议**

不要用 str_replace 处理请求路径：改用 parse_url() 拆分 path 与 query，对 path 做规范化（去除重复分隔符、拒绝 `..`、统一大小写与百分号解码后再比较），并以白名单映射到固定的内部资源标识，禁止把客户端路径直接拼接进文件系统或 include；对错误响应统一返回通用信息，避免回显服务器路径。

**验证说明**

静态证据：入口 GET /002；source=repository/API response user object；sink=002.php:10；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送任意 HTTP 请求 → 第 9 行 `$_SERVER['REQUEST_URI']` 取得完整请求 URI（含查询串，完全可控）→ 第 10 行 str_replace 仅删除首个 `/vulnerabilities/api/` 字面量得到 `$stripped_url`，未做规范化与白名单校验 → 后续消费点未在证据中给出，危险汇点缺失，链条在“读取后的危险汇点”处断开。
POC 备注：仅文本工件，不执行、不联网。目标统一使用 TARGET。第 10 行后续消费点未在 code_pack 中提供，若无法确认则本 POC 仅作为静态证据记录，不宣称已验证信息泄露。

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
| safety_guard | 安全防护 | 3.71 | 是 |
| surface_mapper | 攻击面测绘 | 8.97 | 是 |
| deep_finder | LLM 深挖 | 4.6 | 是 |
| candidate_screener | 候选筛选 | 2.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.46 | 是 |
| coordinator | 管线协调 | 7.65 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
