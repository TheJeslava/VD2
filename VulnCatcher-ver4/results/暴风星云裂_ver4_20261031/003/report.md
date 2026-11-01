# 落日二号乙漏洞挖掘报告 — 20261031-163837-f8bde4

- 生成时间：2026-10-31T08:39:24.256991+00:00
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

本次审计范围收敛到单文件 PHP 脚本 003.php（98 行，无框架、无路由配置、无端点清单）。共交付 2 条高危发现：LLM-d891d8de8c0d 为 003.php 中基于 $_SERVER['REQUEST_URI'] 的反射型/DOM XSS（JavaScript 字符串上下文，line_end=51），SEM-b5ee97e20ce3 为同一 REQUEST_URI 路径处理导致的 API 信息泄露（CWE-200，line_end=4）。两条均带 POC，但均为静态文本 POC（HTTP 型，需在授权环境自行验证），本次未做任何动态验证。最高危为 XSS：参数直接进入页面脚本字符串上下文，可导致会话/凭据窃取。二次注入链：输入未提供存储写点/读点证据，本次不认定二次注入。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3115 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 003.php（98 行），已逐行审计。该文件为前端演示页，主要逻辑在浏览器端 JS：读取 /vulnerabilities/api/v2/user/2 并 PUT 更新 name。服务端唯一外部输入为 $_SERVER['REQUEST_URI']（第 3 行），经 str_replace 弱过滤后在第 31/51 行拼入 <script> 单引号字符串，构成反射型 XSS（已报告）。第 83 行 $_SERVER['PHP_SELF'] 拼入 form action 属性，同样未编码，但 PHP_SELF 受服务器路径规范化限制，注入难度高且证据不足，未单独立项。文件中未出现 system/exec/SQL/include/文件读写/反序列化等汇点，无命令注入、SQL 注入、路径穿越、SSRF、反序列化证据；无 md5/sha1/openssl/rand/setcookie 调用，配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie）在本文件中无证据。页面提示“elevate your user to admin”暗示后端 API 存在越权/批量赋值风险，但后端 API 代码不在 code_pack 内，按规则视为不存在，未报告。

未覆盖 / 证据缺口：
- 后端 /vulnerabilities/api/v2/user/2 的实现不在 code_pack，无法评估其是否存在 IDOR/批量赋值提权
- 无部署配置（.htaccess/nginx），无法确认 REQUEST_URI 是否被服务器规范化或拒绝特殊字符
- 无 PHP 版本与运行时开关信息，无法判断 PHP_SELF 注入可利用性
- policy 未提供被抑制候选信息，未输出不代表不存在

## 3. Findings

### F-1: 003.php 通过 REQUEST_URI 反射注入 JavaScript 字符串上下文（DOM/反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`003.php:3-51`
- **来源**：`llm_finding`

**描述**

003.php 第 3 行读取 $_SERVER['REQUEST_URI']，第 4 行仅用 str_replace 删除固定子串 "/vulnerabilities/api/"，未做任何 HTML/JS 编码或白名单校验；第 31 行与第 51 行把 $stripped_url 直接拼接进 <script> 内的单引号 JS 字符串（const url = '" . $stripped_url . "/vulnerabilities/api/v2/user/2';）。攻击者可在请求 URI 中注入单引号闭合字符串并插入任意 JS，脚本在受害者浏览器执行，属于反射型 XSS。

**source / sink**

- source：path `REQUEST_URI`（003.php:3）
- sink：003.php:51 第 31/51 行字符串拼接进 <script> 内 JS 单引号字符串，最终由第 6/78 行 $html 输出到响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:3` | 从 $_SERVER['REQUEST_URI'] 读取完整请求 URI，包含查询串与路径 | 攻击者完全可控的原始字符串 |  |
| 2 | `003.php:4` | str_replace 仅删除固定子串 "/vulnerabilities/api/"，不改变引号、尖括号等危险字符 | 仍含单引号/尖括号的可控字符串 | 黑名单式替换只针对固定子串，可用不含该子串的 payload 或拆分该子串绕过 |
| 3 | `003.php:31` | 把 $stripped_url 拼进 JS 单引号字符串 const url = '...' | 进入 JavaScript 字符串上下文 |  |
| 4 | `003.php:6` | $html 被输出到 HTTP 响应，浏览器解析执行注入的 JS | 反射到响应体，浏览器执行 |  |

**POC**

针对 /003.php（GET）的反射型跨站脚本 POC。源码 003.php:3 取 $_SERVER['REQUEST_URI']，第 4 行 str_replace 去掉 "/vulnerabilities/api/" 前缀后，第 51 行把结果输出到页面（未做 HTML 实体编码），因此 URL 路径中的脚本片段会原样进入响应体。注入通道是 URL path（REQUEST_URI），不是查询参数。

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
- POC 目录：`poc/LLM-d891d8de8c0d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取会话/发起越权请求（结合页面内对 /vulnerabilities/api/v2/user/2 的 PUT 调用可篡改用户数据）

**CVE / CWE 论证**

CWE-79 反射型 XSS；无需认证，外部可直接通过请求 URI 触发，链闭合（source→拼接→响应输出）

**修复建议**

对 $stripped_url 使用 json_encode() 或 htmlspecialchars(..., ENT_QUOTES) 后再嵌入 JS 字符串；更佳做法是不把 URI 拼进脚本，改用相对路径或服务端生成的固定前缀

**验证说明**

需确认 Web 服务器是否对 REQUEST_URI 做规范化/拒绝含引号的路径；部分服务器会拒绝原始单引号，需用编码形式验证实际反射内容
模型 POC 要点：在请求 URI 中注入单引号闭合 JS 字符串并插入脚本，使页面加载时执行任意 JS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /003.php）：符合 CWE-79（跨站脚本）。漏洞位于 003.php:51 的输出汇点，外部输入来自 $_SERVER['REQUEST_URI']（003.php:3），经 003.php:4 的 str_replace 处理后未做 HTML 编码即输出，source→sink 链静态闭合，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。所有请求中的主机统一为 TARGET:8080，需替换为授权目标后手动执行；管线不执行、不联网。注意注入点在 URL 路径而非查询串，若目标前置代理对路径做规范化，需确认载荷是否被改写。

### F-2: 003.php 基于 REQUEST_URI 的路径处理与 API 信息泄露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`003.php:3-4`
- **来源**：`rule`

**描述**

证据仅覆盖 003.php 第 3-4 行：第 3 行 `$request_url = $_SERVER['REQUEST_URI'];` 将客户端可控的请求 URI（含路径与查询串）读入变量；第 4 行 `$stripped_url = str_replace("/vulnerabilities/api/", "", $request_url);` 仅做一次固定子串删除，未做规范化、未校验前缀、未限制输出字段。攻击者输入点即 HTTP 请求行中的 URI（任意路径/查询串），经 `$_SERVER['REQUEST_URI']` → `$request_url` → `str_replace` → `$stripped_url`。由于 `str_replace` 只删除字面子串且不区分大小写变体、重复出现、URL 编码形式（如 `%2f`、`..%2f`、`//vulnerabilities/api/`），剥离结果仍可能保留攻击者构造的路径片段；同时该变量后续如何被用于路由分发或响应拼装，在给定片段中不可见，因此“信息泄露”的具体汇点（是否回显 `$stripped_url`、是否据此选择 API 资源并返回用户对象字段）证据不足。当前只能确认：该端点以请求 URI 作为唯一输入并做非规范化字符串处理，属于典型的路径/资源标识处理缺陷面，但缺少读取后的危险汇点证据。

**source / sink**

- source：repository `API response user object`（003.php）
- sink：003.php:4 $stripped_url = str_replace ("/vulnerabilities/api/", "", $request_url);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `003.php:4` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型条目：003.php:3-4 直接使用 $_SERVER['REQUEST_URI'] 并做字符串替换后参与后续处理，属于对外部请求路径的信任与信息暴露面。本条为源码审查记录，不发送请求；其“硬编码凭据/弱算法”描述与所给代码片段（仅 REQUEST_URI 处理）不匹配，实际证据仅支持“请求路径被直接信任并回显/参与处理”，建议按 CWE-200/CWE-79 方向复核，而非凭据泄露。

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

若后续代码将 `$stripped_url` 直接用于资源定位或响应回显，可能导致：未授权读取其他 API 资源/用户对象字段（越权信息泄露）、通过路径变体绕过 `/vulnerabilities/api/` 前缀限制访问内部端点、以及在错误响应中回显内部路径结构。基于现有片段，上述影响为推断，未验证。

**CVE / CWE 论证**

CWE-200（向未授权方暴露信息）。外部可达性：入口为 `$_SERVER['REQUEST_URI']`，任意远程 HTTP 请求即可触达，无需认证（片段中未见任何鉴权判断）。利用链闭合性：source（第 3 行）与中间处理（第 4 行）已确认，但缺少“读取后的危险汇点”（响应输出或资源分发）证据，链未闭合，故不满足 CVE 级论证；需补充 003.php 第 5 行之后的代码以确认汇点。

**修复建议**

1) 不要用 `str_replace` 做前缀剥离，改为解析后比较：用 `parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)` 取路径并 `rawurldecode` 规范化，再用 `str_starts_with($path, '/vulnerabilities/api/')` 严格校验前缀，不匹配直接返回 404；2) 对剥离后的资源标识使用白名单映射（固定路由表/枚举），禁止把用户输入直接拼入资源查找；3) 响应仅返回显式声明的字段（DTO 白名单），避免整对象序列化；4) 该 API 端点强制鉴权与对象级授权校验；5) 统一错误响应，不回显内部路径或堆栈。

**验证说明**

静态证据：入口 GET /003；source=repository/API response user object；sink=003.php:4；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造形如 `GET /vulnerabilities/api/../admin/...` 或含重复/编码前缀的 URI → Web 服务器填入 `$_SERVER['REQUEST_URI']`（003.php:3）→ `str_replace` 仅删除首个字面 `/vulnerabilities/api/`，残留路径片段进入 `$stripped_url`（003.php:4）→ 后续（片段未给出）若以该值定位资源或回显，则造成越权资源访问或路径信息泄露。当前证据止于第 4 行，汇点缺失。
POC 备注：仅限授权测试。本条为离线静态审查，不含网络请求；不执行任何命令。

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
| safety_guard | 安全防护 | 4.55 | 是 |
| surface_mapper | 攻击面测绘 | 8.97 | 是 |
| deep_finder | LLM 深挖 | 8.14 | 是 |
| candidate_screener | 候选筛选 | 4.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.75 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.37 | 是 |
| coordinator | 管线协调 | 5.47 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
