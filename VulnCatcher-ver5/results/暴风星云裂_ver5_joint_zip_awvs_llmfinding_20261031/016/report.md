# 落日二号乙漏洞挖掘报告 — 20261031-214254-f70391

- 生成时间：2026-10-31T13:43:46.651205+00:00
- 输入：`$WORKSPACE\暴风星云裂\016.zip`
- 输入模式：`zip`
- SHA256：`8496ed015983b44430f1b8716ed9b77300dea2ae53954f97621110e329af01e4`
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

本次汇总基于单文件 PHP 脚本 016.php（70 行）的静态审计结果，共交付 2 条 findings，均已附带 POC 文本。最高危为 SEM-22bc26282629（api_info_disclosure，high）：016.php 第 18 行附近的前端 fetch 调用暴露了 API 端点与用户对象字段，属信息泄露（CWE-200），POC 为 HTTP 型，可对照 TARGET 复现请求路径。其次为 SEM-8ca5b94d5c6d（weak_crypto，medium）：016.php 第 7 行令牌生成使用弱加密算法（CWE-327），该条仅有静态证据 POC，不能宣称可动态复现，需代码语义复核算法与密钥/IV 使用方式。两条 POC 均已生成（with_poc=2），但均未经动态验证，仅为文本工件。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 016.php（70 行，已完整展示 1-70 行）。该脚本是一个令牌挑战页面：第 3 行 require 引入 token_library_high.php（该文件不在 code_pack 中，视为不存在，无法审计），第 7 行调用 create_token() 生成令牌，第 52/62 行用 htmlentities() 对 $token_data 做 HTML 实体编码后输出到 textarea，第 9-68 行输出一段静态 HTML/JS，前端 fetch 将用户输入的 token POST 到 source/check_token_high.php（该文件同样不在 code_pack 中）。审计结论：脚本自身没有任何请求参数读取点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/filter_input/extract/parse_str），因此不存在从外部输入到本文件内 sink 的污点链；两处输出点均已用 htmlentities 编码，不构成反射型 XSS；本文件内无 exec/system/shell_exec/proc_open、无 include/require 拼接变量（第 3 行为字面量路径）、无 SQL 调用、无文件读写、无 setcookie、无 md5/sha1/rand/openssl 等配置类证据。真正的安全逻辑（令牌生成算法、令牌校验、身份/等级判定）全部位于未提供的 token_library_high.php 与 source/check_token_high.php 中，无法判断是否存在弱令牌生成（weak_random/weak_crypto）、可伪造令牌导致的认证绕过或越权。按零容忍误报原则，不输出 finding。

未覆盖 / 证据缺口：
- token_library_high.php 未在 code_pack 中，create_token() 的令牌生成算法（是否使用 rand/mt_rand/uniqid、是否可预测、是否含可篡改的 level 字段）无法审计，这是本挑战最可能的核心漏洞点
- source/check_token_high.php 未在 code_pack 中，令牌校验逻辑、解密逻辑、用户身份与 level 判定、是否存在签名校验缺失或可伪造管理员令牌，均无法审计
- 无部署配置（.htaccess/nginx/composer.json），无法确认 016.php 的实际暴露路径与访问控制
- surface_notes 中提到的 2 处 sink 热点未给出行号与函数名；经逐行核对，本文件内可见的输出点仅为第 52、62 行的 htmlentities 编码输出，未发现命令/文件/SQL 类汇点

## 3. Findings

### F-1: 016.php 前端 fetch 调用暴露 API 端点与用户对象字段（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:17-18`
- **来源**：`rule`

**描述**

证据覆盖 016.php 第 17-19 行：第 18 行 `fetch(url, {` 发起 POST 请求（第 19 行 `method: 'POST'`），`url` 变量与请求体内容未在片段中给出。规则将其标记为 API 信息泄露，但片段中既没有硬编码的 API 地址、密钥、令牌，也没有返回的用户对象字段定义；`url` 的来源（硬编码常量还是服务端注入）无法确认。因此「信息泄露」目前仅为语义模式命中，缺少具体泄露内容的原文证据。

**source / sink**

- source：repository `API response user object`（016.php）
- sink：016.php:18 			fetch(url, { 

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:18` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（api_info_disclosure，CWE-200）：016.php:18 起为前端 fetch(url, {method:'POST', ...}) 调用，code_pack 仅给出 fetch 起始行，未给出 url 变量来源、请求体字段与响应处理，无法确认泄露的具体 API 与字段。因此仅记录证据位置，不伪造请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 016.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-22bc26282629`
- 风险提示：HTTP POC 未使用 TARGET 占位符, 请求未包含 finding 端点 /016, 请求未体现 HTTP 方法 GET, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码, POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若 `url` 指向内部/管理 API 且响应包含用户敏感字段（如手机号、邮箱、内部 ID、令牌），未授权访问者可通过浏览器直接调用该端点获取数据，造成用户信息批量泄露。当前证据不足以确认泄露字段与鉴权状态。

**CVE / CWE 论证**

CWE-200（敏感信息暴露给未授权方）。外部可达性：该 fetch 位于 016.php 输出的前端脚本中，任何访问页面者均可触发；但利用链未闭合——缺少 `url` 定义、请求体与响应字段，无法证明存在敏感数据暴露或鉴权缺失。

**修复建议**

1) 服务端 API 对每个请求做身份与权限校验，不依赖前端隐藏；2) 响应体按最小必要原则裁剪字段，避免返回内部 ID、令牌、完整联系方式；3) 将 API 基址与密钥从页面脚本中移除，改由服务端代理调用；4) 对敏感接口增加速率限制与审计日志；5) 补充 `url` 定义与响应结构以便复核。

**验证说明**

静态证据：入口 GET /016；source=repository/API response user object；sink=016.php:18；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者访问 016.php 页面 → 页面脚本第 18 行 `fetch(url, {method:'POST'})` 调用后端 API → （待确认）`url` 指向内部接口且无鉴权 → 响应返回用户敏感字段 → 攻击者直接读取或批量枚举。链路在 `url` 定义与响应字段处断开，需补充证据才能闭合。
POC 备注：仅文本工件，不执行、不联网。目标地址统一写 TARGET。未覆盖范围：url 变量赋值、fetch body 字段、API 鉴权与响应结构。

### F-2: 016.php 令牌生成使用弱加密算法（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6-7 行：第 7 行 `$token_data = create_token();` 调用 `create_token()` 生成令牌数据。规则命中判定为弱加密算法/可预测令牌，但输入片段中未给出 `create_token()` 的函数体，无法确认其内部使用的具体算法（如 DES/ECB/RC4 等）、密钥来源、IV/盐值处理方式，也无法确认该令牌保护的对象（会话、CSRF、重置口令等）。因此「弱算法」这一根因目前只有语义模式命中，缺少算法名与调用参数的原文证据。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：016.php:7 调用 create_token() 生成令牌，但 code_pack 仅给出调用行，未给出 create_token() 的实现，无法确认其内部使用的算法（如是否使用 MD5/SHA1、固定密钥、可预测随机源）。因此本 POC 仅记录证据位置与人工确认路径，不构造 HTTP 请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 016.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-8ca5b94d5c6d`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若 `create_token()` 确实使用弱加密算法或可预测随机源生成令牌，攻击者可在获取少量令牌样本后离线分析或直接预测后续令牌，从而伪造会话/重置令牌，导致身份冒用或越权访问。当前证据不足以量化具体影响面。

**CVE / CWE 论证**

CWE-327（使用已被攻破或风险性加密算法）。外部可达性：016.php 为可访问脚本，第 7 行在请求处理路径上执行；无需认证即可触发令牌生成。但利用链未闭合——缺少 `create_token()` 实现，无法证明算法强度不足或令牌可伪造，故不能作为已确认漏洞对外论证。

**修复建议**

1) 在 `create_token()` 中改用 CSPRNG（PHP 的 `random_bytes()` / `random_int()`）生成令牌，避免自行实现加密；2) 若必须加密，使用 AES-256-GCM 等认证加密模式，密钥由 KMS/环境变量注入并定期轮换，禁止硬编码；3) 令牌设置足够熵（≥128 bit）与有效期，服务端存储哈希而非明文；4) 补充 `create_token()` 源码以便复核算法与密钥管理。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 016.php 发起请求 → 第 7 行调用 `create_token()` 生成 `$token_data` → （待确认）函数内部使用弱算法/弱随机源 → 令牌可预测或可伪造 → 攻击者伪造令牌冒充他人。链路在 `create_token()` 实现处断开，需补充该函数源码才能闭合。
POC 备注：仅文本工件，不执行、不联网。目标地址如需引用统一写 TARGET。未覆盖范围：create_token() 定义、调用入口路由。

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
| `weak_crypto` | CWE-327 |  | 1 |
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
| safety_guard | 安全防护 | 5.06 | 是 |
| surface_mapper | 攻击面测绘 | 12.1 | 是 |
| deep_finder | LLM 深挖 | 4.95 | 是 |
| candidate_screener | 候选筛选 | 4.98 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.51 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.56 | 是 |
| coordinator | 管线协调 | 7.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
