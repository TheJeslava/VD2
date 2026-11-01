# 落日二号乙漏洞挖掘报告 — 20261031-164122-a1991f

- 生成时间：2026-10-31T08:42:03.111188+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\016.zip`
- 输入模式：`zip`
- SHA256：`8496ed015983b44430f1b8716ed9b77300dea2ae53954f97621110e329af01e4`
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

本次汇总基于单文件 PHP 目标 016.php（70 行，约 2KB），共交付 2 条已去重 findings，均带 POC：一条 high 级 api_info_disclosure（016.php 第 18 行附近，前端 fetch 调用涉及的 API 信息暴露，CWE-200），一条 medium 级 weak_crypto（016.php 第 7 行附近，create_token() 令牌生成，CWE-327）。最高危为 api_info_disclosure（high）。POC 齐全度：2/2 有 POC，但需注意 weak_crypto 属配置/实现类，其 POC 为静态证据型，不能宣称可动态复现；api_info_disclosure 的 POC 亦需人工确认是否具备真实 HTTP 响应信号。本次 min_severity=low、min_confidence=0.6、suppressed_count=0，无策略抑制项，但覆盖面极窄（仅 1 文件、0 端点、无框架），结论不代表目标整体安全。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 016.php（70 行），已逐行审计。该文件是一个令牌挑战页面：第 3 行 require 引入 token_library_high.php（未在 code_pack 中，视为不存在），第 7 行调用 create_token() 生成令牌，第 52/62 行通过 htmlentities() 输出到 textarea，第 9-68 行内联 JS 将用户输入的 token 以 POST 方式提交到 source/check_token_high.php（该文件同样不在 code_pack 中）。016.php 自身不读取任何 $_GET/$_POST/$_COOKIE/$_SERVER 输入，不存在 source→sink 污点链；两处 sink_hot 热点对应的是 htmlentities 输出与前端 fetch 调用，均无服务端危险操作。真正的令牌生成/校验逻辑位于未提供的 token_library_high.php 与 source/check_token_high.php，无法评估弱随机、弱加密、令牌伪造或认证绕过，故不产出 finding。surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均需在未提供的库文件中确认，本文件无相关证据。未发现 prompt 注入诱导文本。

未覆盖 / 证据缺口：
- token_library_high.php 未提供，create_token() 的令牌生成算法（是否使用 rand/mt_rand/uniqid、是否可预测、是否含签名）无法审计
- source/check_token_high.php 未提供，令牌校验逻辑、是否可伪造管理员令牌、是否存在认证绕过无法审计
- 无部署配置（php.ini、Web 服务器重写规则），无法确认 016.php 与 source/ 目录的实际可达路径与 HTTP 方法
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 016.php 前端 fetch 调用涉及的 API 信息暴露（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:17-18`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 17-19 行：第 18 行 `fetch(url, {` 发起 POST 请求（第 19 行 `method: 'POST'`）。片段中未出现具体的 API 路径、请求体字段、响应字段或鉴权头，`url` 变量的赋值位置也不在 code_pack 内。因此无法确认是否存在敏感字段（如用户对象、内部 ID、令牌）被返回或暴露。

**source / sink**

- source：repository `API response user object`（016.php）
- sink：016.php:18 			fetch(url, { 

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:18` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（api_info_disclosure，CWE-200）：`016.php:18` 处前端代码执行 `fetch(url, { method: 'POST', ... })`，将请求发往某 API 端点。code_pack 未给出 url 的取值来源、请求体内容与响应处理逻辑，因此无法确认是否泄露敏感信息（如令牌、内部地址、调试信息）。当前仅为信息暴露候选，需人工确认。

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

若该 API 在响应中返回超出前端所需的敏感字段（如完整用户对象、内部标识、令牌），未认证或低权限用户可读取他人数据。当前证据不足以确认返回内容，影响范围无法量化。

**CVE / CWE 论证**

CWE-200（敏感信息暴露）。外部可达性无法确认：API 端点路径、鉴权要求、返回字段均不在片段中；利用链未闭合。证据不足，暂不作为已确认漏洞。

**修复建议**

对 API 响应实施字段白名单（仅返回前端渲染所需字段），移除内部 ID、令牌、邮箱等敏感字段；对接口强制服务端鉴权与对象级授权校验；避免在前端源码中硬编码内部端点或调试信息。

**验证说明**

静态证据：入口 GET /016；source=repository/API response user object；sink=016.php:18；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：016.php:18 通过 fetch(url, {method:'POST'}) 调用后端接口。由于 url 的赋值、请求参数与响应处理逻辑均不在 code_pack 中，无法确定攻击者输入点与敏感数据汇点，利用链无法闭合。
POC 备注：仅文本工件，不执行、不联网；目标地址如需引用统一写 TARGET。证据等级：llm_inferred。

### F-2: 016.php 令牌生成调用 create_token() 的弱加密/可预测令牌风险（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6-8 行：第 7 行 `$token_data = create_token();` 将令牌生成委托给 `create_token(` 函数，但该函数的实现体不在本次 code_pack 中，无法确认其内部使用的算法（如 DES/ECB/固定 IV/硬编码密钥）或随机源（如 rand()/mt_rand()/time()）。因此当前只能确认「令牌由单一函数集中生成、结果赋给 $token_data」这一事实，无法确认具体算法名、密钥来源或模式。攻击者输入点、污点路径均无法从现有片段确定。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：`016.php:7` 调用 `create_token()` 生成令牌，但 code_pack 未给出该函数的实现，无法确认其内部是否使用 MD5/SHA1/ECB/固定 IV 等弱算法。当前证据仅能定位到令牌生成调用点，属于待人工确认的候选，不能断言算法强度不足。

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

若 create_token() 内部确使用弱算法或可预测随机源，则攻击者可在获知一个或多个令牌样本后推测/伪造其他用户的令牌，导致会话劫持或身份冒用。当前证据不足以量化影响范围。

**CVE / CWE 论证**

CWE-327（使用已被攻破或危险的加密算法）。外部可达性、无需认证、利用链闭合三项均无法从现有片段确认：create_token() 实现缺失，无法证明令牌可被外部请求触发或可被离线预测。证据不足，暂不作为已确认漏洞。

**修复建议**

在 create_token() 实现中改用 CSPRNG（PHP 的 random_bytes()/random_int()）生成至少 128 位熵的令牌；若涉及加密，使用 AES-GCM 等认证加密并每次随机生成 IV；禁止使用 rand()/mt_rand()/uniqid()/time() 派生安全令牌；令牌比较使用 hash_equals() 防时序侧信道。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：016.php:7 调用 create_token() 并将返回值存入 $token_data。由于 create_token() 的函数体未包含在 code_pack 中，无法追踪其内部算法与随机源，也无法确认 $token_data 后续是否被写入 Cookie/响应头或用于鉴权比较。利用链在此处断开，需补充 create_token() 源码后才能闭合。
POC 备注：仅文本工件，不执行、不联网；目标地址如需引用统一写 TARGET。证据等级：llm_inferred。

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
| safety_guard | 安全防护 | 4.12 | 是 |
| surface_mapper | 攻击面测绘 | 7.98 | 是 |
| deep_finder | LLM 深挖 | 3.2 | 是 |
| candidate_screener | 候选筛选 | 3.44 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.75 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.44 | 是 |
| coordinator | 管线协调 | 7.24 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
