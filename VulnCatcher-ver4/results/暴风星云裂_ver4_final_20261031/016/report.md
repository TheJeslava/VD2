# 落日二号乙漏洞挖掘报告 — 20261031-172702-3c5e63

- 生成时间：2026-10-31T09:27:44.182774+00:00
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

本次汇总基于单文件 PHP 脚本 016.php（70 行）的静态审计结果，共交付 2 条 finding：一条 high 级 api_info_disclosure（016.php 第 18 行附近前端 fetch 调用暴露 API 端点与请求结构，CWE-200），一条 medium 级 weak_crypto（016.php 第 7 行附近 create_token() 令牌生成存在弱加密/可预测风险，CWE-327）。最高危为 api_info_disclosure。两条 finding 均标注 has_poc=true，但需区分：api_info_disclosure 具备 HTTP 侧证据，可形成 HTTP POC；weak_crypto 属配置/算法型候选，其 POC 为静态证据 POC，不能宣称可动态复现。本次未产出二次注入链。需强调：surface_notes 明确指出清单未提供代码片段、source 侧为空、sink 热点 2 处未给行号，因此上述结论均为基于已给代码的静态推断（llm_inferred 级），未经动态验证。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 016.php（70 行）一个文件，已逐行审计。该文件是一个演示/靶场页面：第 3 行 require 引入 token_library_high.php（未在 code_pack 中，视为不存在，无法审计其 create_token 实现），第 7 行调用 create_token() 生成令牌，第 9-68 行拼接 HTML 输出，第 52、62 行对 $token_data 使用 htmlentities() 转义后嵌入 textarea，第 13 行前端 fetch 指向 source/check_token_high.php（同样不在 code_pack 中）。文件内不存在 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 等外部输入读取，不存在 exec/system/include/eval/unserialize/文件读写/SQL 等危险汇点，因此 source→sink 链无法闭合，不产出 finding。surface_notes 中提到的 2 处 sink 热点与 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 待查项，其真实实现位于未提供的 token_library_high.php 与 source/check_token_high.php 中，本阶段无证据支撑，不能推断。

未覆盖 / 证据缺口：
- token_library_high.php 未在 code_pack 中，create_token() 的令牌生成算法（是否弱随机/弱加密/可预测）无法审计
- source/check_token_high.php 未在 code_pack 中，令牌校验逻辑（是否可伪造管理员令牌、是否校验签名）无法审计
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、open_basedir 等影响
- 无端点清单，无法确认该脚本的 HTTP 入口与认证上下文

## 3. Findings

### F-1: 016.php 前端 fetch 调用暴露 API 端点与请求结构（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:17-18`
- **来源**：`rule`

**描述**

证据覆盖 016.php 第 17-19 行：第 18 行 `fetch(url, {` 发起前端请求，第 19 行指定 `method: 'POST'`。片段中 url 变量、请求体字段、响应处理逻辑以及服务端鉴权均未给出，因此无法确认是否返回了敏感用户对象或内部字段。现有证据仅表明页面内嵌了 API 调用代码，端点与请求方法对任何能加载该页面的访问者可见。

**source / sink**

- source：repository `API response user object`（016.php）
- sink：016.php:18 			fetch(url, { 

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:18` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（api_info_disclosure，CWE-200）：`016.php:18` 处存在前端 `fetch(url, { method: 'POST', ... })` 调用，可能将内部 API 路径、参数结构或凭据暴露在客户端脚本中。code_pack 仅给出 fetch 起始行，未给出完整 URL 与请求体，无法确认泄露的具体信息。

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

若该 API 在未鉴权情况下返回用户对象或内部字段，攻击者可直接读取敏感数据（数据泄露）。但当前片段未展示响应字段、鉴权头或服务端校验，影响无法确认。

**CVE / CWE 论证**

CWE-200 需要证明敏感信息实际被未授权方获取；016.php:17-19 只显示 fetch 调用与 POST 方法，未显示 url 取值、请求参数、响应解析或服务端返回字段，外部可达性与无需认证条件均无法从该片段确认，利用链不闭合。

**修复建议**

确认该 API 的服务端鉴权与返回字段白名单，仅返回前端必需的最小字段；避免在响应中携带内部 ID、邮箱、角色等敏感属性；对接口做速率限制与访问日志；前端不要硬编码内部管理端点。补充服务端处理文件与行号后再判定。

**验证说明**

静态证据：入口 GET /016；source=repository/API response user object；sink=016.php:18；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：016.php:18 的 fetch(url, { method: 'POST' }) 是前端发起点，但 url 来源、请求体、响应字段与服务端鉴权均不在 code_pack 中，无法建立“攻击者输入→敏感字段返回”的完整链路，利用链未闭合。
POC 备注：仅文本工件，不执行、不联网。请求使用占位符 TARGET。缺口：fetch 的 url/headers/body 未在 code_pack 中提供，需补充源码后再定稿请求。

### F-2: 016.php 令牌生成调用 create_token() 的弱加密/可预测令牌风险（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6-8 行：第 7 行 `$token_data = create_token();` 调用了一个名为 create_token 的函数，并把返回值赋给 $token_data。该函数体不在 code_pack 中，因此无法确认其内部使用的是 DES/ECB/固定 IV/硬编码密钥等具体弱算法，也无法确认令牌的熵源与长度。当前证据只能说明：令牌由单一函数集中生成，且该函数是安全令牌的唯一来源，属于需要重点复核的加密实现点。攻击者输入路径、可控变量与校验失效环节在现有片段中均不可见。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：`016.php:7` 调用 `create_token()` 生成令牌，但 code_pack 仅给出调用点，未给出 `create_token()` 的实现，无法确认其内部是否使用弱算法（如 MD5/SHA1、固定 IV、可预测种子）。因此本 POC 只记录证据位置与人工确认路径，不发送请求、不执行。

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

若 create_token() 内部确实使用弱算法或低熵随机源，则生成的令牌可被预测或离线破解，进而导致会话/身份令牌伪造、越权访问受保护资源。当前证据不足以确认该影响成立，属于待验证的潜在影响。

**CVE / CWE 论证**

CWE-327（使用有缺陷的加密算法）要求明确指出算法名与使用场景；现有片段只给出函数名 create_token()，未给出算法、模式、密钥或 IV 的任何原文证据，外部可达性与无需认证条件也无法从 016.php:6-8 推断。因此不满足 CVE 论证所需的利用链闭合条件，本项应降级为待复核候选而非已确认漏洞。

**修复建议**

在 create_token() 实现中改用密码学安全的随机源（如 random_bytes / CSPRNG）生成足够长度（≥128 bit）的令牌；若涉及加密，使用 AES-GCM 等认证加密并避免 ECB 与固定 IV；密钥从配置/密钥管理服务读取而非硬编码；令牌应设置有效期并在服务端校验。补充 create_token() 的实现文件与行号后再行判定。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：016.php:7 调用 create_token() 生成 $token_data，但函数实现未包含在 code_pack 中，无法追踪算法选择、随机源与密钥来源，也无法确认攻击者能否预测或伪造该令牌。利用链在“算法/熵源”这一环缺失证据，未闭合。
POC 备注：仅文本工件，不执行、不联网。目标地址占位符 TARGET 未使用（离线审查）。缺口：`create_token()` 实现未在 code_pack 中提供。

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
| safety_guard | 安全防护 | 3.57 | 是 |
| surface_mapper | 攻击面测绘 | 9.06 | 是 |
| deep_finder | LLM 深挖 | 2.7 | 是 |
| candidate_screener | 候选筛选 | 4.29 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.67 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.24 | 是 |
| coordinator | 管线协调 | 6.42 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
