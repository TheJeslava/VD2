# 落日二号乙漏洞挖掘报告 — 20261031-011621-8958c0

- 生成时间：2026-10-30T17:17:04.202984+00:00
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

本次汇总基于已去重的 2 条 findings，均来自单文件 PHP 脚本 016.php（code_pack 仅含该文件，其余文件视为不存在）。最高危为 SEM-22bc26282629（api_info_disclosure，high，CWE-200）：016.php 第 18 行附近前端 fetch 调用暴露 API 端点与用户对象，属信息泄露，具备 HTTP 侧 POC 文本。其次为 SEM-8ca5b94d5c6d（weak_crypto，medium，CWE-327）：016.php 第 7 行附近令牌生成使用弱加密算法，仅有静态证据 POC，不能宣称可动态复现。两条 finding 均带 POC（with_poc=2），但均为文本工件，未执行、未做动态验证。攻击面测绘显示 sink_hot_files 标记 016.php 有 2 处汇点而 source_hot_files 为空，源-汇不匹配，注入类（command_injection / sql_injection / path_traversal / ssrf）攻击面尚未定论，需人工通读确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 016.php（70 行）。通读后确认：该脚本是 Prognostication 令牌挑战的前端页面，第 3 行 require("token_library_high.php") 引入令牌库，第 7 行调用 create_token() 生成令牌，第 52/62 行用 htmlentities() 对 $token_data 做 HTML 实体编码后输出到 textarea，未发现未编码的反射点，因此不构成 XSS。脚本本身不读取任何 $_GET/$_POST/$_REQUEST/$_SERVER 输入，无文件操作、无命令执行、无 SQL、无反序列化、无 include 变量、无 eval/assert、无变量函数调用，sink_hot_files 标记的 2 处汇点实际是 htmlentities 输出与前端 fetch 调用，均不接收攻击者可控数据。真正的令牌生成/校验逻辑位于 token_library_high.php 与 source/check_token_high.php，这两个文件不在 code_pack 中，按契约视为不存在，无法审计 create_token() 的算法（是否弱随机/弱加密/可预测）、令牌结构、以及 check_token_high.php 的校验与越权逻辑。因此本次无法闭合任何 source→sink 利用链，按“宁可漏报不可误报”原则返回空 findings。

未覆盖 / 证据缺口：
- token_library_high.php（create_token 实现，可能涉及 weak_random/weak_crypto/可预测令牌）未在 code_pack 中，无法审计
- source/check_token_high.php（令牌校验与用户/权限判定，可能存在 auth_bypass/idor/令牌伪造）未在 code_pack 中，无法审计
- 无 php.ini/Web 服务器配置，无法确认 016.php 是否对外暴露及运行环境
- 无端点清单，无法确认 HTTP 方法与认证要求
- 016.php 中 $token_data 由 create_token() 生成后仅经 htmlentities 输出，未发现可控输入进入危险汇点

## 3. Findings

### F-1: 016.php 前端 fetch 调用暴露 API 端点与用户对象（CWE-200）

- **类型**：`api_info_disclosure` / CWE-200
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:17-18`
- **来源**：`rule`

**描述**

证据覆盖 016.php 第 17-19 行：第 18 行 `fetch(url, {` 发起请求，第 19 行 `method: 'POST',` 指定方法。片段中 `url` 为变量，未给出其赋值来源，也未出现 API 版本号、用户对象字段或鉴权头（如 Authorization/token）的具体内容。规则以「API 端点/字段暴露」语义模式命中，但无法确认：攻击者输入点（证据不足）、经过的变量（仅知 `url` 与请求选项对象）、校验为何无效（证据不足）、最终危险操作（返回数据如何渲染或存储，证据不足）。该命中属于前端代码中可见的 API 调用，是否构成信息泄露取决于服务端返回字段与鉴权强度，现有片段不足以支撑 high 级结论。

**source / sink**

- source：request `API version/user object`（016.php）
- sink：016.php:18 			fetch(url, { 

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:18` | API 端点/字段暴露；需对比版本、鉴权和返回字段 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /016（ANY）的 API 信息泄露 POC。注入点：ANY 参数 API version/user object；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/016'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 API 信息泄露 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/016?API version/user object=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-22bc26282629`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该 fetch 指向未鉴权或返回过度字段（如用户对象含手机号、内部 ID、角色、令牌）的 API，攻击者可直接调用该端点获取敏感数据，造成用户信息泄露。但基于现有片段，端点地址、鉴权方式与返回结构均未知，实际影响证据不足，不能断言已发生数据泄露。

**CVE / CWE 论证**

CWE-200（敏感信息暴露给未授权方）。外部可达性：016.php 为可访问页面，第 18 行 fetch 在客户端执行，端点可被任意访问者观察并重放（推断）。但利用链未闭合：缺少 `url` 赋值、服务端路由与响应字段、鉴权校验逻辑，无法证明未授权可读取敏感数据，故不满足 CVE 级论证，仅为 llm_inferred 的规则命中。

**修复建议**

1) 服务端对 API 做强制鉴权与对象级授权（每个用户只能读取自身对象），不要依赖前端隐藏；2) 响应使用白名单字段序列化（DTO），避免直接返回完整用户实体；3) 前端不要把内部端点、版本号、调试字段硬编码在可公开访问的脚本中，改由服务端按需下发；4) 对敏感接口增加速率限制与审计日志；5) 统一错误响应，避免通过差异回显泄露对象是否存在。

**验证说明**

静态证据：入口 ANY /016；source=request/API version/user object；sink=016.php:18；规则 php-api-surface。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：规则在 016.php:18 命中 `fetch(url, {`，判定为 API 信息暴露模式。完整链路应为：攻击者访问 016.php 页面 → 读取前端脚本中的 `url` 与请求体结构 → 直接向该 API 发起请求 → 服务端缺少鉴权或返回过度字段 → 攻击者获得他人用户对象等敏感数据。当前证据只到前端调用点，`url` 赋值、服务端路由与返回字段均未在 code_pack 中出现，链路不闭合，需补充对应服务端接口源码后才能确认。
PocWriter 建议（未采纳，缺少端点 /016）：针对 016.php:18 的 API 信息泄露候选（CWE-200）。外部输入来自 query 参数 `API version/user object`，静态链路指向第 18 行的响应/输出汇点。POC 保留原有请求结构，仅补充说明与预期结果；目标统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /016）：符合 CWE-200。漏洞位于 016.php:18，外部输入来自 query 参数 `API version/user object`，source→sink 链静态闭合且未发现有效净化，具备远程触发条件；证据等级为 llm_inferred，需动态确认实际泄露内容。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。请求中的方法 ANY 为占位，实际测试时按路由支持的方法（GET/POST）替换；参数名含空格与斜杠，需按原样编码发送。

### F-2: 016.php 令牌生成使用弱加密算法（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6-7 行：第 7 行 `$token_data = create_token();` 调用 `create_token()` 生成令牌数据，第 6 行为空行。候选由规则以「弱算法/模式或可预测令牌」语义模式命中，但输入片段中未给出 `create_token()` 的函数体，也未出现具体算法名（如 DES/ECB/RC4/MD5 等）、密钥来源、IV 生成方式或随机源。因此无法确认：攻击者输入点（证据不足）、经过的变量（仅知返回值赋给 `$token_data`）、校验为何无效（证据不足）、最终危险操作（令牌被用于何种鉴权/签名场景，证据不足）。按类型边界，若后续确认是 MD5/SHA-1 用于令牌则应改判 weak_hash（CWE-328）；当前仅有「弱加密算法」规则命中，故保留 weak_crypto（CWE-327）但置信度低。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 016.php:7 处调用 create_token() 生成令牌数据，属于弱加密/弱令牌生成候选（CWE-327）。本 POC 为离线源码审查工件，不发送任何请求，仅用于记录证据位置与人工确认步骤。

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

若 `create_token()` 确实使用弱加密算法或可预测随机源生成令牌，则攻击者可能离线分析或预测令牌，进而伪造会话/令牌实现身份冒用或越权访问。但基于现有片段，受影响的具体保护对象（会话、API 令牌、CSRF token 等）与可利用性均证据不足，不能断言实际数据泄露或越权。

**CVE / CWE 论证**

CWE-327（使用已被攻破或危险的加密算法）。外部可达性：016.php 为可访问脚本，第 7 行在请求处理路径上执行；无需认证即可触发令牌生成（推断）。但利用链未闭合：缺少 `create_token()` 实现、算法标识、密钥/IV 管理与令牌消费点，无法证明可伪造，故不满足 CVE 级论证，仅为 llm_inferred 的规则命中。

**修复建议**

1) 在 `create_token()` 中改用密码学安全算法与模式（如 AES-256-GCM 或 ChaCha20-Poly1305），禁止 DES/3DES/RC4/ECB 等；2) 令牌随机部分使用 `random_bytes()`/`random_int()` 等 CSPRNG，禁止 `rand()`/`mt_rand()`/时间戳拼接；3) 密钥从配置/密钥管理服务读取，禁止硬编码，IV/Nonce 每次随机生成且不复用；4) 若令牌用于完整性校验，改用 HMAC-SHA-256 并做常量时间比较（`hash_equals`）；5) 为令牌设置有效期与绑定上下文（用户、IP、用途），降低被预测后的滥用面。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：规则在 016.php:7 命中 `$token_data = create_token();`，判定为弱加密/可预测令牌模式。完整链路应为：外部请求进入 016.php → 调用 `create_token()` → 内部使用弱算法或弱随机源生成令牌 → 令牌返回/下发 → 攻击者预测或伪造令牌 → 以伪造令牌访问受保护资源。当前证据只到第 2 步的调用点，`create_token()` 实现与令牌消费点均未在 code_pack 中出现，链路不闭合，需补充该函数源码后才能确认可利用性。
POC 备注：纯静态证据，不生成可执行脚本；不联网、不执行。create_token() 实现缺失是本条的主要证据缺口。

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
| safety_guard | 安全防护 | 2.73 | 是 |
| surface_mapper | 攻击面测绘 | 9.17 | 是 |
| deep_finder | LLM 深挖 | 3.38 | 是 |
| candidate_screener | 候选筛选 | 4.25 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.83 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.69 | 是 |
| coordinator | 管线协调 | 5.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
