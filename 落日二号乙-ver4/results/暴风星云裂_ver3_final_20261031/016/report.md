# 落日二号乙漏洞挖掘报告 — 20261031-013902-cb3098

- 生成时间：2026-10-30T17:39:34.633055+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-8ca5b94d5c6d，类型 weak_crypto（CWE-327），严重度 medium，位于唯一源文件 016.php 第 7 行附近，标题指向 create_token() 令牌生成使用弱加密/可预测算法。该条为规则命中（origin=rule），已附带 POC，但属于静态证据型 POC（算法/实现层面），不具备 HTTP 请求-响应语义，不能宣称可动态复现。最高危即此条 medium；本次无 high/critical 交付项。POC 齐全度为 1/1（仅静态）。需强调：本次未交付注入类（sql_injection / command_injection / path_traversal / xss）结论，原因是 source_hot_files 为空、静态污点链未建立，而非确认不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含 016.php（70 行），已逐行审计。该文件是一个令牌练习页面：第 3 行 require("token_library_high.php") 引入令牌库，第 7 行调用 create_token() 生成令牌，第 52、62 行用 htmlentities() 对 $token_data 做 HTML 实体编码后输出到 textarea，第 9-68 行构造的 $html 字符串在本文件内并未 echo/print 输出（文件在第 70 行以 ?> 结束，无输出语句），因此本文件内不存在可闭合的 source→sink 链。关键缺口：真正的令牌生成/校验逻辑位于 token_library_high.php 与 source/check_token_high.php，这两个文件不在 code_pack 中，按契约视为不存在，无法判断 create_token() 是否使用弱随机/弱加密/可预测令牌（weak_random / weak_crypto / auth_bypass 线索），也无法判断 check_token_high.php 的 JSON body 解析与用户/级别判定是否存在伪造或越权。页面文案（第 49-55 行）提示“解密令牌、伪造令牌成为管理员”，属于练习说明，不是代码证据，不能据此下结论。未发现满足 CVE 级别、链闭合的漏洞，故 findings 为空。

未覆盖 / 证据缺口：
- token_library_high.php 未在 code_pack 中，create_token() 的令牌生成算法（随机源、加密算法、签名校验）无法审计，weak_random/weak_crypto/auth_bypass 线索无法闭合
- source/check_token_high.php 未在 code_pack 中，令牌校验、用户/级别解析与授权判定无法审计
- 016.php 中 $html 变量未被输出，若实际部署中存在未展示的 echo $html 则第 52/62 行 htmlentities 已做编码，XSS 风险低；但输出点缺失使该判断无法完全确认
- 无路由/部署配置，无法确认 016.php 与 check_token_high.php 的外部可达性与 HTTP 方法
- 无 PHP 版本与 disable_functions 信息，无法评估潜在命令执行面（本文件内未见 exec/system 类调用）

## 3. Findings

### F-1: 016.php 令牌生成调用 create_token() 的弱加密/可预测令牌疑点（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6–7 行：第 7 行 `$token_data = create_token();` 调用了一个名为 create_token 的函数，并把返回值赋给 $token_data。候选将其标记为 weak_crypto（CWE-327）。但输入片段中没有给出 create_token() 的函数体，也没有给出任何算法名（DES/RC4/ECB 等）、密钥派生方式、IV/模式或随机源；因此无法确认该函数内部是否使用了弱加密算法或可预测的令牌生成方式。攻击者输入点、经过的变量与最终危险操作在当前证据下均无法确定。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：在 016.php 第 7 行，`$token_data = create_token();` 的返回值被直接用于生成令牌数据，但 code_pack 中未给出 `create_token()` 的实现，因此无法确认其内部是否使用弱算法（如 DES/RC4/ECB 模式）或弱随机源。当前证据仅能定位到调用点，算法强度需结合 `create_token()` 定义进一步确认；本 POC 为离线源码审查工件，不发送请求。

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

证据不足。若 create_token() 确实使用弱算法或可预测随机源生成会话/认证令牌，则可能导致令牌被预测或伪造，进而造成身份冒用/越权；但当前片段无法确认保护对象（会话、CSRF、重置令牌等）与可伪造性，不能断言具体影响。

**CVE / CWE 论证**

CWE-327（使用有风险的加密算法）要求明确算法与用途。当前仅有 016.php:7 的调用点，缺少 create_token() 实现、算法标识与密钥/随机源证据，外部可达性与无需认证的利用链均未闭合，不满足 CWE-327 的论证条件。

**修复建议**

补充 create_token() 的实现以确认算法与随机源；若用于安全令牌，应改用 CSPRNG（如 random_bytes()/random_int()）生成足够熵的令牌，避免使用 MD5/SHA1 或可预测种子；对令牌设置有效期并做服务端校验。若确认使用 DES/ECB 等弱算法，应迁移到 AES-GCM 等认证加密模式并妥善管理密钥。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：当前可见链路仅为 016.php:7 调用 create_token() 并赋值给 $token_data，之后如何使用 $token_data、函数内部如何生成令牌均不在证据范围内，利用链未闭合。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一写 TARGET。证据缺口：code_pack 未包含 create_token() 定义，无法确认算法与随机源，建议补充该函数源码后再定级。

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
| `api_info_disclosure` | CWE-200 |  | 0 |
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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 8.39 | 是 |
| deep_finder | LLM 深挖 | 3.51 | 是 |
| candidate_screener | 候选筛选 | 3.69 | 是 |
| vulnerability_analyzer | 漏洞分析 | 3.96 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.19 | 是 |
| coordinator | 管线协调 | 5.64 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
