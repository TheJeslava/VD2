# 落日二号乙漏洞挖掘报告 — 20261031-005940-3c7be3

- 生成时间：2026-10-30T17:00:17.216421+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-8ca5b94d5c6d，类型 weak_crypto（CWE-327），严重度 medium，位于唯一文件 016.php 第 7 行附近，标题指向 create_token() 的弱加密/可预测令牌候选，来源为规则命中，已附带 POC。最高危即该条 medium 级配置型候选；无高危/严重级发现。POC 齐全度为 1/1，但该 POC 属静态证据型（算法/令牌生成语义），不具备 HTTP 动态复现信号，不能宣称可动态复现。攻击面测绘显示 016.php 存在 2 处 sink 热点，但未提供行号与代码，相关风险点未被任何 finding 覆盖，已转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2390 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 016.php（70 行，已完整展示 1-70 行）。该文件是一个演示/靶场页面：第 3 行 require "token_library_high.php"，第 7 行调用 create_token() 生成令牌，第 9-68 行拼接 HTML 输出，其中第 52、62 行对 $token_data 使用 htmlentities() 编码后写入 textarea，第 13 行前端 fetch 提交到 source/check_token_high.php。审计结论：016.php 自身没有任何超全局变量读取点（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/$_SERVER），没有 exec/system/passthru/proc_open、include/require 动态路径、fopen/file_get_contents/file_put_contents/move_uploaded_file、SQL 调用、eval/assert/create_function、unserialize 等 sink；唯一的 require 是硬编码常量路径，不可控。因此 surface_notes 中提到的 2 处 sink 热点并不落在本文件可见代码内，实际危险逻辑（令牌生成算法、令牌校验与身份/权限判定）位于未送入 code_pack 的 token_library_high.php 与 source/check_token_high.php，按零工具契约视为不存在，无法建立 source→sink 闭合链。第 35 行 message_line.innerText 使用 innerText 而非 innerHTML，且 data.user/data.level 来自服务端 JSON，不构成 DOM XSS。配置型线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均需查看 token_library_high.php 的 create_token() 实现才能判断，本文件无 md5/sha1/mcrypt/openssl/rand/setcookie/session_set_cookie_params 调用，证据不足，不单独立项。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- token_library_high.php 未送入 code_pack：create_token() 的令牌生成算法（是否可预测、是否弱加密/弱随机、是否可伪造管理员身份）无法审计，这是本靶场最可能的核心漏洞所在
- source/check_token_high.php 未送入 code_pack：令牌校验逻辑、解密流程、user/level 字段来源与信任方式无法审计，无法判断是否存在认证绕过或权限提升
- 无 HTTP 端点清单与认证信息，无法确认 016.php 是否对外暴露
- 无 php.ini/.htaccess 等配置，无法确认 allow_url_include、open_basedir 等前提
- 无 composer 依赖清单，无法评估第三方库 CVE

## 3. Findings

### F-1: 016.php 令牌生成调用 create_token() 的弱加密/可预测令牌候选（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`016.php:6-7`
- **来源**：`rule`

**描述**

证据仅覆盖 016.php 第 6–7 行：第 7 行 `$token_data = create_token();` 调用了一个名为 create_token 的函数并把返回值存入 $token_data。规则引擎将其标记为弱加密/可预测令牌语义命中，但 code_pack 中未提供 create_token 的函数体（定义在其他文件或未纳入本次片段），因此无法确认其内部使用的算法（如 DES/ECB/固定 IV/可预测随机源）或密钥管理方式。攻击者输入点、经过的变量与校验失效环节在当前证据下均无法确定：既没有看到外部可控输入进入 create_token 的参数，也没有看到令牌被用于鉴权/签名校验的汇点。因此本条只能作为配置/实现型弱点的待复核候选，不能断言可利用链闭合。

**source / sink**

- source：repository `create_token(`（016.php）
- sink：016.php:7 $token_data = create_token();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `016.php:7` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：在 016.php 第 7 行，`$token_data = create_token();` 的返回值被直接用于令牌数据，但当前 code_pack 只给出该调用点，未给出 `create_token()` 的实现，因此无法确认其内部是否使用弱算法（如 DES/RC4/ECB 模式、固定 IV、可预测种子等）。本 POC 仅记录证据位置与人工确认路径，不发送任何请求。

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

若 create_token 确实使用弱算法或可预测随机源生成会话/鉴权令牌，后果为令牌可被预测或伪造，进而导致身份冒用与越权访问。但当前证据不足以确认保护对象（会话、CSRF、API 令牌）与可伪造性，影响范围证据不足。

**CVE / CWE 论证**

CWE-327（使用已被攻破或有风险的加密算法）。外部可达性：016.php 第 7 行在脚本顶层执行，若该文件可被 HTTP 直接访问则令牌生成逻辑外部可达；但无需认证这一点无法从现有片段确认。利用链闭合：不成立——缺少 create_token 实现、算法名、密钥/IV 来源以及令牌校验汇点，无法证明可伪造。

**修复建议**

1) 在 create_token 实现中改用 CSPRNG（PHP 的 random_bytes()/random_int()）生成至少 128 位熵的令牌；2) 若涉及加密，改用 AES-GCM 等认证加密并每次使用随机 nonce，禁止 ECB 与固定 IV；3) 令牌比较使用 hash_equals() 防时序侧信道；4) 令牌设置合理过期时间并在服务端可撤销；5) 补充 create_token 源码到审计范围以完成复核。

**验证说明**

静态证据：入口 ANY /016；source=repository/create_token(；sink=016.php:7；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：当前可见链路仅为：016.php:7 调用 create_token() → 返回值赋给 $token_data。由于 create_token 的函数体、随机源、算法与后续使用点均不在 code_pack 内，攻击者输入→变量→危险汇点的完整链路无法构建；本条为语义模式命中的待复核候选，需补充实现代码后才能判定是否构成真实弱加密/可预测令牌漏洞。
POC 备注：本 POC 为纯文本静态证据工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一写 `TARGET`（本 finding 为离线审查，无 HTTP 请求）。仅限授权测试。缺口：code_pack 未包含 `create_token()` 定义，无法确认算法与密钥来源，建议补充该函数源码后再定级。

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
| safety_guard | 安全防护 | 2.1 | 是 |
| surface_mapper | 攻击面测绘 | 9.81 | 是 |
| deep_finder | LLM 深挖 | 4.05 | 是 |
| candidate_screener | 候选筛选 | 2.94 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.17 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.54 | 是 |
| coordinator | 管线协调 | 6.52 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
