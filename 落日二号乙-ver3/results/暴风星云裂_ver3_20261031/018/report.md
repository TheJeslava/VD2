# 落日二号乙漏洞挖掘报告 — 20261031-005957-5e203b

- 生成时间：2026-10-30T17:00:40.895894+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\018.zip`
- 输入模式：`zip`
- SHA256：`c4b42bf16d7ffb0d67ab50a7b701b39c7724a0451847bcfe91b4606313b9fcfd`
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

本次汇总基于已去重 findings：共 2 条，均为 weak_crypto，集中在单文件 PHP 脚本 018.php。最高危为 LLM-86c6c58e13d2（high）：会话令牌使用 AES-128-ECB 且密钥硬编码，理论上可通过块重放/拼接伪造 admin 令牌；另一条 SEM-1f3cfc0b6797（medium）为同一文件 ECB 模式解密（CWE-327），属规则命中，与前者同源。两条均带 POC，但均为静态证据型 POC（算法/模式/硬编码密钥），不宣称可动态复现；ECB 块拼接伪造需在授权环境人工构造验证。覆盖面上仅 1 个文件、1 种语言（php）、0 个端点，无框架信息；surface_notes 明确 sink_hot_files 为空、未提供代码片段，因此 sql_injection / path_traversal / command_injection / xss / 二次注入等均未覆盖，不能据此认定不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已通读 018.php 全部可见行（1-56、65-110）。核心风险为第 2-8 行 AES-128-ECB 解密 + 第 10 行硬编码密钥 + 第 32 行仅凭解密 JSON 字段判定管理员，构成 weak_crypto 认证绕过链。第 100 行 $_SERVER['PHP_SELF'] 拼入表单 action 存在反射型 XSS 可能，但需依赖服务器对 PHP_SELF 的处理，证据不足以闭合，未单独立项。第 52 行等泄露令牌为利用前提。未提供部署/认证配置，无法评估其它配置型风险。

未覆盖 / 证据缺口：
- 无部署配置，无法确认 PHP_SELF 是否可注入 XSS
- 无端点清单，路由按单文件推断
- 第 57-64 行未在 code_pack 中显示

## 3. Findings

### F-1: 018.php 会话令牌使用 AES-128-ECB 且密钥硬编码，可被块重放/拼接伪造 admin 令牌

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

018.php 第 2-8 行的 decrypt() 使用 openssl_decrypt 以 'aes-128-ecb' 模式解密会话令牌，第 10 行硬编码密钥 "ik ben een aardbei"。ECB 模式对相同明文块产生相同密文块，且无完整性校验（无 MAC/HMAC），攻击者可将页面泄露的合法令牌按 16 字节块重排/拼接，构造出 user=sweep、level=admin 的伪造令牌。第 32 行仅校验解密后 JSON 的 user/ex/level 字段，无签名验证，因此块级篡改可直接通过认证成为管理员。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, ...) 后 json_decode 并据 $user->level 判定管理员

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 读取攻击者提交的 token 参数 | 原始十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，无格式/完整性校验 | 长度合法的 hex 字符串 | 长度检查不阻止块重排 |
| 3 | `018.php:25` | hex2bin 后交给 decrypt() 用 ECB 模式解密 | AES-ECB 密文块 |  |
| 4 | `018.php:3` | openssl_decrypt 以 aes-128-ecb 解密，ECB 无扩散，块可独立重排 | 可控明文块拼接结果 | ECB 模式 + 无 MAC，块级篡改不被检测 |
| 5 | `018.php:27` | json_decode 解析为对象 | JSON 对象 |  |
| 6 | `018.php:32` | 校验 user==sweep && ex>time() && level==admin，伪造对象满足即登录管理员 | 伪造的 admin 会话 |  |

**POC**

静态证据型 POC（离线源码审计，不发送请求）：018.php 使用 AES-128-ECB 模式解密客户端提交的 token，且密钥硬编码为字符串 "ik ben een aardbei"（018.php:32 附近）。ECB 模式无 IV、相同明文块产生相同密文块，且密钥随源码泄露，攻击者可离线伪造任意 token（如 user=sweep、level=admin、ex 为未来时间戳）绕过认证。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 018.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/LLM-86c6c58e13d2`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需凭据即可伪造管理员会话，完全绕过认证。

**CVE / CWE 论证**

CWE-327 使用已被攻破/不安全的加密算法（ECB 模式），叠加 CWE-798 硬编码密钥与缺失完整性校验，外部 POST 可达，链闭合。

**修复建议**

改用 AES-GCM 等带认证的加密模式，密钥从安全配置读取，令牌加 HMAC 签名并校验完整性。

**验证说明**

需动态确认 ECB 块边界与 JSON 字段对齐，实际构造需精确块偏移；密钥硬编码已在源码确认。
模型 POC 要点：利用 ECB 块重排：从页面泄露的 Sweep(user) 令牌与 Sooty(admin) 令牌中提取包含 level 字段的块，拼接构造 user=sweep、level=admin 的令牌。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网；目标统一使用 TARGET 占位符；仅限授权测试。token 需为 hex 且长度为 32 的整数倍，否则在格式校验处被拒。

### F-2: 018.php 使用 AES-128-ECB 模式进行解密（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

在 018.php 第 2-3 行的 decrypt($ciphertext, $key) 函数中，第 3 行调用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)。算法字符串硬编码为 'aes-128-ecb'，即 AES-128 配合 ECB（电子密码本）分组模式。ECB 对每个 16 字节分组独立加密，不使用 IV，相同明文分组产生相同密文分组，因此不具备语义安全性，会泄露明文分组结构与重复模式。此外第 3 行把 OPENSSL_PKCS1_PADDING 作为 openssl_decrypt 的 options 参数传入，该常量语义上属于 RSA 填充，与 AES 分组解密不匹配，说明填充/模式配置本身存在实现错误。攻击者不需要任何 HTTP 输入：只要能够获取或截获密文（例如通过接口返回、日志、存储泄露），即可利用 ECB 的分组重排/分组替换与模式分析对明文进行推断或篡改。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线源码审计，不发送请求）：018.php 第 3 行 decrypt() 函数使用 openssl_decrypt 的 'aes-128-ecb' 模式，ECB 不使用 IV、块间可重排/重放，属弱加密模式；配合第 32 行附近硬编码密钥，可离线构造合法密文。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 018.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-1f3cfc0b6797`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

机密性受损：ECB 模式使密文保留明文分组重复特征，攻击者可对结构化明文（如令牌、序列化对象、含重复字段的配置）做分组字典与重排攻击，逐步恢复或伪造明文内容；若该 decrypt 结果被用于身份判断或数据完整性校验，还可导致越权或数据篡改。由于缺少完整性保护（无 MAC/AEAD），密文可被分组级篡改而不易被发现。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：018.php:3 明确使用 'aes-128-ecb'，ECB 模式被公认不适用于保护敏感数据。该弱点为配置/实现型，无需认证、无需外部 HTTP 污点即可成立：任何能接触密文的攻击者均可利用。利用链闭合性：算法选择（018.php:3）→ 密文分组独立处理 → 明文模式泄露/分组篡改。注意：本条为 weak_crypto（CWE-327），不是 weak_hash；证据等级为源码推断，未做动态验证。

**修复建议**

1) 将 'aes-128-ecb' 替换为带随机 IV 的认证加密模式，如 'aes-256-gcm'（openssl_encrypt/openssl_decrypt 配合 $tag 与 OPENSSL_RAW_DATA），或至少使用 'aes-256-cbc' + 随机 IV + HMAC-SHA256 的 encrypt-then-MAC 组合；2) 移除误用的 OPENSSL_PKCS1_PADDING，改用与所选模式匹配的填充/标志（GCM 下使用 OPENSSL_RAW_DATA 并校验 tag）；3) IV 每次加密随机生成并与密文一同存储，禁止复用；4) 密钥由 KMS/密钥管理服务托管，避免硬编码；5) 对历史 ECB 密文制定迁移与重加密方案。

**验证说明**

静态证据：入口 ANY /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者获取 018.php 所保护数据的密文（来源可为接口响应、日志或存储泄露，源码中未给出具体入口，属证据不足部分）→ 密文由 decrypt() 在 018.php:3 以 'aes-128-ecb' 处理 → ECB 对每个 16 字节分组独立运算、无 IV、相同明文分组映射为相同密文分组 → 攻击者据此进行分组模式分析、分组重排或替换，推断/篡改明文 → 若解密结果用于鉴权或数据校验则进一步导致越权或数据篡改。
POC 备注：仅文本工件，不执行、不联网；目标使用 TARGET 占位符；仅限授权测试。本条目与 LLM-86c6c58e13d2 为同一文件同一根因的不同证据点（算法模式 vs 硬编码密钥），未新增 finding、未改文件/行号。

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
| `weak_crypto` | CWE-327 |  | 2 |
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
| safety_guard | 安全防护 | 2.71 | 是 |
| surface_mapper | 攻击面测绘 | 7.16 | 是 |
| deep_finder | LLM 深挖 | 8.11 | 是 |
| candidate_screener | 候选筛选 | 4.32 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.89 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.37 | 是 |
| coordinator | 管线协调 | 6.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
