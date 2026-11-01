# 落日二号乙漏洞挖掘报告 — 20261031-172723-94f494

- 生成时间：2026-10-31T09:28:15.779202+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 018.php：最高危为 LLM-dbe275d394bb（weak_crypto，high），指 018.php 第 33 行附近使用 AES-128-ECB 加密会话令牌，ECB 的确定性分组特性使令牌可被字节级重排/拼接，从而伪造 admin 身份；另有 LLM-a5c5a430e98b（hardcoded_secret，medium，018.php 第 10 行硬编码 AES 密钥）与 SEM-1f3cfc0b6797（weak_crypto，medium，018.php 第 3 行 AES-128-ECB 解密，规则命中）。3 条 finding 均带 POC，但均为静态证据 POC（源码级构造），其中 weak_crypto 的 ECB 篡改链在具备可访问实例时可转为 HTTP POC，本次未做任何动态验证，不能宣称可动态复现。攻击面测绘指出 018.php 第 4 行为唯一 source 热点，sink_hot_files 为空，注入类风险未得到管线确认，需人工逐行追踪。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 018.php（可见行 1-56、65-110，第 57-64 行未送入）。核心攻击面为 POST token 参数经 hex2bin 后进入 openssl_decrypt（aes-128-ecb，硬编码密钥），解密结果 json_decode 后直接作为身份与权限判定依据，无 MAC/签名校验，构成 ECB 块级可塑性导致的认证绕过/权限提升，以及硬编码密钥问题。未发现命令执行、SQL、文件操作、反序列化、SSRF 等其它 sink。第 57-64 行（其余示例令牌）未覆盖，但不影响上述结论。

未覆盖 / 证据缺口：
- 018.php 第 57-64 行未送入 code_pack
- 无部署配置/认证机制证据，无法确认访问控制
- 未动态验证 ECB 块重排的实际可行性

## 3. Findings

### F-1: 018.php 使用 AES-128-ECB 加密会话令牌，可被字节级篡改伪造 admin 身份

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-33`
- **来源**：`llm_finding`

**描述**

脚本用硬编码密钥 "ik ben een aardbei" 以 aes-128-ecb 模式解密客户端提交的 token（第 3、10、25 行），解密结果直接 json_decode 后作为身份凭据使用（第 27-33 行）。ECB 模式对相同明文块产生相同密文块且块间无关联，攻击者无需密钥即可对捕获的 token 做块重排/块替换/块删除，构造出 user=sweep、level=admin、ex 为未来的伪造令牌，从而以管理员身份登录。页面本身即提供了三个已过期令牌与明文 JSON 格式（第 46-84 行），构成完整的攻击前提。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:33 openssl_decrypt(..., 'aes-128-ecb', $key, ...) 解密结果被 json_decode 后作为身份与权限判定依据（第 25-33 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 读取攻击者提交的 token 参数 | 原始十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，不校验完整性/签名 | 长度合法的十六进制串 | 无 MAC/HMAC 校验，长度检查不提供任何完整性保护 |
| 3 | `018.php:25` | hex2bin 后以 ECB 模式解密，ECB 逐块独立解密，块可任意重排替换 | 攻击者可控的明文块序列 | ECB 无链接、无 IV、无认证，块级篡改不会被检测 |
| 4 | `018.php:27` | json_decode 得到对象 | 攻击者构造的 JSON 对象 |  |
| 5 | `018.php:32` | 以 user/ex/level 三个字段判定管理员身份 | user=sweep, ex=未来时间戳, level=admin | 身份完全来自可篡改的密文，服务端无独立会话状态 |

**POC**

018.php 使用 AES-128-ECB 模式（openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)，第 3 行）解密来自 $_POST['token'] 的十六进制密文，并据此判定管理员身份（$user->user == "sweep" && $user->ex > time() && $user->level == "admin"）。ECB 模式无 IV、相同明文块产生相同密文块，且无完整性校验（未使用 AEAD/HMAC），属于弱加密算法使用（CWE-327）。本 POC 为静态证据 + 可复现的请求结构说明，用于验证 token 解密路径可被外部输入直接驱动。

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
- POC 目录：`poc/LLM-dbe275d394bb`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需密钥即可伪造任意用户身份，包括管理员 sweep，实现认证绕过与权限提升。

**CVE / CWE 论证**

CWE-327（使用已被攻破或危险的加密算法）/CWE-353（缺少完整性校验）。外部匿名可达，利用链在单文件内闭合，无需认证。

**修复建议**

改用带认证的加密模式（AES-GCM）或对令牌加 HMAC 签名并在解密前校验；密钥不得硬编码在源码中；身份判定不应完全依赖客户端可控密文。

**验证说明**

需动态确认 ECB 块对齐与 PKCS1_PADDING 填充处理是否允许构造的块序列通过解密；建议人工用实际令牌验证块重排可行性。
模型 POC 要点：利用 ECB 块级可塑性：将捕获令牌按 16 字节块切分，重排/替换块使解密后的 JSON 满足 user=sweep、level=admin、ex 为未来时间。由于明文 JSON 结构已知（页面第 69-74 行给出格式），可离线构造目标明文块并与已有密文块对齐。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网。密文构造需在授权环境离线完成；目标地址统一使用 TARGET。

### F-2: 018.php 硬编码 AES 加密密钥

- **类型**：`hardcoded_secret` / CWE-798
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:10-10`
- **来源**：`llm_finding`

**描述**

第 10 行将加密密钥以明文硬编码为 "ik ben een aardbei"，任何能读取源码（源码泄露、备份文件、版本库）的人都能直接解密所有令牌并伪造任意身份，与 ECB 弱点叠加放大风险。

**source / sink**

- source：config `$key`（018.php）
- sink：018.php:10 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, ...) 使用该密钥解密身份令牌（第 3、25 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:10` | 密钥硬编码在源码中 | 明文密钥常量 |  |
| 2 | `018.php:25` | 该密钥用于解密客户端提交的令牌 | 攻击者获知密钥后可任意加解密 | 密钥泄露后所有令牌可被离线解密与重签 |

**POC**

018.php 第 10 行将加密密钥硬编码为字符串 $key = "ik ben een aardbei"，该密钥用于第 3 行 AES-128-ECB 解密管理员 token。硬编码密钥随源码泄露即导致所有受保护 token 可被解密/伪造（CWE-798）。本 POC 为静态证据型，说明密钥泄露如何直接支撑 LLM-dbe275d394bb 的伪造链。

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

- payload：`（仓库静态证据）`
- POC 目录：`poc/LLM-a5c5a430e98b`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

密钥泄露导致令牌可被任意伪造，认证机制完全失效。

**CVE / CWE 论证**

CWE-798（硬编码凭据）。与 ECB 弱点叠加，外部可达。

**修复建议**

密钥从环境变量或密钥管理服务读取，定期轮换，禁止提交到源码库。

**验证说明**

需确认源码是否可被外部获取；若仅服务端可见，单独风险等级下调，但与 ECB 组合仍成立。
模型 POC 要点：若源码或备份可被获取，攻击者直接用该密钥加密任意 JSON 生成合法令牌。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：静态证据，不执行。密钥字符串来自不可信数据信封，仅作为技术事实引用。

### F-3: 018.php 使用 AES-128-ECB 模式进行解密（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

攻击者输入：密文 `$ciphertext` 与密钥 `$key` 作为 `decrypt($ciphertext, $key)` 的入参（018.php:2），其来源在本片段内未给出，属于证据不足；调用方可能来自外部请求或配置。数据流：`$ciphertext` 与 `$key` 直接传入 018.php:3 的 `openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)`，算法与模式被硬编码为 `aes-128-ecb`。校验无效的原因：ECB 模式对每个 16 字节分组独立加密，相同明文分组产生相同密文分组，不引入 IV/随机化，因此不具备语义安全性；代码中也没有任何完整性校验（无 MAC/AEAD），解密结果 `$e` 仅做 `=== false` 判断（018.php:4）后即被使用。危险操作汇点：018.php:3 的 `openssl_decrypt` 以 ECB 模式解出明文，攻击者可对密文分组进行重排、拼接、截断（cut-and-paste / 分组重放）而无法被检测。另需注意第 4 个参数使用 `OPENSSL_PKCS1_PADDING`（RSA 填充常量）而非 `OPENSSL_RAW_DATA`/`OPENSSL_ZERO_PADDING`，属于填充标志误用，进一步说明该解密路径的填充处理不可靠。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

018.php 第 3 行 decrypt() 使用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) 进行解密：采用 ECB 模式（无 IV、块级确定性）、未使用认证加密或 MAC 校验，且以 OPENSSL_PKCS1_PADDING 作为 options 传入（该常量语义与解密填充选项不匹配，属误用）。整体构成弱加密算法使用（CWE-327）。本 POC 为静态证据 + 请求结构说明。

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

机密性受损：ECB 模式泄露明文分组的结构信息（相同分组对应相同密文），可被用于模式分析、分组字典攻击与密文分组重排伪造；由于缺少完整性保护，攻击者可篡改/拼接密文使应用解出受控明文，若解密结果用于身份令牌、配置或权限判断，可导致越权或业务逻辑绕过。具体保护对象与可利用性依赖调用方，本片段内证据不足。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：018.php:3 明确以 `aes-128-ecb` 作为解密算法，ECB 为公认不安全的确定性分组模式。外部可达性：`decrypt()` 为普通 PHP 函数，是否由 HTTP 路由调用在本片段内未体现，属证据不足；无需认证这一点同样无法从片段确认。利用链闭合度：算法层根因已确认（硬编码 ECB + 无完整性校验 + 填充常量误用），但「攻击者可控密文 → 解出受控明文 → 影响安全决策」的完整链路缺少调用方代码，故按 llm_inferred 记录，不宣称已闭合。

**修复建议**

1) 改用带认证的加密模式：`openssl_encrypt/openssl_decrypt` 使用 `aes-256-gcm`，并校验 GCM tag（或使用 libsodium `sodium_crypto_secretbox_open`）；2) 若必须用 CBC，则每次加密生成随机 IV 并随密文传输，且对密文附加 HMAC-SHA256 做先验校验（encrypt-then-MAC）；3) 修正第 4 个参数，使用 `OPENSSL_RAW_DATA` 并自行处理/校验 PKCS#7 填充，不要使用 `OPENSSL_PKCS1_PADDING`；4) 密钥从密钥管理服务/环境变量读取，禁止硬编码，并轮换历史 ECB 加密数据；5) 对解密失败统一返回错误，避免填充预言。

**验证说明**

静态证据：入口 POST /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：调用方将密文 `$ciphertext` 与密钥 `$key` 传入 018.php:2 的 `decrypt()`；018.php:3 以硬编码 `aes-128-ecb` 调用 `openssl_decrypt`，无 IV、无 MAC，仅以 `=== false` 判断成败（018.php:4）。攻击者若可控制或截获密文，即可利用 ECB 的分组确定性进行模式分析，并通过分组重排/拼接构造出可被成功解密的受控明文，绕过应用对解密结果的信任。调用方与外部入口在本片段中缺失，链路末端影响需结合调用方复核。
POC 备注：仅文本工件，不执行、不联网；目标地址统一使用 TARGET。

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
| `hardcoded_secret` | CWE-798 |  | 1 |
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
| safety_guard | 安全防护 | 2.7 | 是 |
| surface_mapper | 攻击面测绘 | 7.16 | 是 |
| deep_finder | LLM 深挖 | 11.62 | 是 |
| candidate_screener | 候选筛选 | 4.87 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.96 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.65 | 是 |
| coordinator | 管线协调 | 6.52 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
