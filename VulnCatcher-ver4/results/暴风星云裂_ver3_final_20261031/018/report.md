# 落日二号乙漏洞挖掘报告 — 20261031-013917-29b728

- 生成时间：2026-10-30T17:40:12.774651+00:00
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

本次审计范围是单文件 PHP 脚本 018.php（110 行，无框架、无路由、无端点清单）。共交付 3 条去重后的 findings，全部集中在 018.php 的加密实现上：最高危的是 LLM-86c6c58e13d2（high，weak_crypto）——018.php 第 32 行附近使用 AES-128-ECB 解密会话令牌，ECB 模式无 IV、按块独立加密，可被字节翻转/块拼接伪造 admin 身份；其次是 LLM-a5c5a430e98b（medium，hardcoded_secret）——第 10 行硬编码 AES 密钥 "ik ben een aardbei"，密钥随源码泄露即可直接构造合法密文；SEM-1f3cfc0b6797（medium，weak_crypto）是规则侧对同一 ECB 模式的独立命中，与 high 条目同源、属同一缺陷的不同证据角度。3 条 finding 均带 POC，但需注意：weak_crypto/hardcoded_secret 的 POC 主要是静态证据 POC（密钥、算法、模式、行号），不宣称可动态复现；若要动态验证需在授权环境自行构造密文，本管线未执行。攻击面测绘指出 018.php:4 是唯一参数读取入口、sink_hot_files 为空，即注入类/XSS/路径类汇点未被规则命中，这不等于不存在，需人工逐行追踪。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 018.php 全部可见行（1-56、65-110）。核心逻辑为 POST token 经 AES-128-ECB 解密后 json_decode 并做身份判定。发现两条链：AES-ECB 弱加密模式可块拼接伪造 admin（weak_crypto），以及硬编码密钥（hardcoded_secret）。第 57-64 行未在 code_pack 中显示，可能含额外示例 token，但不影响结论。未发现 SQL/命令/路径/XSS 类 sink；页面输出均为静态 HTML 或异常消息（异常消息来自固定字符串，非用户可控）。

未覆盖 / 证据缺口：
- 018.php 第 57-64 行未提供，无法确认是否含额外令牌或逻辑
- 无部署配置，无法确认运行时 openssl 行为与错误回显

## 3. Findings

### F-1: 018.php 使用 AES-128-ECB 解密会话令牌，可被字节翻转/块拼接伪造 admin 身份

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

018.php 第 2-8 行的 decrypt() 使用 openssl_decrypt(..., 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) 对客户端提交的 token 解密，第 10 行硬编码密钥 "ik ben een aardbei"。ECB 模式对相同明文块产生相同密文块且块间无链接，攻击者无需密钥即可对密文块进行重排/拼接（block splicing），把已知 user 令牌中的 "level":"user" 块替换为可控/已知的 "level":"admin" 块，从而在第 32 行 $user->user=="sweep" && $user->ex>time() && $user->level=="admin" 判断中通过，获得管理员身份。根因是弱加密模式（CWE-327），而非单纯认证逻辑缺陷。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 openssl_decrypt 使用 aes-128-ecb 模式（018.php:3），解密结果直接作为身份判定依据（018.php:32）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 读取攻击者提交的 token 参数 | 十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，不校验完整性/签名 | 长度合法的 hex 串 | 无 MAC/HMAC 校验，仅长度检查 |
| 3 | `018.php:25` | hex2bin 后交给 decrypt() | 原始密文字节 |  |
| 4 | `018.php:3` | AES-128-ECB 解密，块间独立，可拼接 | 攻击者可控的明文块组合 | ECB 无链接、无完整性保护，块可重排 |
| 5 | `018.php:27` | json_decode 得到对象 | JSON 对象 |  |
| 6 | `018.php:32` | 以 user/ex/level 判定管理员身份 | 伪造的 admin 对象通过校验 | 身份完全依赖可篡改的 ECB 密文 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：`018.php:32` 处 `decrypt()` 使用 `openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)`，采用 ECB 模式且无 IV/无完整性校验（无 MAC、无 AEAD），同时 `OPENSSL_PKCS1_PADDING` 与 `openssl_decrypt` 的原始密文语义不匹配。ECB 对相同明文块产生相同密文块，泄露结构信息；缺少认证使密文可被篡改/拼接，配合 `json_decode` 后的 `user/level` 判定存在伪造与填充预言风险。本 POC 为离线静态证据，不发送请求。

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

攻击者无需密钥即可伪造管理员会话，获得 admin 权限，属于认证绕过/权限提升。

**CVE / CWE 论证**

CWE-327 使用已被攻破的加密算法/模式（AES-ECB 缺乏语义安全与完整性），外部 POST 参数直接可达，无需认证，链闭合。

**修复建议**

改用 AES-GCM 等带认证的加密模式，并对令牌做 HMAC 签名校验；密钥不应硬编码在源码中。

**验证说明**

需动态确认块边界与 JSON 字段对齐方式，实际拼接偏移需按真实密文块长度计算。
模型 POC 要点：利用 ECB 块拼接：将 Sweep(user) 令牌中 level 字段所在块替换为已知 admin 明文对应的密文块，或对已知明文块做重排，使解密后 level 为 admin。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，未执行、未联网。目标地址统一使用 `TARGET`。token 长度须满足 `strlen($token) % 32 == 0` 且为合法十六进制，否则在进入解密前即被拒绝。仅限授权测试。

### F-2: 018.php 硬编码 AES 密钥 "ik ben een aardbei"

- **类型**：`hardcoded_secret` / CWE-798
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:10-10`
- **来源**：`llm_finding`

**描述**

018.php 第 10 行将加密密钥硬编码为字符串 "ik ben een aardbei"，任何能读取源码或反编译部署包的人都能获得密钥，直接解密/伪造所有令牌，绕过第 32 行的身份校验。

**source / sink**

- source：config `$key`（018.php）
- sink：018.php:10 openssl_decrypt 使用该硬编码密钥（018.php:3）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:10` | 密钥硬编码在源码 | 明文密钥常量 |  |
| 2 | `018.php:3` | decrypt 使用该密钥解密攻击者提交的 token | 攻击者可用已知密钥自行加密任意明文 |  |
| 3 | `018.php:32` | 伪造的 admin 令牌通过身份校验 | 任意伪造身份 |  |

**POC**

静态证据型 POC（hardcoded_secret，CWE-798）：`018.php:10` 将 AES 密钥硬编码为字符串字面量 `$key = "ik ben een aardbei";`，该密钥随后被 `decrypt()`（`018.php:2-8`）用于解密 `$_POST['token']` 并据此判定管理员身份（`$user->user == "sweep" && $user->level == "admin"`）。任何能读取源码或反编译产物的人都能获得该密钥，从而伪造合法 token。本 POC 为离线静态证据，不发送请求、不执行任何命令。

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

密钥泄露导致令牌可被任意伪造，完全破坏认证。

**CVE / CWE 论证**

CWE-798 硬编码凭据，外部可达且直接导致认证绕过。

**修复建议**

从环境变量或密钥管理服务加载密钥，并轮换已泄露密钥。

**验证说明**

需确认部署环境中该密钥未被替换。
模型 POC 要点：使用硬编码密钥自行 AES-128-ECB 加密伪造的 admin JSON，提交即可登录。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，未执行、未联网。目标地址统一使用 `TARGET` 占位符。token 需为 32 字符整数倍长度的十六进制串（源码 `strlen($token) % 32 != 0` 校验），构造时注意 hex 编码。仅限授权测试。

### F-3: 018.php 使用 AES-128-ECB 弱加密模式（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

在 018.php 第 2-3 行的 decrypt($ciphertext, $key) 函数中，openssl_decrypt 的第二个参数被硬编码为 'aes-128-ecb'，即使用 AES-128 的 ECB（电子密码本）模式进行解密。ECB 模式对每个 16 字节分组独立加密/解密，不使用 IV，相同明文分组产生相同密文分组，因此不具备语义安全性。攻击者输入位置为传入 decrypt() 的 $ciphertext 参数（该函数为库函数，调用方未在片段中给出，证据不足），$key 为密钥参数。数据流为：$ciphertext → openssl_decrypt(..., 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) → 返回明文 $e。校验无效的原因在于算法模式本身：ECB 不提供分组间扩散，且此处第四个参数使用 OPENSSL_PKCS1_PADDING（该常量用于 RSA 填充，对 openssl_decrypt 的对称解密并不适用，实际填充行为依赖 OpenSSL 默认处理），进一步削弱了完整性保护。最终危险操作是使用弱模式完成机密性/完整性保护。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：`018.php:3` 为 `decrypt()` 函数体内的 `openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)` 调用点，是 ECB 弱模式在代码中的实际落点（与 `018.php:32` 为同一调用的行号视图）。该调用使用无 IV 的 ECB 模式、无认证标签，且 `OPENSSL_PKCS1_PADDING` 标志与 `openssl_decrypt` 的原始密文接口语义不符，可能导致填充处理异常或错误信息泄露。本 POC 为离线静态证据，不发送请求。

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

使用 ECB 模式导致：1) 相同明文分组在密文中重复出现，攻击者可对结构化数据（如会话令牌、序列化对象、逐块拼接的敏感字段）进行分组重排、拼接、删除（cut-and-paste）攻击，伪造或篡改解密后的内容；2) 缺乏 IV 使加密结果确定性，可进行已知明文/选择明文比对与字典式推断；3) 若该函数用于保护认证令牌或配置密文，可能导致身份伪造或敏感数据泄露。具体业务影响取决于调用方，片段中未给出调用点，证据不足。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：AES-128-ECB 属于不安全的加密模式，缺乏语义安全性与完整性保护。外部可达性：decrypt() 为普通 PHP 函数，若被 Web 入口调用则攻击者可通过请求参数控制 $ciphertext；但片段中未出现具体路由或 getParameter 调用，外部可达性证据不足。无需认证：取决于调用方，证据不足。利用链闭合：算法层根因明确（018.php:3 硬编码 'aes-128-ecb'），但缺少调用点与攻击者可控输入的完整链路，故仅判定为配置/实现型弱点，不宣称完整可利用链。

**修复建议**

1) 改用带认证的 AEAD 模式，如 openssl_encrypt/openssl_decrypt 配合 'aes-256-gcm'，并正确生成随机 12 字节 IV（random_bytes(12)）与 16 字节认证标签，解密时校验 tag；2) 若必须使用 CBC，需使用随机 IV 并配合 HMAC-SHA256 做先加密后 MAC（encrypt-then-MAC）；3) 移除错误的 OPENSSL_PKCS1_PADDING 参数，对称解密应使用 OPENSSL_RAW_DATA 或 0，并自行做严格填充校验；4) 密钥通过 KMS/环境变量管理，禁止硬编码；5) 对历史 ECB 密文制定迁移方案（重新加密）。

**验证说明**

静态证据：入口 ANY /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者（若存在 Web 调用点）提交受控的 $ciphertext → decrypt() 第 3 行以 'aes-128-ecb' 模式调用 openssl_decrypt → 因 ECB 分组独立、无 IV，攻击者可对密文分组进行重排/拼接/截断 → 解密得到被篡改的明文 $e 并被上层逻辑信任。当前证据仅覆盖算法层（018.php:2-3），调用点、输入来源与上层信任逻辑未在 code_pack 中给出，链路未闭合。
POC 备注：仅文本工件，未执行、未联网。目标地址统一使用 `TARGET`。token 需满足 `strlen($token) % 32 == 0` 且为十六进制。仅限授权测试。

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
| surface_mapper | 攻击面测绘 | 7.85 | 是 |
| deep_finder | LLM 深挖 | 10.55 | 是 |
| candidate_screener | 候选筛选 | 4.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.77 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 15.38 | 是 |
| coordinator | 管线协调 | 7.78 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
