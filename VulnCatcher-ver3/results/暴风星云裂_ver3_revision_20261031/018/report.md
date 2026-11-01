# 落日二号乙漏洞挖掘报告 — 20261031-011653-2433e3

- 生成时间：2026-10-30T17:17:42.822160+00:00
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

本次汇总基于单文件 PHP 应用 018.php（110 行）的源码审计，共去重后交付 2 条 weak_crypto 发现，均带 POC。最高危为 LLM-86c6c58e13d2（high）：018.php 第 32 行附近使用 AES-128-ECB 加密会话令牌且密钥硬编码，ECB 模式无 IV、相同明文块产生相同密文块，可被块拼接/字节翻转伪造 admin 令牌，属 CWE-327；规则侧 SEM-1f3cfc0b6797（medium）为同一文件第 3 行的 AES-128-ECB 解密用法，属同一根因的规则命中，二者应合并处置。两条 POC 均为静态证据型（算法/模式/硬编码密钥），不宣称可动态复现。攻击面测绘标记 018.php:4 为唯一输入读取点，但 sink 热点为空，注入/XSS/路径穿越/命令执行等污点类风险未形成 finding，需人工沿第 4 行变量做数据流追踪。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 018.php（110 行，code_pack 覆盖 1-56 与 65-110 行，57-64 行未展示）。核心发现：decrypt() 使用 AES-128-ECB 且硬编码密钥，$_POST['token'] 解密结果直接作为身份/权限判据，构成弱加密导致的认证绕过（CWE-327/CWE-321），链闭合。其余攻击面：第 100 行 $_SERVER['PHP_SELF'] 拼入表单 action，存在反射型 XSS 可能，但需确认部署环境与是否编码，证据不足以单独成链，未单独立项；未发现 system/exec/eval、SQL、文件操作、SSRF 等汇点；无 setcookie/session 相关代码。57-64 行（Sooty 令牌与说明）未在 code_pack 中展示，可能含额外令牌但属数据非漏洞。

未覆盖 / 证据缺口：
- 018.php 第 57-64 行未在 code_pack 中展示
- 无部署配置/php.ini，无法确认 PHP_SELF 反射 XSS 的实际可利用性
- 无路由与认证元数据，无法确认脚本对外暴露路径

## 3. Findings

### F-1: 018.php 会话令牌使用 AES-128-ECB 且硬编码密钥，可被 ECB 字节翻转/块拼接伪造 admin 令牌

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

018.php 第 2-8 行的 decrypt() 使用 openssl_decrypt(..., 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)，第 10 行硬编码密钥 $key = "ik ben een aardbei"。第 21-32 行把用户提交的 $_POST['token'] 十六进制解码后直接解密，并把解密出的 JSON 的 user/ex/level 字段作为唯一身份与权限判据（$user->user == "sweep" && $user->ex > time() && $user->level == "admin"）。ECB 模式对相同明文块产生相同密文块，且各块独立解密，攻击者无需密钥即可对已知明文结构的令牌做块重排/拼接（cut-and-paste），把 "level":"user" 所在块替换为构造出的 "level":"admin" 块，从而伪造管理员会话。根因是弱加密模式（CWE-327）与硬编码密钥（CWE-321），最终导致认证绕过。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) 解密结果直接作为身份/权限判据（018.php:3 与 018.php:32）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 从 $_POST['token'] 读取攻击者可控的十六进制令牌字符串 | 原始十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，不校验完整性/签名 | 长度合法的十六进制串 | 无 MAC/HMAC 校验，任何 16 字节对齐的密文都被接受 |
| 3 | `018.php:25` | hex2bin 解码后交给 decrypt() | 二进制密文 |  |
| 4 | `018.php:3` | AES-128-ECB 解密，各 16 字节块独立，相同明文块产生相同密文块 | 明文 JSON 字节流 | ECB 无扩散，可对块做重排/拼接而不破坏其它块 |
| 5 | `018.php:27` | json_decode 解析为对象 | JSON 对象 $user |  |
| 6 | `018.php:32` | 以 $user->user/$user->ex/$user->level 作为唯一鉴权判据，伪造 level=admin 即通过 | 伪造的 admin 身份 | 身份完全来自可篡改的 ECB 密文，无服务端会话校验 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：018.php 使用 AES-128-ECB 模式解密客户端提交的 token，且密钥硬编码为字符串 "ik ben een aardbei"（第 32 行附近）。ECB 模式无 IV、相同明文块产生相同密文块，且密钥随源码泄露，攻击者可离线构造任意明文（如 {"user":"sweep","ex":<未来时间戳>,"level":"admin"}）的密文并 hex 编码后作为 token 提交，从而伪造管理员身份。本 POC 为文本工件，不执行、不联网。

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

攻击者无需密钥即可伪造 Sweep 的 admin 会话，实现认证绕过与权限提升，访问管理员功能。

**CVE / CWE 论证**

CWE-327（使用已被攻破/不安全的加密算法，ECB 模式）+ CWE-321（硬编码密钥）。外部 POST 参数直接进入解密并作为唯一鉴权依据，链闭合，无需认证即可触发。

**修复建议**

改用带完整性校验的 AEAD 模式（如 AES-256-GCM）并对令牌做 HMAC 签名；密钥从安全配置/环境变量读取，禁止硬编码；服务端维护会话状态而非完全信任客户端令牌。

**验证说明**

需动态确认 ECB 块偏移与 JSON 字段对齐，实际构造出可解密的 admin 令牌；需确认 PHP 版本与 openssl 扩展行为。
模型 POC 要点：利用 ECB 块独立性与已知明文结构，将 "level":"user" 所在块替换为预先构造的 "level":"admin" 块（或对已知令牌做块级 cut-and-paste），提交伪造令牌获得管理员登录。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱；目标地址统一使用 TARGET；仅限授权测试。生成密文需在本地离线完成，禁止对真实目标自动化爆破。

### F-2: 018.php 使用 AES-128-ECB 模式进行解密（CWE-327 弱加密算法/模式）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

在 018.php 第 2 行定义的 decrypt($ciphertext, $key) 函数中，第 3 行调用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) 对密文进行解密。算法字符串硬编码为 'aes-128-ecb'，即 AES-128 配合 ECB（电子密码本）分组模式。ECB 模式对每个 16 字节分组独立加密/解密，不引入 IV 或链式反馈，相同明文分组在相同密钥下产生相同密文分组，因此会泄露明文分组的结构与重复模式，且不具备语义安全性（IND-CPA）。此外第 3 行把 OPENSSL_PKCS1_PADDING 作为 options 参数传入 openssl_decrypt，该常量属于 RSA 填充语义，与 AES 分组解密并不匹配，说明填充处理配置本身也不严谨。攻击者无需认证即可获得/截获密文（该函数为库函数，调用方未在片段中给出），通过分组重排、分组替换、截断与模式分析即可对受保护数据实施篡改或部分明文推断。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：018.php 第 3 行 decrypt() 函数调用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)，使用 ECB 模式且以 OPENSSL_PKCS1_PADDING 作为 options 参数（该常量用于 RSA 填充，对 openssl_decrypt 的 options 位掩码语义不正确，属误用）。ECB 模式缺乏随机化 IV，相同明文块产生相同密文块，可被块级重放/拼接；结合同文件硬编码密钥可进一步伪造令牌。本 POC 为文本工件，不执行、不联网。

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

机密性受损：ECB 模式使密文保留明文分组级重复特征，攻击者可对结构化数据（如令牌、序列化对象、配置字段）进行模式识别与分组字典比对，推断或还原部分明文；完整性受损：由于 ECB 无认证、无 IV，攻击者可对密文分组进行重排、删除、复制粘贴（cut-and-paste）攻击，在解密端产生可控的明文篡改，进而影响依赖该解密结果的后续业务逻辑（如身份标识、权限字段）。具体业务影响取决于调用方如何使用 decrypt 的返回值，该部分证据不足。

**CVE / CWE 论证**

对应 CWE-327（Use of a Broken or Risky Cryptographic Algorithm）与 CWE-329/CWE-353 相关的 ECB 模式误用。外部可达性：decrypt 为普通 PHP 函数，若被 Web 入口调用则攻击者仅需提供密文即可触发，无需认证；利用链闭合度：算法与模式在第 3 行硬编码，属确定性缺陷，不依赖运行时随机条件。但片段未给出调用方与密文来源，因此“外部可达 + 无需认证”目前为基于代码结构的推断，未做动态验证。

**修复建议**

1) 改用带认证的 AEAD 模式，如 openssl_encrypt/openssl_decrypt 的 'aes-256-gcm'，并显式生成、传输、校验 12 字节随机 nonce 与 16 字节 tag（PHP 7.1+ 使用 $tag 参数）；2) 若必须使用 CBC，则每次加密使用 random_bytes(16) 生成随机 IV 并随密文一同存储，解密时校验 HMAC-SHA256（encrypt-then-MAC）以保证完整性；3) 移除与 AES 不匹配的 OPENSSL_PKCS1_PADDING 选项，改用 OPENSSL_RAW_DATA 并自行做严格填充校验，或直接依赖 GCM；4) 密钥通过 KMS/环境变量管理，禁止硬编码；5) 对历史 ECB 密文制定迁移方案（解密后以新算法重新加密）。

**验证说明**

静态证据：入口 ANY /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者获取或截获由 018.php:3 的 openssl_decrypt 处理的密文（来源未在片段中给出，属证据缺口）→ 密文以 'aes-128-ecb' 模式解密，无 IV、无认证 tag → 攻击者对密文按 16 字节分组进行重排/替换/截断，或利用 ECB 的分组重复特征做模式分析 → 解密端返回被篡改或可被推断的明文 → 调用方若将该明文用于身份、权限或配置判断，则导致越权或数据泄露。校验为何无效：ECB 模式本身不提供任何完整性保护，且代码未在解密后做 MAC/tag 校验，因此篡改不会被发现。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱；目标地址统一使用 TARGET；仅限授权测试。块重排需在本地离线完成。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 9.95 | 是 |
| deep_finder | LLM 深挖 | 9.68 | 是 |
| candidate_screener | 候选筛选 | 4.09 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.58 | 是 |
| coordinator | 管线协调 | 6.73 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
