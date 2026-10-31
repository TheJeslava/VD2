# 落日二号乙漏洞挖掘报告 — 20261031-214310-1c79f9

- 生成时间：2026-10-31T13:44:08.319847+00:00
- 输入：`$WORKSPACE\暴风星云裂\018.zip`
- 输入模式：`zip`
- SHA256：`c4b42bf16d7ffb0d67ab50a7b701b39c7724a0451847bcfe91b4606313b9fcfd`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 018.php，类型均为 weak_crypto（CWE-327）。最高危的是 LLM-86c6c58e13d2（high）：018.php 会话令牌使用 AES-128-ECB 且密钥硬编码，ECB 模式无 IV、相同明文块产生相同密文块，配合硬编码密钥可导致令牌被篡改/伪造，进而冒充 admin 身份；规则侧 SEM-1f3cfc0b6797（medium）对同一文件的 AES-128-ECB 解密用法给出独立佐证，二者为同一根因的不同粒度描述。2 条 findings 均带 POC，但均为静态证据型 POC（算法/模式/密钥硬编码），不宣称可动态复现；其中 high 条目的“伪造 admin 身份”属基于源码的推断（llm_inferred），未经动态验证。本次 min_severity=low、suppressed_count=0，无策略抑制项。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已通读 code_pack 中唯一文件 018.php（1-56、65-110 行，中间 57-64 行未展示）。核心问题为 AES-128-ECB + 硬编码密钥导致的令牌伪造（weak_crypto，CWE-327/321），可篡改 level 提权至 admin。未发现命令执行、文件包含、SQL 注入或反射型 XSS 的闭合链：018.php:100 使用 $_SERVER['PHP_SELF'] 拼接表单 action，存在潜在反射型 XSS，但 PHP_SELF 受服务器规范化影响且利用条件依赖部署，证据不足以单独立项，列入 gaps。57-64 行未在 code_pack 中展示，可能含另一示例令牌，未审计。

未覆盖 / 证据缺口：
- 018.php 第 57-64 行未在 code_pack 中展示，未审计
- $_SERVER['PHP_SELF'] 在 018.php:100 的反射型 XSS 可能性未闭合（依赖部署与路径规范化）
- 缺少部署/包含关系与 php.ini 配置，无法确认对外暴露与 allow_url_include 等设置
- 无数据库/依赖清单，未评估第三方组件

## 3. Findings

### F-1: 018.php 会话令牌使用 AES-128-ECB 且硬编码密钥，可被篡改伪造 admin 身份

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

脚本用 openssl_decrypt($ciphertext,'aes-128-ecb',$key,OPENSSL_PKCS1_PADDING) 解密客户端提交的 token，密钥硬编码为 "ik ben een aardbei"（018.php:10）。AES-ECB 无 IV、按 16 字节块独立加密，相同明文块产生相同密文块，攻击者可在不知道密钥的情况下对已捕获的 token 做块级拼接/重排（ECB cut-and-paste），把 "Sweep (user)" 令牌中的 level 字段块替换为 admin 块，构造出 user=sweep、level=admin 的合法令牌，从而通过 018.php:32 的身份判断获得管理员权限。根因是弱加密模式（CWE-327）叠加硬编码密钥（CWE-321），而非单纯认证逻辑缺陷。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 openssl_decrypt(...,'aes-128-ecb',$key,...) 后 json_decode 结果直接用于 018.php:32 的权限判定

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 读取攻击者提交的 token 参数 | 原始十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，不校验完整性/签名 | 长度合法的十六进制串 | 无 MAC/签名校验，任意块对齐密文均被接受 |
| 3 | `018.php:25` | hex2bin 后交给 decrypt，使用硬编码密钥做 AES-128-ECB 解密 | 明文 JSON 字节串 | ECB 模式块独立，可对密文块做拼接重排 |
| 4 | `018.php:27` | json_decode 解析为对象 | $user 对象 |  |
| 5 | `018.php:32` | 比较 user/ex/level 判定管理员身份 | 被篡改的 user=sweep, level=admin | 篡改后的明文满足全部条件 |

**POC**

018.php:32 的 POST 处理读取 $_POST['token']，要求 strlen($token)%32==0，经 hex2bin 后交给 decrypt()（AES-128-ECB，硬编码密钥 $key="ik ben een aardbei"），再 json_decode 并校验 $user->user=='sweep' && $user->ex>time() && $user->level=='admin'。硬编码密钥 + ECB 模式 + 无完整性校验，使攻击者可离线用已知密钥构造任意明文 token 并加密提交，实现认证/权限绕过（CWE-327，兼 CWE-321 硬编码密钥）。

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

攻击者无需密钥即可伪造管理员会话令牌，以 Sweep 管理员身份登录，完全绕过认证。

**CVE / CWE 论证**

CWE-327 使用不安全加密算法（AES-ECB）+ CWE-321 硬编码密钥；外部 POST 可达、无需认证，链闭合。

**修复建议**

改用带完整性保护的 AEAD 模式（如 AES-256-GCM）并对令牌签名；密钥从安全配置/环境变量加载，禁止硬编码；解密后校验 HMAC。

**验证说明**

需确认示例令牌的实际块布局与字段对齐，动态验证 ECB 拼接能否精确命中 level 字段；需确认 ex 字段未过期。
模型 POC 要点：利用 ECB 块级拼接：将 Sweep(user) 令牌中 level 字段所在块替换为 admin 值对应块，保持 user=sweep 与未过期的 ex 块不变，重新十六进制拼接后提交。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：POC 为文本工件，不执行、不联网、不搭建沙箱。密文需攻击者离线自行计算，本管线不生成可自动运行脚本；目标统一写 TARGET。

### F-2: 018.php 使用 AES-128-ECB 模式进行解密（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.81`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

在 018.php 第 2 行定义的 decrypt($ciphertext, $key) 函数中，第 3 行调用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING)。攻击者可控的输入是传入该函数的 $ciphertext（密文）与 $key（密钥）参数，二者经函数参数直接进入 openssl_decrypt 的算法选择参数。算法字符串被硬编码为 'aes-128-ecb'，即 AES 的 ECB（电子密码本）分组模式：每个 16 字节分组独立加密/解密，不使用 IV，相同明文分组产生相同密文分组，且分组可被重排、拼接、删除而不被检测。代码中不存在任何完整性校验（无 MAC/HMAC、无 AEAD），因此校验环节缺失，无法发现密文被篡改或分组被替换。最终危险操作是第 3 行的 openssl_decrypt 以 ECB 模式解出明文，返回值在第 4 行仅做 === false 判断，未做任何认证性验证。此外第 3 行第 4 个参数使用 OPENSSL_PKCS1_PADDING（该常量语义上属于 RSA 填充，用于 openssl_decrypt 的对称解密选项并不正确，实际应使用 OPENSSL_RAW_DATA/OPENSSL_ZERO_PADDING 语义），进一步说明填充处理未按对称加密规范配置。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

018.php:3 的 decrypt() 使用 AES-128-ECB 模式（openssl_decrypt($ciphertext,'aes-128-ecb',$key,OPENSSL_PKCS1_PADDING)）。ECB 为确定性分组模式，相同明文分组产生相同密文分组，不提供语义安全，且无 IV/认证，属弱加密算法使用（CWE-327）。本 POC 为静态证据型，仅记录源码事实，不发送请求。

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

机密性与完整性受损：ECB 模式泄露明文分组的结构信息（相同明文块对应相同密文块），对结构化数据（如令牌、序列化对象、含重复字段的记录）可被进行分组重排/拼接/剪切攻击（cut-and-paste），在无 MAC 的情况下攻击者可构造被篡改但仍能成功解密的密文，导致业务逻辑绕过、伪造解密结果或敏感数据泄露。若该函数用于解密会话令牌、配置密文或用户数据，攻击者可离线分析密文结构并实施重放/拼接。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：AES-ECB 属于不安全的确定性分组模式，缺乏语义安全与完整性保护。外部可达性：decrypt 为普通 PHP 函数，其 $ciphertext/$key 为调用方传入参数，若被 Web 入口（如解密 Cookie、请求参数中的密文）调用即可由远程攻击者控制输入；无需认证即可触发解密路径（具体调用点不在 code_pack 范围内，属证据不足部分）。利用链闭合度：算法选择硬编码为 'aes-128-ecb' 且无 MAC 校验，攻击者控制密文即可直接影响解密结果，链路在函数内部闭合；但“远程可控密文”的入口需结合调用方确认，故按 llm_inferred 记录。

**修复建议**

1) 改用带认证的 AEAD 模式，如 openssl_encrypt/openssl_decrypt 使用 'aes-256-gcm'，并正确传入 12 字节随机 nonce 与 16 字节 tag，解密后校验 tag 失败即拒绝；2) 若必须使用 CBC，则须随机 IV 并对密文计算 HMAC-SHA256 做先验校验（encrypt-then-MAC），比较使用 hash_equals；3) 修正第 3 行第 4 个参数，对称解密应使用 OPENSSL_RAW_DATA（或 OPENSSL_ZERO_PADDING 配合自行填充），不应使用 OPENSSL_PKCS1_PADDING；4) 密钥通过 KMS/环境变量管理，禁止硬编码或由外部直接传入；5) 对历史 ECB 密文做迁移，重新以 AEAD 加密。

**验证说明**

静态证据：入口 POST /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：调用方将攻击者可控的 $ciphertext 与 $key 传入 018.php:2 的 decrypt()；第 3 行以硬编码算法 'aes-128-ecb' 调用 openssl_decrypt，ECB 模式逐分组独立解密且无 IV、无 MAC；由于缺少完整性校验，攻击者可对密文分组进行重排/拼接/剪切，构造出可被成功解密但内容被篡改的明文；第 4 行仅判断返回值是否为 false，不校验来源真实性，篡改后的明文被当作合法结果返回给上层业务，形成“密文可控→ECB 解密→无认证→业务使用被篡改明文”的链路。
POC 备注：仅文本工件，不执行、不联网。目标地址如需引用统一写 TARGET。

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
| safety_guard | 安全防护 | 4.54 | 是 |
| surface_mapper | 攻击面测绘 | 10.98 | 是 |
| deep_finder | LLM 深挖 | 9.62 | 是 |
| candidate_screener | 候选筛选 | 5.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.79 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 9.65 | 是 |
| coordinator | 管线协调 | 8.35 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
