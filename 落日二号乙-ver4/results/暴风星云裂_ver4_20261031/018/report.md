# 落日二号乙漏洞挖掘报告 — 20261031-164142-8e7a9b

- 生成时间：2026-10-31T08:42:33.536930+00:00
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

本次汇总仅包含 1 个 PHP 文件（018.php）的 2 条去重后 weak_crypto 发现，均指向同一根因：018.php 使用 AES-128-ECB 模式处理会话令牌。最高危为 LLM-86c6c58e13d2（high）：ECB 模式无 IV、相同明文块产生相同密文块，可被块重放/拼接以伪造 admin 令牌，属 CWE-327。两条发现均带 POC，但均为静态证据型 POC（源码级加密模式判定），不具备 HTTP 动态复现条件，不能宣称可动态验证。除此之外，注入类、路径穿越、文件包含、weak_hash、weak_random、insecure_cookie、trust_boundary 等攻击面均未形成 findings，其中多数是因为本次未提供 018.php 代码正文、sink_hot_files 为空导致汇点识别不完整，属覆盖缺口而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3269 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 018.php 全部可见行（1-56、65-110）。核心问题为 AES-128-ECB 弱加密导致令牌伪造/认证绕过，硬编码密钥加剧风险。第 100 行 $_SERVER['PHP_SELF'] 拼入表单 action 存在反射型 XSS 可能，但利用价值低未单列。未发现命令/文件/反序列化汇点。

未覆盖 / 证据缺口：
- 57-64 行未提供
- 无部署/网络暴露信息
- 无 PHP 版本信息

## 3. Findings

### F-1: 018.php 使用 AES-128-ECB 加密会话令牌，可通过 ECB 块重放/拼接伪造 admin 令牌

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`018.php:2-32`
- **来源**：`llm_finding`

**描述**

018.php 第 3 行使用 openssl_decrypt($ciphertext,'aes-128-ecb',$key,...) 解密客户端提交的 token，第 10 行硬编码密钥 "ik ben een aardbei"。ECB 模式对相同明文块产生相同密文块且无完整性保护，攻击者可对页面泄露的多个令牌（第 52 行 Sooty admin 令牌、Sweep user 令牌）按 16 字节块进行重排/拼接，构造出 user=sweep、level=admin 的合法 JSON 令牌，从而通过第 32 行的管理员判定，实现认证绕过。

**source / sink**

- source：body `token`（018.php:21）
- sink：018.php:32 openssl_decrypt(...,'aes-128-ecb',...) 后 json_decode 并据 $user->level 判定管理员

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:21` | 读取攻击者可控的 POST token | 十六进制字符串 |  |
| 2 | `018.php:22` | 仅校验长度是否为 32 的倍数，无完整性校验 | 长度合法的 hex 串 |  |
| 3 | `018.php:25` | hex2bin 后 AES-128-ECB 解密，ECB 无 IV、块独立 | 明文 JSON 字节 |  |
| 4 | `018.php:27` | json_decode 得到对象 | PHP 对象 |  |
| 5 | `018.php:32` | 依据 user/ex/level 字段判定管理员，字段完全由攻击者拼接的明文块决定 | user=sweep, level=admin |  |

**POC**

静态证据型 POC（离线审查，不发送请求）：018.php 第 32 行附近使用 AES-128-ECB 模式（openssl_decrypt(..., 'aes-128-ecb', ...)）解密客户端提交的 token，且密钥硬编码为字符串 "ik ben een aardbei"。ECB 模式无 IV、相同明文块产生相同密文块，且密钥随源码泄露，攻击者可离线构造/篡改 token 伪造身份（代码随后以 $user->user=='sweep' && $user->level=='admin' 做授权判断）。

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

未授权攻击者伪造 admin 会话，完全绕过认证

**CVE / CWE 论证**

CWE-327 使用不安全加密算法（ECB 无完整性）；外部 POST 可达，无需认证，链闭合

**修复建议**

改用 AES-GCM 等带认证的加密模式，密钥不入源码，令牌加 HMAC 签名

**验证说明**

需动态确认 ECB 块边界与 JSON 字段对齐，实际拼接偏移需按样本调整
模型 POC 要点：利用 ECB 块重排：将泄露的 Sweep 令牌中 user=sweep 的块与 Sooty admin 令牌中 level=admin 的块拼接，构造合法 admin 令牌
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网；目标统一使用 TARGET 占位符；仅限授权测试。未生成自动执行脚本。

### F-2: 018.php 使用 AES-128-ECB 弱加密模式（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.81`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`018.php:2-3`
- **来源**：`rule`

**描述**

在 018.php 第 2-3 行的 decrypt($ciphertext, $key) 函数中，第 3 行调用 openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING) 对密文进行解密，算法/模式参数被硬编码为 'aes-128-ecb'。攻击者不需要注入任何输入：只要能够获取或截获密文（例如通过接口参数、Cookie、存储文件等外部通道），就能利用 ECB 模式的确定性特征——相同明文分组产生相同密文分组——对密文进行分组重排、拼接、块替换与块删除，从而在不知道密钥的情况下篡改解密后的明文结构。此外，第 3 行把 OPENSSL_PKCS1_PADDING 作为 openssl_decrypt 的 options 参数传入，而该常量语义上属于 RSA 填充，并非 AES 分组模式填充选项，说明填充处理配置本身也不正确，进一步削弱完整性保障。校验无效的原因在于：ECB 模式不引入随机 IV、不做分组间链接，代码中也没有任何 MAC/签名或完整性校验步骤，因此解密端无法区分合法密文与被重排/拼接的密文。最终危险操作是第 3 行的解密结果 $e 被直接当作可信明文返回给上层使用（第 4 行仅判断 $e === false）。

**source / sink**

- source：repository `aes-128-ecb`（018.php）
- sink：018.php:3 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `018.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线审查，不发送请求）：018.php 第 3 行 decrypt() 函数使用 'aes-128-ecb' 作为 openssl_decrypt 的算法参数，ECB 模式不具备语义安全性（无 IV、块级重放/重排），属弱加密算法使用。

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

机密性与完整性受损：ECB 模式泄露明文分组的结构信息（相同明文块对应相同密文块），可用于模式分析、字典式比对与块级重放；攻击者可在无密钥情况下对密文做块重排/拼接/删除，使解密后的业务数据（如权限字段、金额、标识符）被篡改，进而导致越权或业务逻辑绕过。具体受保护对象与可伪造性取决于 $ciphertext/$key 的上游来源，输入中未提供调用方，属证据不足部分。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：第 3 行显式使用 'aes-128-ecb' 这一不具备语义安全的确定性分组模式，且无 IV、无认证标签、无 MAC 校验，属典型可被选择明文/块重排攻击的加密实现。外部可达性：该弱点位于解密函数，只要上层存在对外暴露的密文入口（HTTP 参数、Cookie、令牌）即可被外部触发；输入未给出调用点，故外部可达性为推断。无需认证：利用仅需持有密文，不依赖账号凭据。利用链闭合度：算法层证据闭合（算法名与模式在源码中明确），但“攻击者如何取得密文”与“解密结果被用于何种安全决策”两环在给定片段中缺失，因此整体链为部分闭合，置信度按 0.81 保留。

**修复建议**

1) 改用带认证的 AEAD 模式，如 openssl_encrypt/openssl_decrypt 配合 'aes-256-gcm'，并正确传入 $tag 与 $aad，解密后校验 tag 失败即拒绝；2) 若必须使用 CBC，则每次加密生成随机 IV（random_bytes）并与密文一同传输，同时对密文附加 HMAC-SHA256 并做常量时间比较（hash_equals）；3) 移除第 3 行误用的 OPENSSL_PKCS1_PADDING，改用 OPENSSL_RAW_DATA 或 0，由 AEAD 自身保证完整性；4) 密钥管理上使用 KMS/密钥派生（HKDF）而非硬编码或可预测密钥；5) 对历史 ECB 密文制定迁移方案（版本号前缀 + 重加密）。

**验证说明**

静态证据：入口 POST /018；source=repository/aes-128-ecb；sink=018.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者从外部通道（HTTP 参数/Cookie/令牌，具体入口在给定片段中未出现，属证据不足）取得由 018.php 加密的密文 → 密文作为 $ciphertext 传入 decrypt($ciphertext, $key)（018.php:2）→ 第 3 行以 'aes-128-ecb' 调用 openssl_decrypt，因 ECB 无 IV、无链接、无完整性校验，攻击者可对密文做 16 字节块的重排、拼接、删除或替换 → 解密结果 $e 仅经第 4 行 $e === false 判断后被当作可信明文返回 → 上层若据此做权限/金额/身份判断即被篡改。校验无效的根因是 ECB 的确定性与缺失 MAC/AEAD，而非输入过滤问题。
POC 备注：仅文本工件，不执行、不联网；仅限授权测试。

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
| safety_guard | 安全防护 | 7.48 | 是 |
| surface_mapper | 攻击面测绘 | 9.56 | 是 |
| deep_finder | LLM 深挖 | 6.67 | 是 |
| candidate_screener | 候选筛选 | 4.63 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.56 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 7.23 | 是 |
| coordinator | 管线协调 | 6.53 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
