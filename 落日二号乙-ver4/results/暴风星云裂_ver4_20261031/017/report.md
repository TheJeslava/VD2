# 落日二号乙漏洞挖掘报告 — 20261031-164138-27b16a

- 生成时间：2026-10-31T08:42:18.270149+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\017.zip`
- 输入模式：`zip`
- SHA256：`22eb1c366ca6de367dfb32771c8d253b8bddb6e1e510d5d40c62a409823cb0bf`
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

本次汇总仅含 1 条已去重 finding：017.php 中 xor_this() 以 XOR 作为加密原语（weak_crypto / CWE-327，medium，origin=rule），已附带 POC，但该 POC 属静态证据型（算法/实现层面），不具备 HTTP 动态复现语义，不能宣称可动态验证。最高危项即此条 medium 弱加密实现问题。POC 齐全度：1/1 有 POC，但均为静态 POC。攻击面测绘指出 017.php 同时存在 source 热点（约第 9 行）与 sink 热点（约第 1 行），可能构成注入/文件操作类风险，但该方向没有任何 finding 覆盖，且输入未提供代码文本，只能作为人工复核项，不得视为已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 017.php 的第 1-74 行（共 112 行，truncated=false 但 shown_ranges 只到 74，第 75-112 行未送入）。已审计的攻击面：xor_this() 自定义 XOR 加解密函数（第 3-14 行）、硬编码密钥 $key="wachtwoord"（第 16 行）、POST 参数 message（第 28-37 行）与 password（第 38-46 行）的读取与处理、登录判断 $password == "Olifant"（第 41 行）、以及 HTML 输出拼接（第 52-74 行）。<br><br>未形成可申报 finding 的原因：<br>1) 第 59 行 $message 回显前经过 htmlentities() 编码，第 56 行 $_SERVER['PHP_SELF'] 在标准 PHP 部署下由 SAPI 规范化，未见到可闭合的反射型 XSS 链；<br>2) 第 31/35/40 行的 base64_decode/xor_this 仅做字符串变换，未进入 exec/system/include/fopen/SQL 等危险汇点，code_pack 可见范围内不存在命令执行、SQL 注入、路径穿越、文件包含、反序列化或 SSRF 的 sink；<br>3) 第 41 行登录比较使用明文常量 "Olifant"，属于硬编码凭据/弱认证设计，但这是该脚本自身的演示性登录逻辑，缺少认证后敏感操作与权限边界证据，单独不足以构成 CVE 级认证绕过；<br>4) 第 16 行硬编码 XOR 密钥与第 3-14 行 XOR 加密属于弱加密实现（CWE-327/硬编码密钥），但仅用于消息编解码演示，未保护会话、凭据或业务数据，未形成实际利用链，按规则只作为线索记录，不单独立 finding；<br>5) 第 40 行 $decoded 计算后未被使用，属死代码，无安全影响。<br><br>未闭合线索：第 75-112 行未送入，可能包含 $encoded 的输出回显（第 71-74 行已开始拼接 "<label for='encoded'>Message:" 段落），若后续对 $encoded（即 base64_decode($_POST['message']) 经 XOR 后的原始字节）未做 htmlentities 直接回显，则存在反射型 XSS 的可能；但该段代码不在 code_pack 内，按零工具契约不得推断，故不报告。建议后续将 017.php 第 75-112 行补入 code_pack 后复审该回显点。<br><br>未覆盖范围：无 php.ini/.htaccess/Web 服务器配置、无 composer 依赖、无路由与认证前置信息、无部署与 PHP 版本信息，因

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未送入 code_pack，$encoded 的最终输出回显点无法确认是否编码
- 无 php.ini / .htaccess / 反向代理配置，无法确认 PHP_SELF 规范化与安全开关
- 无依赖清单与部署信息，无法评估第三方组件与运行环境风险
- 无认证/会话机制证据，硬编码口令 "Olifant" 与 XOR 密钥的实际业务影响无法闭合

## 3. Findings

### F-1: 017.php 中 xor_this() 使用 XOR 作为加密原语（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

证据仅覆盖 017.php 第 2-4 行：第 3 行定义了 `function xor_this($cleartext, $key)`，第 4 行是注释 `// Our output text`。该函数以调用方提供的 `$key` 对 `$cleartext` 做逐字节 XOR 变换，属于自制的流式异或“加密”。XOR 本身不是分组/流密码算法，不具备密钥扩展、IV/nonce、完整性校验，密钥重用下可被已知明文直接恢复密钥流（C1⊕C2 = P1⊕P2），因此不满足 CWE-327 所要求的密码学强度。攻击者输入面：任何调用 xor_this() 的上层入口（HTTP 参数、Cookie、配置文件值）传入的 `$cleartext` 与 `$key`；由于 code_pack 只给出第 2-4 行，调用点、密钥来源、保护对象（口令/令牌/配置密文）均无法确认，属于证据缺口。校验无效的原因：函数体内没有任何密钥管理、随机化或认证逻辑，XOR 的可逆性与线性使其在密钥复用或已知明文场景下不提供机密性。最终危险操作：将 XOR 结果当作“密文”输出/存储（第 4 行注释所指的 output text），使受保护数据可被离线还原。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 `017.php:3` 处定义了一个自定义 XOR 加密函数 `xor_this($cleartext, $key)`，该函数使用重复密钥 XOR 作为“加密”手段。XOR 属于可逆的弱混淆算法，不提供机密性保障（已知明文即可恢复密钥流，密钥复用可被频率分析/ crib-dragging 破解），属于 CWE-327 弱加密算法使用。本 POC 为离线源码审查证据，不发送任何请求。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 017.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-2e4335a5c995`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

机密性丧失：若 xor_this() 用于保护凭据、会话令牌或配置中的敏感值，攻击者获取到密文后可通过已知明文攻击或密钥重用直接还原明文，进而冒用身份或读取受保护数据。由于缺少调用点证据，具体受影响数据对象（口令/令牌/配置文件）证据不足，不能断言 RCE 或越权。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）。外部可达性：取决于 xor_this() 的调用方，code_pack 未提供调用点，证据不足；无需认证的前提同样无法从第 2-4 行确认。利用链闭合度：仅闭合到“弱算法原语存在”这一环，缺少 source（外部输入入口）与受保护资产两环，故按 llm_inferred 记录，不主张完整可利用链。

**修复建议**

1) 废弃 xor_this()，改用 libsodium（PHP 的 sodium_crypto_secretbox / sodium_crypto_aead_xchacha20poly1305_ietf_encrypt）或 OpenSSL 的 AES-256-GCM，提供机密性与完整性；2) 每次加密使用 CSPRNG 生成随机 nonce/IV（random_bytes()），并与密文一同存储；3) 密钥由 KMS/密钥库管理，禁止硬编码或从用户输入取 `$key`；4) 若历史数据已用 XOR 加密，制定一次性重加密迁移方案并轮换密钥；5) 对存量密文做密钥复用检测。

**验证说明**

静态证据：入口 POST /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：调用方（未在 code_pack 中给出）将 `$cleartext` 与 `$key` 传入 017.php:3 的 xor_this()；函数对二者逐字节 XOR 后作为“密文”返回（017.php:4 注释的 output text）；该输出被上层存储或传输。攻击者获得密文后，利用 XOR 的线性性质与可能的密钥重用/已知明文，离线还原出原始明文，完成对受保护数据的读取。链路在“弱算法原语”处成立，但 source 与资产两环证据不足。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一使用 `TARGET` 占位符；仅限授权测试。证据片段来自不可信数据信封，仅作技术事实提取。

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
| safety_guard | 安全防护 | 3.34 | 是 |
| surface_mapper | 攻击面测绘 | 9.14 | 是 |
| deep_finder | LLM 深挖 | 5.39 | 是 |
| candidate_screener | 候选筛选 | 2.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.16 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.05 | 是 |
| coordinator | 管线协调 | 7.91 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
