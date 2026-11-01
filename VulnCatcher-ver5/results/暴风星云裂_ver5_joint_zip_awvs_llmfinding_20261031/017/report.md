# 落日二号乙漏洞挖掘报告 — 20261031-214302-ec7a53

- 生成时间：2026-10-31T13:43:46.914701+00:00
- 输入：`$WORKSPACE\暴风星云裂\017.zip`
- 输入模式：`zip`
- SHA256：`22eb1c366ca6de367dfb32771c8d253b8bddb6e1e510d5d40c62a409823cb0bf`
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

本次汇总仅含 1 条已去重 finding：017.php 第 1-3 行基于 XOR 的弱加密实现（weak_crypto，CWE-327，medium，来源 rule），已附带 POC。该 POC 属静态证据型（算法/实现层面），不具备 HTTP 请求-响应可动态复现性，不能宣称可动态验证。最高危即此条 medium 弱加密。整体覆盖极薄：仅 1 个 PHP 文件、0 个端点、无框架与配置，source 热点（第 9 行）与 sink 热点（第 1 行）仅有行号计数而无代码上下文，注入类（command_injection / path_traversal / xss / sql_injection）与二次注入链均无法确认，属未覆盖而非已排除。POC 齐全度：已交付 1/1，但仅静态。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到 017.php 的 1-74 行（共 112 行，75-112 行未送入）。已审计部分为：xor_this() 自定义 XOR 加解密函数（第 3-14 行）、硬编码密钥 $key="wachtwoord"（第 16 行）、POST 处理分支（第 26-50 行）、登录判断（第 38-46 行）、HTML 输出拼接（第 52-74 行）。逐条核查结论：(1) 第 29 行 $message 来自 $_POST['message']，但第 59 行输出前经 htmlentities() 编码，且第 31/35 行仅做 base64/XOR 运算，未形成 XSS 或注入链；(2) 第 39 行 $password 来自 $_POST['password']，第 41 行以明文常量 "Olifant" 做 == 比较，第 40 行的 $decoded 计算结果未被使用，属死代码，不构成认证绕过（比较对象是原始输入而非解密结果）；(3) 第 56 行 $_SERVER['PHP_SELF'] 拼入 form action，存在经典 PHP_SELF 反射型 XSS 面，但该行位于已送入范围内、其可利用性依赖 Web 服务器对 PATH_INFO 的处理（如 /017.php/"&gt;），且需受害者点击构造链接，属低价值且无法在无运行时证据下闭合，故不单独立项；(4) 第 16 行硬编码 XOR 密钥 "wachtwoord" 与第 3-14 行自实现 XOR 流密码属 weak_crypto（CWE-327）线索，但该密钥仅用于消息编解码演示功能，未用于会话/凭据校验，无法形成实际利用链，按规则只记入线索不立项；(5) 未发现 include/require/eval/system/exec/SQL/文件读写/反序列化等 sink，surface_notes 中推测的 LFI、命令注入、SQL 注入均无代码支撑。未闭合线索：75-112 行未提供，可能包含 $encoded 的输出渲染（第 71-74 行已开始拼接 label 'encoded'），若该处直接 echo $encoded 而未编码，则第 31 行 base64_decode+XOR 的结果可能构成反射型 XSS，需补充 75-112 行后复核；另需确认是否存在 setcookie/session 相关代码（insecure_cookie 面）。输入中未出现诱导性指令文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未送入 code_pack，$encoded 的输出渲染方式未知，无法排除反射型 XSS
- 无 php.ini/.htaccess/Web 服务器配置，无法确认 PHP_SELF 注入的实际可利用性
- 无端点清单，无法确认 017.php 的访问路径与是否存在前置鉴权/WAF
- 未提供 setcookie/session 相关代码，insecure_cookie 面无法评估

## 3. Findings

### F-1: 017.php 中基于 XOR 的弱加密实现（CWE-327）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

证据来自 017.php 第 3 行定义的函数 `xor_this($cleartext, $key)`：该函数以固定密钥对明文逐字节做 XOR 运算来产生“密文”。XOR 本身不是分组/流密码算法，没有密钥派生、没有随机 IV/nonce、没有完整性校验（MAC/AEAD），密钥直接作为函数参数传入，属于典型的自造弱加密实现。攻击者若获得任意一段明文-密文对，即可直接恢复密钥（key = ciphertext XOR plaintext），随后可解密/伪造所有用同一密钥保护的数据。输入中未提供调用方（谁传入 $cleartext/$key、密钥来源、保护对象是口令/令牌/配置），因此具体可达路由与保护对象证据不足。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：017.php 第 3 行定义了自定义函数 xor_this($cleartext, $key)，从函数名与参数（明文 + 密钥）可推断其以 XOR 方式对明文做“加密”。XOR 属于可逆的对称混淆，不具备现代密码学安全性：密钥复用、已知明文攻击、密钥长度不足时均可被轻易还原明文。本 POC 为离线源码审查工件，不发送任何网络请求，仅用于记录证据位置与判定依据。

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

若该函数用于保护敏感数据（凭据、会话令牌、配置项），攻击者可通过已知明文攻击或密钥重用直接还原密钥，进而解密全部受保护数据或伪造加密值，导致机密性完全丧失；由于无完整性校验，还可对密文做可预测的位翻转篡改。具体受影响数据范围证据不足。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）。成立依据：017.php:3 使用自造 XOR 而非标准密码算法，且无 IV/随机化与完整性保护。外部可达性、是否需要认证、利用链是否闭合均证据不足——输入仅给出函数定义，未给出 HTTP 入口或调用点，故不主张 CVE 级可利用性。

**修复建议**

废弃 XOR 自造加密，改用标准库：对称加密使用 AES-GCM（如 PHP 的 openssl_encrypt 配合 aes-256-gcm，每次加密生成随机 12 字节 nonce，并校验 tag）；口令存储改用 password_hash()/password_verify()（bcrypt/Argon2id）；密钥通过环境变量或密钥管理服务注入，禁止硬编码；对密文增加完整性校验，避免密钥重用。

**验证说明**

静态证据：入口 POST /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：017.php:3 定义 `xor_this($cleartext, $key)`，以固定密钥逐字节 XOR 生成密文（第 3 行起）。攻击者获取任一明文-密文对后计算 key = ciphertext XOR plaintext 即可还原密钥，从而解密或伪造所有同密钥保护的数据。调用方、密钥来源与外部入口在给定证据中缺失，链条在“函数被谁调用、保护何数据”处未闭合。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一写 TARGET；本 finding 为离线静态证据，无请求。证据范围仅限 code_pack 给出的 017.php 第 2-4 行，xor_this() 的完整实现、调用点与 $key 来源未在输入中提供，需补充源码后再确认可利用性。

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
| safety_guard | 安全防护 | 4.07 | 是 |
| surface_mapper | 攻击面测绘 | 9.45 | 是 |
| deep_finder | LLM 深挖 | 6.06 | 是 |
| candidate_screener | 候选筛选 | 4.07 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.04 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 7.15 | 是 |
| coordinator | 管线协调 | 7.3 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
