# 落日二号乙漏洞挖掘报告 — 20261031-013905-70294a

- 生成时间：2026-10-30T17:39:42.807606+00:00
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

本次汇总仅含 1 条已去重 finding：017.php 第 1-3 行的自定义 XOR 加密函数 xor_this 使用可复用密钥流，判定为 weak_crypto（CWE-327），严重度 medium，来源为规则命中，已附带 POC。最高危项即该条 weak_crypto；除此之外没有注入类、路径类或信任边界类 finding 交付。POC 齐全度为 1/1，但该 POC 属静态证据型（算法/实现层面），不具备 HTTP 动态复现语义，不能宣称可动态验证。攻击面测绘指出 017.php 第 9 行存在 source 热点、全文仅 1 处 sink 热点且污点路径极短，但该链路未形成任何交付 finding，属未覆盖区域，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 017.php（code_pack 只提供 1-74 行，共 112 行，75-112 行未送入）。该文件是一个 XOR 编解码小工具：第 26-50 行处理 POST，第 29 行取 $_POST['message']、第 39 行取 $_POST['password']。逐条核对：message 经 xor_this/base64 处理后在第 59 行通过 htmlentities() 输出，XSS 被转义；password 仅与硬编码字符串 "Olifant" 做 == 比较（第 41 行），属于演示性硬编码口令，不构成可申报 CVE 的认证绕过（无会话、无权限提升、无后续敏感操作）；xor_this 为固定密钥 "wachtwoord" 的 XOR 编码（第 3-16 行），是编码而非加密，但本文件内不存在依赖该密钥保护机密或令牌的链路，单独作为 weak_crypto 证据不足；第 56 行 $_SERVER['PHP_SELF'] 拼入 form action，存在经典 PHP_SELF 反射型 XSS 的可能，但输出点位于第 56 行、且 code_pack 未展示 75-112 行是否还有其它输出/包含/文件操作，无法确认是否存在 htmlspecialchars 之外的上下文与可利用条件，证据不足以闭合链，故不报告。未发现命令执行、SQL、文件包含/路径穿越、反序列化、SSRF 等 sink。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未包含在 code_pack 中，无法确认后半部分是否存在文件操作、include、数据库或其它输出汇点
- 无部署配置/路由信息，无法确认该脚本对外暴露路径与访问控制
- 无 PHP 版本与 php.ini 信息，无法评估 register_globals/allow_url_include 相关风险
- 第 56 行 PHP_SELF 反射型 XSS 线索未闭合：缺少完整输出上下文与可利用性证据
- 无外部 DAST/AWVS 证据

## 3. Findings

### F-1: 017.php 自定义 XOR 加密函数 xor_this 使用可复用密钥流（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

证据来自 017.php 第 3 行定义的函数 `xor_this($cleartext, $key)`：该函数以调用方传入的 `$key` 对明文逐字节做 XOR 运算（第 3 行起为函数签名与实现入口，第 4 行注释为输出文本起始）。XOR 属于无扩散、无密钥调度、无完整性校验的对称变换：同一密钥下相同明文位置产生相同密文，密钥重复使用即形成可预测密钥流；攻击者获得任意一段明文-密文对即可直接恢复密钥并解密其余全部密文，且密文可被逐字节篡改而不被检测。此处不存在参数校验问题——弱点在于算法本身的选择，而非输入过滤，因此任何调用方传入的 `$cleartext`/`$key` 都继承该缺陷。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto / CWE-327）：`017.php:3` 定义 `function xor_this($cleartext, $key)`，即使用 XOR 作为加密/混淆原语。XOR 属于可逆的流式异或，不具备现代密码学强度：密钥复用会导致明文可恢复（已知明文攻击 / crib-dragging），且无完整性保护。本 POC 为离线源码审查工件，不发送任何请求，不执行代码。

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

机密性丧失：持有密文与任一已知明文片段（如固定格式头部、已知字段）的攻击者可离线恢复密钥并解密全部受保护数据；完整性丧失：XOR 流密码无 MAC，攻击者可对密文做定向比特翻转以可控地改变解密后的明文内容（例如篡改序列化字段或标志位）。不涉及直接 RCE，但若该函数用于保护凭据、令牌或配置，将导致凭据泄露与身份伪造。

**CVE / CWE 论证**

对应 CWE-327（Use of a Broken or Risky Cryptographic Algorithm）。外部可达性：`xor_this` 为普通 PHP 函数，任何包含 017.php 的脚本均可调用，无需认证即可触发其加密路径；利用链闭合：攻击者只需获取一份密文与对应明文（或已知明文结构）即可恢复密钥，进而解密/伪造其余数据，无需额外前置条件。注意：本项为配置/实现型弱点，不依赖 HTTP 污点链，证据等级为源码推断，未做运行时验证。

**修复建议**

1) 废弃 `xor_this`，改用经审计的 AEAD 构造：PHP 的 `sodium_crypto_secretbox()`/`sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()` 或 `openssl_encrypt()` 配合 AES-256-GCM；2) 密钥由 CSPRNG 生成（`random_bytes(32)`），禁止硬编码或从低熵口令派生，如需口令派生使用 `password_hash`/`hash_pbkdf2`/Argon2；3) 每次加密使用随机 nonce 并与密文一同存储，禁止 nonce 复用；4) 解密时校验认证标签，失败即拒绝；5) 对存量用 XOR 保护的数据执行密钥轮换与重新加密迁移。

**验证说明**

静态证据：入口 ANY /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：调用方将待保护数据 `$cleartext` 与密钥 `$key` 传入 017.php:3 的 `xor_this()`；函数以固定密钥对明文逐字节 XOR 生成密文（无 IV、无认证标签）。攻击者获取密文后，利用已知明文片段（固定头部/已知字段）与密文异或即可还原密钥流，从而解密其余密文；或对密文特定偏移做比特翻转，使解密结果按预期改变。整条链路不经过任何输入校验点，因为缺陷位于算法选择层而非数据流过滤层。
POC 备注：本 finding 为静态证据型，无 HTTP 端点（endpoint 为「离线审查」），因此不构造请求、不使用 TARGET 占位符、不执行任何命令。证据片段仅引用输入中给出的 `017.php:3`，未扩展至 code_pack 之外的文件。若后续需要动态验证，应由授权人员在隔离环境中进行，且不属于本 POC 交付范围。

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
| safety_guard | 安全防护 | 2.52 | 是 |
| surface_mapper | 攻击面测绘 | 7.74 | 是 |
| deep_finder | LLM 深挖 | 3.7 | 是 |
| candidate_screener | 候选筛选 | 2.77 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.08 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.75 | 是 |
| coordinator | 管线协调 | 6.06 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
