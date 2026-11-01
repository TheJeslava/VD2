# 落日二号乙漏洞挖掘报告 — 20261031-172722-ced608

- 生成时间：2026-10-31T09:28:05.760117+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-2e4335a5c995，类型 weak_crypto（CWE-327），严重度 medium，位于 017.php 第 1-3 行，规则判定自定义 XOR 加密函数 xor_this 使用可复用密钥流。该条已附带 POC，但属于静态证据型 POC（源码级算法判定），不具备 HTTP 请求/响应语义，不能宣称可动态复现。最高危即此条 medium；本次无 high/critical 交付项。POC 齐全度为 1/1（按 finding 计），但覆盖面极窄：code_pack 仅 1 个 PHP 文件、0 个端点、无框架，攻击面测绘给出的 source 热点（017.php:9）与 sink 热点（017.php:1）之间的数据流未被任何 finding 覆盖，命令执行/代码执行/文件包含/SQL 注入/XSS 等高危链路均处于未审计状态，不能据此认为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 017.php 的第 1-74 行（共 112 行，第 75-112 行未送入）。已审计范围：xor_this() 异或加解密函数（第 3-14 行）、硬编码密钥 $key="wachtwoord"（第 16 行）、POST 处理分支（第 26-50 行）、消息编解码（第 28-37 行）、登录判断（第 38-46 行）、HTML 输出拼接（第 52-74 行）。逐条核对结论如下：(1) 第 29 行 $message 来自 $_POST['message']，第 59 行输出时经 htmlentities() 转义，且第 56 行 $_SERVER['PHP_SELF'] 在常规部署下由 Web 服务器规范化，未发现可闭合的反射型 XSS 链；(2) 第 39-41 行 $password 仅与字符串字面量 "Olifant" 做 == 比较，未进入 SQL/命令/文件/包含类 sink，属于演示性硬编码口令，不构成可申报 CVE 的认证绕过（无会话、无权限提升后果）；(3) 第 16 行硬编码 XOR 密钥与 xor_this() 的重复密钥异或属于弱加密实现，但该脚本本身不承担真实机密保护职责，孤立配置项按规则不单独立 finding；(4) 第 31/35/40 行 base64_decode 结果仅参与异或运算，未流向文件系统、命令执行、反序列化或模板求值。第 75-112 行（$encoded 的最终输出渲染部分）未在 code_pack 中提供，无法确认该处是否对 $encoded 做了转义；若该段直接 echo $encoded 且 $encoded 可由 base64_decode($_POST['message']) 控制，则可能存在反射型 XSS，但当前证据不足，按“宁可漏报不可误报”原则不报告，列入 gaps 供后续补充代码后复核。输入信封中的 surface_notes 属于攻击面测绘推断（明确声明未提供代码片段、未做漏洞定性），其中关于 sink 位于第 1 行、source 位于第 9 行的描述与实际代码不符（第 1 行为 <?php，第 9 行为 for 循环），说明该测绘为基于文件类型的猜测，未作为结论依据；未发现诱导性指令文本。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未送入 code_pack，$encoded 的最终输出渲染与可能的其它 sink 无法审计
- 无 HTTP 端点清单、无部署配置（php.ini/.htaccess），无法确认 PHP_SELF 是否可被 PATH_INFO 污染
- 无数据库与外部服务配置，SQL 注入/SSRF 可达性无法评估
- 第 75-112 行若存在未转义输出 $encoded，需补充代码后复核反射型 XSS

## 3. Findings

### F-1: 017.php 自定义 XOR 加密函数 xor_this 使用可复用密钥流（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

证据来自 017.php 第 3 行定义的函数 `xor_this($cleartext, $key)`：该函数以调用方传入的 `$key` 对明文逐字节做 XOR 运算来生成密文（第 2-4 行可见函数签名与输出缓冲注释）。攻击者输入面为任何调用 `xor_this()` 的上层入口所传入的 `$cleartext` 与 `$key`（本 code_pack 仅包含 017.php 第 2-4 行，未给出调用点，故具体 HTTP 参数名证据不足）。校验无效的原因在于：XOR 是自逆运算，同一密钥重复使用即构成固定密钥流，`C = P ⊕ K` 与 `P = C ⊕ K` 对称，攻击者只要获得任意一组已知明文/密文对即可直接恢复密钥流并解密其余全部密文，无需破解任何计算难题；同时该实现未使用分组密码模式、未做完整性校验（无 MAC/AEAD），密文可被逐字节篡改且改动可预测地映射到明文对应字节。最终危险操作是：以自实现的 XOR 代替标准加密原语来保护数据机密性。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：在 `017.php:3` 定义的自定义加密函数 `xor_this($cleartext, $key)` 中，使用 XOR 作为加密算法保护数据。XOR 属于可逆的弱加密构造（无密钥派生、无完整性校验、密钥复用即导致明文可恢复），符合 CWE-327（使用有缺陷的加密算法）。本 POC 为离线源码审查工件，不发送网络请求。

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

机密性失效：任何能观察到密文（如存储的配置、Cookie/令牌、传输字段）的攻击者，在获得一段已知明文（如固定格式头部、可猜测字段）后即可恢复密钥流，从而解密全部历史与后续密文；由于缺少完整性保护，攻击者还可对密文做按位翻转，精确控制解密后明文的对应比特，实现数据篡改或绕过基于明文字段的判断。若该函数被用于口令或令牌保护，则进一步导致身份伪造。

**CVE / CWE 论证**

对应 CWE-327（Use of a Broken or Risky Cryptographic Algorithm）。外部可达性：函数定义于 017.php 第 3 行，属应用代码，任何引用该文件的请求路径均可触达；利用链闭合性：XOR 自逆 + 固定密钥复用 → 已知明文攻击恢复密钥流 → 解密/篡改任意密文，链路在算法层面即闭合，无需额外运行时条件。无需认证的前提是调用点未做鉴权（调用点未包含在 code_pack 中，此点证据不足）。未分配 CVE 编号，按 CWE-327 归类。

**修复建议**

1) 废弃自实现 XOR，改用标准 AEAD 原语：PHP 中使用 `sodium_crypto_secretbox()`/`sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()` 或 `openssl_encrypt()` 配合 AES-256-GCM，并校验认证标签；2) 密钥必须由 CSPRNG 生成（`random_bytes(32)`），禁止硬编码或从弱口令派生，派生口令场景使用 `sodium_crypto_pwhash()`/`password_hash()`；3) 每次加密使用唯一 nonce 并与密文一同存储，严禁密钥流复用；4) 若仅为混淆而非加密，应在代码注释与文档中明确标注不得用于安全用途，并从安全相关调用点移除；5) 对既有用 XOR 保护的数据执行密钥轮换与重新加密迁移。

**验证说明**

静态证据：入口 POST /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者从调用 `xor_this($cleartext, $key)` 的上层入口（017.php:3 定义的函数，具体调用点未在 code_pack 中给出）提交或读取受保护数据 → 数据进入 `$cleartext`，与固定 `$key` 逐字节 XOR 生成密文 → 由于 XOR 自逆且密钥复用，攻击者收集一组已知明文/密文对即可恢复密钥流 → 用恢复的密钥流解密其余全部密文，或对目标密文做按位翻转以可控篡改解密后明文 → 达成机密性破坏与完整性绕过。
POC 备注：本 POC 为文本工件，不执行、不联网、不搭建沙箱。目标地址如需引用统一写 `TARGET`。当前 code_pack 仅提供 017.php 第 2-4 行，调用点与密钥来源未覆盖，需补充源码后再评估实际可利用性。

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
| safety_guard | 安全防护 | 3.6 | 是 |
| surface_mapper | 攻击面测绘 | 11.15 | 是 |
| deep_finder | LLM 深挖 | 5.2 | 是 |
| candidate_screener | 候选筛选 | 3.35 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.09 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 4.14 | 是 |
| coordinator | 管线协调 | 7.95 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
