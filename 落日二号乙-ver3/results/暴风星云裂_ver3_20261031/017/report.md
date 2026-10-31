# 落日二号乙漏洞挖掘报告 — 20261031-005946-397bc7

- 生成时间：2026-10-30T17:00:23.468130+00:00
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

本次汇总仅包含 1 条已去重 finding：017.php 第 1-3 行存在基于 XOR 的自制加密函数，判定为 weak_crypto（CWE-327），严重度 medium，来源为规则命中，已附带 POC。该 POC 属于静态证据型（源码级算法判定），不具备 HTTP 请求/响应层面的动态可复现性，不能宣称可动态复现。最高危项即此条 weak_crypto。POC 齐全度：1/1 条 finding 有 POC，但均为静态 POC。攻击面测绘指出 017.php:9 存在参数读取 source 热点、另有 1 处 sink 热点，但输入未提供代码片段，无法确认注入类（command_injection / sql_injection / path_traversal / xss）污点链，故本次未交付任何注入类 finding，这属于证据不足而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 017.php 的可见范围（第 1-74 行，共 112 行，后 38 行未送入）。该脚本是一个 XOR 编解码小工具：第 26-50 行处理 POST，第 29 行读取 $_POST['message']、第 39 行读取 $_POST['password']。逐跳追踪结果：(1) message 经 xor_this/base64 处理后在第 59 行通过 htmlentities() 输出，XSS 被编码阻断；(2) password 仅与硬编码字符串 "Olifant" 做 == 比较（第 41 行），属于演示性硬编码口令，但脚本无任何会话/权限状态、无后续受保护功能，不构成可申报的认证绕过链；(3) 第 56 行 $_SERVER['PHP_SELF'] 被拼入 form action，存在经典 PHP_SELF 反射型 XSS 的可能，但该行位于可见范围内且未做 htmlspecialchars，然而利用依赖 Web 服务器对 PATH_INFO 的处理（如 /017.php/"onmouseover=...），且输入未在 code_pack 中体现为可控参数，证据不足以闭合链，故不报告；(4) 第 16 行硬编码 XOR 密钥 "wachtwoord" 与 xor_this 弱加密（CWE-327）属配置型线索，但脚本本身无敏感数据保护语义，孤立配置不单独立项。未发现命令执行、SQL、文件包含、反序列化、SSRF 等 sink。未闭合线索：第 75-112 行未送入，可能包含 $encoded 的输出点（若未编码则可能构成反射型 XSS），建议补充该段代码后复核；PHP_SELF 拼接需结合部署配置确认。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未包含在 code_pack 中，$encoded 的最终输出点无法确认是否做了 htmlentities 编码
- 无 Web 服务器配置，无法确认 PHP_SELF 拼接是否可被 PATH_INFO 注入
- 无端点清单，入口仅由源码推断为直接访问 017.php

## 3. Findings

### F-1: 017.php 中基于 XOR 的自制加密函数（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

017.php 第 3 行定义了 `function xor_this($cleartext, $key)`，其实现是对明文与密钥逐字节做 XOR 运算（第 4 行注释 `// Our output text` 之后为输出构造逻辑）。该函数把 XOR 当作加密原语使用：XOR 是线性、可逆的按位运算，不具备分组密码或流密码应有的非线性混淆与扩散特性；当密钥被重复使用（同一 `$key` 对多段明文做 XOR）时，攻击者只要获得任意一组明文-密文对即可直接恢复密钥流，进而解密其余全部密文，甚至可对已知明文片段做选择性篡改（XOR 的延展性 malleability）。代码中未见任何密钥派生、随机 IV/nonce、完整性校验（MAC/AEAD）或标准密码库调用，属于典型的自制弱加密实现。证据等级为源码推断：输入仅给出第 2–4 行片段，`$key` 的来源、长度与复用方式，以及该函数的调用点（是否用于口令、令牌、会话或配置文件加密）在 code_pack 中未提供，因此无法确认具体保护对象与外部可达路径。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：在 017.php 第 3 行定义函数 xor_this($cleartext, $key)，从函数名与参数（明文 + 密钥）可推断其使用 XOR 方式对数据做“加密”。XOR 属于可逆的弱加密/混淆手段，密钥复用或密钥硬编码时，攻击者获得密文与部分明文即可还原密钥并解密其余数据。本 POC 为离线源码审查证据，不发送任何网络请求。

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

若该函数用于保护敏感数据（凭据、会话令牌、配置项或业务数据），攻击者可在获取任一明文-密文对后恢复密钥流，从而批量解密其余密文（机密性丧失）；由于 XOR 无完整性保护，攻击者还可对密文做按位翻转以可控地篡改解密后的明文（完整性丧失），在令牌/权限字段场景下可能进一步导致越权。当前证据不足以确认具体受影响数据与外部可达性。

**CVE / CWE 论证**

对应 CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：XOR 逐字节运算不是密码学安全的加密算法，缺乏非线性与扩散，且无 IV/nonce 与完整性校验，密钥复用下可被已知明文攻击直接攻破。该弱点为配置/实现型弱点，按规则不要求 source→sink 污点链，但外部可达性（是否有 HTTP 入口调用 `xor_this`）与无需认证条件在给定片段中无法确认，故不主张完整 CVE 级利用链闭合。

**修复建议**

1) 停止使用 XOR 作为加密原语，改用标准库的认证加密：PHP 中优先 `sodium_crypto_secretbox()` / `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`，或 `openssl_encrypt()` 配合 AES-256-GCM；2) 每次加密使用密码学安全随机数生成器（`random_bytes()`）产生唯一 nonce/IV，并与密文一同存储，严禁密钥复用；3) 通过 `hash_hkdf()` 等 KDF 从主密钥派生用途隔离的子密钥；4) 解密前校验认证标签，失败即拒绝，避免延展性篡改；5) 若该函数仅用于混淆而非安全保护，应在代码注释与文档中明确标注，禁止用于任何安全用途。

**验证说明**

静态证据：入口 ANY /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者视角：若 `xor_this($cleartext, $key)` 被用于加密可外部获取的密文（如 Cookie、令牌或接口返回字段），攻击者先收集一组已知明文对应的密文，按 `keystream = ciphertext XOR known_plaintext` 恢复密钥流；随后对任意目标密文执行 `plaintext = ciphertext XOR keystream` 完成解密，或对密文特定字节做 XOR 翻转以可控修改解密结果。整条链的关键前提——`$key` 的复用与密文的外部可获取性——在提供的 017.php:2-4 片段中未体现，属于证据缺口，需补充调用点与密钥管理代码后才能确认利用链闭合。
POC 备注：本 POC 为纯文本静态证据工件，不执行、不联网、不搭建沙箱。目标地址占位符 TARGET 未使用（离线审查无 HTTP 端点）。所有结论基于 code_pack 中 017.php 第 3 行的可见片段，未覆盖该函数完整实现、调用点及密钥来源，需人工补充确认。

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
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 9.4 | 是 |
| deep_finder | LLM 深挖 | 3.77 | 是 |
| candidate_screener | 候选筛选 | 2.75 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.03 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 4.82 | 是 |
| coordinator | 管线协调 | 5.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
