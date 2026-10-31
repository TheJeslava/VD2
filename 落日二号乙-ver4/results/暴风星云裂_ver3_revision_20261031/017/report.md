# 落日二号乙漏洞挖掘报告 — 20261031-011645-93aff2

- 生成时间：2026-10-30T17:17:22.549565+00:00
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

本次汇总仅含 1 条已去重 finding：017.php 第 1-3 行的自制 XOR 加密函数 xor_this，类型 weak_crypto（CWE-327），严重度 medium，来源为规则命中，已附带 POC。最高危即该条，属配置/实现类弱加密，只有静态证据 POC，不能宣称可动态复现。POC 齐全度：1/1 有 POC，但均为静态文本工件，未做动态验证。攻击面测绘指出 017.php 有 9 处输入读取热点与 1 处汇点热点，但本次 findings 未覆盖任何注入类（command_injection / sql_injection / path_traversal / ssrf / xss）结论，属未交付而非不存在，需人工按档位复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2688 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 PHP 脚本 017.php 的 1-74 行（共 112 行，75-112 行未送入 code_pack，按契约视为不可见）。已审计的输入点：$_POST['message']（0029）、$_POST['direction']（0030）、$_POST['password']（0039）、$_SERVER['REQUEST_METHOD']（0026）、$_SERVER['PHP_SELF']（0056）。逐条结论：(1) message 经 xor_this 异或与 base64 编解码后仅用于回显，0059 处输出前经过 htmlentities()，不构成 XSS；异或为对称可逆运算，属设计功能而非可利用加密缺陷，且无密钥泄露到客户端的路径。(2) password 在 0041 处与硬编码字符串 "Olifant" 做明文比较，0040 的 xor_this 结果 $decoded 计算后未被使用，属死代码；硬编码口令本身是设计缺陷，但该脚本无会话建立、无后续受保护资源、无角色区分，登录成功仅返回 "Welcome back user" 文本，无法构成认证绕过或权限提升的闭合利用链，故不单独立项（若该口令被复用到其它系统，属部署层面问题，需人工确认）。(3) 0056 处 $_SERVER['PHP_SELF'] 拼入 form action，PHP_SELF 在部分服务器配置下可含路径信息（如 /017.php/foo），但此处仅作为 HTML 属性值输出且未做 htmlspecialchars，理论上存在 PHP_SELF 反射型 XSS 的可能；然而利用依赖 Web 服务器对 PATH_INFO 的处理方式（Apache 需 AcceptPathInfo、且现代 PHP 默认对 PHP_SELF 做部分转义），code_pack 未提供服务器配置，链不闭合，按“宁可漏报不可误报”原则不报告，仅作为线索记录。(4) 未发现 exec/system/passthru/shell_exec/popen/proc_open、SQL 查询、文件读写、include/require、反序列化、SSRF 类汇点；sink 热点 1 处即 0059 的 htmlentities 输出，已做编码。未闭合线索：017.php 第 75-112 行未在 code_pack 中，可能包含 $encoded 的后续输出（0071 起已开始拼接 "<label for='encoded'>Message:" 段落），若该段落直接 echo $encoded 而未编码，则存在反射型 XSS 的可能，需补充该段源码后再评估；此外缺少 php.ini、Web 服务器配置与部署路径，无法确认 PHP_SELF 行为与脚本是否公网可达。

未覆盖 / 证据缺口：
- 017.php 第 75-112 行未送入 code_pack，$encoded 的最终输出方式（是否 htmlentities/echo 直出）无法确认，是本次最主要的未闭合线索
- 缺少 php.ini、Apache/Nginx 配置，无法判定 PHP_SELF 是否可注入路径信息（PHP_SELF XSS 前提）
- 无端点清单与部署路径，无法确认脚本实际 URL 与访问控制
- 硬编码口令 "Olifant" 是否被复用于其它系统无法从单文件判断

## 3. Findings

### F-1: 017.php 中基于 XOR 的自制加密函数 xor_this（CWE-327 弱加密算法）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`017.php:2-3`
- **来源**：`rule`

**描述**

证据来自 017.php 第 3 行定义的函数 `xor_this($cleartext, $key)`：该函数以调用方传入的 `$cleartext` 与 `$key` 为参数，采用逐字节 XOR 的方式对明文做“加密”。XOR 属于可逆的线性运算，不是分组密码或流密码标准算法：它没有密钥扩展、没有初始化向量（IV）、没有完整性校验（MAC/AEAD），密钥空间完全取决于 `$key` 的长度与熵；当密钥短于明文或重复使用时，攻击者可通过已知明文/选择明文直接恢复密钥（`key = ciphertext XOR plaintext`），进而解密全部密文。代码片段仅显示函数签名与注释起始行（第 2–4 行），未显示密钥来源、密钥长度、调用点与保护对象，因此“该函数被用于保护口令/令牌/会话”这一环节属于推断，需按 notes 中的跨文件条件复核。

**source / sink**

- source：repository `xor_this`（017.php）
- sink：017.php:3 function xor_this($cleartext, $key) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `017.php:3` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：`017.php:3` 定义 `xor_this($cleartext, $key)`，使用 XOR 作为加密/混淆手段。XOR 属于可逆的弱加密构造（密钥复用、无完整性校验、密钥管理缺失），符合 CWE-327。本 POC 为离线源码审查工件，不发送请求、不执行代码。

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

若该函数被用于保护敏感数据（凭据、令牌、配置密文），攻击者获得任意一段明文-密文对即可恢复 XOR 密钥并解密其余全部密文，造成机密性完全失效；由于无完整性保护，攻击者还可对密文做比特翻转以可控地篡改解密后的明文（可控明文篡改/伪造）。当前证据仅能确认弱算法实现本身，具体数据泄露范围证据不足。

**CVE / CWE 论证**

CWE-327（Use of a Broken or Risky Cryptographic Algorithm）：017.php:3 的 `xor_this` 使用自制 XOR 代替标准加密算法，属可破解/高风险算法。外部可达性：该函数为 PHP 脚本内定义，是否通过 HTTP 路由暴露、是否需要认证，取决于未提供的调用方代码，证据不足；利用链闭合性：算法弱点本身成立，但“外部输入→该函数→敏感数据”的完整链路在给定片段中未闭合，故不主张 CVE 级定级，仅作为实现型弱点记录。

**修复建议**

1) 废弃 `xor_this`，改用标准库：对称加密使用 AES-256-GCM（PHP `openssl_encrypt` 配合 `aes-256-gcm`，每次随机 12 字节 nonce，并校验 tag）；2) 口令存储改用 `password_hash()`/`password_verify()`（bcrypt/Argon2id），不要用可逆加密；3) 密钥由 CSPRNG（`random_bytes`）生成并妥善保管，禁止硬编码或短密钥；4) 对密文附加 HMAC 或使用 AEAD 模式保证完整性；5) 若仅为混淆用途，应在代码注释中明确其非安全用途，避免被误用于保护敏感数据。

**验证说明**

静态证据：入口 ANY /017；source=repository/xor_this；sink=017.php:3；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者视角：若 `xor_this` 的输出（密文）或可触发的加解密接口对外可见，攻击者先获取一段已知明文对应的密文（例如自己提交的已知内容被加密后回显），计算 `key = ciphertext XOR plaintext` 恢复密钥；随后用该密钥解密截获的其他密文，或对目标密文做比特翻转构造期望的明文。整条链的关键前提是密钥短/复用且密文可获取，这两点在给定片段中未直接体现，属推断环节。
POC 备注：本 POC 为纯文本静态证据工件，目标地址统一使用 `TARGET` 占位符；不包含可自动执行的脚本，管线不执行、不联网、不搭建沙箱。证据等级：llm_inferred（基于 017.php:3 源码推断）。

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
| safety_guard | 安全防护 | 2.83 | 是 |
| surface_mapper | 攻击面测绘 | 8.09 | 是 |
| deep_finder | LLM 深挖 | 5.76 | 是 |
| candidate_screener | 候选筛选 | 3.18 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.52 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.14 | 是 |
| coordinator | 管线协调 | 5.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
