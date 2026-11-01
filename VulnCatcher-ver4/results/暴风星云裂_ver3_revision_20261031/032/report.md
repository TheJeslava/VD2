# 落日二号乙漏洞挖掘报告 — 20261031-011941-2b1a8a

- 生成时间：2026-10-30T17:20:16.992477+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\032.zip`
- 输入模式：`zip`
- SHA256：`00f20c6c4951b7689cab1e0be3d0e1d93bb7cb42b3399af954133774b6e161fd`
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

本次管线仅交付 1 条 finding：SEM-991eb6123bf3，类型 weak_crypto（medium），位于单文件 PHP 脚本 032.php 第 18 行附近，实际语义是客户端使用 MD5 生成令牌，属 CWE-328 弱哈希而非 CWE-327 弱加密，标题已自行标注该归类差异，建议在交付时按 weak_hash 口径复核类型标签。该 finding 附带 POC，但只有静态证据 POC（源码级算法判定），不具备 HTTP 动态复现条件，不能宣称可动态复现。最高危即此条 medium，本次无 high/critical 交付项。POC 齐全度为 1/1（仅静态）。整体覆盖面极窄：仅 1 个文件、0 个端点、无框架、无隔离文件，且 code_pack 未提供 032.php 的任何代码片段，因此除该条规则命中外，注入类、文件操作类、Cookie/session 类攻击面均未做行级判定，不能据此认为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 032.php（24 行），已全文审计。该文件行为：第 2 行通过 heredoc 向 $page['body'] 追加一段前端 <script>，内容为 blueimp JavaScript-MD5 库（第 10 行）、rot13 函数（第 12-14 行）、generate_token 函数（第 16-19 行）以及页面加载时调用 generate_token()（第 21 行）。generate_token 从 DOM 元素 id=phrase 读取值，经 md5(rot13(phrase)) 计算后写入 id=token 的输入框。全部逻辑均在浏览器端执行，服务端 PHP 代码没有任何 $_GET/$_POST/$_COOKIE/$_SERVER 输入读取，没有 exec/system/popen、SQL 查询、文件读写、include、反序列化、SSRF 或模板渲染等危险汇点，也没有 setcookie/session 配置。因此不存在服务端 source→sink 污点链，无法构造外部可达的 CVE 级漏洞。客户端使用 MD5 仅为前端令牌派生（且叠加 rot13），属于设计层面的弱哈希，但无服务端校验逻辑可被绕过，不构成可申报的认证绕过或弱加密漏洞，故不单独立项。未闭合线索：该文件疑似某训练/靶场页面（$page['body'] 说明存在外部框架拼接），其真实入口、认证方式、token 的服务端校验逻辑均不在 code_pack 中，无法评估 md5(rot13(phrase)) 生成的 token 是否被服务端用于鉴权；若后续能提供接收 token 的服务端脚本，需重新审计是否存在可预测令牌导致的认证绕过。

未覆盖 / 证据缺口：
- code_pack 仅含 032.php，缺少拼接 $page['body'] 的框架/入口文件，无法确认页面访问路径与认证要求
- 缺少服务端校验 token 的脚本，无法判断 md5(rot13(phrase)) 是否被用于鉴权从而形成可预测令牌绕过
- 无 php.ini/Web 服务器配置，无法评估部署暴露面

## 3. Findings

### F-1: 客户端使用 MD5 生成令牌（CWE-328 弱哈希，非 CWE-327 弱加密）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

证据来自 032.php 第 17-18 行：第 17 行 `var phrase = document.getElementById("phrase").value;` 从页面输入框读取用户可控的 phrase；第 18 行 `document.getElementById("token").value = md5(rot13(phrase));` 先用 ROT13 做可逆替换，再用 MD5 计算摘要并写入隐藏/表单字段 token。攻击者输入点即页面元素 id=phrase 的输入框（前端可控），数据流为 phrase → rot13(phrase) → md5(...) → token 字段值。校验无效的原因：ROT13 不是密钥、不引入任何熵，MD5 也不是抗碰撞的密码学哈希，二者组合对令牌没有任何保密性或不可预测性保障；且整个计算在浏览器端完成，算法与过程对攻击者完全可见。需要说明的证据缺口：输入片段只包含前端 JS 片段，未给出 token 字段提交到哪个后端路由、后端如何使用该 token（是否作为 CSRF token、会话标识或签名），因此“该令牌被服务端当作安全凭据”这一环属于基于源码的推断，未在给定片段中闭合。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线源码审查，不发送请求）：`032.php` 第 18 行在浏览器端用 `md5(rot13(phrase))` 生成 `token` 字段值。该构造把口令经 ROT13（可逆、无密钥）后送入 MD5（无盐、快速、已不适合口令派生），属于弱哈希/弱口令派生（CWE-328），并伴随客户端生成凭据令牌的设计缺陷。证据等级：llm_inferred（基于所给源码片段推断，未做动态验证）。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 032.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-991eb6123bf3`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

若该 token 被服务端用作 CSRF 令牌、一次性校验值或签名，则攻击者可离线复现同一算法：已知或可猜测的 phrase 经 ROT13+MD5 即可得到合法 token，从而伪造请求、绕过 CSRF 防护或重放；由于 MD5 存在碰撞与快速字典/彩虹表攻击，令牌空间可被高效枚举。若 token 仅用于非安全用途（如展示用短标识），实际影响降为信息泄露级别。具体后端影响因缺少服务端代码而证据不足。

**CVE / CWE 论证**

对应 CWE-328（Use of Weak Hash）。注意：候选原标注为 weak_crypto/CWE-327，但源码证据是 MD5 摘要用于令牌生成，属于弱哈希而非弱加密算法（DES/ECB 类），应归类为 weak_hash。外部可达性：该逻辑位于 032.php 返回的页面脚本中，任何能加载该页面的用户均可触发；无需认证即可在客户端复现算法；利用链为 输入框 phrase → rot13 → md5 → token 字段，闭合于前端，但“token 被服务端信任”这一后置环节在给定片段中未提供，故不宣称完整可利用链。

**修复建议**

1) 令牌必须由服务端使用 CSPRNG 生成（如 Java 的 SecureRandom、PHP 的 random_bytes、Node 的 crypto.randomBytes），禁止在客户端计算安全令牌；2) 若需完整性/签名，改用 HMAC-SHA-256 及以上，并使用服务端保管的密钥，密钥不得下发到浏览器；3) 移除 ROT13 这类可逆混淆，它不提供任何安全性；4) 令牌应具备足够长度（≥128 bit 熵）、一次性使用并绑定会话与过期时间；5) 对令牌比较使用常量时间比较函数，防止时序侧信道。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者打开 032.php 页面，在 id=phrase 的输入框中填入任意内容（第 17 行读取）；页面脚本执行 rot13(phrase) 后调用 md5() 计算摘要并写入 id=token 的字段（第 18 行）。由于 ROT13 可逆且无密钥、MD5 计算完全公开且可离线复现，攻击者可在本地用相同步骤为任意 phrase 生成与服务端一致的 token 值，进而伪造或重放携带该 token 的请求。该链条的前端部分由源码直接证实；token 在服务端的校验与信任方式未在给定片段中出现，属推断，需服务端代码佐证。
POC 备注：本 finding 为静态证据型，无 HTTP 端点与请求；目标地址占位符 `TARGET` 仅用于说明性文本，未写入真实地址。POC 不执行、不联网、不搭建沙箱。证据仅覆盖 `032.php` 第 17-19 行，服务端处理逻辑未在 code_pack 中提供，故未覆盖。

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
| safety_guard | 安全防护 | 2.73 | 是 |
| surface_mapper | 攻击面测绘 | 6.96 | 是 |
| deep_finder | LLM 深挖 | 3.54 | 是 |
| candidate_screener | 候选筛选 | 3.02 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.35 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.69 | 是 |
| coordinator | 管线协调 | 6.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
