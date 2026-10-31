# 落日二号乙漏洞挖掘报告 — 20261031-014150-a12407

- 生成时间：2026-10-30T17:42:29.089948+00:00
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

共发现 1 条候选 finding，覆盖 1 种漏洞类型；1 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 032.php（24 行），已逐行通读。该文件全部内容是一个 heredoc 字符串（第 2-23 行），向 $page['body'] 追加一段前端 JavaScript：内嵌 blueimp JavaScript-MD5 实现（第 10 行）、rot13 函数（第 12-14 行）、generate_token 函数（第 16-19 行）以及一次 generate_token() 调用（第 21 行）。文件中不存在任何服务端危险汇点：没有 exec/system/passthru/shell_exec/popen/proc_open，没有 mysqli/mysql_query/PDO 拼接，没有 include/require/file_get_contents/fopen/readfile，没有 unserialize，没有 echo/print 用户输入，也没有 setcookie/session 配置或硬编码凭据。所有逻辑均为客户端 JS，且 md5(rot13(phrase)) 只是把页面输入框的值做客户端摘要后写回另一个输入框，不构成服务端信任边界或认证机制，无法形成外部可达的 source→sink 利用链。因此不产出 finding。未闭合线索：$page 变量在本文件中未初始化/未输出，实际渲染逻辑（可能存在的父级模板或包含该文件的入口）不在 code_pack 内，按契约视为不存在；若该文件被其他页面 include 且 $page['body'] 被输出，则第 10-22 行的 JS 会进入响应，但其中不含任何服务端污点，仍不构成漏洞。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 候选均无对应代码证据，属推断而非事实，不予报告。

未覆盖 / 证据缺口：
- $page 变量的初始化与最终输出位置不在 code_pack 内，无法确认该文件是否被 Web 可达地渲染
- 无部署配置/端点清单，无法确认匿名可达性
- 无 composer.json/PHP 版本信息
- surface_notes 中的配置类候选（weak_hash 等）在代码中无对应实现，无法确认

## 3. Findings

### F-1: 客户端使用 MD5 生成令牌（CWE-328 弱哈希，非 CWE-327 弱加密）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

证据位于 032.php 第 17-18 行：第 17 行从页面元素 phrase 读取用户输入 `var phrase = document.getElementById("phrase").value;`，第 18 行将其经 rot13 变换后送入 md5 计算并写入隐藏/表单字段 `document.getElementById("token").value = md5(rot13(phrase));`。攻击者输入点即页面中 id 为 phrase 的输入框（客户端可控），数据流为 phrase → rot13(phrase) → md5(...) → token 字段值。校验无效的原因在于：rot13 只是可逆的字符替换，不引入任何密钥或随机性；MD5 已被证明存在碰撞攻击且计算极快，且整个令牌生成完全在浏览器端 JavaScript 中完成，算法与变换对攻击者完全可见，因此该“令牌”不具备不可预测性与抗伪造性。需要说明的是，该弱点本质是弱哈希（CWE-328），而非 DES/ECB 类弱加密算法（CWE-327），标题中的 CWE-327 归类应修正。此外，输入仅给出 032.php 第 17-19 行片段，token 字段在服务端如何被消费（是否用于 CSRF 校验、会话绑定或一次性凭证）在 code_pack 中不可见，因此“可伪造令牌导致绕过”的最终汇点属于推断，证据不足。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线源码审计，不发送请求）：`032.php` 第 18 行在客户端 JavaScript 中把用户输入的 `phrase` 经 `rot13` 变换后交给 `md5()` 生成 `token` 字段值。该实现属于弱哈希/弱口令派生：MD5 已不具备抗碰撞与抗暴力破解能力，且 `rot13` 只是可逆替换而非加密，二者组合无法为 token 提供任何密码学强度。证据等级：llm_inferred（基于所给代码片段的推断，未做动态验证）。

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

若该 token 被服务端用作安全令牌（如 CSRF token、表单防重放令牌或隐藏状态凭证），攻击者可在本地复现同一算法（rot13 + MD5）离线批量生成合法 token，从而伪造请求、绕过 CSRF 防护或重放表单，造成越权操作或业务数据篡改。若 token 仅用于非安全用途（如展示用摘要），则实际影响降级为信息暴露（可预测摘要）。由于服务端消费逻辑未在证据中给出，具体影响等级需结合后端校验代码确认。

**CVE / CWE 论证**

对应 CWE-328（Use of Weak Hash）：MD5 用于生成安全相关令牌，属不可逆哈希的强度不足问题，不应归为 CWE-327（Use of a Broken or Risky Cryptographic Algorithm，指 DES/RC4/ECB 等加密算法/模式）。外部可达性：该逻辑位于 032.php 返回的页面脚本中，任何能访问该页面的用户（无需认证即可加载页面）都能触发并观察算法；利用链闭合度：输入（phrase）→ 变换（rot13）→ 弱哈希（md5）→ 输出（token 字段）在客户端完整闭合，但“token 被服务端信任”这一环在给定证据中缺失，故不宣称完整可利用链，仅确认弱点成立。

**修复建议**

1) 不要在客户端生成任何安全令牌；令牌必须由服务端使用密码学安全随机源生成（如 Java 的 SecureRandom、PHP 的 random_bytes、Node 的 crypto.randomBytes）。2) 若必须对用户输入做完整性保护，改用带密钥的 HMAC-SHA-256（服务端持有密钥），而非裸 MD5。3) 令牌应绑定会话并设置有效期与一次性使用语义，服务端校验时使用常量时间比较。4) 移除 rot13 这类可逆混淆，它不提供任何安全性。5) 若历史数据已用 MD5，迁移时对存量令牌做失效处理而非兼容。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者打开 032.php 页面，在 id=phrase 的输入框中填入任意内容；页面脚本第 17 行读取该值到变量 phrase，第 18 行执行 rot13(phrase) 后交给 md5()，结果写入 id=token 的字段。由于 rot13 可逆且无密钥、MD5 快速且可碰撞，攻击者可在本地用相同步骤为任意 phrase 计算出相同 token，从而在客户端侧完全预测/伪造该字段值。该伪造值是否被服务端接受并产生越权或重放效果，取决于 code_pack 之外的服务端校验代码，当前证据不足以确认最终危险汇点。
POC 备注：本 POC 为纯文本静态证据工件，不包含可自动执行的脚本，不联网、不搭建沙箱。目标地址如需引用统一写作 `TARGET`。仅限授权测试使用。注意：输入草稿中的 `grep` 命令仅用于说明定位方式，管线不应实际执行；`safety.target_uses_placeholder` 原为 false，本 POC 未引入任何真实地址。

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
| safety_guard | 安全防护 | 2.32 | 是 |
| surface_mapper | 攻击面测绘 | 8.97 | 是 |
| deep_finder | LLM 深挖 | 3.44 | 是 |
| candidate_screener | 候选筛选 | 2.98 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.75 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.53 | 是 |
| coordinator | 管线协调 | 6.25 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
