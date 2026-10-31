# 落日二号乙漏洞挖掘报告 — 20261031-164441-8faf7b

- 生成时间：2026-10-31T08:45:22.505062+00:00
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

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 032.php（24 行），已逐行通读。该文件全部逻辑为：第 2 行以 heredoc 向 $page['body'] 追加一段前端 <script>，其中内嵌 blueimp JavaScript-MD5 库（第 10 行）、rot13 函数（第 12-14 行）、generate_token 函数（第 16-19 行）与一次 generate_token() 调用（第 21 行）。服务端侧不存在任何 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 取值，不存在 include/require、eval、system/exec/shell_exec/proc_open、file_get_contents/fopen/readfile、mysqli_query/PDO、echo 输出请求参数、setcookie 等任何 source 或 sink；也没有硬编码凭据、弱哈希/弱加密/弱随机（md5 仅用于浏览器端由用户输入短语派生表单 token，属客户端逻辑，不构成服务端安全机制）、Cookie 标志位或信任边界判断。因此不存在可闭合的 source→sink 利用链，无可申报 CVE 的发现。surface_notes 中列出的 LFI/命令注入/SQLi/XSS/弱加密等攻击面均为基于文件清单的推断，经源码核对均不成立。未发现 prompt_injection 诱导性文本。未闭合线索：该脚本依赖外部变量 $page 与 DOM 元素 phrase/token，其上下文（是否被其他脚本 include、token 的后续服务端校验逻辑）不在 code_pack 内，按契约视为不存在，无法也不应据此推断漏洞。

未覆盖 / 证据缺口：
- $page 变量的初始化与使用方、phrase/token 表单元素所在页面、token 的服务端校验逻辑均不在 code_pack 内，无法评估其安全性
- 无 php.ini/Web 服务器配置，无法判断部署与暴露方式（但当前源码本身无危险汇点，不影响结论）

## 3. Findings

### F-1: 客户端令牌生成使用 MD5 弱哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

在 032.php 第 17-18 行，页面脚本从 DOM 元素 phrase 读取用户输入（document.getElementById("phrase").value），先经 rot13 做可逆替换，再调用 md5() 生成令牌并写入 document.getElementById("token").value。该令牌完全在浏览器端计算，算法为 MD5（128 位、已被证明存在碰撞且不适合安全用途），前置变换 rot13 只是字符置换、不引入任何密钥或随机性，因此令牌对相同 phrase 恒定可预测。此处不存在服务端校验环节的证据，校验有效性无法确认，但算法选择本身即构成弱哈希实现弱点。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（离线源码审计，不发送请求）：`032.php:18` 在浏览器端用 `md5(rot13(phrase))` 生成 `token` 字段值。该 token 由客户端 JavaScript 计算，算法为 MD5（CWE-328 弱哈希）叠加 ROT13（可逆混淆，无密钥），且完全在客户端执行，服务端无法保证 token 的机密性与不可预测性。攻击者读取页面 JS 即可离线复现任意 phrase 对应的 token，或对截获的 token 做彩虹表/暴力破解。

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

若该 token 被用作会话标识、表单防伪令牌或完整性校验值，攻击者可离线枚举/碰撞构造合法 token，导致令牌伪造、请求伪造或校验绕过；由于 rot13 可逆且无密钥，任何获得算法与输入格式的人都能复现同一 token。当前证据仅覆盖客户端生成逻辑，服务端如何使用该 token 证据不足。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于生成安全相关令牌，抗碰撞性与抗原像性均不满足安全要求；触发点位于 032.php:18 的 md5(rot13(phrase)) 调用，属实现型弱点，无需认证即可在客户端复现算法，利用链为「用户输入 phrase → rot13 可逆变换 → MD5 → token 字段」，闭合性依赖服务端是否信任该 token（证据不足）。

**修复建议**

1) 令牌应由服务端使用 CSPRNG（如 Java SecureRandom、PHP random_bytes、Node crypto.randomBytes）生成，禁止在客户端计算安全令牌；2) 若必须做摘要，改用 SHA-256 及以上并配合服务端密钥的 HMAC；3) 令牌需具备足够熵（≥128 位）、一次性使用与有效期；4) 移除 rot13 这类可逆混淆，避免造成「已加密」的错觉。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者控制页面中 id=phrase 的输入值 → 第 17 行读取为变量 phrase → 第 18 行 rot13(phrase) 做可逆置换 → md5() 计算摘要 → 写入 id=token 的隐藏/表单字段。由于算法与变换均公开且无密钥，攻击者可对任意候选输入离线生成同样的 token 值，从而在服务端若直接采信该字段时伪造令牌。
POC 备注：本 POC 为纯文本静态证据，不包含可执行脚本、不联网、不搭建沙箱。目标地址占位符 `TARGET` 在本离线场景中不适用（无 HTTP 请求）。所有结论为基于源码的 llm_inferred 推断，未经动态验证。

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
| safety_guard | 安全防护 | 4.44 | 是 |
| surface_mapper | 攻击面测绘 | 9.26 | 是 |
| deep_finder | LLM 深挖 | 3.66 | 是 |
| candidate_screener | 候选筛选 | 3.55 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.71 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.47 | 是 |
| coordinator | 管线协调 | 7.63 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
