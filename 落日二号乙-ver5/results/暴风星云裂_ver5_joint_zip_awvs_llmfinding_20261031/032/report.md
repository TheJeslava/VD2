# 落日二号乙漏洞挖掘报告 — 20261031-214627-fbd8ee

- 生成时间：2026-10-31T13:47:15.698684+00:00
- 输入：`$WORKSPACE\暴风星云裂\032.zip`
- 输入模式：`zip`
- SHA256：`00f20c6c4951b7689cab1e0be3d0e1d93bb7cb42b3399af954133774b6e161fd`
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

本次汇总 2 条已去重 findings：一条来自外部 AWVS 的 client_side_validation（high，无文件/行号，仅有外部证据与 POC 标记），一条来自规则引擎的 weak_crypto（medium，032.php 第 18 行，实际语义为 MD5 弱哈希，应归 weak_hash/CWE-328）。最高危为 AWVS 的客户端校验绕过，但其 file_path 为空、无行号，无法在源码层定位，只能作为外部证据引用。两条均标记 has_poc=true，但 weak_crypto 属静态证据型 POC（算法/标志位证据），不能宣称可动态复现；AWVS 条目为外部扫描结论，本次未做任何动态验证。整体覆盖面很窄：仅 1 个文件、0 个端点、无框架，surface_notes 明确说明未提供 032.php 源码片段，因此注入类攻击面（命令/SQL/XSS/路径穿越/SSRF 等）全部处于未覆盖状态，不能据此认为不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 4350 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 032.php 一个文件（24 行），已完整审计。该文件是 DVWA 风格的页面片段：第 2-23 行用 heredoc 向 $page['body'] 追加一段前端 JavaScript，内容为 blueimp JavaScript-MD5 库（第 10 行）、rot13 函数（第 12-14 行）以及 generate_token()（第 16-19 行，读取 DOM 元素 phrase 的值，计算 md5(rot13(phrase)) 后写入 token 输入框）。全文件没有任何服务端输入接收（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 取值）、没有任何 sink（无 system/exec/shell_exec/proc_open、无 include/require、无 fopen/file_get_contents/file_put_contents、无 mysqli_query/PDO、无 echo 直接输出请求参数、无 setcookie/session_set_cookie_params、无 md5()/sha1() 服务端散列、无 rand()/mt_rand()/uniqid()、无 mcrypt/openssl 调用）。第 10 行的 MD5 是客户端 JS 库，用于前端生成令牌，不构成服务端 weak_hash（CWE-328）证据；rot13 是前端混淆，不是加密。surface_notes 中列出的所有攻击面（命令注入、SQL 注入、路径穿越、SSRF、XSS、弱哈希/弱加密/弱随机、insecure_cookie、trust_boundary）在本文件中均无对应代码，属于基于文件形态的假设，未被源码证实。因此无可闭合的 source→sink 利用链，按零容忍误报原则返回空 findings。未闭合线索：该片段依赖外部 $page 数组与 HTML 表单（phrase/token 元素）以及可能的服务端处理逻辑，这些均不在 code_pack 中，视为不存在；若完整应用包含处理 token 的服务端代码，需另行提供源码再审计。

未覆盖 / 证据缺口：
- code_pack 仅含 032.php 前端片段，无服务端请求处理、无路由/端点、无认证逻辑，无法评估后端注入类风险
- 无 php.ini/Web 服务器配置，无法判断 allow_url_include、open_basedir、display_errors 等
- 无依赖清单与部署方式信息
- surface_notes 中的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 候选在本文件中均无对应实现，未证实

## 3. Findings

### F-1: AWVS: Client-side Validation Bypass

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/032.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed response relies on client validation. baseline HTTP 200 (8810 bytes); attack HTTP 200 (8810 bytes); marker='client validation markers'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/032.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/032.php` | AWVS 报告 Client-side Validation Bypass |  |  |

**POC**

AWVS 外部扫描发现（client_side_validation，CWE-602）：http://127.0.0.1:18081/032.php 的校验仅在前端 JavaScript 完成（第 18 行 md5(rot13(phrase)) 生成 token），服务端未做等价校验。AWVS 基线请求与攻击请求均返回 HTTP 200（8810 字节），响应体含 client validation markers，说明绕过前端校验后服务端仍正常处理。本 POC 保留 AWVS 记录的请求结构，仅补充说明与预期结果，不执行。

1. **重放 AWVS 记录的请求**

```http
GET /032.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-2e648d958fae`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed response relies on client validation. baseline HTTP 200 (8810 bytes); attack HTTP 200 (8810 bytes); marker='client validation markers'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-602；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：仅文本工件，不执行、不联网。保留 AWVS 原始 GET 请求结构；步骤 2 的 POST 字段名 phrase/token 来自 032.php 第 17-18 行 DOM 元素 id，服务端接收参数名未在 code_pack 中确认，已在 preconditions 标注需补充源码/路由。

### F-2: 客户端令牌生成使用 MD5 弱哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.66`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`032.php:17-18`
- **来源**：`rule`

**描述**

在 032.php 第 17-18 行，页面脚本从 DOM 元素 phrase 读取用户输入（var phrase = document.getElementById("phrase").value），随后执行 document.getElementById("token").value = md5(rot13(phrase))，把结果写入隐藏/表单字段 token。也就是说，令牌值完全由客户端 JavaScript 用 MD5 计算得出，且输入仅经过 ROT13（一种可逆的字符替换，不提供任何密码学强度）处理。攻击者可直接在浏览器控制台或本地脚本中复现同一算法：读取或猜测 phrase、执行 rot13 后做 MD5，即可离线生成任意合法 token，无需知道任何服务端密钥。校验无效的根因是：令牌的机密性与不可预测性依赖客户端算法，而 MD5 已被证明存在碰撞攻击且计算极快，ROT13 不引入任何熵，因此该令牌不具备抗伪造能力。最终危险操作是把可预测的弱哈希值作为 token 提交给服务端做身份/防伪校验。注意：本结论基于 code_pack 中给出的 032.php 片段，服务端如何比对 token 的代码未在输入中提供，故服务端校验逻辑属证据不足。

**source / sink**

- source：repository `md5(`（032.php）
- sink：032.php:18 		document.getElementById("token").value = md5(rot13(phrase));

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `032.php:18` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：032.php 第 18 行在客户端 JavaScript 中用 md5(rot13(phrase)) 生成 token 并写入隐藏字段 token。该值由浏览器端计算，算法为 MD5（已被证明可碰撞、可快速暴力破解），且 rot13 仅为可逆替换而非加密，二者组合不构成任何安全强度；token 完全由客户端控制，服务端若信任该值即等于无校验。本 POC 为离线源码审查工件，不发送请求。

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

令牌可被离线伪造：攻击者无需认证即可为任意 phrase 生成匹配的 token，从而绕过基于该 token 的防伪/会话/表单保护，导致越权提交、请求伪造或业务逻辑绕过。若该 token 被用作口令派生或签名，还会造成凭据可预测与离线爆破（MD5 高速计算）。具体业务影响取决于服务端对 token 的信任程度，该部分证据不足。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 属已知弱哈希，用于令牌生成时无法提供抗碰撞与抗预测性；同时 ROT13 为可逆替换而非加密，不增加熵。外部可达性：032.php 为可通过浏览器访问的页面，脚本在客户端执行，任何访问者均可读取并复现算法，无需认证。利用链闭合：攻击者控制 phrase → rot13(phrase) → md5(...) → 写入 token 字段 → 提交，全链在客户端完成，不依赖服务端秘密。

**修复建议**

1) 停止在客户端生成安全令牌，改由服务端使用 CSPRNG（如 Java SecureRandom、Node crypto.randomBytes）生成至少 128 位随机令牌并绑定会话；2) 若必须做完整性校验，使用 HMAC-SHA-256 并以服务端密钥签名，替代裸 MD5；3) 移除 ROT13 这类可逆混淆，避免误当作保护措施；4) 服务端对 token 做一次性校验（nonce + 过期时间）并常量时间比较；5) 对已使用 MD5 的历史令牌做失效与轮换。

**验证说明**

静态证据：入口 ANY /032；source=repository/md5(；sink=032.php:18；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者打开 032.php，在 phrase 输入框填入任意内容（或直接读取页面已有值）；页面第 17 行取到 phrase，第 18 行执行 md5(rot13(phrase)) 并把结果写入 token 字段。由于算法公开且无服务端密钥参与，攻击者可在本地用相同步骤为任意 phrase 计算出合法 token，再随表单提交，服务端若仅比对 MD5 值即被绕过。
POC 备注：仅文本工件，不执行、不联网。未给出服务端接收端点与参数名，故不构造 HTTP 请求；如需动态验证，须先由源码确认 token 的提交路由与字段名（当前 code_pack 未覆盖）。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `AWVS-2e648d958fae` | Client-side Validation Bypass | http://127.0.0.1:18081/032.php | external_only |

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
| `client_side_validation` | CWE-602 |  | 1 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.09 | 是 |
| surface_mapper | 攻击面测绘 | 9.35 | 是 |
| deep_finder | LLM 深挖 | 4.98 | 是 |
| candidate_screener | 候选筛选 | 3.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.69 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.7 | 是 |
| coordinator | 管线协调 | 7.61 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
