# 落日二号乙漏洞挖掘报告 — 20261031-173315-408636

- 生成时间：2026-10-31T09:33:53.556842+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\048.zip`
- 输入模式：`zip`
- SHA256：`7be45c1a53974d969c5fea706096bfd9b3d27604468af7e49423890e14859d57`
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

本次汇总仅含 1 条已去重 finding：SEM-26658112c975，类型 weak_id（CWE-330），严重度 high，位于唯一文件 048.php 第 1-6 行，会话标识由 time() 派生导致可预测。该条已附带 POC（has_poc=true），但属静态证据型 POC，未做动态验证。最高危即此条。整体攻击面极小：单文件 PHP 脚本（9 行、145 字节），无框架、无路由、endpoints 为空，sink_hot_files 为空，说明管线未识别到明确危险汇点，不能据此判定无注入类漏洞。POC 齐全度：1/1 有 POC，但均为静态推断，无 HTTP 可复现 POC。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 048.php（共 9 行，已完整展示 1-9 行）。该脚本在 POST 请求时执行 `$cookie_value = time(); setcookie("dvwaSession", $cookie_value);`，即用秒级时间戳作为会话 Cookie 值。逐项核对：(1) 无任何 $_GET/$_POST/$_COOKIE/$_SERVER 用户输入进入 echo/print、include、file 系列、system/exec、SQL 等汇点，不存在可闭合的注入/穿越/RCE 链；(2) 该 Cookie 值仅被写入客户端，脚本内没有任何读取 `dvwaSession` 并据此做鉴权/会话校验的逻辑，因此不构成认证绕过或会话固定（会话状态完全由客户端持有，服务端无校验点，无法证明可提升权限）；(3) 配置型候选方面，`time()` 属可预测值（CWE-330/CWE-340 弱随机），但缺少服务端消费该值的代码，无法证明令牌可被用于冒充或越权，证据不足以支撑 CVE 级结论，故不单独立项，仅作为线索记录；(4) setcookie 未设置 HttpOnly/Secure/SameSite（CWE-1004/CWE-614），但同样缺少读取该 Cookie 的敏感逻辑，无法形成实际利用链。surface_notes 中提到的 weak_hash/weak_crypto/trust_boundary 等复核项在代码中均未出现对应调用（无 md5/sha1、无 openssl/mcrypt、无 X-Forwarded-For/REMOTE_ADDR 鉴权）。输入中未出现诱导性文本，无 prompt_injection 证据。未闭合线索：该脚本疑似 DVWA 的弱会话 ID 练习片段，若仓库外存在读取 dvwaSession 并作为身份凭据的服务端逻辑，则 time() 可预测性可能升级为会话预测/认证绕过，但该逻辑不在 code_pack 内，按契约视为不存在，不予报告。

未覆盖 / 证据缺口：
- code_pack 仅含 048.php 一个文件，无路由、无认证逻辑、无读取 dvwaSession 的服务端代码，无法评估会话预测是否可导致认证绕过
- 缺少部署配置（Web 服务器、PHP 版本、php.ini），无法确认脚本暴露方式
- 无依赖清单，无法评估第三方组件 CVE
- time() 作为会话值的可预测性（CWE-330）与 Cookie 缺少 HttpOnly/Secure/SameSite（CWE-1004/CWE-614）因缺少服务端消费点而未闭合，未达 min_confidence 0.6 的立项标准

## 3. Findings

### F-1: 048.php 会话标识由 time() 派生导致可预测（CWE-330 弱随机/可预测标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`048.php:5-6`
- **来源**：`rule`

**描述**

攻击者无需任何输入参数即可利用：服务端在 048.php 第 5 行判断请求方法为 POST 后，于第 6 行执行 `$cookie_value = time();`，把当前 Unix 时间戳（秒级整数）直接作为会话标识值，并在第 7 行通过 `setcookie("dvwaSession", $cookie_value)` 下发给客户端。该值不是由安全随机源（如 random_bytes / CSPRNG）生成，而是由可公开观测、可高精度估算的系统时间派生，熵极低（同一秒内所有会话取值相同，且相邻会话仅相差 1）。攻击者只需知道或估算目标签发 cookie 的大致时间窗口，即可枚举出候选 `dvwaSession` 值集合，逐个提交以猜测/复用他人会话。校验无效的原因在于：代码完全没有对标识做随机化、长度扩展或服务端绑定（无 IP/UA 绑定、无签名、无一次性 nonce），标识空间仅等于时间戳秒数范围，暴力枚举成本极低。最终危险操作是 `setcookie` 下发的会话标识被服务端当作会话凭据接受，导致会话预测/劫持。

**source / sink**

- source：session `dvwaSession`（048.php）
- sink：048.php:6 	$cookie_value = time();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `048.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /048（POST）的 弱 ID / 可预测会话标识 POC。注入点：POST 会话建立请求；连续请求比较 dvwaSession Cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/048'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/048' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/048' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-26658112c975`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

会话预测与会话劫持：攻击者可枚举时间窗口内的 `dvwaSession` 候选值，冒充其他已认证用户身份，读取或操作该用户权限下的数据与功能（越权访问、账户接管）。由于标识在同一秒内碰撞，还可造成会话混淆/串号。属于认证与会话管理层面的高危弱点。

**CVE / CWE 论证**

对应 CWE-330（Use of Insufficiently Random Values），亦可关联 CWE-331（Insufficient Entropy）与 CWE-340（Generation of Predictable Numbers or Identifiers）。外部可达性：048.php 为 Web 可访问端点，任意远程攻击者发送 POST 即可触发标识签发，无需认证、无需特权。利用链闭合：源码第 6 行 `time()` 生成 → 第 7 行 `setcookie("dvwaSession", ...)` 下发 → 服务端以该 cookie 作为会话标识接受，攻击者侧仅需离线枚举时间戳候选并在线提交，链路完整。证据等级为源码推断（llm_inferred），未做运行时验证服务端是否严格以该 cookie 作为唯一会话凭据，该环节为置信度扣减项。

**修复建议**

1) 使用密码学安全随机源生成会话标识，如 PHP 的 `bin2hex(random_bytes(32))` 或 `session_id()` 配合 `session.use_strict_mode=1`；2) 禁止使用 `time()`、`rand()`、`mt_rand()`、自增计数器等可预测值作为会话/令牌；3) 标识长度不少于 128 bit 熵，并在服务端维护会话存储与过期策略；4) 设置 cookie 安全属性：`HttpOnly`、`Secure`、`SameSite=Lax/Strict`，并通过 `session_regenerate_id(true)` 在登录成功后轮换标识；5) 增加会话与客户端指纹（IP/UA 哈希）的弱绑定与异常检测，降低被枚举复用后的可用性。

**验证说明**

静态证据：入口 POST /048；source=session/dvwaSession；sink=048.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 048.php 发送 POST 请求（无需认证）→ 第 5 行进入 POST 分支 → 第 6 行 `$cookie_value = time()` 以秒级时间戳作为标识 → 第 7 行 `setcookie("dvwaSession", $cookie_value)` 下发 → 攻击者根据目标签发时间窗口枚举候选时间戳，构造 `Cookie: dvwaSession=<候选值>` 提交 → 服务端接受该可预测标识，攻击者获得/复用目标会话，实现会话劫持与越权。
PocWriter 建议（未采纳，缺少端点 /048）：针对 048.php:6 的弱 ID / 可预测会话标识（CWE-330）POC。源码在 POST 请求处理路径上生成会话标识并写入 dvwaSession Cookie；连续请求得到的 Cookie 值呈可预测序列（递增/低熵），攻击者可枚举或预测他人会话标识。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /048）：符合 CWE-330（Use of Insufficiently Random Values）。漏洞位于 048.php:6，会话标识 dvwaSession 由弱随机/可预测逻辑生成，静态链路已闭合，具备远程触发条件；未发现有效熵增强或签名校验。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行时需将 TARGET 替换为授权实例地址，并使用同一 cookie jar 保存/回放 Cookie 以比较连续会话值。若源码中会话字段名或生成算法与 dvwaSession 不一致，需回到 048.php:6 补充确认后再调整请求，不得伪造字段。

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
| `weak_crypto` | CWE-327 |  | 0 |
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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.92 | 是 |
| surface_mapper | 攻击面测绘 | 7.25 | 是 |
| deep_finder | LLM 深挖 | 5.0 | 是 |
| candidate_screener | 候选筛选 | 3.16 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.98 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.08 | 是 |
| coordinator | 管线协调 | 6.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
