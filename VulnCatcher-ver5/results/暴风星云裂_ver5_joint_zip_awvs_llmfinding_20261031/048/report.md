# 落日二号乙漏洞挖掘报告 — 20261031-214944-093a46

- 生成时间：2026-10-31T13:50:24.798064+00:00
- 输入：`$WORKSPACE\暴风星云裂\048.zip`
- 输入模式：`zip`
- SHA256：`7be45c1a53974d969c5fea706096bfd9b3d27604468af7e49423890e14859d57`
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

本次汇总仅含 1 条已去重 finding：048.php 第 6 行会话标识由 time() 派生，属 weak_id（CWE-330 可预测会话标识），严重度 high，已附 POC（静态证据型，非 HTTP 动态复现）。这是本次最高危项，也是唯一交付项。POC 覆盖率为 1/1，但该 POC 基于源码推断，未做动态验证。攻击面测绘显示 048.php 第 1 行为 source 热点，但 sink_hot_files 为空，注入类（command_injection/sql_injection/xss/path_traversal/ssrf 等）均无法落地判断，不能据此认定存在或不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 048.php（9 行），已逐行审计。该脚本在 POST 请求时以 time() 生成 dvwaSession Cookie 并通过 setcookie 下发，无任何请求参数读取、无 include/exec/system/eval/文件操作/SQL 等危险汇点，也无认证或业务逻辑分支。关于 weak_random（time() 作为会话标识，可预测）与 insecure_cookie（setcookie 未设置 HttpOnly/Secure/SameSite）的线索：time() 返回值仅为秒级时间戳，且脚本未将该 Cookie 用于任何服务端鉴权或状态判断（无读取 $_COOKIE 的代码），无法在 CODE PACK 内闭合“可预测令牌→认证绕过/会话劫持”的利用链；setcookie 缺标志位属配置缺陷，但缺少会话建立与敏感操作证据，单独不足以申报 CVE。按“宁可漏报不可误报”原则不单独立 finding，仅作为线索记录。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 048.php 全部 9 行已覆盖，无未读范围
- 无端点清单与部署配置（php.ini/Web 服务器），无法确认 dvwaSession 是否被其它未提供文件消费
- 若存在同项目其它文件读取 dvwaSession 做鉴权，则 weak_random 线索可能升级为 auth_bypass，但该文件不在 code_pack 内，视为不存在

## 3. Findings

### F-1: 会话标识由 time() 派生导致可预测（CWE-330 弱 ID / 可预测会话标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`048.php:5-6`
- **来源**：`rule`

**描述**

攻击者无需任何输入参数即可利用：服务端在 048.php 第 5 行判断请求方法为 POST 后，第 6 行执行 `$cookie_value = time();`，把当前 Unix 时间戳（秒级整数）直接作为会话标识值，第 7 行通过 `setcookie("dvwaSession", $cookie_value)` 下发给客户端。该值不是由密码学安全随机源（如 random_bytes / SecureRandom）生成，而是单调递增、可外部推算的时间量：攻击者只需知道或估算目标签发 cookie 的大致时间窗口（例如自己触发一次登录观察自身时间戳，或利用服务器 Date 响应头），即可在秒级范围内枚举候选值。校验无效的根本原因是代码中不存在任何熵注入、随机化或服务端绑定（无 HMAC、无用户绑定、无随机盐），标识空间仅为时间戳秒数，碰撞与预测成本极低。最终危险操作是：该可预测值被当作会话标识写入 Cookie 并由服务端接受，攻击者可伪造/猜测他人会话标识从而劫持会话。

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

会话劫持/身份冒用：攻击者可在秒级窗口内枚举或推算 `dvwaSession` 值，伪造受害者会话 Cookie，以受害者身份访问应用，导致账户接管与越权数据访问。由于标识为纯时间戳，同一秒内多用户还会得到相同标识，进一步造成会话串号与横向越权。

**CVE / CWE 论证**

对应 CWE-330（Use of Insufficiently Random Values），亦可关联 CWE-340（Generation of Predictable Numbers or Identifiers）与 CWE-384（Session Fixation）。外部可达性：048.php 为 Web 可访问脚本，任意远程攻击者发送 POST 请求即可触发第 6 行生成逻辑，无需认证、无需特权。利用链闭合：POST 请求 → 第 6 行 `time()` 生成可预测值 → 第 7 行 `setcookie` 下发 → 服务端以该值作为会话标识接受，攻击者侧仅需时间推算即可构造候选 Cookie，链路无缺口。证据等级为源码推断（llm_inferred），未做运行时验证。

**修复建议**

1) 使用密码学安全随机源生成会话标识，例如 PHP 中 `bin2hex(random_bytes(32))`，禁止使用 time()、rand()、mt_rand()、uniqid() 等可预测函数；2) 会话标识长度不低于 128 位熵，且每次认证成功后重新生成（session_regenerate_id(true)）；3) 将会话标识与用户身份、客户端指纹做服务端绑定校验，并设置 HttpOnly、Secure、SameSite 属性；4) 服务端维护会话存储并校验标识存在性与有效期，拒绝任何未在服务端登记的标识；5) 增加会话固定防护：登录前后更换标识并作废旧标识。

**验证说明**

静态证据：入口 POST /048；source=session/dvwaSession；sink=048.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 048.php 发送 POST 请求（无需认证）→ 第 5 行 `$_SERVER['REQUEST_METHOD'] == "POST"` 成立 → 第 6 行 `$cookie_value = time()` 以秒级时间戳作为会话标识 → 第 7 行 `setcookie("dvwaSession", $cookie_value)` 将该可预测值写入客户端 Cookie → 服务端后续请求以该 Cookie 值识别会话。由于标识空间仅为时间戳秒数且无随机化/无用户绑定，攻击者可通过估算签发时间窗口枚举候选值，构造受害者 Cookie 完成会话劫持。
AWVS 外部佐证：Predictable Session Identifier @ http://127.0.0.1:18081/048.php（未在本管线执行扫描）。

**外部佐证**

- awvs: Predictable Session Identifier @ http://127.0.0.1:18081/048.php

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
| `SEM-26658112c975` | Predictable Session Identifier | http://127.0.0.1:18081/048.php | corroborated |

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
| safety_guard | 安全防护 | 4.23 | 是 |
| surface_mapper | 攻击面测绘 | 7.36 | 是 |
| deep_finder | LLM 深挖 | 4.07 | 是 |
| candidate_screener | 候选筛选 | 4.0 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.58 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.38 | 否 |
| coordinator | 管线协调 | 5.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
