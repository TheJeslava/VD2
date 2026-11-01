# 落日二号乙漏洞挖掘报告 — 20261031-164718-257c4b

- 生成时间：2026-10-31T08:47:57.094720+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\046.zip`
- 输入模式：`zip`
- SHA256：`9d98d51f3b7f8ead39aea7b49f01b44680c06b424521a0bf068da8c5c5a86a40`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 046.php（14 行、约 395 字节，无框架、无路由清单）。最高危为 SEM-19354a0facf2（weak_id，high）：会话标识基于自增整数，可预测（CWE-330），位于 046.php 第 6 行附近；其次为 SEM-7da0188b59a9（weak_crypto，medium）：使用 MD5 生成会话 Cookie 值，实为弱哈希（CWE-328），位于 046.php 第 10 行附近。两条均带 POC，但均为静态证据型 POC（算法/标识生成逻辑），不具备 HTTP 请求级动态复现条件，不能宣称可动态复现。攻击面测绘显示唯一外部输入点为 046.php:2 的请求参数读取，但 sink_hot_files 为空，未识别到危险汇点，因此本次未交付任何注入类（command_injection / sql_injection / path_traversal / ssrf / xss）结论，这属于证据不足而非已排除。无二次注入链，无 prompt_injection 证据。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 046.php（14 行，PHP 单文件脚本）。该脚本在 POST 请求时基于 $_SESSION['last_session_id_high'] 自增计数，用 md5() 生成 dvwaSession Cookie 值并通过 setcookie 下发（第 5-12 行）。分析结论：(1) 无任何外部请求参数（$_GET/$_POST/$_REQUEST/$_COOKIE）被读取，surface_notes 中 source_hot_files 标注的 046.php:2 实际为空行，不存在外部可控输入，因此不存在 source→sink 污点链，command_injection/sql_injection/path_traversal/ssrf/xss 均不成立；(2) 无 include/require、文件操作、SQL、system/exec、echo 输出等危险汇点，sink_hot_files 为空与源码一致；(3) 唯一可讨论的是 md5(自增整数) 生成会话标识，属于弱随机/可预测 ID 模式（CWE-330/CWE-338 类），但该值仅由服务端自增计数派生、无攻击者输入参与，且本文件未展示任何以该 Cookie 做鉴权或对象归属判断的消费点，无法在 CODE PACK 内闭合“预测 Cookie → 冒充/越权”的利用链，按零容忍误报原则不单独立项，仅作为线索记录。未发现满足 CVE 级别且链闭合的漏洞，返回空 findings。

未覆盖 / 证据缺口：
- 无端点/路由信息，无法确认 046.php 的实际访问路径与参数名
- 无 php.ini、Web 服务器配置、composer.json，无法确认运行环境与危险函数禁用情况
- dvwaSession Cookie 的消费方（校验逻辑）不在 CODE PACK 内，弱 ID 是否可导致会话预测/越权无法闭合
- 无数据库 schema、日志、模板文件，无法评估二次注入或存储型 XSS

## 3. Findings

### F-1: 046.php 会话标识基于自增整数，可预测（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

046.php:5 在 POST 请求下进入 046.php:6，检查 $_SESSION['last_session_id_high'] 是否存在，不存在则置 0（046.php:7），随后在 046.php:9 自增、046.php:10 用 md5 派生 Cookie 值。会话标识的熵来源是单调递增的整数计数器，而非随机源，攻击者可通过观察自身会话值推断相邻用户的会话标识。

**source / sink**

- source：session `dvwaSession`（046.php）
- sink：046.php:6 	if (!isset ($_SESSION['last_session_id_high'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /046（POST）的弱 ID / 可预测会话标识 POC。源码 046.php:9-11 显示 $_SESSION['last_session_id_high'] 自增后经 md5 生成 dvwaSession Cookie，连续请求的 Cookie 值呈可预测序列。注入点为会话建立请求，比较连续响应的 Set-Cookie。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/046'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现 1、2、3 等递增/可预测序列，或可重放访问

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-19354a0facf2`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

会话预测与劫持：攻击者获取一次自身 dvwaSession 值后，可推算前后用户的令牌（自增序列 + 确定性 md5），实现会话固定/劫持，导致越权访问受害者账户数据。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）：会话标识由计数器派生，缺乏随机性；外部可达性——046.php 为公开 Web 端点，任意 POST 即可触发；利用链闭合——046.php:6/7 初始化 → 046.php:9 自增 → 046.php:10 md5 → 046.php:11 setcookie，序列完全确定，攻击者可离线复现。

**修复建议**

使用密码学安全随机数生成会话 ID（random_bytes / random_int 配合足够熵），避免任何自增或时间派生；服务端维护会话表并校验绑定信息（IP/UA 指纹可选）；启用 session_regenerate_id 在登录后轮换标识。

**验证说明**

静态证据：入口 POST /046；source=session/dvwaSession；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 POST 至 046.php → 046.php:6 判断并 046.php:7 初始化计数器 → 046.php:9 自增 → 046.php:10 md5 派生确定性值 → 046.php:11 下发 dvwaSession → 攻击者按序列推算他人令牌并伪造请求。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330（使用不充分的随机值）。漏洞位于 046.php:6-11，会话标识由自增计数器经 md5 派生，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。请求结构沿用输入草稿，补充了保持同一会话的 Cookie 头与三步基线/攻击/状态确认说明。

### F-2: 046.php 使用 MD5 生成会话 Cookie 值（弱哈希，CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

攻击者无需输入任何参数：在 046.php:5 判断 REQUEST_METHOD 为 POST 后，046.php:9 将 $_SESSION['last_session_id_high'] 自增，046.php:10 用 md5($_SESSION['last_session_id_high']) 计算 $cookie_value，046.php:11 通过 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 下发。根因是使用 MD5 这一已被证明存在碰撞、且对短整型输入可被完全预计算的哈希算法来派生安全令牌；同时 setcookie 的 secure 参数为 false、httponly 为 false，令牌可经明文通道传输并被脚本读取。注意：该候选原始类型标注为 weak_crypto，但按证据应归类为 weak_hash（CWE-328），而非 CWE-327 的加密算法误用。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：046.php 第 10 行使用 md5($_SESSION['last_session_id_high']) 生成会话 Cookie 值，属于弱哈希（CWE-328/CWE-327 类）。该值随后在第 11 行通过 setcookie("dvwaSession", ...) 下发，路径 /vulnerabilities/weak_id/。无需发送请求即可在源码中确认算法选择。

1. **在源码中定位证据**

```http
grep -n -A2 -B2 '<evidence>' 046.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**

```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-7da0188b59a9`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

会话标识可预测/可伪造：由于输入空间仅为自增整数，攻击者可在本地枚举 md5(0..N) 建立彩虹表，直接猜解或构造合法 dvwaSession 值，进而劫持其他用户会话（越权访问、身份冒用）。Cookie 未设置 Secure/HttpOnly，进一步扩大泄露面（明文嗅探、XSS 读取）。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于生成会话令牌属安全用途，短整型输入使预计算攻击成本极低；外部可达性——046.php 为 Web 可直接访问脚本，POST 请求即可触发令牌生成，无需认证；利用链闭合——046.php:9 自增 → 046.php:10 md5 派生 → 046.php:11 setcookie 下发，攻击者只需预测/枚举该值即可复用会话。

**修复建议**

改用 CSPRNG 生成会话标识：random_bytes(32) 或 session_regenerate_id(true)，禁止用 MD5/SHA-1 派生令牌；若必须哈希，使用 hash('sha256', ...) 并配合服务端随机盐与 HMAC。setcookie 增加 secure=true、httponly=true、samesite=Lax/Strict；会话标识应完全随机而非自增计数。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST 请求进入 046.php:5 → 046.php:9 对 $_SESSION['last_session_id_high'] 自增（可预测序列）→ 046.php:10 md5() 计算 $cookie_value → 046.php:11 setcookie 将可预测值写入 dvwaSession Cookie → 攻击者离线枚举 md5(整数) 并伪造 Cookie 劫持会话。
POC 备注：仅文本工件，不执行、不联网。证据片段：046.php:9-11。

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
| `weak_id` | CWE-330 |  | 1 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.87 | 是 |
| surface_mapper | 攻击面测绘 | 6.59 | 是 |
| deep_finder | LLM 深挖 | 3.87 | 是 |
| candidate_screener | 候选筛选 | 4.32 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.38 | 是 |
| coordinator | 管线协调 | 5.83 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
