# 落日二号乙漏洞挖掘报告 — 20261031-173257-37e5c9

- 生成时间：2026-10-31T09:33:37.304807+00:00
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 046.php（14 行）。最高危为 SEM-19354a0facf2（weak_id，high）：会话标识由自增计数器派生，可预测（CWE-330），属配置/逻辑型弱标识问题；其次为 SEM-7da0188b59a9（weak_crypto，medium）：046.php 第 10 行使用 MD5 派生会话 Cookie 值，归类存在偏差，实为 CWE-328 弱哈希而非 CWE-327 弱加密。两条均带 POC（with_poc=2），但均为静态证据型 POC，不宣称可动态复现；weak_id 的可预测性需结合会话生成时序在代码/会话语义层面复核。攻击面测绘指出 046.php 第 2 行为请求参数入口（source 热点），但 sink_hot_files 为空，参数后续数据流未被规则覆盖，属未交付而非不存在，需人工通读 14 行确认是否进入 include/eval/system/mysqli_query/echo 等汇点。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 046.php（14 行，DVWA weak_id 教学样例片段）。第 5-11 行在 POST 时把 $_SESSION['last_session_id_high'] 自增后经 md5() 生成 dvwaSession Cookie 值，setcookie 的 secure/httponly 均为 false。该逻辑确实属于弱会话标识（可预测、MD5 无盐、无 HttpOnly/Secure），但：1) 会话 ID 由服务端自增计数器派生，攻击者无法从外部直接注入污点，不存在 source→sink 污点链；2) 代码片段未包含 session_start()、登录校验、Cookie 校验逻辑，无法证明可凭预测值完成会话劫持或认证绕过；3) 无端点清单与部署信息，无法确认对外可达性。按“宁可漏报不可误报”原则，不将其作为闭合 finding 交付。线索：若后续补充 session_start() 与基于 dvwaSession 的鉴权代码，可评估 weak_id / insecure_cookie（CWE-330/CWE-614）候选。

未覆盖 / 证据缺口：
- 缺少 session_start() 与 Cookie 校验/鉴权代码，无法闭合会话预测→劫持链
- 无端点清单与部署信息，无法确认 046.php 对外可达性
- 无 php.ini/.htaccess 等配置，无法确认 cookie 安全标志与运行环境
- sink_hot_files 为空，静态规则未命中汇点，仅能人工通读单文件

## 3. Findings

### F-1: 046.php 会话标识由自增计数器派生，可预测（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

攻击者通过向 046.php 发起 POST 请求（046.php:5 仅校验 REQUEST_METHOD == "POST"，无认证要求）驱动会话状态机：046.php:6 判断 $_SESSION['last_session_id_high'] 是否已设置，未设置时在 046.php:7 初始化为 0，随后 046.php:9 每次请求自增 1，046.php:10 以 md5 包装该值，046.php:11 写入名为 dvwaSession 的 Cookie。校验无效的根因是：标识的熵完全来自一个单调递增的小整数，既不使用 random_bytes/uniqid 等随机源，也不绑定服务端密钥；攻击者只需知道初始值 0 与自增步长 1，即可精确预测任意后续请求的 Cookie 值，无需任何暴力破解。

**source / sink**

- source：session `dvwaSession`（046.php）
- sink：046.php:6 	if (!isset ($_SESSION['last_session_id_high'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /046（POST）的弱 ID / 可预测会话标识 POC。源码 046.php 第 9-11 行将 $_SESSION['last_session_id_high'] 自增后经 md5() 写入 dvwaSession Cookie，Cookie 值随请求次数呈确定性序列，可被预测。通过保持同一会话连续 POST 并比较 Set-Cookie 中的 dvwaSession 值验证可预测性。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/046'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**

```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-19354a0facf2`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

会话固定/会话预测：攻击者可预先算出下一个 dvwaSession 值并植入受害者浏览器（会话固定），或在观察到一次合法值后推算后续值，从而劫持会话、以受害者身份访问 /vulnerabilities/weak_id/ 相关功能，造成越权与数据泄露。不涉及命令执行或文件系统操作。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）：安全决策所依赖的会话标识来自可预测的计数器而非 CSPRNG。外部可达性：046.php:5 的 POST 分支对外暴露，无需认证；利用链闭合：POST → 046.php:6/7 初始化 → 046.php:9 自增 → 046.php:10 派生 → 046.php:11 下发 Cookie → 攻击者预测/固定。与 SEM-7da0188b59a9 的区别在于本条根因是随机性不足（CWE-330），MD5 只是放大可预测性的包装层。

**修复建议**

1) 使用 CSPRNG 生成会话标识：bin2hex(random_bytes(32))，或直接依赖 PHP 原生 session 机制并调用 session_regenerate_id(true) 在登录后轮换；2) 禁止以自增计数器、时间戳、mt_rand 等可预测源派生安全令牌；3) 服务端保存令牌→用户的映射并校验来源 IP/UA 指纹，设置绝对与空闲超时；4) 下发 Cookie 时启用 secure、httponly 与 SameSite，降低固定攻击面。

**验证说明**

静态证据：入口 POST /046；source=session/dvwaSession；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 POST /vulnerabilities/weak_id/ → 046.php:5 通过方法判断 → 046.php:6 检测 last_session_id_high 未设置 → 046.php:7 置 0 → 046.php:9 自增为 1 → 046.php:10 md5(1) → 046.php:11 setcookie("dvwaSession", ...) → 攻击者据 0/1 步长推算后续值并实施会话固定或劫持。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330（Use of Insufficiently Random Values）与 CWE-328（弱哈希）叠加；漏洞位于 046.php:9-11，会话标识来源为自增计数器，source→sink 链静态闭合，具备远程触发条件。
POC 备注：仅限授权测试；所有请求目标使用 TARGET 占位符，不执行、不联网。连续请求必须复用同一 Cookie jar 以保持会话，否则计数器重置将影响序列观察。若响应未返回 Set-Cookie，需补充源码/路由确认 dvwaSession 的实际下发位置。

### F-2: 046.php 使用 MD5 派生会话 Cookie 值（CWE-327 归类偏差，实为 CWE-328 弱哈希）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

攻击者无需输入任何参数：服务端在 046.php:9 将 $_SESSION['last_session_id_high'] 自增，随后在 046.php:10 用 md5($_SESSION['last_session_id_high']) 生成 $cookie_value，并在 046.php:11 通过 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 下发。校验无效的原因在于：被哈希的输入本身是一个从 0 开始的小整数计数器（046.php:7 初始化为 0），MD5 只是对该整数做无密钥的单向压缩，不引入任何熵，也不提供完整性保护；攻击者可直接对 0、1、2… 预先计算 MD5 字典，完全枚举 Cookie 值空间。此外 setcookie 的 secure 与 httponly 两个标志位均显式为 false（046.php:11），Cookie 可在明文 HTTP 下传输并被脚本读取。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：046.php 第 10 行使用 md5($_SESSION['last_session_id_high']) 生成 dvwaSession Cookie 值，属于弱哈希（CWE-328，MD5 无盐、无密钥），且该值直接作为会话标识写入 Cookie（第 11 行 setcookie，HttpOnly=false、Secure=false）。无需发送请求即可在源码层确认算法选择。

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

会话标识可预测/可伪造：攻击者枚举 md5(0..N) 即可猜出合法 dvwaSession 值，配合 secure=false、httponly=false 可在明文信道或 XSS 场景下窃取并复用会话，导致身份冒用与越权访问 /vulnerabilities/weak_id/ 下的受保护功能。不构成 RCE 或文件读写。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 用于生成安全敏感的会话令牌，属口令/令牌类安全用途，抗碰撞与抗原像强度不足。外部可达性：046.php:5 仅要求 REQUEST_METHOD == "POST"，无需认证即可触发令牌生成与下发；利用链闭合：POST 请求 → 计数器自增（046.php:9）→ md5 派生（046.php:10）→ setcookie 下发（046.php:11）→ 攻击者离线枚举比对。注意：本条原始归类为 weak_crypto（CWE-327），按证据应更正为 weak_hash（CWE-328），算法为 MD5 而非 DES/ECB 类加密算法缺陷。

**修复建议**

1) 停止使用 MD5 派生会话标识，改用 CSPRNG：random_bytes(32) 或 session_regenerate_id(true) 生成服务端会话 ID；2) 若必须下发自定义 Cookie，使用 hash_hmac('sha256', $value, $server_side_secret) 并保证 $value 含足够熵；3) 将 setcookie 的 secure 与 httponly 置为 true，并补充 SameSite=Lax/Strict；4) 服务端维护令牌白名单并设置短有效期与一次性使用，避免纯计数器派生。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST /vulnerabilities/weak_id/ → 046.php:5 方法判断通过 → 046.php:6-7 首次请求将 last_session_id_high 置 0 → 046.php:9 自增为 1 → 046.php:10 md5(1) 得到固定值 c4ca4238a0b923820dcc509a6f75849b → 046.php:11 setcookie 下发 dvwaSession（secure=false, httponly=false）→ 攻击者离线计算 md5(1..N) 字典并伪造/预测 Cookie。
POC 备注：本项为静态证据，不生成可执行请求；仅保留源码行号引用。注意：该 finding 类型为 weak_hash（CWE-328），不应与 weak_crypto（CWE-327）混记。

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
| safety_guard | 安全防护 | 3.23 | 是 |
| surface_mapper | 攻击面测绘 | 5.34 | 是 |
| deep_finder | LLM 深挖 | 3.03 | 是 |
| candidate_screener | 候选筛选 | 3.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.69 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.34 | 是 |
| coordinator | 管线协调 | 6.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
