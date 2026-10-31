# 落日二号乙漏洞挖掘报告 — 20261031-014357-05a9e5

- 生成时间：2026-10-30T17:44:45.229071+00:00
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

本次汇总 4 条已去重发现，全部集中在单文件 046.php，均为配置/算法型弱随机与 Cookie 标志问题：最高危为 SEM-19354a0facf2（weak_id，high，046.php 第 6 行，会话标识可预测，CWE-330）；其余为 LLM-e9310d5416a7（weak_random，medium，第 11 行，dvwaSession 由自增计数器经 md5 生成）、SEM-7da0188b59a9（weak_crypto，medium，第 10 行，弱哈希用于会话标识，CWE-328）、LLM-70200a605a7e（insecure_cookie，low，第 11 行，dvwaSession 未设 HttpOnly/Secure）。4 条均带 POC，但均为静态证据型 POC（算法/标志位/会话语义），不宣称可动态复现；其中 weak_id 与 weak_random 的“可预测性”需结合会话生成时序在代码/会话语义层面复核。未发现 HTTP 污点型注入类发现，且 surface_notes 明确 sink_hot_files 为空、源码正文未随清单提供，因此命令执行、SQL、文件包含、XSS 等攻击面本轮未覆盖，不能据此断言不存在。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：2 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 046.php（14 行），已逐行审计。该文件为 DVWA weak_id 模块：POST 时对 $_SESSION['last_session_id_high'] 自增并 md5 后写入 dvwaSession Cookie。发现两条配置/算法型问题：会话标识由自增整数 md5 派生（weak_random，可预测）与 Cookie 未设 HttpOnly/Secure（insecure_cookie）。未发现命令执行、SQL、文件包含、反序列化、SSRF 等汇点；无 echo 输出用户输入，故无 XSS。surface_notes 中提到的 source_hot_files 第 2 行实为空行，未发现外部参数读取点，与元数据描述不符，已按实际源码为准。未覆盖范围：无部署配置、无 php.ini、无其它文件，无法评估 allow_url_include 等运行时条件。

未覆盖 / 证据缺口：
- 无部署/php.ini 配置，无法判断 Cookie 传输层与包含行为
- dvwaSession 是否被服务端作为真实鉴权标识未在 code_pack 中体现
- surface_notes 声称第 2 行为外部输入读取点，但实际第 2 行为空行，元数据与源码不一致

## 3. Findings

### F-1: 046 弱 ID / 可预测会话标识（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

在 046.php 中，POST 请求处理分支（第 5 行）读取会话状态 $_SESSION['last_session_id_high']（第 6 行），若未设置则初始化为 0（第 7 行），随后在第 9 行执行 $_SESSION['last_session_id_high']++ 自增，并在第 10 行用 md5() 对该自增后的整数做哈希，第 11 行通过 setcookie("dvwaSession", $cookie_value, ...) 下发名为 dvwaSession 的 Cookie。该会话标识完全由单调递增的整数派生，没有任何随机源（无 random_bytes/random_int/uniqid 等），因此攻击者只需观察自己或他人一次下发的 dvwaSession 值，即可离线枚举 md5(1)、md5(2)、md5(3)… 预测后续所有会话标识。校验无效的原因在于：标识空间是连续小整数，哈希只是确定性变换，不引入熵，无法阻止预测。最终危险操作是第 11 行 setcookie 下发的会话标识被服务端当作会话凭据接受。

**source / sink**

- source：request `session cookie`（046.php）
- sink：046.php:6 	if (!isset ($_SESSION['last_session_id_high'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /046 路由的弱 ID / 可预测会话标识验证。源码 046.php:9-11 显示 dvwaSession cookie 由自增计数器经 md5 派生，因此连续请求可观察到可预测的 cookie 序列。原草稿中的注入点写法 `session cookie` 与源码不符（源码无 getParameter/getCookie 读取该名），此处按源码事实修正为观察 Set-Cookie 响应头。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/046'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/046?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-19354a0facf2`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

会话标识可预测/可枚举，攻击者可伪造或猜测其他用户的 dvwaSession 值，导致会话劫持与身份冒用（越权访问受害者会话）。由于标识按自增序列生成，攻击者甚至可批量预生成候选 Cookie 值进行撞库。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）。外部可达性：046.php 通过 HTTP POST 直接可达，无需认证即可触发第 5-11 行逻辑并获取 Cookie；利用链闭合：请求 → $_SESSION['last_session_id_high'] 自增（第 9 行）→ md5 确定性变换（第 10 行）→ setcookie 下发（第 11 行）→ 服务端接受可预测标识。证据等级为源码推断，未做运行时验证服务端是否严格以该 Cookie 作为唯一会话凭据。

**修复建议**

改用密码学安全的随机源生成会话标识，例如 random_bytes(32) 后 base64/hex 编码，或直接使用框架的 session_regenerate_id(true)；禁止使用自增计数器或时间戳派生会话 ID；服务端应校验会话标识长度与熵，并在登录成功后轮换会话 ID；Cookie 设置 HttpOnly、Secure、SameSite 属性。

**验证说明**

静态证据：入口 ANY /046；source=request/session cookie；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 046.php 发送 POST 请求 → 第 6 行检查 $_SESSION['last_session_id_high'] 是否存在 → 第 9 行自增 → 第 10 行 md5(自增整数) 生成 cookie_value → 第 11 行 setcookie 下发 dvwaSession。攻击者观察到任一 dvwaSession 后，可枚举相邻整数对应的 md5 值预测后续标识，从而伪造会话。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330；证据位于 046.php:9-11，source 为自增计数器，sink 为 setcookie 写入 dvwaSession。
POC 备注：仅文本工件；如需手工复现，请自行替换 TARGET 并在授权环境执行，管线不执行。

### F-2: DVWA weak_id 会话标识可预测：dvwaSession 由自增计数器 md5 生成

- **类型**：`weak_random` / CWE-330
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`046.php:9-11`
- **来源**：`llm_finding`

**描述**

046.php 在每次 POST 请求时把 $_SESSION['last_session_id_high'] 自增（第 9 行），然后直接对其做 md5 作为 Cookie 值 dvwaSession（第 10-11 行）。该值完全由单调递增的整数决定，不含任何随机源（无 random_bytes / random_int / uniqid / mt_rand），因此攻击者只要获得任意一个 dvwaSession 值，即可通过 md5(1..N) 穷举出全部历史与未来会话标识，从而伪造/预测其他用户的会话标识，属于可预测会话标识（CWE-330 / CWE-340，弱随机）。

**source / sink**

- source：session `last_session_id_high`（046.php）
- sink：046.php:11 setcookie("dvwaSession", $cookie_value, ...) 第 11 行，写入可预测的会话标识

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:5` | POST 请求进入分支，触发会话标识生成逻辑 | 外部请求触发 |  |
| 2 | `046.php:9` | 会话计数器自增，值域为连续整数 1,2,3,... | 整数 N（可预测、单调递增） |  |
| 3 | `046.php:10` | 对整数 N 做 md5，得到确定性输出 | md5(N)，无随机熵 |  |
| 4 | `046.php:11` | 将 md5(N) 作为 dvwaSession Cookie 下发 | 可预测 Cookie 值 |  |

**POC**

046.php:9-11 使用自增计数器 $_SESSION['last_session_id_high'] 作为会话标识来源，再经 md5() 派生 cookie 值，属于可预测的弱随机/弱标识生成（CWE-330）。本 POC 为静态证据型，仅记录源码事实，不发送请求。

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
- POC 目录：`poc/LLM-e9310d5416a7`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

会话标识可预测，攻击者可枚举/伪造其他用户的会话标识，导致会话劫持或身份冒用。

**CVE / CWE 论证**

CWE-330 使用不充分的随机值 / CWE-340 可预测的随机数。链闭合：POST 触发 → 自增整数 → md5 → setcookie，全程无随机源，外部可直接触发。

**修复建议**

使用密码学安全随机源生成会话标识，例如 bin2hex(random_bytes(16))，不要用自增计数器或 md5 派生。

**验证说明**

需确认该 Cookie 是否被服务端作为会话标识校验（DVWA 中该模块为演示性质，实际鉴权可能仍依赖 PHPSESSID），若仅作展示则实际影响降低。
模型 POC 要点：攻击者先获取一次 dvwaSession 值，反推当前计数器 N，再离线计算 md5(N+1)、md5(N+2)… 预测后续会话标识。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：静态证据，不生成可执行脚本；不执行、不联网。

### F-3: 046 弱哈希用于会话标识（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.5`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

046.php 第 10 行 $cookie_value = md5($_SESSION['last_session_id_high']); 使用 MD5 对自增会话计数器做哈希，并在第 11 行作为 dvwaSession Cookie 值下发。MD5 属于已被攻破的弱哈希算法（存在碰撞与快速暴力枚举），且此处输入空间仅为连续小整数，攻击者可瞬间穷举全部候选值。校验无效的原因：MD5 不提供任何抗预测性，哈希输出与输入一一对应且可离线计算，无法作为安全凭据的保护手段。最终危险操作是第 11 行 setcookie 将 MD5 派生值作为会话标识下发并被服务端接受。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

046.php:10 使用 md5($_SESSION['last_session_id_high']) 生成会话 cookie 值。md5 为非密码学安全哈希且此处输入空间极小（自增整数），可被轻易枚举/碰撞（CWE-328）。注意：该问题本质为弱哈希，与 weak_crypto（CWE-327，加密算法误用）应区分。静态证据型 POC。

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

会话标识可被离线穷举/碰撞伪造，导致会话劫持、身份冒用与越权访问。攻击者无需在线爆破即可预计算 md5(1..N) 映射表，命中任意用户会话。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）。外部可达性：046.php 的 POST 分支无需认证即可触发第 10-11 行并取得 Cookie；利用链闭合：HTTP 请求 → 自增计数器（第 9 行）→ md5 弱哈希（第 10 行）→ setcookie 下发（第 11 行）→ 服务端接受。注意此处为弱哈希（CWE-328），非弱加密算法（CWE-327）。证据为源码推断，未验证服务端会话校验实现。

**修复建议**

停止使用 MD5/SHA-1 派生会话标识；改用 CSPRNG（random_bytes/random_int）直接生成高熵令牌，或使用 HMAC-SHA-256 配合服务端密钥；对会话标识实施服务端存储与比对，登录后轮换；Cookie 增加 HttpOnly、Secure、SameSite。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 POST 至 046.php → 第 9 行 $_SESSION['last_session_id_high']++ → 第 10 行 md5() 生成 cookie_value → 第 11 行 setcookie 下发 dvwaSession。攻击者离线计算 md5(1..N) 即可预测/伪造会话标识。
POC 备注：静态证据，不生成可执行脚本。

### F-4: dvwaSession Cookie 未设置 HttpOnly 与 Secure 标志

- **类型**：`insecure_cookie` / CWE-614
- **严重度**：`low`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`046.php:11-11`
- **来源**：`llm_finding`

**描述**

第 11 行 setcookie 的第 6、7 个参数分别为 false、false，即 httponly=false、secure=false，导致会话标识 Cookie 可被 JavaScript 读取且可在明文 HTTP 下传输，一旦存在 XSS 即可直接窃取该 Cookie。

**source / sink**

- source：config `dvwaSession`（046.php）
- sink：046.php:11 setcookie 第 11 行，secure 与 httponly 均为 false

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:11` | setcookie 显式将 secure 与 httponly 置为 false | Cookie 缺少安全标志 |  |

**POC**

046.php:11 的 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 中 secure 与 httponly 两个标志位均为 false，会话 cookie 可经明文 HTTP 传输且可被 JavaScript 读取（CWE-614/CWE-1004）。静态证据型 POC。

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
- POC 目录：`poc/LLM-70200a605a7e`
- 风险提示：POC 未使用 TARGET 占位符，请人工检查目标地址
- 执行状态：未执行（`executed=False`）

**影响**

会话 Cookie 可被脚本读取并在明文信道传输，配合 XSS 或中间人可窃取会话。

**CVE / CWE 论证**

CWE-1004 缺少 HttpOnly / CWE-614 敏感 Cookie 未设 Secure。配置型问题，外部可观测。

**修复建议**

setcookie 的 secure 与 httponly 参数设为 true。

**验证说明**

需确认该 Cookie 是否承载实际鉴权语义；若仅为演示值则影响有限。
模型 POC 要点：观察响应头 Set-Cookie 是否缺少 HttpOnly/Secure。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：静态证据，不生成可执行脚本。

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
| `weak_random` | CWE-330 |  | 1 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 1 |
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
| safety_guard | 安全防护 | 2.46 | 是 |
| surface_mapper | 攻击面测绘 | 7.4 | 是 |
| deep_finder | LLM 深挖 | 9.74 | 是 |
| candidate_screener | 候选筛选 | 4.56 | 是 |
| vulnerability_analyzer | 漏洞分析 | 8.04 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.87 | 是 |
| coordinator | 管线协调 | 6.45 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
