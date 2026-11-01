# 落日二号乙漏洞挖掘报告 — 20261031-012153-6c77b3

- 生成时间：2026-10-30T17:22:41.964574+00:00
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

本次汇总 3 条去重后的发现，全部集中在单文件 PHP 脚本 046.php，主题是会话标识生成不安全：规则命中 SEM-19354a0facf2（weak_id，high，会话标识由可预测递增计数器派生，CWE-330）与 SEM-7da0188b59a9（weak_crypto，medium，会话 Cookie 用 MD5 派生，实际属弱哈希 CWE-328，类型标注需纠正）；LLM 发现 LLM-e9310d5416a7（weak_random，medium，dvwaSession Cookie 由自增计数器经 MD5 生成）。最高危为 SEM-19354a0facf2：会话 ID 可预测意味着可枚举/伪造会话，属认证绕过风险。3 条均带 POC，但均为静态证据型 POC（算法/派生逻辑），不构成可动态复现的 HTTP 请求 POC；weak_crypto 一条实为 weak_hash 语义，交付时需按 CWE-328 归类。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅收到单文件 046.php（14 行，DVWA weak_id 模块片段）。已审计全部可见代码：入口为 POST 分支（第 5 行），核心逻辑为会话内自增计数器经 md5 生成 dvwaSession Cookie（第 6-11 行）。确认存在弱随机/可预测会话标识问题（weak_random，兼弱哈希与不安全 Cookie 标志）。未发现命令执行、文件包含、SQL、XSS 等汇点（文件中无相关函数）。surface_notes 中提到的 source 热点（第 2 行）实为空行，无超全局变量读取；sink_hot_files 为空与代码一致。未闭合线索：该 Cookie 的服务端校验/使用逻辑不在 code_pack 内，无法确认会话劫持的最终影响；无 php.ini/部署信息。

未覆盖 / 证据缺口：
- dvwaSession Cookie 的服务端校验与使用逻辑不在 code_pack 内
- 无部署/配置信息，无法确认公网可达性与会话机制
- 仅单文件，无法评估被 include 的公共库

## 3. Findings

### F-1: 会话标识由可预测递增计数器派生（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

046.php 第 5 行在 POST 请求下进入分支，第 6 行检查 if (!isset($_SESSION['last_session_id_high']))，第 7 行将其初始化为 0，随后第 9 行自增、第 10 行 md5 后写入 Cookie。会话标识的唯一熵来源是会话内单调递增的整数计数器，既不含随机数也不含时间戳混合，攻击者可通过观察自己的一次令牌推断计数器区间，进而预测同站点其他会话的令牌序列。校验无效的原因：代码没有任何随机化或服务端绑定校验，仅依赖“值递增”这一可预测模式。

**source / sink**

- source：request `session cookie`（046.php）
- sink：046.php:6 	if (!isset ($_SESSION['last_session_id_high'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /046（ANY）的 弱 ID / 可预测会话标识 POC。注入点：ANY 参数 session cookie；payload 使用 TARGET 占位符。

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

会话预测/会话固定：攻击者可枚举或推算 dvwaSession 值，接管他人会话，造成越权访问与身份冒用；若该 Cookie 被用于权限判定，可横向提升至其他用户上下文。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）：会话标识应来自 CSPRNG，此处来自自增整数。外部可达性：POST 到 /vulnerabilities/weak_id/ 即可触发并读取 Set-Cookie，无需认证；利用链闭合：请求 → 计数器 → md5 → Cookie → 离线预测 → 伪造。

**修复建议**

使用 random_bytes()/random_int() 或平台会话 ID 生成器产生至少 128 位熵的标识；避免使用递增计数器、时间戳、自增主键作为令牌；服务端保存令牌并校验绑定（IP/UA 可选，但核心是熵）；设置 HttpOnly、Secure、SameSite。

**验证说明**

静态证据：入口 ANY /046；source=request/session cookie；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST /vulnerabilities/weak_id/（046.php:5）→ 首次请求初始化 last_session_id_high=0（046.php:6-7）→ 后续请求自增（046.php:9）→ md5 生成 Cookie（046.php:10-11）→ 攻击者据自身令牌推算计数器并预测他人令牌 → 伪造会话。
PocWriter 建议（未采纳，缺少端点 /046）：弱 ID / 可预测会话标识（weak_id，CWE-330）的请求级 POC。046.php 第 6 行起通过自增计数器 + md5 生成 dvwaSession Cookie，攻击者可预测并伪造该 Cookie。注意：源码中并不存在名为 `session cookie` 的请求参数，该 Cookie 由服务端 setcookie 下发；因此 POC 的正确形态是「先获取一次响应拿到 dvwaSession，再按 md5(递增整数) 推算并替换 Cookie 重放」，而不是把 payload 放在 query 参数里。下面保留原请求结构并补充说明。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330；证据位于 046.php:6-11（自增计数器 + md5 派生 + setcookie 下发 dvwaSession）。原 POC 中 `?session cookie=SUNSET_PROBE` 的 query 参数在源码中无对应 getParameter 读取点，属表述偏差，已按源码修正为 Cookie 通道。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。原 poc.sh 中的 `-X ANY` 与 query 参数形式保留作参考，但实际注入通道应为 Cookie 头；请勿在未授权环境运行。

### F-2: DVWA weak_id 会话 Cookie 使用可预测的自增计数器经 MD5 生成（dvwaSession）

- **类型**：`weak_random` / CWE-330
- **严重度**：`medium`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`046.php:6-11`
- **来源**：`llm_finding`

**描述**

046.php 在 POST 请求时，把会话内自增整数 $_SESSION['last_session_id_high']（初始 0，每次 +1）直接 md5() 后写入 Cookie dvwaSession。Cookie 值完全由单调递增的小整数决定，攻击者无需任何秘密即可离线枚举 md5(1)、md5(2)、md5(3)… 预测/伪造任意用户的会话标识；同时 md5 属弱哈希（CWE-328），且 setcookie 的 secure=false、httponly=false，Cookie 可被 JS 读取并在明文 HTTP 下传输。该文件是 DVWA 的 weak session IDs 教学模块，真实部署中该 Cookie 被用作会话标识，可导致会话预测/固定。

**source / sink**

- source：session `dvwaSession`（046.php）
- sink：046.php:11 setcookie("dvwaSession", $cookie_value, ...) 于 046.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6-9` | 若会话中无 last_session_id_high 则置 0，随后自增；值域为 1,2,3,… 完全可枚举 | 整数计数器，无随机性 |  |
| 2 | `046.php:10` | 对计数器做 md5 得到 cookie_value | md5(小整数)，可离线预计算全表 |  |
| 3 | `046.php:11` | setcookie 写入 dvwaSession，secure=false、httponly=false | 可预测 Cookie 下发到客户端，且可被脚本读取 |  |

**POC**

静态证据型 POC（weak_random，CWE-330）：046.php 第 9-11 行使用自增计数器 $_SESSION['last_session_id_high'] 作为会话标识的唯一熵源，再经 md5() 派生后写入 dvwaSession Cookie。会话 ID 完全可预测（0,1,2,... 的 MD5），攻击者无需猜测即可枚举/伪造他人会话。本 POC 为离线源码证据，不发送请求。

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

会话标识可预测/可固定，攻击者可劫持或冒充其他用户会话；Cookie 未设 HttpOnly/Secure 进一步放大风险。

**CVE / CWE 论证**

CWE-338（弱随机）/CWE-330，兼 CWE-328（MD5 弱哈希）与 CWE-1004/CWE-614（Cookie 缺 HttpOnly/Secure）。外部可通过 POST 直接触发，无需认证即可观察生成规律，链闭合。

**修复建议**

使用 CSPRNG（random_bytes/random_int）生成会话标识，弃用 md5；setcookie 设置 HttpOnly=true、Secure=true、SameSite=Lax/Strict。

**验证说明**

需确认该 Cookie 在真实部署中是否被用作会话标识（而非仅演示），以及是否存在服务端对该 Cookie 的校验逻辑；本仓库仅单文件，未见校验端。
模型 POC 要点：攻击者枚举 md5(1..N) 得到候选会话标识，结合固定/预测受害者 Cookie 实现会话预测或固定。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网。若需动态佐证，可在授权环境连续请求两次并观察 dvwaSession 是否为 md5(递增整数)，但本管线不做动态验证。

### F-3: 会话 Cookie 使用 MD5 派生，属弱哈希（CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

046.php 第 5 行判断请求方法为 POST 后，第 9 行把会话变量 $_SESSION['last_session_id_high'] 自增，第 10 行执行 $cookie_value = md5($_SESSION['last_session_id_high'])，第 11 行通过 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 下发会话标识。攻击者无需提供输入：服务端每次 POST 都把可预测的整数值交给 MD5，输出即会话令牌。校验无效的根因是算法本身：MD5 无密钥、无盐、无随机性，且输入空间为连续小整数，任何拿到一个令牌的人都能离线枚举 0..N 的 md5 值反推计数器状态并预测后续令牌。注意：该处 MD5 用于生成会话标识/令牌，属 weak_hash（CWE-328），不是加密算法误用（CWE-327）；候选标题中的 weak_crypto 分类应修正为 weak_hash。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC（weak_crypto，CWE-327）：046.php 第 10 行使用 md5() 派生会话 Cookie 值。MD5 为非密码学安全哈希，且此处输入空间极小（自增整数），可被瞬间穷举/碰撞，无法提供会话标识所需的不可预测性。本 POC 为离线源码证据，不发送请求。

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

会话标识可预测/可伪造：攻击者获取任一 dvwaSession 值后可离线计算相邻计数值的 MD5，构造有效会话 Cookie 冒充其他会话，导致身份冒用与越权访问（会话固定/劫持）。不涉及 RCE 或文件读写。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 已不具备抗碰撞与抗原像强度，且此处无盐、输入为可预测递增整数，令牌熵接近零。外部可达性：setcookie 作用于 /vulnerabilities/weak_id/ 路径，任何能发起 POST 的未认证用户均可触发并观察令牌；利用链闭合：POST → 计数器自增 → md5 → Set-Cookie → 攻击者离线枚举预测。无需认证即可获得令牌样本。

**修复建议**

改用 CSPRNG 生成会话标识：如 random_bytes(32) 后 base64/hex 编码，或直接使用框架会话机制（session_regenerate_id(true)）；禁止用 MD5/SHA-1 派生任何认证令牌；为 Cookie 增加 HttpOnly、Secure、SameSite 属性（当前 setcookie 第 6、7 参数为 false, false，未设 HttpOnly/Secure）；令牌应携带足够熵并服务端存储校验。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 /vulnerabilities/weak_id/ 发起 POST（046.php:5）→ 服务端 $_SESSION['last_session_id_high'] 自增（046.php:9）→ md5() 计算（046.php:10）→ setcookie 下发 dvwaSession（046.php:11）→ 攻击者取得令牌后离线枚举 md5(0..N) 匹配并预测下一值 → 伪造 Cookie 冒充会话。
POC 备注：仅文本工件，不执行、不联网；不提供自动穷举脚本，仅说明离线映射的可行性。

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
| safety_guard | 安全防护 | 2.28 | 是 |
| surface_mapper | 攻击面测绘 | 7.52 | 是 |
| deep_finder | LLM 深挖 | 8.55 | 是 |
| candidate_screener | 候选筛选 | 4.18 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.18 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.53 | 是 |
| coordinator | 管线协调 | 6.49 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
