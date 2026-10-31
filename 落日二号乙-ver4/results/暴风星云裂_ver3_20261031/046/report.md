# 落日二号乙漏洞挖掘报告 — 20261031-010458-55c073

- 生成时间：2026-10-30T17:05:41.255142+00:00
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

本次审计范围仅 1 个 PHP 文件（046.php，14 行），共交付 3 条去重 findings，全部集中在会话标识生成环节：最高危为 SEM-19354a0facf2（weak_id，high），046.php 第 6 行会话标识基于可预测递增计数器；另有 SEM-7da0188b59a9（weak_crypto，medium，第 10 行 MD5 生成会话 Cookie 值，实为弱哈希 CWE-328）与 LLM-e9310d5416a7（weak_random，medium，第 11 行自增计数器 + md5 组合导致会话 ID 可预测）。3 条均带 POC，但均为静态证据型 POC（算法/计数器语义推断），不含 HTTP 请求响应验证，不能宣称可动态复现。攻击面测绘指出第 2 行为唯一 source 热点、sink 热点为空，该数据流去向未被任何 finding 覆盖，需人工通读确认。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已完整审计唯一文件 046.php（14 行）。该脚本为 DVWA weak_id 演示模块：POST 时自增会话计数器并 md5 后通过 setcookie 下发 dvwaSession，属弱/可预测会话 ID 生成（weak_random）。未发现命令执行、SQL、文件包含、反序列化等 sink；无输出语句故无 XSS；无配置型加密/哈希线索。surface_notes 中提到的第 2 行 source 热点在代码中实为空行，未发现对应污点参数。未覆盖：无 composer/服务器配置/端点清单，无法确认部署可达性与 dvwaSession 是否参与鉴权。

未覆盖 / 证据缺口：
- 无 Web 服务器/部署配置，无法确认对外可达路径
- 无证据表明 dvwaSession 被服务端用于身份判定，弱 ID 的实际影响待确认
- 无依赖清单，无法评估第三方组件

## 3. Findings

### F-1: 046.php 会话标识基于可预测递增计数器（弱 ID，CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

攻击者通过请求携带/接收 dvwaSession Cookie 参与会话。046.php:5 判断 POST 后，第 6 行 if (!isset($_SESSION['last_session_id_high'])) 初始化会话计数器，第 7 行置为 0，第 9 行每次请求自增，第 10 行 md5 后第 11 行写入 Cookie。校验无效的根因是标识的熵源为单调递增整数：取值空间极小且顺序可预测，攻击者无需任何秘密即可枚举出全部可能值（配合 md5 预计算表直接对应），服务端也没有绑定 IP/UA 或做二次校验。最终危险操作是把该可预测值作为会话标识下发并在后续请求中作为身份凭据使用。

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

会话预测与劫持：攻击者可枚举/推算 dvwaSession 值，冒充其他会话访问受保护页面，造成越权与敏感数据泄露；结合 Cookie 未设 Secure/HttpOnly，还可被中间人或脚本窃取。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）/CWE-340（Generation of Predictable Numbers or Identifiers）：046.php:6-7 以 0 初始化、046.php:9 单调自增作为会话标识来源，熵远低于安全要求。外部可达性：POST 请求即可触发（046.php:5），无需认证。利用链闭合：请求 → 计数器初始化/自增（046.php:6-9）→ md5（046.php:10）→ setcookie 下发（046.php:11）→ 攻击者预测并伪造 Cookie。证据为源码推断，未做动态验证。

**修复建议**

使用 CSPRNG 生成会话 ID（random_bytes / session_regenerate_id(true)），保证 ≥128 bit 熵且不可预测；登录成功后强制轮换会话 ID；将会话与用户绑定并在服务端校验；Cookie 设置 Secure、HttpOnly、SameSite=Lax/Strict；避免使用自增计数器或时间戳作为标识来源。

**验证说明**

静态证据：入口 ANY /046；source=request/session cookie；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 POST 到 046.php（046.php:5）→ 首次请求时 $_SESSION['last_session_id_high'] 被初始化为 0（046.php:6-7）→ 每次请求自增（046.php:9）→ md5 摘要（046.php:10）→ setcookie 写入 dvwaSession（046.php:11）。由于序列为 0,1,2,…，攻击者可离线生成 md5 映射表并预测/伪造任意会话的 Cookie 值，实现会话劫持。
PocWriter 建议（未采纳，缺少端点 /046）：针对 046.php:6 弱 ID / 可预测会话标识的验证 POC。会话标识由自增整数经 MD5 派生，攻击者可预测 dvwaSession Cookie 值。请求使用 TARGET 占位符，仅作文本工件。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330；漏洞位于 046.php:6，会话标识由可预测自增整数派生，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网；目标地址统一使用 TARGET 占位符；仅限授权测试。

### F-2: 046.php 使用 MD5 生成会话 Cookie 值（弱哈希，CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

攻击者无需输入任何参数：在 046.php 第 5 行判断 REQUEST_METHOD 为 POST 后，第 9 行把 $_SESSION['last_session_id_high'] 自增，第 10 行 $cookie_value = md5($_SESSION['last_session_id_high']) 用 MD5 对一个小整数计数器做摘要，第 11 行通过 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 下发。校验之所以无效，是因为 MD5 不是为不可预测性设计的：输入空间仅为递增整数（0,1,2,...），攻击者可离线枚举 md5(0)、md5(1)… 建立完整映射表，把 Cookie 值直接还原为计数器值；同时 setcookie 的 secure 与 httponly 两个标志位均为 false，Cookie 可在明文 HTTP 下传输并被脚本读取。最终危险操作是把可预测、可离线反推的摘要值当作会话标识写入客户端 Cookie。注意：该候选原始类型标注为 weak_crypto，但按 CWE 分类，MD5 用于会话标识属 weak_hash（CWE-328），不是 DES/ECB 类加密算法问题（CWE-327）。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：046.php:10 使用 MD5 派生会话 Cookie 值，MD5 属弱哈希（CWE-328），且输入空间为自增整数，进一步降低安全性。无需发送请求。

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

会话标识可预测/可伪造：攻击者枚举 md5(小整数) 即可猜出其他用户的 dvwaSession 值，进而劫持会话、以受害者身份访问 /vulnerabilities/weak_id/ 下的功能；由于 Cookie 未设 Secure/HttpOnly，还可经明文信道或 XSS 窃取。影响为身份冒用与越权访问，不涉及 RCE。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：046.php:10 对安全用途（会话 Cookie 值）使用 MD5；CWE-330/CWE-340 辅助说明熵源为可预测递增整数。外部可达性：该逻辑位于 POST 请求处理路径（046.php:5），任何未认证访问者提交 POST 即可触发并获取 Cookie，无需登录、无需特权。利用链闭合：POST → 计数器自增（046.php:9）→ md5 摘要（046.php:10）→ setcookie 下发（046.php:11）→ 攻击者离线枚举映射并伪造 Cookie。证据等级为源码推断，未做运行时验证。

**修复建议**

改用 CSPRNG 生成会话标识：如 PHP 7+ 的 bin2hex(random_bytes(32)) 或 session_regenerate_id(true)，不要对计数器做摘要；若必须保留派生关系，使用 hash_hmac('sha256', $value, $server_side_secret) 并保证密钥不泄露。同时把 setcookie 的 secure 设为 true、httponly 设为 true，并在全站强制 HTTPS；会话标识应有足够熵（≥128 bit）且不可枚举。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：未认证攻击者向 046.php 发送 POST（046.php:5 命中）→ 服务端 $_SESSION['last_session_id_high'] 自增（046.php:9）→ md5() 计算摘要得到 $cookie_value（046.php:10）→ setcookie 以 dvwaSession 名称、secure=false、httponly=false 下发（046.php:11）。攻击者侧只需预计算 md5(0..N) 表即可把任意观察到的 Cookie 反推为计数器值，并预测后续值，从而伪造/劫持会话。
POC 备注：仅文本工件，不执行、不联网；目标地址统一使用 TARGET 占位符；仅限授权测试。

### F-3: DVWA weak_id 模块使用自增计数器 md5 生成会话 Cookie（可预测会话 ID）

- **类型**：`weak_random` / CWE-330
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`046.php:9-11`
- **来源**：`llm_finding`

**描述**

046.php 在 POST 请求时把 $_SESSION['last_session_id_high'] 自增后直接 md5() 作为 Cookie `dvwaSession` 的值下发。该值完全由单调递增的整数决定（md5(1)、md5(2)、md5(3)…），不含任何随机源，攻击者可离线枚举全部候选值，从而预测/伪造其他用户的会话标识，属于弱会话 ID 生成（CWE-330/CWE-340）。

**source / sink**

- source：session `last_session_id_high`（046.php）
- sink：046.php:11 setcookie("dvwaSession", $cookie_value, ...) 第 11 行下发可预测 Cookie

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:5` | 仅当 REQUEST_METHOD 为 POST 时进入 ID 生成分支 | 触发条件成立 |  |
| 2 | `046.php:9` | 会话计数器自增，取值空间为连续整数 1,2,3,... | 整数序列，无随机性 |  |
| 3 | `046.php:10` | 对计数器做 md5，得到确定性可枚举的 Cookie 值 | md5(n)，可离线预计算 |  |
| 4 | `046.php:11` | 通过 setcookie 下发 dvwaSession，作用域 /vulnerabilities/weak_id/ | 可预测 Cookie 写入客户端 |  |

**POC**

静态证据型 POC：046.php:11 使用 md5($_SESSION['last_session_id_high']) 生成 dvwaSession Cookie 值，会话标识仅由自增整数派生，属可预测弱随机/弱标识（CWE-330）。无需发送请求，源码审计即可确认。

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

会话标识可预测，攻击者可枚举/伪造 dvwaSession，导致会话劫持或身份冒用（在依赖该 Cookie 做身份判定时）。

**CVE / CWE 论证**

CWE-330 使用不充分的随机值 / CWE-340 可预测的会话标识；无需认证即可通过 POST 触发并观察生成规律，链闭合。

**修复建议**

使用 CSPRNG（random_bytes/bin2hex 或 session_regenerate_id）生成会话标识，避免由自增计数器派生。

**验证说明**

需确认 dvwaSession 是否被服务端用于身份/会话判定；若仅作演示展示则影响降级。当前代码未见读取该 Cookie 做鉴权的逻辑。
模型 POC 要点：连续发送 POST 观察 dvwaSession 是否按 md5(1)、md5(2)… 递增，从而证明可预测性
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
POC 备注：仅文本工件，不执行、不联网；目标地址统一使用 TARGET 占位符；仅限授权测试。

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
| safety_guard | 安全防护 | 2.69 | 是 |
| surface_mapper | 攻击面测绘 | 5.12 | 是 |
| deep_finder | LLM 深挖 | 6.68 | 是 |
| candidate_screener | 候选筛选 | 4.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.63 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.76 | 是 |
| coordinator | 管线协调 | 6.35 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
