# 落日二号乙漏洞挖掘报告 — 20261031-014404-fedc70

- 生成时间：2026-10-30T17:44:40.818796+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-26658112c975（weak_id，high），指向 048.php 第 6 行附近，会话标识由 time() 派生，属可预测标识（CWE-330），已附带 POC（静态证据型，非 HTTP 动态复现）。最高危即该条 high 级 weak_id。POC 齐全度为 1/1，但需注意其证据基础是源码推断（llm_inferred/rule），未做动态验证。整体攻击面极小：仅 1 个 PHP 文件、9 行、无端点清单、无框架、无 sink 热点，审计深度受限于 code_pack 仅提供元数据与单条规则命中。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 048.php（9 行），已逐行审计。文件逻辑：第 5 行判断 REQUEST_METHOD 为 POST 时，第 6 行用 time() 生成 $cookie_value，第 7 行通过 setcookie("dvwaSession", $cookie_value) 写入会话 Cookie。该片段无任何外部输入读取（无 $_GET/$_POST/$_COOKIE/$_SERVER 用户可控值参与计算）、无 SQL/命令/文件/模板/反序列化/SSRF 类 sink、无输出回显（$html 声明后未使用），因此不存在可闭合的 source→sink 利用链。关于 setcookie 未设置 secure/httponly/samesite 以及使用 time() 作为会话标识（可预测、秒级碰撞）的线索：setcookie 调用未显式传 flags，但 PHP 5.2+ 的 httponly 默认值受 php.ini session.cookie_httponly 影响，且该 Cookie 未与任何服务端会话校验或鉴权逻辑关联（文件中无 session_start、无读取该 Cookie 的代码），无法证明可导致会话劫持或认证绕过，证据不足以构成 CVE 级发现，故不单独立项。weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 复核项均未在代码中找到对应调用（无 md5/sha1、无 mcrypt/openssl、无 rand/mt_rand/uniqid、无信任 X-Forwarded-* 头）。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- code_pack 仅含 048.php 一个文件，无路由/端点清单，无法确认该脚本在真实应用中的调用上下文与可达性
- 无 php.ini / Web 服务器配置，无法确认 session.cookie_httponly、session.use_strict_mode 等默认值，影响对 setcookie 标志位的判定
- 该 Cookie 是否在其它（未提供的）文件中被读取并用于鉴权无法确认，若存在跨文件会话校验则 time() 可预测性可能升级为会话固定/预测问题，但当前证据不足
- 无框架与依赖清单，无法评估中间件层过滤

## 3. Findings

### F-1: 048.php 会话标识由 time() 派生导致可预测（CWE-330 弱随机/可预测标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`048.php:5-6`
- **来源**：`rule`

**描述**

攻击者输入点：无需任何请求参数，攻击者只需向 048.php 发起 POST 请求（源码 048.php:5 判断 `$_SERVER['REQUEST_METHOD'] == "POST"`），服务端即进入会话标识生成分支。数据流：048.php:6 `$cookie_value = time();` 直接以当前 Unix 时间戳（秒级整数）作为会话标识值，随后 048.php:7 `setcookie("dvwaSession", $cookie_value);` 将其写入名为 dvwaSession 的 Cookie 下发客户端。校验为何无效：代码中不存在任何随机源（未使用 random_bytes / random_int / session_id 等 CSPRNG），也没有对标识做哈希、加盐或熵扩展，标识空间仅为秒级时间戳，攻击者可在目标时间窗口内枚举少量候选值。最终危险操作：该可预测值被当作会话标识使用（setcookie 下发），使会话标识可被猜测/伪造。证据等级为源码推断（llm_inferred），跨请求是否被服务端接受需运行时复核，本报告不执行验证。

**source / sink**

- source：request `session cookie`（048.php）
- sink：048.php:6 	$cookie_value = time();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `048.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /048（ANY）的 弱 ID / 可预测会话标识 POC。注入点：ANY 参数 session cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/048'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/048?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-26658112c975`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

会话标识可预测：攻击者可在已知/估计的时间窗口内枚举秒级时间戳候选值，伪造或猜测他人会话标识，进而劫持会话、冒充已认证用户访问受保护功能，造成越权与敏感数据泄露。由于标识仅由 time() 派生，同一秒内多个会话还会产生标识碰撞，进一步削弱会话隔离。

**CVE / CWE 论证**

对应 CWE-330（Use of Insufficiently Random Values），亦可关联 CWE-340（Generation of Predictable Numbers or Identifiers）。外部可达性：048.php 为可直接 HTTP 访问的脚本，POST 请求即可触发 048.php:5-7 分支，无需认证、无需特殊权限；利用链闭合：请求 → time() 生成标识（048.php:6）→ setcookie 下发 dvwaSession（048.php:7）→ 标识可预测/可碰撞。注意：跨请求接受性与实际会话绑定逻辑不在本次 code_pack 证据范围内，属证据不足部分，故不宣称已动态验证。

**修复建议**

1) 使用密码学安全随机源生成会话标识，如 PHP 的 `session_start()` 默认会话机制，或 `bin2hex(random_bytes(32))`；2) 禁止使用 time()、rand()、mt_rand()、uniqid() 等可预测值作为会话/令牌标识；3) 为 Cookie 设置 HttpOnly、Secure、SameSite 属性，并在登录成功后轮换会话标识以防固定；4) 服务端维护会话存储并校验标识有效性、绑定来源特征，设置合理过期时间。

**验证说明**

静态证据：入口 ANY /048；source=request/session cookie；sink=048.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者对 048.php 发起 POST 请求（048.php:5 命中 POST 分支）→ 服务端执行 048.php:6 `$cookie_value = time();` 以秒级时间戳作为标识 → 048.php:7 `setcookie("dvwaSession", $cookie_value);` 将该可预测值作为会话 Cookie 下发 → 攻击者在时间窗口内枚举候选时间戳即可猜测/碰撞会话标识，实现会话劫持或冒充。链中缺少 CSPRNG 与熵扩展是校验失效的根本原因。
PocWriter 建议（未采纳，缺少端点 /048）：针对 048.php:6 的弱 ID / 可预测会话标识（CWE-330）POC 文本。源码侧证据为 048.php 第 6 行对会话标识的生成/赋值逻辑，输入通道为请求参数 `session cookie`（注意：参数名本身含空格，需按 URL 编码或原样传递，不能拆成 `session` 与 `cookie` 两个参数）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /048）：对应 CWE-330（Use of Insufficiently Random Values）。证据定位在 048.php 第 6 行的会话标识生成/赋值逻辑，输入通道为请求参数 `session cookie`；属配置/逻辑型弱随机候选，无传统 HTTP 污点汇点，判定依据为算法与熵特征而非注入链。证据等级：llm_inferred（基于所给代码片段的静态推断），未经动态验证。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，按实际部署调整端口。参数名 `session cookie` 含空格，HTTP 请求行中应写作 `session%20cookie=SUNSET_PROBE`，请求体中可原样写 `session cookie=SUNSET_PROBE`。原始草稿中的 `-X ANY` 为占位方法，实际测试请替换为真实方法（GET/POST）。禁止使用破坏性载荷。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 7.97 | 是 |
| deep_finder | LLM 深挖 | 3.82 | 是 |
| candidate_screener | 候选筛选 | 3.13 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.64 | 是 |
| coordinator | 管线协调 | 5.21 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
