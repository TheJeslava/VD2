# 落日二号乙漏洞挖掘报告 — 20261031-012211-d37b8b

- 生成时间：2026-10-30T17:22:42.745325+00:00
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

本次汇总仅含 1 条已去重 finding：SEM-26658112c975，类型 weak_id（CWE-330），严重度 high，位于 048.php 第 6 行，会话标识由 time() 派生导致可预测，已附带 POC（静态证据型，非 HTTP 动态复现）。最高危即此条：可预测标识可能被用于会话/令牌枚举，但当前仅有源码级证据，未做动态验证。POC 齐全度：1/1 有 POC，但属静态 POC，不能宣称可动态复现。整体攻击面极窄：仓库仅 1 个 PHP 文件（9 行、145 字节），无框架、无路由、无端点清单，sink 热点为空，因此注入类（xss/path_traversal/command_injection/sql_injection/ssrf）均无证据支撑，未形成结论。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 048.php（共 9 行，已完整展示 1-9 行）。该脚本在 POST 请求时执行 $cookie_value = time(); setcookie("dvwaSession", $cookie_value);，即用秒级时间戳作为会话 Cookie 值。逐行确认：无 echo/print 输出、无 include/require、无 file_get_contents/文件读写、无 system/exec/shell_exec、无 SQL 调用、无 curl/fsockopen 等网络请求，因此不存在可闭合的注入类或文件类 source→sink 链；$_SERVER['REQUEST_METHOD'] 仅用于分支判断，未进入任何危险汇点。关于 setcookie 使用 time() 作为会话标识：这属于弱随机/可预测会话令牌（CWE-330/CWE-339）的配置型线索，但本文件既未建立服务端会话状态、也未在任何后续逻辑中读取或校验该 Cookie，缺少『令牌被服务端信任并用于鉴权』这一关键环节，无法证明可导致会话预测或认证绕过，故不单独立 finding，仅作为线索记录。文件中无硬编码凭据/密钥字符串（仅空字符串与 Cookie 名 "dvwaSession"）。未覆盖范围：无 php.ini、Web 服务器配置、composer.json、路由与部署信息，无法确认 048.php 的实际可访问路径、是否需认证、是否前置 WAF；这些缺口使任何依赖运行时环境的结论都无法闭合。

未覆盖 / 证据缺口：
- 缺少 php.ini / Web 服务器配置，无法确认错误显示与 Cookie 属性（Secure/HttpOnly/SameSite）
- 无路由与端点清单，无法确认 048.php 对外可访问路径及认证要求
- 无部署/容器编排文件，无法判断是否公网暴露及前置防护
- setcookie 使用 time() 的弱令牌线索缺少服务端读取/校验该 Cookie 的代码，链不闭合

## 3. Findings

### F-1: 会话标识由 time() 派生导致可预测（CWE-330 弱随机/可预测标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`048.php:5-6`
- **来源**：`rule`

**描述**

攻击者无需任何输入参数：在 048.php 中，当请求方法为 POST 时（第 5 行 `if ($_SERVER['REQUEST_METHOD'] == "POST")`），第 6 行直接以 `$cookie_value = time();` 生成会话标识，第 7 行通过 `setcookie("dvwaSession", $cookie_value)` 写入名为 dvwaSession 的 Cookie。该值仅为当前 Unix 时间戳（秒级），取值空间极小且单调可预测：攻击者只需知道或估算受害者提交 POST 的大致时间窗口，即可枚举该窗口内的秒级时间戳作为 dvwaSession 值。代码中不存在随机源（无 random_bytes / random_int / uniqid+熵 / 会话框架 ID），也没有对时间戳做加盐或 HMAC，因此校验环节不存在任何不可预测成分，无法阻止枚举。最终危险操作是把可预测值作为会话标识下发并（在 DVWA 语义下）用于后续请求的身份识别。

**source / sink**

- source：request `session cookie`（048.php）
- sink：048.php:6 	$cookie_value = time();

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `048.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 048.php:6 的弱 ID / 可预测会话标识（CWE-330）POC。源码在该行使用可预测的会话标识生成逻辑，攻击者可在获得一个会话标识后推测其他会话标识，从而劫持会话或枚举资源。入口为 /048（ANY 方法），注入通道为查询参数 `session cookie`。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

会话标识可预测/可枚举，攻击者可伪造或猜测他人 dvwaSession 值，实现会话劫持与身份冒用（越权访问受害者会话数据、以受害者身份执行操作）。由于标识为秒级时间戳，同一秒内多个用户还会得到相同标识，造成会话碰撞与相互串号，进一步扩大越权与数据泄露面。

**CVE / CWE 论证**

对应 CWE-330（Use of Insufficiently Random Values），亦可关联 CWE-340（Predictable Seed/Generation of Predictable Numbers or Identifiers）与 CWE-384（Session Fixation 相关会话标识问题）。外部可达性：该逻辑位于 048.php 的 POST 处理分支，任何能向该端点发送 POST 的远程用户都会触发；无需认证即可获得一个可预测标识，且预测过程不需要任何服务端信息泄露，仅依赖公开的时间基准，利用链闭合（生成点 048.php:6 → 下发点 048.php:7 → 后续请求携带该 Cookie 被当作会话标识）。证据等级为源码推断，未做运行时验证服务端是否仅以该 Cookie 判定身份。

**修复建议**

改用密码学安全的随机源生成会话标识，例如 `bin2hex(random_bytes(32))` 或直接使用框架/PHP 原生会话机制（session_start() 生成的 session_id）；禁止使用 time()、microtime()、递增计数器、mt_rand() 等可预测值作为会话标识。为 Cookie 增加安全属性：HttpOnly、Secure、SameSite=Lax/Strict，并在登录成功后轮换会话标识以防固定。服务端应校验会话标识的存在性、有效期与绑定信息（如用户代理/来源约束），并对会话标识做恒定时间比较。

**验证说明**

静态证据：入口 ANY /048；source=request/session cookie；sink=048.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 048.php 发送 POST 请求（第 5 行条件成立）→ 第 6 行 `$cookie_value = time()` 以秒级时间戳作为唯一“随机性”→ 第 7 行 `setcookie("dvwaSession", $cookie_value)` 将该可预测值作为会话 Cookie 下发 → 攻击者按目标提交时间窗口枚举秒级时间戳，构造同名 Cookie 发起请求 → 服务端以该值识别会话，导致会话劫持/身份冒用。整条链无输入过滤环节可依赖，因为弱点在于标识生成算法本身缺乏熵，而非输入校验缺失。
PocWriter 建议（未采纳，缺少端点 /048）：符合 CWE-330（Use of Insufficiently Random Values）。漏洞位于可交付代码 048.php:6，外部输入来自查询参数 `session cookie`，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；请勿自动化批量执行。request.http 中的 Content-Length 需按实际 body 长度调整。

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
| safety_guard | 安全防护 | 2.27 | 是 |
| surface_mapper | 攻击面测绘 | 5.55 | 是 |
| deep_finder | LLM 深挖 | 3.38 | 是 |
| candidate_screener | 候选筛选 | 3.1 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.3 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.49 | 是 |
| coordinator | 管线协调 | 5.51 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
