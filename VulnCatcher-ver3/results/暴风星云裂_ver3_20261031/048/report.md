# 落日二号乙漏洞挖掘报告 — 20261031-010502-4eb4e7

- 生成时间：2026-10-30T17:05:33.384721+00:00
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

本次汇总仅含 1 条已去重 finding：048.php 第 6 行附近会话标识由 time() 派生，类型 weak_id（CWE-330 可预测会话标识），严重度 high，带 POC（静态证据型，非 HTTP 动态复现）。仓库为单文件 9 行 PHP 脚本，无框架、无路由、无端点清单，sink_hot_files 为空，自动数据流未命中，注入类风险无法从现有证据确认。最高危即该 weak_id。POC 齐全度：1/1 有 POC，但属静态证据 POC，不能宣称可动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 048.php（共 9 行，全部可见）。该脚本仅在 POST 请求时执行 setcookie("dvwaSession", time())，无任何请求参数读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER 用户可控值进入数据流），无 echo/print 输出、无 include/require、无文件读写、无 exec/system/反序列化/模板/SQL 调用，因此不存在可闭合的 source→sink 注入链。关于配置类候选：第 6-7 行使用 time() 生成会话 Cookie 值，属于可预测的弱随机/弱会话标识（CWE-330/CWE-340 类），且 setcookie 未设置 HttpOnly/Secure/SameSite 标志（CWE-1004/CWE-614 类）；但该脚本本身不读取、不校验、不依赖该 Cookie 做任何认证或授权判断，code_pack 内看不到任何消费该 Cookie 的代码，无法证明可导致会话劫持或认证绕过，利用链不闭合，故不单独立 finding，仅作为线索记录。同理，无硬编码密钥、无弱加密/弱哈希调用、无信任 X-Forwarded-* 或 Host 头的访问控制逻辑。未覆盖范围：无 composer.json、无 Web 服务器/路由配置、无 .htaccess，无法确认 048.php 的实际 URL 映射与是否公网暴露；endpoints 为空，攻击面只能停留在文件级；无 sink_hot_files 自动数据流证据。若后续能提供消费 dvwaSession Cookie 的其它文件（如 DVWA 的登录/会话校验代码），可重新评估弱会话标识与 Cookie 标志缺失是否构成可利用链。

未覆盖 / 证据缺口：
- 无 Web 服务器/路由配置，无法确认 048.php 的访问路径与暴露面
- endpoints 为空，参数名与请求方式只能从源码推断为 POST
- 无消费 dvwaSession Cookie 的代码，弱会话标识与 Cookie 标志缺失无法闭合为可利用链
- 无依赖清单，无法评估第三方组件 CVE
- 无数据库/日志/认证配置，无法判断二次注入

## 3. Findings

### F-1: 会话标识由 time() 派生导致可预测（CWE-330 弱 ID / 可预测会话标识）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`048.php:5-6`
- **来源**：`rule`

**描述**

攻击者输入点：HTTP 请求中的会话 Cookie（服务端下发的 dvwaSession）。在 048.php 第 5 行，仅当 REQUEST_METHOD 为 POST 时进入分支；第 6 行 `$cookie_value = time()` 直接以当前 Unix 时间戳（秒级整数）作为会话标识值；第 7 行 `setcookie("dvwaSession", $cookie_value)` 将其写入客户端 Cookie。整个生成过程没有任何随机源（未使用 random_bytes / random_int / CSPRNG），也没有服务端会话存储与校验，标识空间仅为秒级时间戳，取值高度可枚举、可预测。校验无效的原因：代码中不存在任何对标识唯一性、熵值或服务端绑定关系的检查，标识完全由可预测的时间决定，因此攻击者无需猜测随机数，只需枚举候选时间戳即可命中有效标识。最终到达的危险操作是 setcookie 下发的会话标识被用于标识会话身份，导致会话标识可被预测/伪造。

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

会话标识可预测：攻击者可在目标时间窗口内枚举秒级时间戳，构造或猜测他人/后续会话的 dvwaSession 值，从而劫持会话、冒充已认证用户身份，造成越权访问与身份冒用。由于标识空间仅为秒级时间戳，实际可枚举范围极小，利用成本低。

**CVE / CWE 论证**

对应 CWE-330（Use of Insufficiently Random Values）/ 弱会话标识。外部可达性：048.php 通过 HTTP POST 请求即可触发，无需认证、无需本地访问；利用链闭合：请求 → 第 5 行方法判断 → 第 6 行 time() 生成标识 → 第 7 行 setcookie 下发，链路在单文件内完整闭合。证据等级为源码推断（llm_inferred），未做运行时验证，服务端是否在其他位置接受该 Cookie 作为会话凭据需运行时复核。

**修复建议**

使用密码学安全的随机源生成会话标识，例如 PHP 7+ 的 `bin2hex(random_bytes(32))` 或 `session_create_id()`/原生 session 机制；不要使用 time()、rand()、mt_rand()、uniqid() 等可预测值。将会话标识存储在服务端并校验其存在性与绑定关系；Cookie 设置 HttpOnly、Secure、SameSite 属性；会话建立与权限提升后重新生成标识以防固定/预测。

**验证说明**

静态证据：入口 ANY /048；source=request/session cookie；sink=048.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 048.php 发送 POST 请求（第 5 行条件成立）→ 第 6 行 `$cookie_value = time()` 以秒级时间戳作为会话标识 → 第 7 行 `setcookie("dvwaSession", $cookie_value)` 下发该标识。由于标识仅由可预测时间派生且无随机性与服务端校验，攻击者可在时间窗口内枚举候选值并伪造/预测会话标识，进而劫持会话。
PocWriter 建议（未采纳，缺少端点 /048）：针对 048.php:6 的弱 ID / 可预测会话标识（CWE-330）问题。源码在该行使用可预测的会话标识生成/取值逻辑，攻击者可在获得一个会话标识后推测其他用户的会话标识，从而劫持会话或枚举资源。POC 仅用于授权测试，目标统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /048）：符合 CWE-330（Use of Insufficiently Random Values）。证据位于可交付代码 048.php:6，会话标识生成/取值缺乏足够熵，属配置/逻辑型弱点，无需 HTTP 污点即可成立；具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试前需替换为授权目标。建议先采集多个会话标识样本做熵与序列分析，再构造预测值验证，避免对生产环境造成干扰。

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
| safety_guard | 安全防护 | 2.73 | 是 |
| surface_mapper | 攻击面测绘 | 6.28 | 是 |
| deep_finder | LLM 深挖 | 3.97 | 是 |
| candidate_screener | 候选筛选 | 3.27 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.44 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.7 | 是 |
| coordinator | 管线协调 | 3.95 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
