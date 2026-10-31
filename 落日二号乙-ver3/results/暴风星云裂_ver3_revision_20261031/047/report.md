# 落日二号乙漏洞挖掘报告 — 20261031-012200-aa2518

- 生成时间：2026-10-30T17:22:33.995464+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\047.zip`
- 输入模式：`zip`
- SHA256：`3fb7cef196d058e1429319161506d9b7757247c40a8879ee94ca463b3d47eead`
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

本次汇总仅含 1 条已去重 finding：047.php 的 weak_id（CWE-330，会话标识可预测/弱 ID），严重度 high，带 POC（静态证据型，非 HTTP 动态复现）。该文件为 13 行单文件 PHP 脚本，无框架、无路由、无端点清单，sink_hot_files 为空，管线未识别明确汇点，因此除该 weak_id 外无其他可交付漏洞结论。最高危即该 weak_id。POC 齐全度为 1/1，但需注意其证据等级为规则/静态推断，未经动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 378 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 047.php（13 行），已逐行审计。该脚本仅在 POST 请求时把 $_SESSION['last_session_id'] 自增后写入 Cookie dvwaSession，无任何外部输入（$_GET/$_POST/$_COOKIE/$_REQUEST/Header）参与数据流，也无 include/require、文件读写、eval/assert、system/exec、SQL 查询或输出回显等汇点，因此不存在可闭合的 source→sink 污点链。配置类候选复核：setcookie("dvwaSession", $cookie_value) 位于第 11 行，未设置 HttpOnly/Secure/SameSite 标志，属 insecure_cookie 的实现缺陷，但该 Cookie 值仅为会话内自增计数器（非会话标识、非认证凭据），且脚本未读取该 Cookie 做任何授权判断，无法形成账户接管或权限提升的利用链，按“宁可漏报不可误报”原则不单独立项，仅作为线索记录。文件中未出现 md5/sha1/hash、rand/mt_rand/uniqid、mcrypt/openssl_encrypt，也未信任 X-Forwarded-For 等客户端头，weak_hash/weak_random/weak_crypto/trust_boundary 均无证据。未覆盖范围：无 php.ini/Web 服务器配置、无 composer.json、无路由与认证机制说明，无法确认该脚本的实际暴露路径与运行环境；endpoints 为空，无法判断是否经 Web 服务器可达。

未覆盖 / 证据缺口：
- 缺少 php.ini / Web 服务器配置 / .htaccess，无法确认危险函数禁用与脚本暴露方式
- endpoints 为空，无法确认 047.php 的访问路径、请求方法与是否需要认证
- 无 composer.json 等依赖清单，无法评估第三方组件风险
- 无外部 AWVS/动态扫描证据，全部结论为源码级静态推断
- 第 11 行 setcookie 缺失 HttpOnly/Secure/SameSite 属实现缺陷，但因 Cookie 值非敏感凭据且未被服务端读取鉴权，利用链不闭合，未立项

## 3. Findings

### F-1: 047.php 会话标识可预测/弱 ID（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`047.php:5-6`
- **来源**：`rule`

**描述**

证据仅覆盖 047.php 第 5-6 行：第 5 行判断 `$_SERVER['REQUEST_METHOD'] == "POST"`，第 6 行 `if (!isset ($_SESSION['last_session_id'])) {`，第 7 行将 `$_SESSION['last_session_id']` 初始化为 0。候选声称会话标识由时间或递增值派生，但输入片段中并未出现任何生成会话 ID 的代码（无 `session_id()`、`mt_rand()`、`uniqid()`、`time()` 等调用），也没有 `session_start()` 或 Cookie 写入点。因此「攻击者从哪里输入、经过哪些变量、最终到达哪个危险操作」这一链条在给定证据内无法闭合：source 被标注为 request `session cookie`，但片段中不存在读取该 Cookie 的语句，sink 指向的 `isset($_SESSION['last_session_id'])` 只是会话内状态判断，本身不产生可预测标识。

**source / sink**

- source：request `session cookie`（047.php）
- sink：047.php:6 	if (!isset ($_SESSION['last_session_id'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `047.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /047（ANY）的 弱 ID / 可预测会话标识 POC。注入点：ANY 参数 session cookie；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/047'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 弱 ID / 可预测会话标识 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/047?session cookie=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-f8846702c19b`
- 风险提示：finding 来源为 Cookie，但 POC 未发送 Cookie 请求头, POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该弱点成立，攻击者可预测或枚举其他用户的会话标识，从而劫持会话、以受害者身份访问受保护功能（越权/身份冒用）。但基于当前片段，无法确认存在可预测的会话 ID 生成逻辑，实际影响证据不足。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）。外部可达性：第 5 行表明代码在 POST 请求路径上执行，具备 HTTP 可达性；无需认证：片段中未见任何鉴权检查。但利用链未闭合——缺少会话 ID 生成算法、缺少 Cookie 下发与接受逻辑、缺少跨请求预测验证，故不能据此认定可利用。

**修复建议**

1) 使用框架或语言内置的安全会话 ID 生成器（如 PHP 默认 `session_start()` 的 CSPRNG 会话 ID），不要自行用时间戳/自增计数构造标识；2) 显式设置 `session.cookie_httponly=1`、`session.cookie_secure=1`、`session.use_strict_mode=1`、`session.sid_length>=32`、`session.sid_bits_per_character>=5`；3) 登录成功后调用 `session_regenerate_id(true)` 防固定；4) 若确需自定义 ID，使用 `random_bytes()` 生成并做恒定时间比较。

**验证说明**

静态证据：入口 ANY /047；source=request/session cookie；sink=047.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：给定片段仅显示：POST 请求进入 047.php:5 → 047.php:6 检查 `$_SESSION['last_session_id']` 是否已设置 → 047.php:7 未设置时置 0。片段内没有从请求 Cookie 读取会话标识的代码，也没有生成会话标识的代码，因此「攻击者提供/预测会话 ID → 服务端接受 → 越权」的链路在证据层面缺失关键环节。需补充会话 ID 生成函数、Cookie 读写点及跨请求验证结果后才能确认。
PocWriter 建议（未采纳，缺少端点 /047）：针对 047.php:6 的弱会话标识（weak_id / CWE-330）POC。源码在该行使用可预测的会话标识生成/取值逻辑，攻击者可在已知或可枚举的会话标识空间内猜测有效会话，从而劫持会话或绕过身份校验。注入通道为请求参数 `session cookie`（参数名含空格，需 URL 编码为 `session%20cookie`），payload 使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /047）：符合 CWE-330（使用不充分的随机值）。漏洞位于 047.php:6，外部输入经参数 `session cookie` 进入会话标识逻辑，静态链路闭合且未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。原始草稿中的 `-X ANY` 非合法 HTTP 方法，已改为显式 GET；参数名含空格，请求行中必须编码为 `session%20cookie`，不可写成 `session cookie=...` 或 `param=...`。步骤 3 的枚举应严格限制次数，避免对目标造成负载。

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
| safety_guard | 安全防护 | 2.89 | 是 |
| surface_mapper | 攻击面测绘 | 8.11 | 是 |
| deep_finder | LLM 深挖 | 2.97 | 是 |
| candidate_screener | 候选筛选 | 3.04 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.98 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.49 | 是 |
| coordinator | 管线协调 | 4.84 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
