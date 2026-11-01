# 落日二号乙漏洞挖掘报告 — 20261031-214906-4e3896

- 生成时间：2026-10-31T13:49:57.543745+00:00
- 输入：`$WORKSPACE\暴风星云裂\046.zip`
- 输入模式：`zip`
- SHA256：`9d98d51f3b7f8ead39aea7b49f01b44680c06b424521a0bf068da8c5c5a86a40`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 046.php：一条 high 级 weak_id（会话标识由递增计数器派生，可预测，CWE-330，行 1-6），一条 medium 级 weak_crypto（实际为 MD5 弱哈希，CWE-328，行 1-10）。最高危为 SEM-19354a0facf2，可预测会话标识可能导致会话劫持/伪造。两条均带 POC，但均为静态证据型 POC（源码级推导），不宣称可动态复现。本次无二次注入链、无 HTTP 端点证据，攻击面测绘未提供 046.php 实际代码片段，source 到 sink 数据流无法确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 489 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 046.php（14 行，DVWA weak_id 模块片段）。已逐行审计：第 5 行判断 POST 请求，第 6-9 行使用 $_SESSION['last_session_id_high'] 自增计数器，第 10 行 md5() 对该计数器做哈希生成 cookie 值，第 11 行 setcookie 写入 dvwaSession，路径 /vulnerabilities/weak_id/，domain 取 $_SERVER['HTTP_HOST']，secure=false、httponly=false。<br><br>未产出 finding 的理由：<br>1) 该片段不存在任何外部可控输入进入危险汇点：$_SESSION 值由服务端自增产生，$_SERVER['HTTP_HOST'] 仅作为 setcookie 的 domain 参数，不构成 SQL/命令/文件/反序列化/模板注入链；无 echo/print 输出，无 include/require，无数据库或文件操作，无 SSRF 汇点。<br>2) 可讨论的候选是 weak_id / weak_random（CWE-330/CWE-340）：会话标识由可预测的单调递增整数经 md5 派生，攻击者可枚举 dvwaSession 值。但本片段中该 cookie 未被任何鉴权逻辑消费（无 session_id 校验、无登录判定），无法在给定代码内闭合“预测 cookie → 冒充会话/越权”的利用链；且 md5 在此处是确定性派生而非口令哈希，单独报 weak_hash 证据不足。按“宁可漏报不可误报”原则不单独立项。<br>3) insecure_cookie 线索：第 11 行 setcookie 显式传 secure=false、httponly=false，属真实缺陷，但缺少消费该 cookie 的鉴权代码，无法证明可导致会话窃取或权限提升，故仅作为线索记录。<br>4) 无端点清单、无框架路由、无部署信息（PHP 版本、php.ini、是否公网暴露），无法判断可达性。<br><br>未闭合线索（供后续人工/更大 code_pack 复核）：weak_id（可预测会话标识，需补充消费该 cookie 的鉴权代码）、insecure_cookie（缺 HttpOnly/Secure，需补充会话使用点）、$_SERVER['HTTP_HOST'] 作为 cookie domain 的信任边界问题（Host 头可控时可能影响 cookie 作用域，但需完整响应头与浏览器行为验证）。

未覆盖 / 证据缺口：
- code_pack 仅含 046.php 一个文件，缺少消费 dvwaSession cookie 的鉴权/会话校验代码，weak_id 利用链无法闭合
- 缺少 Web 服务器配置、PHP 版本、php.ini（allow_url_include、open_basedir、session 配置）
- 无端点清单与访问日志，无法确认脚本对外暴露方式与调用路径
- 无依赖清单，无法评估第三方组件 CVE
- surface_notes 中提到的 source_hot_files 第 2 行实际为空行，与源码不符，热点标注不可信

## 3. Findings

### F-1: 046.php 会话标识由递增计数器派生，可预测（CWE-330）

- **类型**：`weak_id` / CWE-330
- **严重度**：`high`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`046.php:5-6`
- **来源**：`rule`

**描述**

046.php:5 判断 REQUEST_METHOD 为 POST 后，046.php:6 检查 $_SESSION['last_session_id_high'] 是否存在，不存在则在 046.php:7 置为 0，随后 046.php:9 自增、046.php:10 用 md5 派生 Cookie 值。会话标识的熵来源仅为服务端会话中的一个单调递增整数，攻击者可通过一次合法请求获得当前值，再线性推算前后所有取值；代码中没有任何随机数、时间抖动或服务端白名单校验来阻止伪造值被接受。

**source / sink**

- source：session `dvwaSession`（046.php）
- sink：046.php:6 	if (!isset ($_SESSION['last_session_id_high'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:6` | 会话标识由时间/递增值派生；需跨请求预测并确认服务端接受 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 046.php 的弱 ID / 可预测会话标识 POC。源码 046.php:9-11 将 $_SESSION['last_session_id_high'] 自增后 md5 作为 dvwaSession Cookie 下发，连续请求下 Cookie 值呈可预测序列。POC 通过同一会话连续两次 POST /046 并比较 Set-Cookie 中的 dvwaSession 值来验证可预测性。目标统一使用 TARGET 占位符，仅限授权测试。

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

攻击者可预测并伪造 dvwaSession 会话标识，实现会话固定/会话预测攻击，冒充其他用户身份访问受保护功能，造成越权与敏感数据泄露；由于 Cookie 未设置 secure/httponly，还可结合明文信道窃取进一步扩大影响。

**CVE / CWE 论证**

CWE-330（Use of Insufficiently Random Values）：会话标识取值空间为可枚举的整数序列，不满足不可预测性要求。外部可达性：046.php 为可直接访问的 Web 脚本，POST 即触发；无需认证即可获取样本并推算；利用链闭合：请求 → 计数器自增 → md5 派生 → setcookie 下发 → 攻击者构造同构值回放。

**修复建议**

使用 CSPRNG（random_bytes / random_int）生成至少 128 位熵的会话标识，或直接依赖 PHP session 并调用 session_regenerate_id(true) 在登录后轮换；服务端维护已签发令牌集合并做恒定时间校验；为 Cookie 设置 secure、httponly 与 SameSite 属性；避免使用自增计数器作为任何安全令牌的种子。

**验证说明**

静态证据：入口 POST /046；source=session/dvwaSession；sink=046.php:6；规则 php-predictable-session-id。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者发送 POST 至 046.php → 046.php:6 判定会话计数器未初始化 → 046.php:7 置 0 → 046.php:9 自增 → 046.php:10 md5 派生 $cookie_value → 046.php:11 setcookie 下发。攻击者据此推算相邻请求的合法 Cookie 值并回放，服务端无二次校验即接受，形成会话冒用链。
AWVS 外部佐证：Predictable Session Identifier @ http://127.0.0.1:18081/046.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /046）：符合 CWE-330（使用不充分的随机值）/CWE-328（弱哈希）。证据位于 046.php:9-11，source 为会话计数器 $_SESSION['last_session_id_high']，sink 为 setcookie 下发的 dvwaSession；静态链闭合，但“可劫持”结论依赖部署中该 Cookie 是否用于校验，属 llm_inferred。
POC 备注：仅文本工件，不执行、不联网。原 poc.sh 中的 curl 命令仅作请求结构参考，管线不得运行；cookie_jar 为本地临时文件占位，实际测试需自行管理会话。未覆盖范围：code_pack 未包含读取/校验 dvwaSession 的代码，也未包含 /046 路由的方法与参数定义，故请求方法（POST）与空 body 为基于页面触发逻辑的推断，若源码显示需特定参数（如 submit 按钮字段）须补充。

**外部佐证**

- awvs: Predictable Session Identifier @ http://127.0.0.1:18081/046.php

### F-2: 046.php 使用 MD5 生成会话 Cookie 值（弱哈希，CWE-328）

- **类型**：`weak_crypto` / CWE-327
- **严重度**：`medium`
- **置信度**：`0.76`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`046.php:9-10`
- **来源**：`rule`

**描述**

攻击者无需输入任何参数：服务端在 046.php:9 将 $_SESSION['last_session_id_high'] 自增，随后在 046.php:10 用 md5($_SESSION['last_session_id_high']) 计算 Cookie 值，并在 046.php:11 通过 setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false) 下发。该值完全由单调递增的整数派生，没有任何随机盐或密钥参与，因此不存在需要绕过的校验环节——校验本身缺失。注意：此处算法为 MD5，属弱哈希（CWE-328），不是 DES/ECB 类弱加密（CWE-327），候选的 vulnerability_type 标注为 weak_crypto 属类型串用，实际应按 weak_hash 归类。

**source / sink**

- source：repository `md5(`（046.php）
- sink：046.php:10 	$cookie_value = md5($_SESSION['last_session_id_high']);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `046.php:10` | 弱算法/模式或可预测令牌是根因；需确认保护对象与可伪造性 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

静态证据型 POC：046.php 第 9-11 行把会话计数器 $_SESSION['last_session_id_high'] 自增后直接 md5() 作为 dvwaSession Cookie 值下发，属于弱哈希（CWE-328）用于生成会话标识；因输入空间为连续整数，md5 可被离线枚举还原，等价于可预测会话 ID。本 POC 为离线源码审查，不发送请求。

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

会话标识可被离线枚举/预测：攻击者只需知道或猜到一个合法 dvwaSession 值（其取值空间为 md5(0)、md5(1)、md5(2)… 的极小集合），即可伪造 Cookie 冒充其他会话，导致身份冒用与越权访问 /vulnerabilities/weak_id/ 下的受保护资源；同时 setcookie 的 secure 与 httponly 参数均为 false，Cookie 可在明文 HTTP 下被窃取。

**CVE / CWE 论证**

CWE-328（Use of Weak Hash）：MD5 抗碰撞与抗原像能力均不满足安全令牌用途，且此处输入为可预测的递增整数，熵接近零。外部可达性：046.php 位于 Web 根目录，POST 请求即可触发 Cookie 下发，无需认证即可获得样本值；利用链闭合：请求 → $_SESSION['last_session_id_high']++ → md5() → setcookie 下发 → 客户端回放伪造值。

**修复建议**

改用 CSPRNG 生成会话标识，例如 random_bytes(32) 后 base64/hex 编码，或直接使用 PHP 原生 session 机制（session_regenerate_id(true)）；不要用 MD5/SHA-1 派生令牌；setcookie 增加 secure=true、httponly=true，并考虑 SameSite=Lax/Strict；服务端保存令牌并做恒定时间比对，避免仅凭可推导值判定身份。

**验证说明**

静态证据：入口 ANY /046；source=repository/md5(；sink=046.php:10；规则 php-weak-crypto。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST 请求进入 046.php:5 → 046.php:6-7 初始化 $_SESSION['last_session_id_high']=0 → 046.php:9 自增 → 046.php:10 md5(递增整数) 得到 $cookie_value → 046.php:11 setcookie 下发 dvwaSession。攻击者观察一次响应即可推导后续值序列，回放伪造 Cookie 完成会话冒用。
POC 备注：仅文本工件，不执行。原 current_poc 中的 grep 命令仅作定位说明，管线不应运行。未覆盖范围：code_pack 中未见读取 dvwaSession 进行校验的代码，故“可预测会话 ID 导致劫持”为基于源码的推断（llm_inferred），非动态验证结论。

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
| `SEM-19354a0facf2` | Predictable Session Identifier | http://127.0.0.1:18081/046.php | corroborated |

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
| safety_guard | 安全防护 | 4.39 | 是 |
| surface_mapper | 攻击面测绘 | 8.07 | 是 |
| deep_finder | LLM 深挖 | 6.03 | 是 |
| candidate_screener | 候选筛选 | 4.76 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.19 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.72 | 是 |
| coordinator | 管线协调 | 6.24 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
