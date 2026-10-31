# 落日二号乙漏洞挖掘报告 — 20261031-013929-5646af

- 生成时间：2026-10-30T17:40:06.839481+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

本次汇总仅含 1 条已去重 finding：019.php 第 2 行的 CSP 策略问题（SEM-3004577a69c4，medium，CWE-693），策略以 script-src 'self' 硬编码，缺少 nonce/hash 以及 object-src/base-uri 限制，已附带 POC（静态/响应头类 POC，未做动态验证）。最高危即此条 medium 级 CSP 配置缺陷，其余类型无交付项。POC 齐全度为 1/1，但均为文本工件，未执行、未搭建沙箱、未做动态复现。需强调：surface_notes 明确指出输入未提供 019.php 实际代码内容、sink_hot_files 为空、无端点清单，因此注入类（SQL/路径/命令/XSS）与配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）均处于“未覆盖/未交付”状态，不能解读为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 019.php（1-22 行，DVWA CSP 关卡 high 级别页面）。第 2-4 行设置 CSP 响应头 `script-src 'self'`；第 8-12 行读取 $_POST['include'] 并直接拼接到 $page['body']，第 13-21 行继续拼接表单与 `<script src="source/high.js">`。该拼接点确实存在未转义的反射型输入，但：(1) 页面自身设置了 `script-src 'self'`，内联脚本与外部域脚本均被 CSP 阻断，无法形成可执行 XSS；(2) 该文件仅构建 $page['body'] 片段，最终输出（echo/print）发生在 code_pack 之外的模板文件中，无法在给定范围内确认输出上下文与转义情况；(3) 无认证/授权、文件、命令、SQL、反序列化、SSRF 等其它汇点。因此不构成可闭合的 CVE 级利用链，按“宁可漏报不可误报”原则不提交 finding。未闭合线索：$page['body'] 的最终渲染位置与是否二次转义（若模板未转义且 CSP 被移除/降级，则可能成为反射型 XSS，属 DVWA 教学场景，非真实产品漏洞）；source/high.js 与 source/jsonp.php 不在 code_pack 内，视为不存在。

未覆盖 / 证据缺口：
- $page['body'] 的最终输出点不在 code_pack 内，无法确认输出上下文与转义
- source/high.js、source/jsonp.php 未提供，无法评估 JSONP 回调注入面
- 无 php.ini / Web 服务器配置，无法判断 CSP 是否实际生效
- 无端点清单与部署信息，无法确认外部可达性与认证状态

## 3. Findings

### F-1: 019.php 中 CSP 策略以 script-src 'self' 硬编码，缺少 nonce/hash 与 object-src/base-uri 限制（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:1-2`
- **来源**：`rule`

**描述**

证据来自 019.php 第 1-2 行：第 2 行定义 $headerCSP = "Content-Security-Policy: script-src 'self';"。该字符串是唯一的策略内容，仅包含 script-src 'self'，未设置 default-src、object-src 'none'、base-uri 'none'、frame-ancestors，也未使用 nonce 或 hash 白名单。攻击者输入点：本片段中未出现任何 getParameter/getHeader/Cookie 读取，因此不存在由请求参数直接进入该 header 变量的污点链；该候选属于配置/实现型弱点（source_kind 语义为配置），其风险取决于该 header 是否被实际输出到响应（片段中未见 header()/echo 输出语句，证据不足）。校验无效的原因：策略本身过于宽松且不完整——'self' 允许加载同源任意脚本，一旦站点存在同源上传目录、JSONP 端点、或被托管的第三方同源资源，攻击者即可借同源脚本执行；同时缺少 object-src/base-uri 使插件与 <base> 劫持类绕过不受约束。最终到达的危险操作是浏览器端脚本执行策略的放宽，而非服务端危险函数调用。

**source / sink**

- source：query `include`（019.php）
- sink：019.php:2 $headerCSP = "Content-Security-Policy: script-src 'self';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:2` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（ANY）的 CSP 配置缺陷 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-3004577a69c4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若该 CSP 被实际下发，XSS 缓解能力被削弱：同源任意脚本可执行，object/embed 插件内容与 <base> 标签劫持不受限制，攻击者可利用同源上传或 JSONP 端点绕过 CSP 执行任意脚本，导致会话 Cookie 窃取、页面内容篡改与钓鱼。由于片段中未见 header 输出语句，实际影响需以运行时响应头为准，当前证据不足以确认已生效。

**CVE / CWE 论证**

CWE-693（Protection Mechanism Failure）。外部可达性：该策略为静态字符串，若被输出则对所有访问该页面的用户生效，无需认证。利用链闭合性：当前证据不闭合——片段中缺少 header()/echo 等输出点，也缺少可控脚本注入点，无法证明攻击者能实际利用；因此仅作为配置缺陷记录，不主张 CVE 级可利用性。

**修复建议**

1) 补全策略：default-src 'none'; script-src 'self' 'nonce-<随机值>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'；2) 对每个内联脚本生成每次请求随机的 nonce 并在服务端模板中同步输出；3) 避免使用 'unsafe-inline'/'unsafe-eval'；4) 将 CSP 通过 header() 统一在响应头下发，并配合 report-uri/report-to 收集违规；5) 清理同源上传目录与 JSONP 端点，避免 'self' 被滥用。

**验证说明**

静态证据：入口 ANY /019；source=query/include；sink=019.php:2；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：019.php:2 定义静态 CSP 字符串 script-src 'self'，未包含 nonce/hash 与 object-src/base-uri 限制。片段中未出现请求参数读取，也未出现 header 输出语句，因此不存在 source→sink 污点链；该候选为配置型弱点，风险成立的前提是该 header 被实际下发且站点存在同源可控脚本资源。证据不足以确认运行时生效，故置信度维持较低水平。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:2 的 CSP（内容安全策略）配置缺陷。该文件在响应中设置 Content-Security-Policy 相关头/策略，但策略过宽或缺失关键指令（如 script-src 使用 unsafe-inline/unsafe-eval 或通配符），导致浏览器端 XSS 缓解失效。注意：CSP 缺陷本身是响应头配置问题，query 参数 include 并非该缺陷的注入通道；POC 以观察响应头为主，include 参数仅用于确认路由可达。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-693（保护机制失效）。缺陷位于 019.php:2 的响应头/策略配置；属于配置型候选，无 HTTP 污点链，判定依据为响应中 CSP 指令的宽松程度或缺失，而非 include 参数值。
POC 备注：仅文本工件，不执行、不联网。脚本中的 TARGET 需由授权测试人员手动替换；重点检查响应头 Content-Security-Policy，而非请求参数回显。原始草稿将 include 参数当作注入点，与 CSP 配置缺陷的实际证据不符，此处已更正为以响应头观察为主。

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
| `csp` | CWE-693 |  | 1 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.29 | 是 |
| surface_mapper | 攻击面测绘 | 8.46 | 是 |
| deep_finder | LLM 深挖 | 3.26 | 是 |
| candidate_screener | 候选筛选 | 5.43 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.52 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.92 | 是 |
| coordinator | 管线协调 | 6.14 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
