# 落日二号乙漏洞挖掘报告 — 20261030-225155-b80f29

- 生成时间：2026-10-30T14:52:28.693385+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\054.zip`
- 输入模式：`zip`
- SHA256：`f56d8d7acab4a33d76750401c5e2eec81cfdf4ce2a39a589bd28299560fe4eb0`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：054.php 的反射型 XSS（LLM-04dd02aad740，high，llm_finding），成因是第 3 行读取请求参数后经 str_replace 单次黑名单过滤 <script>，第 11 行附近回显，可用嵌套标签绕过；该条已附 POC（静态文本 POC，未做动态验证）。最高危即此条 high XSS。POC 齐全度为 1/1，但全部为源码推断级证据，无 HTTP 请求样例、无端点清单，动态可达性未知。本次 min_severity=high、min_confidence=0.6、suppressed_count=0，无策略抑制项；但 suppressed_count=0 仅表示本档位无候选被抑制，不代表其他类型（sql_injection / path_traversal / command_injection / weak_hash / weak_random / insecure_cookie 等）已排查完毕——surface_notes 明确说明 sink_hot_files 为空、未提供代码片段，这些类别属于未覆盖而非未检出。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 054.php（14 行，已完整审计 1-14 行）。该文件为无框架的独立脚本，唯一外部输入为第 6 行 $_GET['name']，经第 8 行单趟 str_replace('<script>','') 黑名单过滤后，于第 11 行未编码拼接进 HTML 输出，构成反射型 XSS；第 3 行显式关闭 X-XSS-Protection 加剧风险。未发现 SQL 注入、命令执行、文件包含/读写、反序列化等其它汇点（文件中不存在相关函数调用）。未覆盖范围：无 php.ini/Web 服务器配置、无 composer.json、无 README，无法确认部署暴露面、PHP 版本与 disable_functions；无端点清单，动态可达性未验证。

未覆盖 / 证据缺口：
- 无运行环境与部署配置，无法确认公网可达性与 WAF 前置
- 未做动态验证，XSS 实际执行依赖浏览器与可能的 CSP
- 未提供其它文件，无法交叉验证是否存在共享过滤逻辑

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 单次黑名单过滤 <script> 可被嵌套标签绕过

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取用户输入，第 8 行仅用 str_replace('<script>', '', ...) 做一次非递归的字符串替换，第 11 行将结果直接拼接进 HTML 并输出（$html .= "<pre>Hello {$name}</pre>"），全程无 htmlspecialchars/htmlentities 编码。由于 str_replace 只做单趟替换，构造 '<scr<script>ipt>' 时，内层 '<script>' 被删除后外层残余字符重新拼合成 '<script>'，从而绕过过滤；同时第 3 行显式发送 'X-XSS-Protection: 0' 关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JavaScript，窃取会话 Cookie 或代表受害者执行敏感操作。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 echo/输出 $html 到 HTTP 响应体（第 11 行字符串拼接后随脚本输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | 检查 $_GET['name'] 存在且非 NULL，确认外部可控输入进入脚本 | 原始 URL 查询参数值 |  |
| 2 | `054.php:8` | str_replace('<script>', '', $_GET['name']) 单趟删除字面量 '<script>'，非递归、无大小写/变体处理 | 经一次黑名单替换的字符串，嵌套构造可还原出 <script> | str_replace 只执行一次替换，'<scr<script>ipt>' 删除内层后重新拼合为 '<script>'；且未过滤 <img onerror>、<svg onload> 等其它向量 |
| 3 | `054.php:11` | 将未编码的 $name 拼入 "<pre>Hello {$name}</pre>" 并赋给 $html，随后由 PHP 输出到响应体 | 未做 HTML 实体编码的原始 HTML 片段，直接进入响应 |  |

**POC**

针对 /054.php（GET）的反射型跨站脚本（XSS）POC。注入点为 GET 参数 name，该参数值被直接输出到 HTML 响应中而未做编码，导致浏览器执行注入脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/054.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/054.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-04dd02aad740`
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie、伪造请求执行敏感操作、篡改页面内容实施钓鱼。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数 name 无需认证即可注入，过滤为单趟 str_replace 黑名单可被嵌套标签绕过，且第 3 行主动关闭 X-XSS-Protection，source→sink 链在 054.php 内完整闭合。

**修复建议**

使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 对输出进行上下文编码；移除 'X-XSS-Protection: 0' 头；如需过滤应采用白名单或递归/规范化处理，而非单趟 str_replace 黑名单。

**验证说明**

需在真实浏览器确认嵌套 <script> 还原后的执行效果，以及目标是否设置 CSP 等额外缓解；未做动态验证。
模型 POC 要点：构造含嵌套 <script> 的 name 参数，使过滤后还原为可执行脚本标签，诱导受害者点击链接触发反射型 XSS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79（跨站脚本）。漏洞位于 054.php:11，外部输入来自 GET 参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级为 llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，执行前需替换为授权测试目标。原始确定性请求结构（GET /054.php?name=...）予以保留，仅补充说明与预期结果。注意：原始 request.http 草稿中 Content-Length 与 GET 请求体不一致，实际发送时不应携带请求体，以 URL 查询参数为准。

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
| `xss` | CWE-79 | 是 | 1 |
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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.51 | 是 |
| surface_mapper | 攻击面测绘 | 6.47 | 是 |
| deep_finder | LLM 深挖 | 8.17 | 是 |
| candidate_screener | 候选筛选 | 3.2 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.99 | 是 |
| coordinator | 管线协调 | 6.67 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
