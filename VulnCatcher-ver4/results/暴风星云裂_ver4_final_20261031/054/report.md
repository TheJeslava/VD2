# 落日二号乙漏洞挖掘报告 — 20261031-173356-37e681

- 生成时间：2026-10-31T09:34:26.225860+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\054.zip`
- 输入模式：`zip`
- SHA256：`f56d8d7acab4a33d76750401c5e2eec81cfdf4ce2a39a589bd28299560fe4eb0`
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

本次汇总仅含 1 条已去重 finding：LLM-04dd02aad740，类型 xss（medium），位于单文件 PHP 脚本 054.php 第 11 行附近，描述为 str_replace 单次黑名单过滤可被嵌套标签绕过导致反射型 XSS，已附带 POC（HTTP 型，属静态构造、未动态验证）。最高危即该条 medium XSS，无 high/critical。POC 齐全度：1/1 finding 有 POC，但均为文本工件，未经动态复现。整体攻击面极小（1 文件、14 行、无框架无端点），且 surface_notes 明确指出输入未提供 054.php 源码内容，因此该 finding 的代码级证据无法在本汇总环节独立复核，需回到源码确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 054.php（14 行），已逐行审计。发现第 6 行 $_GET['name'] 外部输入经第 8 行单次 str_replace('<script>','') 过滤后于第 11 行拼接输出，构成可绕过的反射型 XSS；第 3 行显式关闭 X-XSS-Protection 加剧风险。未发现 SQL/命令/文件/反序列化等其它汇点（文件内无相关调用）。未覆盖范围：无部署配置、无 PHP 版本信息，无法评估 register_globals/allow_url_include 等运行时因素；$html 变量未初始化属代码质量问题，不影响 XSS 结论。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/部署配置，无法确认 054.php 对外可达性
- 缺少 PHP 版本与运行时设置
- 无端点清单，参数传递方式仅从源码推断为 GET

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 单次黑名单过滤可被嵌套标签绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>', '', ...) 做单次、大小写敏感、非递归的黑名单替换，第 11 行将结果直接拼接进 HTML 并输出（$html .= "<pre>Hello {$name}</pre>"）。由于替换只执行一次且不递归，构造 '<scr<script>ipt>' 这类嵌套 payload 时，内层 '<script>' 被删除后外层残余字符重新拼合成 '<script>'，从而绕过过滤；同时第 3 行显式发送 'X-XSS-Protection: 0' 关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JavaScript，窃取会话或发起敏感操作。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 echo/输出 $html 到 HTML 响应体（第 11 行字符串拼接，脚本末尾隐式输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | 检查 $_GET 中是否存在 name 且非 NULL，确认外部输入入口 | 原始攻击者可控字符串 |  |
| 2 | `054.php:8` | str_replace('<script>', '', $_GET['name']) 单次非递归黑名单替换 | 仅删除首次出现的字面量 '<script>'，嵌套/大小写变体保留 | 替换非递归且大小写敏感，'<scr<script>ipt>' 删除内层后重组为 '<script>'；'<SCRIPT>' 等变体不被匹配 |
| 3 | `054.php:11` | 将 $name 拼接进 "<pre>Hello {$name}</pre>" 并输出到响应 | 未做 HTML 实体编码的原始标签进入响应体 |  |
| 4 | `054.php:3` | header("X-XSS-Protection: 0") 关闭浏览器 XSS 过滤器 | 响应头禁用内置防护 | 移除浏览器侧反射型 XSS 拦截 |

**POC**

针对 /054.php（GET）的 跨站脚本 POC。注入点：GET 参数 name；payload 使用 TARGET 占位符。

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
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JavaScript，可窃取 Cookie/会话令牌、伪造请求执行敏感操作、篡改页面内容。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数 name 无需认证即可注入，过滤为单次非递归黑名单可被嵌套标签绕过，且显式关闭 X-XSS-Protection，链闭合。

**修复建议**

对输出使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行 HTML 实体编码；移除 X-XSS-Protection: 0；不要依赖黑名单替换。

**验证说明**

需动态确认 PHP 对 $html 未初始化变量的处理（notice 不影响输出）以及实际响应体是否原样回显 payload；确认部署环境是否直接暴露 054.php。
模型 POC 要点：构造嵌套 script 标签绕过单次 str_replace，诱导受害者点击链接触发脚本执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：针对 054.php 的反射型跨站脚本（CWE-79）。源码 054.php:11 将 GET 参数 name 的值直接输出到响应中，未做 HTML 实体编码，攻击者构造的 <script> 会在受害者浏览器中执行。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79。漏洞位于 054.php:11，外部输入来自查询参数 name，source→sink 链在给定代码中静态闭合，未见有效净化或编码，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。目标地址统一使用 TARGET 占位符，仅限授权测试。请求结构沿用输入中的确定性草稿，仅补充基线与状态确认步骤。

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
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.66 | 是 |
| surface_mapper | 攻击面测绘 | 5.91 | 是 |
| deep_finder | LLM 深挖 | 7.42 | 是 |
| candidate_screener | 候选筛选 | 2.44 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.97 | 是 |
| coordinator | 管线协调 | 5.96 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
