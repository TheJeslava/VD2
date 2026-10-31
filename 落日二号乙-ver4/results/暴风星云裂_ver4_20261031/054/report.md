# 落日二号乙漏洞挖掘报告 — 20261031-164821-ddab46

- 生成时间：2026-10-31T08:48:52.824069+00:00
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

本次管线仅交付 1 条 finding：054.php 的反射型 XSS（LLM-04dd02aad740，medium，llm_finding），其成因是 str_replace 只过滤小写 <script>，并且显式关闭 X-XSS-Protection；该条已附带 POC（has_poc=true），属于 HTTP 型 POC，但尚未做动态验证，仅为静态推断。最高危项即此条 medium XSS，没有 high/critical 级别发现。POC 齐全度：1/1 有 POC，但全部为静态证据支撑的文本 POC，未经动态复现。需强调：本次输入未提供 054.php 源码正文，仅给出文件清单、行号范围与攻击面测绘，因此结论只能停留在测绘与推断层面。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 054.php（14 行，已 100% 覆盖）。审计确认：第 6 行 $_GET['name'] 为唯一外部输入入口；第 8 行 str_replace('<script>','') 为大小写敏感、非递归的黑名单过滤，可被 <SCRIPT>、<img onerror>、<svg onload> 等绕过；第 11 行将未编码的 $name 直接拼接进 HTML 输出，构成反射型 XSS；第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器 XSS 过滤器，加重风险。未发现 include/require、文件操作、SQL、命令执行、反序列化、SSRF 等其它 sink；无认证/会话/Cookie/加密相关代码，故无 weak_crypto/weak_hash/insecure_cookie 类候选。输入中未出现诱导性文本，无 prompt_injection 证据。未闭合线索：无端点清单与部署信息，无法确认公网可达性与上游 WAF；$html 变量在第 11 行前未初始化（PHP 8 会触发 Warning），不影响 XSS 成立但需运行时确认输出未被错误处理中断。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单，访问路径 /054.php 为按文件名推断
- 无部署/网络暴露信息，无法确认公网可达
- 无 WAF/反向代理配置，无法确认载荷是否被上游拦截
- $html 未初始化，PHP 8 下可能产生 Warning 影响响应格式，需动态确认

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 仅过滤小写 <script> 且显式关闭 X-XSS-Protection

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>','',...) 做单次、大小写敏感、非递归的黑名单替换，第 11 行将结果直接拼接进 HTML 片段 $html 并输出。由于过滤只匹配精确小写字符串 <script>，攻击者可用 <SCRIPT>、<ScRiPt>、<img src=x onerror=...>、<svg onload=...> 等任意变体绕过；同时第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。该脚本无认证、无 CSRF token、无输出编码，任意访问者构造链接即可在受害者浏览器上下文执行脚本，可窃取会话 Cookie、伪造页面内容或发起钓鱼。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 $html .= "<pre>Hello {$name}</pre>" 后由 PHP 输出到响应体（HTML 上下文）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | array_key_exists('name', $_GET) 判断参数存在，$_GET['name'] 为攻击者完全可控的查询字符串值 | 原始 URL 编码字符串，PHP 自动 URL 解码 |  |
| 2 | `054.php:8` | str_replace('<script>','',$_GET['name']) 仅删除精确小写 <script> 子串，大小写敏感且非递归 | 过滤后字符串；<SCRIPT>、<img onerror>、<svg onload> 等均原样保留 | 黑名单只匹配小写 <script>，可用大写/混合大小写标签或非 script 标签的事件处理器绕过；单次替换也无法处理嵌套构造 |
| 3 | `054.php:11` | 过滤后的 $name 被直接插值进 "<pre>Hello {$name}</pre>" 并输出到 HTML 响应，无 htmlspecialchars 等输出编码 | 未编码的 HTML 片段，浏览器按标签解析 |  |
| 4 | `054.php:3` | header("X-XSS-Protection: 0") 关闭浏览器 XSS 审计过滤器，减少客户端侧拦截 | 响应头 X-XSS-Protection: 0 |  |

**POC**

针对 /054.php（GET）的反射型跨站脚本（CWE-79）。源码 054.php:11 将 GET 参数 name 的值直接输出到响应中，未做 HTML 实体编码，导致脚本在受害者浏览器执行。

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

反射型 XSS：攻击者可在受害者浏览器中以目标站点源执行任意 JavaScript，窃取同域 Cookie/令牌、读取页面敏感数据、发起 CSRF 式操作或实施钓鱼；第 3 行关闭 X-XSS-Protection 使旧版浏览器防护失效。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation）。外部无需认证即可通过 GET 参数触发，source（054.php:6）→ 弱过滤（054.php:8）→ HTML 输出汇点（054.php:11）链路在 CODE PACK 内完整闭合，且过滤可被大小写/非 script 标签绕过，属可申报的真实反射型 XSS。

**修复建议**

对输出使用 htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') 进行 HTML 上下文编码；移除 header("X-XSS-Protection: 0")，改为 X-XSS-Protection: 1; mode=block 或依赖 CSP；不要依赖黑名单替换，采用白名单或上下文编码；增加 Content-Security-Policy 限制内联脚本。

**验证说明**

需动态确认 054.php 的实际访问路径与响应是否原样回显（$html 未初始化在 PHP 8 会告警但不影响输出）；确认无上游 WAF 拦截 <img onerror> 等载荷；确认响应 Content-Type 为 text/html 而非 text/plain。
模型 POC 要点：构造带 HTML 事件处理器的 name 参数，诱导受害者访问，脚本在目标域上下文执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79。漏洞位于 054.php:11，外部输入来自 GET 参数 name，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；目标统一使用 TARGET 占位符，仅限授权测试。保留原确定性 POC 的请求结构，补充了基线/攻击/状态确认三步。若源码中输出语句或参数名与推断不符，需以实际源码为准再调整请求。

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
| safety_guard | 安全防护 | 3.49 | 是 |
| surface_mapper | 攻击面测绘 | 5.84 | 是 |
| deep_finder | LLM 深挖 | 9.66 | 是 |
| candidate_screener | 候选筛选 | 2.32 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.99 | 是 |
| coordinator | 管线协调 | 6.44 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
