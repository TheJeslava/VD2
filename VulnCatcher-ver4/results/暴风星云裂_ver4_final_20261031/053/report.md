# 落日二号乙漏洞挖掘报告 — 20261031-173354-f1819f

- 生成时间：2026-10-31T09:34:34.223491+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\053.zip`
- 输入模式：`zip`
- SHA256：`dec73bedc036c1309393989aea493094094031b09deb800e5d4d4666bfc8824e`
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

本次汇总仅含 1 条已去重 finding：053.php 的反射型 XSS（CWE-79，high），证据为 $_GET['name'] 未编码直接拼接进 HTML 输出，位于 053.php 第 8 行附近，已附带 POC（HTTP 型，可动态复现）。最高危即该条 high 级 XSS，POC 齐全（with_poc=1/1）。未发现二次注入链，无配置型（weak_crypto/weak_hash/weak_random/insecure_cookie）候选。需注意：surface_notes 明确指出本次输入未提供 053.php 实际代码内容、sink_hot_files 为空，因此除该 XSS 外的数据流（文件操作、命令执行、SQL、include、unserialize 等）均未覆盖，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 053.php（11 行），已通读全文。唯一外部输入为第 6 行 $_GET['name']，第 8 行未编码拼接进 HTML 输出，构成反射型 XSS；第 3 行 X-XSS-Protection: 0 加剧风险。未发现命令执行、文件操作、SQL、反序列化、SSRF 等其它汇点（sink_hot_files 为空与源码一致）。未闭合线索：无路由/鉴权配置，无法判断是否位于认证之后；无 php.ini 与部署信息，无法评估其它配置型风险；无依赖清单。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/PHP 配置，无法评估 register_globals、allow_url_include 等
- 无部署与网络暴露信息，无法确认脚本是否公网可达
- 无端点清单与框架信息，无法做路由级鉴权分析
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 053.php 反射型跨站脚本（CWE-79）：$_GET['name'] 未编码直接拼接进 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求的 `name` 参数输入任意内容（053.php:8 的 `$_GET[ 'name' ]`）。该值未经任何 HTML 实体编码、过滤或白名单校验，被字符串拼接进 `$html` 累积变量：`$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';`（053.php:8），随后该 `$html` 作为页面响应输出给浏览器。由于注入点位于 `<pre>` 元素内部的 HTML 文本上下文，攻击者提交 `name=<script>...</script>` 或 `name=<img src=x onerror=...>` 即可闭合/逃逸文本上下文，使浏览器把注入内容当作可执行标记解析。校验无效的原因：源码中该参数从读取到拼接之间不存在 htmlspecialchars/htmlentities、类型约束或长度限制，属于典型的“直接反射”。

**source / sink**

- source：query `name`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（无 .php 后缀路由）的反射型 XSS：与 LLM-3ca7baf03343 同一源码汇点 053.php:8，GET 参数 name 未编码输出。若部署环境启用了无后缀路由重写，则 /053 同样可触发。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/053'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/053?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/SEM-fca2dd504a67`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可构造带恶意 `name` 参数的链接诱导受害者点击，在受害者浏览器中以站点源执行任意 JavaScript，从而窃取会话 Cookie/令牌、读取页面敏感数据、以受害者身份发起操作（CSRF 式请求）、篡改页面内容或进行钓鱼跳转。由于脚本在站点源下执行，可绕过同源策略对同站资源的访问限制。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation，跨站脚本）。外部可达性：注入点为 HTTP GET 查询参数 `name`，无需认证、无需特殊权限，任意远程请求即可触发；利用链闭合：`$_GET['name']`（source，053.php:8）→ 字符串拼接进 `$html`（053.php:8）→ 作为 HTML 响应输出（sink，053.php:8），中间无编码/过滤环节。证据等级为源码推断（llm_inferred），未做运行时验证。

**修复建议**

1) 输出编码：在拼接前对用户输入执行上下文相关的 HTML 实体编码，如 PHP 的 `htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`；2) 输入校验：对 `name` 施加长度上限与字符白名单（如仅允许字母数字与少量标点），拒绝不符合的值；3) 若需保留富文本，使用成熟的白名单净化库（如 HTMLPurifier）而非手写过滤；4) 设置 `Content-Type: text/html; charset=UTF-8` 并配合 `X-Content-Type-Options: nosniff`，同时部署 CSP（禁止 inline script）作为纵深防御；5) 会话 Cookie 加 HttpOnly，降低脚本窃取会话的影响。

**验证说明**

静态证据：入口 GET /053；source=query/name；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 URL：`http://TARGET/053.php?name=<script>alert(document.cookie)</script>`（仅限授权测试）。请求到达 053.php 后，第 8 行读取 `$_GET['name']`，未做任何编码即拼入 `$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';`，最终 `$html` 作为响应体返回。浏览器解析响应时，`<pre>` 内的 `<script>` 被当作脚本执行，攻击者 JavaScript 在站点源下运行，完成会话窃取或页面篡改。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79。漏洞位于 053.php:8，外部输入来自 GET 参数 name，source→sink 链静态闭合，未见有效净化；触发依赖无后缀路由重写配置。
POC 备注：POC 仅为文本工件，不执行、不联网。若目标未启用 /053 重写，请以 LLM-3ca7baf03343 的 /053.php 版本为准。curl 示例仅供授权测试人员手动使用。

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
| safety_guard | 安全防护 | 2.96 | 是 |
| surface_mapper | 攻击面测绘 | 6.61 | 是 |
| deep_finder | LLM 深挖 | 7.17 | 是 |
| candidate_screener | 候选筛选 | 3.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.99 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.25 | 是 |
| coordinator | 管线协调 | 5.99 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
