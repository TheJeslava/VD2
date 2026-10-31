# 落日二号乙漏洞挖掘报告 — 20261031-010543-6ac297

- 生成时间：2026-10-30T17:06:19.260573+00:00
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

本次汇总仅包含 1 条已去重 finding：053.php 的反射型 XSS（CWE-79，high，规则命中，已附 POC）。该文件为 11 行、229 字节的单文件 PHP 脚本，第 3 行存在外部输入读取点，第 8 行附近为输出汇点，构成 source→sink 的直接反射链，是本次最高危且唯一交付项。POC 齐全（1/1，HTTP 型可复现文本），但未做动态验证。其余注入类（command/sql/xpath/ldap/path_traversal/ssrf）与配置类（weak_crypto/weak_hash/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）在输入中均无 sink 或算法/标志位证据，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 053.php（11 行）。已审计第 3 行 header 设置、第 6 行 $_GET['name'] 输入读取、第 8 行字符串拼接输出。确认存在一条闭合的反射型 XSS 链：$_GET['name'] → 未编码拼接 → HTML 响应输出，且第 3 行显式关闭 X-XSS-Protection。未发现命令执行、SQL、文件操作、反序列化、SSRF 等其它 sink（文件中不存在此类调用）。未覆盖范围：无 php.ini/Web 服务器配置、无路由与鉴权信息、无部署方式，无法确认该脚本是否公网可达及是否置于鉴权之后；文件名形似遗留调试文件，若已下线则实际风险降低。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 disable_functions 与访问控制
- 无路由与鉴权信息，无法确认 053.php 是否公网可达
- 无部署与版本历史，无法判断是否为遗留调试文件

## 3. Findings

### F-1: 053.php 反射型跨站脚本（CWE-79）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求向 053.php 提交 name 参数（`$_GET['name']`）。该值在 053.php:8 未经任何 HTML 实体编码或过滤，被直接字符串拼接进 `$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';`，随后作为页面响应输出。由于拼接发生在 `<pre>` 元素内容上下文，攻击者提交 `name=<script>...</script>` 或 `name=<img src=x onerror=...>` 即可闭合/逃逸文本上下文，在受害者浏览器中执行任意脚本。校验无效的原因：代码路径中不存在 htmlspecialchars/urlencode/白名单等任何净化步骤，原始请求参数直达输出汇点。

**source / sink**

- source：query `request parameter`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（任意方法）的反射型跨站脚本 POC。注入点为查询参数 request parameter，源码 053.php:8 将该参数值直接输出到响应且未做 HTML 编码，payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/053'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/053?request parameter=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/SEM-fca2dd504a67`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可构造带恶意 name 参数的链接诱导受害者点击，在目标站点源下执行任意 JavaScript，从而窃取会话 Cookie/令牌、以受害者身份发起操作（越权）、篡改页面内容或进行钓鱼。属于客户端代码执行，不涉及服务端 RCE 或文件读写。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation）。外部可达性：053.php 为 Web 入口，name 为 GET 参数，无需认证即可触发；利用链闭合：`$_GET['name']`（source）→ 字符串拼接（053.php:8）→ HTML 响应（sink），无编码/过滤环节。证据等级为源码推断（llm_inferred），未做运行时验证。

**修复建议**

1) 输出前对不可信数据做上下文相关编码：在 HTML 文本/元素内容上下文使用 `htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`；2) 若需允许有限格式，采用白名单校验（如仅字母数字）而非黑名单；3) 设置 `Content-Type: text/html; charset=UTF-8` 并配合 CSP（`default-src 'self'`）作为纵深防御；4) 避免直接拼接用户输入到 HTML 字符串，改用模板引擎的自动转义。

**验证说明**

静态证据：入口 ANY /053；source=query/request parameter；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 `GET /053.php?name=<script>alert(document.cookie)</script>` → PHP 从 `$_GET['name']` 读取原始值 → 053.php:8 直接拼入 `$html` 的 `<pre>Hello ...</pre>` 中 → 响应返回浏览器 → 脚本在站点源下执行。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79。漏洞位于可交付代码 053.php:8，外部输入来自查询参数 request parameter，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。参数名含空格，实际请求中应编码为 request%20parameter；执行前须将 TARGET 替换为授权目标并确保已获授权。ANY 方法在文本中保留为占位，实际可用 GET 触发。

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
| safety_guard | 安全防护 | 3.26 | 是 |
| surface_mapper | 攻击面测绘 | 6.43 | 是 |
| deep_finder | LLM 深挖 | 6.42 | 是 |
| candidate_screener | 候选筛选 | 3.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.82 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.71 | 是 |
| coordinator | 管线协调 | 6.04 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
