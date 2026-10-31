# 落日二号乙漏洞挖掘报告 — 20261031-164820-3e3c70

- 生成时间：2026-10-31T08:48:58.925325+00:00
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

本次汇总仅含 1 条已去重 finding：053.php 第 8 行附近的反射型 XSS（CWE-79，high，来源 rule），已附带 POC，属 HTTP 类可复现工件（未执行、未动态验证）。最高危即该 XSS。整体攻击面极小：单文件 PHP 脚本 11 行、229 字节，无框架、无路由、无端点清单，sink_hot_files 为空，静态数据流未完整覆盖。除该 XSS 外无其他类型 finding，POC 齐全度为 1/1（仅针对已交付项）。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 053.php（11 行）。确认第 6 行读取 GET 参数 name，第 8 行未编码拼入 HTML 输出，第 3 行关闭 X-XSS-Protection，构成反射型 XSS 闭合链。未发现命令执行、文件操作、SQL、反序列化、SSRF 等其它汇点；无硬编码密钥或弱哈希调用。未覆盖范围：无 Web 服务器配置、PHP 版本、php.ini、路由与部署信息，无法确认实际可达性与 Content-Type；无外部 DAST 证据。输入中未出现诱导性文本。

未覆盖 / 证据缺口：
- 缺少部署/服务器配置，无法确认 053.php 是否公网可达及响应 Content-Type
- 无 php.ini 与 PHP 版本信息
- 无外部动态验证证据

## 3. Findings

### F-1: 053.php 反射型跨站脚本（CWE-79）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求参数 `name` 提供输入（053.php:8 中的 `$_GET['name']`）。该值未经任何编码、过滤或类型校验，被直接字符串拼接到 `$html` 累积变量中：`$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';`（053.php:8）。随后 `$html` 作为页面响应体输出（输出语句在片段范围之外，属证据不足，但变量命名与注释「Feedback for end user」表明其为最终 HTML 响应）。由于 `name` 落在 HTML 元素文本上下文（`<pre>` 内），攻击者提交 `</pre><script>...</script>` 即可闭合标签并注入脚本，服务端不存在 HTML 实体编码（如 htmlspecialchars）或白名单校验，因此校验无效。

**source / sink**

- source：query `name`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（无 .php 后缀路由）第 8 行的反射型 XSS（CWE-79），与 LLM-3ca7baf03343 为同一源码位置的不同路由写法。源码从 GET 参数 name 读取输入并直接输出，未编码。POC 使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS：攻击者可构造带恶意 `name` 参数的链接，在受害者浏览器中于目标站点源下执行任意 JavaScript，可窃取会话 Cookie/令牌、伪造页面内容、以受害者身份发起操作（越权操作），并可作为钓鱼或蠕虫传播载体。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation）。外部可达性：注入点为 GET 查询参数 `name`，无需认证即可访问 053.php 触发；利用链闭合：`$_GET['name']` → 字符串拼接进 `$html` → 作为 HTML 响应输出，中间无编码/过滤环节。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 输出编码：在拼接前对 `$_GET['name']` 使用 `htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8')`，确保 `<`、`>`、`&`、引号被实体化；2) 输入校验：对 `name` 施加长度与字符白名单（如仅字母数字与空格）；3) 若需保留原始值，采用上下文感知模板引擎自动转义；4) 设置 `Content-Security-Policy` 与 `HttpOnly` Cookie 作为纵深防御。

**验证说明**

静态证据：入口 GET /053；source=query/name；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 URL `053.php?name=</pre><script>alert(document.cookie)</script>` → PHP 从 `$_GET['name']` 读取原始字符串（053.php:8）→ 直接拼接进 `$html`，未做 HTML 实体编码 → `$html` 作为响应体返回浏览器 → 浏览器解析 `</pre>` 闭合后执行注入的 `<script>`，脚本在目标源下运行。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79。漏洞位于 053.php:8，外部输入来自 GET 参数 name，source→sink 链静态闭合，未见有效净化或编码，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。脚本中的 curl 命令仅供人工在授权环境手动运行，需先将 TARGET 替换为授权测试地址；不得用于未授权目标。

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
| surface_mapper | 攻击面测绘 | 6.45 | 是 |
| deep_finder | LLM 深挖 | 6.78 | 是 |
| candidate_screener | 候选筛选 | 3.35 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.23 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.75 | 是 |
| coordinator | 管线协调 | 5.04 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
