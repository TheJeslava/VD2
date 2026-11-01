# 落日二号乙漏洞挖掘报告 — 20261031-014447-4f0270

- 生成时间：2026-10-30T17:45:22.969412+00:00
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

本次汇总仅含 1 条已去重 finding：053.php 的反射型 XSS（CWE-79，high），证据为 $_GET['name'] 未编码直接拼接进 HTML 输出（第 3 行读取、第 8 行附近输出），已附带 POC，属 HTTP 可复现类型。最高危即该条 high 级 XSS。POC 齐全度：1/1 有 POC，无静态-only 类型（本次无 weak_crypto/weak_hash/weak_random 类候选）。二次注入链：无。需注意 surface_notes 明确说明输入未提供 053.php 代码正文，仅给出行数与热点行号，因此该 finding 的代码级证据来自规则命中，行号需与仓库实际文件核对；其余攻击面（命令执行、SQL、文件包含、SSRF、配置类）均未覆盖，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 053.php（11 行）。已逐行审计：第 3 行 header 设置、第 6 行 GET 参数 name 读取、第 8 行字符串拼接输出。确认存在一条闭合的反射型 XSS 链（$_GET['name'] → $html 拼接 → 响应输出），并伴随 X-XSS-Protection: 0 的防护削弱。未发现命令执行、SQL、文件包含、反序列化、SSRF 等其它 sink（文件中不存在相关函数调用）。未覆盖范围：无路由/部署配置、无 php.ini 与 Web 服务器配置、无依赖清单，无法评估该脚本的实际暴露面与运行环境；$html 变量初始化情况未在片段中体现。

未覆盖 / 证据缺口：
- 缺少部署与路由信息，无法确认 053.php 是否可被外部 HTTP 访问
- 缺少 php.ini/Web 服务器配置，无法评估运行环境与全局防护
- $html 变量是否预先初始化未在代码中体现
- 无依赖清单，无法评估第三方组件风险

## 3. Findings

### F-1: 053.php 反射型跨站脚本（CWE-79）：$_GET['name'] 未编码直接拼接进 HTML

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求参数 name 提供输入（053.php:8 的 $_GET['name']）。该值未经任何 HTML 实体编码、过滤或白名单校验，直接被字符串拼接进 $html 累积变量：$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>'（053.php:8）。随后 $html 作为页面响应输出（输出语句在 code_pack 片段之外，属未覆盖范围，但该变量命名与注释「Feedback for end user」表明其用于回显给终端用户）。由于拼接发生在 <pre> 元素内容上下文中，攻击者提交 name=<script>...</script> 或 <img src=x onerror=...> 即可闭合/逃逸文本上下文，在受害者浏览器中执行任意 JavaScript。校验无效的原因：代码路径上不存在 htmlspecialchars/htmlentities 等编码调用，也不存在标签/字符白名单，属于典型的「直接回显」模式。

**source / sink**

- source：query `request parameter`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（任意方法）的反射型跨站脚本 POC。注入点为查询参数 request parameter，源码 053.php:8 将外部输入直接输出到响应，未做 HTML 编码。目标地址统一使用 TARGET 占位符。

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

反射型 XSS：攻击者可构造带恶意 name 参数的链接诱导受害者点击，在目标站点源下执行任意脚本，从而窃取会话 Cookie（若未设 HttpOnly）、读取页面敏感数据、以受害者身份发起操作（CSRF 绕过）、篡改页面内容或进行钓鱼跳转。危害程度取决于会话保护与 CSP 配置。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation，跨站脚本）。外部可达性：注入点为 HTTP GET 参数 name，任何能访问 053.php 的远程用户均可触发，无需认证、无需本地访问。利用链闭合：source（$_GET['name']）→ 无净化拼接（053.php:8）→ $html 输出到响应，链路在片段内已完整可见；唯一未在 code_pack 中直接展示的是最终 echo/print 语句，属证据缺口，但变量语义与注释足以支撑回显用途。

**修复建议**

1) 输出编码：在拼接前对用户输入执行 htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')，确保 <、>、&、"、' 被实体化；2) 上下文感知编码：若未来输出到属性或 JS 上下文，改用对应编码器（如 json_encode 用于 JS）；3) 输入校验：对 name 施加长度上限与字符白名单（如仅字母数字与空格）；4) 纵深防御：为会话 Cookie 设置 HttpOnly 与 SameSite，并部署限制内联脚本的 CSP（如 script-src 'self'）。

**验证说明**

静态证据：入口 ANY /053；source=query/request parameter；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 URL：http://TARGET/053.php?name=<script>alert(document.cookie)</script>（仅限授权测试）。浏览器发起 GET 请求，PHP 在 053.php:8 读取 $_GET['name'] 并原样拼入 $html 的 <pre> 块；响应返回后浏览器将 <script> 解析为可执行脚本，在站点源下运行，完成会话窃取或任意前端操作。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79（跨站脚本）。漏洞位于 053.php:8，外部输入来自查询参数 request parameter，source→sink 链静态闭合，未见有效净化/编码，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。POC 为文本工件，管线不执行、不联网、不搭建沙箱。目标地址使用 TARGET 占位符。原始草稿中参数名含空格且未编码，实际发送时建议使用 request%20parameter 形式；ANY 方法在真实请求中应替换为具体方法（如 GET）。

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
| safety_guard | 安全防护 | 2.66 | 是 |
| surface_mapper | 攻击面测绘 | 4.92 | 是 |
| deep_finder | LLM 深挖 | 7.4 | 是 |
| candidate_screener | 候选筛选 | 2.95 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.87 | 是 |
| coordinator | 管线协调 | 6.02 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
