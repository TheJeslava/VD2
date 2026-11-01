# 落日二号乙漏洞挖掘报告 — 20261031-215030-ee17fe

- 生成时间：2026-10-31T13:51:15.703708+00:00
- 输入：`$WORKSPACE\暴风星云裂\053.zip`
- 输入模式：`zip`
- SHA256：`dec73bedc036c1309393989aea493094094031b09deb800e5d4d4666bfc8824e`
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

本次汇总仅含 1 条已去重 finding：053.php 第 3 行读取的 $_GET['name'] 未经 HTML 编码直接拼接进响应体，构成反射型 XSS（CWE-79），严重度 high，已附带 POC（HTTP 型，可动态复现）。这是本次唯一交付项，也是最高危项。其余类型（command_injection / sql_injection / path_traversal / ssrf / weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）均无 finding 交付，但攻击面测绘明确指出输入未提供 053.php 源码正文、sink 热点为空，因此这些属于“证据不足、未交付”，不能表述为不存在。POC 齐全度：1/1 finding 有 POC，但仅覆盖 XSS 一类。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 308 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 053.php（11 行）。已逐行审计：第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器 XSS 过滤；第 6 行读取 $_GET['name'] 仅判非 NULL；第 8 行将参数原样拼入 HTML 片段 $html，构成反射型 XSS 的完整 source→sink 链，已作为唯一 finding 交付。未发现命令执行、SQL、文件包含、反序列化、SSRF 等汇点（脚本中无相关函数调用）。未闭合线索：脚本末尾未见显式 echo $html，输出语句可能被截断或依赖部署环境，需人工确认响应体确实包含 $html；无端点清单、无部署配置、无依赖清单，无法评估 register_globals/allow_url_include 等影响面；weak_hash/weak_crypto/weak_random/insecure_cookie 在可见 11 行中均无对应调用，不成立。输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 053.php 末尾缺少显式输出语句，$html 是否真正回显需人工确认
- 无 HTTP 端点清单与部署配置，无法确认访问路径、PHP 版本与 php.ini 设置
- 无依赖清单，无法评估第三方组件 CVE
- 无认证/会话文件，无法评估 insecure_cookie 与 trust_boundary

## 3. Findings

### F-1: 053.php 中 $_GET['name'] 未编码直接拼接进 HTML 导致反射型跨站脚本（CWE-79）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`053.php:7-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP GET 请求向 053.php 传入参数 name（源码中具体注入点为 $_GET['name']，即查询参数 name）。该值在 053.php 第 8 行被直接字符串拼接进 $html 累积变量：$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';，随后该 $html 被输出到响应页面（第 7 行注释表明这是面向终端用户的反馈输出）。整个链路中不存在 htmlspecialchars/htmlentities 等 HTML 实体编码，也没有白名单或类型校验，因此用户可控内容原样进入 HTML 文本上下文，浏览器会将其解析为标签/事件处理器。由于注入点位于 <pre> 元素内部，攻击者可闭合或直接插入 <script>、<img onerror> 等载荷。

**source / sink**

- source：query `name`（053.php）
- sink：053.php:8 	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `053.php:8` | 请求参数直接进入 HTML 累积变量；需按 HTML/属性/JS 上下文确认编码 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /053（GET）的反射型跨站脚本 POC。源码 053.php:8 将 GET 参数 name 直接输出到响应，未做 HTML 编码，导致脚本在受害者浏览器执行。目标地址使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS：攻击者可构造带恶意 name 参数的链接，诱导受害者点击后在目标站点源下执行任意 JavaScript，从而窃取会话 Cookie/令牌、以受害者身份发起操作（越权）、篡改页面内容或进行钓鱼。属于客户端代码执行，不直接导致服务器 RCE，但可造成账户接管与数据泄露。

**CVE / CWE 论证**

CWE-79（Improper Neutralization of Input During Web Page Generation，跨站脚本）。外部可达性：053.php 为可通过 HTTP GET 直接访问的页面，name 为普通查询参数，无需认证即可触发；利用链闭合：source（$_GET['name']）→ 无编码拼接（053.php:8）→ 输出至 HTML 响应，三步均在给定代码片段内可见，无中间净化环节。证据等级为基于源码的推断（llm_inferred），未做运行时验证。

**修复建议**

1) 输出前对不可信数据做上下文相关编码：在 HTML 文本/属性上下文使用 htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')；2) 对 name 参数做长度与字符白名单校验（如仅允许字母数字与有限符号）；3) 设置响应头 Content-Type: text/html; charset=UTF-8，并部署 Content-Security-Policy 限制内联脚本；4) 为会话 Cookie 设置 HttpOnly，降低被窃取风险。

**验证说明**

静态证据：入口 GET /053；source=query/name；sink=053.php:8；规则 php-html-accumulator。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 URL：/053.php?name=<script>alert(document.cookie)</script>（仅限授权测试，目标以 TARGET 占位）。请求到达 053.php 后，PHP 从查询串解析出 name 参数，第 8 行将其与固定前缀 '<pre>Hello ' 和后缀 '</pre>' 直接拼接进 $html，未经过任何编码或过滤；$html 随后被写入 HTTP 响应体，浏览器在 <pre> 内解析到 <script> 标签并执行，完成 XSS。
PocWriter 建议（未采纳，缺少端点 /053）：符合 CWE-79。漏洞位于可交付代码 053.php:8，外部输入来自 query 参数 name，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；目标统一使用 TARGET 占位符，仅限授权测试。请求结构沿用已有确定性草稿，仅补充说明与预期结果。

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
| `LLM-3ca7baf03343` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/053.php | corroborated |

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
| safety_guard | 安全防护 | 3.79 | 是 |
| surface_mapper | 攻击面测绘 | 8.17 | 是 |
| deep_finder | LLM 深挖 | 9.59 | 是 |
| candidate_screener | 候选筛选 | 4.28 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.44 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.69 | 是 |
| coordinator | 管线协调 | 6.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
