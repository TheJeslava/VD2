# 落日二号乙漏洞挖掘报告 — 20261031-010300-44564a

- 生成时间：2026-10-30T17:03:38.681177+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\036.zip`
- 输入模式：`zip`
- SHA256：`21f0b55e102a19f7e1305cfce872a6ab1e1c931079a8ad1e4b9dbafe94f87b7f`
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

本次汇总仅包含 1 条已去重 finding：036.php 的开放重定向（open_redirect，medium，LLM-7af8cc31bcdd），该条已附带 POC（has_poc=true），但 POC 属于静态源码推断型，尚未做动态验证。最高危项即该开放重定向：第 4 行读取的请求参数被用于第 13 行的跳转，且未对协议相对 URL（//evil）做校验。整体覆盖面极窄：仅 1 个 PHP 文件、0 个端点清单、无框架、无依赖清单，sink 热点为空，因此注入类、文件包含、XSS 等攻击面均未形成可交付结论。POC 齐全度：1/1 条 finding 带 POC，但均为静态证据，不能宣称可动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 036.php（21 行，已完整展示 1-21 行）。审计了唯一攻击面：第 3 行 $_GET['redirect'] 读取、第 4 行 http/https 黑名单、第 11 行 header("location: ...") 汇点。确认存在开放重定向（协议相对 URL 绕过黑名单），链在文件内闭合。未发现 SQL/命令执行/文件包含/反序列化等其它汇点；该脚本无认证、无数据库、无文件操作。surface_notes 中提到的 LFI/RFI、XSS 等推断在源码中无对应证据（redirect 值仅进入 Location 头，未 echo 到 HTML 正文），故不报告。未覆盖范围：无 php.ini、Web 服务器配置、部署暴露情况与依赖清单，无法评估 allow_url_include、open_basedir 及是否公网可达；这些不影响本 finding 的链闭合，但影响实际可利用性。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 Location 头是否被规范化及是否有额外重定向防护
- 无端点/路由清单，无法确认脚本对外暴露与访问控制
- 无依赖清单，无法评估第三方组件 CVE
- 未提供部署环境（PHP 版本、是否公网），影响实际可利用性评估

## 3. Findings

### F-1: 036.php redirect 参数未校验导致的开放重定向（协议相对 URL 绕过）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

036.php 第 3 行从 $_GET['redirect'] 读取重定向目标，第 4 行仅用正则 /http:\/\/|https:\/\//i 拦截以 http:// 或 https:// 开头的绝对 URL，第 11 行直接执行 header("location: " . $_GET['redirect'])。该黑名单只匹配带 scheme 的绝对 URL，未拦截以 // 开头的协议相对 URL（如 //evil.example），也未拦截反斜杠变体（如 /\evil.example，部分浏览器会规范化为 //evil.example），因此攻击者可构造 //attacker.tld 使 Location 头指向外部域，实现开放重定向。该脚本无任何认证，直接 HTTP 访问即可触发。

**source / sink**

- source：query `redirect`（036.php:3）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | 从 $_GET['redirect'] 读取攻击者可控的重定向目标，仅要求非空 | 原始字符串，未做任何规范化或编码 |  |
| 2 | `036.php:4` | preg_match 黑名单仅匹配 http:// 或 https:// 前缀 | //attacker.tld 不含 http:// 或 https://，正则不匹配，进入 else 分支 | 黑名单只覆盖带 scheme 的绝对 URL，协议相对 URL //host 与反斜杠变体 /\host 均绕过 |
| 3 | `036.php:11` | 将未校验的 redirect 值直接拼入 Location 响应头并 exit | Location: //attacker.tld，浏览器按当前页面协议解析为外部域 |  |

**POC**

针对 /036.php（GET）的 开放重定向 POC。注入点：GET 参数 redirect；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`//example.com`
- POC 目录：`poc/LLM-7af8cc31bcdd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可借助受信任域名的链接将用户重定向到钓鱼/恶意站点，用于凭据窃取或 OAuth/SSO 流程劫持；由于脚本无认证，任何访问者均可被诱导。

**CVE / CWE 论证**

CWE-601 URL Redirection to Untrusted Site（Open Redirect）。外部可达、无需认证、source→sink 链在 036.php:3-11 完整闭合，黑名单可被协议相对 URL 绕过。

**修复建议**

不要使用黑名单。改为白名单校验：解析目标后仅允许相对路径（拒绝以 // 或 /\ 开头），或维护允许的 host 列表并比对 parse_url 的 host；也可仅接受站内相对路径并强制以单个 / 开头且不含 //。

**验证说明**

需动态确认 Web 服务器是否原样透传 Location 头（部分容器会规范化），以及目标浏览器对 // 与 /\ 的处理；未提供 php.ini/服务器配置，无法确认是否有额外重定向防护。
模型 POC 要点：利用协议相对 URL 绕过 http/https 黑名单，使服务端返回指向外部域的 302 重定向
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：针对 036.php（GET 路由）的开放重定向（CWE-601）POC。注入点为 GET 查询参数 redirect，其值被直接用于跳转目标（036.php:13 附近），未做白名单/同源校验。payload 使用 //example.com 形式（协议相对 URL），可绕过仅检查是否以 http 开头的朴素过滤。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 036.php:13，外部输入来自 GET 查询参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化（如域名白名单、相对路径强制），具备远程未认证触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。手工验证时请将 TARGET 替换为授权环境地址，并仅使用自有测试域名替代 example.com。禁止对生产环境或第三方站点发起请求。

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
| `open_redirect` | CWE-601 |  | 1 |
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
| safety_guard | 安全防护 | 2.68 | 是 |
| surface_mapper | 攻击面测绘 | 5.01 | 是 |
| deep_finder | LLM 深挖 | 7.97 | 是 |
| candidate_screener | 候选筛选 | 3.11 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.23 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.63 | 是 |
| coordinator | 管线协调 | 5.24 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
