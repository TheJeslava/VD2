# 落日二号乙漏洞挖掘报告 — 20261031-012018-7910c6

- 生成时间：2026-10-30T17:20:57.549797+00:00
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

本次汇总仅含 1 条已去重 finding：036.php 的 open_redirect（medium，LLM-7af8cc31bcdd），其成因是重定向参数黑名单只拦截 http:// 与 https://，可用协议相对 URL（//evil）绕过，已附 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即此条，属中危；POC 齐全（with_poc=1/1）。需强调：攻击面测绘明确说明输入未提供 036.php 源码正文，仅有行数/字节数与 source 热点行号（第 4 行），因此除该重定向外，注入类、文件包含、配置类风险均无法确认，属覆盖缺口而非“无漏洞”。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 524 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 036.php（21 行），已通读全文。该脚本为开放重定向：第 3 行读取 $_GET['redirect']，第 4 行黑名单仅拦截 http:// 与 https://，第 11 行直接写入 Location 头，可用 // 协议相对 URL 绕过，构成 CWE-601。除此之外文件中无 SQL、命令执行、文件包含、反序列化、模板、SSRF、上传等 sink；无 md5/sha1/rand/setcookie 等配置类风险代码，故 weak_hash/weak_crypto/weak_random/insecure_cookie 等候选在本文件中无证据，不单独立项。未覆盖范围：无 php.ini/Web 服务器配置、无路由与部署信息、无依赖清单，无法评估运行时配置与第三方组件风险；输入未提供 036.php 之外的任何文件。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/Web 服务器配置，无法评估 allow_url_include、display_errors 等运行时风险
- 无端点清单与部署路径，无法确认 036.php 的实际可达 URL 与访问控制
- 无依赖清单，无法评估第三方组件 CVE
- 未做动态验证，协议相对 URL 的实际跳转行为需人工确认

## 3. Findings

### F-1: 036.php redirect 参数开放重定向（黑名单仅拦截 http:// 与 https://，可用协议相对 URL 绕过）

- **类型**：`open_redirect` / CWE-601
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`036.php:3-13`
- **来源**：`llm_finding`

**描述**

036.php 第 3 行从 $_GET['redirect'] 读取外部输入，第 4 行用正则 /http:\/\/|https:\/\//i 做黑名单校验，仅拦截以 http:// 或 https:// 开头的绝对 URL；第 11 行将未经过滤的原始值直接拼入 header("location: " . $_GET['redirect'])。攻击者可提交以 // 开头的协议相对 URL（如 //evil.example）或其它不含 http://、https:// 字样的跳转目标，绕过黑名单，使服务端返回 302 将用户重定向到攻击者控制的站点，可用于钓鱼、OAuth/SSO 令牌窃取或绕过基于域名的访问控制。

**source / sink**

- source：query `redirect`（036.php）
- sink：036.php:13 header("location: " . $_GET['redirect']) 位于 036.php:11

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `036.php:3` | 检查 $_GET 中是否存在非空的 redirect 参数，攻击者完全控制其值 | 原始外部字符串，未做任何规范化 |  |
| 2 | `036.php:4` | preg_match 黑名单仅匹配 http:// 或 https:// 子串，不匹配 // 开头的协议相对 URL，也不匹配其它跳转形式 | 校验通过（不含 http:// / https://） | 黑名单只覆盖两种绝对 URL 前缀；//evil.example 为协议相对 URL，浏览器会按当前页面协议解析为 http(s)://evil.example，正则不命中 |
| 3 | `036.php:11` | 将未过滤的 redirect 值直接写入 Location 响应头并 exit | 原样拼接到 Location 头 |  |

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

攻击者可构造指向恶意站点的链接，诱导已登录用户点击后跳转至钓鱼页面，或用于 OAuth/SSO 回调参数污染窃取授权码；也可绕过依赖域名白名单的访问控制。

**CVE / CWE 论证**

CWE-601 URL 重定向到不可信站点。入口为公开 GET 参数，无需认证；source（036.php:3）→ 黑名单校验（036.php:4，可绕过）→ sink（036.php:11 header Location）链路在 CODE PACK 内完整闭合。

**修复建议**

不要使用黑名单。改为白名单校验：仅允许相对路径（拒绝以 // 或 /\ 开头、拒绝包含 :// 与 scheme），或维护允许跳转的域名列表并解析后比对 host；也可用固定映射表将逻辑名映射到内部路径。

**验证说明**

需动态确认目标 PHP 版本对 header() 中 // 值的处理以及浏览器是否按协议相对 URL 跳转；部分客户端可能不跟随协议相对 Location，可改用 /\evil.example 或 javascript: 等变体进一步验证。未提供部署路径与是否有前置 WAF。
模型 POC 要点：利用协议相对 URL 绕过 http(s):// 黑名单，使服务端返回指向外部站点的 302 重定向
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /036.php）：针对 036.php（GET）的开放重定向（CWE-601）POC。注入点为 GET 查询参数 redirect，其值被直接用于跳转目标（036.php:13 附近），未做白名单/同源校验；payload 使用 //example.com 触发协议相对跳转。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /036.php）：符合 CWE-601（URL 重定向到不可信站点）。漏洞位于可交付代码 036.php:13，外部输入来自 GET 查询参数 redirect，source→sink 链在给定代码范围内静态闭合，未发现有效净化（无白名单、无同源校验）；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。request.http 中的 Content-Length 仅对带 body 的请求有意义，本 GET 请求无 body，可忽略该头。执行时请将 TARGET 替换为授权测试目标，并确保已获书面授权。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 6.35 | 是 |
| deep_finder | LLM 深挖 | 7.88 | 是 |
| candidate_screener | 候选筛选 | 3.35 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.07 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.22 | 是 |
| coordinator | 管线协调 | 5.93 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
