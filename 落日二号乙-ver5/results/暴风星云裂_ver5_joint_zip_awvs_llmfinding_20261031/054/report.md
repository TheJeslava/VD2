# 落日二号乙漏洞挖掘报告 — 20261031-215033-0a3796

- 生成时间：2026-10-31T13:51:14.227261+00:00
- 输入：`$WORKSPACE\暴风星云裂\054.zip`
- 输入模式：`zip`
- SHA256：`f56d8d7acab4a33d76750401c5e2eec81cfdf4ce2a39a589bd28299560fe4eb0`
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

本次汇总仅含 1 条已去重 finding：054.php 的反射型 XSS（LLM-04dd02aad740，medium），成因是 str_replace 只过滤小写 <script> 且显式关闭 X-XSS-Protection，已附带 POC（HTTP 型，可动态复现）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC。需注意：攻击面测绘明确说明输入未提供任何代码片段，仅第 3 行被标为 source 热点，因此除该 XSS 外的所有判断均为文件级推断（llm_inferred），不构成漏洞结论；path_traversal、command_injection、weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均未交付，需按档位与人工复核处理，不能表述为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 054.php（14 行），已通读全部 1-14 行。审计结论：第 6 行 $_GET['name'] 为唯一外部输入源，第 8 行 str_replace('<script>','',...) 为大小写敏感、单次、非递归的黑名单过滤，可被 <Script>、<scr<script>ipt>、<img onerror> 等绕过；第 11 行将 $name 直接插值进 HTML 输出，无 htmlspecialchars 编码；第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器 XSS 过滤器。构成一条闭合的反射型 XSS 链，已作为唯一 finding 交付。其余攻击面核查：文件中不存在 include/require、文件读写、system/exec/eval、SQL 拼接、反序列化、SSRF、setcookie/session、md5/sha1/rand 等调用，故 path_traversal、command_injection、sql_injection、weak_hash、weak_crypto、weak_random、insecure_cookie、trust_boundary 均无证据支撑，不报告。surface_notes 中提到的 getParameterMap/getParameterNames、Runtime.exec(args,env) 等 Java 语义与本 PHP 文件无关，属测绘模板残留，未采纳。未覆盖范围：无 HTTP 端点清单、无框架/依赖、无 php.ini 与 Web 服务器配置、无认证会话实现，无法评估部署层防护与组件 CVE；这些缺口不影响上述 XSS 链的源码闭合性。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认是否有 WAF 或输出编码中间件
- 无端点清单，无法确认 054.php 的实际路由与访问控制
- 无认证/会话实现，无法评估 Cookie 窃取的实际收益
- 仅单文件，无法判断是否存在跨文件包含或二次注入存储读写点

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 仅过滤小写 <script> 且显式关闭 X-XSS-Protection

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.91`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`054.php:3-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>','',...) 做单次、大小写敏感、非递归的黑名单替换，第 11 行把结果直接拼接进 HTML 并输出。攻击者可用大小写混写（<Script>）、嵌套构造（<scr<script>ipt>，替换后重新拼出 <script>）或完全不用 script 标签（<img src=x onerror=...>、<svg onload=...>）绕过过滤。第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。结果是在受害者浏览器上下文中执行任意 JavaScript，可窃取会话 Cookie、伪造用户操作或进行钓鱼。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 $html .= "<pre>Hello {$name}</pre>" 直接输出到 HTML 响应体（第 11 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | array_key_exists('name', $_GET) 判断参数存在，$_GET['name'] 为攻击者完全可控的字符串 | 原始外部输入，未做任何编码 |  |
| 2 | `054.php:8` | str_replace('<script>','',$_GET['name']) 仅删除精确小写字符串 <script>，单次非递归替换 | 黑名单过滤后的字符串；大小写变体、嵌套标签、非 script 标签均原样保留 | 过滤为大小写敏感的单次字面量替换：<Script>、<SCRIPT>、<scr<script>ipt>（替换后重组为 <script>）、<img src=x onerror=alert(1)>、<svg onload=alert(1)> 均可绕过 |
| 3 | `054.php:11` | $name 被直接插值进 "<pre>Hello {$name}</pre>" 并写入响应，无 htmlspecialchars 等输出编码 | 未编码的 HTML 片段进入响应体 |  |
| 4 | `054.php:3` | 响应头 X-XSS-Protection: 0 关闭浏览器反射型 XSS 过滤器 | 响应头配置，削弱浏览器侧防护 |  |

**POC**

针对 /054.php（GET）的反射型跨站脚本（CWE-79）。源码 054.php:11 将 GET 参数 name 的值直接输出到响应 HTML 中，未做 HTML 实体编码，攻击者构造的 <script> 会在受害者浏览器执行。POC 仅使用 TARGET 占位符，仅限授权测试。

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

在受害者浏览器上下文执行任意 JavaScript，可窃取非 HttpOnly 会话 Cookie、读取页面敏感数据、以受害者身份发起请求（CSRF 链）、篡改页面内容进行钓鱼。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部无需认证即可通过 GET 参数 name 触发，source（054.php:6）到 sink（054.php:11）链路完整闭合，过滤（054.php:8）为可绕过的黑名单，且 054.php:3 主动关闭 X-XSS-Protection。属于反射型 XSS，需受害者交互，故定级 medium。

**修复建议**

移除 X-XSS-Protection: 0 头；不要依赖黑名单替换，改用输出编码：echo '<pre>Hello ' . htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '</pre>'; 或使用上下文感知的模板自动转义。

**验证说明**

需动态确认：1) 响应 Content-Type 是否为 text/html（决定浏览器是否解析 HTML）；2) 是否存在前置 WAF/反向代理对 < > 等字符做额外过滤；3) 响应体是否确实原样回显未编码的 $name。源码层面链路已闭合。
模型 POC 要点：构造绕过 str_replace 的 payload，诱导受害者访问带 payload 的链接，脚本在受害者浏览器执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Cross-site Scripting (XSS) @ http://127.0.0.1:18081/054.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 054.php:11，外部输入来自查询参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。poc.sh 与 request.http 保留原确定性 POC 的请求结构，仅补充基线/攻击/确认三步说明；执行前需将 TARGET 替换为授权测试实例并人工确认。request.http 中 Content-Length 与 GET 无 body 不一致，实际发送时以无 body 的 GET 为准。

**外部佐证**

- awvs: Cross-site Scripting (XSS) @ http://127.0.0.1:18081/054.php

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
| `LLM-04dd02aad740` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/054.php | corroborated |

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
| safety_guard | 安全防护 | 4.13 | 是 |
| surface_mapper | 攻击面测绘 | 8.37 | 是 |
| deep_finder | LLM 深挖 | 11.55 | 是 |
| candidate_screener | 候选筛选 | 2.92 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.73 | 是 |
| coordinator | 管线协调 | 6.5 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
