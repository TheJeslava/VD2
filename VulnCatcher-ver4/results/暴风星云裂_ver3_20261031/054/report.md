# 落日二号乙漏洞挖掘报告 — 20261031-010547-d734e8

- 生成时间：2026-10-30T17:06:15.079344+00:00
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

本次汇总仅包含 1 条已去重 finding：054.php 的反射型 XSS（LLM-04dd02aad740，medium）。该脚本用 str_replace 只过滤小写 <script> 标签，可通过大小写变体或其它标签绕过，属于本次最高危项，也是唯一交付项。该 finding 附带 POC（has_poc=true），但 POC 为静态源码推断产物，未做动态验证，不能宣称可动态复现。整体攻击面极小：单文件 PHP 脚本 14 行、288 字节，无框架、无路由、无端点清单；source_hot_files 指向 054.php:3 的外部输入读取点，但 sink_hot_files 为空，危险汇点完全依赖人工阅读源码确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 054.php（14 行），已 100% 逐行审计。确认第 6 行 $_GET['name'] 为外部输入源，第 8 行 str_replace 黑名单可被大小写/其它标签绕过，第 11 行直接拼接输出形成反射型 XSS；第 3 行主动关闭 X-XSS-Protection。未发现命令执行、文件包含、SQL、反序列化等其它 sink（脚本无此类调用）。未覆盖：无 php.ini/Web 服务器配置、无端点清单、无依赖清单，无法确认部署可达性与环境设置；配置类攻击面无证据。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、部署路径
- 无端点清单，URL 路径与请求方法为推断
- 无依赖清单

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 仅过滤小写 <script> 标签，可被大小写/其它标签绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>','',...) 做单次、区分大小写的黑名单替换，第 11 行将结果直接拼接进 HTML 并输出到响应体。攻击者可用 <SCRIPT>、<img onerror>、<svg onload> 等绕过黑名单，在受害者浏览器执行任意 JS。第 3 行 header("X-XSS-Protection: 0") 主动关闭了浏览器内置 XSS 过滤器，进一步降低利用门槛。

**source / sink**

- source：query `name`（054.php:6）
- sink：054.php:11 echo/输出 $html 到 HTTP 响应（第 11 行字符串拼接后随脚本结束输出）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | 检查 $_GET['name'] 存在且非 NULL，读取外部输入 | 原始攻击者字符串 |  |
| 2 | `054.php:8` | str_replace('<script>','',...) 仅删除精确小写 <script> 子串，区分大小写且只处理一种标签 | <SCRIPT>alert(1)</SCRIPT> 或 <img src=x onerror=alert(1)> 原样保留 | 黑名单区分大小写且只覆盖 <script>，未做 HTML 实体编码 |
| 3 | `054.php:11` | 将 $name 拼接进 <pre>Hello {$name}</pre> 并赋给 $html | HTML 中嵌入未编码的攻击者 payload |  |
| 4 | `054.php:3` | 响应头 X-XSS-Protection: 0 关闭浏览器 XSS 过滤 | 浏览器不拦截反射型 XSS | 主动禁用内置防护 |

**POC**

针对 /054.php（GET）的反射型跨站脚本（CWE-79）。注入点为 GET 查询参数 name，源码 054.php:11 将外部输入直接输出到响应而未做 HTML 编码，source→sink 链静态闭合。POC 仅使用 TARGET 占位符，仅限授权测试。

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话 Cookie、伪造请求、钓鱼；X-XSS-Protection:0 使现代浏览器内置防护失效。

**CVE / CWE 论证**

CWE-79。外部 GET 参数直达 HTML 输出，黑名单可绕过，无需认证，链闭合。

**修复建议**

输出前使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 进行 HTML 实体编码；移除 X-XSS-Protection:0；不要依赖黑名单过滤。

**验证说明**

需确认 054.php 实际部署路径与是否公网可达；XSS 属客户端漏洞，需人工在浏览器确认执行。
模型 POC 要点：构造绕过 str_replace 的 payload，诱导受害者访问带 payload 的链接，脚本在受害者浏览器执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 054.php:11，外部输入来自 GET 查询参数 name，source→sink 链已静态闭合，未发现有效净化/编码，具备远程触发条件；未分配 CVE，按 CWE 归类说明。
POC 备注：仅文本工件，不执行、不联网、不搭建沙箱。目标统一使用 TARGET 占位符，端口 8080 为示例，可按实际部署调整。request.http 中的 Content-Length 仅对带 body 的请求有意义，本 GET 请求无 body，可忽略该头。若需验证执行效果，应在授权测试浏览器中手动打开构造的 URL，而非由管线自动运行。

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
| safety_guard | 安全防护 | 2.83 | 是 |
| surface_mapper | 攻击面测绘 | 5.19 | 是 |
| deep_finder | LLM 深挖 | 6.44 | 是 |
| candidate_screener | 候选筛选 | 2.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.39 | 是 |
| coordinator | 管线协调 | 5.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
