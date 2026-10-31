# 落日二号乙漏洞挖掘报告 — 20261031-014448-a7dbf5

- 生成时间：2026-10-30T17:45:18.331173+00:00
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

本次汇总仅含 1 条已去重 finding：LLM-04dd02aad740，类型 xss，严重度 medium，位于 054.php 第 11 行（文件共 14 行），标题为「str_replace 单次黑名单过滤 <script> 可被绕过」的反射型 XSS，已附带 POC（HTTP 型，可动态复现方向）。最高危即此条，属 medium，无 high/critical。POC 齐全度：1/1 finding 有 POC，但该 POC 为静态推导的 HTTP 请求文本，未经动态验证。整体覆盖面极窄：仅 1 个 PHP 文件、0 个端点清单、无框架、无配置，攻击面测绘明确说明未提供代码片段与 sink 热点，因此除该 XSS 外的注入类、配置类风险均处于未覆盖状态，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 382 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 054.php（14 行），已通读全部 14 行。确认一条闭合链：$_GET['name']（第 6 行）→ str_replace 单次黑名单（第 8 行）→ 未编码拼接输出（第 11 行），构成可绕过的反射型 XSS；第 3 行 X-XSS-Protection: 0 加剧风险。未发现命令执行、SQL、文件包含、反序列化等 sink（文件中不存在相关函数）。weak_hash/weak_crypto/weak_random/insecure_cookie 等配置型候选在可见代码中无对应实现（无 md5/sha1/rand/setcookie），不单独立项。$html 变量在第 11 行前未初始化，属代码质量问题，不构成独立漏洞。输入中无 prompt_injection 文本。

未覆盖 / 证据缺口：
- 无端点清单与部署信息，无法确认是否为 Web 可达入口（若为 CLI 脚本则 XSS 不可外部触发）
- 缺少 php.ini/服务器配置，无法评估 CSP 等缓解措施
- 无依赖清单，未评估第三方组件

## 3. Findings

### F-1: 054.php 反射型 XSS：str_replace 单次黑名单过滤 <script> 可被绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`054.php:6-11`
- **来源**：`llm_finding`

**描述**

054.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用 str_replace('<script>', '', ...) 做一次非递归的黑名单替换，第 11 行将结果直接拼接进 HTML 输出（$html .= "<pre>Hello {$name}</pre>"）。由于替换只执行一次且区分大小写、只匹配字面量 <script>，攻击者可用嵌套写法 <scr<script>ipt>（替换内层后重新拼出 <script>）、大小写变形 <Script>、或其它标签/事件处理器（<img src=x onerror=...>、<svg onload=...>）绕过。第 3 行还显式发送 X-XSS-Protection: 0，主动关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。

**source / sink**

- source：query `name`（054.php）
- sink：054.php:11 $html .= "<pre>Hello {$name}</pre>" 直接输出到响应 HTML

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `054.php:6` | 检查 $_GET 中是否存在 name 且非 NULL，确认外部可控输入入口 | 原始攻击者字符串 |  |
| 2 | `054.php:8` | str_replace('<script>','',$_GET['name']) 仅做一次字面量替换 | 仅删除首个/全部字面量 <script>，其余标签与大小写变体保留 | 非递归替换：<scr<script>ipt> 删除内层后重新拼出 <script>；且不匹配 <Script>、<img onerror>、<svg onload> 等 |
| 3 | `054.php:11` | 将未编码的 $name 拼接进 <pre> 并输出到响应体 | 未做 HTML 实体编码，原样进入 HTML 上下文 |  |

**POC**

针对 /054.php（GET）的反射型跨站脚本（CWE-79）。注入点为 GET 查询参数 name，其值未经 HTML 编码即被输出到响应页面（054.php:11）。POC 使用 TARGET 占位符，仅限授权测试。

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

攻击者可在受害者浏览器上下文执行任意 JavaScript，窃取会话 Cookie、伪造用户操作或进行钓鱼；X-XSS-Protection: 0 使现代浏览器不再拦截。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 GET 参数直达 HTML 输出，无需认证，过滤为可绕过的单次黑名单替换，链闭合。

**修复建议**

移除黑名单替换，改用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 在输出前做上下文正确的 HTML 实体编码；移除 X-XSS-Protection: 0，并配置 CSP。

**验证说明**

需动态确认 PHP 版本与输出编码行为；payload 依赖浏览器对嵌套标签的解析，建议在授权环境验证 <scr<script>ipt> 与 onerror 两种变体。
模型 POC 要点：构造绕过 str_replace 的 payload，使浏览器解析出可执行脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /054.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 054.php:11，外部输入来自 GET 查询参数 name，source→sink 链在给定代码范围内静态闭合，未发现有效输出编码或过滤；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网。目标统一使用 TARGET 占位符；如需手工复现，请替换 TARGET 后在授权环境中由测试人员自行发起请求。原始确定性 POC 的请求结构（GET /054.php?name=...）保持不变，仅补充说明与预期结果。

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
| safety_guard | 安全防护 | 2.34 | 是 |
| surface_mapper | 攻击面测绘 | 7.18 | 是 |
| deep_finder | LLM 深挖 | 7.04 | 是 |
| candidate_screener | 候选筛选 | 2.29 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.8 | 是 |
| coordinator | 管线协调 | 6.5 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
