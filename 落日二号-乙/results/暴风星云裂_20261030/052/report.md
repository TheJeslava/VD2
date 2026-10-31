# 落日二号乙漏洞挖掘报告 — 20261030-225138-c55394

- 生成时间：2026-10-30T14:52:13.479763+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\052.zip`
- 输入模式：`zip`
- SHA256：`6b53fa2c4a30c16747b1ae8a0236ae3f7fb52d1a4bc7e7999805f539e733c540`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：052.php 反射型 XSS（LLM-4be6b4e0336a，high），$_GET['name'] 直接拼入 HTML 输出，preg_replace 黑名单可被嵌套标签绕过，已附 POC（HTTP 型，可动态复现，但本次未执行验证）。最高危即该条 high XSS。POC 齐全度：1/1 finding 带 POC，无缺失。二次注入链：无。需注意：surface_notes 明确说明输入未提供任何代码行内容，仅给出文件清单与 source 热点（052.php 第 3 行），因此除该条 XSS 外的注入类、配置类判断均无法落地，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 052.php（14 行），已逐行审计。确认一条闭合链：$_GET['name']（第 6 行）→ 单次 preg_replace 黑名单（第 8 行，可被嵌套标签绕过）→ 字符串拼接输出（第 11 行，无 HTML 编码），构成反射型 XSS；第 3 行主动关闭 X-XSS-Protection 加剧风险。未发现文件操作、命令执行、SQL、反序列化、SSRF 等其它 sink（文件中不存在相关调用）。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中无对应代码，未单独立项。$html 变量在第 11 行前未初始化，属代码质量问题，不构成独立漏洞。

未覆盖 / 证据缺口：
- 无 endpoints/路由信息，无法确认 052.php 是否对外暴露及是否需认证
- 缺少 php.ini/Web 服务器配置，无法确认错误回显与部署形态
- 无依赖清单，无法评估第三方组件 CVE
- 未提供隔离文件，无法判断是否存在被隐藏的敏感文件

## 3. Findings

### F-1: 052.php 反射型 XSS：preg_replace 黑名单可被嵌套标签绕过（$_GET['name'] 直接拼入 HTML）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:6-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取外部输入，第 8 行仅用单次 preg_replace 正则 '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i' 删除形如 <script 的子串，第 11 行将处理后的 $name 直接拼接进 "<pre>Hello {$name}</pre>" 输出到响应体，全程无 htmlspecialchars/htmlentities 编码。由于 preg_replace 只做一次非重叠替换，构造嵌套标签（如 <scr<script>ipt>alert(1)</script>）时，内层 <script> 被删除后外层残余片段重新拼合成可执行的 <script>，从而绕过黑名单。第 3 行还主动发送 X-XSS-Protection: 0 关闭浏览器内置 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JS，窃取会话 Cookie 或发起 CSRF 式敏感操作。

**source / sink**

- source：query `name`（052.php）
- sink：052.php:11 第 11 行字符串拼接 $html .= "<pre>Hello {$name}</pre>" 后输出到 HTTP 响应体（无输出编码）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | array_key_exists("name", $_GET) 判断参数存在，$_GET['name'] 取得攻击者可控字符串 | 原始攻击者输入，未编码 |  |
| 2 | `052.php:8` | preg_replace 用单次非重叠正则删除匹配 <...s...c...r...i...p...t 的子串 | 仅删除一次匹配；嵌套构造的残余片段被保留 | 单次 preg_replace 不递归，<scr<script>ipt> 删除内层后外层重新拼成 <script> |
| 3 | `052.php:11` | $name 直接插入 "<pre>Hello {$name}</pre>" 并累加到 $html，随后输出 | 未做 HTML 实体编码，浏览器按标签解析执行 |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 name，该参数值未经 HTML 编码即被输出到响应页面（052.php:11）。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/052.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/052.php?name=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-4be6b4e0336a`
- 执行状态：未执行（`executed=False`）

**影响**

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie、伪造请求执行敏感操作、篡改页面内容；第 3 行关闭 X-XSS-Protection 使浏览器内置防护失效。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部可达（GET 参数 name），无需认证即可构造链接，source→sink 链完整闭合；黑名单为单次 preg_replace，属典型可绕过假防护。

**修复建议**

使用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 对输出进行 HTML 实体编码；移除 X-XSS-Protection: 0；不要依赖正则黑名单过滤，改用输出编码 + CSP。

**验证说明**

需在浏览器中确认嵌套标签绕过后的实际 DOM 解析与脚本执行；确认 $html 变量在未初始化时（PHP notice）不影响输出；确认部署环境未在上层网关做额外输入过滤。
模型 POC 要点：构造嵌套 script 标签绕过黑名单，诱导受害者点击链接触发反射型 XSS
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 052.php:11，外部输入来自 GET 查询参数 name，source→sink 链静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网、不搭建沙箱。poc.sh 与 request.http 仅为参考文本，需人工替换 TARGET 后在授权环境手动执行；禁止自动化批量投递。request.http 中 Content-Length 仅对 GET 无 body 场景无实际意义，可按实际请求调整。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.78 | 是 |
| surface_mapper | 攻击面测绘 | 6.16 | 是 |
| deep_finder | LLM 深挖 | 8.96 | 是 |
| candidate_screener | 候选筛选 | 3.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.83 | 是 |
| coordinator | 管线协调 | 6.29 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
