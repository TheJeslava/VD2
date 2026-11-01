# 落日二号乙漏洞挖掘报告 — 20261031-012244-3d8a38

- 生成时间：2026-10-30T17:23:14.684473+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\052.zip`
- 输入模式：`zip`
- SHA256：`6b53fa2c4a30c16747b1ae8a0236ae3f7fb52d1a4bc7e7999805f539e733c540`
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

本次汇总仅含 1 条已去重 finding：052.php 第 3 行读取的 name 参数经不完整黑名单过滤后直接回显，构成反射型 XSS（medium，LLM-4be6b4e0336a），且该文件显式关闭 X-XSS-Protection，浏览器侧防护缺失。该条已附带 POC（HTTP 型，可动态复现路径清晰），POC 齐全度 1/1。最高危即此条 medium XSS；未出现 high/critical 级别结论。需强调：本次仅覆盖单文件 14 行 PHP，sink 热点为空、无端点清单，覆盖极不完整，不能据此推断项目整体安全性。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 409 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 052.php（14 行，已完整覆盖 1-14 行）。该文件为独立 PHP 片段，无框架、无路由、无端点声明。第 6 行读取 $_GET['name']，第 8 行使用仅针对 script 标签的黑名单正则过滤，第 11 行将结果未编码拼入 HTML 输出，第 3 行显式关闭 X-XSS-Protection，构成可闭合的反射型 XSS 链。未发现 SQL/命令/文件包含/反序列化等其它 sink（文件中不存在相关调用）。未闭合线索：缺少 Web 服务器配置与部署信息，无法确认文件对外可达性及响应头 Content-Type；缺少同目录依赖文件，无法判断是否存在 include 链。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/php.ini 配置，无法确认 052.php 对外可达性与响应 Content-Type
- 缺少同目录其它文件与 include 依赖，无法确认完整调用链
- 无端点清单与请求样例，参数名 name 与 GET 传参方式依据源码推断
- 未做动态验证，XSS 实际执行需人工确认

## 3. Findings

### F-1: 052.php 中 name 参数经不完整黑名单过滤导致反射型 XSS（X-XSS-Protection 被显式关闭）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`052.php:3-11`
- **来源**：`llm_finding`

**描述**

052.php 第 6 行从 $_GET['name'] 读取用户输入，第 8 行仅用正则 /<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i 删除形如 <script 的片段，第 11 行将结果直接拼接进 HTML 字符串 $html .= "<pre>Hello {$name}</pre>" 并输出。该黑名单只匹配以 < 开头、且 s/c/r/i/p/t 顺序出现的标签，无法覆盖其它可执行脚本的标签与事件处理器（如 <img src=x onerror=...>、<svg onload=...>、<body onload=...>），也无法覆盖大小写/嵌套绕过（如 <scr<script>ipt> 被删除内层后重组）。同时第 3 行 header("X-XSS-Protection: 0") 主动关闭浏览器 XSS 过滤器，进一步降低利用门槛。攻击者可构造恶意链接诱导受害者访问，在受害者浏览器上下文执行任意 JavaScript，窃取会话或发起敏感操作。

**source / sink**

- source：query `name`（052.php:6）
- sink：052.php:11 第 11 行 $html .= "<pre>Hello {$name}</pre>" 将未转义输入拼入 HTML 输出

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `052.php:6` | 通过 array_key_exists 检查并读取 $_GET['name']，仅要求非 NULL | 原始攻击者字符串 |  |
| 2 | `052.php:8` | preg_replace 用黑名单正则删除 <...script...> 片段 | 仅移除匹配 <script 模式的子串，其它标签/事件属性原样保留 | 黑名单只覆盖 script 标签，未覆盖 img/svg/body 等标签的 onerror/onload 事件处理器，也未做 HTML 实体编码 |
| 3 | `052.php:11` | 过滤后的 $name 直接拼接进 $html 的 <pre> 标签内输出 | 未编码的 HTML 片段进入响应体 |  |
| 4 | `052.php:3` | 响应头显式设置 X-XSS-Protection: 0，关闭浏览器内置 XSS 过滤 | 浏览器不再拦截反射型 XSS |  |

**POC**

针对 /052.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 name，源码 052.php:11 将外部输入直接写入响应且未做 HTML 编码，source→sink 链静态闭合。目标地址统一使用 TARGET 占位符，仅限授权测试。

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
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者可在受害者浏览器上下文执行任意脚本，窃取 Cookie/会话令牌、伪造请求执行敏感操作或进行钓鱼。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部无需认证即可通过 GET 参数触发，source→sink 链在 052.php 内完整闭合，黑名单过滤可被非 script 标签绕过，且 X-XSS-Protection 被显式关闭。

**修复建议**

移除黑名单过滤，改用 htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 对输出进行 HTML 实体编码；删除 header("X-XSS-Protection: 0")，改为启用 CSP 与 X-XSS-Protection: 1; mode=block。

**验证说明**

需确认 052.php 实际对外可达且响应 Content-Type 为 text/html；需动态验证浏览器确实执行注入脚本（本管线不做动态验证）。
模型 POC 要点：构造包含非 script 标签事件处理器的 name 参数，诱导受害者点击链接后在浏览器执行脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /052.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 052.php:11，外部输入来自 GET 查询参数 name，直接汇入响应输出且未发现有效编码/净化，具备远程无认证触发条件；当前为静态源码推断（llm_inferred），未经动态验证。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。手工验证时请将 TARGET 替换为已授权环境地址，并逐条手动发送上述请求；不要将请求串联为自动执行脚本。若响应中载荷被编码或过滤，需回到源码复核 052.php:11 的上下文与净化逻辑，不得据此扩大结论。

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
| safety_guard | 安全防护 | 2.97 | 是 |
| surface_mapper | 攻击面测绘 | 5.56 | 是 |
| deep_finder | LLM 深挖 | 8.23 | 是 |
| candidate_screener | 候选筛选 | 2.98 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.85 | 是 |
| coordinator | 管线协调 | 6.0 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
