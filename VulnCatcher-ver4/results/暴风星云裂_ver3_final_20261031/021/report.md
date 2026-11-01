# 落日二号乙漏洞挖掘报告 — 20261031-013944-39c3ed

- 生成时间：2026-10-30T17:40:27.759224+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\021.zip`
- 输入模式：`zip`
- SHA256：`ff9631d6e9310b5ffe2f51550d4a9e5b12c4e83ee69a263543f6be3776889254`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 021.php：一条为反射型 XSS（LLM-cd298cc9bb86，medium，POST 参数 include 未编码拼接进页面，且 CSP nonce 硬编码可绕过），一条为 CSP 配置缺陷（SEM-e8635bcf499d，medium，同时启用 'unsafe-inline' 与固定 nonce，CWE-693）。最高危为上述两条 medium 级问题，二者相互叠加会放大 XSS 可利用性。两条 finding 均带 POC（has_poc=true，共 2/2），但均为静态/文本 POC，未做动态验证，不能宣称可动态复现。本次未发现二次注入链，未发现 prompt_injection 证据。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 877 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 021.php（25 行，DVWA CSP 练习页）。已审计：第 3-8 行 CSP/X-XSS-Protection 响应头、第 14-18 行 POST include 参数拼接、第 19-25 行表单输出。发现一条闭合的反射型 XSS 链：$_POST['include'] 未编码拼入 $page['body']，且 CSP nonce 硬编码、X-XSS-Protection 被关闭，可绕过 CSP 执行脚本。未发现 SQL 拼接、命令执行、文件包含、反序列化等 sink；无 md5/sha1/rand/setcookie 等配置型风险证据。未闭合线索：$page['body'] 的最终输出模板不在 code_pack 内，无法确认是否二次编码；无部署/认证信息。按策略感知，未输出不代表不存在，仅表示本文件内无更多可闭合链。

未覆盖 / 证据缺口：
- $page['body'] 的渲染模板未提供，无法确认最终输出是否编码
- 无 Web 服务器/php.ini 配置，无法判断 CSP 是否被代理覆盖
- 无认证与部署信息，无法确认外部可达性

## 3. Findings

### F-1: 021.php 中 POST 参数 include 未编码直接拼接进页面导致反射型 XSS（CSP nonce 硬编码可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`021.php:14-18`
- **来源**：`llm_finding`

**描述**

021.php 第 14-18 行读取 $_POST['include']，未经任何 HTML 实体编码或过滤，直接字符串拼接进 $page['body']，随后该变量被输出到页面（本文件为 DVWA CSP 练习页，body 由外层模板渲染）。同时第 3 行 CSP 使用硬编码固定 nonce 'TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA='，且第 8 行显式发送 X-XSS-Protection: 0 关闭浏览器 XSS 过滤。攻击者可提交带该固定 nonce 的 <script> 标签，既绕过 CSP 又执行任意 JS，形成反射型 XSS。

**source / sink**

- source：body `include`（021.php）
- sink：021.php:18 $page['body'] 字符串拼接后输出到 HTML 响应（模板渲染 body）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:14` | 检测到 POST 参数 include 存在 | 原始攻击者输入 $_POST['include'] |  |
| 2 | `021.php:15-17` | 将 include 值直接字符串拼接到 $page['body']，无 htmlspecialchars/实体编码 | 未编码的 HTML/JS 片段进入页面 body |  |
| 3 | `021.php:3-5` | 响应头设置固定 nonce 的 CSP，攻击者可在 payload 中复用同一 nonce 使内联脚本被允许执行 | CSP 因 nonce 可预测而失效 | nonce 硬编码在源码中，攻击者可直接读取并复用 |
| 4 | `021.php:8` | X-XSS-Protection: 0 关闭浏览器反射型 XSS 过滤 | 浏览器不再拦截 | 显式关闭 XSS 审计 |

**POC**

针对 /021.php（POST）的反射型跨站脚本 POC。注入点为 POST 表单参数 include，源码 021.php:18 处将外部输入直接输出到响应，未做 HTML 实体编码；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/021.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cd298cc9bb86`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可构造链接诱导受害者提交表单，在目标域执行任意 JS，窃取会话或执行敏感操作；CSP 因固定 nonce 形同虚设。

**CVE / CWE 论证**

CWE-79 反射型 XSS；外部无需认证即可通过 POST 触发，污点链在 021.php 内闭合（source 第 14 行 → 拼接第 15-17 行 → 输出 body），CSP 绕过由第 3 行硬编码 nonce 与第 8 行关闭 XSS 过滤共同支撑。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出；CSP nonce 每次请求随机生成（random_bytes）而非硬编码；移除 X-XSS-Protection: 0。

**验证说明**

需确认外层模板确实将 $page['body'] 原样输出（本 code_pack 仅含 021.php，未见渲染模板）；若模板做了二次编码则链不成立。
模型 POC 要点：向 021.php 提交带固定 nonce 的 script 标签，绕过 CSP 执行 alert
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /021.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 021.php:18，外部输入来自 POST body 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化/编码；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标并确认授权范围。若响应中脚本被 HTML 实体编码，则说明存在净化，应判定为不可利用。

### F-2: 021.php 中 CSP 策略同时启用 'unsafe-inline' 与固定 nonce，削弱脚本来源限制（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`021.php:2-3`
- **来源**：`rule`

**描述**

证据来自 021.php 第 3 行：$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';"。该策略在 script-src 中同时声明 'self'、'unsafe-inline' 和一个硬编码的 nonce 值（base64 解码为 "Never going to give you up"）。攻击者输入点：任何能向页面注入 HTML 的入口（如反射型参数、存储型内容、第三方脚本或同源上传/JSONP 端点）——本 code_pack 仅给出 021.php 第 2-4 行，未提供具体 getParameter/getHeader 等取值语句，因此具体注入参数名证据不足。经过的变量/函数：注入内容进入响应 HTML 后由浏览器按第 3 行下发的 CSP 解析。校验为何无效：'unsafe-inline' 使内联 <script> 与事件处理器（onerror/onload 等）无需 nonce 即可执行，nonce 白名单形同虚设；同时 nonce 为源码中硬编码常量，任何能读取该文件或从历史响应中获取该值的攻击者都可复用同一 nonce 构造 <script nonce=...>，nonce 的“每次响应随机”安全前提被破坏。最终危险操作：浏览器执行攻击者控制的脚本，CSP 未能阻断。

**source / sink**

- source：query `include`（021.php）
- sink：021.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `021.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /021（021.php:3）的 CSP 配置缺陷 POC。该端点未下发有效的 Content-Security-Policy 响应头（或策略缺失/过宽），无法缓解同页面的脚本注入；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/021'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/021?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-e8635bcf499d`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 作为纵深防御失效：一旦存在任意 HTML 注入点（反射/存储型 XSS、富文本、第三方组件），攻击者脚本可在受害者浏览器上下文执行，导致会话 Cookie/令牌窃取、以受害者身份发起操作（CSRF 绕过同源策略防护）、页面内容篡改与钓鱼。注意：本 finding 本身是配置型弱点，不直接构成 XSS；实际脚本执行仍需一个独立的注入入口，该入口在本 code_pack 中未提供。

**CVE / CWE 论证**

CWE-693（Protection Mechanism Failure）：安全机制（CSP script-src）被配置为不生效。外部可达性：021.php 为 Web 可访问脚本，第 3 行策略随响应头下发，任何访问者均无需认证即可获得该策略。利用链闭合度：配置缺陷部分闭合（策略文本已确认），但“攻击者脚本注入点”这一环在给定 code_pack 中缺失，故不能宣称完整可利用链；置信度按此下调。

**修复建议**

1) 从 script-src 中移除 'unsafe-inline'，改用 nonce 或 hash 白名单；2) nonce 必须每次响应由 CSPRNG 生成（如 random_bytes(16) 后 base64），禁止硬编码常量，且不得在日志/错误页回显；3) 若必须兼容旧代码，使用 'strict-dynamic' 配合 nonce，并保留 'self' 作为回退；4) 增加 object-src 'none'、base-uri 'self'、frame-ancestors 限制；5) 通过响应头统一注入 CSP（避免模板拼接），并对所有输出点做上下文相关编码，从根上消除 HTML 注入入口。

**验证说明**

静态证据：入口 ANY /021；source=query/include；sink=021.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 021.php 相关页面提交可注入 HTML 的内容（具体参数名在 code_pack 中未给出，证据不足）→ 内容未经充分编码进入响应体 → 浏览器解析第 3 行下发的 CSP：因含 'unsafe-inline'，内联脚本/事件处理器被放行；因 nonce 为硬编码常量，攻击者可复用该 nonce 通过 nonce 校验 → 攻击者脚本在受害者会话中执行 → 窃取会话或执行越权操作。链条中“注入点”环节需运行时/跨文件证据补全。
PocWriter 建议（未采纳，缺少端点 /021）：符合 CWE-693（保护机制失效）。问题位于 021.php:3 的响应头/策略配置，属配置型候选，无 HTTP 污点链；证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。CSP 缺陷本身不直接执行代码，需与注入点结合评估；执行前须将 TARGET 替换为授权测试目标。

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
| `csp` | CWE-693 |  | 1 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.69 | 是 |
| surface_mapper | 攻击面测绘 | 8.43 | 是 |
| deep_finder | LLM 深挖 | 7.22 | 是 |
| candidate_screener | 候选筛选 | 5.2 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.25 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.08 | 是 |
| coordinator | 管线协调 | 5.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
