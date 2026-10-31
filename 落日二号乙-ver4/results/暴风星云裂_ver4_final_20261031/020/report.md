# 落日二号乙漏洞挖掘报告 — 20261031-172746-227a70

- 生成时间：2026-10-31T09:28:50.140323+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\020.zip`
- 输入模式：`zip`
- SHA256：`f7bc24fccdcc53d2a999c3468bedf97d91c239734baf4f227ae7ef495dbe0b26`
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

本次汇总 4 条已去重 findings，全部集中在单文件 PHP 脚本 020.php（27 行），且 4 条均带 POC（has_poc=true）。最高危为 GEN-8f1d6361cb1e（path_traversal，high）：$_POST['include'] 未校验即用于脚本路径拼接（020.php:13），若流入 include/require 或文件读取汇点，可导致任意文件包含/读取；同文件 SEM-cc52c467496c（client_side_validation，high，020.php:15）表明服务端未重复校验、仅依赖外部脚本，二者叠加会放大路径穿越的可利用性。中危为 LLM-370901c0cb4c（xss，medium，020.php:17，include 参数未编码拼入 <script src>，反射型 XSS/CSP 绕过）与 SEM-582e93de1b73（csp，medium，020.php:3，script-src 白名单过宽）。POC 齐全度为 4/4，但均为静态/文本 POC，未做动态验证；其中 csp 与 client_side_validation 属配置/语义类，需代码与会话语义复核，不能宣称可动态复现。注意：surface_notes 明确说明输入未提供 020.php 源码行内容，因此上述行级结论的证据等级为规则命中与模型推断（llm_inferred），需人工对照源码确认。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 020.php（27 行）。已逐行审计：第 3-5 行设置宽松 CSP（script-src 白名单含 pastebin.com、unpkg.com、cdn.jsdelivr.net 等），第 13-17 行 $_POST['include'] 未编码直接拼入 <script src> 标签，构成反射型 XSS 且可借 CSP 白名单绕过。未发现 include/require、文件读写、命令执行、SQL、反序列化等其它汇点；无认证/会话/弱加密相关代码。surface_notes 中提到的 weak_hash/weak_random/insecure_cookie/hardcoded_secret 等候选在源码中均不存在对应调用，不成立。未覆盖范围：无框架配置、php.ini、部署形态信息，无法判断该脚本是否对外暴露及是否在认证之后。

未覆盖 / 证据缺口：
- 无部署/认证信息，无法确认外部可达性与是否需登录
- 无 php.ini 等配置，无法评估 CSP 实际生效与输出编码中间件
- 未提供其它文件，无法交叉验证

## 3. Findings

### F-1: 020.php 中 $_POST['include'] 未校验即用于脚本路径拼接（CWE-22 路径穿越候选）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 include 提交任意字符串（020.php:13 `if (isset ($_POST['include']))` 仅做存在性判断，未做任何白名单、规范化或路径约束）。该值在 020.php:14-15 被直接拼进 `$page['body']` 的 `<script src='...'>` 属性中。就本候选而言，污点从 POST 参数 include 进入页面模板的脚本路径位置，中间没有任何 basename()、realpath()、白名单或字符过滤，因此路径/URL 内容完全由攻击者控制。需要说明的是：该汇点是 HTML 属性中的脚本 URL，而非服务端文件系统 API（无 include()/fopen()/readfile() 等），因此“任意文件读写”这一结论在给定片段内证据不足，实际风险更偏向客户端资源加载控制（可指向攻击者域名的 JS），与 GEN-dda61ef2bad8 属同一处代码。

**source / sink**

- source：query `include`（020.php:13）
- sink：020.php:13 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `020.php:13` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /020（POST）的 路径穿越 / 任意文件读写 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN8f1d6.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN8f1d6.txt`
- POC 目录：`poc/GEN-8f1d6361cb1e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可控制页面加载的脚本来源，诱导受害者浏览器从任意外部域加载并执行 JavaScript，从而窃取会话、发起 CSRF 或进行钓鱼；若后续代码将该值用于服务端文件包含，则可升级为任意文件读取/本地文件包含。当前片段仅能确认客户端脚本源可控。

**CVE / CWE 论证**

CWE-22（路径穿越）要求外部输入未经规范化即用于路径解析。此处外部输入 $_POST['include'] 在 020.php:13 被接收、020.php:15 被拼接，无任何净化，外部可达且无需认证；但汇点为 HTML 属性而非文件系统调用，利用链在服务端文件读写环节未闭合，故仅作为路径/资源控制类弱点记录，不主张完整 CWE-22 文件读写。

**修复建议**

对 include 参数使用严格白名单（仅允许预定义页面标识），禁止直接拼接用户输入；如需路径，使用 basename() 并配合 realpath() 校验结果必须位于允许目录内；输出到 HTML 属性时使用 htmlspecialchars($v, ENT_QUOTES) 转义，并对脚本 URL 做协议/域名白名单校验。

**验证说明**

静态证据：入口 POST /020；source=query/include；sink=020.php:13；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST include → 020.php:13 isset 判断（无校验）→ 020.php:14-15 字符串拼接进 $page['body'] 的 <script src='...'> → 浏览器按攻击者指定 URL 加载脚本。服务端文件系统汇点未在片段中出现，故文件读写影响证据不足。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:13 的路径穿越 POC。源码中 POST 参数 include 未经规范化即被用于文件路径拼接/包含，攻击者可用 ../ 序列逃逸预期目录，读取或写入 testfiles 目录之外的文件。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22。漏洞位于 020.php:13，外部输入 include 经 POST 进入文件路径 sink，静态链闭合且未见有效净化，具备远程触发条件。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。执行前需将 TARGET 替换为授权目标，并确认 /tmp/sunset_GEN8f1d6.txt 的存在性；若源码实际为读操作，可改用已知系统文件路径验证。

### F-2: 020.php 依赖外部脚本且服务端未重复校验（CWE-602 客户端校验绕过）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:14-15`
- **来源**：`rule`

**描述**

020.php:14-15 将用户可控值作为 `<script src='...'>` 引入外部 JavaScript，页面逻辑依赖该外部脚本完成处理。给定片段中未见服务端对 include 参数的任何独立校验（020.php:13 仅 isset），即安全判断若发生在客户端脚本中，可被攻击者直接构造 POST 请求绕过。需注意：片段内未展示外部脚本的具体校验逻辑，因此“客户端校验”这一语义判断的证据有限。

**source / sink**

- source：client `external JavaScript`（020.php）
- sink：020.php:15 	<script src='" . $_POST['include'] . "'></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:15` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /020（POST）的 客户端校验绕过 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-cc52c467496c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若业务校验仅存在于被引入的客户端脚本，攻击者可绕过前端限制直接向服务端提交任意 include 值，配合 020.php:15 的拼接实现脚本源控制或 XSS；服务端缺乏兜底校验会放大前述注入风险。

**CVE / CWE 论证**

CWE-602（依赖客户端安全校验）。外部可达（POST 参数）、无需认证；但利用链闭合依赖外部脚本内容，给定片段未包含该脚本，故证据等级为推断。

**修复建议**

所有安全校验必须在服务端执行，客户端校验仅作体验优化；对 include 参数在服务端做白名单与格式校验；避免从用户可控 URL 加载执行脚本，改为服务端固定资源映射。

**验证说明**

静态证据：入口 POST /020；source=client/external JavaScript；sink=020.php:15；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接 POST include（绕过前端）→ 020.php:13 仅 isset → 020.php:15 拼接进 script src → 服务端无二次校验，注入生效。外部脚本校验逻辑未在片段中，闭合性证据不足。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的客户端校验绕过 POC。020.php:15 处依赖前端 JavaScript 校验，服务端未重复校验 include 参数，攻击者直接构造 POST 请求即可绕过。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-602。问题位于 020.php:15，校验仅在前端，服务端缺失等价检查，属客户端校验依赖缺陷。
POC 备注：仅限授权测试。文本工件，不执行、不联网。验证时需明确对比浏览器提交与直接构造请求的差异，并补充源码确认服务端缺失校验的具体位置。

### F-3: 020.php POST 参数 include 未编码直接拼入 <script src> 导致反射型 XSS / CSP 绕过

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行接收 $_POST['include']，未做任何 HTML 实体编码、URL 校验或白名单过滤，直接以单引号包裹拼入 <script src='...'> 标签并输出到响应体。攻击者可闭合单引号并注入任意 HTML/JS（如 '></script><script>alert(1)</script>），或利用 CSP 白名单域（pastebin.com、unpkg.com、cdn.jsdelivr.net 等）托管恶意脚本实现 CSP 绕过。该页面本身设置了宽松的 script-src 白名单，进一步放大了利用价值。

**source / sink**

- source：body `include`（020.php:13）
- sink：020.php:17 $page['body'] 字符串拼接后输出到 HTML 响应（第 14-16 行），最终由 PHP 输出到页面

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 通过 isset($_POST['include']) 判断参数存在，直接读取外部输入 | 原始字符串，未过滤 |  |
| 2 | `020.php:14-16` | 将 $_POST['include'] 以单引号包裹拼入 <script src='...'> 标签 | 字符串拼接，无 HTML 实体编码、无 URL 校验 | 无任何编码或白名单校验，单引号可直接闭合属性 |
| 3 | `020.php:18-27` | $page['body'] 最终输出到响应 HTML，浏览器解析执行注入的脚本 | 注入的 HTML/JS 进入 DOM |  |

**POC**

针对 /020.php（POST）的 跨站脚本 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-370901c0cb4c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话/发起敏感操作；结合宽松 CSP 白名单可加载外部恶意脚本。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部 POST 参数直达 HTML 输出汇点，无编码无校验，链闭合，无需认证。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES) 编码；对 URL 做协议与域名白名单校验；收紧 CSP script-src 白名单。

**验证说明**

需确认页面是否位于认证之后、是否有其它输出编码中间件；CSP 实际生效情况需动态确认。
模型 POC 要点：向 020.php 提交 include 参数，闭合 script 标签注入任意 JS；或指向 CSP 白名单域上的恶意脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型 XSS POC。POST 参数 include 在 020.php:17 处被直接输出到响应 HTML 中，未做 HTML 实体编码，注入 <script> 即可在受害者浏览器执行。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79。漏洞位于 020.php:17，外部输入 include 经 POST 进入 HTML 输出 sink，静态链闭合且未见有效编码，具备远程触发条件。
POC 备注：仅限授权测试。文本工件，不执行、不联网。验证时在浏览器中打开响应或检查响应体，勿在真实用户会话中触发。

### F-4: 020.php CSP script-src 白名单过宽（CWE-693 防护机制失效）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php:3 定义 `$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"`。该策略允许从多个第三方 CDN 与用户内容托管站点（pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net 等）加载脚本，攻击者可在这些站点托管恶意 JS 并通过 020.php:15 的 src 注入点引用，从而绕过 CSP 的 XSS 缓解作用。策略中还存在未带协议的裸域名条目（hastebin.com、www.toptal.com、example.com、unpkg.com、cdn.jsdelivr.net、digi.ninja），语义上会匹配 http/https 两种协议，进一步放宽限制。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"; // allows js from various trusted locations

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /020（POST）的 CSP 配置缺陷 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/020' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：响应包含 Content-Security-Policy，检查 script-src 是否允许过宽的外部脚本源。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-582e93de1b73`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 无法有效阻止脚本注入：即使存在 020.php:15 的注入点，攻击者仍可借助被允许的第三方托管域加载并执行任意脚本，削弱纵深防御，使 XSS 利用更稳定。

**CVE / CWE 论证**

CWE-693（防护机制失效）。属配置型弱点，无需污点链；证据为 020.php:3 的策略字符串原文。外部可达性体现在该响应头随页面下发，任何访问者均受影响。

**修复建议**

将 script-src 收紧为 'self' 加必要的固定版本资源域，移除 pastebin/hastebin/unpkg/jsdelivr 等用户可上传内容的域；所有域条目显式写 https://；引入 nonce 或 hash 机制替代宽泛域名白名单；配合 object-src 'none'、base-uri 'self'。

**验证说明**

静态证据：入口 POST /020；source=body/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：020.php:3 设置过宽 CSP → 响应头下发 → 020.php:15 注入的 script src 指向被允许的第三方托管域 → 浏览器按 CSP 放行并执行攻击者脚本。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:3 的 CSP 配置缺陷 POC。020.php:3 处响应未设置或设置了过宽的 Content-Security-Policy（如 script-src 允许 * 或 unsafe-inline），削弱对 XSS 的纵深防御。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693。问题位于 020.php:3 的响应头配置，属配置型缺陷，需以响应头证据确认。
POC 备注：仅限授权测试。文本工件，不执行、不联网。验证以响应头为准，不依赖响应体。

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
| `path_traversal` | CWE-22 | 是 | 1 |
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
| `client_side_validation` | CWE-602 |  | 1 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.8 | 是 |
| surface_mapper | 攻击面测绘 | 8.72 | 是 |
| deep_finder | LLM 深挖 | 6.98 | 是 |
| candidate_screener | 候选筛选 | 6.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 13.96 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 15.76 | 是 |
| coordinator | 管线协调 | 8.34 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
