# 落日二号乙漏洞挖掘报告 — 20261031-011715-f531f1

- 生成时间：2026-10-30T17:18:09.371322+00:00
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

本次审计对象为单文件 PHP 脚本 020.php（27 行，无框架、无路由配置、无端点清单）。共交付 4 条已去重 findings，全部带 POC：最高危为 path_traversal（GEN-8f1d6361cb1e，high，020.php 第 13 行，POST 参数 include 未校验即进入页面拼接，CWE-22）与 client_side_validation（SEM-cc52c467496c，high，第 15 行，服务端未校验 include 参数、仅依赖外部脚本，CWE-602）；另有反射型 XSS（LLM-370901c0cb4c，medium，第 17 行，include 参数未编码直接拼入 <script src>）与 CSP script-src 白名单过宽（SEM-582e93de1b73，medium，第 3 行，CWE-693）。POC 齐全（with_poc=4/4），但均为静态文本 POC，未做动态验证；其中 path_traversal 与 XSS 具备 HTTP 请求形态，client_side_validation 与 csp 属配置/逻辑型证据，需代码语义复核。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 020.php（27 行全量）。发现第 13-17 行 POST 参数 include 未编码拼入 <script src> 导致反射型 XSS。CSP 配置（第 3-5 行）因白名单包含 pastebin.com、unpkg.com、cdn.jsdelivr.net 等可托管任意脚本的公共域而可被绕过。未发现命令执行、文件包含、SQL、反序列化等其它 sink；无硬编码凭据、弱哈希、弱随机、Cookie 标志问题。无端点清单与部署配置，实际可达性需人工确认。

未覆盖 / 证据缺口：
- 无 composer.json/服务器配置，无法确认 PHP 版本与 disable_functions
- 无端点清单，实际访问路径与鉴权中间件未知
- CSP 实际生效情况与浏览器行为需动态验证

## 3. Findings

### F-1: 020.php 未校验 POST 参数 include 直接进入页面拼接（CWE-22 路径/资源引用注入）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（020.php:13 `isset($_POST['include'])`），该值未经任何白名单、规范化或路径校验，被直接拼接到 `$page['body']` 的 HTML 输出中（020.php:14-15）。源码片段中可见的唯一“校验”是 `isset()`，它只判断参数是否存在，不校验内容，因此不构成有效净化。需要说明：片段中并未出现 `include()`/`require()`/`file_get_contents()` 等真正的文件读取函数，因此本条按“外部输入未校验进入资源引用/路径拼接”记录，路径穿越的最终文件读写汇点在给定片段内证据不足。

**source / sink**

- source：query `include`（020.php:13）
- sink：020.php:13 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `020.php:13` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /020（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/020?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN8f1d6.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN8f1d6.txt`
- POC 目录：`poc/GEN-8f1d6361cb1e`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若下游存在文件包含或文件读取逻辑，可导致任意本地文件读取/包含（取决于部署环境）；在当前可见片段中，至少可将攻击者控制的 URL/路径注入 `<script src>`，造成外部脚本加载与前端逻辑劫持。具体 RCE/文件读写影响证据不足。

**CVE / CWE 论证**

CWE-22（路径穿越）要求外部输入未经规范化即用于路径构造。此处外部可达（POST 参数 include，无需认证），但利用链在给定片段内未闭合到文件系统 API，故仅能确认“未校验输入进入路径/资源引用”，不能断言任意文件读写。

**修复建议**

对 include 参数使用严格白名单（枚举允许的页面/资源名），拒绝包含 `../`、绝对路径、协议前缀（`http:`、`//`）的值；使用 `realpath()` 规范化后校验结果仍位于允许目录内；输出到 HTML 属性时进行 HTML 实体编码与引号转义。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:13；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST include → `isset($_POST['include'])`（020.php:13）→ 字符串拼接进 `$page['body']`（020.php:14-15）→ 输出到响应。片段内无文件系统汇点，路径穿越的文件读写环节未闭合。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:13 的路径穿越（CWE-22）POC。外部输入来自 query 参数 include，未经净化即进入文件路径拼接/包含汇点，可通过 ../ 序列逃逸预期目录，读取或写入任意文件。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 020.php:13，外部输入来自 query 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：保留原有请求结构，仅补充说明与预期结果。脚本为文本工件，不执行、不联网；执行前需人工替换 TARGET 并获得授权。

### F-2: 020.php 依赖外部脚本且服务端未对 include 参数做校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:14-15`
- **来源**：`rule`

**描述**

020.php:14-15 将外部输入拼入 `<script src>`，页面行为依赖客户端加载的外部脚本；服务端在 020.php:13 仅用 `isset()` 判断参数存在，未做任何服务端校验。若业务逻辑依赖该脚本执行校验或渲染，攻击者可通过替换脚本源或直接构造请求绕过客户端校验。

**source / sink**

- source：client `external JavaScript`（020.php）
- sink：020.php:15 	<script src='" . $_POST['include'] . "'></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:15` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /020（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 external JavaScript；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/020?external JavaScript=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-cc52c467496c`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

客户端校验可被绕过，导致服务端接受未经校验的输入；结合脚本源可控，可执行任意前端逻辑。具体业务影响因缺少下游处理代码而证据不足。

**CVE / CWE 论证**

CWE-602（依赖客户端安全控制）。外部可达（POST，无需认证）；但片段内未展示被绕过的具体业务校验逻辑，利用链仅部分闭合。

**修复建议**

所有安全校验必须在服务端执行；对 include 参数使用服务端白名单；不要将安全决策委托给外部脚本；对输出做属性转义。

**验证说明**

静态证据：入口 ANY /020；source=client/external JavaScript；sink=020.php:15；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：POST include → 020.php:15 拼入 script src → 客户端加载外部脚本 → 服务端仅 isset 校验 → 客户端校验可被绕过。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的客户端校验绕过（CWE-602）POC。该候选指出安全校验仅在前端/客户端完成，服务端未复验，攻击者可直接构造请求绕过。注意：原草稿中的参数名 'external JavaScript' 含空格，不符合常规参数命名，实际参数名应以源码 getParameter 的字符串字面量为准，此处保留原结构但标注需核对。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-602（客户端实施服务端安全）。问题位于可交付代码 020.php:15，属配置/逻辑型候选。证据等级：llm_inferred；参数名 'external JavaScript' 需与源码字面量核对后再定稿。
POC 备注：保留原有请求结构，仅补充说明与预期结果；参数名含空格已按 URL 编码处理，实际以源码为准。脚本为文本工件，不执行、不联网；执行前需人工替换 TARGET 并获得授权。

### F-3: 020.php 中 POST 参数 include 未编码直接拼入 <script src> 导致反射型 XSS

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.82`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

脚本在第 13 行读取 $_POST['include']，在第 14-16 行将其原样拼接进 <script src='...'></script> 并输出到响应体，未做 HTML 实体编码、URL 校验或白名单过滤。攻击者可通过构造 include 值闭合单引号并注入任意 HTML/JS，实现反射型 XSS。虽然第 3-5 行设置了 CSP（script-src 白名单），但 CSP 仅限制脚本来源，不阻止注入内联 HTML 结构（如 <img onerror>、<svg onload> 等事件处理器在部分浏览器/配置下仍可执行），且白名单中包含 pastebin.com、unpkg.com、cdn.jsdelivr.net 等可托管任意 JS 的公共 CDN，攻击者可借助这些域加载恶意脚本，CSP 无法有效防护。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接进 <script src='...'> 并输出到 HTML 响应体（第 14-16 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 检查 POST 参数 include 是否存在 | 外部可控字符串 |  |
| 2 | `020.php:14-16` | 将 $_POST['include'] 原样拼接进 <script src='...'></script> 模板字符串 | 未编码、未校验的原始字符串 |  |
| 3 | `020.php:18` | 拼接后的 $page['body'] 被输出到响应，浏览器解析执行 | 注入的 HTML/JS 进入 DOM |  |

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话、发起 CSRF 或钓鱼。CSP 因白名单含公共 CDN 而可被绕过。

**CVE / CWE 论证**

CWE-79：外部可控 POST 参数未经编码直接进入 HTML 输出，链闭合，无需认证，外部可达。

**修复建议**

对 $_POST['include'] 做 HTML 实体编码（htmlspecialchars），并校验 URL 协议与域名白名单；收紧 CSP，移除可托管任意内容的公共 CDN 域。

**验证说明**

需确认实际部署中 CSP 是否生效及浏览器对注入事件处理器的执行情况；CSP 白名单绕过依赖外部 CDN 可托管任意 JS。
模型 POC 要点：提交 include 参数闭合单引号并注入事件处理器或借助 CSP 白名单域加载恶意脚本
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型跨站脚本（CWE-79）POC。外部输入来自 POST body 参数 include，未经 HTML 编码即回显到响应页面，脚本可在受害者浏览器执行。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79。漏洞位于可交付代码 020.php:17，外部输入来自 body 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。证据等级：llm_inferred。
POC 备注：保留原有请求结构，仅补充说明与预期结果。脚本为文本工件，不执行、不联网；执行前需人工替换 TARGET 并获得授权。

### F-4: 020.php CSP script-src 白名单过宽（CWE-693 防护机制失效）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php:3 定义 `Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;`。该策略允许从多个第三方托管/CDN 与 pastebin 类站点加载脚本，其中 pastebin.com、hastebin.com 允许匿名发布任意内容，unpkg.com、cdn.jsdelivr.net 允许托管任意公开包，均可被攻击者用于托管恶意脚本。结合 020.php:15 的 `<script src>` 注入点，CSP 无法阻止攻击者从这些白名单域加载脚本。

**source / sink**

- source：query `include`（020.php）
- sink：020.php:3 $headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"; // allows js from various trusted locations

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:3` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /020（ANY）的 CSP 配置缺陷 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/020?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-582e93de1b73`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

CSP 作为纵深防御失效：即使存在脚本注入点，攻击者仍可从白名单中的匿名托管域加载任意 JS，导致 XSS 防护被绕过、会话劫持与数据窃取。

**CVE / CWE 论证**

CWE-693（防护机制失效）。属配置型弱点，无需污点链；证据为 020.php:3 的策略原文。外部可达性取决于响应是否实际下发该头，片段内未显示 header() 调用，故为推断。

**修复建议**

移除 pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net 等可匿名托管任意内容的源；仅保留确需的固定版本 CDN 并配合 SRI；增加 `object-src 'none'`、`base-uri 'none'`、`frame-ancestors 'none'`；优先使用 nonce/hash 而非域名白名单。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：020.php:3 定义过宽 script-src → 020.php:15 存在可控 script src → 浏览器按 CSP 允许从白名单匿名托管域加载攻击者脚本。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:3 的 CSP 配置缺陷（CWE-693）POC。该候选属于配置型问题，重点在于响应头中 Content-Security-Policy 缺失或过于宽松，而非参数污点。请求中的 include=SUNSET_PROBE 仅用于触发页面响应以便观察安全响应头。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693（防护机制失效）。问题位于可交付代码 020.php:3 附近的响应头配置，属配置型候选，无 HTTP 污点不代表误报。证据等级：llm_inferred（需以实际响应头为准）。
POC 备注：保留原有请求结构，仅补充说明与预期结果。脚本为文本工件，不执行、不联网；执行前需人工替换 TARGET 并获得授权。

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
| safety_guard | 安全防护 | 2.42 | 是 |
| surface_mapper | 攻击面测绘 | 7.56 | 是 |
| deep_finder | LLM 深挖 | 6.48 | 是 |
| candidate_screener | 候选筛选 | 6.86 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.15 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.33 | 是 |
| coordinator | 管线协调 | 6.39 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
