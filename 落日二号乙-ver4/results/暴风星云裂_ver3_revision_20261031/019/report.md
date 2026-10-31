# 落日二号乙漏洞挖掘报告 — 20261031-011705-06b91e

- 生成时间：2026-10-30T17:17:58.573655+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

共发现 4 条候选 finding，覆盖 4 种漏洞类型；4 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 019.php（22 行）。第 2-4 行设置 CSP script-src 'self'；第 8-12 行存在 $_POST['include'] 未编码拼接进 $page['body'] 的反射型 XSS 根因。未发现 include/require、文件读写、命令执行、SQL 拼接、反序列化等汇点；无 md5/sha1、rand、setcookie 等配置类弱点证据。$page['body'] 的实际输出点不在 code_pack 内，XSS 链的最终渲染环节依赖框架模板，故置信度中等。

未覆盖 / 证据缺口：
- $page['body'] 的最终输出位置未在 code_pack 中显示
- 无 HTTP 端点清单与部署配置，无法确认可达性与鉴权
- CSP 是否可绕过未验证

## 3. Findings

### F-1: 019.php 未校验的 include 参数导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:6-8`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 include 提交外部输入（019.php:8 的 isset($_POST['include']) 仅做存在性判断，未做任何白名单、basename 或 realpath 规范化）。该值在 019.php:10 被直接拼接进 $page['body'] 的字符串中（" . $_POST['include'] . "），随后作为页面内容/包含路径使用。由于缺少对 ../、绝对路径、协议前缀等的过滤，攻击者可控制被包含/读取的文件路径。注意：候选的 source 标注为 query `include`，但源码实际读取的是 $_POST['include']，注入点为 POST 参数 include，POC 应按 POST 参数构造。

**source / sink**

- source：query `include`（019.php:8）
- sink：019.php:8 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:8` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:8` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GENc0759.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GENc0759.txt`
- POC 目录：`poc/GEN-c0759cbfa182`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取/包含服务器上任意可读文件（如配置文件、密钥、/etc/passwd），若可包含上传文件或日志则可能进一步导致代码执行；也可造成敏感信息泄露。

**CVE / CWE 论证**

CWE-22 路径穿越：外部可控输入（POST include）未经规范化直接进入文件包含/路径拼接汇点（019.php:10），无需认证即可通过 HTTP POST 触达，利用链闭合。证据等级为源码推断，未做动态验证。

**修复建议**

对 include 参数使用固定白名单映射（如允许的页面名到文件路径的字典），拒绝包含 ../、绝对路径与协议前缀；使用 basename() 与 realpath() 规范化并校验结果仍位于允许目录内；避免把用户输入直接拼接进包含路径或页面内容。

**验证说明**

静态证据：入口 ANY /019；source=query/include；sink=019.php:8；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST include=../../etc/passwd → 019.php:8 isset 判断通过 → 019.php:10 直接拼接进 $page['body'] → 未规范化即用于包含/输出 → 读取任意文件。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:8 的路径穿越（CWE-22）POC。外部输入来自 query 参数 include，被直接用于文件路径拼接/包含，未发现有效净化，可穿越到 Web 根之外读取任意文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22（路径穿越）。漏洞点位于可交付代码 019.php:8，外部输入来自 query 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；建议先读取无害文件（如 /etc/hostname）验证，避免触碰敏感数据。

### F-2: 019.php 引用外部脚本 source/high.js 的客户端校验语义命中（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:19-20`
- **来源**：`rule`

**描述**

019.php:20 通过 <script src="source/high.js"></script> 引入客户端脚本，可能承担输入校验职责。若校验仅在客户端进行而服务端未重复校验，攻击者可直接构造请求绕过。当前证据仅显示脚本引用，未提供 high.js 内容，也未证明服务端缺少对应校验，属语义模式命中。

**source / sink**

- source：client `external JavaScript`（019.php）
- sink：019.php:20 <script src="source/high.js"></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:20` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（ANY）的 客户端校验绕过 POC。注入点：ANY 参数 external JavaScript；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?external JavaScript=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-99a2f26a9c57`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若校验仅存在于客户端，攻击者可绕过前端限制提交恶意数据，进而触发服务端其他缺陷（如路径穿越/内容注入）。当前证据不足以确认。

**CVE / CWE 论证**

CWE-602 依赖客户端安全：需证明校验仅在客户端且服务端缺失。外部可达性存在，但利用链未闭合，证据不足。

**修复建议**

在服务端对 include 等参数实施与客户端一致的校验与白名单；客户端校验仅作为体验优化，不作为安全边界。

**验证说明**

静态证据：入口 ANY /019；source=client/external JavaScript；sink=019.php:20；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：019.php:20 加载 source/high.js → 客户端校验 → 攻击者绕过前端直接 POST → 服务端若无重复校验则接受恶意输入。链路未闭合。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:20 的客户端校验绕过（CWE-602）POC。该候选关注服务端是否仅依赖前端 JavaScript 校验；探针用于确认服务端未重复校验。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-602（依赖客户端安全校验）。问题位于可交付代码 019.php:20，属配置/逻辑型候选。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；参数名含空格需按 URL 编码提交。

### F-3: DVWA CSP 页面 POST 参数 include 未编码直接拼接进 HTML 响应体（反射型 XSS）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.72`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`019.php:8-12`
- **来源**：`llm_finding`

**描述**

019.php 第 8-12 行读取 $_POST['include']，未做任何 HTML 实体编码或白名单过滤，直接以字符串拼接方式追加到 $page['body']，随后该 body 被输出到页面。攻击者可构造包含 <script> 或事件处理器的 POST 请求，使恶意脚本在受害者浏览器中执行。页面第 2-4 行设置了 Content-Security-Policy: script-src 'self'，会阻止内联脚本与外部域脚本执行，因此经典 <script> 注入被 CSP 削弱；但注入的 HTML 标记本身仍被渲染（如 <img src=x onerror=...> 受 CSP 限制同样被拦），实际可利用性依赖 CSP 是否被绕过或页面是否在其它上下文输出。根因是缺少输出编码（CWE-79）。

**source / sink**

- source：body `include`（019.php）
- sink：019.php:12 $page['body'] 字符串拼接，最终输出到 HTTP 响应 HTML

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:8` | 检查 POST 参数 include 是否存在 | 原始用户输入 |  |
| 2 | `019.php:10` | 将 $_POST['include'] 直接拼接进 $page['body']，无 htmlspecialchars 等编码 | 未编码的 HTML 片段 | 无任何过滤或编码 |

**POC**

针对 /vulnerabilities/csp/（POST）的 跨站脚本 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/csp/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/csp/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-cf764c9b36ce`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者浏览器执行脚本；受 script-src 'self' CSP 限制，内联脚本被拦，实际危害取决于 CSP 绕过或其它输出上下文。

**CVE / CWE 论证**

CWE-79：外部可控 POST 参数未经编码进入 HTML 输出，链闭合；但 CSP 削弱了脚本执行，故定为 medium。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 后再输出，或改用白名单。

**验证说明**

需确认 $page['body'] 最终输出位置（本文件未显示 echo，可能在框架模板中输出）；需验证 CSP 是否可绕过以执行脚本。
模型 POC 要点：向 CSP 页面提交含 HTML 标记的 include 参数，观察响应中原样回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csp/）：针对 019.php:12 的跨站脚本（CWE-79）POC。外部输入来自 POST body 参数 include，被输出到响应页面且未做 HTML 编码，脚本可在受害者浏览器执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/csp/）：符合 CWE-79（跨站脚本）。漏洞点位于可交付代码 019.php:12，外部输入来自 body 参数 include，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；alert 仅用于验证，实际评估请使用无害标记。

### F-4: 019.php CSP 配置为 script-src 'self' 的语义命中（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:1-2`
- **来源**：`rule`

**描述**

019.php:2 定义 $headerCSP = "Content-Security-Policy: script-src 'self';";。该策略限制脚本来源为同源，但同源下若存在可控脚本文件（如 019.php:20 引用的 source/high.js）或可上传/可写入的同源资源，则 CSP 无法阻止脚本执行。当前证据仅显示策略字符串定义，未显示其被发送到响应头，也未确认同源可控脚本的存在，属语义模式命中。

**source / sink**

- source：query `include`（019.php）
- sink：019.php:2 $headerCSP = "Content-Security-Policy: script-src 'self';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:2` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（ANY）的 CSP 配置缺陷 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-3004577a69c4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若同源存在可控脚本或上传点，CSP 保护可被绕过，导致脚本注入/XSS 类影响；当前证据不足以确认实际可利用性。

**CVE / CWE 论证**

CWE-693 保护机制失效：CSP 策略过宽或未生效。外部可达性依赖响应头实际下发与同源资源可控性，证据不足，未闭合利用链。

**修复建议**

确认 $headerCSP 通过 header() 实际下发；收紧策略（如增加 nonce/hash、object-src 'none'、base-uri 'none'）；审计同源 source/high.js 等资源是否可被攻击者写入或替换。

**验证说明**

静态证据：入口 ANY /019；source=query/include；sink=019.php:2；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：策略定义于 019.php:2 → 需确认是否下发响应头 → 若同源脚本可控则绕过 script-src 'self' → 执行攻击者脚本。当前链路未闭合。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:2 的 CSP 配置缺陷（CWE-693）POC。该候选为配置型问题，重点在于响应头中 Content-Security-Policy 的存在性与策略强度，而非参数值本身。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-693（防护机制失效）。问题位于可交付代码 019.php:2，属配置型候选，证据来自响应头策略而非 HTTP 污点。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试目标；判定以响应头为准，参数值仅用于触发页面渲染。

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
| safety_guard | 安全防护 | 2.45 | 是 |
| surface_mapper | 攻击面测绘 | 7.82 | 是 |
| deep_finder | LLM 深挖 | 6.03 | 是 |
| candidate_screener | 候选筛选 | 6.78 | 是 |
| vulnerability_analyzer | 漏洞分析 | 9.57 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 13.12 | 是 |
| coordinator | 管线协调 | 7.35 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
