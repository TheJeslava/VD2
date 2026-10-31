# 落日二号乙漏洞挖掘报告 — 20261031-010018-4e551a

- 生成时间：2026-10-30T17:01:15.374409+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在唯一源文件 020.php（27 行单文件 PHP 脚本，无框架、无路由配置）。最高危为 GEN-dda61ef2bad8（path_traversal，high）：$_POST['include'] 被直接拼入 <script src> 属性，导致脚本源可控与属性注入（CWE-79/CWE-116）；同一根因另有 LLM-370901c0cb4c（xss，medium，反射注入 script src 并绕过 CSP 白名单）与 SEM-582e93de1b73（csp，medium，script-src 白名单过宽，CWE-693）。三条 finding 均带 POC（with_poc=3），但均为静态/HTTP 文本 POC，未做动态验证；其中 csp 一条本质是配置型证据，POC 为静态证据，不能宣称可动态复现。需注意 GEN-dda61ef2bad8 的类型标注为 path_traversal，但其描述与证据指向的是 <script src> 属性注入/脚本源可控，类型与证据存在不一致，建议人工按 xss/CWE-79 复核归类。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 020.php（27 行，已全量覆盖）。发现 1 条闭合链：POST 参数 include 未编码拼接进 <script src> 造成反射型 XSS，且第 3-5 行 CSP 白名单包含可托管任意 JS 的域，CSP 无法阻止利用。未发现命令执行、文件包含、SQL 拼接、反序列化等汇点；文件中无 md5/sha1、openssl、rand、setcookie 等配置类风险调用。未覆盖范围：无 Web 服务器配置、无端点清单、无鉴权信息，实际可达性与认证前置未知；policy 中 min_severity=low、min_confidence=0.6，本 finding 满足阈值。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与鉴权配置，入口可达性未确认
- 无 Web 服务器/php.ini 配置，无法判断部署暴露面
- CSP 白名单域是否可匿名托管脚本需运行时验证

## 3. Findings

### F-1: 020.php 中 $_POST['include'] 直接拼入 <script src> 的属性注入 / 脚本源可控（CWE-79/CWE-116）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.55`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:13-15`
- **来源**：`rule`

**描述**

020.php:13-15 显示：`if (isset ($_POST['include'])) {` 后执行 `$page['body'] .= "\n\t<script src='" . $_POST['include'] . "'></script>"`。外部 POST 参数 `include` 未经任何编码或校验，被直接拼接进 HTML 的 `<script src='...'>` 单引号属性中。攻击者可在参数值中闭合单引号并注入任意属性或标签（例如 `x' onerror='...` 或 `'></script><script>...`），从而在受害者浏览器中执行脚本。注意：该汇点是 HTML/JS 输出上下文，性质为 XSS/HTML 注入，而非路径穿越；候选将其标为 path_traversal 属于类型误判。

**source / sink**

- source：query `include`（020.php:15）
- sink：020.php:15 <script src='" . $_POST['include'] . "'></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:15` | 从 query `include` 读取外部输入 | 污点进入 src |  |
| 2 | `020.php:15` | 危险汇点：<script src='" . $_POST['include'] . "'></script> | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /020（ANY）的 路径穿越 / 任意文件读写 POC。注入点：ANY 参数 include；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/020?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GENdda61.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GENdda61.txt`
- POC 目录：`poc/GEN-dda61ef2bad8`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS：攻击者构造带恶意 `include` 参数的 POST 请求（或借助自动提交表单）诱导受害者访问，可在站点源下执行任意 JavaScript，窃取会话 Cookie、发起 CSRF 操作、篡改页面内容。由于该值同时被用作脚本 src，还可让页面从攻击者指定域加载脚本（受 CSP 约束，见 SEM-582e93de1b73）。

**CVE / CWE 论证**

CWE-79（跨站脚本）/CWE-116（输出编码不当）。外部可达性：`$_POST['include']` 为匿名可提交参数，无需认证；利用链闭合：输入 → 字符串拼接 → 写入 `$page['body']` → 输出到响应 HTML 的 script 标签属性，中间无编码或白名单。

**修复建议**

输出到 HTML 属性前使用 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` 进行上下文编码；对脚本来源使用固定白名单（仅允许已知 CDN 主机名）而非任意用户输入；优先改为服务端映射的固定脚本路径，避免把用户输入放进 src。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:15；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 POST `include=x' onerror='alert(1)` → 020.php:13 判定通过 → 020.php:15 拼接为 `<script src='x' onerror='alert(1)'></script>` → 响应返回浏览器 → 属性被闭合，事件处理器执行。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的路径穿越（CWE-22）POC。外部输入来自 query 参数 include，在 020.php:15 处未经有效净化进入文件路径汇点，可用 ../ 序列访问预期目录之外的文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22（路径穿越）。漏洞位于可交付代码 020.php:15，外部输入来自 query 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。手工验证时请将 TARGET 替换为授权目标，并先创建/确认探针文件存在以区分读写行为。

### F-2: 020.php 通过 POST 参数 include 反射注入 script src，CSP 白名单可被绕过导致任意脚本执行

- **类型**：`xss` / CWE-79
- **严重度**：`medium`
- **置信度**：`0.87`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行在收到 POST 参数 include 时，未做任何 HTML 属性编码或 URL 白名单校验，直接把 $_POST['include'] 拼进 <script src='...'> 的单引号属性中。攻击者可闭合单引号并注入任意属性/标签，或直接指向 CSP 白名单内可托管任意 JS 的域（pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net、digi.ninja 等），从而在受害者浏览器执行任意脚本。第 3-5 行设置的 CSP 明确把上述域列入 script-src，等于为攻击者提供了合法的脚本托管源，CSP 无法阻止利用。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 字符串拼接进 <script src='...'> 并输出到 HTML 响应（反射型 XSS）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | 检测到 POST 参数 include 存在 | 原始用户输入 $_POST['include'] |  |
| 2 | `020.php:15` | 未编码直接拼接到 script 标签 src 属性的单引号内 | 字符串拼接，无 HTML 实体编码、无 URL 校验 | 无任何过滤；CSP 白名单域本身可托管任意 JS，CSP 不构成防护 |
| 3 | `020.php:14-16` | 拼接结果写入 $page['body'] 并随页面输出，浏览器解析执行 | 进入 HTML 响应，被浏览器当作脚本加载 |  |

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

在受害者浏览器上下文执行任意 JavaScript，可窃取会话、伪造请求、篡改页面内容；CSP 因白名单域可托管任意脚本而失效。

**CVE / CWE 论证**

CWE-79 反射型 XSS。外部无需认证即可通过 POST 触发，输入直达 HTML 输出汇点，链闭合；CSP 白名单域（jsdelivr/unpkg/pastebin 等）可被攻击者用于托管脚本，属典型 CSP 绕过。

**修复建议**

对 include 做严格 URL 白名单校验（仅允许受控域），输出时使用 htmlspecialchars 对属性值编码，并收紧 CSP 至不可托管任意内容的源。

**验证说明**

需确认 020.php 实际可访问路径与是否需认证；CSP 白名单域是否允许匿名托管脚本需运行时确认。
模型 POC 要点：利用 CSP 白名单域托管恶意 JS，或闭合单引号注入事件处理器
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型跨站脚本（CWE-79）POC。外部输入来自 POST body 参数 include，在 020.php:17 处未经 HTML 编码即输出到响应，导致脚本在受害者浏览器执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 020.php:17，外部输入来自 body 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。手工验证时请将 TARGET 替换为授权目标；若响应为 JSON 或非 HTML 上下文，需相应调整载荷上下文。

### F-3: 020.php 中过于宽松的 CSP script-src 白名单（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:2-3`
- **来源**：`rule`

**描述**

020.php:3 定义 `$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"`。该策略把多个第三方内容托管域（pastebin.com、hastebin.com、unpkg.com、cdn.jsdelivr.net、example.com 等）加入 script-src 白名单，其中 pastebin/hastebin/unpkg/jsdelivr 允许用户上传或托管任意 JS 内容，等于为攻击者提供了合法的脚本加载源。结合 020.php:15 中 `$_POST['include']` 直接进入 `<script src>`，攻击者只需把 src 指向这些白名单域上的恶意脚本即可绕过 CSP。片段未显示该 header 是否真正通过 `header()` 输出，也未显示 nonce/hash 或 `'strict-dynamic'` 的使用。

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

CSP 防护形同虚设：在存在 020.php:15 的属性注入/脚本源可控问题时，攻击者可借助白名单内的用户内容托管域加载任意脚本，实现持久或反射型脚本执行，削弱对 XSS 的纵深防御。

**CVE / CWE 论证**

CWE-693（防护机制失效）。外部可达性：CSP 随响应头下发，任何访问者均受影响；无需认证。利用链闭合性：策略文本本身已确认包含可托管任意 JS 的第三方域，与 020.php:15 的可控 src 形成组合；但 header 实际下发位置在片段中未给出，属证据缺口。

**修复建议**

收紧 script-src：移除 pastebin/hastebin/unpkg/jsdelivr 等用户内容托管域，仅保留确需的固定版本资源域；引入 nonce 或 hash 并配合 `'strict-dynamic'`；对 020.php:15 的 src 使用服务端白名单映射，禁止用户直接控制脚本 URL；同时补充 `object-src 'none'`、`base-uri 'none'`。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:3；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者利用 020.php:15 将 `<script src>` 指向 `https://pastebin.com/...` 或 `https://cdn.jsdelivr.net/...` 上的恶意脚本 → 浏览器按 020.php:3 的 CSP 判定该源在白名单内 → 脚本被加载执行，CSP 未起到阻断作用。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:3 的 CSP/安全响应头配置缺陷（CWE-693）POC。该处未设置有效的 Content-Security-Policy 等防护响应头，导致浏览器端缺少纵深防御。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-693（防护机制失效）。问题位于可交付代码 020.php:3，属配置型缺陷，无 HTTP 污点但可通过响应头证据确认。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。该候选为配置型，验证以响应头为准，不依赖参数值；手工验证时请将 TARGET 替换为授权目标。

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
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.83 | 是 |
| surface_mapper | 攻击面测绘 | 8.16 | 是 |
| deep_finder | LLM 深挖 | 7.62 | 是 |
| candidate_screener | 候选筛选 | 6.38 | 是 |
| vulnerability_analyzer | 漏洞分析 | 12.6 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.55 | 是 |
| coordinator | 管线协调 | 6.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
