# 落日二号乙漏洞挖掘报告 — 20261031-002000-8c4a7c

- 生成时间：2026-10-30T16:20:48.604909+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\020.zip`
- 输入模式：`zip`
- SHA256：`f7bc24fccdcc53d2a999c3468bedf97d91c239734baf4f227ae7ef495dbe0b26`
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

本次汇总基于已去重的 2 条 findings，均集中在单文件 PHP 脚本 020.php：一条为 LLM 发现的反射型 XSS（high，020.php 第 17 行，$_POST['include'] 未编码直接拼入 <script src> 属性，CSP 白名单可绕过），一条为规则命中的 path_traversal 候选（high，020.php 第 15 行，同一 $_POST['include'] 拼入 <script src> 属性，属输出注入/路径穿越候选）。两条 finding 均带 POC，但均为静态文本 POC，未做动态验证；其中 path_traversal 与 XSS 指向同一污点源与同一输出点，实际更可能是同一处输出注入的两种归类，需人工判定是否重复计数。最高危为 020.php 的 $_POST['include'] 未编码输出注入（XSS 可执行脚本，且可绕过 CSP 白名单）。整体攻击面极小（1 文件、27 行、无框架、无端点清单），POC 齐全但仅覆盖该单点，其余攻击面（文件包含、命令执行、反序列化等）因未提供源码正文而无法确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1199 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 020.php（27 行）。已通读全文：第 3-5 行设置 CSP 头；第 13-17 行存在唯一外部输入点 $_POST['include']，未编码直接拼入 <script src='...'>，构成反射型 XSS，且 CSP 白名单含 unpkg.com/cdn.jsdelivr.net 等可托管任意 JS 的域、未限制内联事件属性，防护可绕过，链闭合。未发现 SQL 拼接、命令执行、文件包含、反序列化等其它汇点。缺口：$page['body'] 的最终渲染模板不在 code_pack 中，无法确认输出上下文；无部署配置确认脚本对外暴露；无依赖清单。surface_notes 中关于第 2 行输入点的推断与实际不符（第 2 行为空行，真实输入在第 13 行），已按实际代码修正。

未覆盖 / 证据缺口：
- $page['body'] 渲染模板未提供，输出上下文需人工确认
- 无 Web 服务器/php.ini 配置，无法确认对外暴露与危险函数禁用情况
- 无依赖清单与版本历史

## 3. Findings

### F-1: 020.php POST 参数 include 未编码直接拼入 <script src> 导致反射型 XSS（CSP 白名单可绕过）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`020.php:13-17`
- **来源**：`llm_finding`

**描述**

020.php 第 13-17 行读取 $_POST['include']，未做任何 HTML 实体编码或 URL 白名单校验，直接以单引号包裹拼入 <script src='...'></script> 并输出到页面。攻击者可注入单引号闭合 src 属性，插入任意 HTML/事件处理器（如 onerror、onload）或额外 <script> 标签，实现反射型 XSS。页面虽在第 3-5 行设置了 CSP（script-src 白名单），但白名单包含 unpkg.com、cdn.jsdelivr.net、pastebin.com 等可托管任意 JS 的公共 CDN，且注入点本身允许内联事件属性（CSP 未设置 script-src-attr 'none'，也未使用 nonce/hash），因此 CSP 无法阻止利用。

**source / sink**

- source：body `include`（020.php）
- sink：020.php:17 $page['body'] .= "<script src='" . $_POST['include'] . "'></script>" 后输出到 HTML 响应

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `020.php:13` | isset($_POST['include']) 判断外部 POST 参数是否存在，进入注入分支 | 攻击者完全可控的字符串 |  |
| 2 | `020.php:14-16` | 将 $_POST['include'] 以单引号包裹拼入 <script src='...'> 标签，无 htmlspecialchars/实体编码/白名单校验 | 原始未编码字符串，单引号可闭合属性 | 无任何输出编码或 URL 校验；CSP 白名单含 unpkg.com/cdn.jsdelivr.net 等可托管任意 JS 的域，且未限制内联事件属性，故 CSP 不构成有效防护 |
| 3 | `020.php:18-27` | $page['body'] 最终渲染进响应页面，注入的标签/事件处理器被浏览器解析执行 | 注入的 HTML/JS 在受害者浏览器上下文执行 |  |

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

在受害者浏览器上下文执行任意 JavaScript，可窃取会话 Cookie/令牌、伪造请求执行敏感操作、篡改页面内容；CSP 因白名单含公共 CDN 且未限制内联属性而无法缓解。

**CVE / CWE 论证**

CWE-79 跨站脚本。外部可达（HTTP POST 参数 include），无需认证，source→sink 链在 020.php:13-17 完整闭合，无输出编码，CSP 可绕过。

**修复建议**

对 $_POST['include'] 使用 htmlspecialchars($v, ENT_QUOTES, 'UTF-8') 编码后再输出；更佳做法是解析 URL 并校验 scheme/host 是否在严格白名单内，仅允许 https 且主机精确匹配；CSP 增加 script-src-attr 'none' 或使用 nonce/hash，移除可托管任意 JS 的公共 CDN 域。

**验证说明**

需确认 020.php 在目标环境实际对外暴露且 $page['body'] 被渲染输出（本文件仅片段，渲染模板未在 code_pack 中）；需动态确认浏览器对注入标签的解析与 CSP 实际生效情况。
模型 POC 要点：向 020.php 提交 include 参数，用单引号闭合 src 属性并注入 onerror 事件处理器执行 JS；或注入指向 CSP 白名单域（如 unpkg.com）的脚本 URL。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /020.php）：针对 020.php:17 的反射型跨站脚本（CWE-79）POC。外部输入来自 POST body 参数 include，在 020.php:17 处未经 HTML 编码直接输出到响应，导致脚本在受害者浏览器执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020.php）：符合 CWE-79（跨站脚本）。漏洞点位于 020.php:17，source 为 POST body 参数 include，sink 为 HTML 输出点，静态链路闭合且未见有效编码，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动运行；验证时使用无害 alert 载荷，避免影响真实用户。

### F-2: 020.php 中 $_POST['include'] 直接拼入 <script src> 属性（输出注入/路径穿越候选）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.45`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`020.php:13-15`
- **来源**：`rule`

**描述**

020.php 第 13-15 行：`if (isset ($_POST['include'])) { $page['body'] .= "<script src='" . $_POST['include'] . "'></script>"; }`。攻击者通过 POST 参数 `include` 提交的值被原样拼接进 `<script src='...'>` 的单引号属性中，未做 HTML 属性编码、URL 校验或路径规范化。由于属性使用单引号包裹，提交含单引号的值可闭合属性并注入任意 HTML/JS（存储或反射取决于 `$page['body']` 的输出时机，片段未展示输出点）。同时该值作为脚本 URL，可指向攻击者控制的域或 `../` 相对路径，构成客户端路径/资源加载操纵。

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

可导致反射型/存储型 XSS（在受害者浏览器执行任意脚本、窃取会话），或通过 `src` 指向外部恶意脚本实现脚本注入；若该值同时被服务端用于文件定位，则可能演变为路径穿越。

**CVE / CWE 论证**

CWE-79（跨站脚本）/ CWE-22（路径穿越）。外部可达性：POST 参数 `include` 无需认证；利用链在片段内闭合（输入→字符串拼接→HTML 属性输出），但最终响应输出点未在片段中给出，故为推断级。

**修复建议**

对输出到 HTML 属性的值使用 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`；对 `src` 使用 URL 白名单或固定前缀校验；避免将用户输入直接拼入标签属性，改用模板引擎自动转义。

**验证说明**

静态证据：入口 ANY /020；source=query/include；sink=020.php:15；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST `include='><script>alert(1)</script>` → 020.php:13 存在性判断 → 020.php:15 直接拼接进 `<script src='...'>` 单引号属性 → 属性被闭合，注入脚本在浏览器执行。
PocWriter 建议（未采纳，缺少端点 /020）：针对 020.php:15 的路径穿越（CWE-22）POC。外部输入来自 query 参数 include，在 020.php:15 处未经净化进入文件路径汇点，可通过 ../ 序列逃逸目录边界。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /020）：符合 CWE-22（路径穿越）。漏洞点位于 020.php:15，source 为 query 参数 include，sink 为文件路径使用点，静态链路闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。脚本中的 curl 命令需人工替换 TARGET 后在授权环境手动运行；禁止对生产环境执行写操作类验证。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.69 | 是 |
| surface_mapper | 攻击面测绘 | 7.0 | 是 |
| deep_finder | LLM 深挖 | 9.48 | 是 |
| candidate_screener | 候选筛选 | 4.93 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.24 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.04 | 是 |
| coordinator | 管线协调 | 6.39 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
