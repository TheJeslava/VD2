# 落日二号乙漏洞挖掘报告 — 20261031-172746-06f51b

- 生成时间：2026-10-31T09:28:37.890670+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 019.php（22 行），无框架、无路由清单、无 HTTP 端点测绘结果。最高危为 GEN-c0759cbfa182：019.php 第 8 行附近对 POST 参数未经白名单/路径规范化即进入 include，构成路径穿越/任意文件包含（CWE-22，high），已附 POC；其次 SEM-99a2f26a9c57：019.php 第 20 行附近仅依赖 source/high.js 做客户端校验，服务端未见对应校验（CWE-602，high），已附 POC；SEM-3004577a69c4：019.php 第 2 行 CSP 仅 script-src 'self'，缺 object-src/base-uri 等指令（CWE-693，medium），已附 POC。3 条 findings 均标记 has_poc=true，POC 文本齐全，但均为静态源码推断产物，未做动态验证；其中 path_traversal 与 client_side_validation 具备 HTTP 复现形态，CSP 属配置/响应头类静态证据。需注意 surface_notes 明确说明输入未提供代码正文、sink_hot_files 为空，因此上述行号与数据流结论以 findings 记录为准，仍属 llm_inferred 级别，需人工逐行核对 019.php 全文确认。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 019.php（22 行，DVWA CSP 练习页）。第 2-4 行设置 Content-Security-Policy: script-src 'self'；第 8-12 行读取 $_POST['include'] 并直接拼接到 $page['body']，第 13-21 行继续拼接表单与 <script src="source/high.js">。该拼接点属于服务端 HTML 输出，但本文件内没有 echo/print 等实际输出语句，$page['body'] 的渲染发生在 code_pack 之外的模板/父页面中，无法确认输出上下文与转义情况，因此 XSS 链不闭合，不报告。此外该页面本身已下发 script-src 'self' 的 CSP，即便存在反射型注入，内联脚本与外部脚本执行均受 CSP 限制，实际可利用性依赖 CSP 绕过（如依赖 source/high.js 或 jsonp.php 的 self 源），这些文件不在 code_pack 内。未发现命令执行、SQL、文件操作、反序列化、动态 include/eval 等 sink；surface_notes 中提到的 source_hot_files 019.php:2 实际是 CSP 头字符串赋值，并非请求参数读取，属管线误标。未覆盖范围：DVWA_WEB_PAGE_TO_ROOT 指向的模板渲染文件、source/high.js、source/jsonp.php 均未提供，无法评估 CSP 绕过与最终输出转义。

未覆盖 / 证据缺口：
- $page['body'] 的最终输出点（模板/父页面）不在 code_pack，无法确认是否转义，XSS 链不闭合
- source/high.js 与 source/jsonp.php 未提供，无法评估 CSP 'self' 源绕过
- 无部署配置（PHP 版本、CSP 是否被覆盖），无法判断实际浏览器行为
- surface_notes 将 019.php:2 标为参数读取点，经核对为 CSP 头字符串，属误标

## 3. Findings

### F-1: 019.php 未过滤的 POST 参数 include 导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:6-8`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（019.php:8 的 isset($_POST['include']) 判断），该值在 019.php:10 被直接拼接进 $page['body'] 的字符串中（" . $_POST['include'] . "），全程未见 basename()、realpath()、白名单或路径规范化等任何净化处理。源码片段仅覆盖 6-10 行，未展示后续对该字符串的消费点（如 include/require 或文件读取函数），因此从「外部输入 → 拼接」这一段是确定的，但「拼接结果最终被当作文件路径使用」这一环在给定片段中未直接可见，属于基于变量名 include 与页面模板拼接语义的推断。

**source / sink**

- source：query `include`（019.php:8）
- sink：019.php:8 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:8` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:8` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（POST）的路径穿越/任意文件包含 POC。注入点为 POST 参数 include，源码 019.php:8 将该参数直接用于文件包含/读取，未做路径规范化或白名单校验。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/019' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GENc0759.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GENc0759.txt`
- POC 目录：`poc/GEN-c0759cbfa182`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

若该拼接结果被用于 include/require 或文件读取，攻击者可构造 ../ 序列读取或包含任意本地文件，导致源码/配置泄露，若可包含上传文件则可能升级为 RCE；具体影响取决于片段外的消费点，证据不足部分已注明。

**CVE / CWE 论证**

CWE-22 路径穿越：外部可控的 POST 参数未经规范化直接进入路径拼接，属于典型的未验证路径输入。外部可达性：019.php 为可直接请求的 PHP 页面，POST 参数无需认证即可提交；利用链在「输入→拼接」段闭合，末段消费点需结合片段外代码确认。

**修复建议**

对 include 参数使用严格白名单（如仅允许预定义页面标识），或至少使用 basename() 去除目录部分并用 realpath() 校验结果仍位于允许的基目录内；禁止将原始请求参数直接拼接进文件路径；对包含操作使用固定映射表而非用户可控路径。

**验证说明**

静态证据：入口 POST /019；source=query/include；sink=019.php:8；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 019.php 发送 POST 请求，include 参数携带 ../ 序列 → 019.php:8 通过 isset 检查进入分支 → 019.php:10 将原始值拼接到 $page['body'] 字符串 → 片段外若该字符串被用于文件包含/读取，则实现任意文件访问。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22（路径穿越）。漏洞位于 019.php:8，外部输入来自 POST 参数 include，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试目标；建议先在目标上放置已知内容的 /tmp/sunset_GENc0759.txt 以便确认读取成功。

### F-2: 019.php 依赖 source/high.js 进行客户端校验，服务端未见对应校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:19-20`
- **来源**：`rule`

**描述**

019.php:20 通过 <script src="source/high.js"></script> 引入外部脚本参与校验逻辑。客户端校验可被攻击者直接绕过（禁用 JS、修改请求或直接构造 HTTP 请求）。给定片段仅显示脚本引用，未展示服务端是否存在等价校验，也未展示 high.js 的具体校验内容，因此「服务端缺失校验」为推断而非确证。

**source / sink**

- source：client `external JavaScript`（019.php）
- sink：019.php:20 <script src="source/high.js"></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:20` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的客户端校验绕过检查 POC。候选指向 019.php:20 处依赖外部 JavaScript 的客户端校验，服务端未做等价校验。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/019' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-99a2f26a9c57`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若安全决策仅由客户端脚本完成，攻击者可绕过限制提交任意数据，可能导致越权操作或注入类问题；具体后果取决于被校验的业务逻辑，证据不足。

**CVE / CWE 论证**

CWE-602 客户端实施的安全检查：安全控制位于客户端，可被绕过。外部可达：页面公开可访问；但服务端是否重复校验在片段中不可见，利用链未完全闭合。

**修复建议**

将所有安全校验在服务端重新实现，客户端脚本仅作为用户体验优化；对提交数据在服务端做类型、范围与权限校验；不要以客户端校验结果作为授权依据。

**验证说明**

静态证据：入口 POST /019；source=client/external JavaScript；sink=019.php:20；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者直接构造 HTTP 请求跳过 source/high.js 的校验 → 服务端若无等价检查则接受非法数据 → 进入后续业务逻辑。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-602（依赖客户端安全）。候选位于 019.php:20，需以服务端实际接受非法输入为证据。
POC 备注：POC 仅为文本工件，不执行、不联网。需结合源码确认具体被绕过的校验字段与业务分支。

### F-3: 019.php 的 CSP 仅限制 script-src 'self'，缺少 object-src/base-uri 等指令（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:1-2`
- **来源**：`rule`

**描述**

019.php:2 定义 $headerCSP = "Content-Security-Policy: script-src 'self';",仅设置 script-src 为 'self'，未设置 default-src、object-src 'none'、base-uri 'self'、frame-ancestors 等指令。该策略本身并非「无 CSP」，而是覆盖不完整：缺少 object-src 时插件内容不受限，缺少 base-uri 时攻击者可通过注入 <base> 改变相对脚本加载来源，从而绕过 script-src 'self' 的限制。片段未展示该 header 是否真正通过 header() 输出到响应，也未展示页面是否存在可注入的 HTML 上下文，故利用可行性需运行时确认。

**source / sink**

- source：body `include`（019.php）
- sink：019.php:2 $headerCSP = "Content-Security-Policy: script-src 'self';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:2` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的 CSP 配置缺陷检查 POC。该候选为配置型（source_kind=config），重点在于检查响应头 Content-Security-Policy 是否存在及 script-src 是否过宽，而非 HTTP 污点注入。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/019' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：响应包含 Content-Security-Policy，检查 script-src 是否允许过宽的外部脚本源。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`SUNSET_PROBE`
- POC 目录：`poc/SEM-3004577a69c4`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

在存在 HTML 注入点时可削弱 CSP 对脚本执行的防护，使 XSS 缓解措施失效；单独存在时影响有限，属于纵深防御缺陷。

**CVE / CWE 论证**

CWE-693 保护机制失效：安全响应头配置不完整。外部可达：响应头随页面返回，无需认证；但实际绕过效果依赖片段外的注入点与浏览器行为，证据不足部分已注明。

**修复建议**

补全策略，例如 default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'；并通过 header() 在输出任何内容前发送；结合 nonce/hash 机制而非仅依赖 'self'。

**验证说明**

静态证据：入口 POST /019；source=body/include；sink=019.php:2；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者若能向页面注入 HTML → 缺少 base-uri 限制使其可插入 <base href> 改变相对脚本来源 → script-src 'self' 被绕过 → 加载攻击者脚本。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-693（防护机制失效）。候选位于 019.php:2，属配置型问题，需以响应头证据确认。
POC 备注：POC 仅为文本工件，不执行、不联网。判定依据为响应头 Content-Security-Policy 的实际内容，而非请求体。

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
| `xss` | CWE-79 | 是 | 0 |
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
| safety_guard | 安全防护 | 3.32 | 是 |
| surface_mapper | 攻击面测绘 | 6.87 | 是 |
| deep_finder | LLM 深挖 | 4.71 | 是 |
| candidate_screener | 候选筛选 | 4.79 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.84 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 12.74 | 是 |
| coordinator | 管线协调 | 7.38 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
