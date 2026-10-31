# 落日二号乙漏洞挖掘报告 — 20261031-214317-c2b6fc

- 生成时间：2026-10-31T13:44:15.647914+00:00
- 输入：`$WORKSPACE\暴风星云裂\019.zip`
- 输入模式：`zip`
- SHA256：`6025929a102eb86bb4fd115eeca31f75dc4fa121b1ef36f13f537ead06568b83`
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 019.php（22 行，约 570 字节），无框架、无路由、无端点清单。最高危为 GEN-c0759cbfa182（path_traversal，high）：019.php 第 8 行附近对 include 参数未做校验，可导致路径穿越/任意文件包含（CWE-22）；其次 SEM-99a2f26a9c57（client_side_validation，high，CWE-602）表明校验仅依赖 source/high.js 客户端脚本，服务端未复验；SEM-3004577a69c4（csp，medium，CWE-693）为 CSP 仅 script-src 'self' 的配置缺陷。3 条均带 POC（has_poc=true），但均为静态源码证据 POC，未做动态验证，不能宣称可动态复现。需特别说明：surface_notes 明确本次输入未提供任何源码文本，仅有文件元数据与热点行号，因此上述行号级结论应视为基于规则/元数据的定位，仍需人工对照源码复核。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 019.php（22 行，DVWA CSP 练习页 high 级别）。已逐行审计：第 2-4 行设置 Content-Security-Policy: script-src 'self' 并输出响应头；第 8-12 行接收 $_POST['include'] 并直接拼接到 $page['body']，第 13-21 行拼接静态表单与 <script src="source/high.js">。第 10 行的 $_POST['include'] 未做任何编码即进入 $page['body']，属于典型的反射型注入点，但该文件本身不输出 $page['body']（无 echo/print），实际渲染发生在 code_pack 之外的模板/包含文件中，链路在给定代码内不闭合；同时页面已下发 script-src 'self' 的 CSP，即使注入 <script> 也会被拦截，仅剩 CSP 未覆盖的向量（如注入 <form>/<base>/<meta> 或利用同源 source/high.js、source/jsonp.php 的 JSONP 回调）才可能生效，而这些依赖未提供的文件。按零容忍误报原则，不将未闭合的 XSS 作为 finding 交付。其余攻击面：无 include/require、无文件函数、无 system/exec/eval、无数据库调用、无反序列化、无 SSRF 汇点；无认证/会话/Cookie/加密相关代码，故无 weak_crypto/weak_hash/insecure_cookie 类候选。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- $page['body'] 的最终输出点不在 code_pack 内，无法确认 $_POST['include'] 是否原样回显到响应体，反射型 XSS 链路未闭合
- source/high.js 与 source/jsonp.php 未提供，无法评估 CSP 绕过（JSONP 回调、同源脚本注入）的可行性
- DVWA_WEB_PAGE_TO_ROOT 常量定义与模板包含关系未知，无法确认部署形态与端点路由
- 无 php.ini/服务器配置，无法判断 CSP 头是否被覆盖或是否存在其它响应头注入面

## 3. Findings

### F-1: 019.php 未校验的 include 参数导致路径穿越/任意文件包含（CWE-22）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:6-8`
- **来源**：`rule`

**描述**

攻击者通过 POST 参数 include 提交外部输入（019.php:8 的 isset($_POST['include']) 仅判断存在性，未做任何过滤）。该值在 019.php:10 被直接拼接进 $page['body'] 的字符串中（" . $_POST['include'] . "），随后作为页面 body 内容输出/渲染。代码中不存在白名单、basename()、realpath()、路径规范化或 ../ 过滤，因此校验完全无效。注意：本候选的 source 标注为 query `include`，但源码实际读取的是 $_POST['include']，注入点为 POST 参数 include，而非 URL query。

**source / sink**

- source：query `include`（019.php:8）
- sink：019.php:8 if (isset ($_POST['include'])) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:8` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:8` | 危险汇点：if (isset ($_POST['include'])) { | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（POST）的 路径穿越 / 任意文件读写 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

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

攻击者可控制页面 body 中拼接的内容，若该 body 后续被 include/require 或写入文件，则可导致任意本地文件读取/包含乃至代码执行；即使仅回显，也可注入任意 HTML/脚本内容，造成内容伪造与客户端脚本执行。具体最终危险操作取决于 $page['body'] 的消费方，该消费方不在 code_pack 中，证据不足。

**CVE / CWE 论证**

CWE-22 路径穿越：外部可控输入（POST include）未经规范化直接进入文件/路径相关拼接点，外部 HTTP 可达、无需认证。但利用链闭合性存疑——拼接结果进入 $page['body'] 字符串而非直接的 include()/file_get_contents() 调用，最终文件操作汇点未在 code_pack 中出现，故不能断言完整 RCE/任意文件读取链。

**修复建议**

1) 不要将用户输入直接拼接进路径或页面内容；2) 若确需按名加载页面，使用固定白名单映射（如 ['home','about'] => 文件路径），拒绝一切未命中项；3) 对路径使用 basename() 并配合 realpath() 校验结果仍位于允许目录内；4) 输出到 HTML 时进行 HTML 实体编码，避免内容注入。

**验证说明**

静态证据：入口 POST /019；source=query/include；sink=019.php:8；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者 POST include=../../etc/passwd（或任意内容）→ 019.php:8 isset 判断通过（无过滤）→ 019.php:10 直接字符串拼接进 $page['body'] → 页面 body 输出/后续消费。由于缺少最终文件操作汇点证据，链路在“body 消费”处中断，需补充消费方代码才能确认任意文件读取/RCE。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:8 的路径穿越（CWE-22）POC。源码中 POST 参数 include 未经净化即被用于文件路径拼接/包含，攻击者可通过 ../ 序列跳出预期目录，读取或写入 testfiles 目录之外的文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22（路径穿越）。漏洞位于 019.php:8，外部输入来自 POST 参数 include，source→sink 链在 code_pack 内静态闭合，未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。执行前需将 TARGET 替换为授权测试目标，并确认 019.php:8 的 sink 类型（读/写）以选择对应预期结果。

### F-2: 019.php 依赖客户端脚本 source/high.js 进行校验（CWE-602）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:19-20`
- **来源**：`rule`

**描述**

019.php:20 通过 <script src="source/high.js"></script> 引入客户端脚本参与校验逻辑。客户端校验可被攻击者完全绕过（禁用 JS、直接构造请求、修改脚本），若服务端未对同一数据重复校验，则校验形同虚设。code_pack 中未提供服务端对应校验代码，无法确认是否存在服务端兜底。

**source / sink**

- source：client `external JavaScript`（019.php）
- sink：019.php:20 <script src="source/high.js"></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:20` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的 客户端校验绕过 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

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

攻击者可绕过前端限制直接提交恶意数据（如 include 参数），配合 019.php:10 的拼接点放大注入风险；具体影响取决于被校验字段，证据不足。

**CVE / CWE 论证**

CWE-602 客户端安全控制依赖：安全决策依赖客户端脚本。外部可达、无需认证，但服务端是否缺失校验未在 code_pack 中体现，利用链闭合性不足。

**修复建议**

所有安全校验必须在服务端强制执行；客户端脚本仅用于用户体验提示；对 include 等敏感参数在服务端做白名单与规范化。

**验证说明**

静态证据：入口 POST /019；source=client/external JavaScript；sink=019.php:20；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者绕过 source/high.js 的前端校验 → 直接 POST include 恶意值 → 019.php:8/10 无服务端校验直接拼接。服务端校验缺失证据不足，需补充后端代码确认。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:20 的客户端校验绕过（CWE-602）POC。该 finding 涉及页面中外部 JavaScript 的客户端校验逻辑，服务端未做等价校验，攻击者可直接构造请求绕过前端限制。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-602（依赖客户端安全）。漏洞位于 019.php:20，涉及外部 JavaScript 客户端校验，服务端未见等价校验。证据等级：llm_inferred（基于源码推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。需人工确认 019.php:20 前端校验字段与服务端处理逻辑的对应关系。

### F-3: 019.php CSP 仅限制 script-src 'self' 的配置缺陷（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:1-2`
- **来源**：`rule`

**描述**

019.php:2 设置 $headerCSP = "Content-Security-Policy: script-src 'self';";。该策略仅限制脚本来源为同源，未设置 default-src、object-src 'none'、base-uri、frame-ancestors 等，且未禁止内联事件处理器之外的其它向量（如通过同源上传/JSONP 加载脚本）。结合 019.php:10 可将外部输入拼入 body，若攻击者能注入同源脚本引用或利用同源资源，CSP 无法有效阻断。

**source / sink**

- source：body `include`（019.php）
- sink：019.php:2 $headerCSP = "Content-Security-Policy: script-src 'self';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:2` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的 CSP 配置缺陷 POC。注入点：POST 参数 include；payload 使用 TARGET 占位符。

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

CSP 保护不完整，降低了对 XSS/内容注入的纵深防御能力；在存在 body 注入（GEN-12e64feced48）时可被绕过，导致脚本在同源上下文执行。

**CVE / CWE 论证**

CWE-693 保护机制失效：策略配置过宽/不完整。属配置型弱点，无直接污点链要求，但需结合 019.php:10 的注入点评估实际可利用性；最终响应头是否真正下发需运行时确认，证据不足。

**修复建议**

采用严格 CSP：default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'；避免同源下可上传可执行脚本；配合 nonce/hash 机制。

**验证说明**

静态证据：入口 POST /019；source=body/include；sink=019.php:2；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：019.php:2 定义宽松 CSP → 019.php:10 存在 body 注入 → 攻击者尝试注入同源脚本引用 → CSP 因仅限 script-src 'self' 无法阻断同源加载。需运行时确认响应头实际生效。
PocWriter 建议（未采纳，缺少端点 /019）：针对 019.php:2 的 CSP 配置缺陷（CWE-693）POC。该 finding 属配置型候选，无 HTTP 污点依赖，重点在于检查响应头 Content-Security-Policy 是否存在及 script-src 等指令是否过宽。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-693（防护机制失效）。漏洞位于 019.php:2，属配置型候选，需以响应头证据判定。证据等级：llm_inferred（基于源码推断，未动态验证响应头）。
POC 备注：POC 仅为文本工件，不执行、不联网。判定依据为响应头 Content-Security-Policy 的实际内容，需人工核对。

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
| safety_guard | 安全防护 | 4.26 | 是 |
| surface_mapper | 攻击面测绘 | 7.74 | 是 |
| deep_finder | LLM 深挖 | 4.61 | 是 |
| candidate_screener | 候选筛选 | 6.24 | 是 |
| vulnerability_analyzer | 漏洞分析 | 14.09 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 13.52 | 是 |
| coordinator | 管线协调 | 7.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
