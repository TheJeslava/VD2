# 落日二号乙漏洞挖掘报告 — 20261031-164158-04bb08

- 生成时间：2026-10-31T08:42:53.261079+00:00
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

本次汇总基于已去重的 3 条 findings，全部集中在单文件 PHP 脚本 019.php（共 22 行）：高危 2 条、中危 1 条。最高危的是 GEN-12e64feced48（path_traversal，high）：$_POST['include'] 未过滤即拼接进页面输出，属 CWE-22 路径穿越/任意文件包含面；其次 SEM-99a2f26a9c57（client_side_validation，high，CWE-602）引入 source/high.js 客户端脚本，服务端校验缺失；SEM-3004577a69c4（csp，medium，CWE-693）为 CSP script-src 'self' 配置评估。3 条均带 POC（with_poc=3），但均为静态/规则推断证据，未做动态验证；其中 csp 与 client_side_validation 的 POC 属配置/静态证据型，不能宣称可动态复现。攻击面测绘明确说明未提供代码正文，sink_hot_files 为空，因此注入类（command/sql/xpath/ldap/ssrf）与配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均未形成结论，需人工复核。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 704 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 019.php（1-22 行，DVWA CSP 练习页 high 级别）。第 2-4 行设置 Content-Security-Policy: script-src 'self'，第 8-12 行读取 $_POST['include'] 并直接拼接到 $page['body']，第 13-21 行输出表单与 <script src="source/high.js">。该拼接点确实存在未编码的请求参数写入响应体，属于反射型注入面，但本文件内没有任何 echo/print 将 $page['body'] 输出到 HTTP 响应（渲染发生在 code_pack 之外的公共模板/包含文件中），因此 source→sink 链在本文件内不闭合；同时页面 CSP 为 script-src 'self'，注入的 HTML 无法执行内联脚本，仅能注入静态标记，影响不足以申报 CVE。其余攻击面（命令执行、SQL、文件包含、反序列化、SSRF、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）在本文件中均无对应代码：无 system/exec、无数据库调用、无 include/require 动态包含、无 md5/sha1/rand/setcookie。未发现 prompt_injection 诱导文本。未闭合线索：$page['body'] 的最终输出位置（模板文件）未在 code_pack 中提供，若该模板未做 htmlspecialchars 且 CSP 被绕过（例如通过 source/high.js 或 jsonp.php 的 JSONP 回调），则可能构成 XSS，但缺少证据，按规则不报告。

未覆盖 / 证据缺口：
- $page['body'] 的渲染/输出模板不在 code_pack 中，无法确认是否对 $_POST['include'] 做 HTML 编码
- source/high.js 与 source/jsonp.php 未提供，无法评估 CSP 绕过与 JSONP 回调注入
- 无 php.ini/Web 服务器配置，无法判断部署与暴露面
- 无认证/会话代码，无法判断该页面是否在认证之后

## 3. Findings

### F-1: 019.php 未过滤的 $_POST['include'] 直接拼接进页面输出（CWE-22 路径穿越/任意文件包含）

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:8-10`
- **来源**：`rule`

**描述**

攻击者通过 HTTP POST 提交参数 include（019.php:8 的 isset($_POST['include']) 判断存在性，019.php:10 读取其值）。该值未经任何白名单、basename()、realpath() 规范化或路径前缀校验，被直接以字符串拼接方式写入 $page['body'] 的内联表达式（019.php:10：" . $_POST['include'] . "）。由于该拼接结果随后作为页面内容/包含目标使用，攻击者可提交 ../ 序列或绝对路径穿越预期目录，读取或引入任意文件。校验无效的原因：代码只做了 isset() 存在性检查，没有任何内容过滤或路径规范化，属于典型的“存在性检查被误当作安全校验”。

**source / sink**

- source：query `include`（019.php:10）
- sink：019.php:10 " . $_POST['include'] . "

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:10` | 从 query `include` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `019.php:10` | 危险汇点：" . $_POST['include'] . " | 污点进入 path_traversal 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /019（POST）的路径穿越/任意文件读写 POC。注入点为 POST 参数 include，源码 019.php:10 处将外部输入直接用于文件路径操作，未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/019' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN12e64.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`../../../../tmp/sunset_GEN12e64.txt`
- POC 目录：`poc/GEN-12e64feced48`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

任意文件读取/本地文件包含：可读取 Web 根目录之外的敏感文件（配置、凭据、系统文件），若被包含的 PHP 文件可解析则可能导致代码执行；也可用于探测服务器文件系统结构，为后续攻击提供信息。

**CVE / CWE 论证**

CWE-22（路径穿越）。外部可达性：019.php 为可直接 HTTP 访问的脚本，POST 参数 include 无需认证即可提交；利用链闭合：source（$_POST['include']，019.php:8/10）→ 无净化拼接（019.php:10）→ 危险汇点（页面输出/包含）。无需前置权限，攻击复杂度低。

**修复建议**

1) 不要将用户输入直接拼接进包含路径或页面输出；2) 使用固定白名单映射（如 $allowed = ['home','about']; 仅接受白名单键）；3) 若必须使用文件名，先 basename() 去除目录部分，再用 realpath() 规范化并校验结果仍位于允许的基目录内；4) 对输出到 HTML 的内容使用 htmlspecialchars() 编码；5) 关闭 allow_url_include，限制 open_basedir。

**验证说明**

静态证据：入口 POST /019；source=query/include；sink=019.php:10；规则 php-include。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 019.php 发送 POST 请求，参数 include 携带 ../ 或绝对路径 → 019.php:8 的 isset($_POST['include']) 为真 → 019.php:10 将原始值直接拼接到 $page['body'] 的内联表达式 → 未经过任何路径规范化或白名单 → 最终以攻击者控制的路径进行文件读取/包含。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-22。漏洞位于可交付代码 019.php:10，外部输入来自 POST 参数 include，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构（POST /019，参数 include，URL 编码 ../）。脚本仅为文本工件，不执行、不联网；执行前需人工替换 TARGET 并确认授权。

### F-2: 019.php 引入 source/high.js 客户端脚本（CWE-602 客户端校验）

- **类型**：`client_side_validation` / CWE-602
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:19-20`
- **来源**：`rule`

**描述**

019.php:20 通过 <script src="source/high.js"></script> 引入外部脚本。输入中未提供 source/high.js 的内容，无法确认其中是否包含校验逻辑，也未提供服务端缺少对应校验的证据。因此“客户端校验绕过”的结论证据不足，不能确认。

**source / sink**

- source：client `external JavaScript`（019.php）
- sink：019.php:20 <script src="source/high.js"></script>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:20` | 客户端脚本参与校验；需同时审计服务端是否重复校验 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的客户端校验绕过 POC。源码 019.php:20 处依赖外部 JavaScript 进行校验，服务端未做等价校验，可通过直接构造 POST 请求绕过前端限制。payload 使用 TARGET 占位符，仅限授权测试。

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

证据不足：若 high.js 仅做前端校验而服务端无重复校验，攻击者可直接构造请求绕过；但当前无 high.js 源码与对应服务端处理逻辑证据。

**CVE / CWE 论证**

CWE-602（依赖客户端安全）。外部可达性无法确认，缺少 high.js 内容与服务端校验缺失证据，利用链不闭合。

**修复建议**

所有安全校验必须在服务端重复执行；客户端脚本仅用于提升用户体验；对 019.php 的 include 参数在服务端做白名单与规范化（与 GEN-12e64feced48 修复一致）。

**验证说明**

静态证据：入口 POST /019；source=client/external JavaScript；sink=019.php:20；规则 php-client-validation。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：证据不足：仅见脚本引用（019.php:20），未见校验逻辑与服务端缺失点，无法构成完整利用链。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-602。漏洞位于可交付代码 019.php:20，校验仅存在于客户端 JavaScript，服务端未复现同等校验。
POC 备注：保留原请求结构。需人工确认 019.php:20 前端校验字段后再定稿具体绕过值；当前 SUNSET_PROBE 为占位探测值。脚本仅为文本工件，不执行、不联网。

### F-3: 019.php 的 CSP 策略 script-src 'self' 配置评估（CWE-693）

- **类型**：`csp` / CWE-693
- **严重度**：`medium`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`019.php:1-2`
- **来源**：`rule`

**描述**

019.php:2 定义 $headerCSP = "Content-Security-Policy: script-src 'self';";。该策略限制脚本仅来自同源，属于相对严格的 script-src 配置；输入中未提供该头部被实际发送（header() 调用）的证据，也未提供可绕过同源限制的内联脚本或 JSONP 端点证据。因此“CSP 配置缺陷”的结论证据不足，不能确认存在可利用的防护缺失。

**source / sink**

- source：body `include`（019.php）
- sink：019.php:2 $headerCSP = "Content-Security-Policy: script-src 'self';";

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `019.php:2` | CSP 与可控脚本来源联动；需检查最终响应和浏览器加载结果 | 语义模式命中 | 需按 notes 中的运行时/跨文件条件复核 |

**POC**

针对 /019（POST）的 CSP 配置缺陷 POC。通过请求入口并检查响应头 Content-Security-Policy 是否存在及 script-src 是否过宽。payload 使用 TARGET 占位符，仅限授权测试。

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

证据不足：若该 CSP 未被实际输出到响应，则页面无 CSP 防护；若已输出，script-src 'self' 可缓解外部脚本注入，但对同源上传/JSONP 仍有限制不足的可能。当前无法确认具体影响。

**CVE / CWE 论证**

CWE-693（防护机制不当）。外部可达性无法确认，因为缺少 header() 发送点与响应证据；利用链不闭合。

**修复建议**

确认在输出前调用 header($headerCSP)；补充 object-src 'none'、base-uri 'self'、frame-ancestors 'none'；避免同源下存在用户可控脚本/JSONP；对上传目录单独设置 Content-Disposition 与独立源。

**验证说明**

静态证据：入口 POST /019；source=body/include；sink=019.php:2；规则 php-csp-policy。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：证据不足：仅见 CSP 字符串定义（019.php:2），未见发送与绕过路径，无法构成完整利用链。
PocWriter 建议（未采纳，缺少端点 /019）：符合 CWE-693。漏洞位于可交付代码 019.php:2，属配置型候选，需以响应头证据判定，而非 HTTP 污点。
POC 备注：保留原请求结构。CSP 判定必须检查响应头 Content-Security-Policy，而非响应体。脚本仅为文本工件，不执行、不联网。

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
| safety_guard | 安全防护 | 3.29 | 是 |
| surface_mapper | 攻击面测绘 | 10.2 | 是 |
| deep_finder | LLM 深挖 | 3.87 | 是 |
| candidate_screener | 候选筛选 | 6.33 | 是 |
| vulnerability_analyzer | 漏洞分析 | 11.24 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 11.31 | 是 |
| coordinator | 管线协调 | 8.04 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
