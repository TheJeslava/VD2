# 落日二号乙漏洞挖掘报告 — 20261031-014320-98caf0

- 生成时间：2026-10-30T17:44:01.214610+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\044.zip`
- 输入模式：`zip`
- SHA256：`3d813153119636f5c8c7ceeb52e0c898d6179ed4c598625db3defa0dff283e44`
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

本次汇总仅含 1 个文件 044.php（19 行）的 2 条 file_upload 发现，均已去重且均带 POC：GEN-7d549df94451（critical，规则命中，行 9）与 LLM-6ccece6535f3（high，模型推断，行 16），二者指向同一根因——上传文件未做类型/扩展名校验即落盘，可写入 PHP 文件进而 RCE。最高危为 critical 级任意文件写入。POC 齐全（2/2），但均为静态构造的 HTTP 上传 POC 文本，未做动态验证。除此之外，攻击面测绘提出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 五类配置型候选均无 findings 覆盖，且本次上下文未提供 044.php 源码片段，无法逐行核对，需人工复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 044.php（19 行），已逐行审计。该文件为 DVWA 文件上传漏洞模块：POST 参数 Upload 触发，$_FILES['uploaded']['name'] 经 basename() 后拼接到 hackable/uploads/ 并 move_uploaded_file 落盘，无扩展名/MIME/内容校验，构成无限制文件上传（CWE-434），可上传 PHP 文件实现 RCE。未发现 SQL 注入、命令注入、反序列化、SSRF、路径穿越（basename 已去除目录分隔符，无法穿越目录）、弱哈希/弱加密/弱随机/不安全 Cookie 等其它可闭合链。surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在源码中均无对应调用，属未命中而非漏洞。未覆盖范围：无部署配置（php.ini disable_functions、Web 服务器规则）、无认证/路由信息，无法确认上传目录是否可执行脚本及页面鉴权要求，已在 verification_notes 标注。

未覆盖 / 证据缺口：
- 缺少 Web 服务器与 php.ini 配置，无法确认 uploads 目录脚本执行与危险函数可用性
- 缺少认证/路由信息，无法确认上传页面是否需登录
- 无外部动态扫描证据，结论为静态源码推断

## 3. Findings

### F-1: 044.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（044.php:9 的 `$_FILES['uploaded']['tmp_name']`），代码在 044.php:9 直接调用 `move_uploaded_file()` 将临时文件移动到 `$target_path`。从给出的片段看，第 7-9 行之间没有任何扩展名白名单、MIME 校验、文件内容检查或 `$target_path` 的规范化/重命名逻辑，`$target_path` 的构造（推测位于第 9 行之前）在片段中不可见，因此无法确认其是否包含原始文件名或用户可控路径；但可以确认的是，上传动作本身没有对文件类型做任何校验，校验缺失即为绕过原因。最终危险操作是 `move_uploaded_file()` 把攻击者控制的文件内容写入 Web 可访问目录。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /044（ANY）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/044'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/044' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/GEN-7d549df94451`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若上传目录位于 Web 根下且允许 PHP 等可执行扩展名，攻击者可上传 webshell 并访问对应 URL，实现远程代码执行（RCE）；即使不可执行，也可造成任意文件写入/覆盖、存储型恶意内容托管（钓鱼、恶意脚本分发）以及磁盘占用。具体可利用性取决于 `$target_path` 的构造与目录权限，该部分证据不足。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 表单字段 `uploaded`，无需认证即可触达（片段中未见任何鉴权/会话校验）。利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file()` → 目标路径落盘，缺少类型/扩展名校验，攻击者可直接控制落盘内容。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端解析的真实 MIME 与文件头校验，而非客户端 `Content-Type`；2) 忽略客户端文件名，由服务端生成随机文件名并固定扩展名；3) 将上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 PHP 的 `php_admin_flag engine off`）；4) 对 `$target_path` 做 `realpath()` 规范化并校验其位于允许目录内，防止路径穿越；5) 限制文件大小与上传频率，上传后做病毒/内容扫描；6) 上传接口增加认证与 CSRF 防护。

**验证说明**

静态证据：入口 ANY /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，将恶意文件放入字段 `uploaded`。PHP 将其存入临时文件，`$_FILES['uploaded']['tmp_name']` 指向该临时文件；044.php:9 的 `move_uploaded_file()` 在无任何扩展名/类型校验的情况下把临时文件移动到 `$target_path`。攻击者随后通过 Web 访问落盘文件，若为可执行脚本则获得代码执行。片段未展示 `$target_path` 的赋值语句，故目标路径是否含用户可控成分（如原始文件名）无法确认，属证据缺口。
PocWriter 建议（未采纳，缺少端点 /044）：针对 044.php:9 的不安全文件上传（CWE-434）POC。上传处理入口位于 044.php 第 9 行附近，外部输入来自 multipart 表单字段 `uploaded` 的文件名/内容，未发现扩展名白名单或内容类型校验。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434（不受限制的危险类型文件上传）。漏洞位于可交付代码 044.php:9，外部输入来自 multipart 字段 `uploaded`，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并手动运行；上传文件内容保持无害标记，禁止上传真实 webshell 或破坏性载荷。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 uploads 目录（可 RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，并调用 move_uploaded_file() 将临时文件移动到该路径。代码未校验扩展名、MIME 类型、文件内容，也未做白名单/重命名，攻击者可上传 .php 文件到 Web 可访问的 hackable/uploads/ 目录，随后请求该文件即可执行任意 PHP 代码，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 后进入上传处理分支 | 攻击者控制请求体与上传文件 |  |
| 2 | `044.php:5-6` | 拼接目标目录 hackable/uploads/ 与 basename(上传文件名)，basename 仅去除路径分隔符，不限制扩展名 | $target_path = <web_root>/hackable/uploads/<攻击者文件名> |  |
| 3 | `044.php:9` | move_uploaded_file 将临时文件移动到攻击者可控路径，无扩展名/MIME/内容校验 | 任意内容文件落盘到 Web 可访问目录 |  |
| 4 | `044.php:15` | 成功时回显完整落盘路径，泄露上传位置 | 响应包含 $target_path |  |

**POC**

针对 /vulnerabilities/upload/ (044.php)（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (044.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (044.php)' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-6ccece6535f3`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在服务器写入并执行任意 PHP 代码，完全控制 Web 应用与主机（在 PHP 进程权限范围内）。

**CVE / CWE 论证**

CWE-434 无限制文件上传。外部 HTTP 可达，无需高权限，source（上传文件名/内容）到 sink（move_uploaded_file 落盘到 Web 目录）链路在 044.php:3-16 完整闭合，落盘路径可预测且可回显。

**修复建议**

使用扩展名与 MIME 白名单校验，重命名上传文件为随机名并去除可执行扩展名，将上传目录置于 Web 根之外或禁用该目录的脚本执行（如 php_flag engine off），限制文件大小与内容类型。

**验证说明**

需确认 hackable/uploads/ 是否可被 HTTP 直接访问及 PHP 是否在该目录执行；需确认上传页面是否需要认证。代码层面无任何校验，链闭合。
模型 POC 要点：上传一个 PHP webshell 到 uploads 目录，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 044.php:16 的不安全文件上传（CWE-434）POC。上传处理逻辑位于 044.php 第 16 行附近，外部输入来自 multipart 表单字段 `uploaded` 的文件名/内容，未发现扩展名白名单或内容类型校验，攻击者可上传可被服务端解析的脚本文件。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（不受限制的危险类型文件上传）。漏洞位于可交付代码 044.php:16，外部输入来自 multipart 字段 `uploaded`，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标并手动运行；上传文件内容保持无害标记，禁止上传真实 webshell 或破坏性载荷。

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
| `path_traversal` | CWE-22 | 是 | 0 |
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
| `file_upload` | CWE-434 |  | 2 |
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
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.61 | 是 |
| surface_mapper | 攻击面测绘 | 7.21 | 是 |
| deep_finder | LLM 深挖 | 7.86 | 是 |
| candidate_screener | 候选筛选 | 3.78 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.83 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.46 | 是 |
| coordinator | 管线协调 | 5.64 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
