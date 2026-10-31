# 落日二号乙漏洞挖掘报告 — 20261031-012146-f417f3

- 生成时间：2026-10-30T17:22:27.934155+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\045.zip`
- 输入模式：`zip`
- SHA256：`a0b2458750b044b980ebfd21404d68504f146fb80f29769046d1fc1c3577d5c4`
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

本次汇总仅涉及单文件 PHP 脚本 045.php（33 行），共 2 条去重后的 file_upload 发现：GEN-60f80eecf7e1（critical，规则命中，第 18 行 move_uploaded_file 直接落盘、缺少扩展名/类型校验）与 LLM-ba92d09576fd（high，LLM 推断，第 25 行仅校验客户端可控 MIME，可上传 PHP 脚本导致 RCE）。两者均带 POC（HTTP 型，可动态复现），最高危为 critical 的无限制上传。POC 齐全度：2/2 有 POC，但均为静态构造文本，未做动态验证。其余注入/XSS/路径穿越/配置类风险因 sink_hot_files 为空、无数据流结果，未形成 finding，需人工通读源码确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 045.php（33 行，DVWA 文件上传练习页）。已通读全部 33 行：入口为 $_POST['Upload'] 触发的 $_FILES['uploaded'] 上传，唯一危险汇点为第 18 行 move_uploaded_file。发现并闭合一条文件上传→RCE 链：MIME 校验取自客户端可控的 $_FILES['uploaded']['type']，文件名经 basename 后直接拼接为 .php 目标路径，可上传 webshell。未发现 SQL 拼接、命令执行、include/文件读取、反序列化、SSRF、弱哈希/弱随机/setcookie 等其它 sink（文件中无 md5/rand/setcookie/session 调用）。未闭合线索：DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，无法确认最终绝对路径；endpoints 为空，无法确认实际访问路由与是否存在前置鉴权/WAF；无部署配置，无法确认上传目录是否允许脚本执行。这些属于运行时条件，不影响链本身的源码闭合性。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义未在 code_pack 中，最终落盘绝对路径依赖运行时
- 无部署配置，无法确认 hackable/uploads/ 是否可写及 .php 是否被解析
- endpoints 为空，实际访问路径与前置鉴权/WAF 未知
- 无 composer.json/依赖清单，无法评估第三方组件

## 3. Findings

### F-1: 045.php 不安全文件上传（CWE-434）：上传文件被直接 move_uploaded_file 落盘，缺少类型/扩展名校验

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交任意文件（045.php:18 的 `$_FILES['uploaded']['tmp_name']`）。代码在 045.php:18 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 将临时文件移动到目标路径，输入中给出的代码片段（045.php:16-18）未出现任何扩展名白名单、MIME 校验、`getimagesize()` 校验或文件名规范化逻辑，因此校验无效/缺失。污点从上传字段 `uploaded` 进入 `$_FILES['uploaded']['tmp_name']`，经 `move_uploaded_file()` 到达文件系统写入汇点。注意：`$target_path` 的构造代码不在本次 code_pack 片段内，其是否包含原始文件名、是否落在 Web 可访问目录，证据不足，需结合 045.php 其余行确认。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /045（ANY）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/045' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/GEN-60f80eecf7e1`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

若目标目录位于 Web 根下且可执行脚本，攻击者可上传 .php/.phtml 等文件并获得远程代码执行（RCE）；即使不可执行，也可造成任意文件写入、覆盖已有文件、磁盘占用，以及上传恶意内容用于钓鱼/挂马。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传接口为 HTTP 表单处理逻辑，无需认证即可触达（输入中未见鉴权判断）。利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file()` → 目标路径落盘，中间无有效净化。RCE 成立的前提是 `$target_path` 指向可执行目录，该前提在片段中未给出，故按 llm_inferred 记录。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并基于服务端解析的真实类型校验（`finfo_file`/`getimagesize`），不要信任 `$_FILES['uploaded']['type']` 与客户端文件名；2) 用 `basename()` + 随机生成的文件名重命名，禁止路径分隔符与 `..`；3) 上传目录置于 Web 根之外，或通过 Web 服务器配置禁止该目录执行脚本；4) 限制文件大小与数量，设置目录最小权限；5) 上传后做病毒/内容扫描。

**验证说明**

静态证据：入口 ANY /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 045.php 的上传字段 `uploaded` 提交恶意文件 → PHP 将其存入临时文件 `$_FILES['uploaded']['tmp_name']` → 045.php:18 调用 `move_uploaded_file()` 直接移动到 `$target_path`，无扩展名/类型校验 → 文件持久化到服务器；若目录可执行则访问该文件触发 RCE。
PocWriter 建议（未采纳，缺少端点 /045）：针对 045（任意方法）的不安全文件上传 POC。注入通道为 multipart 表单字段 `uploaded` 的 filename（045.php:18 附近的上传处理逻辑）。该 finding 的端点未限定 HTTP 方法，实际测试应优先使用 POST（multipart 上传语义要求），若服务端仅接受特定方法再按响应调整。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434。漏洞位于可交付代码 045.php:18，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。原草稿使用 `-X ANY` 非标准方法，实际 HTTP 无 ANY 方法，建议以 POST 发送 multipart；执行前将 TARGET 替换为授权测试实例地址；上传内容保持无害标记，禁止上传真实 webshell。

### F-2: DVWA 文件上传页面仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本并 RCE

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-25`
- **来源**：`llm_finding`

**描述**

045.php 处理 POST 上传时，仅用 $_FILES['uploaded']['type']（完全由客户端 multipart 请求的 Content-Type 决定）与 size<100000 作为“是否为图片”的判断，未校验扩展名、未校验真实文件内容（无 getimagesize/finfo）、未做白名单重命名。$target_path 由 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 拼接 basename(原始文件名) 得到，攻击者可将文件名设为 shell.php，并把 multipart 分片的 Content-Type 伪造成 image/jpeg，从而通过第 14 行判断，在第 18 行 move_uploaded_file 落盘为可执行 PHP 文件，随后访问该文件即可远程执行任意代码。

**source / sink**

- source：upload `uploaded`（045.php）
- sink：045.php:25 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 hackable/uploads/ 下攻击者命名的文件

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `045.php:6` | 用 basename($_FILES['uploaded']['name']) 拼接目标路径，文件名完全由攻击者控制，basename 只去掉目录部分，不限制扩展名 | $target_path = <webroot>/hackable/uploads/shell.php |  |
| 3 | `045.php:10` | $uploaded_type 取自 $_FILES['uploaded']['type']，即客户端 multipart 分片的 Content-Type，可任意伪造 | $uploaded_type = 'image/jpeg'（伪造） |  |
| 4 | `045.php:14` | 仅比较伪造的 MIME 与大小，未检查扩展名/真实内容，判断通过 | 条件为真，进入上传分支 | MIME 类型来自客户端，可任意设置；无扩展名白名单、无 getimagesize 内容校验 |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到攻击者命名的 .php 路径，落盘为可执行脚本 | webshell 写入 hackable/uploads/shell.php |  |

**POC**

针对 /045.php（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/045.php' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-ba92d09576fd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可上传并执行任意 PHP 代码，完全控制 Web 服务器（RCE）。

**CVE / CWE 论证**

CWE-434 无限制文件上传 / CWE-646 依赖不可信文件元数据。外部 HTTP 可达，无需认证，source→sink 链在 045.php:3-18 完整闭合，MIME 校验可被客户端伪造绕过。

**修复建议**

使用扩展名白名单并重命名为随机名；用 getimagesize()/finfo 校验真实文件内容；将上传目录置于 web 根之外或禁止脚本执行；校验失败时拒绝落盘。

**验证说明**

需确认 hackable/uploads/ 目录可写且 .php 被解析执行（DVWA 默认配置下成立）；需确认 DVWA_WEB_PAGE_TO_ROOT 常量在包含本文件前已定义，否则路径拼接会异常。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传 PHP webshell，随后访问触发命令执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /045.php）：针对 045.php（POST）的不安全文件上传 POC。注入通道为 multipart 表单字段 `uploaded` 的 filename（045.php:25 附近的上传处理逻辑），攻击者可将可执行脚本（如 .jsp）作为文件名/内容上传，若上传目录可被 Web 容器解析则导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:25，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单、内容类型校验或重命名等有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。执行前将 TARGET 替换为授权测试实例地址；上传内容保持无害标记，禁止上传真实 webshell 或破坏性载荷；第 3 步路径需按实际上传目录调整。

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
| safety_guard | 安全防护 | 2.26 | 是 |
| surface_mapper | 攻击面测绘 | 6.35 | 是 |
| deep_finder | LLM 深挖 | 9.35 | 是 |
| candidate_screener | 候选筛选 | 3.41 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.28 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.16 | 是 |
| coordinator | 管线协调 | 5.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
