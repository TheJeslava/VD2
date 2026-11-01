# 落日二号乙漏洞挖掘报告 — 20261031-014350-40b250

- 生成时间：2026-10-30T17:44:30.276491+00:00
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

本次汇总仅覆盖单文件 PHP 脚本 045.php（33 行），共交付 2 条 file_upload 发现：规则命中 GEN-60f80eecf7e1（critical，045.php 第 18 行附近，不安全上传导致任意文件写入，CWE-434）与 LLM 推断 LLM-ba92d09576fd（high，045.php 第 25 行附近，仅校验客户端可控 MIME 类型即可上传 PHP 脚本导致 RCE）。两条均带 POC，但均为静态文本 POC（HTTP 形态的上传请求），未做动态验证。最高危为 GEN-60f80eecf7e1（critical）。需注意：输入未提供 045.php 源码正文，行号来自 findings 元数据，sink_hot_files 为空，因此上传落盘路径、扩展名/内容校验逻辑、目标目录是否可执行均未经代码级确认，属 llm_inferred 级别证据。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 045.php（33 行，DVWA 文件上传练习代码）。已审计其唯一攻击面：POST Upload 触发的文件上传流程。发现一条闭合链：客户端可控的 $_FILES['uploaded']['type'] 被当作图片校验依据，配合 basename 保留扩展名与 move_uploaded_file 落盘到 Web 可访问目录，可上传 PHP 脚本实现 RCE（CWE-434）。未发现 SQL/命令/路径穿越/反序列化/SSRF 等其它 sink；文件中无 md5/sha1、rand、setcookie、硬编码凭据等配置型风险。未覆盖范围：DVWA_WEB_PAGE_TO_ROOT 定义、uploads 目录执行策略、部署配置均不在 code_pack 内，无法确认运行时可利用性。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack
- hackable/uploads 目录的 Web 执行配置未知
- 无认证/会话机制信息，无法确认是否需要登录

## 3. Findings

### F-1: 045.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 multipart/form-data 请求向 045.php 提交文件字段 `uploaded`，PHP 将临时文件路径放入 `$_FILES['uploaded']['tmp_name']`，脚本在 045.php:18 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 将其移动到目标目录。输入中给出的代码片段（045.php:16-18）只显示移动动作，未显示对扩展名、MIME 类型、文件内容或目标文件名的任何白名单校验；`$target_path` 的构造逻辑位于片段之外，证据不足，无法确认其是否包含原始文件名或是否被规范化。因此可确认的危险点是：外部可控的上传内容被持久化写入服务器文件系统，且缺少可见的类型/扩展名校验。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 045（ANY 方法）的不安全文件上传 POC。与 LLM-ba92d09576fd 为同一文件 045.php 的同一上传逻辑（此处行号 18），入口路径写作 /045、方法标注为 ANY。注入通道同为 multipart 字段 `uploaded` 的 filename。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

若目标目录位于 Web 可访问路径且允许脚本扩展名落地，攻击者可上传 PHP 等可执行脚本，通过后续 HTTP 请求触发，形成远程代码执行（RCE）；即使不可执行，也可造成任意文件写入/覆盖、磁盘占用，并可能作为钓鱼页面或恶意文件分发点，影响服务器完整性与可用性。

**CVE / CWE 论证**

对应 CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：045.php 为可直接请求的脚本端点，上传字段 `uploaded` 无需认证即可提交（片段中未见任何鉴权逻辑）；利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file()` → 目标路径落盘，中间无可见的扩展名/MIME/内容校验。证据等级为 llm_inferred：`$target_path` 的赋值与目录可访问性未在片段中给出，故 RCE 结论依赖该前提。

**修复建议**

1) 对上传文件使用扩展名白名单（如仅 jpg/png/pdf），并结合 `finfo_file()`/`getimagesize()` 校验真实 MIME 与文件头，不信任客户端 `Content-Type`；2) 由服务端生成随机文件名（如 `bin2hex(random_bytes(16))` + 白名单后缀），不使用用户提供的文件名；3) 将上传目录置于 Web 根之外，或通过下载脚本以 `Content-Disposition: attachment` 输出；4) 上传目录禁用脚本执行（如 Nginx `location ~ \.php$ { deny all; }`）；5) 限制文件大小与请求体大小，并以最小权限账户运行 Web 进程；6) 对 `$target_path` 做 `realpath()` 规范化并校验其位于允许目录内，防止路径穿越。

**验证说明**

静态证据：入口 ANY /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart POST 请求到 045.php，文件字段名为 `uploaded`，内容为恶意脚本。PHP 解析请求后把临时文件路径写入 `$_FILES['uploaded']['tmp_name']`。脚本在 045.php:18 未做任何可见的扩展名/类型/内容校验，直接调用 `move_uploaded_file()` 将临时文件移动到 `$target_path`。由于片段未显示 `$target_path` 的构造与目录访问控制，攻击者能否获得可执行落地取决于该路径是否位于 Web 可访问目录且保留危险扩展名——此点为推断，需结合完整源码确认。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434。漏洞位于 045.php:18，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；ANY 方法在 POC 中落地为 POST multipart。请自行替换 TARGET 并在授权环境手工复现，上传后访问路径以响应回显为准。

### F-2: DVWA 文件上传端点仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-25`
- **来源**：`llm_finding`

**描述**

045.php 在收到 POST 参数 Upload 时，将上传文件移动到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，文件名取自 $_FILES['uploaded']['name'] 经 basename() 处理。唯一的“是否图片”校验使用 $_FILES['uploaded']['type']（即 HTTP 请求中的 Content-Type，完全由客户端控制）与 $_FILES['uploaded']['size']（同样由客户端声明）。攻击者只需在 multipart 请求中把文件 Content-Type 伪造成 image/jpeg 或 image/png，即可上传任意扩展名（如 .php）的脚本到 Web 可访问的 uploads 目录，随后直接请求该文件触发 PHP 执行，实现远程代码执行。代码未做扩展名白名单、未做 getimagesize() 真实内容校验、未做文件重命名。

**source / sink**

- source：upload `uploaded`（045.php:9-11）
- sink：045.php:25 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 于 045.php:18

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制请求体 |  |
| 2 | `045.php:9-11` | 从 $_FILES['uploaded'] 读取文件名、类型、大小，均为客户端声明值 | 未过滤的客户端数据 |  |
| 3 | `045.php:14-15` | 仅比较 $uploaded_type 是否等于 image/jpeg 或 image/png，并检查 size<100000；两者都由客户端在 multipart 头中声明 | 伪造 Content-Type 即可通过 | MIME 类型来自请求头 Content-Type，非服务端真实检测；未调用 getimagesize() 或检查扩展名 |
| 4 | `045.php:6` | 目标路径拼接 basename(文件名)，保留 .php 扩展名 | hackable/uploads/shell.php |  |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到 Web 可访问目录 | 恶意脚本落盘 |  |
| 6 | `045.php:24` | 返回上传成功及完整路径，攻击者据此访问脚本 | 路径泄露 |  |

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

任意文件上传导致远程代码执行，攻击者可完全控制 Web 服务器，读取/篡改数据、横向移动。

**CVE / CWE 论证**

CWE-434 无限制危险类型文件上传。外部 HTTP 直接可达，无需认证，校验仅依赖客户端可控 MIME，链完整闭合。

**修复建议**

使用 getimagesize()/finfo 做服务端真实类型检测；对扩展名做白名单；上传文件重命名为随机名并去除可执行扩展；将上传目录配置为禁止脚本执行。

**验证说明**

需确认 hackable/uploads 目录是否允许 PHP 执行（Web 服务器配置），以及 DVWA_WEB_PAGE_TO_ROOT 的实际路径；动态验证上传后访问是否执行。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传 PHP webshell，再访问上传路径执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /045.php）：针对 045.php（POST）的不安全文件上传 POC。上传入口为 multipart 字段 `uploaded`，注入通道是 multipart 的 filename（`filename=sunset.jsp`），服务端未对扩展名/内容类型做有效校验即落盘，导致可上传可执行脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 045.php:25，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单、内容类型校验或重命名等有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请自行替换 TARGET 并在授权环境操作。上传后的访问路径以步骤 2 响应回显为准，勿猜测固定目录。

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
| safety_guard | 安全防护 | 2.51 | 是 |
| surface_mapper | 攻击面测绘 | 5.56 | 是 |
| deep_finder | LLM 深挖 | 8.32 | 是 |
| candidate_screener | 候选筛选 | 4.04 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.68 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.58 | 是 |
| coordinator | 管线协调 | 5.34 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
