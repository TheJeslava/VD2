# 落日二号乙漏洞挖掘报告 — 20261031-173237-e68222

- 生成时间：2026-10-31T09:33:29.657082+00:00
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

共发现 2 条候选 finding，覆盖 1 种漏洞类型；2 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅有一个 PHP 文件 045.php（33 行），已逐行通读。该文件是 DVWA 的 Low 级别文件上传示例：入口为 POST 参数 Upload + $_FILES['uploaded']，唯一校验是客户端可控的 MIME 类型（$_FILES['uploaded']['type']）与大小 <100000，随后 move_uploaded_file 写入 hackable/uploads/ 且保留原始文件名与扩展名，构成可闭合的无限制文件上传→RCE 链，已作为 high 级 finding 交付。其余攻击面：文件内无 include/require、无 system/exec、无数据库查询、无 echo 直接输出用户参数（仅输出 $target_path 与固定文案，$target_path 经 basename 处理，不构成 XSS 或路径穿越的独立可利用链）；未发现 md5/sha1、mcrypt/openssl、rand/mt_rand、setcookie、X-Forwarded-For 等配置型候选。未发现 prompt_injection 诱导文本。未覆盖范围：无 composer/框架配置、无 php.ini、无路由与认证信息，无法评估 allow_url_include、open_basedir、disable_functions 等运行时开关对利用的影响；DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，其实际路径需人工确认。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 uploads 目录的 Web 可执行性未在 code_pack 中，需运行时确认
- 无 php.ini/服务器配置，无法确认上传目录是否禁用脚本执行
- endpoints 为空，045.php 的实际 URL 路由与是否需要认证未确认

## 3. Findings

### F-1: 045.php 不安全文件上传导致任意文件落盘（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 多部分表单上传文件，文件内容进入 PHP 超全局数组 $_FILES['uploaded']（045.php:18 引用的上传字段名为 uploaded）。代码在 045.php:18 直接调用 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)，把客户端提交的临时文件移动到 $target_path 指定的目标路径。输入中给出的片段仅覆盖第 16-18 行，未展示 $target_path 的构造过程，也未展示任何扩展名白名单、MIME 校验、getimagesize() 内容校验、文件重命名或目标目录禁止脚本执行的配置，因此从可见证据看不存在有效净化。校验无效的原因：上传文件名/内容完全由客户端控制，服务端仅做“移动”动作，未对扩展名与内容做约束，攻击者可提交 .php 等可执行扩展名文件。最终危险操作是 move_uploaded_file 将攻击者可控内容写入 Web 可访问目录。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 045.php（POST /045）的不安全文件上传（CWE-434）POC。源码在 045.php:18 附近处理 multipart 上传，表单字段为 `Upload`（提交按钮）与 `uploaded`（文件域），未对上传文件扩展名/类型做有效校验。与 LLM-916b10bd8caa 为同一文件的不同行号定位（18 与 26），路由写作 /045（无 .php 后缀），需按实际部署确认。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/045' \
  -F 'Upload=Upload' \
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

若目标目录位于 Web 根且允许 PHP 解析，攻击者可上传 webshell 并访问对应 URL，实现远程代码执行（RCE），进而读取数据库配置、窃取业务数据、横向移动；即使不可解析，也可造成任意文件落盘、磁盘占满、覆盖既有文件（取决于 $target_path 是否含用户可控文件名）。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 表单字段 uploaded，无需认证即可访问该脚本（片段中未见任何鉴权/session 校验）。利用链闭合：客户端上传 → $_FILES['uploaded']['tmp_name'] → move_uploaded_file 落盘到 $target_path，中间无白名单/内容校验。证据等级为 llm_inferred：$target_path 的赋值与目录可执行性未在给定片段中出现，故 RCE 结论依赖该前提。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并基于服务端解析的真实内容（getimagesize/finfo）校验，不信任 $_FILES['uploaded']['name'] 与 Content-Type；2) 由服务端生成随机文件名，禁止使用客户端文件名拼接 $target_path，防止路径穿越与覆盖；3) 上传目录置于 Web 根之外，或通过 Web 服务器配置禁用该目录的脚本解析（如 php_flag engine off / 禁止 .php 执行）；4) 限制文件大小与数量，设置目录最小权限；5) 上传后做病毒/内容扫描并按需重命名归档。

**验证说明**

静态证据：入口 POST /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 045.php 提交字段 uploaded，携带恶意文件（如 shell.php）。PHP 将临时文件路径写入 $_FILES['uploaded']['tmp_name']。045.php:18 调用 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)，在缺少扩展名/内容校验的情况下把文件移动到 $target_path。攻击者随后请求落盘文件路径触发解析，获得代码执行。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:18，外部输入来自 multipart 文件字段 `uploaded`，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于 code_pack 源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；手工复现时请将 request.http 内容粘贴到授权测试工具，并将 TARGET 替换为授权测试实例地址。上传内容使用无害标记 SUNSET_POC，禁止上传真实 webshell。

### F-2: DVWA 文件上传端点仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-26`
- **来源**：`llm_finding`

**描述**

045.php 在收到 POST 参数 Upload 时，将上传文件保存到 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，文件名取自 $_FILES['uploaded']['name'] 经 basename() 处理。唯一的“图片校验”是 $uploaded_type == "image/jpeg" || "image/png"，而 $uploaded_type 直接来自 $_FILES['uploaded']['type']（第 10 行），该值完全由客户端 multipart 请求的 Content-Type 头决定，攻击者可任意伪造。代码未做扩展名白名单、未做 getimagesize()/finfo 内容检测、未重命名文件、未禁止 .php 扩展名，因此攻击者可上传内容为 PHP 代码、Content-Type 声明为 image/jpeg 的文件（如 shell.php），文件被 move_uploaded_file 落到 Web 可访问的 uploads 目录，随后访问该文件即可执行任意 PHP 代码，形成 RCE。

**source / sink**

- source：upload `uploaded`（045.php:10）
- sink：045.php:26 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 Web 可访问目录（045.php:18）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者提交 multipart 表单，含 Upload 字段与 uploaded 文件 |  |
| 2 | `045.php:6` | 用 basename($_FILES['uploaded']['name']) 拼接目标路径，文件名由攻击者控制，basename 仅去掉目录部分，不限制扩展名 | $target_path = <webroot>/hackable/uploads/shell.php |  |
| 3 | `045.php:10` | 读取客户端声明的 MIME 类型到 $uploaded_type | $uploaded_type = 'image/jpeg'（攻击者伪造） |  |
| 4 | `045.php:14` | 仅比较 $uploaded_type 是否为 image/jpeg 或 image/png，该值来自客户端，可任意伪造 | 校验通过（伪造 Content-Type: image/jpeg） | MIME 类型取自 $_FILES['uploaded']['type']，完全由客户端 multipart 头决定，无服务端内容检测 |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到 uploads 目录，保留 .php 扩展名 | 恶意 PHP 文件落盘为 <webroot>/hackable/uploads/shell.php |  |
| 6 | `045.php:24` | 返回上传成功信息，攻击者随后直接请求该 PHP 文件触发执行 | Web 服务器解析并执行 shell.php |  |

**POC**

针对 045.php（POST /045.php）的不安全文件上传（CWE-434）POC。源码在 045.php:26 附近处理 multipart 上传，表单字段为 `Upload`（提交按钮）与 `uploaded`（文件域），未对上传文件的扩展名/类型做有效校验，攻击者可上传 .jsp 等可执行脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/045.php' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-916b10bd8caa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者无需认证即可在服务器上写入并执行任意 PHP 代码，完全控制 Web 应用与服务器，可读取数据库配置、横向移动。

**CVE / CWE 论证**

CWE-434 无限制文件上传 / CWE-646 依赖不可信文件类型。外部可达（HTTP POST），无需认证，source→sink 链在 045.php 内闭合，MIME 校验可被客户端伪造绕过，落盘后可执行，属 RCE 级别。

**修复建议**

服务端使用 finfo/getimagesize 校验真实文件内容；对扩展名做白名单并强制重命名（如随机名 + 固定图片扩展名）；将上传目录置于 Web 根之外或禁用该目录的脚本执行（php_flag engine off / 移除 handler）；限制文件大小并校验。

**验证说明**

需确认部署环境中 uploads 目录是否允许执行 PHP（Apache/Nginx 配置），以及 DVWA_WEB_PAGE_TO_ROOT 的实际路径与可访问 URL；代码层面链已闭合。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传一个 .php 文件，绕过仅基于客户端 MIME 的校验，随后访问上传后的脚本执行命令。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:26，外部输入来自 multipart 文件字段 `uploaded`，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单、MIME 校验或重命名等有效净化；具备远程触发条件。证据等级：llm_inferred（基于 code_pack 源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请自行将上述 request.http 内容粘贴到授权测试工具中，并将 TARGET 替换为授权测试实例地址。上传内容使用无害标记 SUNSET_POC，禁止上传真实 webshell。

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
| safety_guard | 安全防护 | 3.4 | 是 |
| surface_mapper | 攻击面测绘 | 9.98 | 是 |
| deep_finder | LLM 深挖 | 10.56 | 是 |
| candidate_screener | 候选筛选 | 4.63 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.09 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 10.64 | 是 |
| coordinator | 管线协调 | 7.23 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
