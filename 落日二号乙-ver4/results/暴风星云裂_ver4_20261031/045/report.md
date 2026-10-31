# 落日二号乙漏洞挖掘报告 — 20261031-164708-5569d5

- 生成时间：2026-10-31T08:47:55.906323+00:00
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

本次汇总仅覆盖单文件 PHP 脚本 045.php（33 行），共交付 2 条去重后 finding，全部为 file_upload 类型：GEN-60f80eecf7e1（critical，规则命中，第 18 行附近）与 LLM-916b10bd8caa（high，模型推断，第 26 行附近），两者均带 POC，属 HTTP 型 POC（上传 PHP 脚本落盘）。最高危为 GEN-60f80eecf7e1：不安全文件上传导致任意文件落盘，若上传目录可被 Web 解析则等价于远程代码执行。POC 齐全度为 2/2，但均为静态构造的文本工件，未做动态验证。除 file_upload 外，注入类、路径穿越、配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均未形成 finding，属覆盖缺口而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 045.php（33 行，DVWA upload 模块）。已通读全部 33 行：入口为 POST 参数 Upload 与 $_FILES['uploaded']，危险汇点为 move_uploaded_file 写入 hackable/uploads/。发现一条闭合链：仅用客户端可控的 MIME/size 做校验，可上传 .php 并 RCE（CWE-434）。未发现命令注入、SQL 注入、路径穿越、SSRF、反序列化、弱哈希/弱加密/弱随机、Cookie 标志或信任边界类问题（文件内无 exec/system、无 SQL、无 include、无 md5/rand、无 setcookie）。未闭合/未覆盖：无端点清单、无 Web 服务器配置（是否允许 uploads 执行 PHP）、无 DVWA_WEB_PAGE_TO_ROOT 定义，均影响可利用性确认；code_pack 之外文件视为不存在。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 uploads 目录是否可执行 PHP
- 无 DVWA_WEB_PAGE_TO_ROOT 定义，目标绝对路径未知
- 无端点清单，无法确认 045.php 的实际路由与上游鉴权

## 3. Findings

### F-1: 045.php 不安全文件上传导致任意文件落盘（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（045.php:18 的 `$_FILES['uploaded']['tmp_name']`），代码在 045.php:18 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 将临时文件移动到 `$target_path`。输入片段仅覆盖第 16-18 行，未出现对扩展名、MIME 类型、文件内容或目标路径的任何白名单校验，也未出现 `$target_path` 的构造与规范化代码，因此从可见证据看不存在有效净化，污点从上传字段直达文件落盘汇点。需注意：`$target_path` 的具体取值（是否包含用户可控的文件名、是否固定目录）在给定片段中不可见，属于证据缺口。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /045（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

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

若 `$target_path` 位于 Web 可访问目录且文件名/扩展名可控，攻击者可上传 .php 等可执行脚本，通过访问上传后的 URL 触发远程代码执行，进而读取配置、数据库凭据、篡改站点内容或作为内网跳板；即使不可执行，也可造成任意文件写入/覆盖、磁盘占满与恶意内容托管。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 请求的 multipart 表单字段 `uploaded`，无需认证即可访问该脚本；利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file(..., $target_path)` 直接落盘，可见代码段内无扩展名/类型/路径校验。证据等级为源码推断（llm_inferred），`$target_path` 构造逻辑未在片段中给出，故不宣称已完全验证。

**修复建议**

1) 对上传文件使用扩展名白名单（如仅 jpg/png/pdf）并同时校验服务端 MIME 与文件魔数，不信任客户端 Content-Type；2) 上传文件名由服务端生成（UUID + 白名单扩展名），禁止使用用户提供的文件名拼接路径；3) 使用 `basename()` 与 `realpath()` 规范化并校验目标路径必须落在固定上传目录内，防止路径穿越；4) 上传目录置于 Web 根之外，或通过 Nginx/Apache 配置禁止该目录执行 PHP（如 `php_flag engine off`）；5) 限制文件大小与数量，上传后重命名并设置最小权限（0644、非可执行）；6) 对图片等做二次编码/重采样以剥离潜在脚本载荷。

**验证说明**

静态证据：入口 POST /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 045.php 提交字段名为 `uploaded` 的文件。PHP 将临时文件路径写入 `$_FILES['uploaded']['tmp_name']`；045.php:18 未做任何类型或扩展名校验，直接以 `move_uploaded_file()` 将其移动到 `$target_path`。若目标路径位于 Web 可访问目录且保留攻击者可控的文件名/扩展名，攻击者随后请求该文件即可执行任意 PHP 代码，形成从上传到 RCE 的完整链路。
PocWriter 建议（未采纳，缺少端点 /045）：针对 045.php（第 18 行附近）不安全文件上传的 POC。源码从 multipart 表单字段 `uploaded` 读取上传文件，`Upload` 为提交按钮字段，未对文件类型做有效限制。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434。漏洞位于 045.php:18，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；上传内容保持无害标记，禁止上传真实 webshell。落盘路径需按 045.php:18 源码确认后再调整第 3 步 URL。

### F-2: DVWA 上传端点 045.php 仅校验客户端可控的 MIME 类型，可上传 PHP 脚本并远程执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-26`
- **来源**：`llm_finding`

**描述**

045.php 在收到 POST 参数 Upload 后，把上传文件写入 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，文件名取自 $_FILES['uploaded']['name'] 经 basename() 处理。唯一的“是不是图片”校验使用 $_FILES['uploaded']['type']（即 HTTP 请求中的 Content-Type，完全由客户端控制）与 $_FILES['uploaded']['size']（同样由客户端声明），既没有校验扩展名，也没有用 getimagesize()/finfo 检查真实内容。攻击者只要把 Content-Type 伪造成 image/jpeg 并控制文件大小，就能把任意 .php 文件写入 Web 可访问的 uploads 目录，随后直接请求该文件即可在服务器上执行任意 PHP 代码（RCE）。

**source / sink**

- source：upload `uploaded`（045.php:9-11）
- sink：045.php:26 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 hackable/uploads/ 目录

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者发起 multipart POST，携带 Upload 与 uploaded 文件 |  |
| 2 | `045.php:5-6` | 拼接目标路径为 uploads 目录 + basename(原始文件名)，文件名由攻击者控制，basename 只去掉目录部分，不限制扩展名 | $target_path = <webroot>/hackable/uploads/shell.php |  |
| 3 | `045.php:9-11` | 从 $_FILES 读取 name/type/size，其中 type 与 size 完全来自客户端请求 | $uploaded_type = 'image/jpeg'（伪造），$uploaded_size = 1234（伪造） |  |
| 4 | `045.php:14-15` | 校验仅比较客户端声明的 MIME 与 size，伪造 Content-Type 即可通过，无扩展名白名单、无 getimagesize 内容校验 | 条件为真，进入写入分支 | Content-Type 与 size 均由客户端控制，可任意伪造；未检查文件真实内容与扩展名 |
| 5 | `045.php:18` | move_uploaded_file 把临时文件移动到 Web 可访问的 uploads 目录，保留 .php 扩展名 | 服务器上出现 <webroot>/hackable/uploads/shell.php |  |
| 6 | `045.php:24` | 返回上传成功信息，泄露最终路径，攻击者据此直接访问该脚本触发执行 | 响应包含 <webroot>/hackable/uploads/shell.php succesfully uploaded! |  |

**POC**

针对 /vulnerabilities/upload/ (045.php)（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (045.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (045.php)' \
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

未认证/低权限攻击者可在服务器写入并执行任意 PHP 代码，完全控制 Web 应用与主机（RCE）。

**CVE / CWE 论证**

CWE-434 不受限制的危险文件上传。外部 HTTP 可达，无需认证即可触发，source（$_FILES 客户端字段）到 sink（move_uploaded_file）链路在 CODE PACK 内完整闭合，校验可被 Content-Type 伪造绕过。

**修复建议**

使用服务端内容检测（getimagesize/finfo_file）验证真实图片类型；对文件名做白名单扩展名与随机化重命名；将上传目录置于 Web 根之外或禁止其执行脚本；限制文件大小在服务端校验。

**验证说明**

需确认 uploads 目录可被 Web 访问且允许执行 PHP（DVWA 默认配置下成立）；需确认 DVWA_WEB_PAGE_TO_ROOT 指向的路径可写。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传一个 PHP webshell，再访问上传后的脚本执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 045.php（第 26 行附近）不安全文件上传的 POC。源码从 multipart 表单字段 `uploaded` 读取上传文件，并写入 Web 可访问目录，未对扩展名/内容做有效校验；`Upload` 为表单提交按钮字段。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 045.php:26，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未见扩展名/内容白名单校验，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；上传内容保持无害标记，禁止上传真实 webshell。落盘路径需按 045.php:26 源码确认后再调整第 3 步 URL。

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
| safety_guard | 安全防护 | 3.76 | 是 |
| surface_mapper | 攻击面测绘 | 8.98 | 是 |
| deep_finder | LLM 深挖 | 10.56 | 是 |
| candidate_screener | 候选筛选 | 3.65 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.03 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.07 | 是 |
| coordinator | 管线协调 | 6.39 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
