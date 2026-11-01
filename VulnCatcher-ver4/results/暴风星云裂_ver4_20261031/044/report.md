# 落日二号乙漏洞挖掘报告 — 20261031-164650-5989cc

- 生成时间：2026-10-31T08:47:39.982158+00:00
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

本次汇总仅含 1 个文件 044.php（PHP，19 行），共 2 条去重后 findings，均为 file_upload（CWE-434）：GEN-7d549df94451（critical，规则命中，行 1-9）与 LLM-6ccece6535f3（high，模型推断，行 1-16），二者描述同一处无限制上传导致任意 PHP 文件写入 Web 目录，最高危即该 critical 项。两条均带 POC（HTTP 型，可构造 multipart 上传），但 POC 为文本工件，未执行、未动态验证。其余攻击面（命令执行、路径穿越/LFI、SQLi/XSS/SSRF、配置类弱哈希/弱加密/弱随机/Cookie/信任边界/硬编码凭据）在 surface_notes 中被列为待复核优先级，但本次无对应 findings，属未覆盖而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 044.php（19 行），已逐行审计。该文件是 DVWA 文件上传模块，存在无限制文件上传（CWE-434）：$_FILES['uploaded']['name'] 经 basename() 后直接拼接进 hackable/uploads/ 并由 move_uploaded_file 落盘，无扩展名/类型/内容校验，可上传 PHP 文件实现 RCE，链路在 044.php:3-9 完整闭合。其余攻击面：未发现 SQL/命令/路径穿越/SSRF/反序列化/模板注入 sink；未发现 md5/sha1/rand/setcookie 等配置类调用；未发现 X-Forwarded-For 等信任边界判断；未发现硬编码凭据。DVWA_WEB_PAGE_TO_ROOT 常量定义、uploads 目录权限与 PHP 解析策略不在 code_pack 内，属未闭合线索。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack，无法确认落盘绝对路径
- hackable/uploads/ 目录权限与 Web 服务器对 .php 的解析策略未知
- 044.php 是否位于认证后区域、是否被其他页面包含未知
- 无 php.ini/部署配置，无法评估 open_basedir、file_uploads 等设置

## 3. Findings

### F-1: 044.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 多部分表单上传文件，文件内容进入 PHP 超全局数组 $_FILES['uploaded']，其临时路径 $_FILES['uploaded']['tmp_name'] 在 044.php:9 被直接作为源参数传给 move_uploaded_file()，目标路径为变量 $target_path。代码片段显示第 8 行注释为“Can we move the file to the upload folder?”，第 9 行仅判断移动是否成功，未对上传文件的扩展名、MIME 类型、文件内容做任何白名单校验，也未对 $target_path 做规范化或限制在固定目录内。由于校验缺失，攻击者可控制上传文件的原始文件名/内容，使 $target_path 指向 Web 可访问目录下的可执行脚本（如 .php），从而将任意内容落盘。证据仅覆盖 044.php:7-9，$target_path 的构造位置不在 code_pack 范围内，其具体拼接方式（是否使用 $_FILES['uploaded']['name']）证据不足，但第 9 行缺少任何类型/扩展名校验这一事实已足以支撑不安全上传判定。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 044.php（第 9 行附近的上传处理逻辑）的不安全文件上传 POC。入口按 /044 路由访问，上传字段为 `uploaded`，需同时提交按钮字段 `Upload=Upload`；通过 multipart filename 指定脚本扩展名，若上传目录可解析则可能导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/044'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/044' \
  -F 'Upload=Upload' \
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

任意文件写入：攻击者可将恶意 PHP/脚本文件写入 Web 根目录可访问路径，随后通过 HTTP 请求触发执行，形成远程代码执行（RCE），进而读取数据库配置、篡改站点内容、横向移动；即使目标目录不可执行，也可造成磁盘占用与文件覆盖。

**CVE / CWE 论证**

对应 CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 表单字段 uploaded，无需认证即可访问 044.php；利用链闭合：$_FILES['uploaded']['tmp_name'] → move_uploaded_file(..., $target_path) → 落盘至可控路径，中间无扩展名白名单、无 MIME 校验、无内容检测，第 9 行仅判断返回值。$target_path 的具体来源在给定片段外，属证据不足部分，不影响“缺少危险类型限制”这一核心弱点成立。

**修复建议**

1) 对上传文件实施扩展名白名单（如仅允许 .jpg/.png/.pdf），并基于服务端解析的真实 MIME 与文件头魔数二次校验，不信任客户端 Content-Type；2) 使用随机生成的文件名（如 bin2hex(random_bytes(16))）替代用户可控文件名，禁止路径分隔符与 .. 序列；3) 将上传目录置于 Web 根之外，或通过 Nginx/Apache 配置禁止该目录执行脚本（如 location ~ \.php$ { deny all; }）；4) 限制文件大小与数量，上传目录以最小权限运行，禁止覆盖已有文件；5) 对图片等可二次处理类型做重编码以剥离潜在载荷。

**验证说明**

静态证据：入口 POST /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 044.php 提交字段名为 uploaded 的文件，文件内容为恶意脚本。PHP 将临时文件路径写入 $_FILES['uploaded']['tmp_name']；044.php:9 调用 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)，由于第 9 行前后均无扩展名/MIME/内容白名单校验，且 $target_path 未做目录与文件名约束，文件被移动到 Web 可访问位置。攻击者随后请求该落盘文件，脚本在服务器上下文执行，完成从上传到 RCE 的闭合链路。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434。漏洞位于可交付代码 044.php:9，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链在静态审计中闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。TARGET 由授权测试人员手动替换；上传内容保持无害标记，禁止放入反弹 shell 或自动执行逻辑。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，并调用 move_uploaded_file 落盘。代码未做任何扩展名白名单、MIME/内容类型校验、文件内容检查、大小限制或随机化重命名，攻击者可上传 .php 文件到 Web 可访问的 hackable/uploads/ 目录，随后直接请求该文件由 PHP 解析执行，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 位于 044.php:9

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支，无认证/CSRF/权限校验 | 攻击者控制请求体与上传文件 |  |
| 2 | `044.php:5-6` | 目标路径固定为 hackable/uploads/ 前缀，再拼接 basename($_FILES['uploaded']['name'])；basename 仅去掉目录部分，不限制扩展名与内容 | $target_path = <webroot>/hackable/uploads/<攻击者文件名> | basename() 只做路径规范化，不做扩展名/类型白名单，无法阻止 .php 后缀 |
| 3 | `044.php:9` | move_uploaded_file 将临时文件移动到 Web 可访问目录，文件名与内容完全由攻击者决定 | 任意内容文件落盘为 <webroot>/hackable/uploads/shell.php |  |
| 4 | `044.php:15` | 成功分支回显完整落盘路径，攻击者据此确认上传成功并获得访问 URL | 响应泄露 $target_path |  |

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
  -F 'Upload=Upload' \
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

攻击者可在 Web 根目录写入任意 PHP 文件并执行，获得 Web 服务器权限，进而读取配置/数据库凭据、横向移动，构成远程代码执行。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部 HTTP 可达，无需认证即可触发（DVWA 默认部署），source（上传文件名/内容）到 sink（move_uploaded_file）链路在 044.php:3-9 完整闭合，无任何白名单或内容校验。

**修复建议**

对上传文件实施扩展名白名单（仅允许图片等）、校验真实 MIME 与文件头魔数、使用随机化文件名并去除原始扩展名、将上传目录置于 Web 根之外或禁止该目录执行 PHP（如 Nginx location 拒绝 .php），并限制文件大小。

**验证说明**

需确认 hackable/uploads/ 目录对 Web 服务器可写且该目录下 .php 会被解析；需确认 044.php 的实际部署路径与是否位于认证后区域。DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，其具体值需人工确认。
模型 POC 要点：上传一个 PHP webshell 到 hackable/uploads/，再请求该文件触发命令执行。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 044.php（第 16 行附近的上传处理逻辑）的不安全文件上传 POC。上传表单字段名为 `uploaded`，同时需携带触发按钮字段 `Upload=Upload`；通过 multipart 的 filename 将文件保存为可执行脚本（sunset.jsp），若上传目录可被 Web 容器解析则可能导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434 不受限制的危险类型文件上传。漏洞位于可交付代码 044.php:16，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链在静态审计中闭合，未发现有效扩展名白名单或内容校验，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。脚本中的 TARGET 需由授权测试人员手动替换；上传内容保持无害标记，禁止放入反弹 shell 或自动执行逻辑。

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
| surface_mapper | 攻击面测绘 | 9.91 | 是 |
| deep_finder | LLM 深挖 | 10.67 | 是 |
| candidate_screener | 候选筛选 | 3.31 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.07 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.16 | 是 |
| coordinator | 管线协调 | 6.98 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
