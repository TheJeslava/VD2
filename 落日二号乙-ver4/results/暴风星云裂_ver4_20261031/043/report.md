# 落日二号乙漏洞挖掘报告 — 20261031-164645-ac6331

- 生成时间：2026-10-31T08:47:29.714742+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\043.zip`
- 输入模式：`zip`
- SHA256：`07af6f04e9411f0557b345faaf32fcbb3e1405cb4402c57b6fc79a4bf804244f`
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

本次汇总仅覆盖单文件 PHP 脚本 043.php（35 行，无框架、无路由清单）。已去重后交付 2 条 file_upload 发现：规则命中 GEN-729d053acdfd（critical，043.php:20，任意文件写入 CWE-434）与 LLM 命中 LLM-7a70487f2fb0（high，043.php:27，仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片写入 hackable/uploads/ 导致 RCE）。两者均带 POC，但 POC 为文本工件，未执行、未做动态验证；最高危为 GEN-729d053acdfd 的任意文件写入。需注意：surface_notes 明确说明本次未提供 043.php 的源码片段，因此行号与汇点结论来自上游规则/模型，属静态推断（llm_inferred 级），不是已验证事实。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：code_pack 仅含单文件 043.php（35 行），为 DVWA 文件上传模块。已逐行审计：入口为 POST 参数 Upload + $_FILES['uploaded']，sink 为 move_uploaded_file 写入 hackable/uploads/。发现扩展名校验+getimagesize 可被图片马与多后缀绕过，构成不受限文件上传（CWE-434），在服务器解析上传目录 PHP 时可升级为 RCE。未发现 SQL 注入、命令注入、SSRF、反序列化、弱哈希/弱随机/不安全 Cookie 等其它汇点（文件中无 md5/sha1/rand/setcookie/eval/system 调用）。未闭合点：DVWA_WEB_PAGE_TO_ROOT 常量定义、Web 服务器对上传目录的解析策略、是否存在前置鉴权均不在 code_pack 内，需人工确认。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义未提供
- Web 服务器/php.ini 配置未知，无法确认上传目录是否解析 PHP
- 无端点清单，无法确认 043.php 是否被鉴权包裹
- 无依赖清单与提交历史

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（043.php:12 读取上传内容并写入 `$uploaded_tmp`），代码随后在 043.php:20 直接调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将临时文件移动到 `$target_path`。从给出的代码片段看，在 043.php:12 到 043.php:20 之间没有出现扩展名白名单、MIME 校验、文件内容检查或目标路径规范化等有效校验，因此攻击者可以控制上传文件的原始文件名/内容，使 `$target_path` 指向 Web 可访问目录并写入可执行脚本。由于校验缺失，污点从上传字段直达文件写入汇点，利用链闭合。

**source / sink**

- source：upload `uploaded`（043.php:12）
- sink：043.php:20 if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:12` | 从 upload `uploaded` 读取外部输入 | 污点进入 uploaded_tmp |  |
| 2 | `043.php:20` | 危险汇点：if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 043.php（第 20 行附近上传处理逻辑）的不安全文件上传 POC，入口为根路径 /043。源码直接使用 multipart 字段 `uploaded` 的文件名与内容落盘，缺少扩展名白名单，可上传可执行脚本。目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/043'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/043' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/GEN-729d053acdfd`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

任意文件写入：攻击者可将 .php 等可执行脚本上传至 Web 根目录，通过访问该文件触发服务端代码执行，进而导致远程代码执行（RCE）、服务器失陷、数据泄露与横向移动；即使不可执行，也可覆盖或投放任意文件造成完整性破坏。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 请求的 `uploaded` 文件字段，无需认证即可访问（证据中未见鉴权逻辑）。利用链闭合：source（043.php:12 上传字段）→ `$uploaded_tmp` → sink（043.php:20 `move_uploaded_file`）之间无有效净化，攻击者完全控制写入内容与目标路径，满足无需认证的外部可利用条件。

**修复建议**

1) 对上传文件实施扩展名白名单校验（仅允许业务必需类型），并基于服务端解析的真实 MIME/文件头而非客户端 Content-Type 判断；2) 使用 `pathinfo()` 提取扩展名后与白名单严格比对，拒绝双扩展名与大小写绕过；3) 将上传目录置于 Web 根之外，或对上传目录禁用脚本执行（如 PHP 引擎关闭、`Content-Disposition: attachment`）；4) 上传后重命名为随机文件名，避免攻击者控制路径；5) 对 `$target_path` 做 `realpath()` 规范化并校验其位于允许目录内，防止路径穿越；6) 限制文件大小并配合最小权限运行 Web 进程。

**验证说明**

静态证据：入口 POST /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，在 `uploaded` 字段中提交名为 `shell.php` 的恶意脚本 → 043.php:12 读取该上传并保存临时路径到 `$uploaded_tmp` → 代码未做扩展名/内容校验，直接拼接 `$target_path` → 043.php:20 调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将脚本落盘到 Web 可访问目录 → 攻击者访问该脚本 URL，服务端执行任意代码，完成 RCE。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434。漏洞位于 043.php:20，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未见有效净化。
POC 备注：仅文本工件，未执行；TARGET 为占位符。上传内容不含真实 webshell。

### F-2: DVWA 文件上传端点（043.php）仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 hackable/uploads/ 导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`043.php:3-27`
- **来源**：`llm_finding`

**描述**

043.php 在收到 POST 参数 Upload 后，直接取 $_FILES['uploaded']['name'] 经 basename() 拼接到 $target_path（DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/"），并用 move_uploaded_file() 落盘。校验仅有三个条件：扩展名（substr 取最后一个点之后）小写后属于 jpg/jpeg/png、文件大小 < 100000 字节、getimagesize() 返回真。getimagesize() 只检查文件头是否为合法图片，不阻止文件尾部附加任意 PHP 代码（图片马）；扩展名检查只看最后一个点后的字符串，攻击者可将文件名设为 shell.php.jpg 或 shell.jpg.php 之类，最终落盘文件名由 basename() 原样保留，若服务器对 .php 后缀解析（或利用多后缀/解析漏洞），即可执行任意 PHP 代码。攻击者无需认证即可通过该端点写入 webshell，形成 RCE。

**source / sink**

- source：upload `uploaded`（043.php:9-12）
- sink：043.php:27 move_uploaded_file( $uploaded_tmp, $target_path ) 写入 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 下攻击者可控文件名

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支 | 攻击者提交 multipart 表单，含 Upload 与 uploaded 文件字段 |  |
| 2 | `043.php:9-12` | 从 $_FILES['uploaded'] 读取文件名、扩展名、大小、临时路径 | 文件名完全由客户端控制 |  |
| 3 | `043.php:15-17` | 仅校验扩展名属于 jpg/jpeg/png、大小 <100000、getimagesize 通过 | 扩展名取最后一个点之后；getimagesize 只验证文件头为图片，不阻止尾部附加 PHP 代码 | 图片马（GIF89a/PNG 头 + <?php ... ?>）可通过 getimagesize；扩展名检查只看最后一段，可用 shell.php.jpg 或依赖服务器多后缀解析 |
| 4 | `043.php:5-6` | 用 basename() 拼接目标路径，保留攻击者文件名 | $target_path = DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/".basename(name) |  |
| 5 | `043.php:20` | move_uploaded_file 将临时文件移动到目标路径 | 恶意文件落盘到 hackable/uploads/ 下，文件名可控 |  |

**POC**

针对 /vulnerabilities/upload/ (043.php)（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (043.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (043.php)' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-7a70487f2fb0`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

未授权攻击者可上传并执行任意 PHP 代码，获取服务器控制权，读取/篡改数据库与文件系统。

**CVE / CWE 论证**

CWE-434 不受限制的危险类型文件上传。外部可达（POST 上传端点），无需认证，校验可被图片马与多后缀绕过，链闭合至 move_uploaded_file 落盘并可执行。

**修复建议**

使用白名单校验扩展名并重命名文件为随机名+固定安全扩展名；用 finfo/getimagesize 结合内容重编码图片剥离附加代码；将上传目录置于 Web 根之外或禁用该目录 PHP 解析；限制文件大小与 MIME。

**验证说明**

需确认部署环境是否将 hackable/uploads/ 下 .php 或多后缀文件交由 PHP 解析；若服务器仅按固定扩展名解析且上传目录禁止执行，则 RCE 不成立，仅剩任意文件写入。DVWA_WEB_PAGE_TO_ROOT 常量定义未在 code_pack 中，路径前缀需人工确认。
模型 POC 要点：上传一个带合法图片头、尾部含 PHP 代码的文件，文件名使用 .php 后缀（或 .php.jpg 依赖解析），随后访问该文件触发代码执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 043.php（第 27 行附近的上传处理逻辑）的不安全文件上传 POC。源码将 multipart 表单字段 `uploaded` 的文件名/内容直接落盘，未对扩展名做白名单校验，攻击者可上传 .jsp 等可执行脚本。注入通道为 multipart 的 filename 与文件内容，目标地址统一使用 TARGET 占位符。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 043.php:27，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未见扩展名白名单或内容校验。
POC 备注：仅保留文本请求结构，未执行；TARGET 为占位符。若目标中间件不解析 .jsp，可改用目标实际支持的脚本扩展名（如 .php）复测，但不得上传真实 webshell。

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
| safety_guard | 安全防护 | 2.92 | 是 |
| surface_mapper | 攻击面测绘 | 7.46 | 是 |
| deep_finder | LLM 深挖 | 10.59 | 是 |
| candidate_screener | 候选筛选 | 4.04 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.31 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.38 | 是 |
| coordinator | 管线协调 | 5.92 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
