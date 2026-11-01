# 落日二号乙漏洞挖掘报告 — 20261031-214846-f2dbac

- 生成时间：2026-10-31T13:49:41.093166+00:00
- 输入：`$WORKSPACE\暴风星云裂\043.zip`
- 输入模式：`zip`
- SHA256：`07af6f04e9411f0557b345faaf32fcbb3e1405cb4402c57b6fc79a4bf804244f`
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

本次汇总仅包含 1 个源码文件 043.php（35 行，单文件 PHP 脚本，无框架/路由/端点清单）。去重后共 2 条 findings，均为 file_upload 类型：规则命中 GEN-729d053acdfd（critical，043.php 第 20 行，任意文件写入 CWE-434）与 LLM 推断 LLM-24bb446ce5ae（high，043.php 第 26 行，仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片写入 web 可访问目录导致 RCE）。最高危为 GEN-729d053acdfd（critical，任意文件写入）。两条 finding 均标记 has_poc=true，POC 文本齐全，但均为静态源码证据推导，未做动态验证；且输入未提供 043.php 实际代码内容，行号与变量细节需人工比对源码确认。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 CODE PACK 中唯一文件 043.php（35 行，DVWA 文件上传模块）。该文件接收 $_FILES['uploaded']，经扩展名白名单（jpg/jpeg/png）、大小 <100000、getimagesize 三项校验后，用 move_uploaded_file 写入 web 根下 hackable/uploads/ 目录，文件名保留客户端 basename。校验只验证图像头与后缀，不检查内容、不重命名、不限制目录解析，可被 PNG/JPEG polyglot 绕过，形成上传导致 RCE 的闭合链，已作为 high 级 file_upload 报告。未发现 SQL 注入、命令注入、反序列化、SSRF、路径穿越、弱哈希/弱加密/弱随机、不安全 Cookie、硬编码密钥等其它线索：文件内无数据库查询、无 system/exec、无 unserialize/eval、无 setcookie/session 配置、无 rand/md5、无硬编码凭据。surface_notes 中列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 六项 medium_review_items 在代码中均无对应实现，故不报告。未覆盖范围：无 Web 服务器配置、php.ini、.htaccess、composer 依赖信息，无法评估 uploads 目录解析策略与 PHP 版本等环境放大因素；DVWA_WEB_PAGE_TO_ROOT 常量定义不在 CODE PACK 内，其具体路径依赖部署。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 hackable/uploads/ 实际路径不在 CODE PACK 内
- Web 服务器对 uploads 目录的 PHP 解析策略未知，影响 RCE 是否成立
- 无 php.ini/.htaccess/composer.json 等部署与依赖配置，无法评估环境放大因素

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（043.php:12 读取上传内容，临时文件路径进入 `$uploaded_tmp`）。代码随后在 043.php:20 调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将上传文件移动到 `$target_path`。从给出的片段看，在 043.php:12 到 043.php:20 之间没有出现扩展名白名单、MIME 校验、文件内容检查或目标文件名规范化等有效净化逻辑，因此上传文件的类型与落盘名称未受约束，攻击者可控制写入 Web 目录的文件。证据仅覆盖 043.php:12 与 043.php:18-20 片段，`$target_path` 的具体构造代码未在输入中给出，其是否完全由用户控制属推断。

**source / sink**

- source：upload `uploaded`（043.php:12）
- sink：043.php:20 if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:12` | 从 upload `uploaded` 读取外部输入 | 污点进入 uploaded_tmp |  |
| 2 | `043.php:20` | 危险汇点：if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /043（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

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

若 `$target_path` 位于 Web 可访问目录且扩展名可控，攻击者可上传 .php 等可执行脚本，通过访问上传后的 URL 触发任意 PHP 代码执行，进而读取/篡改服务器文件、窃取数据库凭据、横向移动；即使不可执行，也可造成任意文件覆盖写入（覆盖配置、模板、其他用户文件），导致数据完整性破坏或拒绝服务。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP multipart 请求的 `uploaded` 字段，无需认证即可访问该脚本（片段中未见任何鉴权/会话校验）。利用链闭合：外部输入 `uploaded` → `$uploaded_tmp`（043.php:12）→ `move_uploaded_file($uploaded_tmp, $target_path)`（043.php:20）→ 文件落盘至目标路径，中间无类型/扩展名/路径校验。证据等级为 llm_inferred：`$target_path` 的赋值与目录可执行性未在输入片段中出现，需以实际部署配置确认。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端解析的真实 MIME 与文件头校验，不信任客户端 Content-Type 与文件名；2) 目标文件名由服务端生成（UUID/哈希 + 白名单扩展名），禁止使用用户提供的文件名拼接路径；3) 对 `$target_path` 做规范化（realpath）并校验其位于预设上传目录内，防止路径穿越；4) 上传目录置于 Web 根之外，或关闭该目录的脚本执行权限（如 Nginx `location ~ \.php$ { deny all; }`）；5) 上传接口增加认证与 CSRF 防护，限制文件大小与数量。

**验证说明**

静态证据：入口 POST /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 043.php 的 `uploaded` 字段提交名为 shell.php 的恶意脚本。043.php:12 读取上传内容并将临时路径存入 `$uploaded_tmp`；代码未对扩展名或内容做任何校验，直接进入 043.php:20 的 `move_uploaded_file( $uploaded_tmp, $target_path )`，把文件写入 Web 可访问目录。攻击者随后请求该文件 URL，PHP 代码在服务器上执行，获得命令执行能力。
PocWriter 建议（未采纳，缺少端点 /043）：针对 043.php:20 的不安全文件上传（CWE-434）POC。上传处理逻辑位于 043.php:20，表单字段为 `Upload`（按钮）与 `uploaded`（文件域），服务端未有效限制上传类型，可上传 .jsp 脚本。目标地址使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434。漏洞位于 043.php:20，外部输入来自 multipart 文件域 `uploaded`，在给定代码范围内 source→sink 链闭合，未见有效净化。
POC 备注：仅文本工件，不执行、不联网。curl 需人工替换 TARGET 后手动运行；上传内容为标记字符串，不含命令执行代码。

### F-2: DVWA 文件上传端点（043.php）仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录导致 RCE

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`043.php:5-26`
- **来源**：`llm_finding`

**描述**

043.php 在收到 POST 参数 Upload 时，从 $_FILES['uploaded'] 读取文件名、扩展名、大小与临时文件。校验逻辑为：扩展名（strrpos 取最后一个点之后的部分，strtolower 后）必须为 jpg/jpeg/png，大小 < 100000 字节，且 getimagesize() 返回真。校验通过后调用 move_uploaded_file() 将临时文件移动到 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，文件名使用 basename($_FILES['uploaded']['name'])。该目录位于 web 根下且可被 HTTP 直接访问。校验只检查文件头是否为合法图片（getimagesize 只解析图像头），不检查文件内容中是否夹带 PHP 代码，也不重命名文件、不限制上传目录执行权限。攻击者可构造一个合法 PNG/JPEG 文件头 + 尾部嵌入 PHP 代码的多语言文件（polyglot），扩展名保持 .png/.jpg 通过校验，上传后通过 HTTP 访问该文件，若服务器对 uploads 目录未禁用 PHP 解析，则嵌入的 PHP 代码被执行，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（043.php:9-12）
- sink：043.php:26 move_uploaded_file($uploaded_tmp, $target_path) 写入 web 可访问的 hackable/uploads/ 目录（043.php:20）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 入口判断 isset($_POST['Upload'])，攻击者提交 Upload 参数即进入上传处理分支 | 外部请求进入上传逻辑 |  |
| 2 | `043.php:9-12` | 从 $_FILES['uploaded'] 读取文件名、扩展名、大小、临时路径，全部由客户端控制 | 攻击者可控的文件名与文件内容 |  |
| 3 | `043.php:15-17` | 校验扩展名为 jpg/jpeg/png、大小 <100000、getimagesize 通过；getimagesize 只解析图像头，不检查尾部内容，可被 polyglot 文件绕过 | 合法图片头 + 尾部 PHP 代码，扩展名 .png | getimagesize 仅验证文件头为合法图像，不检测嵌入的 PHP 代码；扩展名白名单只限制后缀，不限制内容 |
| 4 | `043.php:20` | move_uploaded_file 将文件移动到 web 根下 hackable/uploads/，文件名保留攻击者提供的 basename | 恶意文件落盘到 web 可访问目录 |  |
| 5 | `043.php:26` | 返回上传成功并回显目标路径，攻击者据此构造访问 URL 触发执行 | 获得上传文件的可访问路径 |  |

**POC**

针对 /vulnerabilities/upload/（043.php 直接访问）（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/（043.php 直接访问）'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/（043.php 直接访问）' \
  -F 'Upload=Upload' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-24bb446ce5ae`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在服务器上写入并执行任意 PHP 代码，获得 web 进程权限，读取敏感文件、横向移动，形成远程代码执行。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部无需认证即可通过 HTTP 上传，校验仅基于扩展名与图像头，可被 polyglot 绕过，链闭合至 move_uploaded_file 写入 web 可访问目录。

**修复建议**

上传后重命名文件为随机名并强制安全扩展名；将上传目录移出 web 根或禁用该目录的脚本解析；对文件内容做真实图像重编码（如 GD/Imagick 重新生成图像）剥离嵌入代码；校验 MIME 与文件内容一致性；限制上传目录权限。

**验证说明**

需确认部署环境中 hackable/uploads/ 目录是否允许 PHP 解析（DVWA 默认通常允许）；需确认 getimagesize 对构造的 polyglot 文件确实返回真。若 uploads 目录禁用脚本解析，则降级为任意文件上传/存储型风险。
模型 POC 要点：构造一个以合法 PNG 头开头、尾部嵌入 PHP 代码的多语言文件，扩展名 .png，通过 multipart 上传；上传成功后访问该文件触发 PHP 执行。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Unrestricted File Upload @ http://127.0.0.1:18081/043.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/（043.php）：针对 043.php:26 的不安全文件上传（CWE-434）POC。源码中上传表单字段名为 `Upload`（提交按钮）与 `uploaded`（文件域），服务端未对扩展名/内容做有效校验即落盘，攻击者可上传 .jsp 等可执行脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/（043.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 043.php:26，外部输入来自 multipart 文件域 `uploaded`，source→sink 链在给定代码范围内静态闭合，未见扩展名白名单或内容校验。
POC 备注：仅文本工件，不执行、不联网。curl 示例需人工替换 TARGET 后手动运行；上传内容仅为标记字符串，不含任何命令执行代码。端点路径中的中文说明需按实际部署替换。

**外部佐证**

- awvs: Unrestricted File Upload @ http://127.0.0.1:18081/043.php

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `LLM-24bb446ce5ae` | Unrestricted File Upload | http://127.0.0.1:18081/043.php | corroborated |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.57 | 是 |
| surface_mapper | 攻击面测绘 | 7.94 | 是 |
| deep_finder | LLM 深挖 | 13.59 | 是 |
| candidate_screener | 候选筛选 | 5.08 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.05 | 是 |
| coordinator | 管线协调 | 7.2 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
