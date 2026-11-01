# 落日二号乙漏洞挖掘报告 — 20261031-173229-3e0aec

- 生成时间：2026-10-31T09:33:13.629709+00:00
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

本次汇总仅含 1 个文件（044.php，19 行 PHP 脚本）的 2 条已去重发现，全部为 file_upload 类型：GEN-7d549df94451（critical，规则命中，上传文件被直接移动到目标路径、缺少类型/扩展名校验，CWE-434）与 LLM-6ccece6535f3（high，模型推断，无限制上传导致任意 PHP 写入 Web 目录进而 RCE）。两者均标注 has_poc=true，但 POC 为静态文本工件，未执行、未做动态验证，不能宣称可动态复现。最高危为 GEN-7d549df94451（critical）。POC 覆盖率为 2/2，但覆盖面极窄：仅 1 个文件、0 个端点、无框架信息，注入类、路径穿越、配置类攻击面均无 findings 落地。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 044.php（19 行）。审计确认其为 DVWA 文件上传模块：POST 参数 Upload 触发，$_FILES['uploaded']['name'] 经 basename() 拼接后由 move_uploaded_file 落盘到 hackable/uploads/，无扩展名/类型/内容校验，构成任意文件上传→RCE，链在 044.php:3-16 闭合。未发现 SQL/命令/路径穿越/反序列化等其它汇点；weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary 等配置类线索在代码中均无对应实现（无 md5/rand/setcookie/加密/HTTP_X_FORWARDED_FOR 使用），故不单独立项。未覆盖范围：无 php.ini、部署路径、认证前置与 WAF 信息，endpoints 为空，无法确认实际路由与是否需要登录。

未覆盖 / 证据缺口：
- 缺少 php.ini/Web 服务器配置，无法确认上传目录是否可执行 PHP
- 缺少认证/部署信息，无法确认是否需登录及 044.php 对外暴露路径
- endpoints 为空，HTTP 方法与路由为推断
- 无 composer.json，未评估第三方组件

## 3. Findings

### F-1: 044.php 不安全文件上传（CWE-434）：上传文件被直接移动到目标路径，缺少类型/扩展名校验

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 044.php 提交 multipart 表单，文件字段名为 `uploaded`。脚本在 044.php:9 直接调用 `move_uploaded_file( $_FILES['uploaded']['tmp_name'], $target_path )`，把 PHP 临时文件移动到 `$target_path` 指定的位置。输入来源是 `$_FILES['uploaded']`（文件名、临时路径、内容均由客户端控制），中间没有经过任何扩展名白名单、MIME 校验、`getimagesize()` 内容校验或文件名规范化；`$target_path` 在给出的片段（044.php:7-9）中未展示其构造过程，因此无法确认其是否包含上传目录前缀或是否由用户可控文件名拼接，这一点属于证据不足。由于缺少对上传内容与扩展名的校验，攻击者可以上传 `.php` 等可执行脚本，若目标目录位于 Web 可访问路径且服务器允许执行该扩展名，则文件落地后即可被请求执行。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 044.php（POST /044）的不安全文件上传（CWE-434），与 LLM-6ccece6535f3 为同一文件不同行号定位（044.php:9）。源码在 044.php:9 附近接收 multipart 上传字段 uploaded，未对文件名/类型做充分校验即处理，攻击者可上传 .jsp 等可执行文件，若落盘目录可被解析则导致 RCE。POC 仅使用 TARGET 占位符，仅限授权测试。

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

若上传目录可被 Web 访问且允许脚本执行，攻击者可上传 PHP 等可执行文件并获得远程代码执行（RCE），进而读取/篡改服务器文件、窃取数据库凭据、以内网身份横向移动；即使不可执行，也可造成任意文件写入、磁盘占满、托管恶意内容（钓鱼/恶意软件分发）等后果。

**CVE / CWE 论证**

对应 CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：044.php 为 Web 端点，上传字段 `uploaded` 由任意未认证 HTTP 客户端提交，无需登录或特权；利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file()` → `$target_path`，中间无白名单/内容校验，属于典型的“客户端可控文件直接落盘”。注意：`$target_path` 的构造在给定片段中不可见，若其被限制在不可执行目录或做了扩展名重写，实际可利用性会下降，故本条为基于源码的推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并同时校验 MIME 与文件头（`finfo_file`/`getimagesize`），拒绝双扩展名与 `.php`、`.phtml`、`.phar` 等；2) 不要使用客户端提供的文件名，改为服务端生成随机文件名（如 `bin2hex(random_bytes(16))` + 白名单后缀），并对 `$target_path` 做 `realpath()` 规范化后校验其位于预期上传目录内；3) 将上传目录置于 Web 根之外，或通过 Web 服务器配置禁用该目录的脚本执行（如 Nginx `location ~ \.php$ { deny all; }`）；4) 限制文件大小与数量，上传目录以最小权限运行，禁止执行位；5) 对上传文件做病毒/内容扫描并按需重编码图片。

**验证说明**

静态证据：入口 POST /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，文件字段名 `uploaded`，内容为恶意脚本（如 shell.php）。请求到达 044.php 后，PHP 将文件写入临时目录并填充 `$_FILES['uploaded']['tmp_name']`；044.php:9 未做任何扩展名/内容校验，直接 `move_uploaded_file()` 到 `$target_path`。文件落地后，攻击者访问对应 URL 触发脚本执行，完成从“上传”到“代码执行”的链路。校验无效的原因是该行只有移动动作，没有任何类型判断或路径约束。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434。漏洞位于可交付代码 044.php:9，外部输入来自 multipart 字段 uploaded 的 filename/内容，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；上传内容保持无害标记，禁止写入反弹 shell 或破坏性载荷。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接把 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，并调用 move_uploaded_file() 落盘。代码未校验扩展名、MIME、文件内容，也未做白名单或重命名，攻击者可上传 .php 文件到 Web 可访问目录，随后直接请求该文件即可在服务器执行任意 PHP 代码，形成远程代码执行。basename() 仅剥离路径部分，不限制扩展名，无法阻止 webshell 上传。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制 multipart 请求体 |  |
| 2 | `044.php:6` | 用 basename() 取上传文件名并拼接到上传目录，仅剥离路径，不校验扩展名/类型 | $target_path = <webroot>/hackable/uploads/shell.php | basename() 只处理路径分隔符，不构成扩展名白名单 |
| 3 | `044.php:9` | move_uploaded_file 将临时文件移动到 Web 可访问目录，无任何内容/类型校验 | 恶意 PHP 文件落盘到 Web 根下可访问路径 |  |
| 4 | `044.php:15` | 响应回显完整落盘路径，攻击者据此定位 webshell URL | 泄露绝对/相对上传路径 |  |

**POC**

针对 044.php（POST /044.php）的不安全文件上传（CWE-434）。源码在 044.php:16 附近处理 multipart 上传，外部可控的 multipart 文件名/内容（表单字段 uploaded）未经充分校验即落盘，攻击者可上传 .jsp 等可执行脚本，若上传目录可被 Web 容器解析则导致远程代码执行。POC 仅使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/044.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/044.php' \
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

攻击者可在服务器写入并执行任意 PHP 代码，完全控制 Web 应用与主机（RCE）。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部可直接 POST 触发，无需认证（取决于部署），source→sink 链在 044.php:3-9 完整闭合，落盘路径可由响应回显确认。

**修复建议**

使用扩展名白名单（仅允许图片等）、校验 MIME 与文件魔数、随机重命名文件、将上传目录置于 Web 根之外或禁用该目录 PHP 执行（如 php_flag engine off / location 拒绝 .php）。

**验证说明**

需确认 044.php 是否需登录（DVWA 通常需认证）、hackable/uploads/ 是否允许 PHP 执行、DVWA_WEB_PAGE_TO_ROOT 的实际路径与 Web 可达性。
模型 POC 要点：上传一个 PHP webshell 到 hackable/uploads/，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /044.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 044.php:16，外部输入来自 multipart 字段 uploaded 的 filename/内容，source→sink 链静态闭合，未见有效扩展名/类型/路径净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权目标；上传内容保持无害标记，禁止写入反弹 shell 或破坏性载荷。

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
| safety_guard | 安全防护 | 3.34 | 是 |
| surface_mapper | 攻击面测绘 | 8.65 | 是 |
| deep_finder | LLM 深挖 | 8.02 | 是 |
| candidate_screener | 候选筛选 | 3.39 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.06 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.04 | 是 |
| coordinator | 管线协调 | 5.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
