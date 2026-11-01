# 落日二号乙漏洞挖掘报告 — 20261031-010437-c6355a

- 生成时间：2026-10-30T17:05:21.710256+00:00
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

本次汇总基于已去重 findings：仅 1 个文件 045.php（33 行），共 2 条 file_upload 发现，均带 POC。最高危为 GEN-60f80eecf7e1（critical，045.php 第 18 行附近，未校验扩展名/类型即 move_uploaded_file 落盘，CWE-434）；LLM-916b10bd8caa（high，045.php 第 26 行附近，仅校验客户端可控 MIME，可上传 PHP 脚本导致 RCE）与其同源同文件，属同一上传端点的不同证据视角，需人工确认是否为同一代码路径的重复计数。两条 POC 均为 HTTP 型（上传请求 + 恶意文件），但均未动态验证，仅为静态/规则推断证据。除此之外，注入类、配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）均无 findings 交付，属未覆盖而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入 045.php（33 行）一个文件，已通读全文件。该文件是 DVWA 的 File Upload 关卡：入口为 POST 参数 Upload，上传字段 uploaded 的文件名、MIME 类型、大小全部来自客户端，唯一校验是 $_FILES['uploaded']['type'] 与 size，均可伪造，随后 move_uploaded_file 写入 Web 可访问的 hackable/uploads/ 目录，构成可闭合的任意文件上传→RCE 链。未发现 SQL/命令/反序列化/SSRF/路径穿越等其它汇点；文件中无弱哈希、弱加密、弱随机、硬编码密钥或 cookie 设置，故未报告配置类问题。未覆盖范围：无 composer.json、Web 服务器配置、.env，无法确认部署方式、DVWA_WEB_PAGE_TO_ROOT 取值及 uploads 目录是否禁止脚本执行；这些属于运行时条件，已写入 verification_notes。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 中，无法确认上传目录绝对路径
- 无 Web 服务器配置，无法确认 uploads 目录是否允许 PHP 解析
- 无认证/会话代码，无法确认该端点是否被上层鉴权保护

## 3. Findings

### F-1: 045.php 不安全文件上传：未校验扩展名/类型即 move_uploaded_file 落盘（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 多部分表单上传文件，文件字段名为 `uploaded`（045.php:18 的 `$_FILES['uploaded']['tmp_name']`）。脚本把上传临时文件直接交给 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)`（045.php:18）写入 `$target_path` 指向的上传目录。在给出的代码片段（045.php:16-18）中，落盘前没有任何扩展名白名单、MIME/魔数校验、文件重命名或大小限制，`$target_path` 的构造逻辑位于片段之外（证据不足，无法确认是否含用户可控文件名），因此校验环节缺失，污点从上传字段直达文件写入汇点。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 045.php（路由 /045，方法以源码实际接受为准）的不安全文件上传（CWE-434）POC。上传点参数名为 uploaded，注入通道为 multipart 的 filename；045.php:18 处对上传文件缺少扩展名/类型校验。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

若上传目录位于 Web 可访问路径且允许 PHP 等可执行扩展名，攻击者可上传 webshell 并请求该文件，导致远程代码执行（RCE）；即使不可执行，也可造成任意文件写入/覆盖、存储型恶意内容托管（钓鱼、恶意脚本分发）与磁盘占用。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传接口为常规 HTTP POST 多部分请求，无需认证（片段中未见任何鉴权/会话检查）；利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file()` → 目标路径落盘，中间无净化。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并基于服务端解析的真实 MIME/魔数校验，不信任客户端 Content-Type；2) 服务端生成随机文件名，禁止使用用户提供的文件名拼接 `$target_path`，并对路径做规范化后校验其仍位于上传根目录内（防路径穿越）；3) 上传目录置于 Web 根之外，或通过下载脚本以 `Content-Disposition: attachment` 与正确 Content-Type 输出；4) 上传目录禁用脚本执行（如 PHP 的 open_basedir/引擎关闭、Nginx location 拒绝 .php）；5) 限制文件大小并做病毒/内容扫描；6) 上传操作要求认证与 CSRF 令牌。

**验证说明**

静态证据：入口 ANY /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，字段 `uploaded` 携带恶意文件 → PHP 将其存入临时文件 `$_FILES['uploaded']['tmp_name']` → 045.php:18 直接调用 `move_uploaded_file()` 移动到 `$target_path`，全程无扩展名/类型/路径校验 → 文件落入可访问目录，攻击者请求该文件触发执行或内容托管。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:18，外部输入来自 multipart 字段 uploaded 的 filename，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。原草稿使用 -X ANY 为占位方法，实际发送时应替换为源码接受的方法（通常为 POST）；执行前须将 TARGET 替换为授权测试实例地址，上传内容保持无害标记，禁止上传真实 webshell 或破坏性载荷。

### F-2: DVWA 文件上传端点仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-26`
- **来源**：`llm_finding`

**描述**

045.php 在收到 POST 参数 Upload 后，把上传文件保存到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，文件名取自 $_FILES['uploaded']['name'] 经 basename() 处理。唯一的“是不是图片”校验使用 $_FILES['uploaded']['type']（即 HTTP 请求中的 Content-Type，完全由客户端控制）与 $_FILES['uploaded']['size']（同样由客户端控制），既没有校验文件扩展名，也没有用 getimagesize()/finfo 检查真实文件内容。攻击者只要把 Content-Type 伪造成 image/jpeg 或 image/png，就能把任意内容的 .php 文件写入 Web 可访问的 uploads 目录，随后直接请求该文件即可执行任意 PHP 代码，形成 RCE。

**source / sink**

- source：upload `uploaded`（045.php:9-11）
- sink：045.php:26 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 Web 根目录下的 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 入口判断：只要 POST 中存在 Upload 字段即进入上传逻辑，无认证、无 CSRF token 校验 | 攻击者完全控制请求体 |  |
| 2 | `045.php:5-6` | 拼接目标路径：DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 加上 basename(原始文件名)，basename 只去掉目录部分，保留扩展名 | $target_path = <webroot>/hackable/uploads/shell.php |  |
| 3 | `045.php:9-11` | 从 $_FILES 读取文件名、MIME 类型、大小，三者均来自客户端 multipart 请求 | $uploaded_type 由请求头 Content-Type 决定 |  |
| 4 | `045.php:14-15` | 校验条件：$uploaded_type 等于 image/jpeg 或 image/png 且 size<100000。由于 type 来自客户端，可任意伪造；size 也可伪造 | 伪造 Content-Type: image/jpeg 即通过校验 | MIME 类型取自客户端提交的 Content-Type，未使用 getimagesize()/finfo_file() 校验真实内容；扩展名未做白名单 |
| 5 | `045.php:18` | move_uploaded_file 把临时文件移动到 Web 可访问目录，文件名与扩展名由攻击者指定 | 任意 PHP 代码落盘为 .php 文件 |  |
| 6 | `045.php:24` | 成功分支回显目标路径，攻击者据此得知上传后的 URL，可直接请求执行 |  |  |

**POC**

针对 045.php（POST /045.php）的不安全文件上传（CWE-434）POC。上传点参数名为 uploaded，注入通道为 multipart 的 filename；045.php:26 处对上传文件缺少扩展名/类型白名单校验，攻击者可上传 .jsp 等可执行脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。

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
- POC 目录：`poc/LLM-916b10bd8caa`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可在服务器上写入并执行任意 PHP 代码，完全控制 Web 应用与主机（RCE）。

**CVE / CWE 论证**

CWE-434 无限制危险类型文件上传。入口 045.php:3 无认证，校验 045.php:14 仅依赖客户端可控的 MIME 类型，sink 045.php:18 直接落盘到 Web 目录，链路闭合且外部可达。

**修复建议**

使用 finfo_file()/getimagesize() 校验真实文件类型；对扩展名做白名单并重命名为随机名；把上传目录移出 Web 根或禁止脚本执行；增加认证与 CSRF 校验。

**验证说明**

需确认 DVWA_WEB_PAGE_TO_ROOT 的实际值与 uploads 目录是否允许 PHP 解析；若服务器对 uploads 目录禁用 PHP 执行，则 RCE 降级为任意文件写入。
模型 POC 要点：伪造 Content-Type 上传 PHP webshell 到 uploads 目录，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:26，外部输入来自 multipart 字段 uploaded 的 filename，source→sink 链静态闭合，未发现扩展名/类型白名单等有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试实例地址，并手动逐条发送；上传内容保持无害标记，禁止上传真实 webshell 或破坏性载荷。

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
| safety_guard | 安全防护 | 3.09 | 是 |
| surface_mapper | 攻击面测绘 | 7.46 | 是 |
| deep_finder | LLM 深挖 | 9.36 | 是 |
| candidate_screener | 候选筛选 | 4.0 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.9 | 是 |
| coordinator | 管线协调 | 6.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
