# 落日二号乙漏洞挖掘报告 — 20261031-002325-2c3b58

- 生成时间：2026-10-30T16:24:13.188456+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\043.zip`
- 输入模式：`zip`
- SHA256：`07af6f04e9411f0557b345faaf32fcbb3e1405cb4402c57b6fc79a4bf804244f`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅覆盖单文件 PHP 脚本 043.php（35 行，约 1.1KB），共交付 2 条去重后的 file_upload 发现：规则命中 GEN-729d053acdfd（critical，任意文件写入，CWE-434）与 LLM 发现 LLM-7a70487f2fb0（high，仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片写入 web 可访问目录），两者均带 POC（has_poc=true），但均为静态文本 POC，未做动态验证。最高危为 GEN-729d053acdfd 的任意文件写入，若目标目录可被 Web 直接访问，等价于远程代码执行。POC 齐全度：2/2 有 POC，但均为静态证据型，不能宣称可动态复现。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 043.php（35 行，DVWA 文件上传示例）。发现一条闭合链：POST 参数 Upload 触发，$_FILES['uploaded'] 文件名/内容经扩展名、大小、getimagesize 三重校验后由 move_uploaded_file 写入 web 可访问的 hackable/uploads/ 目录。getimagesize 仅校验文件头，polyglot 图片可绕过，形成任意文件上传；若 uploads 目录可解析 PHP 则升级为 RCE。未发现命令注入、SQL 注入、路径穿越（basename 已去除路径分隔符）、反序列化、SSRF 等其它汇点；文件中无 md5/sha1/rand/setcookie 等配置类风险代码。endpoints 为空，实际访问路径按 DVWA 惯例推断为 /vulnerabilities/upload/，需人工确认。

未覆盖 / 证据缺口：
- 无 php.ini/nginx/apache 配置，无法确认 uploads 目录是否解析 PHP（决定是否 RCE）
- endpoints 为空，实际路由与是否需要认证未确认
- 无 DVWA_WEB_PAGE_TO_ROOT 定义文件，上传目录绝对路径未知
- 无版本控制/README，无法判断是否为裁剪示例

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 上传请求的 `uploaded` 文件字段（043.php:12 读取上传文件，临时路径进入 `$uploaded_tmp`）提交任意内容与任意文件名的文件。代码在 043.php:20 直接调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将临时文件移动到 `$target_path`，在给出的片段（043.php:18-20）中未见对扩展名、MIME 类型、文件内容或目标路径的白名单校验，也未见对 `$target_path` 的规范化与目录限制，因此校验无效。最终危险操作是 `move_uploaded_file` 把攻击者可控内容写入 Web 可访问目录。

**source / sink**

- source：upload `uploaded`（043.php:12）
- sink：043.php:20 if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:12` | 从 upload `uploaded` 读取外部输入 | 污点进入 uploaded_tmp |  |
| 2 | `043.php:20` | 危险汇点：if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /043（ANY）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/043'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/043' \
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

攻击者可上传 .php 等可执行脚本到 Web 根目录下，随后通过 HTTP 请求触发执行，形成远程代码执行（RCE）；即使目标目录禁止脚本执行，也可造成任意文件写入/覆盖、磁盘占用与恶意内容托管（钓鱼、恶意下载）。无需认证即可利用（取决于部署是否在 043.php 前加访问控制，代码片段本身未见认证逻辑）。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：入口为 HTTP multipart 上传，`uploaded` 字段由客户端完全控制；无需认证（片段内无鉴权代码）；利用链闭合：`uploaded` → `$uploaded_tmp`（043.php:12）→ `move_uploaded_file($uploaded_tmp, $target_path)`（043.php:20），中间无扩展名/MIME/内容白名单与路径规范化，攻击者可直接落盘可执行脚本。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并同时校验服务端探测的 MIME 与文件魔数，不信任客户端 Content-Type；2) 上传文件名由服务端随机生成（UUID），不使用客户端文件名，禁止路径分隔符与 `..`；3) 将上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 Nginx `location ~ \.php$ { deny all; }`）；4) 对 `$target_path` 做 `realpath` 规范化并校验其前缀必须落在允许的上传目录内；5) 上传目录以最小权限运行，文件权限设为 0644 且属主非 Web 进程；6) 在 043.php 前增加认证与 CSRF 防护、限制上传大小与频率。

**验证说明**

静态证据：入口 ANY /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，在 `uploaded` 字段放入名为 `shell.php` 的 PHP 脚本。043.php:12 读取该上传文件，临时路径赋给 `$uploaded_tmp`；代码未对扩展名/类型做白名单校验，直接拼接 `$target_path` 并在 043.php:20 调用 `move_uploaded_file($uploaded_tmp, $target_path)` 落盘。随后攻击者访问 `TARGET/uploads/shell.php`（路径以实际部署为准）触发脚本执行，获得命令执行能力。POC 仅限授权测试，目标统一使用 `TARGET` 占位符，不提供自动执行脚本。
PocWriter 建议（未采纳，缺少端点 /043）：针对 043.php:20 的不安全文件上传（CWE-434）POC。上传入口为 multipart 字段 `uploaded`，注入通道是 multipart 的 filename；攻击者通过构造 `filename=sunset.jsp` 使服务端以可执行脚本扩展名落盘，若上传目录可被 Web 容器解析则导致 RCE。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:20，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效扩展名/内容校验；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。poc.sh 与 request.http 保留原请求结构，TARGET 为占位符，需人工替换并在授权环境手动执行。上传内容使用无害标记 SUNSET_POC，避免携带真实 webshell 逻辑。

### F-2: DVWA 文件上传端点（043.php）仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.77`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`043.php:3-27`
- **来源**：`llm_finding`

**描述**

043.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 拼接到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 后作为 move_uploaded_file 的目标路径。校验仅有三点：扩展名（strtolower 后必须为 jpg/jpeg/png）、大小 <100000 字节、getimagesize() 返回真。getimagesize 只检查文件头是否为合法图片，不检查文件其余内容，因此攻击者可构造「合法 PNG/JPG 头 + 尾部 PHP 代码」的 polyglot 文件通过校验，并被写入 web 根下 hackable/uploads/ 目录。若目标服务器对该目录下的 .php 解析（DVWA 默认部署常见），即可通过访问上传文件执行任意 PHP 代码，形成 RCE。

**source / sink**

- source：upload `uploaded`（043.php:9-12）
- sink：043.php:27 move_uploaded_file($uploaded_tmp, $target_path) 写入 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制 multipart 请求 |  |
| 2 | `043.php:9-12` | 从 $_FILES['uploaded'] 读取文件名、扩展名、大小、临时路径 | 文件名与内容完全由攻击者控制 |  |
| 3 | `043.php:15-17` | 校验扩展名为 jpg/jpeg/png、大小 <100000、getimagesize 通过 | polyglot 文件（合法图片头 + PHP 尾）可通过 | getimagesize 仅校验文件头，不校验文件其余内容；扩展名取自文件名最后一段，攻击者可直接命名为 shell.png |
| 4 | `043.php:5-6` | 目标路径 = 上传目录 + basename(文件名) | basename 去除路径分隔符，但保留文件名与扩展名 |  |
| 5 | `043.php:20` | move_uploaded_file 将临时文件移动到 web 可访问的 hackable/uploads/ 目录 | 恶意文件落盘为 web 可访问资源 |  |

**POC**

针对 043.php:27 的不安全文件上传（CWE-434）POC。上传入口为 POST /vulnerabilities/upload/，multipart 字段 `uploaded`，注入通道为 filename；构造 `filename=sunset.jsp` 使服务端以脚本扩展名保存文件，若上传目录可解析则导致 RCE。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (043.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (043.php)' \
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

可上传任意内容文件至 web 可访问目录；在常见 DVWA 部署下可进一步执行任意 PHP 代码，导致服务器被控。

**CVE / CWE 论证**

CWE-434 无限制文件上传。外部可直接通过 HTTP multipart 触发，无需高权限；链闭合至文件落盘，RCE 取决于 uploads 目录解析配置（运行时条件）。

**修复建议**

使用白名单校验扩展名并重命名文件（随机名 + 固定安全扩展名）；将上传目录移出 web 根或禁止脚本执行；对图片做二次编码（如 GD 重绘）剥离尾部代码；校验 MIME 与文件内容一致性。

**验证说明**

需确认目标部署中 hackable/uploads/ 是否可被 PHP 解析（DVWA 默认通常可），以及是否需登录；文件上传本身已闭合，RCE 依赖解析配置。
模型 POC 要点：构造带合法 PNG 头、尾部含 PHP 代码的 polyglot 文件，以 shell.png 为文件名上传，随后访问上传路径触发 PHP 执行（仅限授权测试）
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:27，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效扩展名/内容校验；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。poc.sh 与 request.http 保留原请求结构，TARGET 为占位符，需人工替换并在授权环境手动执行。上传内容使用无害标记 SUNSET_POC，避免携带真实 webshell 逻辑。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 2.84 | 是 |
| surface_mapper | 攻击面测绘 | 8.09 | 是 |
| deep_finder | LLM 深挖 | 10.16 | 是 |
| candidate_screener | 候选筛选 | 4.77 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.96 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.15 | 是 |
| coordinator | 管线协调 | 6.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
