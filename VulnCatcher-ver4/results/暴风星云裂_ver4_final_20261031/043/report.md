# 落日二号乙漏洞挖掘报告 — 20261031-173224-ff36fe

- 生成时间：2026-10-31T09:33:10.930020+00:00
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

本次汇总仅覆盖单文件 PHP 脚本 043.php（35 行，约 1.1KB），无框架、无路由、无端点清单、无 sink 热点，攻击面极窄。去重后共 2 条 findings，均为 file_upload 类型：规则命中 GEN-729d053acdfd（critical，043.php 第 20 行，不安全文件上传导致任意文件写入，CWE-434）与 LLM 发现 LLM-7a70487f2fb0（high，043.php 第 27 行，仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录）。最高危为 GEN-729d053acdfd（critical，任意文件写入，若目录可执行则等价于远程代码执行）。两条 finding 均带 POC（with_poc=2），但均为静态源码证据 POC，本次未执行、未搭建沙箱、未做动态验证，不能宣称已动态复现。其余注入类（SQLi/XSS/路径穿越/SSRF/文件包含）与配置类（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均无 findings 交付，属覆盖缺口而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 043.php（35 行，DVWA 文件上传 low 级别实现）。发现一条闭合度较高的链：上传文件名/内容经扩展名白名单与 getimagesize 弱校验后由 move_uploaded_file 写入 hackable/uploads/，属 CWE-434 不受限文件上传，是否可升级为 RCE 取决于上传目录的解析配置（code_pack 未提供）。未发现 SQL 注入、命令注入、SSRF、反序列化、路径穿越（basename 已消除目录穿越）、弱哈希/弱随机/不安全 Cookie 等其它可闭合链；文件中无 md5/sha1/rand/setcookie 调用。DVWA_WEB_PAGE_TO_ROOT 常量与 $html 变量初始化不在 code_pack 内，属未覆盖范围。未发现 prompt_injection 证据。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 $html 初始化不在 code_pack
- 缺少 Web 服务器/php.ini 配置，无法确认上传目录是否解析 PHP 及 043.php 实际访问路径
- 无端点清单与认证实现，无法评估访问控制
- 未做动态验证，上传落盘与解析行为均为源码推断

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 上传请求的 `uploaded` 文件字段（043.php:12 读取上传文件，临时路径进入 `$uploaded_tmp`）提交任意内容与文件名的文件。代码在 043.php:20 直接调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将临时文件移动到 `$target_path`，在给出的片段（043.php:18-20）中未见任何扩展名白名单、MIME 校验、文件内容检查或目标路径规范化/限制。由于校验缺失，攻击者可控制落盘文件名与内容，将可执行脚本（如 .php）写入 Web 可访问目录。

**source / sink**

- source：upload `uploaded`（043.php:12）
- sink：043.php:20 if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:12` | 从 upload `uploaded` 读取外部输入 | 污点进入 uploaded_tmp |  |
| 2 | `043.php:20` | 危险汇点：if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 043.php:20 的不安全文件上传（CWE-434）POC。入口 /043 接受 POST multipart，文件域 `uploaded` 与提交按钮 `Upload`，服务端在第 20 行附近处理上传且未做有效类型校验，可上传 .jsp 脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

任意文件写入 Web 根目录可导致远程代码执行（上传 PHP webshell 后访问即执行），进而完全控制服务器；也可覆盖/植入文件造成持久化后门或数据篡改。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传接口为 HTTP 端点，无需认证即可提交 multipart 请求；利用链闭合：`uploaded` 文件 → `$uploaded_tmp`（043.php:12）→ `move_uploaded_file($uploaded_tmp, $target_path)`（043.php:20）→ 文件落盘于 Web 可访问路径。片段中未见任何净化或类型限制，故无需绕过即可利用。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端解析的真实 MIME/魔数校验，而非客户端 Content-Type；2) 上传文件重命名为随机名，禁止使用用户提供的文件名；3) 上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 PHP 引擎关闭）；4) 对 `$target_path` 做规范化并校验其位于允许目录内，防止路径穿越；5) 限制文件大小与权限（最小权限运行）。

**验证说明**

静态证据：入口 POST /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart 上传请求，文件字段名为 `uploaded`，内容为 PHP 代码、文件名为 shell.php。043.php:12 读取上传文件，临时路径赋给 `$uploaded_tmp`；随后 043.php:20 调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将其移动到目标路径。由于片段中不存在扩展名/内容/路径校验，恶意脚本被写入 Web 可访问目录，攻击者访问该文件即触发代码执行。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434。漏洞位于可交付代码 043.php:20，外部输入来自 multipart 文件域 `uploaded`，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权实例地址；上传目录路径需按目标实际配置确认，若无法确认则在步骤 3 标注“需补充源码/路由”。

### F-2: DVWA 文件上传页面 043.php 仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`043.php:3-27`
- **来源**：`llm_finding`

**描述**

043.php 处理 multipart 上传：从 $_FILES['uploaded']['name'] 取文件名，用 strrpos 取最后一个点后的子串作为扩展名，仅做 strtolower 白名单（jpg/jpeg/png）、大小 <100000 与 getimagesize() 校验，随后 basename() 后直接拼接 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 并 move_uploaded_file 落盘。getimagesize 只检查文件头是否为合法图片，不阻止图片尾部附加任意 PHP 代码（polyglot 图片马）；扩展名白名单只约束后缀，不约束内容。落盘目录 hackable/uploads/ 在 DVWA 部署中为 web 可直接访问目录，若服务器对 .jpg/.png 不做 PHP 解析则需配合解析配置，但该页面本身缺失内容级校验与上传目录执行禁用，属于典型的 unrestricted file upload 弱点。

**source / sink**

- source：upload `uploaded`（043.php）
- sink：043.php:27 move_uploaded_file($uploaded_tmp, $target_path) 写入 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 检测到 POST 参数 Upload 后进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `043.php:9-10` | 从上传文件名取扩展名，仅按最后一个点切分，未做内容检查 | $uploaded_ext = 'jpg'（攻击者可控文件名后缀） |  |
| 3 | `043.php:15-17` | 扩展名白名单 + 大小限制 + getimagesize 校验；getimagesize 只验证文件头为图片，允许尾部附加 PHP 代码 | polyglot 图片马通过校验 | getimagesize 仅解析图像头，不扫描尾部载荷；扩展名白名单不限制文件内容 |
| 4 | `043.php:5-6` | 目标路径拼接为 hackable/uploads/ + basename(文件名) | $target_path = <webroot>/hackable/uploads/shell.jpg |  |
| 5 | `043.php:20` | move_uploaded_file 将临时文件移动到 web 可访问目录 | 恶意文件落盘到 hackable/uploads/ |  |

**POC**

针对 /vulnerabilities/upload/（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/' \
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

攻击者可上传含服务端代码的文件到 web 可访问目录，在解析配置允许时实现远程代码执行；即使不解析，也可作为存储型内容托管/钓鱼载体。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部无需认证即可通过 POST 上传触发，source→sink 链在 043.php 内闭合；getimagesize 与扩展名白名单为可绕过的弱防护。

**修复建议**

对上传内容做真实图像重编码（如 GD/Imagick 重新生成图片）去除附加数据；随机化落盘文件名并强制安全扩展名；上传目录禁用脚本执行（php_flag engine off / Nginx location 拒绝 .php）；限制 MIME 与文件头一致性校验。

**验证说明**

需确认 hackable/uploads/ 是否可被 web 访问、服务器是否对 .png/.jpg 解析 PHP；若均不满足则仅剩文件托管影响，需降级。DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，路径基于 DVWA 约定推断。
模型 POC 要点：构造一个合法 PNG 头 + 尾部 PHP 代码的图片马，以 .png 扩展名上传，落盘到 hackable/uploads/ 后访问触发（需目标服务器对图片扩展名解析 PHP 或配合 .htaccess/解析配置）。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 043.php:27 的不安全文件上传（CWE-434）POC。上传表单字段为 `Upload`（提交按钮）与 `uploaded`（文件域），服务端未对扩展名/内容做有效校验即落盘，攻击者可上传 .jsp 等可执行脚本。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:27，外部输入来自 multipart 文件域 `uploaded`，source→sink 链静态闭合，未见有效扩展名/内容校验，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权实例地址；上传目录路径（如 /hackable/uploads/）需按目标实际配置确认，若无法确认则在步骤 3 标注“需补充源码/路由”。

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
| safety_guard | 安全防护 | 3.56 | 是 |
| surface_mapper | 攻击面测绘 | 8.03 | 是 |
| deep_finder | LLM 深挖 | 10.75 | 是 |
| candidate_screener | 候选筛选 | 4.71 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.79 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.94 | 是 |
| coordinator | 管线协调 | 6.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
