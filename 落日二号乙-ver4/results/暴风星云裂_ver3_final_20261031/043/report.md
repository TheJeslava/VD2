# 落日二号乙漏洞挖掘报告 — 20261031-014317-6bb79d

- 生成时间：2026-10-30T17:44:03.404653+00:00
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

本次汇总基于已去重的 2 条 findings，均集中在唯一代码文件 043.php，类型均为 file_upload（CWE-434）。最高危为 GEN-729d053acdfd（critical，规则命中，043.php 第 20 行附近），描述不安全文件上传导致任意文件写入；LLM-24bb446ce5ae（high，043.php 第 26 行附近）从扩展名校验绕过角度描述同一上传端点可上传 PHP 脚本并远程执行，二者为同一攻击面的不同证据视角，已去重但保留双证据。2 条 finding 均带 POC（has_poc=true），POC 齐全度在已交付范围内为 100%，但均为 HTTP 型上传 POC 的文本工件，未做动态验证。覆盖统计显示仅 1 个文件、0 个端点、语言 php:1、无框架、无隔离文件；surface_notes 明确指出未提供 043.php 源码片段、sink_hot_files 为空，因此除文件上传外的路径穿越、命令执行、XSS、弱哈希/弱加密/弱随机、不安全 Cookie、信任边界、硬编码密钥等攻击面均无 findings 覆盖，只能作为人工复核项，不能据此判定安全或不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 043.php（35 行，DVWA upload 模块）。逐行审计确认：入口为 $_POST['Upload'] + $_FILES['uploaded']，扩展名白名单（jpg/jpeg/png）+ 大小限制 + getimagesize 校验，最终 move_uploaded_file 写入 hackable/uploads/。该组合可被 polyglot 图片 + 双扩展名绕过，构成任意文件上传导致 RCE，已作为唯一闭合链交付。其余攻击面：无 SQL/命令/eval/文件包含/SSRF 汇点；无 setcookie/session 配置；无 md5/sha1/rand 等弱算法调用；无硬编码凭据；输出点 $html 仅回显服务端拼接的路径，未直接回显用户可控原始输入（文件名经 basename 处理），反射型 XSS 证据不足，未报告。未覆盖范围：无 endpoints 清单、无部署配置（php.ini、上传目录执行权限、allow_url_include 等），因此上传目录是否可执行 PHP 属运行时条件，已在 verification_notes 标注。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单，实际访问路径与是否需要认证未知
- 无部署配置，无法确认 hackable/uploads/ 是否允许脚本执行
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 CODE PACK 内，目标绝对路径未知

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（043.php:12 读取上传内容并写入 `$uploaded_tmp`），代码未对上传文件的扩展名、MIME 类型或内容做任何白名单校验，随后在 043.php:20 直接调用 `move_uploaded_file($uploaded_tmp, $target_path)` 将临时文件移动到 `$target_path`。由于 `$target_path` 的构造逻辑（文件名/目录来源）在给定片段中未体现，无法确认文件名是否完全由用户控制，但已确认从上传输入到文件落盘汇点之间不存在有效净化，属于典型的无限制文件上传。

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

若目标目录位于 Web 可访问路径且允许 PHP 等可执行扩展名，攻击者可上传 WebShell 实现远程代码执行（RCE）；即使不可执行，也可覆盖/写入任意文件造成数据篡改或磁盘占用。具体可利用程度取决于 `$target_path` 的目录与命名规则，该部分证据不足。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 请求，无需认证即可触达（片段中未见鉴权逻辑）；利用链闭合：`uploaded` 上传输入 → `$uploaded_tmp` → `move_uploaded_file()` 落盘，中间无扩展名/类型校验。因缺少 `$target_path` 构造代码，最终落盘路径可控性为推断，故置信度中等。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端解析的真实内容类型校验，而非客户端 Content-Type；2) 将上传目录置于 Web 根之外，或对目录禁用脚本执行；3) 上传文件重命名为随机名并去除路径分隔符，防止路径穿越；4) 限制文件大小与数量；5) 上传后以只读、非执行权限存储。

**验证说明**

静态证据：入口 ANY /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，在字段 `uploaded` 中携带恶意文件 → 043.php:12 读取上传内容得到 `$uploaded_tmp` → 代码未做任何类型/扩展名校验 → 043.php:20 `move_uploaded_file($uploaded_tmp, $target_path)` 将文件写入目标路径 → 若目标路径可 Web 访问且允许脚本执行，则上传文件被解析执行，形成 RCE。
PocWriter 建议（未采纳，缺少端点 /043）：针对 043.php:20 的不安全文件上传（CWE-434）。同一上传逻辑在 043.php:20 处接收 multipart 字段 `uploaded`，未对文件类型/扩展名做有效限制即写入磁盘，攻击者可上传 .jsp 等可执行文件，若目录可解析则导致 RCE。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434。漏洞位于可交付代码 043.php:20，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。脚本中 TARGET 为占位符，需在授权测试环境中手动替换后执行；上传内容为无害标记 SUNSET_POC，不含命令执行逻辑。

### F-2: DVWA 文件上传端点（043.php）扩展名校验可被绕过，导致上传任意 PHP 脚本并远程执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`043.php:5-26`
- **来源**：`llm_finding`

**描述**

043.php 接收 multipart 上传（字段名 uploaded，提交按钮 Upload），仅通过 substr(strrpos(name,'.')+1) 取最后一段扩展名并与 jpg/jpeg/png 比较，同时要求 size<100000 且 getimagesize() 返回真。校验只针对扩展名字符串与图片头，未对文件内容做真实图片解析后的重编码，也未限制上传目录的可执行权限。攻击者可构造「合法图片头 + PHP 代码」的 polyglot 文件，并用双扩展名（如 shell.php.jpg）或大小写/尾随点等技巧使扩展名判定为 jpg，从而把可执行 PHP 写入 hackable/uploads/ 目录，随后直接请求该文件触发代码执行。

**source / sink**

- source：upload `uploaded`（043.php）
- sink：043.php:26 move_uploaded_file($uploaded_tmp, $target_path) 将攻击者文件写入 web 可访问目录 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `043.php:9-10` | 从 $_FILES['uploaded']['name'] 取文件名，用 strrpos 找最后一个 '.' 后取子串作为扩展名 | $uploaded_ext = 最后一个点之后的字符串 |  |
| 3 | `043.php:15-17` | 扩展名白名单 jpg/jpeg/png + 大小 <100000 + getimagesize 通过才继续 | 校验仅看扩展名与图片头，不看真实内容 | 使用 shell.php.jpg 之类双扩展名使 $uploaded_ext=='jpg'；文件头伪造 GIF89a/PNG 魔数即可让 getimagesize 返回真，PHP 代码置于图片数据之后仍会被 PHP 解析执行 |
| 4 | `043.php:5-6` | 拼接目标路径 hackable/uploads/ + basename(原始文件名) | $target_path = .../hackable/uploads/shell.php.jpg |  |
| 5 | `043.php:20` | move_uploaded_file 将临时文件移动到目标路径 | 恶意文件落盘到 web 目录 |  |
| 6 | `043.php:26` | 回显上传成功及完整路径，攻击者据此定位文件 URL | 响应泄露落盘路径 |  |

**POC**

针对 /vulnerabilities/upload/（043.php 所在路径，具体路由取决于部署）（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/（043.php 所在路径，具体路由取决于部署）'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/（043.php 所在路径，具体路由取决于部署）' \
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

攻击者可在服务器上写入并执行任意 PHP 代码，完全控制 Web 应用与主机（RCE），读取数据库凭据、横向移动。

**CVE / CWE 论证**

CWE-434 无限制危险类型文件上传。外部可通过 HTTP multipart 直接触发，无需高权限；扩展名白名单与 getimagesize 均可被 polyglot + 双扩展名绕过，source→sink 链在 043.php 内闭合。

**修复建议**

对上传文件做服务端真实图片解析并重编码（如 imagecreatefrom* 后重新保存）；使用随机生成的文件名且强制安全扩展名；将上传目录置于 web 根之外或禁用该目录的脚本执行（php_flag engine off / 独立域名）；校验 MIME 与内容而非仅扩展名。

**验证说明**

需确认部署环境 hackable/uploads/ 是否允许 PHP 执行、DVWA_WEB_PAGE_TO_ROOT 实际路径、以及上传端点是否需登录；这些属于运行时条件，不影响源码层链闭合。
模型 POC 要点：构造带合法图片头与 PHP 代码的 polyglot 文件，用双扩展名绕过扩展名白名单，上传后访问执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/（043.php）：针对 043.php:26 的不安全文件上传（CWE-434）。上传入口接收 multipart 字段 `uploaded`，未对扩展名/内容类型做有效校验即落盘，攻击者可上传 .jsp 等可执行脚本，若落盘目录可被 Web 容器解析则导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/（043.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:26，外部输入来自 multipart 字段 `uploaded`，source→sink 链静态闭合，未发现有效扩展名/内容校验，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。脚本中 TARGET 为占位符，需在授权测试环境中手动替换后执行；上传内容为无害标记 SUNSET_POC，不含命令执行逻辑。

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
| safety_guard | 安全防护 | 2.87 | 是 |
| surface_mapper | 攻击面测绘 | 8.98 | 是 |
| deep_finder | LLM 深挖 | 11.02 | 是 |
| candidate_screener | 候选筛选 | 3.93 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.34 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.65 | 是 |
| coordinator | 管线协调 | 6.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
