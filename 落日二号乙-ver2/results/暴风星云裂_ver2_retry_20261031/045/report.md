# 落日二号乙漏洞挖掘报告 — 20261031-002357-bafdf7

- 生成时间：2026-10-30T16:24:43.552112+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\045.zip`
- 输入模式：`zip`
- SHA256：`a0b2458750b044b980ebfd21404d68504f146fb80f29769046d1fc1c3577d5c4`
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

本次汇总仅涉及单文件 PHP 脚本 045.php（33 行），共 2 条去重后的 file_upload 发现：规则命中 GEN-60f80eecf7e1（critical，045.php 第 18 行附近，不安全上传导致任意文件落盘，CWE-434）与 LLM 发现 LLM-916b10bd8caa（high，045.php 第 26 行附近，仅校验客户端可控 MIME 类型，可上传 PHP 脚本导致 RCE）。两者同源同文件、根因一致（上传校验不足），最高危为 critical 的任意文件落盘，其可进一步升级为 Web 侧代码执行。两条发现均带 POC（has_poc=true，with_poc=2），但均为静态/文本 POC，未做动态验证；且输入未提供 045.php 的代码片段内容，POC 与行号只能依据元数据与发现描述，需人工对照源码复核。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 045.php（33 行，DVWA 文件上传模块）。确认一条闭合链：上传类型校验仅依赖客户端可控的 $_FILES['uploaded']['type']，配合 basename 保留 .php 扩展名与 move_uploaded_file 写入 Web 可访问的 hackable/uploads/，构成任意文件上传→RCE（CWE-434）。未发现 SQL/命令/反序列化/SSRF 等其它汇点；文件内无认证逻辑、无数据库操作。未闭合点：DVWA_WEB_PAGE_TO_ROOT 常量与 uploads 目录执行策略未在 code_pack 中给出，需人工确认；无 endpoints 清单，路由按文件直访推断。输入中未出现诱导性文本。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 uploads 目录 Web 可执行性未提供
- 无 HTTP 端点清单，路由为推断
- 无 php.ini/服务器配置，无法确认上传目录执行限制

## 3. Findings

### F-1: 045.php 不安全文件上传导致任意文件落盘（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 多部分表单上传文件，文件内容进入 PHP 超全局数组 $_FILES['uploaded']，其中 $_FILES['uploaded']['tmp_name'] 为临时文件路径、$_FILES['uploaded']['name'] 为客户端可控的原始文件名。代码在 045.php:18 直接调用 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 将上传文件移动到目标路径 $target_path。从给出的片段看，第 16-18 行之间不存在扩展名白名单、MIME 校验、文件内容检测或文件名规范化逻辑，$target_path 的构造（是否拼接客户端文件名、是否限制在固定目录）在片段中未体现，因此无法证明存在有效净化。校验缺失使攻击者可控制落盘文件的名称/扩展名，从而把可执行脚本写入 Web 可访问目录。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /045（ANY）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

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

任意文件写入 Web 根目录：若 $target_path 位于可被 Web 服务器解析的目录且允许 .php/.phtml 等扩展名，攻击者可上传 WebShell 实现远程代码执行（RCE）；即使不可执行，也可覆盖/投放任意文件、造成存储型内容注入或磁盘占用。属于高危（critical）级别。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部可达性：上传入口为 HTTP 表单字段 uploaded，无需认证即可访问 045.php；利用链闭合：$_FILES['uploaded']['tmp_name'] → move_uploaded_file() → $target_path 落盘，中间无扩展名/类型白名单，攻击者可直接提交恶意文件完成利用。注意：$target_path 的具体构造在给定片段（045.php:16-18）中未展示，若其被固定为安全目录或强制重命名，实际可利用性会下降，此点属证据不足。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端检测的真实 MIME/魔数校验，而非客户端 Content-Type；2) 忽略客户端文件名，由服务端生成随机文件名（如 UUID）并强制追加白名单扩展名；3) 将上传目录置于 Web 根之外，或配置 Web 服务器禁止该目录执行脚本（如 php_flag engine off / 禁止 .php 解析）；4) 限制文件大小与数量，校验路径规范化后仍位于预期目录内（防目录穿越）；5) 上传后文件以最小权限存储，必要时做病毒/内容扫描。

**验证说明**

静态证据：入口 ANY /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 045.php 提交字段名为 uploaded 的文件，文件名为 shell.php、内容为 PHP 代码。PHP 将临时文件路径写入 $_FILES['uploaded']['tmp_name']。045.php:18 调用 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)，由于缺少扩展名与类型校验，文件被移动到 $target_path 指向的位置。攻击者随后访问该落盘文件路径，若目录可解析 PHP 则执行任意代码，形成 RCE。
PocWriter 建议（未采纳，缺少端点 /045）：针对 045（ANY 方法）的不安全文件上传（CWE-434）POC。与 LLM-916b10bd8caa 为同一上传逻辑的另一入口表述（045.php:18），上传字段为 `uploaded`，注入通道为 multipart filename。目标地址统一使用 TARGET 占位符，仅限授权测试。注意：HTTP 方法 ANY 为占位写法，实际测试应使用服务端接受的方法（通常为 POST）。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434。漏洞位于可交付代码 045.php:18，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：仅文本工件，不执行、不联网。ANY 为占位方法，实际执行前需替换为服务端接受的方法（通常 POST）。上传内容为无害占位串 SUNSET_POC。

### F-2: DVWA 上传端点 045.php 仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-26`
- **来源**：`llm_finding`

**描述**

045.php 处理 multipart 上传时，用 $_FILES['uploaded']['type']（完全由客户端 multipart 请求的 Content-Type 决定）判断是否为 image/jpeg 或 image/png，并仅限制 size<100000，随后直接 move_uploaded_file 到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，文件名取 basename($_FILES['uploaded']['name'])。服务端未做任何内容嗅探（getimagesize/finfo）、未做扩展名白名单、未重命名、未禁止脚本扩展。攻击者把 Content-Type 伪造成 image/jpeg 并上传 shell.php，即可在 Web 可访问的 uploads 目录落地可执行 PHP，形成 RCE。

**source / sink**

- source：upload `uploaded`（045.php）
- sink：045.php:26 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 hackable/uploads/ 下攻击者命名的文件

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `045.php:6` | 目标路径由固定目录拼接 basename(原始文件名)，文件名保留 .php 扩展 | $target_path = <root>/hackable/uploads/shell.php |  |
| 3 | `045.php:10` | 取客户端声明的 MIME 类型作为唯一类型判据 | $uploaded_type 完全由请求头 Content-Type 决定 |  |
| 4 | `045.php:14` | 仅比较 $uploaded_type 是否等于 image/jpeg 或 image/png，伪造 Content-Type 即通过 | 校验恒真（伪造 image/jpeg） | 校验依据是客户端可控的 $_FILES['type']，非服务端内容检测 |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到 uploads 目录，落地为 .php | 恶意 PHP 脚本写入 Web 可访问目录 |  |

**POC**

针对 /045.php（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

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

任意文件上传导致在服务器上执行任意 PHP 代码，完全控制 Web 应用与主机（RCE）。

**CVE / CWE 论证**

CWE-434 无限制文件上传 / CWE-646 依赖不可信文件元数据。外部无需认证即可通过 HTTP 触发，链完整闭合（source $_FILES → 弱校验 → move_uploaded_file → Web 可执行）。

**修复建议**

使用 getimagesize()/finfo 做服务端内容检测；对扩展名做白名单并强制重命名；将上传目录置于 Web 根之外或禁用脚本执行；限制目录权限。

**验证说明**

需确认 DVWA_WEB_PAGE_TO_ROOT 常量定义与 uploads 目录是否允许 PHP 执行；本文件未包含该常量定义。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传 PHP webshell，再访问落地文件触发执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /045.php）：针对 045.php（POST）的不安全文件上传（CWE-434）POC。上传入口为 multipart 表单字段 `uploaded`，注入通道是 multipart 的 filename（文件名后缀未做白名单校验），payload 文件名使用 `sunset.jsp`。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:26，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现扩展名/内容类型白名单等有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：仅保留文本工件，不执行、不联网。curl 示例仅供授权测试人员手动替换 TARGET 后使用；request.http 为等价原始报文。上传内容使用无害占位串 SUNSET_POC，不包含可自动执行的破坏性代码。

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
| safety_guard | 安全防护 | 2.53 | 是 |
| surface_mapper | 攻击面测绘 | 8.37 | 是 |
| deep_finder | LLM 深挖 | 8.7 | 是 |
| candidate_screener | 候选筛选 | 3.75 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.14 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.73 | 是 |
| coordinator | 管线协调 | 7.06 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
