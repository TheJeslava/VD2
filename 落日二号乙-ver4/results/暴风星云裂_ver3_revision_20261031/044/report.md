# 落日二号乙漏洞挖掘报告 — 20261031-012124-99aeae

- 生成时间：2026-10-30T17:22:09.368489+00:00
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

本次汇总仅涉及单文件 PHP 脚本 044.php（19 行），去重后共 2 条 findings，均为 file_upload 类型：规则命中 GEN-7d549df94451（critical，第 9 行 move_uploaded_file 落盘缺少类型/扩展名校验，CWE-434）与 LLM 推断 LLM-6ccece6535f3（high，第 16 行，无限制上传导致任意 PHP 文件写入 web 目录，可 RCE）。最高危为 GEN-7d549df94451（critical），两条均带 POC（has_poc=true，with_poc=2），但 POC 属静态构造文本，未做动态验证。攻击面测绘指出 044.php 为 source 热点、sink 热点为空，且未提供任何源码片段，因此除上传外的注入/路径/命令执行面均停留在推断层面（llm_inferred），未形成 findings。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 044.php（19 行），已完整审计。该文件为 DVWA 文件上传模块，存在无限制文件上传（CWE-434）：上传文件名仅经 basename() 处理即拼入 web 可访问的 hackable/uploads/ 目录，无扩展名/类型/内容校验，可上传 PHP 文件实现 RCE。未发现 SQL 注入、命令注入、路径穿越、反序列化、SSRF、XSS 等其他可闭合链；配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在该文件中均无对应实现。未覆盖范围：无 php.ini/服务器配置、无路由与认证配置、无依赖清单，无法确认运行时是否禁用 uploads 目录的 PHP 执行及端点认证要求。

未覆盖 / 证据缺口：
- 无服务器/php.ini 配置，无法确认 uploads 目录是否允许执行 PHP
- 无路由与认证配置，无法确认端点是否需登录
- 无 DVWA_WEB_PAGE_TO_ROOT 常量定义，无法确认绝对路径

## 3. Findings

### F-1: 044.php 不安全文件上传（CWE-434）：上传文件被直接 move_uploaded_file 落盘，缺少类型/扩展名校验

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交任意文件（044.php:9 的 `$_FILES['uploaded']['tmp_name']`）。代码在 044.php:9 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 将临时文件移动到目标路径，输入中给出的片段（044.php:7-9）未出现任何扩展名白名单、MIME 校验、`getimagesize()` 内容校验或文件名规范化逻辑，因此校验无效（缺失）。最终危险操作是文件写入（落盘到 `$target_path`）。需要说明的证据缺口：`$target_path` 的赋值语句不在 code_pack 片段内，其是否包含上传目录、是否由用户可控文件名拼接无法从现有证据确认；若 `$target_path` 位于 Web 可访问目录且保留原始扩展名，则可上传 .php 等可执行脚本。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /044（ANY）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/044'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/044' \
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

若上传目录可被 Web 服务器解析（如 Apache 对 .php 的处理），攻击者可上传 webshell 并获得远程代码执行（RCE），进而读取/篡改应用数据、横向移动；即使不可执行，也可造成任意文件落盘、磁盘占用、覆盖同名文件等文件写入影响。具体影响取决于 `$target_path` 的目录与命名策略（证据不足，未在片段中给出）。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP multipart 请求的 `uploaded` 字段，无需认证即可触达（片段中未见任何鉴权/会话校验）。利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file(..., $target_path)` 直接落盘，中间无白名单/内容校验，构成 source→sink 完整链路。证据等级为 llm_inferred：`$target_path` 定义与目录可执行性未在 code_pack 中体现，故不宣称已动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并同时校验 MIME 与文件头（`finfo_file`/`getimagesize`）；2) 上传文件名由服务端随机生成（UUID），不采用客户端 `name`，避免路径穿越与覆盖；3) 上传目录置于 Web 根之外，或配置 Web 服务器禁止该目录执行脚本（`php_flag engine off` / 去除 Handler）；4) 限制文件大小与数量，落盘权限最小化（非 Web 用户可写可执行）；5) 对 `$target_path` 做规范化并校验其位于允许的上传根目录内。

**验证说明**

静态证据：入口 ANY /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，在字段 `uploaded` 中附带恶意文件（如 shell.php）。PHP 将其存入临时文件 `$_FILES['uploaded']['tmp_name']`；044.php:9 未做任何类型/扩展名/内容校验，直接 `move_uploaded_file()` 移动到 `$target_path`。若目标目录可被 Web 解析且保留 .php 扩展名，攻击者随后访问该文件即可执行任意代码，完成从上传到 RCE 的闭合链路。
PocWriter 建议（未采纳，缺少端点 /044）：针对 044.php:9 的不安全文件上传（CWE-434）POC。脚本第 9 行处理上传请求，直接采用客户端提供的 multipart filename 作为保存文件名，缺少扩展名白名单与内容校验，攻击者可上传 .jsp 脚本并在 Web 目录访问执行。注入通道为 multipart 表单字段 `uploaded` 的 filename 属性。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434。漏洞位于 044.php:9，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链静态闭合，未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。上传文件内容仅为无害标记 SUNSET_POC。原草稿中 HTTP 方法写作 ANY，实际发送时应使用 POST（multipart 上传语义）；上传后访问路径以响应回显为准。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，并调用 move_uploaded_file() 落盘。代码未校验扩展名、MIME、文件内容，也未做白名单或重命名，攻击者可上传 .php 文件到 web 可访问目录，随后直接请求该文件即可在服务器执行任意 PHP 代码，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file( $_FILES['uploaded']['tmp_name'], $target_path )

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 存在，进入上传处理分支 | 攻击者控制请求体与上传文件 |  |
| 2 | `044.php:5` | 拼接上传目录前缀 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" | 固定目录前缀 |  |
| 3 | `044.php:6` | 取上传文件名，仅经 basename() 去除路径部分后直接拼接到目标路径，无扩展名/类型校验 | 攻击者可控文件名（如 shell.php）拼入 $target_path |  |
| 4 | `044.php:9` | move_uploaded_file 将临时文件移动到 web 可访问目录，文件名与内容均由攻击者控制 | 任意内容写入 hackable/uploads/shell.php |  |

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

CWE-434 无限制文件上传。外部可直接通过 HTTP multipart 请求触发，链闭合：上传文件名/内容 → move_uploaded_file 落盘到 web 目录 → 直接请求执行。

**修复建议**

使用扩展名白名单（如仅 jpg/png/gif）、校验 MIME 与文件魔数、随机重命名文件、将上传目录置于 web 根之外或禁用该目录 PHP 执行（php_flag engine off）。

**验证说明**

需确认 DVWA_WEB_PAGE_TO_ROOT 指向的 uploads 目录可被 HTTP 直接访问且允许执行 PHP；需确认该端点是否要求登录。
模型 POC 要点：上传一个 PHP webshell 到 uploads 目录，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 044.php:16 的不安全文件上传（CWE-434）POC。上传处理逻辑直接使用 multipart 请求中的 filename 作为落盘文件名，未对扩展名/内容类型做白名单校验，攻击者可上传 .jsp 等可执行脚本并在 Web 目录下访问执行。注入通道为 multipart 表单字段 `uploaded` 的 filename 属性。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 044.php:16，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链静态闭合，未见扩展名/内容类型白名单或重命名等有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。上传文件内容仅为无害标记 SUNSET_POC，不含反弹 shell 或破坏性载荷。执行前需将 TARGET 替换为授权实例地址，并确认上传目录路径（示例为 /vulnerabilities/hackable/uploads/，实际以响应回显为准）。

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
| safety_guard | 安全防护 | 2.35 | 是 |
| surface_mapper | 攻击面测绘 | 10.53 | 是 |
| deep_finder | LLM 深挖 | 7.54 | 是 |
| candidate_screener | 候选筛选 | 3.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.57 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.25 | 是 |
| coordinator | 管线协调 | 7.3 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
