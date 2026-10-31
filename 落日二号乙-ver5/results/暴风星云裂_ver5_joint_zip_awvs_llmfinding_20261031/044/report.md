# 落日二号乙漏洞挖掘报告 — 20261031-214851-3f74ba

- 生成时间：2026-10-31T13:49:42.205897+00:00
- 输入：`$WORKSPACE\暴风星云裂\044.zip`
- 输入模式：`zip`
- SHA256：`3d813153119636f5c8c7ceeb52e0c898d6179ed4c598625db3defa0dff283e44`
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

本次汇总仅覆盖单文件 PHP 脚本 044.php（19 行、511 字节），共 2 条去重后 finding，均为 file_upload（CWE-434）：规则命中 GEN-7d549df94451（critical，上传文件被直接移动到目标路径，缺少扩展名/类型校验，行 1-9）与 LLM 推断 LLM-6ccece6535f3（high，无限制上传导致任意 PHP 写入 Web 目录，行 1-16）。最高危为 GEN-7d549df94451，其证据来自静态规则且落在 044.php 行范围内，属可复现的 HTTP 上传类问题。两条 finding 均标记 has_poc=true，POC 文本齐全，但均为静态构造的 HTTP 上传 POC（TARGET 占位），本次未执行、未做动态验证。需注意：surface_notes 明确说明本次上下文未提供 044.php 的代码行内容，因此除上传路径外的注入类、路径包含类、配置类风险均无法确认，属未覆盖而非不存在。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 044.php（19 行），已逐行审计。该文件为 DVWA 文件上传模块，存在无限制文件上传（CWE-434）：$_FILES['uploaded']['name'] 经 basename 后直接拼接到 hackable/uploads/ 并由 move_uploaded_file 落盘，无扩展名/MIME/内容校验，可上传 PHP webshell 实现 RCE，链完整闭合。未发现 SQL 注入、命令注入、路径穿越、反序列化、SSRF、弱哈希/弱随机/不安全 Cookie 等其它汇点（文件内无 md5/sha1/rand/setcookie/exec/include 等调用）。未覆盖范围：无 php.ini/Web 服务器配置、无路由与认证配置、无依赖清单，因此无法评估运行时是否禁用上传目录脚本执行、是否存在前置认证网关；DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，其具体值未确认（推断为 Web 根路径）。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义未在 code_pack 中，落盘绝对路径依赖该常量
- 无 Web 服务器/php.ini 配置，无法确认上传目录是否允许 PHP 执行
- 无认证/路由配置，无法确认 044.php 是否被前置鉴权保护

## 3. Findings

### F-1: 044.php 不安全文件上传（CWE-434）：上传文件被直接移动到目标路径，缺少扩展名/类型校验

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 multipart 表单字段 `uploaded` 提交文件（044.php:9 的 `$_FILES['uploaded']['tmp_name']`）。代码在 044.php:9 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)`，把临时文件移动到 `$target_path`。输入片段中未见任何扩展名白名单、MIME 校验、`getimagesize()` 内容校验或文件名规范化逻辑；`$target_path` 的构造代码不在本次 code_pack 片段内（仅给出第 7-9 行），因此目标目录是否位于 Web 可访问路径、文件名是否由用户可控（如 `$_FILES['uploaded']['name']`）属于证据不足，需结合 044.php 第 1-6 行确认。就已给出的证据看，唯一约束是 `move_uploaded_file` 的返回值判断，它只反映移动是否成功，不构成安全校验。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 044.php 的不安全文件上传（CWE-434）POC，入口写作 POST /044（无 .php 后缀，依赖容器/重写映射到 044.php）。multipart 字段 uploaded 携带 filename=sunset.jsp，触发字段 Upload=Upload。源码 044.php:9 处对上传文件缺少类型/扩展名校验。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

若 `$target_path` 落在 Web 根目录下且保留原始扩展名，攻击者可上传 `.php` 等可执行脚本，通过 HTTP 请求触发，形成远程代码执行（RCE）；即使不可执行，也可造成任意文件落盘、覆盖已有文件、磁盘占用，以及上传恶意 HTML/JS 用于钓鱼或存储型 XSS。具体影响等级取决于 `$target_path` 的目录位置与命名方式，该部分证据不足。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP multipart 请求的 `uploaded` 字段，无需认证（片段中未见任何鉴权/会话检查）。利用链闭合度：source（`$_FILES['uploaded']['tmp_name']`）→ sink（`move_uploaded_file`）在同一行完成，中间无净化函数；但链的最后一环（目标路径可 Web 访问、文件名可控）依赖 044.php 第 1-6 行，当前片段未覆盖，故按 llm_inferred 记录，置信度 0.68。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf），并对上传内容做魔数或 `getimagesize()` 校验，不能只信 `$_FILES['uploaded']['type']`；2) 不要使用用户提供的文件名，改为服务端生成的随机名（如 `bin2hex(random_bytes(16))` + 白名单扩展名）；3) 将上传目录置于 Web 根之外，或在该目录禁用脚本执行（Apache `php_flag engine off` / Nginx `location ~ \.php$ { deny all; }`）；4) 限制文件大小与数量，校验 `is_uploaded_file()`；5) 上传目录设置最小权限，禁止覆盖已有文件。

**验证说明**

静态证据：入口 POST /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart POST 请求，文件字段名为 `uploaded`，内容为 PHP 脚本。PHP 将临时文件路径放入 `$_FILES['uploaded']['tmp_name']`；044.php:9 未做任何类型/扩展名校验，直接 `move_uploaded_file()` 到 `$target_path`。随后攻击者访问该落盘文件的 URL，若目录可执行则代码被执行。片段未展示 `$target_path` 的赋值，故该步为推断。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434。漏洞位于 044.php:9，外部输入来自 multipart 字段 uploaded 的 filename，source→sink 链在给定代码范围内静态闭合，未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；执行需人工替换 TARGET 并在授权环境进行。/044 到 044.php 的映射与落盘路径源码未给出，需补充确认。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.96`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，并调用 move_uploaded_file() 落盘。全程没有扩展名白名单、MIME 校验、getimagesize() 图像校验、文件大小限制或随机重命名，攻击者可上传 .php 文件到 Web 可访问的 hackable/uploads/ 目录，随后直接请求该文件即可执行任意 PHP 代码，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 于 044.php:9

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 存在即进入上传处理分支，无任何认证或 CSRF 校验 | 攻击者控制请求体 |  |
| 2 | `044.php:5-6` | 拼接目标路径：固定前缀 hackable/uploads/ 加上 basename($_FILES['uploaded']['name'])，basename 仅去掉目录部分，不限制扩展名 | 文件名原样保留（如 shell.php） | basename 只做路径截断，不做扩展名/MIME 白名单 |
| 3 | `044.php:9` | move_uploaded_file 将临时文件移动到 Web 可访问目录，无扩展名、内容、大小校验 | 任意内容写入 hackable/uploads/shell.php |  |
| 4 | `044.php:15` | 响应回显完整落盘路径，攻击者据此得知上传文件 URL | 泄露绝对路径 |  |

**POC**

针对 044.php 的不安全文件上传（CWE-434）POC。上传入口为 POST /044.php，multipart 表单字段 uploaded 携带文件名 sunset.jsp，触发字段 Upload=Upload。源码 044.php:16 处对上传文件未做扩展名/类型白名单校验即落盘，攻击者可上传可被服务端解析的脚本文件。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

未认证攻击者可在 Web 根目录写入并执行任意 PHP 代码，完全控制服务器（读取配置、数据库凭据、横向移动）。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部 HTTP 可达、无需认证、source→sink 链在 044.php:3-9 完整闭合，落盘路径位于 Web 可访问目录且响应回显路径，可直接触发 RCE。

**修复建议**

使用扩展名白名单（仅允许图片等安全类型）、校验 MIME 与 getimagesize()、随机重命名文件、将上传目录置于 Web 根之外或禁止该目录执行 PHP（php_flag engine off / location 拒绝 .php），并加入认证与 CSRF 校验。

**验证说明**

需确认 hackable/uploads/ 目录存在且可写、Web 服务器对上传目录的 PHP 解析策略；DVWA 默认环境通常满足，但生产环境可能禁用上传目录脚本执行。
模型 POC 要点：上传一个 PHP webshell 到 hackable/uploads/，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Unrestricted File Upload @ http://127.0.0.1:18081/044.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /044.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 044.php:16，外部输入来自 multipart 字段 uploaded 的 filename，source→sink 链在给定代码范围内静态闭合，未见扩展名/内容类型白名单或重命名等有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；执行需人工替换 TARGET 并在授权环境进行。落盘路径与解析映射源码未给出，步骤 3 的 URL 需按实际部署补充。

**外部佐证**

- awvs: Unrestricted File Upload @ http://127.0.0.1:18081/044.php

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
| `LLM-6ccece6535f3` | Unrestricted File Upload | http://127.0.0.1:18081/044.php | corroborated |

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
| safety_guard | 安全防护 | 4.11 | 是 |
| surface_mapper | 攻击面测绘 | 8.87 | 是 |
| deep_finder | LLM 深挖 | 9.87 | 是 |
| candidate_screener | 候选筛选 | 4.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.77 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.31 | 是 |
| coordinator | 管线协调 | 7.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
