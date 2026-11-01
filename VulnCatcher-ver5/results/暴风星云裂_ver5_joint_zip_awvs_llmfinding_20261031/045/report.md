# 落日二号乙漏洞挖掘报告 — 20261031-214902-7dcb30

- 生成时间：2026-10-31T13:49:56.290619+00:00
- 输入：`$WORKSPACE\暴风星云裂\045.zip`
- 输入模式：`zip`
- SHA256：`a0b2458750b044b980ebfd21404d68504f146fb80f29769046d1fc1c3577d5c4`
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

本次汇总基于已去重的 2 条 findings，全部集中在唯一文件 045.php 的文件上传缺陷：规则命中 GEN-60f80eecf7e1（critical，045.php:18，CWE-434 任意文件写入）与 LLM 命中 LLM-916b10bd8caa（high，045.php:26，仅校验客户端可控 MIME 即可上传 PHP 脚本导致 RCE）。两者为同一上传端点的不同证据视角，最高危为 critical 级任意文件写入，可进一步演化为远程代码执行。两条 finding 均带 POC（with_poc=2），但均为基于源码的静态构造，未做动态验证，不能宣称已可复现。本次无二次注入链、无 prompt_injection 证据。需特别说明：surface_notes 明确指出输入未提供 045.php 代码正文，注入类与配置类结论均无法成立，因此除文件上传外的攻击面仍处于未验证状态。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：CODE PACK 仅含单文件 045.php（33 行，DVWA 文件上传练习代码）。已逐行审计：唯一外部输入为 multipart 上传字段 uploaded，其 Content-Type 与文件名均由客户端控制，仅做 MIME 字符串与大小比较（045.php:14-15），随后 move_uploaded_file 写入 Web 根下 hackable/uploads/（045.php:5-6,18），构成可闭合的任意文件上传→RCE 链。未发现 SQL/命令/路径/反序列化/SSRF 汇点；无 setcookie/session/md5/rand 等配置类线索，故不报告 weak_hash/weak_crypto/insecure_cookie。未覆盖：DVWA_WEB_PAGE_TO_ROOT 定义、上传目录执行策略、认证前置、Web 服务器配置均不在 CODE PACK 内。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与上传目录是否可执行 PHP 未知
- 045.php 是否位于认证之后、实际路由未知
- 无 php.ini/Web 服务器配置，无法确认上传目录执行策略

## 3. Findings

### F-1: 045.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`045.php:16-18`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传表单字段 `uploaded` 提交文件，PHP 将其暂存于 `$_FILES['uploaded']['tmp_name']`（045.php:18）。代码在 045.php:18 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 将临时文件移动到 `$target_path`，在给出的代码片段（045.php:16-18）中未见对文件扩展名、MIME 类型、文件内容或目标路径的任何白名单校验，也未见对 `$target_path` 的规范化与目录限制。因此上传文件的原始名称/类型未经净化即被持久化落盘，校验环节缺失，污点从 `$_FILES['uploaded']` 直达文件写入汇点。注意：`$target_path` 的赋值语句不在本次给出的片段范围内，其具体构造方式（是否拼接用户可控文件名）证据不足，需结合 045.php 更早行确认。

**source / sink**

- source：upload `uploaded`（045.php:18）
- sink：045.php:18 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:18` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `045.php:18` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 045.php 第 18 行不安全文件上传（CWE-434）的文本 POC。入口为 POST /045 的 multipart 表单，文件字段 uploaded、触发按钮字段 Upload；通过 filename 提交 .jsp 文件，若上传目录可被解析则可导致 RCE。目标地址使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/045' \
  -F 'Upload=Upload' \
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

攻击者可上传任意内容与扩展名的文件（如 .php/.phtml/.phar），若上传目录位于 Web 可访问路径且允许脚本执行，则可进一步实现远程代码执行（RCE）；即使不可执行，也可造成任意文件写入、覆盖已有文件、磁盘占满，或作为钓鱼/恶意载荷托管点。属于高危的任意文件上传。

**CVE / CWE 论证**

对应 CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 表单字段 `uploaded`，无需认证即可访问该脚本（片段中未见任何鉴权/会话校验）。利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file(..., $target_path)`（045.php:18），中间无扩展名/类型/内容校验，落盘即完成。证据等级为源码推断（llm_inferred），未做动态验证；`$target_path` 的构造细节因不在片段内而证据不足。

**修复建议**

1) 对上传文件建立扩展名与 MIME 类型双重白名单，仅允许业务必需的类型（如 jpg/png/pdf），并校验文件魔数而非仅信任 Content-Type；2) 使用服务端生成的随机文件名（如 UUID）替代客户端文件名，禁止路径分隔符与 `..`；3) 将上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 Nginx `location ~ \.php$ { deny all; }`）；4) 限制文件大小与数量，落盘后设置最小权限（非可执行）；5) 对图片等可做二次编码/重采样以剥离潜在载荷；6) 上传接口增加认证与 CSRF 防护。

**验证说明**

静态证据：入口 POST /045；source=upload/uploaded；sink=045.php:18；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 045.php 提交字段名为 `uploaded` 的文件。PHP 将文件写入临时路径 `$_FILES['uploaded']['tmp_name']`。045.php:18 调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)`，由于片段中不存在扩展名/类型/内容白名单与目标路径规范化，攻击者可控的文件被原样移动到 `$target_path` 指向的位置。若该位置在 Web 可访问目录且允许脚本解析，攻击者随后请求该文件即可执行任意代码，形成从上传到 RCE 的完整链路。
PocWriter 建议（未采纳，缺少端点 /045）：符合 CWE-434 不受限文件上传。漏洞位于 045.php:18，外部输入来自 multipart 文件字段 uploaded 的 filename，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单或内容校验。
POC 备注：仅文本工件，不执行、不联网。poc.sh 中 curl 命令仅供授权人员手工替换 TARGET 后运行；request.http 为等价原始报文。上传后文件路径需依据 045.php:18 的保存逻辑或第 2 步响应确认，源码片段未给出目录时不得臆造。

### F-2: DVWA 上传端点 045.php 仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本并导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `externally_corroborated`
- **位置**：`045.php:3-26`
- **来源**：`llm_finding`

**描述**

045.php 通过 $_FILES['uploaded']['type']（即 HTTP 请求中的 Content-Type，完全由客户端控制）判断文件是否为图片，未使用 getimagesize()/finfo 等服务端内容检测，也未校验扩展名。攻击者把 PHP 脚本的 Content-Type 伪造成 image/jpeg 并保持体积小于 100000 字节，即可通过校验；随后 move_uploaded_file() 以 basename(原始文件名) 将其写入 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/"，文件名与扩展名均保留（如 shell.php）。该目录位于 Web 根下，直接请求即可执行任意 PHP 代码，形成 RCE。

**source / sink**

- source：upload `uploaded`（045.php:9-11）
- sink：045.php:26 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 Web 可访问目录 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | POST 参数 Upload 存在即进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `045.php:9-11` | 从 $_FILES 读取文件名、Content-Type、大小 | 文件名 shell.php、type image/jpeg、size 小于 100000，全部由客户端决定 |  |
| 3 | `045.php:14-15` | 仅比较客户端提交的 MIME 字符串与大小 | 伪造 Content-Type: image/jpeg 即满足条件 | $uploaded_type 来自请求头 Content-Type，非服务端内容嗅探；无扩展名白名单、无 getimagesize 校验 |
| 4 | `045.php:5-6` | 拼接目标路径为上传目录 + basename(原始文件名) | $target_path = <webroot>/hackable/uploads/shell.php |  |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到 Web 根下目录 | PHP 脚本落盘为可访问文件 |  |

**POC**

针对 045.php 第 26 行不安全文件上传（CWE-434）的文本 POC。上传入口为 POST /045.php 的 multipart 表单，文件字段名为 uploaded，触发按钮字段为 Upload；攻击者通过 filename 提交 .jsp 文件，若上传目录可被 Web 容器解析，则可导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/045.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/045.php' \
  -F 'Upload=Upload' \
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

任意文件上传导致 Web 服务器上的远程代码执行，攻击者可完全控制应用与主机（在 Web 进程权限内）。

**CVE / CWE 论证**

CWE-434 无限制危险类型文件上传。外部可直接 POST 触发，脚本无认证/授权检查，Content-Type 校验可被请求头伪造绕过，链闭合至 move_uploaded_file 落盘 Web 目录。

**修复建议**

使用 finfo/getimagesize 做服务端内容检测；对扩展名与 MIME 双重白名单；上传目录置于 Web 根之外或禁用脚本执行；重命名为随机名并去除原始扩展名。

**验证说明**

需确认 DVWA_WEB_PAGE_TO_ROOT 指向 Web 根、hackable/uploads 可执行 PHP、以及 045.php 是否位于认证之后；这些运行时条件未在 CODE PACK 中给出。
模型 POC 要点：伪造 Content-Type 上传 PHP webshell，再访问上传路径执行
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
AWVS 外部佐证：Unrestricted File Upload @ http://127.0.0.1:18081/045.php（未在本管线执行扫描）。
PocWriter 建议（未采纳，缺少端点 /045.php）：符合 CWE-434 不受限文件上传。漏洞位于 045.php:26，外部输入来自 multipart 文件字段 uploaded 的 filename，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单或内容校验。
POC 备注：仅文本工件，不执行、不联网。poc.sh 中 curl 命令仅供授权人员手工替换 TARGET 后运行；request.http 为等价原始报文。上传后文件路径需依据 045.php:26 的保存逻辑或第 2 步响应确认，源码片段未给出目录时不得臆造。

**外部佐证**

- awvs: Unrestricted File Upload @ http://127.0.0.1:18081/045.php

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
| `LLM-916b10bd8caa` | Unrestricted File Upload | http://127.0.0.1:18081/045.php | corroborated |

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
| safety_guard | 安全防护 | 4.86 | 是 |
| surface_mapper | 攻击面测绘 | 11.64 | 是 |
| deep_finder | LLM 深挖 | 9.36 | 是 |
| candidate_screener | 候选筛选 | 4.27 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.77 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.15 | 是 |
| coordinator | 管线协调 | 7.93 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
