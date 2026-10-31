# 落日二号乙漏洞挖掘报告 — 20261031-002327-9d9df2

- 生成时间：2026-10-30T16:24:14.270452+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\044.zip`
- 输入模式：`zip`
- SHA256：`3d813153119636f5c8c7ceeb52e0c898d6179ed4c598625db3defa0dff283e44`
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

本次汇总仅包含 1 个文件 044.php（PHP 单文件脚本，19 行）的 2 条已去重发现，均为 file_upload 类型：GEN-7d549df94451（critical，规则命中，行 9 附近）与 LLM-6ccece6535f3（high，模型推断，行 16 附近），描述一致指向无限制文件上传导致任意 PHP 文件写入 Web 目录，可进一步导致 RCE。最高危为 GEN-7d549df94451（critical，CWE-434）。两条发现均标记 has_poc=true，POC 齐全，但均为基于源码的静态/HTTP 请求构造文本，未做动态验证。需注意：输入未提供 044.php 源码片段，行号与数据流细节无法在本级复核，证据等级为 llm_inferred 与规则命中混合。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 044.php（19 行，DVWA 文件上传示例）。逐行审计确认：入口为 POST 参数 Upload + $_FILES['uploaded']，sink 为 044.php:9 的 move_uploaded_file，中间仅 basename() 处理文件名，无扩展名/MIME/内容白名单，也无认证，构成无限制文件上传→RCE 的闭合链，已作为 high 级 finding 交付。其余攻击面：文件内无 SQL、命令执行、反序列化、include/require、eval、md5/sha1、rand、setcookie 等调用，故 weak_hash/weak_random/insecure_cookie/trust_boundary 等配置型候选在本文件中均无证据，不单独立项。未覆盖范围：缺少 Web 服务器与 php.ini 配置，无法确认上传目录是否禁止 PHP 执行、display_errors 状态；DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，其取值依赖外部包含文件，属未闭合线索。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 hackable/uploads/ 目录的 Web 可访问性/执行策略未在 code_pack 中提供
- 无 Web 服务器与 php.ini 配置，无法确认上传目录是否禁用脚本执行
- 无认证/会话配置证据，无法判断该脚本是否对外匿名可达

## 3. Findings

### F-1: 044.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.6`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 multipart/form-data 向 044.php 提交文件字段 `uploaded`，PHP 将临时文件路径放入 `$_FILES['uploaded']['tmp_name']`。044.php:9 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 把该临时文件移动到 `$target_path`，在给出的代码片段（044.php:7-9）中未见任何扩展名白名单、MIME 校验、文件内容检查或 `$target_path` 的规范化/固定目录约束，因此上传文件的原始文件名/路径与内容均未受控校验即落盘。校验无效的原因：唯一的安全相关操作是 `move_uploaded_file` 本身，它只保证源是合法上传临时文件，并不限制目标路径与文件类型；`$target_path` 的构造逻辑位于片段之外（044.php:1-6 未在证据中给出），其是否由用户可控文件名拼接无法从现有证据确认，属于证据不足部分。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 044.php:9 的不安全文件上传（CWE-434）POC，入口为 /044（任意方法）。上传字段 `uploaded` 的 filename 可控，可指定 .jsp 等可执行扩展名。目标地址使用 TARGET 占位符，仅限授权测试。

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

若 `$target_path` 落在 Web 可访问目录且保留可执行扩展名（如 .php），攻击者可上传 webshell 实现远程代码执行；即使不可执行，也可造成任意文件覆盖写入、磁盘占用与内容篡改。具体可利用性取决于 `$target_path` 的构造方式与目录可访问性，该部分证据不足。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：044.php 为可直接 HTTP 访问的脚本，上传字段 `uploaded` 无需认证即可提交（片段中未见任何鉴权/会话校验）。利用链闭合度：source（`$_FILES['uploaded']['tmp_name']`）→ sink（`move_uploaded_file`，044.php:9）在片段内闭合；但目标路径 `$target_path` 的赋值未在证据中给出，故「写入 Web 目录并可执行」这一环为推断而非已验证，置信度相应下调。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并基于服务端解析的真实 MIME 与文件头校验，不信任 `$_FILES['uploaded']['type']` 与客户端文件名；2) 目标文件名由服务端生成（UUID + 白名单扩展名），禁止将用户文件名拼入 `$target_path`；3) 用 `basename()` 剥离路径并用 `realpath()` 校验最终路径位于固定上传目录内，防止路径穿越；4) 上传目录置于 Web 根之外，或通过 Nginx/Apache 配置禁止该目录执行脚本（`php_flag engine off` / `location ~ \.php$ { deny all; }`）；5) 限制文件大小与类型，上传后重命名并去除可执行权限。

**验证说明**

静态证据：入口 ANY /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart POST 请求到 044.php，文件字段名为 `uploaded`，内容为恶意脚本。PHP 解析请求后把临时文件路径写入 `$_FILES['uploaded']['tmp_name']`；044.php:9 将该临时文件直接 `move_uploaded_file` 到 `$target_path`，过程中无扩展名/内容/路径校验，文件以攻击者可控（或至少未受控）的名称落盘。若落盘目录可被 Web 访问且扩展名可执行，攻击者随后请求该文件即获得代码执行。`$target_path` 的具体来源在给定片段中缺失，故该环为基于源码的推断。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434。漏洞位于 044.php:9，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未见有效净化。
POC 备注：仅文本工件，不执行、不联网。原草稿中的 `-X ANY` 非合法 HTTP 方法，实际发送时请改为 POST（或按服务端实际接受的方法）；TARGET 为占位符，需替换为授权测试实例。上传内容仅为标记字符串。

### F-2: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" 目录，并调用 move_uploaded_file() 落盘。全程没有扩展名白名单、MIME 校验、getimagesize 检查、文件大小限制或随机重命名，攻击者可上传 .php 文件到 Web 可访问目录并直接请求执行，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 于 044.php:9

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支，无任何认证或 CSRF 校验 | 攻击者控制请求体 |  |
| 2 | `044.php:6` | 取上传文件名 $_FILES['uploaded']['name']，仅经 basename() 去除路径部分，保留完整文件名与扩展名 | 原始文件名 shell.php，basename 后仍为 shell.php | basename() 只剥离目录，不做扩展名/类型白名单，无法阻止 .php |
| 3 | `044.php:5-6` | 拼接目标路径 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/" + 文件名，落在 Web 可访问目录 | 目标路径 .../hackable/uploads/shell.php |  |
| 4 | `044.php:9` | move_uploaded_file 将临时文件移动到目标路径，无 MIME/内容/扩展名校验 | PHP 脚本落盘到 Web 目录 |  |
| 5 | `044.php:15` | 成功分支回显完整落盘路径，攻击者据此得知访问 URL | 响应泄露绝对路径 |  |

**POC**

针对 /044.php（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/044.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/044.php' \
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

攻击者可在 Web 目录写入任意 PHP 代码并执行，获得服务器命令执行权限，完全控制应用与主机。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部可直接通过 HTTP multipart 触发，无需认证（脚本本身无鉴权），source→sink 链在 044.php:3-9 完整闭合，落盘目录位于 Web 根下可被直接请求执行。

**修复建议**

实施扩展名白名单（仅允许图片类型）、校验 MIME 与 getimagesize、随机重命名文件、将上传目录置于 Web 根之外或禁用该目录 PHP 执行（php_flag engine off / Nginx location 拒绝 .php），并加入认证与 CSRF 防护。

**验证说明**

需确认 DVWA_WEB_PAGE_TO_ROOT 常量定义与 hackable/uploads/ 的实际可访问性及是否允许执行 PHP；若上传目录被服务器配置禁止执行脚本，则降级为任意文件写入。
模型 POC 要点：上传一个 PHP webshell 到 hackable/uploads/，随后直接请求该文件执行命令。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /044.php）：针对 044.php:16 的不安全文件上传（CWE-434）POC。上传入口为 multipart 字段 `uploaded`，攻击者通过 `filename` 指定可执行扩展名（如 .jsp），若上传目录可被 Web 容器解析，则可导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /044.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 044.php:16，外部输入来自 multipart 字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未见扩展名白名单或内容校验。
POC 备注：仅文本工件，不执行、不联网。poc.sh 与 request.http 保留原请求结构，TARGET 为占位符；执行前需替换为授权测试实例并人工确认。上传内容仅为标记字符串，不含任何可执行/破坏性代码。

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
| safety_guard | 安全防护 | 2.5 | 是 |
| surface_mapper | 攻击面测绘 | 9.66 | 是 |
| deep_finder | LLM 深挖 | 8.98 | 是 |
| candidate_screener | 候选筛选 | 4.19 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.63 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.01 | 是 |
| coordinator | 管线协调 | 6.87 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
