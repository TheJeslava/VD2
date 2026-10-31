# 落日二号乙漏洞挖掘报告 — 20261031-010418-fb638a

- 生成时间：2026-10-30T17:05:00.257728+00:00
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

本次汇总仅包含 1 个文件 044.php（单文件 PHP 脚本，19 行）的审计结果，共 2 条去重后 finding，全部为 file_upload 类型：规则命中 GEN-7d549df94451（critical，第 9 行，任意文件写入 CWE-434）与 LLM 推断 LLM-6ccece6535f3（high，第 16 行，未校验类型/扩展名导致上传 PHP 脚本 RCE）。最高危为 GEN-7d549df94451（critical）。两条均带 POC，但均为静态源码证据 POC，未做动态验证，不能宣称可动态复现。其余攻击面（注入、XSS、路径穿越、SSRF、命令执行、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码凭据）本次均无 finding 交付，且 surface_notes 明确说明未提供 044.php 源码内容，属覆盖不足而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 code_pack 中唯一文件 044.php（19 行）。该文件为 DVWA 文件上传功能，未做任何类型/扩展名校验，直接 move_uploaded_file 到 Web 可访问目录，构成无限制文件上传→RCE 的闭合链。未发现 SQL 注入、命令注入、反序列化、SSRF、路径穿越等其它汇点。DVWA_WEB_PAGE_TO_ROOT 常量定义、上传目录执行权限、部署配置不在 code_pack 内，属未闭合证据缺口。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义未提供
- Web 服务器对 hackable/uploads/ 的 PHP 执行策略未知
- 无路由/认证配置，无法确认访问控制

## 3. Findings

### F-1: 044.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`044.php:7-9`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件，PHP 将其临时文件路径放入 `$_FILES['uploaded']['tmp_name']`，随后在 044.php:9 直接调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` 把上传内容移动到 `$target_path`。代码片段（044.php:7-9）中，在调用 `move_uploaded_file` 之前没有任何扩展名白名单、MIME 类型校验、文件内容检查或文件名规范化处理；`$target_path` 的构造逻辑未在给定片段中体现，但汇点处对上传文件不做任何类型/后缀约束，因此校验缺失，上传内容被原样落盘。

**source / sink**

- source：upload `uploaded`（044.php:9）
- sink：044.php:9 if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:9` | 从 upload `uploaded` 读取外部输入 | 污点进入 内联表达式 |  |
| 2 | `044.php:9` | 危险汇点：if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 044.php（路由 /044，方法 ANY）的不安全文件上传（CWE-434）POC。与 LLM-6ccece6535f3 为同一上传逻辑的另一路由/方法表述，上传入口同为 multipart 字段 `uploaded`，通过 filename 指定可执行扩展名。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

攻击者可上传 .php/.phtml 等可执行脚本到 Web 可访问目录，通过访问该文件触发服务端代码执行，进而获得 Web 进程权限下的远程代码执行（RCE）；也可用于覆盖/写入任意可写路径文件、投放 webshell、作为进一步横向移动的据点。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP multipart 请求的 `uploaded` 字段，无需认证即可访问 044.php；利用链闭合：`$_FILES['uploaded']['tmp_name']` → `move_uploaded_file(..., $target_path)` → 文件落盘至 Web 目录 → 请求该文件执行。缺少扩展名/类型校验是链闭合的关键缺口。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/gif/pdf）并基于服务端解析的真实 MIME 与文件头（finfo）双重校验；2) 上传文件名由服务端随机生成，禁止使用客户端提供的文件名；3) 上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 Nginx `location ~ \.php$ { deny all; }`）；4) 限制文件大小与数量；5) 以最小权限账户运行 Web 进程，落盘目录不可执行。

**验证说明**

静态证据：入口 ANY /044；source=upload/uploaded；sink=044.php:9；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，向 044.php 的 `uploaded` 字段提交名为 shell.php 的恶意脚本 → PHP 解析为 `$_FILES['uploaded']`，临时文件路径进入 `tmp_name` → 044.php:9 未做任何后缀/类型校验即调用 `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` → 文件被移动到目标路径 → 攻击者访问该 URL，服务端解析执行，达成 RCE。
PocWriter 建议（未采纳，缺少端点 /044）：符合 CWE-434（不受限制的危险类型文件上传）。漏洞位于可交付代码 044.php:9，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效扩展名/内容类型净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：poc.sh 与 request.http 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权目标并确认授权范围；上传内容使用无害占位串 SUNSET_POC，不包含实际 webshell 代码。

### F-2: DVWA 上传接口 044.php 未校验文件类型/扩展名，可上传 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.85`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 时，直接取 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到上传目录 DVWA_WEB_PAGE_TO_ROOT."hackable/uploads/"，并调用 move_uploaded_file() 落盘。代码未做任何扩展名白名单、MIME 校验、getimagesize 检查或内容检测，攻击者可上传 .php 文件到 Web 可访问目录，随后直接请求该文件即可执行任意 PHP 代码，形成 RCE。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file( $_FILES['uploaded']['tmp_name'], $target_path ) 于 044.php:9

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支，无认证/CSRF 校验 | 攻击者控制请求体 |  |
| 2 | `044.php:6` | 取上传文件名并 basename() 处理，仅剥离路径部分，不限制扩展名 | basename 后的原始文件名（如 shell.php） | basename 只做路径规范化，不构成扩展名白名单 |
| 3 | `044.php:5-6` | 拼接目标路径为 hackable/uploads/ + 文件名 | hackable/uploads/shell.php |  |
| 4 | `044.php:9` | move_uploaded_file 将临时文件移动到 Web 可访问目录，无类型/内容校验 | 恶意 PHP 文件落盘 |  |
| 5 | `044.php:15` | 响应回显完整落盘路径，便于攻击者确认上传位置 | 泄露绝对路径 |  |

**POC**

针对 044.php（POST /044.php）的不安全文件上传（CWE-434）POC。上传入口为 multipart 表单字段 `uploaded`，攻击者通过 `filename` 指定可执行扩展名（如 .jsp），若服务器将上传文件写入 Web 可访问目录且未校验扩展名/内容类型，则可导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

任意文件上传导致远程代码执行，攻击者可完全控制 Web 服务器。

**CVE / CWE 论证**

CWE-434 无限制文件上传。外部可直接 POST 触发，无需认证（脚本内无鉴权），链闭合：上传文件名→拼接路径→move_uploaded_file→Web 访问执行。

**修复建议**

实施扩展名白名单、校验 MIME 与 getimagesize、重命名上传文件、将上传目录置于 Web 根之外或禁用该目录 PHP 执行。

**验证说明**

需确认 hackable/uploads/ 目录是否允许执行 PHP（Apache/Nginx 配置），以及 DVWA_WEB_PAGE_TO_ROOT 常量定义位置（不在 code_pack 内）。
模型 POC 要点：上传一个 PHP webshell 到 hackable/uploads/，再访问该文件执行命令
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /044.php）：符合 CWE-434（不受限制的危险类型文件上传）。漏洞位于可交付代码 044.php:16，外部输入来自 multipart 上传字段 `uploaded` 的 filename，source→sink 链在给定代码范围内静态闭合，未发现有效扩展名/内容类型净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：poc.sh 与 request.http 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权目标并确认授权范围；上传内容使用无害占位串 SUNSET_POC，不包含实际 webshell 代码。

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
| safety_guard | 安全防护 | 2.46 | 是 |
| surface_mapper | 攻击面测绘 | 8.22 | 是 |
| deep_finder | LLM 深挖 | 7.26 | 是 |
| candidate_screener | 候选筛选 | 3.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.45 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.1 | 是 |
| coordinator | 管线协调 | 5.49 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
