# 落日二号乙漏洞挖掘报告 — 20261031-010414-4dbdb4

- 生成时间：2026-10-30T17:04:59.710090+00:00
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

本次汇总仅含 1 条已去重 finding：043.php 的不安全文件上传（CWE-434，critical，rule 来源），上传文件被直接 move_uploaded_file 落到目标路径，缺少扩展名/类型校验，POC 已具备（静态文本 POC，未执行、未动态验证）。最高危即此条，也是唯一一条。整体攻击面极小：单文件 PHP（35 行），无框架、无路由、无端点登记，sink 热点为空，污点入口已定位但流向未闭合。POC 齐全度：1/1 有 POC，但均为静态证据，不能宣称可动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 043.php（35 行，DVWA upload 模块）。已逐行审计：入口为 POST 参数 Upload 与 $_FILES['uploaded']，sink 为 move_uploaded_file。发现文件上传校验不足（扩展名白名单 + getimagesize 文件头），可上传 polyglot 图片，在 uploads 目录允许解析时形成 RCE，已给出闭合利用链。未发现 SQL/命令/路径穿越/反序列化/SSRF 汇点；文件中无 md5/rand/setcookie 等弱加密或会话线索。未闭合点：DVWA_WEB_PAGE_TO_ROOT 常量与 uploads 目录的 Web 可达性、服务器是否禁用 uploads 下 PHP 解析，均需运行时确认。code_pack 之外无其它文件，未覆盖依赖与部署配置。

未覆盖 / 证据缺口：
- uploads 目录是否允许 PHP 解析未确认
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内
- 无部署/服务器配置，无法确认实际 URL 与认证要求

## 3. Findings

### F-1: 043.php 不安全文件上传（CWE-434）：上传文件被直接 move_uploaded_file 到目标路径，缺少类型/扩展名校验

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 文件上传字段 `uploaded` 提交文件（043.php:12 读取上传内容，临时文件路径进入 `$uploaded_tmp`）。代码随后在 043.php:20 调用 `move_uploaded_file( $uploaded_tmp, $target_path )` 将临时文件移动到 `$target_path`。从给出的片段看，在读取上传内容（043.php:12）与移动文件（043.php:20）之间，没有出现对文件扩展名、MIME 类型、文件内容或目标路径的白名单校验，也没有对 `$target_path` 做规范化/目录限制，因此上传文件的原始名称/类型可直接影响落盘位置与落盘文件名。校验无效的原因：不存在任何 allowlist 或内容检查，`move_uploaded_file` 只保证文件来自本次上传，不保证其类型安全。最终到达的危险操作是文件写入（落盘到 Web 可访问目录时可被解析执行）。

**source / sink**

- source：upload `uploaded`（043.php:12）
- sink：043.php:20 if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:12` | 从 upload `uploaded` 读取外部输入 | 污点进入 uploaded_tmp |  |
| 2 | `043.php:20` | 危险汇点：if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { | 污点进入 file_upload 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /043（任意方法）的不安全文件上传 POC。注入点为 multipart 表单字段 uploaded 的 filename（043.php:20 附近上传处理逻辑）。注意：源码未限定 HTTP 方法，故请求方法以实际路由为准，示例使用 POST；目标地址统一使用 TARGET 占位符，仅限授权测试。

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

任意文件上传：攻击者可上传 .php/.phtml 等可执行脚本到 Web 根目录下，通过访问上传后的 URL 触发服务端执行，导致远程代码执行（RCE）；即使不可执行，也可造成任意文件写入、覆盖已有文件、磁盘占满，或上传恶意 HTML/JS 用于钓鱼与存储型 XSS。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP multipart 请求的 `uploaded` 字段，无需认证即可访问 043.php。利用链闭合：请求 → `$uploaded_tmp`（043.php:12）→ `move_uploaded_file($uploaded_tmp, $target_path)`（043.php:20）→ 文件落盘。缺少扩展名/类型白名单与目标路径约束，攻击者可直接控制落盘文件，链路上无有效净化点。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 对上传文件使用扩展名白名单（如仅 jpg/png/pdf），并结合 finfo/getimagesize 校验真实 MIME 与文件头，不信任客户端 Content-Type；2) 由服务端生成随机文件名，禁止使用客户端原始文件名拼接路径；3) 将上传目录置于 Web 根之外，或配置该目录禁止脚本执行（如 php-fpm/nginx 关闭 PHP handler）；4) 对 `$target_path` 做 realpath 规范化并校验其前缀必须位于允许的上传目录内，防止路径穿越；5) 限制文件大小与数量，上传后重命名并设置最小权限（0644、非可执行）；6) 对上传内容做病毒/恶意脚本扫描。

**验证说明**

静态证据：入口 ANY /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造 multipart/form-data 请求，在字段 `uploaded` 中提交名为 shell.php 的恶意脚本 → 043.php:12 读取上传，临时文件路径写入 `$uploaded_tmp` → 代码未对扩展名、MIME、内容或目标路径做任何白名单校验 → 043.php:20 `move_uploaded_file( $uploaded_tmp, $target_path )` 将脚本移动到 Web 可访问目录 → 攻击者访问上传后的 URL，服务端解析执行该脚本，获得命令执行能力。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434（不受限制的危险类型文件上传）。漏洞位于可交付代码 043.php:20，外部输入来自 multipart 上传字段 uploaded 的 filename，source→sink 链静态闭合，未发现有效扩展名/内容净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。原草稿使用 -X ANY 并非合法 HTTP 方法，实际发送时请按部署路由选择 POST（或源码实际接受的方法）。执行前须将 TARGET 替换为已获授权的测试目标，上传内容仅使用无害标记，禁止上传真实 webshell 或执行破坏性命令。

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
| `file_upload` | CWE-434 |  | 1 |
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
| safety_guard | 安全防护 | 2.63 | 是 |
| surface_mapper | 攻击面测绘 | 8.14 | 是 |
| deep_finder | LLM 深挖 | 9.3 | 是 |
| candidate_screener | 候选筛选 | 4.66 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.54 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.36 | 是 |
| coordinator | 管线协调 | 5.38 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
