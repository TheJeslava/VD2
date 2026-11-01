# 落日二号乙漏洞挖掘报告 — 20261030-225049-87fac9

- 生成时间：2026-10-30T14:51:35.431190+00:00
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

本次汇总仅含 1 条已去重 finding：LLM-10ebc3a0036d（file_upload，high），指向单文件 PHP 脚本 045.php 第 24 行附近，判定其仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行，且已附带 POC（静态/文本 POC，未做动态验证）。最高危即此条 file_upload（high）。POC 齐全度为 1/1，但需注意该 POC 属静态证据型，未在沙箱或真实目标上复现，不能宣称可动态复现。整体覆盖面极窄：仅 1 个 PHP 文件、0 个端点、无框架、无隔离文件，注入类与配置类结论证据不足。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1154 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：仅审计了 code_pack 中唯一文件 045.php（33 行）。发现一条闭合链：客户端可控 MIME 类型绕过上传白名单，move_uploaded_file 保留 .php 扩展名写入可访问目录，构成任意文件上传→RCE（CWE-434）。未发现其它独立攻击面（无 SQL/命令/反序列化/SSRF 汇点）。未覆盖：php.ini/Web 服务器配置、DVWA_WEB_PAGE_TO_ROOT 定义、uploads 目录执行策略、鉴权层，均不在 code_pack 内。

未覆盖 / 证据缺口：
- DVWA_WEB_PAGE_TO_ROOT 常量定义与 uploads 目录权限/执行策略未知
- 045.php 是否需登录及部署路径未知
- 无 php.ini/服务器配置，无法确认上传目录是否解析 PHP

## 3. Findings

### F-1: DVWA 上传端点 045.php 仅校验客户端可控的 MIME 类型，可上传任意 PHP 脚本导致远程代码执行

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`045.php:3-24`
- **来源**：`llm_finding`

**描述**

045.php 处理 POST 上传时，用 $_FILES['uploaded']['type']（完全由客户端 multipart 请求的 Content-Type 决定）与大小做白名单判断，未校验扩展名、未校验真实文件内容（无 getimagesize/finfo）、未重命名。攻击者把 Content-Type 伪造成 image/jpeg 即可通过检查，move_uploaded_file 将原始文件名（basename 仅去掉路径部分，保留 .php 扩展名）写入 hackable/uploads/ 目录，随后访问该文件即由 PHP 解析执行，形成任意代码执行。

**source / sink**

- source：upload `uploaded`（045.php:10）
- sink：045.php:24 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 写入 hackable/uploads/<原始文件名>

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `045.php:3` | 检测到 POST 参数 Upload，进入上传处理分支 | 攻击者控制整个 multipart 请求 |  |
| 2 | `045.php:6` | 目标路径由固定目录拼接 basename(原始文件名)，basename 只剥离路径不改变扩展名 | $target_path = .../hackable/uploads/shell.php |  |
| 3 | `045.php:10` | 读取客户端提供的 MIME 类型作为唯一类型判据 | $uploaded_type 完全由请求头 Content-Type 决定 |  |
| 4 | `045.php:14` | 白名单比较 image/jpeg 或 image/png，可被伪造 Content-Type 直接满足 | 伪造为 image/jpeg 即通过 | MIME 来自客户端，非服务端探测；无扩展名/内容校验 |
| 5 | `045.php:18` | move_uploaded_file 将临时文件移动到可 Web 访问目录并保留 .php 扩展名 | webshell 落盘为可执行 PHP 文件 |  |

**POC**

针对 /vulnerabilities/upload/ (045.php)（POST）的 不安全文件上传 POC。注入点：multipart filename；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/upload/ (045.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/upload/ (045.php)' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-10ebc3a0036d`
- 执行状态：未执行（`executed=False`）

**影响**

任意文件上传导致远程代码执行，攻击者可完全控制 Web 服务器。

**CVE / CWE 论证**

CWE-434 无限制危险类型文件上传；外部无需认证即可触发，链闭合（上传→落盘→访问执行）。

**修复建议**

服务端用 getimagesize/finfo 校验真实类型，强制白名单扩展名并重命名文件，将上传目录置于 Web 根之外或禁用脚本执行。

**验证说明**

需确认 uploads 目录是否可执行 PHP 及 045.php 是否需认证；DVWA 默认低安全级别下无需认证。
模型 POC 要点：伪造 Content-Type 为 image/jpeg 上传 PHP webshell，随后访问上传路径触发执行。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：针对 045.php:24 的不安全文件上传（CWE-434）POC。上传入口为 multipart 表单字段 `uploaded`，注入通道是 multipart 的 `filename` 与文件内容；攻击者可将可执行脚本（如 .jsp/.php）上传到 Web 可访问目录，若服务器未对扩展名/内容类型/落盘路径做有效校验，则上传文件可被解析执行，导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 045.php:24，外部输入来自 multipart 上传字段 `uploaded` 的 filename/内容，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。所有请求中的目标地址使用 TARGET 占位符，端口 8080 为示例，请按实际授权环境替换。步骤 4 的上传落盘路径（/vulnerabilities/hackable/uploads/）为常见默认路径示例，实际路径以步骤 2/3 响应回显为准。禁止对生产环境执行；仅限授权测试。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.63 | 是 |
| surface_mapper | 攻击面测绘 | 17.45 | 是 |
| deep_finder | LLM 深挖 | 8.06 | 是 |
| candidate_screener | 候选筛选 | 3.72 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.31 | 是 |
| coordinator | 管线协调 | 6.19 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
