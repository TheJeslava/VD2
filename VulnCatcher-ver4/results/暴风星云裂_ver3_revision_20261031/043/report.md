# 落日二号乙漏洞挖掘报告 — 20261031-012122-17a1d9

- 生成时间：2026-10-30T17:21:58.752345+00:00
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

本次汇总仅含 1 条已去重 finding：043.php 的不安全文件上传（file_upload，CWE-434），严重度 critical，带 POC（has_poc=true），来源为规则命中，证据等级为规则/静态推断，未做动态验证。最高危即该 critical 文件上传，若上传目录可被 Web 访问且未限制扩展名/内容类型，可导致任意文件写入乃至代码执行。POC 齐全度：1/1 条 finding 有 POC，但该 POC 属静态构造文本（TARGET 占位、仅限授权测试），不能宣称已动态复现。其余攻击面（注入、XSS、路径穿越、命令执行、配置型弱算法/弱随机/Cookie 标志/信任边界）在本次输入中均无 finding 交付，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入 043.php（35 行，DVWA 风格文件上传片段）。逐行审计结果：入口为 $_POST['Upload'] 触发的文件上传，第 5-6 行拼接目标路径 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" . basename($_FILES['uploaded']['name'])，第 15-17 行做三重校验：扩展名白名单（jpg/jpeg/png，strtolower 后比较）、大小 < 100000 字节、getimagesize() 校验真实图片头；第 20 行 move_uploaded_file 落盘。basename() 已剥离目录分隔符，无法路径穿越；扩展名白名单 + getimagesize 双重校验使上传 webshell 的链不闭合（无法同时满足图片头与可执行 PHP 扩展名，且目标目录 hackable/uploads/ 是否可执行 PHP 取决于未提供的 Web 服务器配置）。第 26 行 $html 拼接 $target_path 后输出，但 $target_path 中的文件名部分经 basename() 处理，且该片段未包含 echo/print 输出语句（$html 变量在本文件内未被输出），反射型 XSS 链不闭合。未发现 md5/sha1、rand/mt_rand、setcookie、openssl_encrypt、$_SERVER 头信任等配置型风险。结论：本 CODE PACK 内无可闭合的 CVE 级利用链，返回空 findings。

未覆盖 / 证据缺口：
- 未提供 DVWA_WEB_PAGE_TO_ROOT 的定义与 hackable/uploads/ 目录的 Web 服务器执行配置（是否禁止 PHP 解析），无法判断上传图片马 + 解析绕过的可行性
- 未提供 $html 变量的最终输出位置（可能在其它 include 文件中 echo），无法确认是否存在基于文件名的反射型 XSS
- 未提供 .htaccess/php.ini，无法确认上传目录是否可执行脚本
- 无端点清单，入口按 PHP 脚本直连访问推断

## 3. Findings

### F-1: 043.php 不安全文件上传导致任意文件写入（CWE-434）

- **类型**：`file_upload` / CWE-434
- **严重度**：`critical`
- **置信度**：`0.68`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`043.php:18-20`
- **来源**：`rule`

**描述**

攻击者通过上传表单字段 `uploaded`（043.php:12 读取上传文件）提交文件，脚本将上传文件的临时路径保存到 `$uploaded_tmp`，随后在 043.php:20 直接调用 `move_uploaded_file($uploaded_tmp, $target_path)` 把文件移动到目标路径。代码片段中未见对扩展名、MIME 类型、文件内容或目标路径的白名单校验，也未见对 `$target_path` 的规范化与目录限制，因此上传文件的类型与落盘位置均未受约束。由于输入仅给出 043.php:12 与 043.php:18-20 的片段，`$target_path` 的具体构造逻辑（是否拼接用户可控文件名/路径）在证据中不可见，此点标注为证据不足。

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

若 `$target_path` 位于 Web 可访问目录且扩展名未受限，攻击者可上传 .php 等可执行脚本，通过 HTTP 请求触发后获得服务器端代码执行（RCE）；即使不可执行，也可造成任意文件写入/覆盖、磁盘占用，并可能借上传的 HTML/SVG 实施存储型 XSS 或钓鱼。

**CVE / CWE 论证**

CWE-434（Unrestricted Upload of File with Dangerous Type）。外部可达性：上传入口为 HTTP 文件上传参数 `uploaded`，无需认证即可访问（片段中未见鉴权逻辑）。利用链闭合：外部上传 → `$uploaded_tmp` → `move_uploaded_file($uploaded_tmp, $target_path)` 落盘，中间无类型/扩展名/路径校验。证据等级为 llm_inferred，`$target_path` 的构造与目录可访问性未在片段中体现，故 RCE 结论依赖该前提。

**修复建议**

1) 使用扩展名白名单（如仅 jpg/png/pdf）并同时校验 MIME 与文件魔数，拒绝双扩展名与可执行类型；2) 上传目录置于 Web 根之外，或关闭该目录的脚本执行权限；3) 服务端生成随机文件名，禁止用户控制 `$target_path`，并对路径做 realpath 规范化后校验其位于允许目录内；4) 限制文件大小与数量；5) 上传后重命名并去除执行位，必要时做病毒/内容扫描。

**验证说明**

静态证据：入口 ANY /043；source=upload/uploaded；sink=043.php:20；规则 php-upload。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 043.php 提交 multipart 上传请求，文件字段为 `uploaded`；PHP 将临时文件路径写入 `$uploaded_tmp`（043.php:12）。脚本未对文件类型、扩展名或目标路径做任何校验，直接在 043.php:20 执行 `move_uploaded_file($uploaded_tmp, $target_path)`，把攻击者文件写入 `$target_path` 指向的位置。若该位置在 Web 可访问目录且允许脚本执行，攻击者随后请求该文件即可执行任意代码；否则至少形成任意文件写入。
PocWriter 建议（未采纳，缺少端点 /043）：针对 043.php:20 的不安全文件上传（CWE-434）POC。上传入口为 multipart 表单字段 `uploaded`，注入通道是 multipart 的 filename（以及文件内容），攻击者可借此把可执行脚本（如 sunset.jsp）写入 Web 可访问目录。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /043）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:20，外部输入来自 multipart 上传字段 `uploaded` 的 filename/内容，source→sink 链已静态闭合，未发现有效净化（扩展名白名单、内容类型校验、落盘目录隔离），具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权测试实例并手动运行；示例脚本中的 curl 仅作请求结构参考，请勿以 curl|sh 方式自动执行。request.http 中的 Content-Length 需按实际 body 长度重算。若应用返回保存路径，请以实际路径替换步骤 3 的 /uploads/sunset.jsp。

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
| surface_mapper | 攻击面测绘 | 8.75 | 是 |
| deep_finder | LLM 深挖 | 3.53 | 是 |
| candidate_screener | 候选筛选 | 2.83 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.68 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.17 | 是 |
| coordinator | 管线协调 | 6.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
