# 落日二号乙漏洞挖掘报告 — 20261030-225032-fc389c

- 生成时间：2026-10-30T14:51:12.065854+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\043.zip`
- 输入模式：`zip`
- SHA256：`07af6f04e9411f0557b345faaf32fcbb3e1405cb4402c57b6fc79a4bf804244f`
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

本次汇总仅含 1 条已去重 finding：LLM-7a70487f2fb0，类型 file_upload，严重度 high，位于 043.php 第 1–27 行，判定为仅校验扩展名与 getimagesize、可上传含 PHP 代码的图片并落入 web 可访问目录，进而导致 RCE；该条已附带 POC（has_poc=true），属 HTTP 型 POC，但仅为静态源码推断（origin=llm_finding），未做动态验证。最高危即此条，也是唯一交付项。POC 齐全度为 1/1，但覆盖面极窄：仅 1 个 PHP 文件、0 个端点被测绘，sink_hot_files 为空，说明危险汇点未被自动识别，其余注入类与配置类风险均未形成 finding。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1316 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 043.php（35 行，DVWA 文件上传模块）。已通读全文：入口为 POST 参数 Upload + $_FILES['uploaded']，校验为扩展名白名单（jpg/jpeg/png）、大小 <100000、getimagesize 非空，随后 move_uploaded_file 写入 DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/'。核心风险为图片马绕过 getimagesize 后落盘 web 可访问目录，构成文件上传导致 RCE 的候选链（confidence 0.8，依赖服务器对上传目录的解析配置）。未发现 SQL 注入、命令注入、路径穿越（basename 已去除目录部分）、反序列化、SSRF、SSTI 等其它汇点；未发现 md5/sha1/rand/setcookie 等配置型风险代码。$html 变量在赋值前未初始化，属低危 notice，不单独立项。未覆盖范围：无 php.ini/服务器配置、无端点清单与认证信息、无依赖清单，故无法确认上传目录解析行为与端点鉴权状态，这些是闭合该链所需的动态/配置证据。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/Apache 配置，无法确认 hackable/uploads/ 下非 .php 扩展名是否被 PHP 解析
- 缺少端点鉴权与部署路径信息，无法确认是否需登录
- 无 php.ini，无法评估 allow_url_include 等运行时风险
- 无依赖清单与框架信息

## 3. Findings

### F-1: DVWA 文件上传端点 043.php 仅校验扩展名与 getimagesize，可上传含 PHP 代码的图片并写入 web 可访问目录导致 RCE

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`043.php:3-27`
- **来源**：`llm_finding`

**描述**

043.php 直接使用 $_FILES['uploaded']['name'] 经 basename() 拼接为 $target_path，写入 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/"。校验仅有：扩展名白名单（jpg/jpeg/png，取自文件名最后一个点之后）、大小 < 100000 字节、getimagesize() 返回真。getimagesize 只检查文件头是否为合法图片，不阻止图片尾部附加任意 PHP 代码（polyglot 图片马）。上传后文件落在 web 根下可访问的 hackable/uploads/ 目录，若服务器对 .php 解析（DVWA 默认 Apache+mod_php 环境即如此），攻击者可通过访问上传文件执行任意 PHP 代码，实现远程代码执行。

**source / sink**

- source：upload `uploaded`（043.php:9-12）
- sink：043.php:27 move_uploaded_file($uploaded_tmp, $target_path) 写入 web 可访问目录 hackable/uploads/

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `043.php:3` | 检测到 POST 参数 Upload 即进入上传处理分支 | 攻击者控制 multipart 请求 |  |
| 2 | `043.php:9-12` | 从 $_FILES['uploaded'] 读取文件名、扩展名、大小、临时路径 | 文件名与内容完全由攻击者控制 |  |
| 3 | `043.php:15-17` | 校验扩展名属于 jpg/jpeg/png、大小 <100000、getimagesize 为真 | 扩展名白名单通过；getimagesize 仅校验文件头，图片尾部附加 PHP 代码仍返回真 | getimagesize 只解析图片头，不检测尾部附加内容；扩展名取自文件名最后一段，攻击者可将文件命名为 shell.php.png 或 shell.png 并在尾部写入 <?php ... ?> |
| 4 | `043.php:5-6` | 用 basename(文件名) 拼接目标路径 hackable/uploads/ | 目标路径 = web 根下可访问目录 + 攻击者文件名 |  |
| 5 | `043.php:20` | move_uploaded_file 将临时文件移动到目标路径 | 恶意图片马落盘到 web 可访问目录 |  |
| 6 | `043.php:26` | 响应回显上传后的完整路径，攻击者据此定位文件 URL | 泄露落盘路径，便于后续访问触发 |  |

**POC**

针对 /043.php（POST，multipart 上传）的不安全文件上传 POC。注入通道为 multipart 表单字段 `uploaded` 的 filename（源码 043.php:27 附近的上传处理逻辑），攻击者可提交可执行脚本（如 .jsp）作为上传文件名/内容，若上传目录可被 Web 容器解析则导致远程代码执行。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/043.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 不安全文件上传 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/043.php' \
  -F 'uploaded=@sunset.jsp;filename=sunset.jsp'
```
预期：上传文件可访问/解析，返回 webshell 执行结果。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`sunset.jsp`
- POC 目录：`poc/LLM-7a70487f2fb0`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在服务器上执行任意 PHP 代码/系统命令，完全控制 Web 应用与主机，属于远程代码执行。

**CVE / CWE 论证**

CWE-434 不受限制的危险类型文件上传。外部可直接 POST 访问，无需认证（DVWA 该模块默认无鉴权），利用链闭合：上传字段→扩展名/getimagesize 弱校验→move_uploaded_file 落盘 web 目录→访问触发执行。

**修复建议**

不要依赖扩展名与 getimagesize；对上传内容重新编码为图片（如 GD 重绘）、随机化文件名并去除原扩展名、将上传目录置于 web 根之外或禁止该目录执行 PHP（php_flag engine off / 独立存储），并校验 MIME 与文件签名。

**验证说明**

需确认部署环境是否对 hackable/uploads/ 下的 .png 文件按 PHP 解析（DVWA 默认 Apache 配置通常仅 .php 解析，需结合 .htaccess 或服务器 AddHandler 配置确认；若仅解析 .php 扩展名，则需进一步利用文件名/多扩展名或配合解析漏洞）。此外需确认该端点是否置于认证之后。
模型 POC 要点：构造一个合法 PNG 头 + 尾部 PHP 代码的图片马，通过 multipart 上传，随后访问上传文件触发 PHP 执行。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /043.php）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于可交付代码 043.php:27 附近的上传处理逻辑，外部输入来自 multipart 字段 `uploaded` 的 filename/内容，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单、MIME 校验或落盘路径限制等有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，不生成可自动执行的脚本；如需手工复现，请将 TARGET 替换为授权目标后由测试人员手动发送上述 HTTP 请求。原始草稿中的 curl 命令仅作参考，管线不执行、不联网、不搭建沙箱。上传路径 /uploads/ 为推测值，应以步骤 2 响应回显为准调整。

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
| safety_guard | 安全防护 | 3.24 | 是 |
| surface_mapper | 攻击面测绘 | 7.61 | 是 |
| deep_finder | LLM 深挖 | 11.43 | 是 |
| candidate_screener | 候选筛选 | 3.42 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.33 | 是 |
| coordinator | 管线协调 | 6.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
