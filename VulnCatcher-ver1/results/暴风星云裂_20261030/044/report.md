# 落日二号乙漏洞挖掘报告 — 20261030-225034-996400

- 生成时间：2026-10-30T14:51:18.199628+00:00
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

本次汇总仅含 1 条已去重 finding：LLM-6ccece6535f3，类型 file_upload，严重度 high，位于 044.php 第 1–16 行，判定为无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE），已附带 POC（has_poc=true）。这是本次唯一交付项，也是最高危项。POC 齐全度为 1/1，但该 POC 属源码推断级（origin=llm_finding），未做动态验证，不能宣称可动态复现。覆盖面上仅审计了 1 个 PHP 文件、0 个端点、无框架；surface_notes 明确指出 source_hot_files 命中 044.php 而 sink_hot_files 为空，说明危险汇点定位缺失，数据流需人工补全。配置类候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret）本次无候选，但 19 行脚本内完全可能存在，属必须人工过一遍的范围，不能因 source 为空而跳过。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 630 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 044.php（19 行，DVWA 文件上传练习片段）。逐行审计确认：POST 参数 Upload 触发分支，$_FILES['uploaded']['name'] 仅经 basename() 处理即拼接到 hackable/uploads/ 并 move_uploaded_file 落盘，无扩展名/MIME/图像校验，构成无限制文件上传→RCE，已给出完整 POC。其余攻击面：文件内无 SQL/命令/模板/反序列化/SSRF/include 汇点；无 md5/sha1/rand/setcookie/硬编码口令等配置类问题；无 $_SERVER 信任边界使用。未覆盖范围：无 composer.json、Web 服务器配置、php.ini、路由与端点清单，无法确认 044.php 的对外 URL、DVWA_WEB_PAGE_TO_ROOT 常量值、上传目录是否可执行 PHP 及外层鉴权；这些属于部署层证据缺口，需人工或动态验证补全。输入中未发现 prompt injection 诱导文本。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini/框架配置，无法确认 044.php 对外路径与上传目录 PHP 可执行性
- DVWA_WEB_PAGE_TO_ROOT 常量定义不在 code_pack 内，落盘绝对路径未知
- 无 endpoints 清单，无法确认外层是否存在登录鉴权与 CSRF 防护
- 无动态/AWVS 证据，结论为源码推断级别

## 3. Findings

### F-1: DVWA 044.php 无限制文件上传导致任意 PHP 文件写入 Web 目录（RCE）

- **类型**：`file_upload` / CWE-434
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`044.php:3-16`
- **来源**：`llm_finding`

**描述**

044.php 在收到 POST 参数 Upload 后，直接把 $_FILES['uploaded']['name'] 经 basename() 处理后拼接到 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" 目录，并调用 move_uploaded_file() 落盘。代码未做任何扩展名白名单、MIME 校验、getimagesize 图像校验、文件大小限制或随机重命名，攻击者可上传 .php 文件到 Web 可访问的 hackable/uploads/ 目录，随后直接请求该文件即可执行任意 PHP 代码，形成远程代码执行。

**source / sink**

- source：upload `uploaded`（044.php）
- sink：044.php:16 move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path) 于 044.php:9

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `044.php:3` | 检测到 POST 参数 Upload 存在即进入上传处理分支，无任何认证/CSRF/来源校验 | 攻击者控制请求体与 multipart 文件部分 |  |
| 2 | `044.php:6` | 取上传文件名 $_FILES['uploaded']['name']，仅经 basename() 去除路径部分，保留完整文件名与扩展名 | 文件名原样保留，扩展名 .php 未被过滤 | basename() 只剥离目录分隔符，不做扩展名/MIME 白名单，无法阻止 .php 后缀 |
| 3 | `044.php:5-6` | 拼接目标路径 DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" . 文件名，落点位于 Web 根下可访问目录 | 最终路径 = Web 根/hackable/uploads/<攻击者文件名> |  |
| 4 | `044.php:9` | move_uploaded_file 将临时文件移动到目标路径，文件被持久化到 Web 可访问目录 | 恶意 PHP 文件写入磁盘并可被 HTTP 直接访问 |  |
| 5 | `044.php:15` | 成功分支回显完整 $target_path，向攻击者泄露上传后的绝对/相对路径，便于定位访问 URL | 响应中返回落盘路径 |  |

**POC**

针对 044.php:16 的不安全文件上传（CWE-434）POC。上传入口为 POST /vulnerabilities/upload/，注入通道是 multipart 表单字段 `uploaded` 的 filename 与文件内容；服务端未对扩展名/内容类型做有效校验，导致可上传可执行脚本（如 .jsp）并被 Web 容器解析。目标地址统一使用 TARGET 占位符，仅限授权测试。

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
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可在 Web 根目录写入任意 PHP 文件并执行，获得服务器代码执行权限，进而读取配置/数据库凭据、横向移动、植入持久后门。

**CVE / CWE 论证**

CWE-434 Unrestricted Upload of File with Dangerous Type。外部 HTTP 可达，无需高权限，source（上传文件名）→ sink（move_uploaded_file）链路在 044.php 内完整闭合，无任何白名单/校验节点，属典型可申报 CVE 的任意文件上传 RCE。

**修复建议**

1) 使用扩展名白名单（仅 jpg/png/gif 等）并校验真实 MIME 与 getimagesize；2) 上传文件随机重命名并去除原始扩展名；3) 上传目录置于 Web 根之外或禁用 PHP 解析（如 nginx location 拒绝 .php 执行）；4) 限制文件大小；5) 上传接口增加认证与 CSRF 校验。

**验证说明**

需确认 044.php 的实际 URL 路径、DVWA_WEB_PAGE_TO_ROOT 常量定义值、hackable/uploads/ 是否允许 PHP 执行，以及外层是否存在登录鉴权。源码层面上传链已闭合，但落点可执行性依赖部署配置。
模型 POC 要点：构造 multipart 上传请求，将 PHP webshell 以 .php 扩展名上传到 hackable/uploads/，再从响应回显的路径直接访问执行。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/upload/）：符合 CWE-434（Unrestricted Upload of File with Dangerous Type）。漏洞位于 044.php:16，外部输入来自上传字段 `uploaded` 的 filename/内容，source→sink 链在给定代码范围内静态闭合，未发现扩展名白名单、内容类型校验或重命名等有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 curl 命令仅供授权测试人员手动执行，需先将 TARGET 替换为授权目标；上传文件内容保持无害标记，禁止放入反弹 shell、删除文件等破坏性载荷。若实际保存路径与 /vulnerabilities/hackable/uploads/ 不同，以第 2 步响应回显的路径为准。

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
| safety_guard | 安全防护 | 3.57 | 是 |
| surface_mapper | 攻击面测绘 | 8.19 | 是 |
| deep_finder | LLM 深挖 | 10.59 | 是 |
| candidate_screener | 候选筛选 | 5.91 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.89 | 是 |
| coordinator | 管线协调 | 8.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
