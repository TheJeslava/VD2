# 落日二号乙漏洞挖掘报告 — 20261030-224605-2904e4

- 生成时间：2026-10-30T14:46:44.121795+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\010.zip`
- 输入模式：`zip`
- SHA256：`819467f4e89f5ccb8366890305cd0e83be79b38873b4535d43cf0f2c08e7c6c7`
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

本次汇总仅含 1 条已去重 finding：010.php 登录成功后把用户名 $user 直接拼入 $html 输出，构成反射型 XSS（high，LLM-f803c7aea6a6，行号落在 010.php 第 28 行范围内），已附带 POC，属 HTTP 可复现类型（POC 仅为文本工件，未执行、未动态验证）。最高危即此条，也是唯一交付项。POC 齐全度：1/1 有 POC，但均为静态推断产物，未经动态确认。未交付任何二次注入链、配置型候选或 trust_boundary 类结论。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2114 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：1 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 010.php（43 行）。第 8/13 行读取 $_GET username/password，经 stripslashes 与 mysqli_real_escape_string 后进入第 19 行 SQL 查询——mysqli_real_escape_string 已对 SQL 上下文转义，且 password 经 md5 处理，未发现可闭合的 SQL 注入链（第 10/15 行在 ___mysqli_ston 非对象时回退为空串，反而阻断注入）。发现两处输出未编码：第 28 行 $user 反射型 XSS（链较完整，但需合法登录凭据与通过 checkToken），第 29 行 $avatar 属性注入 XSS（依赖 avatar 可控，CODE PACK 无写入点，链有缺口）。第 33 行 rand 仅用于登录失败延时，非安全随机数场景，不构成 weak_random。checkToken/generateSessionToken 定义不在 CODE PACK，无法评估 CSRF 防护强度。未发现命令执行、文件包含、反序列化、SSRF 等汇点。

未覆盖 / 证据缺口：
- checkToken 与 generateSessionToken 实现未在 CODE PACK，无法确认 CSRF token 是否可绕过
- avatar 字段写入点未知，无法确认第 29 行 XSS 的可控性
- 无 php.ini/部署信息，无法评估实际可达性
- 无合法凭据，登录成功分支可达性未验证

## 3. Findings

### F-1: 010.php 登录成功后用户名未转义反射型 XSS（$user 直接拼入 $html）

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.77`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`010.php:8-28`
- **来源**：`llm_finding`

**描述**

第 8 行从 $_GET['username'] 读取用户名，仅做 stripslashes 与 mysqli_real_escape_string（后者只针对 SQL 上下文转义，不处理 HTML 特殊字符），第 28 行将 $user 直接拼接进 $html 的 <p> 标签中输出，未调用 htmlspecialchars/htmlentities。攻击者可构造 username 含 HTML/JS 的请求，在登录成功分支（用户名密码匹配到一条记录）时触发脚本执行，窃取会话或执行敏感操作。

**source / sink**

- source：query `username`（010.php:8）
- sink：010.php:28 第 28 行 $html .= "<p>Welcome to the password protected area {$user}</p>" 字符串拼接输出

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `010.php:8` | 从 $_GET['username'] 读取攻击者可控输入 | 原始字符串 |  |
| 2 | `010.php:9` | stripslashes 去除反斜杠，不改变 HTML 元字符 | 去反斜杠字符串 |  |
| 3 | `010.php:10` | mysqli_real_escape_string 仅转义 SQL 特殊字符（引号、反斜杠等），不转义 < > " 等 HTML 字符 | SQL 转义但 HTML 未转义 | 该函数面向 SQL 上下文，对 HTML 注入无效 |
| 4 | `010.php:28` | $user 直接拼入 $html 输出到页面 | 未做 HTML 编码，原样输出 |  |

**POC**

针对 /010.php（GET）的反射型跨站脚本（CWE-79）POC。注入点为 GET 查询参数 username，该参数值未经 HTML 编码即被输出到响应页面（010.php:28）。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/010.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 跨站脚本 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/010.php?username=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
```
预期：响应中脚本未编码，浏览器执行并弹出 document.domain。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`<script>alert(document.domain)</script>`
- POC 目录：`poc/LLM-f803c7aea6a6`
- 执行状态：未执行（`executed=False`）

**影响**

反射型 XSS，可在受害者浏览器执行任意 JS，窃取会话 Cookie、发起 CSRF 式敏感操作或钓鱼。

**CVE / CWE 论证**

CWE-79：外部可控 GET 参数 username 未经 HTML 编码直达输出汇点，链闭合，无需高权限（仅需一次合法登录）。

**修复建议**

输出前对 $user 使用 htmlspecialchars($user, ENT_QUOTES, 'UTF-8')；对 avatar 同样做属性上下文编码。

**验证说明**

需确认登录成功分支可达（需合法凭据）以及 checkToken 是否可绕过；若无法获得合法凭据则利用条件受限。
模型 POC 要点：使用合法凭据登录，username 参数注入 HTML/JS 载荷，登录成功分支将载荷原样回显
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
LLM 深挖重复命中（xss，conf=0.6）；保留首条候选，补充：第 25 行从数据库读取 $row['avatar']，第 29 行直接拼入 <img src="{$avatar}" /> 属性中，未做 HTML 属性上下文编码。若攻击者能控制自身 avatar 字段（如注册/资料修改功能写入），或数据库中存在恶意 avatar 值，则闭合引号后可注入事件处理器执行脚本。
PocWriter 建议（未采纳，缺少端点 /010.php）：符合 CWE-79（跨站脚本）。漏洞位于可交付代码 010.php:28，外部输入来自 GET 查询参数 username，source→sink 链在给定代码范围内静态闭合，未发现有效输出编码/净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。若需手工复现，可将步骤 2 的 URL 粘贴到已授权测试浏览器中观察弹窗；不要对非授权目标使用。

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
| `xss` | CWE-79 | 是 | 1 |
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 0 |
| `csrf` | CWE-352 |  | 0 |
| `file_upload` | CWE-434 |  | 0 |
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
| safety_guard | 安全防护 | 4.84 | 是 |
| surface_mapper | 攻击面测绘 | 7.43 | 是 |
| deep_finder | LLM 深挖 | 11.5 | 是 |
| candidate_screener | 候选筛选 | 3.56 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.35 | 是 |
| coordinator | 管线协调 | 6.08 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
