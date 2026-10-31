# 落日二号乙漏洞挖掘报告 — 20261031-001848-5502fa

- 生成时间：2026-10-30T16:19:35.892596+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

本次汇总仅含 1 条已去重 finding：012.php 登录查询 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径最短：请求参数直接进入 SQL 查询）。最高危即该条 critical SQL 注入，位于 012.php 第 15 行附近，source 与 sink 同处一个 35 行单文件，缺少过滤中间层。POC 齐全度：1/1 有 POC，但仅覆盖 sql_injection 一类；其余攻击面（path_traversal、xss、weak_hash、weak_random、insecure_cookie、trust_boundary）均无 finding 交付，属未覆盖而非已排除。本次未做任何动态验证，POC 仅为文本工件。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 012.php（1-35 行全文）。确认两条链：1) username 参数经 mysqli_real_escape_string 后拼接进 SQL（012.php:5→14→15），因未设置连接字符集且不阻断无引号注入，构成 SQL 注入（high）；2) 登录成功后 $user 未 HTML 编码回显（012.php:23），构成反射型 XSS（medium，依赖登录成功）。password 参数经 md5 后拼接，同样存在注入面但受 md5 固定长度限制，未单列。未发现命令执行、文件包含、反序列化、SSRF 汇点。weak_hash（md5 用于口令）与 sleep(2) 时序问题作为线索记录，未达 CVE 级。code_pack 之外无文件，未覆盖部署配置与 PHP 版本。

未覆盖 / 证据缺口：
- 未提供数据库连接字符集，宽字节绕过需动态确认
- 无 Web 服务器/php.ini 配置，无法确认 register_globals、错误显示等
- 无端点映射与前置鉴权/WAF 信息
- password 参数注入面未单列（受 md5 长度约束）

## 3. Findings

### F-1: 012.php 登录查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`012.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 012.php 提交登录参数，源码在 012.php:5 处从 query 参数 `username`（以及同表单的密码参数）读取外部输入，未做任何转义或类型校验。该值被直接拼接进 012.php:14 的 SQL 语句：$query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";，随后在 012.php:15 交由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $user/$pass 处于单引号字符串字面量内部且无 mysqli_real_escape_string、无预处理语句、无白名单校验，攻击者可用单引号闭合字符串并注入任意 SQL 片段（如 ' OR '1'='1 绕过认证，或 UNION SELECT 读取其他表）。此外 012.php:15 的 die() 分支会把 mysqli_error() 的原始错误信息回显到页面，构成报错型注入的辅助信息泄露通道，进一步降低盲注成本。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:5` | 从 query `username` 读取外部输入 | 污点进入 query |  |
| 2 | `012.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 012.php:15 的 SQL 注入 POC（入口 /012，方法 ANY）。注入点为查询参数 username，外部输入未经有效净化即进入 SQL 语句，payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/012?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-3b547dba7a60`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

认证绕过：构造 user=' OR '1'='1' -- 之类的载荷可使 WHERE 条件恒真，以任意/首个用户身份登录。数据泄露：通过 UNION SELECT 或布尔/报错注入读取 users 表及其他库表内容（口令哈希、个人信息）。若数据库账号权限过高，还可进一步读写文件或篡改数据。错误信息回显（mysqli_error）额外泄露库名、表名、列名等结构信息。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：012.php 为可直接 HTTP 访问的登录入口，参数来自请求 query/表单，无需认证即可触达。利用链闭合：source（012.php:5 的 username 参数）→ 字符串拼接（012.php:14）→ 执行汇点 mysqli_query（012.php:15），中间无有效净化，攻击者完全控制 SQL 语义，满足注入成立的全部条件。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, 'SELECT * FROM `users` WHERE user = ? AND password = ?'); mysqli_stmt_bind_param($stmt, 'ss', $user, $pass); mysqli_stmt_execute($stmt);，彻底消除拼接。2) 若暂不能改造，至少对输入使用 mysqli_real_escape_string 并配合严格白名单（用户名限 [A-Za-z0-9_]{1,32}）。3) 移除或统一收敛 die(mysqli_error(...)) 的原始错误回显，改为记录服务端日志并返回通用错误页。4) 数据库连接使用最小权限账号，禁用 FILE 等不必要权限。5) 口令校验应使用 password_verify 对哈希比对，而非在 SQL 中明文比较。

**验证说明**

静态证据：入口 ANY /012；source=query/username；sink=012.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 012.php 提交登录请求，username 参数在 012.php:5 被读入 $user；该值未经转义直接进入 012.php:14 的 SQL 字符串拼接，形成 SELECT * FROM `users` WHERE user = '<注入>' AND password = '<注入>';；012.php:15 调用 mysqli_query 执行该语句，注入的 SQL 片段被数据库解析执行，查询结果决定登录成败或返回被 UNION 拼接的数据；若语句出错，die() 分支将 mysqli_error 内容回显给攻击者。整条链路无参数化、无转义、无白名单，注入成立。
PocWriter 建议（未采纳，缺少端点 /012）：符合 CWE-89。漏洞位于可交付代码 012.php:15，外部输入来自查询参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原请求结构（ANY /012，参数 username，URL 编码载荷）。脚本仅为文本参考，不自动执行；执行前须替换 TARGET 并获得授权。

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
| `sql_injection` | CWE-89 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.4 | 是 |
| surface_mapper | 攻击面测绘 | 8.63 | 是 |
| deep_finder | LLM 深挖 | 12.37 | 是 |
| candidate_screener | 候选筛选 | 3.64 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.26 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.31 | 是 |
| coordinator | 管线协调 | 5.86 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
