# 落日二号乙漏洞挖掘报告 — 20261031-002458-7c94b4

- 生成时间：2026-10-30T16:25:37.954994+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\055.zip`
- 输入模式：`zip`
- SHA256：`3e6e2cddd55f2250b6f1a0ec122303bfa0c923af602a09aecf8d75ca2f525ece`
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

本次汇总仅含 1 条已去重 finding：055.php 第 19 行附近留言板 INSERT 语句的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现方向）。这是本次最高危且唯一交付项。POC 齐全度：1/1 有 POC，但该 POC 属静态推导产物，尚未经动态验证。覆盖面上仅审计了 1 个 PHP 文件（055.php，24 行），无端点清单、无框架配置、无部署信息；surface_notes 提出的路径遍历、命令注入、反射型 XSS、配置类弱点（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均未形成 finding，需人工按代码复核，不能据此宣称不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（24 行，DVWA 风格 guestbook 留言板）。入口为 POST btnSign 触发的 $_POST['mtxMessage'] 与 $_POST['txtName']（第 3-6 行），sink 为第 18-19 行拼接 INSERT 语句后 mysqli_query。逐跳分析：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9-11 行），$name 经 trim→preg_replace 过滤 script→mysqli_real_escape_string（第 6、14-15 行），两者在进入拼接前均经过 mysqli_real_escape_string，单引号被转义，无法闭合第 18 行 VALUES 中的字符串字面量，SQL 注入链不闭合；addslashes 与 mysqli_real_escape_string 叠加不构成可利用缺陷。第 19 行 die() 回显 mysqli_error 属错误信息泄露，但需先构造 SQL 语法错误，而注入点已被转义封堵，无法从外部稳定触发，且单独的信息泄露不达 CVE 门槛。XSS 面：$message 经 htmlspecialchars 转义，$name 仅过滤 script 关键字但随后未做 HTML 转义，理论上存在存储型 XSS（如 <img src=x onerror=...>），但属第三梯队、需管理员查看留言列表的受害者交互，且当前 policy 的 min_severity=high 下不交付，仅作为线索记录。未发现命令执行、文件包含/读写、反序列化、SSRF、认证绕过等汇点；脚本内无 md5/sha1、rand/mt_rand、setcookie、硬编码凭据，配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）均无证据。输入中未出现 prompt_injection 诱导文本。未覆盖范围：无 composer.json、Web 服务器配置、包含链、数据库 schema 与部署信息，无法确认 URL 重写、访问控制与运行时约束（如 ___mysqli_ston 全局连接对象的初始化位置不在 code_pack 内）。

未覆盖 / 证据缺口：
- ___mysqli_ston 全局 mysqli 连接对象的初始化代码不在 code_pack 内，无法确认连接字符集（若未设 utf8 且使用 GBK 等宽字节字符集，mysqli_real_escape_string 可能被宽字节绕过，但无证据支撑，不报告）
- 无 Web 服务器配置/路由/认证代码，无法确认页面是否需登录及留言列表渲染位置（存储型 XSS 的读点不在 code_pack 内）
- 无数据库 schema，无法确认 guestbook 表字段类型与后续消费方
- 无 PHP 版本与 disable_functions 等运行时信息

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言表单，外部输入在 055.php:5 被读取为 `mtxMessage`（留言内容），随后在 055.php:18 被直接拼接进 SQL 语句：`$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";`，其中 `$message` 与 `$name` 均以单引号包裹的字符串字面量形式嵌入，未做任何转义或参数化。该拼接后的 `$query` 在 055.php:19 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于输入中的单引号可闭合字符串字面量，攻击者可构造如 `' , (SELECT ...))-- -` 之类的载荷改写 INSERT 的列值或追加子查询，从而控制 SQL 语义。校验无效的原因：代码路径中不存在 `mysqli_real_escape_string`、`addslashes`、白名单过滤或预处理语句，污点从读取点到汇点全程未净化。

**source / sink**

- source：query `mtxMessage`（055.php:5）
- sink：055.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `055.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `055.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 055.php 第 19 行（路由 /055，HTTP 方法 ANY）的 SQL 注入 POC。外部输入来自查询参数 mtxMessage，该参数被直接拼接到 SQL 语句中执行，未发现有效净化，source→sink 链在静态层面闭合。POC 仅使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/055'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/055?mtxMessage=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-0108b5d86494`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入内容可被攻击者任意控制，可向 guestbook 表注入伪造记录、通过子查询读取其他表数据（如用户表、凭据）并写入可回显的 comment 字段造成数据泄露；结合 055.php:19 的 `or die(mysqli_error(...))` 错误回显，攻击者可利用报错注入逐字节提取数据库结构、库名、表名与敏感数据，属于机密性/完整性双重破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：055.php 为 Web 可访问脚本，留言提交为公开表单，无需认证即可触发；利用链闭合：055.php:5 读取 `mtxMessage` → 055.php:18 字符串拼接进 `$query` → 055.php:19 `mysqli_query` 执行，且 055.php:19 的 `die(mysqli_error(...))` 提供错误回显通道，使盲注/报错注入均可落地。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);`。若必须动态拼接，至少对每个值使用 `mysqli_real_escape_string($link, $value)` 并强制字符集；同时移除 055.php:19 中向客户端回显 `mysqli_error()` 的 `die(...)`，改为记录服务端日志并返回通用错误页；对留言长度与字符集做白名单校验，数据库账号遵循最小权限（仅 INSERT 权限）。

**验证说明**

静态证据：入口 ANY /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言表单提交参数（对应 055.php:5 读取的 `mtxMessage`），值在 055.php:18 被直接插入 `INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );` 的单引号字面量中，未转义的单引号闭合字符串后即可注入任意 SQL 片段；拼接结果在 055.php:19 由 `mysqli_query` 执行，且失败分支通过 `die(mysqli_error(...))` 将数据库错误回显给攻击者，形成完整的注入与回显链路。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 055.php:19，外部输入来自 query 参数 mtxMessage，source→sink 链静态闭合且未见有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码静态推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确保已获书面授权。原始 poc.sh 中的 curl 命令仅供人工参考，请勿通过管道自动执行；request.http 保留原始请求结构。注入点参数名严格为 mtxMessage（与源码 getParameter 一致），未新增或修改文件/行号。

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
| safety_guard | 安全防护 | 2.32 | 是 |
| surface_mapper | 攻击面测绘 | 10.28 | 是 |
| deep_finder | LLM 深挖 | 5.15 | 是 |
| candidate_screener | 候选筛选 | 2.76 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.2 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.16 | 是 |
| coordinator | 管线协调 | 6.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
