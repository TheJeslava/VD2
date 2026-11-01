# 落日二号乙漏洞挖掘报告 — 20261031-173428-70ee97

- 生成时间：2026-10-31T09:35:04.165619+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\057.zip`
- 输入模式：`zip`
- SHA256：`e5aacb8c730b8fc545d6f2efe30ad90b9aa52a5009f9f368746231c2685d2e23`
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

本次汇总仅含 1 条已去重 finding：057.php 第 19 行留言板 INSERT 语句 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可针对 TARGET 复现，仅限授权测试）。这是本次最高危且唯一交付项。POC 齐全度：1/1 有 POC，但该 POC 属静态构造+HTTP 请求文本，未做动态验证。整体攻击面覆盖极窄：仅 1 个 PHP 文件、0 个端点、无框架，code_pack 未提供代码正文，因此除该条注入外的判断均受限于证据缺口。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行，未截断）。该脚本在 $_POST['btnSign'] 存在时读取 $_POST['mtxMessage'] 与 $_POST['txtName']，经 strip_tags/addslashes/mysqli_real_escape_string/htmlspecialchars 处理后拼接进 INSERT 语句并由 mysqli_query 执行（第 18-19 行）。逐跳核查：$message 经 addslashes + mysqli_real_escape_string + htmlspecialchars，$name 经 str_replace('<script>','') + mysqli_real_escape_string，两者在进入 SQL 前均被 mysqli_real_escape_string 转义，单引号被转义，无法闭合第 18 行的字符串字面量，未发现可闭合的 SQL 注入链；mysqli_real_escape_string 依赖 $GLOBALS['___mysqli_ston'] 为有效连接对象，若未初始化则走 trigger_error 分支返回空串，同样不构成注入。XSS 方面 $message 经 htmlspecialchars、$name 经 strip_tags 与 mysqli_real_escape_string，且本文件无任何输出回显点（无 echo/print 到 HTML），不构成反射/存储型 XSS 的读取汇点证据。文件中未出现 exec/system/passthru、include/require、file_get_contents/fopen、unserialize、md5/sha1、rand/mt_rand、setcookie 等汇点，故 command_injection、path_traversal、ssrf、deserialization、weak_hash、weak_crypto、weak_random、insecure_cookie 均无源码证据。surface_notes 中提到的 getParameterMap/Runtime.exec/new File 等为通用提示，实际代码中并不存在。未闭合线索：$GLOBALS['___mysqli_ston'] 的初始化位置不在 code_pack 内（可能在其他被包含文件中），无法确认数据库连接与字符集设置；若连接字符集为 GBK 等宽字节且未调用 set_charset，mysqli_real_escape_string 的转义在特定条件下可能被宽字节绕过，但该前提在给定代码中无证据，故不作为 finding 上报。整体判断：在可见代码范围内未发现满足 CVE 级

未覆盖 / 证据缺口：
- $GLOBALS['___mysqli_ston'] 数据库连接的初始化与字符集设置不在 code_pack 内，无法排除宽字节/字符集相关的转义绕过
- 无部署配置（php.ini、Web 服务器），无法确认 register_globals、magic_quotes 等环境对转义的影响
- 无端点/路由清单，无法确认该脚本的访问控制与暴露面
- 无依赖清单，无法评估第三方组件漏洞

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 057.php 提交留言板表单，外部输入在 057.php:5 被读入变量 $message（候选标注的 source 为 query `mtxMessage`）。该值未经任何转义或参数化，在 057.php:18 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 057.php:19 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 位于单引号字符串字面量内部，攻击者只需闭合单引号即可跳出值上下文注入任意 SQL 片段（例如在 comment 字段中构造 ' , (SELECT ...))-- - 之类的载荷），无需任何认证即可触发。代码中不存在 mysqli_real_escape_string、prepared statement 或类型白名单，因此校验完全缺失。注意：输入片段仅给出 057.php:17-19 与 source 行 057.php:5，$name 的具体取值行未在片段中展示，其是否同样可注入属证据不足，本 finding 仅就 $message 链闭合。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /057（POST）的 SQL 注入 POC。注入点：POST 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/057'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/057' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-71dd317be73f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入型注入：攻击者可任意改写 INSERT 语句，向 guestbook 表写入伪造/恶意内容，或通过子查询读取其他表数据（如用户表、凭据表）并借助 057.php:19 的 die(mysqli_error(...)) 错误回显把查询结果/结构泄露到 HTTP 响应中，造成敏感数据泄露；在数据库账号权限过高时还可能通过堆叠/文件写入原语进一步扩大影响。无需认证、外部网络可达。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为留言板提交参数，属匿名可访问的 Web 入口；无需认证；利用链闭合：057.php:5 读取外部输入 → 057.php:18 字符串拼接进 $query → 057.php:19 mysqli_query 执行，中间无净化函数，且错误信息经 die() 回显，可作为注入成功的判定与数据外带通道。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);。若短期无法改造，至少对 $message/$name 使用 mysqli_real_escape_string 并配合长度/字符白名单校验；同时移除 057.php:19 中把 mysqli_error 直接输出到页面的 die() 分支，改为记录服务端日志并返回通用错误；数据库账号按最小权限授予，仅保留 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单提交 comment 内容 → 057.php:5 读入 $message → 057.php:18 以单引号包裹方式拼接为 INSERT 语句 → 057.php:19 mysqli_query 执行 → 注入生效，错误信息经 die(mysqli_error(...)) 回显到响应。
PocWriter 建议（未采纳，缺少端点 /057）：针对 057.php:19 的 SQL 注入 POC（CWE-89）。注入点为 POST 参数 mtxMessage，该值被直接拼接进 SQL 查询；提交按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于 057.php:19，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件；证据等级为 llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，仅限授权测试。Content-Length 需按实际载荷字节数调整。若目标使用不同端口/路径前缀，仅替换 TARGET 与端口，不改注入点字段名 mtxMessage 与触发字段 Submit。

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
| safety_guard | 安全防护 | 2.78 | 是 |
| surface_mapper | 攻击面测绘 | 8.06 | 是 |
| deep_finder | LLM 深挖 | 4.31 | 是 |
| candidate_screener | 候选筛选 | 3.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.81 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.13 | 是 |
| coordinator | 管线协调 | 6.23 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
