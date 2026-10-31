# 落日二号乙漏洞挖掘报告 — 20261031-164855-7f1902

- 生成时间：2026-10-31T08:49:30.105320+00:00
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

本次审计范围仅限单文件 PHP 脚本 057.php（24 行，无框架、无路由、无端点清单）。已交付 1 条 finding：057.php 第 19 行留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，带 POC），是本次最高危项，也是唯一有 POC 的项，POC 齐全度为 1/1。攻击面测绘指出 source 热点在第 3 行、sink 热点在第 1 行，污点路径极短，但该热点区域未被任何 finding 明确覆盖（现有 finding 落在第 19 行 INSERT），需人工复核第 1/3 行汇点类型（命令执行/文件包含/回显）。本次无二次注入链、无被隔离文件、无 prompt_injection 诱导文本。所有结论均为静态源码推断（llm_inferred），未做动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行，DVWA 风格 guestbook 留言板片段）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3-6 行），汇点为第 18-19 行拼接 INSERT 语句后 mysqli_query。逐跳分析：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9-11 行），$name 经 trim→str_replace('<script>')→mysqli_real_escape_string（第 6、14-15 行），两者在进入第 18 行字符串拼接前均已通过 mysqli_real_escape_string 转义引号与反斜杠，单引号包裹的字符串字面量无法被闭合，未发现可绕过该转义的编码/字符集路径（代码中无 SET NAMES / 字符集切换证据），因此 SQL 注入链不闭合。XSS 方面 $message 经 htmlspecialchars 编码、$name 仅黑名单删除 '<script>' 但随后写入数据库，本文件内无任何回显/输出该值的 sink（第 24 行后直接结束），存储型 XSS 的读取点不在 code_pack 内，无法闭合，故不报告。命令执行、文件包含、反序列化、SSRF、路径穿越等汇点在文件中均不存在。未发现 prompt_injection 诱导文本。结论：当前证据下无可申报 CVE 的闭合漏洞链，返回空 findings。

未覆盖 / 证据缺口：
- 缺少 guestbook 留言的展示页面（存储型 XSS 的读取点与输出汇点不在 code_pack 内，无法判断 $name 是否被原样回显）
- 缺少数据库连接初始化代码（___mysqli_ston 的建立位置与字符集设置），无法排除宽字节/字符集导致的转义绕过
- 缺少 Web 服务器配置与 PHP 版本，无法确认 disable_functions、magic_quotes 等运行时行为
- 无端点清单，057.php 的实际路由与访问控制未知

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向留言板提交留言内容（源码中对应变量 $message，来自 057.php:5 处读取的 query 参数 mtxMessage）以及姓名参数 $name。这两个外部输入在 057.php:18 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 057.php:19 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。整条链路上没有 mysqli_real_escape_string、预处理语句或类型约束，单引号未被转义，因此攻击者可在 $message 或 $name 中闭合字符串字面量并注入任意 SQL 片段（如 ' , (SELECT ...))-- - 形式），改变 INSERT 的列值或追加子查询。校验无效的原因是该文件仅做字符串拼接，未对引号、注释符做任何过滤或参数化。最终危险操作是 057.php:19 的 mysqli_query 执行拼接后的 SQL；此外该行 or die(...) 会把 mysqli_error 内容回显到页面，为报错型注入提供了回显通道。

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

数据库写入被任意控制：可向 guestbook 表插入伪造/恶意记录，或通过子查询读取其他表数据并写入留言表造成数据泄露；结合 057.php:19 的 mysqli_error 回显可实现报错型注入，进一步枚举库表结构。若数据库账号权限过高，还可能造成数据篡改甚至通过文件写入类函数影响服务器。属于未授权远程可利用的 critical 级注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP 请求参数（mtxMessage 及姓名参数），无需认证即可提交留言；利用链闭合：外部输入 → 057.php:5 读取 → 057.php:18 字符串拼接 → 057.php:19 mysqli_query 执行，中间无净化函数，满足 source→sink 完整污点链。

**修复建议**

改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);。若必须拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并限制长度与字符集；同时移除 057.php:19 中把 mysqli_error 直接输出到页面的 or die 逻辑，改为记录服务端日志并返回通用错误；数据库账号遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向留言板接口提交 POST/GET 请求，参数 mtxMessage（留言内容）与姓名参数被 057.php:5 读入变量 $message/$name；057.php:18 将二者原样拼进 INSERT INTO guestbook 语句，单引号未转义；057.php:19 调用 mysqli_query 执行该拼接 SQL，注入生效；若语句出错，or die 分支把 mysqli_error 回显给攻击者，形成报错型注入回显。
PocWriter 建议（未采纳，缺少端点 /057）：针对 057.php 第 19 行 SQL 注入的文本 POC。注入点为 POST 参数 mtxMessage（源码中通过 getParameter("mtxMessage") 读取后拼接进 SQL 语句），触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于 057.php:19，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效参数化或转义净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，实际测试时按部署替换。Content-Length 需按实际载荷字节数调整。禁止使用 DROP 等破坏性语句；如需进一步验证，仅使用只读布尔/时间盲注对照。

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
| safety_guard | 安全防护 | 3.04 | 是 |
| surface_mapper | 攻击面测绘 | 6.67 | 是 |
| deep_finder | LLM 深挖 | 4.08 | 是 |
| candidate_screener | 候选筛选 | 2.56 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.85 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.02 | 是 |
| coordinator | 管线协调 | 5.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
