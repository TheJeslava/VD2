# 落日二号乙漏洞挖掘报告 — 20261031-010600-e34e41

- 生成时间：2026-10-30T17:06:30.738143+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\055.zip`
- 输入模式：`zip`
- SHA256：`3e6e2cddd55f2250b6f1a0ec122303bfa0c923af602a09aecf8d75ca2f525ece`
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

本次汇总仅含 1 条已去重 finding：055.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，已附 POC），位于 055.php 第 19 行附近，属请求参数到 SQL 汇点的短链路注入，是本次最高危项。POC 齐全度：1/1 条 finding 带 POC，但该 POC 为静态证据型文本工件，未做动态验证，不能宣称可动态复现。覆盖面上仅审计了 1 个 PHP 文件（055.php，24 行），无端点清单、无框架、无配置与依赖信息，攻击面测绘中的 path_traversal/LFI、反射型 XSS、weak_hash、hardcoded_secret、trust_boundary 等方向均未被 findings 覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（1-24 行，DVWA 风格 guestbook 留言板）。入口为 POST 参数 btnSign/mtxMessage/txtName。两条污点链均被服务端转义闭合：$message 经 addslashes + mysqli_real_escape_string + htmlspecialchars（第 9-11 行），$name 经 preg_replace 去 script + mysqli_real_escape_string（第 14-15 行），随后在第 18 行拼接进 INSERT 语句、第 19 行 mysqli_query 执行。mysqli_real_escape_string 对单引号、反斜杠等做了正确转义，无法闭合第 18 行的单引号字符串，故不构成 SQL 注入；htmlspecialchars 使 $message 回显（若后续页面读取）不构成 XSS；$name 的 preg_replace 黑名单虽弱，但后续 mysqli_real_escape_string 已阻断注入，且本文件内无 echo 输出点，无法确认存储型 XSS 的读取端（读取页面不在 code_pack 内，视为不存在）。未发现命令执行、文件包含、反序列化、SSRF 等 sink。medium_review_items 提到的 weak_hash/hardcoded_secret/trust_boundary 在代码正文中均无对应实现（无 md5/sha1、无硬编码口令、无鉴权敏感操作）。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认部署与暴露面
- 无数据库连接建立代码（$GLOBALS['___mysqli_ston'] 来源不在 code_pack），无法确认字符集设置；若连接未设 utf8 且使用 GBK 等宽字节字符集，mysqli_real_escape_string 可能被宽字节绕过，但该前提无证据支撑，故不报告
- guestbook 留言的读取/展示页面不在 code_pack，存储型 XSS 的读取端与危险汇点无法闭合
- 无版本信息，无法关联已知 CVE

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言板表单，外部输入在 055.php:5 被读入变量 $message（候选标注的 source 为 query `mtxMessage`，即留言内容字段）。该值未经任何转义或参数化，在 055.php:18 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );",随后在 055.php:19 通过 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 位于单引号字符串字面量内部且未调用 mysqli_real_escape_string 等转义函数、也未使用预处理语句，攻击者可闭合单引号并注入任意 SQL 片段（如 ' , (SELECT ...))-- - 形式），使 INSERT 语句被改写或追加子查询。校验无效的原因是该路径上不存在白名单、类型校验或参数绑定，仅有字符串拼接。最终危险操作是 055.php:19 的 mysqli_query 执行被污染的 $query；此外该行在失败时通过 die() 回显 mysqli_error，构成基于报错的注入反馈通道，便于攻击者构造盲注/报错注入。

**source / sink**

- source：query `mtxMessage`（055.php:5）
- sink：055.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `055.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `055.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /055 端点（HTTP 方法 ANY）的 SQL 注入 POC。注入点为查询参数 mtxMessage，源码 055.php:19 将该参数直接拼入 SQL 语句，未做有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

数据库写入与读取权限被攻击者控制：可向 guestbook 表插入任意数据、通过子查询读取其他表（如用户表、凭据）内容并借助报错回显外带，造成敏感数据泄露；在数据库账户权限较高时可进一步读写文件或篡改数据，属于数据泄露与数据完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：055.php 为可直接 HTTP 访问的留言板脚本，注入点为表单提交的留言字段，无需认证即可触发；利用链闭合：055.php:5 读取外部输入 → 055.php:18 字符串拼接构造 $query → 055.php:19 mysqli_query 执行，且失败分支回显数据库错误，形成完整可利用链。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt); 2) 若必须拼接，至少对每个值调用 mysqli_real_escape_string 并加引号；3) 对 $message/$name 做长度与字符白名单校验；4) 关闭生产环境的数据库错误回显，改为记录日志并返回通用错误页；5) 数据库账户遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言字段（055.php:5 读入的 $message）中提交形如 x'), (SELECT ...)-- - 的载荷；该值在 055.php:18 被原样拼入 INSERT 语句，未做转义；055.php:19 的 mysqli_query 执行被篡改的 $query，注入的子查询/表达式在数据库端执行，结果可通过 055.php:19 的 die(mysqli_error(...)) 报错回显被攻击者获取，完成从外部输入到数据库执行的闭合链路。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于 055.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止使用 DROP 等破坏性语句。request.http 中的 Content-Length 按 payload 长度计算，实际发送时以工具自动计算为准。

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
| safety_guard | 安全防护 | 3.06 | 是 |
| surface_mapper | 攻击面测绘 | 6.49 | 是 |
| deep_finder | LLM 深挖 | 3.46 | 是 |
| candidate_screener | 候选筛选 | 2.95 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.64 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.64 | 是 |
| coordinator | 管线协调 | 5.29 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
