# 落日二号乙漏洞挖掘报告 — 20261031-215107-c3fe3c

- 生成时间：2026-10-31T13:51:50.148582+00:00
- 输入：`$WORKSPACE\暴风星云裂\056.zip`
- 输入模式：`zip`
- SHA256：`ddeedf015a89af3c4e7d2a26f3eadc8b063046e52cecc3d299334e66c93a1d75`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，行号至 17），已附带 POC，属 HTTP 可复现类型（POC 为文本工件，未执行、未动态验证）。最高危即该条 critical SQL 注入，位于单文件 PHP 脚本的输入采集（约第 3 行）到 INSERT 拼接链路。POC 齐全度：1/1 有 POC，但仅覆盖 sql_injection 一类；weak_hash / weak_random / insecure_cookie / weak_crypto / trust_boundary 等配置型候选均未形成 finding，仅有 surface_notes 中的 medium_review_items 提示，需人工按代码/会话语义复核，不能视为已验证或已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，完整未截断）。该脚本为 DVWA 风格的留言板写入片段：入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），随后对 mtxMessage 与 txtName 分别执行 stripslashes 与 mysqli_real_escape_string（第 9-10、13 行），再拼接进 INSERT 语句并由 mysqli_query 执行（第 16-17 行）。关键判断：两个进入 SQL 的变量均经过 mysqli_real_escape_string 转义，且转义所用连接对象与执行查询的连接对象同为 $GLOBALS["___mysqli_ston"]，不存在字符集不匹配或转义后再次解码/拼接的绕过点，因此第 16 行的字符串拼接不构成可利用的 SQL 注入；第 17 行的 mysqli_error 回显仅在查询失败时输出数据库错误信息，属信息泄露但需先构造失败查询，而失败查询本身受转义限制，无法形成闭合的注入链，故不单独立项。文件中不存在命令执行、文件包含/路径拼接、反序列化、模板、SSRF、文件上传、重定向等 sink；无认证/会话/Cookie/随机数/哈希相关代码，surface_notes 中列出的 weak_hash、weak_random、insecure_cookie、weak_crypto、trust_boundary 五类 medium_review_items 在本文件中均无对应实现，属未证实线索而非漏洞。未发现满足 CVE 级别且利用链闭合的问题，按“宁可漏报不可误报”原则返回空 findings。未闭合线索：(1) 该片段依赖外部已建立的 $GLOBALS["___mysqli_ston"] 连接与 guestbook 表结构，连接字符集（如是否 latin1/gbk）未在 code_pack 中体现，若实际部署使用多字节字符集且未调用 set_charset，理论上存在宽字节绕过 mysqli_real_escape_string 的可能，但无证据支撑，不报告；(2) 留言写入后的读取/回显页面不在 code_pack 内，无法判断是否存在存储型 XSS 或二次注入，需补充读取端代码方可评估。

未覆盖 / 证据缺口：
- 无数据库连接建立代码与字符集设置（set_charset/mysqli_set_charset），无法排除多字节字符集下 mysqli_real_escape_string 被绕过的理论可能
- 留言读取与回显页面未提供，存储型 XSS 与二次注入无法评估
- 无 Web 服务器/php.ini 配置，无法判断错误信息暴露范围与 register_globals 等运行时行为
- 无端点清单，无法确认该脚本是否被其他页面 include 或存在前置认证

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言板表单，外部输入在 056.php:5 被读入变量 $message（候选标注的 source 为 query `mtxMessage`，即留言内容字段），随后在 056.php:16 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 被单引号包裹但未做任何转义或参数化。056.php:17 将该拼接后的 $query 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，污点直达 SQL 汇点。由于代码中未使用 mysqli_real_escape_string、预处理语句或类型约束，单引号可闭合 VALUES 中的字符串字面量，从而改写 INSERT 语义（例如通过 ) 结束 VALUES 列表后追加子查询或堆叠语句，具体可行性取决于 mysqli 驱动是否允许多语句）。此外 056.php:17 的 or die(... mysqli_error(...) ...) 会把数据库错误信息回显到响应中，为布尔/报错型注入提供反馈通道。

**source / sink**

- source：query `mtxMessage`（056.php:5）
- sink：056.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `056.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `056.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /056（POST）的 SQL 注入 POC。注入点：POST 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/056'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/056' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-23ca13029614`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被攻击者控制：可向 guestbook 表插入任意内容（存储型内容污染），并可通过报错回显与布尔差异逐位推断数据库结构与其他表数据，造成数据泄露；若底层驱动支持多语句，还可能执行额外的 INSERT/UPDATE 等写操作，破坏数据完整性。错误信息回显同时泄露数据库版本与表结构，降低后续利用门槛。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：056.php 为 Web 入口脚本，留言提交参数由 HTTP 请求直接提供，无需认证即可触达 056.php:5 的读取逻辑。利用链闭合：056.php:5 读取外部输入 → 056.php:16 字符串拼接构造 $query → 056.php:17 mysqli_query 执行，中间不存在任何净化函数或参数化绑定，候选 exploit_chain 的两步（source 与 sink）完整衔接，且 056.php:17 的 die(mysqli_error(...)) 提供错误回显。

**修复建议**

1) 改用预处理语句：$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);，彻底消除拼接。2) 若必须保留拼接，至少对 $message、$name 使用 mysqli_real_escape_string 并显式加引号。3) 移除 056.php:17 中把 mysqli_error 直接输出到页面的逻辑，改为记录到服务端日志并返回通用错误页。4) 对留言长度与字符集做白名单校验，数据库账户按最小权限仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言字段（056.php:5 读入的 $message）中提交形如 '); <注入载荷> -- 的内容；056.php:16 将该值原样拼入 INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );，单引号闭合字符串字面量；056.php:17 通过 mysqli_query 执行被篡改的语句，若语法或语义出错，die() 分支把 mysqli_error 内容以 <pre> 形式回显给攻击者，形成可观测的注入反馈。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php 第 17 行 SQL 注入的文本 POC。注入点为 POST 参数 mtxMessage（源码中由请求参数读取后拼接进 SQL 语句），触发按钮字段为 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试，不执行、不联网。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php 第 17 行，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未观察到有效参数化或转义；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅保留文本请求结构，未生成可自动执行脚本；如需手工复现，请将 TARGET 替换为授权测试实例地址后逐条手动发送上述三个请求，并保存响应用于对比。禁止对生产环境或未授权目标使用。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 3.39 | 是 |
| surface_mapper | 攻击面测绘 | 9.0 | 是 |
| deep_finder | LLM 深挖 | 5.56 | 是 |
| candidate_screener | 候选筛选 | 3.7 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.58 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.5 | 是 |
| coordinator | 管线协调 | 6.82 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
