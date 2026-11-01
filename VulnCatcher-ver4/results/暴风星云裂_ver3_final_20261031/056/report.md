# 落日二号乙漏洞挖掘报告 — 20261031-014513-66e598

- 生成时间：2026-10-30T17:45:44.971102+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\056.zip`
- 输入模式：`zip`
- SHA256：`ddeedf015a89af3c4e7d2a26f3eadc8b063046e52cecc3d299334e66c93a1d75`
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

本次汇总仅含 1 条已去重 finding：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，origin=rule，has_poc=true），是本次最高危且唯一交付项。该文件为 22 行单文件 PHP 脚本，攻击面测绘显示 source 热点在 056.php:3、sink 热点在 056.php:1 附近，污点路径极短，与已报 SQL 注入结论方向一致；但输入仅给出行号级线索，未提供具体变量名与汇点函数，POC 属静态构造文本，未做动态验证。其余攻击面（命令执行、路径穿越、XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码密钥）本次均无 finding 交付，其中部分为策略档位外的待复核项，不能表述为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，DVWA 风格 guestbook 留言板）。数据流：$_POST['mtxMessage']（第5行）与 $_POST['txtName']（第6行）经 trim、stripslashes 后，在第10/13行通过 mysqli_real_escape_string 转义，再于第16行拼接进 INSERT 语句，第17行 mysqli_query 执行。由于两个可控参数在拼接前均经过 mysqli_real_escape_string（使用有效连接对象 ___mysqli_ston），单引号、反斜杠等元字符被转义，无法闭合字符串字面量改变 SQL 语法，未构成可闭合的 SQL 注入链；第17行 die(mysqli_error()) 仅在查询失败时回显错误，属信息泄露但需先能构造非法 SQL，链不闭合。第3行 isset($_POST['btnSign']) 仅为提交开关，非污点源。文件中未出现 exec/system/popen/proc_open、文件读写、include/require、反序列化、模板渲染、echo 输出用户数据等 sink，故 command_injection / path_traversal / xss / deserialization 均无证据。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/hardcoded_secret/trust_boundary）在 22 行代码中均未出现对应函数或标志位，不成立。未闭合/未覆盖：无 Web 服务器与 php.ini 配置，无法确认 056.php 外部可达性与认证要求；无数据库 schema，无法评估二次注入（本文件亦无读取回显点）；无 composer 依赖。按“宁可漏报不可误报”原则，不输出 finding。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认外部可达性与认证
- 无数据库 schema 与留言读取页面，二次注入的存储读点不可评估
- 无依赖清单，第三方库攻击面未覆盖
- code_pack 仅含单文件，其余项目文件视为不存在

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言板表单，外部输入在 056.php:5 被读入变量 $message（候选标注为 query `mtxMessage`，即留言内容字段），随后在 056.php:16 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，$message 被包裹在单引号内但未做任何转义或参数化处理。056.php:17 将该拼接后的 $query 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，构成危险汇点。由于缺少 mysqli_real_escape_string / 预处理语句，攻击者只需在留言内容中闭合单引号（如 ' , (SELECT ...))-- -）即可改变 SQL 语义。校验无效的原因：代码路径上不存在任何白名单、类型校验、转义或参数绑定，输入从读取到拼接全程保持原始污点状态。

**source / sink**

- source：query `mtxMessage`（056.php:5）
- sink：056.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `056.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `056.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /056（ANY）的 SQL 注入 POC。注入点：ANY 参数 mtxMessage；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/056'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/056?mtxMessage=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-23ca13029614`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可对后端 MySQL 数据库执行任意 INSERT 语义篡改，并通过闭合引号注入子查询/联合结构读取 guestbook 及其他表数据（数据泄露）；配合报错回显（die 中输出 mysqli_error）可实施报错型注入枚举库表结构；在数据库账号权限过高时可进一步读写文件或篡改业务数据。属于未认证远程可利用的 critical 级注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：056.php 为 Web 可直接访问脚本，留言提交参数来自 HTTP 请求，无需认证；利用链闭合：056.php:5 读取外部输入 → 056.php:16 字符串拼接进 INSERT → 056.php:17 mysqli_query 执行，三步在同一脚本内闭合，无净化环节。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：$stmt = $mysqli->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute();。若必须保留拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并强制字符集；同时对输入做长度与内容白名单校验；关闭 die() 中的数据库错误回显，改为记录日志并返回通用错误；数据库账号遵循最小权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 ANY /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言内容字段提交形如 `x'), (SELECT ...)-- -` 的载荷 → 056.php:5 读入 $message（未净化）→ 056.php:16 直接拼入 INSERT INTO guestbook 语句 → 056.php:17 mysqli_query 执行被篡改的 SQL，错误信息经 die() 回显给攻击者。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php:17 的 SQL 注入 POC（CWE-89）。注入点为查询参数 mtxMessage，其值被直接拼接到 SQL 语句中执行，未做参数化或有效转义。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php:17，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，需替换为授权目标后由人工手动执行。禁止使用 DROP/破坏性语句；建议仅使用布尔/报错类只读载荷。原始确定性 POC 的请求结构（GET /056?mtxMessage=...）予以保留，仅补充基线与对照步骤。

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
| safety_guard | 安全防护 | 2.09 | 是 |
| surface_mapper | 攻击面测绘 | 7.73 | 是 |
| deep_finder | LLM 深挖 | 3.36 | 是 |
| candidate_screener | 候选筛选 | 2.15 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.59 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.72 | 是 |
| coordinator | 管线协调 | 5.75 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
