# 落日二号乙漏洞挖掘报告 — 20261031-012318-3a786f

- 生成时间：2026-10-30T17:23:52.251777+00:00
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

本次汇总仅含 1 条已去重 finding：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，已附 POC），是当前唯一且最高危的问题；该 POC 为 HTTP 型，但尚未动态验证。其余攻击面（文件包含/路径拼接、弱哈希、弱随机、弱加密、Cookie 标志、信任边界）均无 finding 交付，属未覆盖或需人工复核，不能据此认定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（22 行，完整展示）。该文件为 DVWA 风格的留言板片段：第 3 行以 $_POST['btnSign'] 作为提交开关，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9 行 stripslashes，第 10/13 行通过 mysqli_real_escape_string 对两个参数做转义，第 16 行拼接 INSERT 语句，第 17 行 mysqli_query 执行。虽然第 16 行是字符串拼接 SQL，但两个污点变量在进入拼接前均经过 mysqli_real_escape_string（依赖 $GLOBALS['___mysqli_ston'] 这个已建立的 mysqli 连接对象），在连接字符集为默认（utf8/utf8mb4 且正确设置）时单引号被转义，无法闭合第 16 行的单引号，因此不构成可闭合的 SQL 注入链；若连接字符集为 GBK 等宽字节且未 set_charset，理论上存在宽字节绕过，但 code_pack 中没有任何建立连接/设置字符集的代码（___mysqli_ston 由外部包含文件创建，不在 code_pack 内），该前提无法从给定代码证实，按零容忍误报原则不申报。第 17 行的 die(mysqli_error(...)) 会把数据库错误回显到页面，属于错误信息泄露，但仅在注入成功时才可利用，本身不构成独立 CVE 级漏洞。文件中未出现 exec/system/proc_open/eval/include/file 系列函数，无命令注入、代码注入、文件包含/路径穿越汇点；未出现 md5/sha1/rand/mt_rand/setcookie/session 相关调用，weak_hash/weak_random/weak_crypto/insecure_cookie 均无证据；未使用 $_SERVER 客户端头做信任判断，trust_boundary 无证据。surface_notes 中“source 在 056.php:3、sink 在 056.php:1”的热点为启发式推断，实际第 1 行为 <?php 开标签，并非危险汇点。未覆盖范围：___mysqli_ston 的初始化代码、数据库连接字符集设置、该文件是否被其它脚本包含、部署与鉴权配置均不在 code_pack 内，无法评估宽字节注入与前置鉴权。

未覆盖 / 证据缺口：
- ___mysqli_ston 的创建位置与连接字符集（set_charset / 初始化 SET NAMES）不在 code_pack，无法排除 GBK 宽字节 SQL 注入
- 无端点/路由与鉴权信息，无法确认该页面是否对外暴露、是否需登录
- 无 php.ini、Web 服务器配置与 composer 依赖，无法确认危险函数禁用情况与运行环境
- surface_notes 的 source/sink 行号热点与实际代码不符（第 1 行为 PHP 开标签），已按真实代码重新判定

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言板表单，外部输入在 056.php:5 被读入变量（候选标注为 query `mtxMessage`，即留言内容字段），随后在 056.php:16 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 与 $name 均以单引号包裹但未做任何转义或参数化。056.php:17 将该拼接后的 $query 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，构成危险汇点。由于代码未使用 mysqli_real_escape_string、预处理语句或类型约束，攻击者只需在留言内容中闭合单引号即可跳出字符串字面量，改写 INSERT 语义（例如追加子查询、改变插入列值，或利用报错回显探测结构）。校验无效的原因是该路径上不存在任何白名单、转义或参数绑定，污点从输入到汇点全程未净化。

**source / sink**

- source：query `mtxMessage`（056.php:5）
- sink：056.php:17 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `056.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `056.php:17` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /056 端点（HTTP 方法 ANY）的 SQL 注入 POC。注入点为查询参数 mtxMessage（对应源码 056.php:17 的 getParameter("mtxMessage") 取值后拼接进 SQL 语句），payload 为 ' OR '1'='1，目标地址统一使用 TARGET 占位符。本 POC 仅为文本工件，不执行、不联网。

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

数据库写入被攻击者控制：可向 guestbook 表注入任意行/任意列值（数据完整性破坏），可通过子查询读取其他表数据并写入留言表造成数据泄露，可借助 056.php:17 的 die(mysqli_error(...)) 报错回显获取库名、表名、列名等结构信息，为进一步利用（如堆叠/联合读取敏感表）提供条件。若数据库账号权限过高，影响可扩展至同库其他业务数据。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：056.php 为 Web 可访问脚本，输入来自 HTTP 请求参数，无需认证即可提交留言；利用链闭合：056.php:5 输入 → 056.php:16 字符串拼接 → 056.php:17 mysqli_query 执行，中间无净化点；报错信息经 die() 直接回显，降低盲注门槛。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);。2) 若必须拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并显式指定连接字符集。3) 对留言长度、字符集做白名单校验。4) 移除 die(mysqli_error(...)) 的原始错误回显，改为记录日志并返回通用错误页。5) 数据库账号遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言内容字段提交形如 `x'), ('y` 或含子查询的载荷 → 056.php:5 读入该值到 $message → 056.php:16 直接拼入 "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );"，单引号闭合使载荷成为 SQL 语法的一部分 → 056.php:17 mysqli_query 执行被篡改的语句 → 写入/读取结果落库，或经 die(mysqli_error(...)) 将数据库错误回显给攻击者。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php:17，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：仅限授权测试。所有请求中的主机统一为 TARGET:8080，需由测试人员手动替换为授权实例后自行执行；管线不执行、不联网、不搭建沙箱。POC 中不含 DROP/破坏性语句，不使用 curl|sh 形式。request.http 中的 Content-Length 按 body 字节数给出，实际发送时可由客户端自动计算。

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
| safety_guard | 安全防护 | 2.47 | 是 |
| surface_mapper | 攻击面测绘 | 7.22 | 是 |
| deep_finder | LLM 深挖 | 4.93 | 是 |
| candidate_screener | 候选筛选 | 2.59 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.46 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.16 | 是 |
| coordinator | 管线协调 | 5.26 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
