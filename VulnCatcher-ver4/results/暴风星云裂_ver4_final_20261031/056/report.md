# 落日二号乙漏洞挖掘报告 — 20261031-173428-45334a

- 生成时间：2026-10-31T09:35:04.800900+00:00
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

本次汇总仅含 1 条已去重发现：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，带 POC）。该发现是唯一交付项，也是本次最高危项；其 POC 为 HTTP 型（留言板 INSERT 参数注入），但本次未提供代码正文，POC 文本与行号（056.php:1-17）需与源码逐行核对后方可视为可复现。整体覆盖极窄：仅 1 个 PHP 文件、0 个端点清单、无框架与依赖信息，攻击面测绘中的多数风险点（路径/包含类汇点、弱哈希、弱随机、Cookie 标志、硬编码凭据、信任边界）均未被 findings 覆盖，已转入人工复核。所有结论均为源码/静态层面推断，未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，DVWA 风格 guestbook 留言板片段）。第 3 行以 $_POST['btnSign'] 作为提交开关，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9 行 stripslashes，第 10/13 行经 mysqli_real_escape_string 转义，第 16 行拼接 INSERT 语句，第 17 行 mysqli_query 执行。虽然第 16 行是字符串拼接 SQL，但两个外部输入在进入拼接前都经过 mysqli_real_escape_string（依赖 ___mysqli_ston 连接对象），对引号、反斜杠等做了转义，未发现可改变 SQL 语法的注入点；stripslashes 在转义之前执行，不会削弱后续转义。第 17 行 die(mysqli_error()) 会把数据库错误回显给客户端，属于错误信息泄露，但需要先构造出 SQL 错误，而当前转义下攻击者难以注入语法错误，且该问题单独不足以申报 CVE，故不单独立项。文件中未出现 md5/sha1、rand/mt_rand、setcookie、硬编码凭据、include/require、文件操作、命令执行、反序列化等汇点，surface_notes 中列出的 weak_hash/weak_random/insecure_cookie/hardcoded_secret/trust_boundary 线索在代码正文中均无对应实现，属未闭合线索而非漏洞。未覆盖范围：无 php.ini/Web 服务器配置、无路由与部署信息、无依赖清单，无法确认该文件对外可达性与 ___mysqli_ston 的初始化来源（该全局连接对象在本片段之外建立，code_pack 未提供）。

未覆盖 / 证据缺口：
- ___mysqli_ston 全局连接对象的初始化代码不在 code_pack 内，无法确认其是否始终为有效 mysqli 对象；若未初始化，第 10/13 行会走 trigger_error 分支返回空串，反而使输入被清空
- 无 php.ini / Web 服务器配置，无法确认 allow_url_include、错误显示等运行时前提
- 无路由与部署信息，无法确认 056.php 是否对外可达
- 无依赖清单与版本历史，第三方组件与文件来源无法评估

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言板表单，外部输入在 056.php:5 被读入变量 $message（候选标注的 source 为 query `mtxMessage`，即留言内容字段）。该值未经任何转义或参数化，在 056.php:16 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 056.php:17 交由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 位于单引号字符串字面量内部，攻击者只需闭合单引号即可跳出字符串上下文并注入任意 SQL 片段（例如在 comment 值中构造 ' , (SELECT ...))-- - 之类的载荷），从而改变语句结构。代码中未见 mysqli_real_escape_string、预处理语句或类型白名单等任何有效净化，因此校验无效。注意：$name 同样以拼接方式进入同一语句，属于同一注入面。

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

数据库注入可导致 guestbook 表数据被任意篡改或伪造（数据完整性破坏），并可通过 UNION/子查询/报错回显读取同库其他表（如用户凭据）造成敏感数据泄露；结合 056.php:17 的 die(mysqli_error(...)) 报错回显，攻击者可获得数据库错误信息辅助盲注与结构探测。在数据库账户权限过高或支持堆叠/文件写入的情况下，存在进一步扩大影响（如写入文件）的可能，但该点证据不足，未在片段中确认。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：056.php 为 Web 入口脚本，输入来自 HTTP 请求参数，无需认证即可访问；利用链闭合：056.php:5 读取外部输入 → 056.php:16 字符串拼接构造 $query → 056.php:17 mysqli_query 执行，全程无净化函数介入，构成完整 source→sink 链。

**修复建议**

改用参数化查询：使用 mysqli_prepare 配合 bind_param 将 comment 与 name 作为绑定参数传入，例如 $stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);。若必须保留拼接，至少对两处变量统一使用 mysqli_real_escape_string 并显式加引号，同时校验输入长度与字符集。生产环境应关闭 056.php:17 的 mysqli_error 直接回显，改为记录日志并返回通用错误页。数据库账户遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 POST /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言字段（056.php:5 读入的 $message）中提交形如 x'), (SELECT ...)-- - 的载荷；该值在 056.php:16 被原样拼入 INSERT 语句，闭合原有单引号后注入新的 SQL 结构；056.php:17 的 mysqli_query 执行被篡改的 $query，注入生效，若语句出错还会通过 die(mysqli_error(...)) 回显数据库错误信息。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php:17 的 SQL 注入 POC（CWE-89）。注入点为 POST 参数 mtxMessage，该值被直接拼接进 SQL 查询；请求需同时携带触发按钮字段 Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php:17，外部可控输入 mtxMessage 经 POST 进入 SQL 汇点，静态 source→sink 链闭合且未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码静态审计，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，需在授权环境中手动替换为测试实例地址后人工执行。步骤2/3 构成真/假布尔对照，用于降低误报；若后端为盲注场景，可改用基于时间的载荷（如 SLEEP）并比较响应延迟，但需先补充源码确认数据库类型。禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 3.0 | 是 |
| surface_mapper | 攻击面测绘 | 7.84 | 是 |
| deep_finder | LLM 深挖 | 3.51 | 是 |
| candidate_screener | 候选筛选 | 3.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.62 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.49 | 是 |
| coordinator | 管线协调 | 6.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
