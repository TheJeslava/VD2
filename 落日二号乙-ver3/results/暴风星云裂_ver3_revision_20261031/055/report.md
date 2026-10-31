# 落日二号乙漏洞挖掘报告 — 20261031-012316-2cf3fc

- 生成时间：2026-10-30T17:23:49.377317+00:00
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

本次汇总仅含 1 条已去重 finding：055.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，规则命中，已附 POC），是本次唯一且最高危的问题，POC 齐全（1/1）。覆盖范围极小：仅 1 个 PHP 文件、0 个端点、无框架，属单文件短链路（source 在 055.php:3，sink 在 055.php:1 附近），数据流极短。除该 SQL 注入外，其余类型（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）在本次输入中均无 source 证据，但 24 行文件仍可能内联 md5()/sha1()/rand()/setcookie() 等调用，需人工通读确认，不能因 source 为空而排除。所有结论均为静态源码推断（llm_inferred / rule），未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已通读 code_pack 中唯一文件 055.php（1-24 行）。该文件为 DVWA 风格的留言板（guestbook）片段：入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），汇点为第 18-19 行拼接 INSERT 语句并 mysqli_query 执行。审计结论：两条污点链均被有效阻断，不构成可申报漏洞。(1) $message：第 9 行 addslashes + strip_tags，第 10 行 mysqli_real_escape_string（在 ___mysqli_ston 存在时生效），第 11 行 htmlspecialchars，单引号被转义，无法闭合第 18 行 VALUES 中的字符串字面量，SQL 注入不成立；输出侧亦被 htmlspecialchars 处理，XSS 不成立。(2) $name：第 14 行仅用正则剔除 script 关键字（黑名单，可绕过），但第 15 行 mysqli_real_escape_string 对单引号做了转义，同样无法逃逸字符串字面量，SQL 注入链不闭合；该字段未做 HTML 编码，若后续页面回显 name 则存在存储型 XSS 的可能，但本 code_pack 中不存在读取/回显该字段的代码（无 SELECT、无 echo），存储读点与危险汇点均不可见，按规则不报告，仅作为线索记录。第 10/15 行的 trigger_error 分支仅在 ___mysqli_ston 非对象时触发，属异常路径，不构成可利用点。配置类候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在 24 行内均无对应调用（无 md5/sha1/rand/mt_rand/setcookie/header 信任逻辑），不成立。未发现 prompt_injection 文本。

未覆盖 / 证据缺口：
- 缺少数据库连接初始化代码（___mysqli_ston 的建立位置），无法确认 mysqli_real_escape_string 是否在所有部署路径下都实际生效；若该全局对象未初始化，第 10/15 行会走 trigger_error 分支并返回空串，反而使注入不可用，因此不改变结论。
- 缺少留言列表读取/回显页面（SELECT 与 echo 部分），无法确认 $name 是否被原样输出到 HTML，故存储型 XSS 无法闭合，未报告。
- 缺少 php.ini / Web 服务器配置，无法确认 magic_quotes、字符集（GBK 宽字节注入）等影响转义有效性的运行时条件；若连接字符集为 GBK 且未调用 set_charset，宽字节注入理论上可绕过 mysqli_real_escape_string，但该配置不在 code_pack 内，属未闭合线索。
- 无路由与认证信息，无法确认该页面的实际 URL 与访问控制。

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言内容（源码中对应变量 $message，来自 query 参数 mtxMessage，见 055.php:5）以及姓名变量 $name。这两个外部输入未经任何转义或参数化处理，在 055.php:18 被直接拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 055.php:19 由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 与 $name 被单引号包裹但未调用 mysqli_real_escape_string 或使用预处理语句，攻击者可闭合单引号注入任意 SQL 片段（例如在 mtxMessage 中提交 ' , (SELECT ...))-- - 之类的载荷），从而改变 INSERT 语义或追加子查询。校验无效的原因：代码路径中不存在任何白名单、类型校验、转义或参数化，污点从 055.php:5 直达 055.php:19 汇点。

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

可对后端 MySQL 数据库执行任意 INSERT/子查询语句，导致留言表数据被伪造或污染、通过报错回显（die 中输出 mysqli_error）泄露数据库结构与版本信息；结合堆叠/子查询可进一步读取其他表数据（数据泄露），在数据库账号权限过高时可能造成数据篡改。属于未授权远程可利用的 SQL 注入。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：055.php 为 Web 入口，参数 mtxMessage 由 HTTP 请求直接提供，无需认证即可触发；利用链闭合：055.php:5 读取外部输入 → 055.php:18 字符串拼接构造 $query → 055.php:19 mysqli_query 执行，中间无净化函数，构成完整 source→sink 链。

**修复建议**

改用预处理语句与参数绑定：$stmt = $mysqli->prepare("INSERT INTO guestbook (comment, name) VALUES (?, ?)"); $stmt->bind_param('ss', $message, $name); $stmt->execute();。若必须拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并配合严格字符白名单与长度限制；同时关闭生产环境的 mysqli_error 回显（die 中不应输出数据库错误详情），并遵循最小权限原则为应用数据库账号仅授予必要表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 055.php 提交 mtxMessage 参数（055.php:5 读取为 $message）→ 055.php:18 将 $message/$name 直接拼入 INSERT 语句 → 055.php:19 mysqli_query 执行拼接后的 $query，注入的 SQL 片段随语句执行；错误分支通过 die 回显 mysqli_error，进一步暴露数据库信息。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 055.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止对生产环境直接运行。request.http 中的 Content-Length 依实际请求体长度调整。

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
| surface_mapper | 攻击面测绘 | 7.07 | 是 |
| deep_finder | LLM 深挖 | 4.74 | 是 |
| candidate_screener | 候选筛选 | 2.72 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.93 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.62 | 是 |
| coordinator | 管线协调 | 5.21 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
