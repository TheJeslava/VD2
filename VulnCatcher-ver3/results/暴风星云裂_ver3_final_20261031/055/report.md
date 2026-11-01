# 落日二号乙漏洞挖掘报告 — 20261031-014501-5283ea

- 生成时间：2026-10-30T17:45:34.240940+00:00
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

本次汇总仅含 1 条已去重 finding：055.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，origin=rule，已附 POC）。该漏洞是本次唯一且最高危的问题，污点从 055.php:3 附近的请求参数读取直达 055.php:19 的 INSERT 汇点，路径短、无中间过滤层，属单文件内直接注入。POC 齐全（with_poc=1/1），但仅为文本工件，未做动态验证。其余攻击面（文件包含/路径拼接、命令执行、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码凭据）在 surface_notes 中被列为待核查项，本次 findings 未覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（24 行，DVWA 风格 guestbook 留言板）。入口为 POST 参数 btnSign/mtxMessage/txtName（055.php:3-6）。两条污点流均汇入 055.php:18 的 INSERT 语句并在 055.php:19 执行。逐跳核查：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（055.php:5,9-11），$name 经 trim→preg_replace 过滤 script→mysqli_real_escape_string（055.php:6,14-15），两者在拼接前均被 mysqli_real_escape_string 转义，单引号被转义，无法闭合字符串改变 SQL 语法，未发现可闭合的 sql_injection 链。XSS 方面 $message 经 htmlspecialchars 编码、$name 经 mysqli_real_escape_string 转义后入库，输出上下文不在 code_pack 内，无法确认存储型 XSS 的读取点与输出编码缺失，证据不足不报告。未发现命令执行、文件包含、反序列化、SSRF、路径拼接等汇点；无 md5/sha1、rand/mt_rand、setcookie、硬编码凭据等配置型证据。surface_notes 中关于第 1 行汇点、第 3 行 source 的推断与实际代码不符（实际 source 在 3-6 行、sink 在 18-19 行），已按真实代码校正。未覆盖范围：无 composer/框架/服务器配置、无 endpoints、无输出渲染文件，无法评估存储型 XSS 与部署层风险；未记录到 prompt_injection 证据。

未覆盖 / 证据缺口：
- 无留言展示/输出页面，无法判定存储型 XSS 的输出上下文与编码
- 无数据库 schema 与字符集配置，无法排除宽字节注入等边缘情形
- 无认证/会话/部署配置，无法评估鉴权与服务器层风险

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.7`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向留言板提交留言内容（源码中对应变量 $message，候选标注的 source 为 query `mtxMessage`，即 055.php:5 处从请求读取的留言字段），该值未经任何转义或参数化处理，在 055.php:18 被直接拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 055.php:19 交由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $message 被包裹在单引号内且未调用 mysqli_real_escape_string 等转义函数、也未使用预处理语句，攻击者可闭合单引号并注入任意 SQL 片段（如通过 comment 字段构造 ' , (SELECT ...))-- - 之类的载荷），使原本的 INSERT 语义被改写。校验无效的原因：代码路径中不存在白名单、类型校验或参数绑定，仅依赖字符串拼接；同时 055.php:19 的 or die(...) 会把 mysqli_error 内容回显到页面，为报错型注入提供了反馈通道。最终危险操作是数据库写入/查询执行，攻击者可借此读取或篡改 guestbook 及其他可访问表的数据。

**source / sink**

- source：query `mtxMessage`（055.php:5）
- sink：055.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `055.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `055.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /055（HTTP 方法 ANY）的 SQL 注入 POC。注入点为查询参数 mtxMessage（源码 055.php:19 将该参数值直接拼入 SQL 语句），payload 使用 TARGET 占位符，仅限授权测试。

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

数据库层面的数据泄露与篡改：攻击者可利用报错回显与 UNION/子查询读取任意可访问表（如用户凭据、其他业务数据），并可向 guestbook 注入伪造记录或通过堆叠/子查询修改数据；在数据库账户权限过高时可能进一步读写文件或影响其他库。属于未授权远程可利用的 critical 级注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点位于留言提交处理逻辑，任何能访问该页面的远程用户均可提交 POST/GET 参数触发，无需认证；利用链闭合：外部输入 $message（055.php:5）→ 字符串拼接 $query（055.php:18）→ mysqli_query 执行（055.php:19），中间无净化函数，且错误信息回显（or die + mysqli_error）增强了可利用性。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);；2) 若必须拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并强制字符集；3) 关闭生产环境的数据库错误回显，将 mysqli_error 写入服务端日志而非响应体；4) 对留言长度与字符集做白名单校验；5) 数据库账户遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言提交表单的留言字段（$message，055.php:5 读取）中输入含单引号与 SQL 片段的载荷 → 该值未经转义直接进入 055.php:18 的 INSERT 语句字符串拼接 → 055.php:19 通过 mysqli_query 执行被篡改的 SQL → 数据库执行攻击者构造的语句，结果或错误信息经 or die(...mysqli_error...) 回显到页面，完成注入闭环。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于 055.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确保已获授权。request.http 中 Content-Length 仅作示例，实际发送时由客户端按 body 长度计算；GET 查询串方式无需 body。

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
| safety_guard | 安全防护 | 3.14 | 是 |
| surface_mapper | 攻击面测绘 | 8.77 | 是 |
| deep_finder | LLM 深挖 | 3.39 | 是 |
| candidate_screener | 候选筛选 | 2.54 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.12 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.82 | 是 |
| coordinator | 管线协调 | 5.11 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
