# 落日二号乙漏洞挖掘报告 — 20261031-012320-5dfba0

- 生成时间：2026-10-30T17:23:56.900117+00:00
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

本次汇总仅包含 1 条已去重 finding：057.php 第 19 行附近的留言板 INSERT 语句 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径清晰）。这是本次唯一交付项，也是最高危项。POC 齐全度为 1/1，无缺失。需注意：surface_notes 明确说明未提供 057.php 源码正文，攻击面测绘基于文件清单与热点行号推断（llm_inferred），因此该 finding 的上下文（过滤函数、参数名、是否预处理）仍需人工对照源码复核；本报告不声称已做动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行，DVWA 风格 guestbook 留言脚本）。入口为 POST 参数 btnSign/mtxMessage/txtName（第 3、5、6 行），汇点为第 18-19 行字符串拼接的 INSERT 语句经 mysqli_query 执行。逐跳核查：$message 经 trim→strip_tags→addslashes→mysqli_real_escape_string→htmlspecialchars（第 5、9、10、11 行），$name 经 trim→str_replace('<script>','')→mysqli_real_escape_string（第 6、14、15 行），两者在进入拼接前均被 mysqli_real_escape_string 转义，单引号被转义，无法闭合第 18 行的字符串字面量，也未进入标识符/数字上下文，故不构成可闭合的 SQL 注入链；addslashes 与 real_escape_string 叠加仅造成双重转义，不产生绕过。第 14 行 str_replace 仅删除字面 '<script>'，属弱 XSS 过滤，但 $name 未在任何位置回显（脚本无 echo/print 输出该变量），且第 11 行对 $message 做了 htmlspecialchars，故无可利用的反射/存储型 XSS 输出汇点（存储型需读取页面，code_pack 中不存在读取/展示逻辑，三要素不齐，按规则不报）。脚本无 include/require、无文件路径拼接、无 system/exec/proc_open、无反序列化、无 SSRF、无 setcookie/session、无 md5/sha1/rand 等实现类证据，surface_notes 中列出的命令执行、路径穿越、弱哈希、弱随机、insecure_cookie、trust_boundary 等攻击面在本文件中均无对应代码，属推断而非事实。未发现满足 CVE 级别且利用链闭合的漏洞，故 findings 为空。未闭合线索：若存在其他文件读取并展示 guestbook 表内容（如 view 页面），第 14 行仅过滤 '<script>' 的弱过滤可能导致存储型 XSS，但该读取点不在 code_pack 内，无法确认，按规则不报告。输入中未出现诱导性文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- code_pack 仅含 057.php，无数据库连接初始化代码（$GLOBALS['___mysqli_ston'] 的来源）、无展示 guestbook 内容的读取页面，无法评估存储型 XSS 的读取汇点
- 无 php.ini/Web 服务器配置，无法确认 magic_quotes、字符集（影响 real_escape_string 有效性）等运行时条件
- 无部署与鉴权信息，无法判断该脚本是否暴露于未认证边界
- surface_notes 中命令执行、路径穿越、弱哈希/弱加密/弱随机、insecure_cookie、trust_boundary 等面在本文件中无对应代码，属清单层推断，未形成证据

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向留言板提交评论/姓名，输入在 057.php:5 附近被读取为 $message 与 $name（候选标注 source 为 query `mtxMessage`，即请求参数 mtxMessage 对应的留言内容）。这两个变量未经任何转义或参数化，直接在 057.php:18 被拼接进 SQL 字符串：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 057.php:19 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于变量被包裹在单引号内且未调用 mysqli_real_escape_string / 预处理语句，攻击者只需在提交内容中放入单引号即可闭合字符串字面量，再追加任意 SQL 片段（如通过 name 字段构造 '),('... 或利用注释符截断），从而改变 INSERT 语句语义。校验无效的原因：代码路径中不存在白名单、类型校验、长度限制或转义处理，唯一“处理”是把原始值直接做字符串插值。最终危险操作是 057.php:19 的 mysqli_query 执行被篡改的 SQL；此外该行在失败时通过 die() 回显 mysqli_error，会把数据库错误信息（表名、列名、语法片段）返回给攻击者，为盲注/报错注入提供反馈通道。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 057.php 第 19 行（端点 /057，HTTP 方法 ANY）的 SQL 注入 POC。外部输入来自查询参数 mtxMessage，该参数未经有效净化即被拼接进 SQL 语句，构成 CWE-89。目标地址统一使用 TARGET 占位符，POC 仅为文本工件，不执行、不联网。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/057'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/057?mtxMessage=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-71dd317be73f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库写入被任意控制：可向 guestbook 表插入伪造/恶意记录，或通过子查询、堆叠/联合技巧读取其他表数据（如用户凭据），造成数据泄露与数据完整性破坏；错误回显进一步降低利用门槛。若数据库账户权限过高，还可能扩展到其他表的篡改。属于典型的存储型 SQL 注入，影响所有可访问该留言提交端点的未认证用户。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点位于 PHP 页面 057.php 的请求参数处理路径，任何能访问该页面的远程用户均可提交；无需认证，代码中未见任何会话/权限校验；利用链闭合：外部输入 → $message/$name（057.php:5 附近）→ 字符串拼接 $query（057.php:18）→ mysqli_query 执行（057.php:19），中间无净化函数，链路完整。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

1) 改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, 'ss', $message, $name); mysqli_stmt_execute($stmt);，彻底消除拼接。2) 若短期无法改造，至少对 $message/$name 使用 mysqli_real_escape_string 并配合严格白名单（长度、字符集）。3) 关闭错误回显：生产环境不要 die(mysqli_error(...))，改为记录日志并返回通用错误页。4) 数据库账户遵循最小权限，仅授予 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言提交表单的 mtxMessage（及 name）字段中构造含单引号的载荷 → 057.php:5 附近读取为 $message/$name → 057.php:18 直接拼接进 INSERT 语句 → 057.php:19 mysqli_query 执行被篡改的 SQL，并通过 die(mysqli_error) 回显数据库错误，形成可迭代的注入反馈。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 057.php:19，外部输入来自 query 参数 mtxMessage，source→sink 链在静态审计中闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。poc.sh 与 request.http 为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权目标，并手动逐条发送；禁止使用 DROP 等破坏性语句。注入通道为查询参数 mtxMessage，与源码 getParameter("mtxMessage") 一致。

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
| safety_guard | 安全防护 | 2.55 | 是 |
| surface_mapper | 攻击面测绘 | 10.0 | 是 |
| deep_finder | LLM 深挖 | 4.86 | 是 |
| candidate_screener | 候选筛选 | 2.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.23 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.41 | 是 |
| coordinator | 管线协调 | 5.88 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
