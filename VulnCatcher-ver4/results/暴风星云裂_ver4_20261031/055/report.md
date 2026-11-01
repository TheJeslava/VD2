# 落日二号乙漏洞挖掘报告 — 20261031-164842-5f0f1e

- 生成时间：2026-10-31T08:49:18.948131+00:00
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

本次汇总仅含 1 条已去重 finding：055.php 第 19 行留言板 INSERT 语句 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可针对 TARGET 复现，仅限授权测试）。这是本次最高危且唯一交付项。POC 齐全度为 1/1，但该 POC 属静态构造、未经动态验证。攻击面测绘显示 055.php 为 24 行单文件 PHP 脚本，source 热点在约第 3 行、sink 热点在约第 1 行，但输入未提供源码行内容，因此第 1 行汇点究竟是 include/echo/exec 还是数据库函数无法确认；surface_notes 中列出的 path_traversal、command_injection、xss、weak_hash、weak_random、insecure_cookie、weak_crypto、trust_boundary 等风险点均未被 findings 覆盖，已转入 human_review。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1482 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 055.php（1-24 行，完整未截断）。该脚本为 DVWA 风格的留言板写入逻辑：第 3 行以 isset($_POST['btnSign']) 作为入口判断，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9-11 行对 message 依次执行 strip_tags、addslashes、mysqli_real_escape_string、htmlspecialchars，第 14-15 行对 name 执行 preg_replace 黑名单（仅过滤 script 关键字）后再做 mysqli_real_escape_string，第 18 行拼接 INSERT 语句，第 19 行 mysqli_query 执行。<br><br>未闭合/不报告的线索：<br>1) SQL 注入：两个参数在拼接前都经过 mysqli_real_escape_string（依赖 $GLOBALS['___mysqli_ston'] 为有效连接对象），单引号被转义，未发现可改变 SQL 语法的路径；若运行时 ___mysqli_ston 未初始化，第 10/15 行会走 trigger_error 分支返回空串，同样不构成注入。链不闭合，不报告。<br>2) XSS：message 经 htmlspecialchars 转义；name 仅做 script 关键字黑名单，未做 HTML 实体编码，理论上可注入 <img onerror> 等非 script 标签。但本 code_pack 中不存在任何读取 guestbook 表并输出到页面的代码（无 SELECT、无 echo 渲染逻辑），存储读点与危险汇点均不可见，二次注入链缺少「读取后的危险汇点」这一必要环节，按规则不报告，仅作为线索记录。<br>3) 配置类候选（weak_hash/weak_random/insecure_cookie/weak_crypto/trust_boundary）：24 行内无 md5/sha1、rand/mt_rand、setcookie/session_set_cookie_params、mcrypt/openssl_encrypt 调用，均不成立。<br>4) 无命令执行、文件包含、反序列化、SSRF、路径穿越相关 sink。<br><br>未覆盖范围：无 Web 服务器/PHP 版本/php.ini 信息；无 guestbook 表的读取端页面（若存在则 name 字段的黑名单过滤可能构成存储型 XSS，需补充读取端代码后再评估）；无认证与部署信息。输入中未出现诱导性指令文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- 缺少 guestbook 表读取/渲染端代码，无法评估 name 字段黑名单过滤是否导致存储型 XSS
- 缺少 $GLOBALS['___mysqli_ston'] 初始化代码（数据库连接文件），无法确认 mysqli_real_escape_string 在运行时是否真正生效
- 缺少部署配置（PHP 版本、php.ini、Web 服务器），无法判断运行时行为
- 无端点清单与认证信息，无法确认该脚本是否需登录访问

## 3. Findings

### F-1: 055.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`055.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 055.php 提交留言表单，外部输入在 055.php:5 被读入变量 $message（候选 source 记为 query `mtxMessage`，即留言内容字段），随后在 055.php:18 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 被单引号包裹但未做任何转义或参数化。该拼接后的 $query 在 055.php:19 传入 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，构成从外部输入到 SQL 执行汇点的完整污点链。由于缺少 mysqli_real_escape_string / 预处理语句，攻击者只需在留言内容中闭合单引号即可跳出字符串字面量并注入任意 SQL 片段；055.php:19 的 or die(...) 分支还会把 mysqli_error 内容回显到页面，为报错型注入提供了回显通道。

**source / sink**

- source：query `mtxMessage`（055.php:5）
- sink：055.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `055.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `055.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 055.php 第 19 行（POST 路由 /055）的 SQL 注入 POC。外部输入来自 POST 参数 mtxMessage，该值被直接拼接进 SQL 查询并执行，未做参数化或有效转义。POC 使用布尔恒真载荷验证注入是否生效，目标地址统一使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/055'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/055' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'mtxMessage=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-0108b5d86494`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库层面的任意 SQL 执行：可读取、篡改或删除 guestbook 及其他同库表数据（数据泄露/完整性破坏），可结合报错回显进行盲注或联合查询提取凭据；若数据库账户权限过高，还可通过文件读写或堆叠语句进一步扩大影响，具体取决于 MySQL 账户权限与驱动是否允许多语句（证据不足，未在片段中体现）。

**CVE / CWE 论证**

CWE-89（SQL 注入）：外部可控输入 $message 未经参数化或转义即拼接进 SQL 语句并在 055.php:19 执行，属于典型的注入类缺陷。外部可达性：055.php 为 Web 可访问脚本，输入来自请求参数，无需认证即可提交留言；利用链闭合：source（055.php:5 读取留言内容）→ 拼接（055.php:18）→ sink（055.php:19 mysqli_query），中间无有效净化，且错误信息回显降低了利用门槛。

**修复建议**

改用预处理语句与参数绑定：$stmt = mysqli_prepare($link, "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, "ss", $message, $name); mysqli_stmt_execute($stmt);。若必须使用拼接，至少对每个变量调用 mysqli_real_escape_string 并强制使用正确的字符集。同时关闭生产环境的数据库错误回显（移除 or die(mysqli_error(...))），改为记录日志并返回通用错误页；数据库账户遵循最小权限，仅授予该表 INSERT 权限。

**验证说明**

静态证据：入口 POST /055；source=query/mtxMessage；sink=055.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在 055.php 的留言表单提交内容 → 055.php:5 读入 $message → 055.php:18 以单引号包裹直接拼接进 INSERT INTO guestbook 语句，未转义 → 055.php:19 mysqli_query 执行被污染的 $query → 注入的 SQL 在数据库执行，错误信息经 or die 回显。
PocWriter 建议（未采纳，缺少端点 /055）：符合 CWE-89（SQL 注入）。漏洞位于 055.php:19，外部输入来自 POST 参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。所有请求中的主机统一为 TARGET:8080，需在授权测试环境中替换为实际测试实例。禁止对生产库执行破坏性语句（如 DROP）。

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
| safety_guard | 安全防护 | 2.97 | 是 |
| surface_mapper | 攻击面测绘 | 8.56 | 是 |
| deep_finder | LLM 深挖 | 5.06 | 是 |
| candidate_screener | 候选筛选 | 3.41 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.02 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.11 | 是 |
| coordinator | 管线协调 | 5.7 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
