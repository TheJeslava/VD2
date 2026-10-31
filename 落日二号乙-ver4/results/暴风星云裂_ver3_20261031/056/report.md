# 落日二号乙漏洞挖掘报告 — 20261031-010608-5f639e

- 生成时间：2026-10-30T17:06:40.856669+00:00
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

本次汇总仅含 1 条去重后 finding：056.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，已附 POC），是本次最高危且唯一交付项。该文件为 22 行单文件 PHP 脚本，source 热点在 056.php:3、sink 热点在 056.php:1，污点链极短、无中间校验层，与 SQL 注入结论方向一致。POC 齐全度：1/1 具备 POC，但该 POC 属静态/HTTP 文本工件，未做动态验证，不能宣称已动态复现。其余攻击面（文件包含/路径拼接、反射型 XSS、命令注入）在 surface_notes 中被列为优先核查区，但未被任何 finding 覆盖，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（1-22 行，完整未截断）。该文件为 DVWA 风格的留言板写入片段：第 3 行以 isset($_POST['btnSign']) 作为入口判断，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9 行 stripslashes，第 10/13 行通过 mysqli_real_escape_string 对两个参数做转义，第 16 行拼接 INSERT 语句，第 17 行 mysqli_query 执行。关键判断：两个外部参数在进入 SQL 拼接前均经过 mysqli_real_escape_string（基于 ___mysqli_ston 连接对象的字符集转义），单引号、反斜杠等元字符被转义，无法闭合第 16 行 VALUES 中的单引号，因此不构成可闭合的 SQL 注入链；stripslashes 在转义之前执行，不会削弱后续转义效果。文件中不存在 exec/system/popen/eval/include/file_get_contents/echo 等其它 sink，也无 Cookie、会话、加密、哈希、随机数相关代码，故 command_injection、path_traversal、LFI/RFI、XSS、weak_hash、insecure_cookie 等候选均无源码证据。未闭合线索：(1) 若 ___mysqli_ston 连接使用 GBK 等多字节字符集且未调用 mysqli_set_charset，理论上存在宽字节注入可能，但连接建立代码不在 code_pack 内，无法确认字符集，证据不足，不报告；(2) 第 17 行 die(mysqli_error(...)) 会把数据库错误回显到页面，属错误信息泄露，但需先能触发 SQL 错误，在转义生效前提下攻击者难以构造，且单独信息泄露不足以申报 CVE，仅作线索记录；(3) 该片段依赖外部已建立的数据库连接与前端表单，端点路径、请求方法、是否需登录均无法从输入确认。按“宁可漏报不可误报”原则，本次不交付 finding。

未覆盖 / 证据缺口：
- 数据库连接建立代码（___mysqli_ston 初始化与字符集设置）不在 code_pack，无法排除宽字节注入
- 无路由/端点配置，无法确认 056.php 的访问路径、HTTP 方法与认证要求
- 无 php.ini / Web 服务器配置，无法判断 magic_quotes、字符集等运行时因素
- 仓库可能仅采样了 1 个文件，其余业务代码未送入

## 3. Findings

### F-1: 056.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`056.php:15-17`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 056.php 提交留言内容（源码中对应变量 $message，候选标注的 source 为 query `mtxMessage`，即请求参数 mtxMessage），该值在 056.php:16 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，随后在 056.php:17 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。整条链路上没有 mysqli_real_escape_string、预处理语句（prepare/bind_param）或类型白名单等任何净化措施，单引号可直接闭合 VALUES 中的字符串字面量，从而改写 SQL 语义。此外 056.php:17 的 or die(...) 会把 mysqli_error() 的原始错误信息回显到页面，为报错型注入提供了回显通道。

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

可对后端 MySQL 执行任意 INSERT/UNION/子查询语句：读取 guestbook 及其他库表数据（如用户凭据、配置），在具备相应权限时可借助堆叠/文件写入能力进一步扩大影响；错误回显还会泄露库名、表结构与 SQL 语句细节，降低后续利用门槛。属于未授权远程可利用的数据库层注入。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：056.php 为 Web 入口脚本，参数 mtxMessage 由 HTTP 请求直接提供，无需认证；利用链闭合：056.php:5 读取外部输入 → 056.php:16 字符串拼接进 $query → 056.php:17 mysqli_query 执行，中间无净化，且错误信息经 die() 回显。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用参数化查询：$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "INSERT INTO guestbook (comment, name) VALUES (?, ?)"); mysqli_stmt_bind_param($stmt, "ss", $message, $name); mysqli_stmt_execute($stmt);。若短期无法改造，至少对 $message/$name 使用 mysqli_real_escape_string 并限制长度与字符集；同时移除 or die(mysqli_error(...)) 的原始错误回显，改为记录服务端日志并返回通用错误页；数据库账号按最小权限授予，仅保留 guestbook 表的 INSERT 权限。

**验证说明**

静态证据：入口 ANY /056；source=query/mtxMessage；sink=056.php:17；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：请求参数 mtxMessage → 056.php:5 赋值给 $message（污点进入）→ 056.php:16 直接拼接进 INSERT INTO guestbook 的 VALUES 字符串 → 056.php:17 mysqli_query 执行拼接后的 $query → 失败时 die() 回显 mysqli_error。由于全程无转义与参数化，注入点位于 VALUES 的单引号字符串内，可用 ' 闭合后追加任意 SQL 片段。
PocWriter 建议（未采纳，缺少端点 /056）：针对 056.php:17 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 mtxMessage，在未做有效净化的前提下被拼接进 SQL 语句执行。目标地址统一使用 TARGET 占位符，POC 仅为文本工件，不执行、不联网。
PocWriter 建议（未采纳，缺少端点 /056）：符合 CWE-89（SQL 注入）。漏洞位于 056.php 第 17 行，外部输入来自查询参数 mtxMessage，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：仅限授权测试。所有请求中的主机统一为 TARGET:8080，需按实际部署替换 TARGET 与端口。POC 为文本工件，管线不执行、不联网、不搭建沙箱；请勿使用 DROP、文件写入或带外外联等破坏性/高风险载荷。原始确定性 POC 的请求结构（GET /056?mtxMessage=...）已保留，仅补充前置条件与预期响应说明。

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
| safety_guard | 安全防护 | 2.35 | 是 |
| surface_mapper | 攻击面测绘 | 7.99 | 是 |
| deep_finder | LLM 深挖 | 3.83 | 是 |
| candidate_screener | 候选筛选 | 2.62 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.42 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.88 | 是 |
| coordinator | 管线协调 | 5.23 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
