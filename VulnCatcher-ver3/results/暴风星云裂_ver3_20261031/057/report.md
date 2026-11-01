# 落日二号乙漏洞挖掘报告 — 20261031-010616-f83a4a

- 生成时间：2026-10-30T17:06:51.583116+00:00
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

本次汇总仅含 1 条已去重 finding：057.php 留言板 INSERT 语句 SQL 注入（CWE-89，critical，rule 来源，带 POC），是当前唯一且最高危的问题，POC 齐全（1/1）。但需注意：surface_notes 明确说明输入未提供 057.php 的代码文本，仅给出 source 热点第 3 行、sink 热点第 1 行，因此该 finding 的落点（第 19 行 INSERT）与攻击面测绘的推断（第 1 行汇点）存在不一致，需人工对齐行号与汇点类型后再定级。其余 weak_hash / weak_random / weak_crypto / insecure_cookie / trust_boundary 均为 medium_review_items 中的待确认项，未形成 finding，属未交付而非未检出。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1455 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 057.php（1-24 行全部可见）。该脚本为 DVWA 风格的留言板写入页面：第 3 行以 isset($_POST['btnSign']) 作为入口判断，第 5-6 行读取 $_POST['mtxMessage'] 与 $_POST['txtName']，第 9-11 行对 message 依次执行 strip_tags、addslashes、mysqli_real_escape_string、htmlspecialchars，第 14-15 行对 name 执行 str_replace('<script>','') 与 mysqli_real_escape_string，第 18 行拼接 INSERT 语句，第 19 行 mysqli_query 执行。逐跳核查结论：(1) SQL 注入不成立——两个变量在拼接前都经过 mysqli_real_escape_string（依赖 ___mysqli_ston 连接对象），单引号、反斜杠等元字符被转义，且第 10/15 行的三元表达式在连接对象存在时走转义分支；虽然 addslashes 与 mysqli_real_escape_string 叠加属于冗余防护，但未发现可绕过点（无 GBK/宽字节场景证据、无数字型上下文、无 ORDER BY/LIMIT 拼接）。(2) XSS 不成立——message 经 htmlspecialchars 编码，name 虽仅做 str_replace('<script>') 黑名单（可被 <img onerror>、大小写/嵌套标签绕过），但该脚本本身只做 INSERT 写库，code_pack 中不存在任何读取并回显 guestbook 内容的读点与输出汇点，二次注入所需的“存储读点 + 读取后危险汇点”两者均缺失，按规则不得作为二次注入或存储型 XSS 报告。(3) 命令执行/文件包含/反序列化/SSRF 均不存在——文件中无 system/exec/eval/include/require/unserialize/file_get_contents/curl 等调用。(4) 配置型候选（weak_hash/weak_random/weak_crypto/insecure_cookie/trust_boundary）均无证据——24 行内无 md5/sha1、rand/mt_rand、openssl/mcrypt、setcookie/session_set_cookie_params，也无对 X-Forwarded-For/HTTP_HOST/User-Agent 的信任使用。未发现 prompt_injection 诱导文本。综上，本 code_pack 内不存在可闭合的 source→sink 利用链，findings 

未覆盖 / 证据缺口：
- 无 guestbook 内容读取/回显页面，无法评估存储型 XSS 或二次注入
- 无 php.ini / Web 服务器配置，无法判断 register_globals、allow_url_include 等利用条件
- 无端点清单与部署信息，无法确认脚本是否对外暴露或位于认证之后
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 057.php 留言板 INSERT 语句 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`057.php:17-19`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求向 057.php 提交留言板表单，外部输入在 057.php:5 被读入变量 $message（候选标注的 source 为 query `mtxMessage`，即留言内容字段），随后在 057.php:18 被直接字符串拼接进 INSERT 语句：$query = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";，其中 $message 被单引号包裹但未做任何转义或参数化处理。该 $query 在 057.php:19 传入 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行，构成从外部输入到 SQL 执行汇点的完整污点链。由于拼接发生在引号内部，攻击者只需在留言内容中闭合单引号即可注入任意 SQL 片段；代码中未见 mysqli_real_escape_string、预处理语句或白名单校验，校验完全缺失。

**source / sink**

- source：query `mtxMessage`（057.php:5）
- sink：057.php:19 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `057.php:5` | 从 query `mtxMessage` 读取外部输入 | 污点进入 query |  |
| 2 | `057.php:19` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /057（ANY）的 SQL 注入 POC。注入点：ANY 参数 mtxMessage；payload 使用 TARGET 占位符。

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

可对后端数据库执行任意 SQL：读取 guestbook 及其他表数据（数据泄露）、篡改或删除记录、在数据库权限允许时通过 UNION/子查询进一步窃取凭据；若数据库账户权限过高还可能写入文件。属于未认证远程可利用的严重注入。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：057.php 为 Web 入口，留言内容经 HTTP 请求参数直接进入；无需认证即可提交留言；利用链闭合：057.php:5 读取输入 → 057.php:18 字符串拼接进 $query → 057.php:19 mysqli_query 执行，中间无有效净化，满足远程未认证注入的 CVE 论证要素。

**修复建议**

改用参数化查询：使用 mysqli_prepare 配合 bind_param 将 comment、name 作为绑定参数传入，禁止字符串拼接；若必须拼接，至少对 $message/$name 使用 mysqli_real_escape_string 并校验长度与字符集；数据库账户遵循最小权限，禁用 FILE 权限；关闭 die(mysqli_error(...)) 的详细错误回显，避免报错注入与信息泄露。

**验证说明**

静态证据：入口 ANY /057；source=query/mtxMessage；sink=057.php:19；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在留言板表单的留言内容字段（057.php:5 读入的 $message）中提交形如 ' , (SELECT ...))-- - 的载荷，闭合 057.php:18 中 VALUES ( '$message' 的单引号，使拼接后的 $query 携带攻击者构造的 SQL；该语句在 057.php:19 由 mysqli_query 执行，注入生效。
PocWriter 建议（未采纳，缺少端点 /057）：针对 057.php:19 的 SQL 注入 POC（CWE-89）。外部输入来自查询参数 mtxMessage，在未做有效净化的前提下被拼接进 SQL 语句执行，可远程触发。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /057）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 057.php:19，外部输入来自查询参数 mtxMessage，source→sink 链在静态审计中闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试环境地址，并确保已获书面授权。原始确定性 POC 的请求结构（ANY /057?mtxMessage=...）予以保留，仅补充说明与预期结果。禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.63 | 是 |
| surface_mapper | 攻击面测绘 | 8.09 | 是 |
| deep_finder | LLM 深挖 | 4.97 | 是 |
| candidate_screener | 候选筛选 | 2.89 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.32 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.95 | 是 |
| coordinator | 管线协调 | 6.46 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
