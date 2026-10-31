# 落日二号乙漏洞挖掘报告 — 20261030-225010-d107df

- 生成时间：2026-10-30T14:50:47.011760+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\041.zip`
- 输入模式：`zip`
- SHA256：`79e2a6d843927e577eebaaeee2a818debf8da783d298ea705037330b946c7905`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：LLM-d2344e4ce96f，类型 sql_injection，严重度 high，位于单文件 PHP 脚本 041.php（第 11 行附近），污点源为 $_REQUEST['id'] 直接拼接进 SELECT 语句，存在 MySQL/SQLite 双分支。该条已附带 POC（has_poc=true），属 HTTP 型可复现 POC（文本工件，未执行、未动态验证）。最高危即此条 SQL 注入，因 source 与 sink 同文件闭合、路径短、无框架过滤层，利用门槛低。POC 齐全度为 1/1，但仅覆盖该注入点；其余攻击面（文件包含/路径穿越、命令/代码执行、XSS、配置类弱算法与 Cookie 标志、信任边界）均无 finding 交付，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：code_pack 仅包含 041.php 的 1-46 行（共 56 行，尾部 47-56 未送入）。已审计该文件全部可见行：第3行以 $_REQUEST['Submit'] 作为分支开关，第5行 $_REQUEST['id'] 未过滤，第10/31行分别拼接进 MySQL 与 SQLite 查询，第11/34行执行，第11行 die(mysqli_error) 提供报错回显，第20行将 $id 与查询结果回显到 HTML（存在反射型 XSS 面，但需管理员交互且危害低于 SQLi，未单独立项）。未发现命令执行、文件包含、反序列化、SSRF 等其它 sink。配置类线索（weak_hash/weak_random/insecure_cookie/trust_boundary）在可见行内无对应调用，无法确认。尾部 47-56 行未覆盖，可能包含结果输出或 SQLite 收尾逻辑，建议人工补看。

未覆盖 / 证据缺口：
- 041.php 第47-56行未在 code_pack 中，未审计
- 无 php.ini/Web 服务器配置，无法确认 request_order、allow_url_include、display_errors 等开关
- 无端点清单，041.php 实际访问路径与是否需要认证未确认
- $_DVWA['SQLI_DB'] 的取值来源与数据库连接可用性未确认
- 第20行 $id 回显存在反射型 XSS 可能，但未构成高危闭合链，未单独立项

## 3. Findings

### F-1: DVWA SQL 注入：$_REQUEST['id'] 直接拼接进 SELECT 语句（MySQL/SQLite 双分支）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`041.php:5-11`
- **来源**：`llm_finding`

**描述**

041.php 在 isset($_REQUEST['Submit']) 成立时，直接把 $_REQUEST['id'] 赋给 $id（第5行），未做任何类型转换、转义或参数化，随后在第10行（MYSQL 分支）与第31行（SQLITE 分支）以单引号包裹方式拼接进 SELECT 语句，并分别交给 mysqli_query（第11行）与 SQLite3::query（第34行）执行。攻击者可通过 id 参数闭合单引号注入任意 SQL，读取 users 表以外的数据（如 dvwa 库中的 users/password 哈希），并借助第11行 die(mysqli_error(...)) 的错误回显进行报错注入与盲注。

**source / sink**

- source：query `id`（041.php）
- sink：041.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第11行）；SQLite 分支 $sqlite_db_connection->query($query)（第34行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:3` | 判断 $_REQUEST['Submit'] 是否存在，作为进入注入分支的开关 | 攻击者控制 Submit 参数存在性 |  |
| 2 | `041.php:5` | 将 $_REQUEST['id'] 原样赋给 $id，无 trim/intval/转义 | 原始字符串，未过滤 |  |
| 3 | `041.php:10` | $id 被单引号包裹拼接进 SELECT 语句 | 字符串拼接，单引号可闭合 |  |
| 4 | `041.php:11` | 拼接后的 SQL 交给 mysqli_query 执行，失败时 die 输出 mysqli_error | SQL 语句被执行，错误信息回显 |  |
| 5 | `041.php:31` | SQLITE 分支同样以 '$id' 拼接并交给 SQLite3::query 执行 | SQL 语句被执行 |  |

**POC**

针对 /041.php（GET）的 SQL 注入 POC。注入点为 GET 参数 id，该参数被直接拼接进 SQL 查询（041.php:11），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/041.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/041.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-d2344e4ce96f`
- 执行状态：未执行（`executed=False`）

**影响**

未授权读取数据库任意数据（用户表、凭据哈希），并可通过报错/布尔盲注进一步枚举 schema，属于典型 SQL 注入，可导致数据泄露与后续账户接管。

**CVE / CWE 论证**

CWE-89。外部 HTTP 参数 id 直接拼接进 SQL 并执行，无参数化、无转义、无白名单，链路在同文件内闭合，无需认证即可触发。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO prepared statement），对 id 做 intval 强制类型转换；关闭 die(mysqli_error) 的详细错误回显。

**验证说明**

需确认 $_DVWA['SQLI_DB'] 的实际取值与数据库连接是否可用；需确认 PHP request_order 是否允许通过 GET 传入 id/Submit；行号 47-56 未在 code_pack 中展示，可能存在额外输出逻辑但不影响本链。
模型 POC 要点：通过 id 参数闭合单引号，使用 UNION 查询读取 users 表中的用户名与密码哈希；Submit 参数用于触发分支。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /041.php）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自 GET 查询参数 id，source→sink 链在源码中静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试；将 TARGET 替换为授权目标后手动执行。POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。请求结构沿用已有确定性草稿，未改动目标占位符与文件/行号。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.62 | 是 |
| surface_mapper | 攻击面测绘 | 10.67 | 是 |
| deep_finder | LLM 深挖 | 8.59 | 是 |
| candidate_screener | 候选筛选 | 3.16 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.6 | 是 |
| coordinator | 管线协调 | 6.27 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
