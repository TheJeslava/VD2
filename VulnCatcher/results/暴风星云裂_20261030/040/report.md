# 落日二号乙漏洞挖掘报告 — 20261030-224956-a4ca0a

- 生成时间：2026-10-30T14:50:31.526558+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\040.zip`
- 输入模式：`zip`
- SHA256：`a7a3a902cbf51a117eedf45420f67900d6bd15338d9838b48c773e4175ce8254`
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

本次汇总仅含 1 条已去重 finding：040.php 第 11 行附近，$_SESSION['id'] 被直接拼接进 SQL 查询，类型 sql_injection，严重度 high，来源 llm_finding，已附带 POC（静态文本 POC，未做动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但该 POC 属静态构造，未经动态复现，且其触发前提是 $_SESSION['id'] 已被写入可控值，实际可利用性取决于会话写入点，需人工确认。其余攻击面（文件包含/路径拼接、命令执行、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）在 surface_notes 中被列为优先区或中危复核项，但本次 findings 未覆盖，已转入 human_review，不能视为已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计 040.php（code_pack 显示 1-46 行，共 53 行，47-53 行未送入）。该文件为 DVWA SQL Injection low 级别实现：$_SESSION['id'] 未过滤直接拼接进 SQL，MySQL 分支 mysqli_query（第 11 行）与 SQLite 分支 query（第 31 行）均无参数化，构成 SQL 注入，已给出闭合链与 POC。未发现命令执行、文件包含、反序列化等其它 sink；weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在可见代码中无对应证据（无 md5/rand/setcookie/HTTP_X_FORWARDED_FOR 等），不单独立项。未闭合线索：$_SESSION['id'] 的写入点不在 code_pack 内，无法确认外部可控性；第 47-53 行未覆盖；无部署配置无法确认 allow_url_include/register_globals 等。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未送入 code_pack
- $_SESSION['id'] 的写入点（上游页面）不在 code_pack，外部可控性依赖 DVWA 上下文
- 无 composer.json/部署配置，无法确认 PHP 版本与运行配置
- 无 HTTP 端点清单，路由路径为按 DVWA 惯例推断

## 3. Findings

### F-1: DVWA SQL Injection（low 级别）——$_SESSION['id'] 直接拼接进 SQL 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:5-11`
- **来源**：`llm_finding`

**描述**

040.php 从 $_SESSION['id'] 取值后未做任何转义/参数化，直接以字符串插值方式拼进 SELECT 语句（第 10 行 MySQL 分支、第 28 行 SQLite 分支），随后交给 mysqli_query / SQLite3::query 执行。攻击者只要能控制会话中的 id（例如通过 DVWA 的 SQL Injection 页面把 payload 写入会话，或存在会话注入/固定），即可闭合单引号注入任意 SQL，读取 users 表以外的数据（如 dvwa.users 口令哈希、information_schema），在 MySQL 高权限下还可进一步 UNION 读取文件或写文件。

**source / sink**

- source：session `id`（040.php:5）
- sink：040.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:5` | 从会话读取 id，未做任何过滤 | 原始字符串，完全可控 |  |
| 2 | `040.php:10` | 以单引号包裹方式字符串插值拼接进 SQL | 污点进入 SQL 文本，单引号可闭合 |  |
| 3 | `040.php:11` | mysqli_query 执行拼接后的语句，无预处理/绑定 | 任意 SQL 被执行 |  |
| 4 | `040.php:20` | 查询结果与 $id 回显到页面，可用于 UNION 回显数据 | 注入结果反射到 HTML |  |

**POC**

针对 /vulnerabilities/sqli/（GET）的 SQL 注入 POC。注入点：GET 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/sqli/'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/sqli/?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b04dcf20e12f`
- 执行状态：未执行（`executed=False`）

**影响**

可读取数据库中任意表（含用户口令哈希），在 MySQL FILE 权限下可读写服务器文件，导致数据泄露与进一步提权。

**CVE / CWE 论证**

CWE-89。外部可通过 HTTP 会话控制 id，链完整闭合（source→拼接→mysqli_query→回显），无需额外权限即可注入。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO 绑定参数），禁止字符串拼接；对 id 做整数类型强校验。

**验证说明**

需确认 $_SESSION['id'] 的实际写入点（不在 code_pack 内）是否可由外部请求控制；若上游页面已对 id 做转义则链不成立。code_pack 仅显示 1-46 行，第 47-53 行未覆盖。
模型 POC 要点：先通过 DVWA SQL Injection 页面把注入 payload 写入会话 id，再访问本脚本触发拼接查询；payload 使用 UNION 回显数据库版本与用户口令哈希。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：针对 040.php:11 的 SQL 注入 POC（CWE-89）。注入点为 GET 参数 id，payload 为 ' OR '1'='1。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /vulnerabilities/sqli/）：符合 CWE-89。漏洞位于 040.php:11，外部输入经 GET 参数 id 进入 SQL 查询，source→sink 链静态闭合且未见有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。request.http 中 Content-Length 与 GET 无 body 不一致，实际发送时请移除 Content-Length 与 body；目标地址保持 TARGET 占位符。

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
| safety_guard | 安全防护 | 3.9 | 是 |
| surface_mapper | 攻击面测绘 | 8.29 | 是 |
| deep_finder | LLM 深挖 | 8.77 | 是 |
| candidate_screener | 候选筛选 | 3.5 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 3.67 | 是 |
| coordinator | 管线协调 | 6.99 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
