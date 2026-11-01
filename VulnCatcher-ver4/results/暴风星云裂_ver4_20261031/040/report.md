# 落日二号乙漏洞挖掘报告 — 20261031-164607-a2430b

- 生成时间：2026-10-31T08:46:48.413897+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\040.zip`
- 输入模式：`zip`
- SHA256：`a7a3a902cbf51a117eedf45420f67900d6bd15338d9838b48c773e4175ce8254`
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

本次汇总仅包含 1 条已去重 finding：040.php 第 11 行附近的 SQL 注入（LLM-b04dcf20e12f，severity=high，origin=llm_finding），证据等级为模型基于源码的推断（llm_inferred），并非动态验证结果。该条已附带 POC 文本（has_poc=true），但属于静态构造的 HTTP POC，目标地址以 TARGET 占位，未执行、未做动态复现。最高危项即此条 SQL 注入：$_SESSION['id'] 被直接拼接进 SQL 查询，缺少参数化/转义。整体覆盖极薄：仅 1 个文件（040.php，PHP，53 行）、0 个端点、无框架；surface_notes 明确指出本次上下文未提供 040.php 的代码内容，仅有文件元数据，因此除该条 finding 外，其余注入面与配置型风险均无法确认。POC 不齐全：仅 sql_injection 有 POC，weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 均无 POC，且这些类型本身多为静态证据，不能宣称可动态复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 040.php 的第 1-46 行（共 53 行，47-53 行未提供）。已逐行审计该文件：入口为 $_SESSION['id']，在 MySQL 分支（第 10-11 行）与 SQLite 分支（第 28、31 行）均以字符串插值方式拼入 SQL 并执行，构成一条闭合的 SQL 注入链，结果经第 20/44 行 $html 回显。未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱随机、Cookie 标志等其它可闭合链；第 47-53 行内容缺失，可能存在收尾逻辑（如 else 分支、页面输出），未纳入判断。endpoints 为空，部署方式与 URL 路径无法确认，POC 以 TARGET 占位。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未在 code_pack 中提供，未审计
- $_SESSION['id'] 的外部写入路径不在 code_pack 内，无法确认攻击者如何设置会话值
- $_DVWA['SQLI_DB'] 配置来源与取值未知
- 无 php.ini/Web 服务器配置，无法判断 register_globals、open_basedir 等开关
- endpoints 为空，无法确认请求方法与参数名

## 3. Findings

### F-1: DVWA SQL 注入（040.php）：$_SESSION['id'] 直接拼接进 SQL 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:5-11`
- **来源**：`llm_finding`

**描述**

040.php 从 $_SESSION['id'] 读取 $id，未做任何转义或参数化，直接以字符串插值方式拼入 SELECT 语句（第 10 行 MySQL 分支、第 28 行 SQLite 分支），随后交给 mysqli_query / SQLite3::query 执行。攻击者只要能控制会话中的 id 值（例如通过同站其它写入 $_SESSION['id'] 的入口、会话固定/会话注入，或该文件被作为 DVWA 的 SQL 注入练习页直接以可控会话访问），即可闭合 SQL 注入链，读取 users 表以外的数据（如 users 口令哈希、information_schema），并可将结果通过第 20/44 行的 $html 回显给攻击者。

**source / sink**

- source：session `id`（040.php）
- sink：040.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:3` | 脚本检查 $_SESSION['id'] 是否存在，存在则进入注入分支 | 会话已建立且 id 已设置 |  |
| 2 | `040.php:5` | 从会话取出 id 赋给 $id，无任何过滤/转义 | $id = 攻击者可控字符串 |  |
| 3 | `040.php:10` | 以单引号包裹方式将 $id 插值进 SQL 语句 | $query 含攻击者注入的 SQL 片段 |  |
| 4 | `040.php:11` | mysqli_query 执行拼接后的语句（SQLite 分支为第 31 行 query） | 注入的 SQL 在数据库执行 |  |
| 5 | `040.php:20` | 查询结果与 $id 一起拼入 $html 回显，形成可观测回显通道 | 注入结果返回给攻击者 |  |

**POC**

针对 /040.php（GET）的 SQL 注入 POC。注入点为 GET 参数 id，源码在 040.php:11 将该参数直接拼入 SQL 查询；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/040.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/040.php?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b04dcf20e12f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取数据库任意表（含用户口令哈希），在具备堆叠/写文件权限时可进一步扩大影响；属于典型 SQL 注入。

**CVE / CWE 论证**

CWE-89。source（$_SESSION['id']）到 sink（mysqli_query / SQLite3::query）链路在 040.php 内完整可见，无参数化、无转义、无白名单，且结果经 $html 回显，外部可观测。

**修复建议**

使用预处理语句（mysqli_prepare / PDO::prepare 或 SQLite3 的 bindValue）绑定 user_id；对 $id 做整型强转（如 (int)$id）；输出时对 $id 做 HTML 编码。

**验证说明**

需确认 $_SESSION['id'] 的外部可控路径（同站写入点或会话固定），以及 $_DVWA['SQLI_DB'] 的实际取值；本次 code_pack 仅展示 1-46 行，47-53 行未覆盖。
模型 POC 要点：通过可控会话将 $_SESSION['id'] 设为注入 payload，再访问 040.php 触发拼接查询并观察回显。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /040.php）：符合 CWE-89（SQL 注入）。漏洞位于 040.php:11，外部输入经 GET 参数 id 进入 SQL 查询汇点，静态链路闭合且未见有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱；所有请求中目标统一为 TARGET 占位符，仅限授权测试。原始 poc.sh 中的 curl 命令仅作请求结构参考，不自动运行。request.http 中 Content-Length 与 GET 无 body 不一致，实际发送时不应带 Content-Length 与 body。

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
| safety_guard | 安全防护 | 3.29 | 是 |
| surface_mapper | 攻击面测绘 | 9.53 | 是 |
| deep_finder | LLM 深挖 | 9.32 | 是 |
| candidate_screener | 候选筛选 | 4.02 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.2 | 是 |
| coordinator | 管线协调 | 9.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
