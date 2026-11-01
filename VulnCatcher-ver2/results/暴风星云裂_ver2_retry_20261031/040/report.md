# 落日二号乙漏洞挖掘报告 — 20261031-002248-383865

- 生成时间：2026-10-30T16:23:23.414753+00:00
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

本次汇总仅含 1 条已去重 finding：040.php 第 11 行附近的 sql_injection（high，LLM-b04dcf20e12f），描述为 $_SESSION['id'] 直接拼接进 user_id 查询，且已附带 POC（has_poc=true，属静态/HTTP 文本 POC，未做动态验证）。最高危即该条 SQL 注入，也是唯一交付项。POC 齐全度：1/1 有 POC，但仅为文本工件，未执行、未搭建沙箱、未动态复现。需注意：surface_notes 明确说明输入未提供 040.php 的代码片段与行号，sink 热点无法定位到具体函数，因此该 finding 的行号与污点链（$_SESSION['id'] 是否真为可控 source）仍需人工对照源码复核，不能视为已验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1627 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单文件 040.php（显示 1-46 行，共 53 行，尾部 47-53 行未显示）。审计确认第 5 行从 $_SESSION['id'] 取值，第 10/28 行直接字符串拼接进 SQL，第 11/31 行执行，构成完整 SQL 注入链（MYSQL 与 SQLITE 两分支同源）。第 20/44 行将 $id 与查询结果回显到 HTML，若 $id 含 HTML 则存在反射/存储型 XSS 面，但受会话可控性约束，未单独立项。未发现命令执行、文件包含、反序列化、SSRF 等其它 sink。尾部 47-53 行未覆盖，可能含收尾逻辑（如 else 分支与 HTML 输出），不影响已确认注入链。

未覆盖 / 证据缺口：
- 040.php 第 47-53 行未在 code_pack 中显示
- $_SESSION['id'] 的上游写入点不在 code_pack 内，无法确认攻击者控制路径
- 无 php.ini/部署配置，无法确认数据库分支与错误回显设置
- 第 20/44 行输出未编码，XSS 面因会话可控性未闭合而未报告

## 3. Findings

### F-1: DVWA SQL 注入（040.php）：$_SESSION['id'] 直接拼接进 user_id 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.8`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`040.php:5-11`
- **来源**：`llm_finding`

**描述**

040.php 从 $_SESSION['id'] 取出 $id，未做任何转义或参数化，直接以字符串插值方式拼进 SQL："SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"，随后分别交给 mysqli_query（MYSQL 分支，第 10-11 行）和 SQLite3::query（SQLITE 分支，第 28-31 行）执行。$id 在单引号内可控，攻击者可用 ' 闭合字符串并注入任意 SQL（UNION 提取 users 表口令哈希、布尔/时间盲注等）。这是 DVWA 经典的 SQL 注入练习代码，属于真实可复现的注入链。

**source / sink**

- source：session `id`（040.php）
- sink：040.php:11 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 11 行）与 $sqlite_db_connection->query($query)（第 31 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `040.php:3-5` | 检查 $_SESSION['id'] 是否存在并赋值给 $id，无任何过滤 | 原始会话字符串 |  |
| 2 | `040.php:10` | 将 $id 以单引号包裹插值拼进 SQL 语句 | 拼接进 SQL 的字符串，单引号可闭合 |  |
| 3 | `040.php:11` | mysqli_query 执行拼接后的查询（SQLITE 分支为第 31 行 query） | 作为 SQL 语句执行 | 无预处理、无 mysqli_real_escape_string、无类型转换，单引号未转义 |

**POC**

针对 /040.php（GET）的 SQL 注入 POC。注入点为 GET 参数 id，payload 为 ' OR '1'='1（URL 编码为 %27%20OR%20%271%27%3D%271）。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/040.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/040.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b04dcf20e12f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取数据库任意数据（含用户口令哈希），进一步可导致认证绕过与数据泄露；SQLite 分支同样受影响。

**CVE / CWE 论证**

CWE-89。外部可达（HTTP 请求 040.php），注入点闭合完整，无需额外权限即可读取数据；属经典 SQL 注入。

**修复建议**

使用预处理语句（mysqli_prepare / PDO::prepare / SQLite3::prepare）绑定 user_id 参数，并对 $id 做整型校验。

**验证说明**

需确认 $_SESSION['id'] 的实际写入点是否允许攻击者控制（DVWA 中通常由登录流程写入，攻击者可通过其他注入点或会话固定影响）；需确认部署分支（MYSQL/SQLITE）与数据库可达性。
模型 POC 要点：在会话中把 id 设为注入 payload，访问 040.php 触发拼接查询
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /040.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 040.php 第 11 行，外部输入经 GET 参数 id 进入 SQL 查询汇点，source→sink 链在给定代码范围内静态闭合，未发现有效净化/参数化处理；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为已获授权的测试实例地址，并确保获得明确授权。禁止使用 DROP/破坏性语句；建议仅使用布尔或时间盲注做最小化验证。原始确定性请求结构（GET /040.php?id=%27%20OR%20%271%27%3D%271）予以保留。

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
| safety_guard | 安全防护 | 2.68 | 是 |
| surface_mapper | 攻击面测绘 | 9.69 | 是 |
| deep_finder | LLM 深挖 | 7.75 | 是 |
| candidate_screener | 候选筛选 | 3.01 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.29 | 是 |
| coordinator | 管线协调 | 6.28 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
