# 落日二号乙漏洞挖掘报告 — 20261030-224932-1475c2

- 生成时间：2026-10-30T14:50:08.902380+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\037.zip`
- 输入模式：`zip`
- SHA256：`2350166e5e411d8f34c674251eff07993757e4851f9d5957708018206bf598c9`
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

本次汇总仅含 1 条已去重 finding：LLM-7c3e001d0900，类型 sql_injection，严重度 high，位于 037.php 第 13 行（行号范围落在输入给出的 037.php 内），描述为 $_COOKIE['id'] 直接拼接进 SQL 查询，属 Cookie 来源的一次注入（非二次注入，输入未给出存储写点/读点/汇点三要素）。该条已附带 POC（has_poc=true），但 POC 为静态文本工件，未做动态验证，不能宣称可动态复现。最高危即此条 high 级 SQL 注入。POC 齐全度：1/1 条 finding 有 POC；但 weak_hash / weak_random / weak_crypto / insecure_cookie / trust_boundary 等配置型候选均无 POC，仅有待复核线索。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1905 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 037.php（63 行，DVWA SQL 注入练习脚本）。已逐行审计：第 3/5 行从 Cookie `id` 取值，第 11/33 行字符串拼接构造 SQL，第 13/35 行执行，构成完整 SQL 注入链（CWE-89），已作为 high 级 finding 交付。其余观察：第 51-52 行使用 rand() 做随机 sleep，属非安全用途，不构成 weak_random 漏洞；第 56 行使用 $_SERVER['SERVER_PROTOCOL'] 设置状态码，非信任边界缺陷；未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱加密、insecure_cookie 等其它可利用链。未覆盖范围：无配置文件、无路由/认证配置、无依赖清单，无法评估运行时配置风险与第三方组件 CVE；endpoints 为空，脚本对外暴露方式与是否需要认证需人工确认。

未覆盖 / 证据缺口：
- 无 php.ini/.htaccess/Web 服务器配置，无法判断 allow_url_include、display_errors 等运行时风险
- endpoints 为空，无法确认 037.php 是否对外暴露及认证要求
- 无 composer.json/依赖版本，无法评估第三方组件 CVE
- 部署方式（CLI/CGI/FPM）未知，影响可达性判断
- 仅 1 个文件，无法评估跨文件信任边界

## 3. Findings

### F-1: DVWA SQL 注入（Cookie `id`）——`037.php` 中 `$_COOKIE['id']` 直接拼接进 SQL 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`037.php:5-13`
- **来源**：`llm_finding`

**描述**

脚本从 Cookie `id` 读取用户输入（第 5 行），未做任何过滤/转义/参数化，直接以字符串拼接方式构造 SQL 语句（第 11 行 MySQL 分支、第 33 行 SQLite 分支），随后交给 `mysqli_query`（第 13 行）与 `$sqlite_db_connection->query`（第 35 行）执行。攻击者只需控制 Cookie 即可注入任意 SQL 片段，绕过 `user_id` 条件读取 `users` 表全部数据，或通过布尔/时间盲注逐字节提取数据库内容。这是 DVWA 经典的 SQL 注入练习点，链路完整闭合。

**source / sink**

- source：cookie `id`（037.php）
- sink：037.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 13 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 35 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `037.php:3` | 判断 Cookie `id` 是否存在，存在则进入注入分支 | 原始 Cookie 值，未解码未过滤 |  |
| 2 | `037.php:5` | 将 Cookie 值赋给 $id | $id = 攻击者完全可控字符串 |  |
| 3 | `037.php:11` | 将 $id 直接插入单引号包裹的 SQL 字符串 | $query 含攻击者注入片段，无转义 |  |
| 4 | `037.php:13` | 执行拼接后的 SQL 语句 | 注入语句在数据库执行 |  |

**POC**

针对 /037.php（GET）的 SQL 注入 POC。注入点为 Cookie `id`，其值被直接拼接到 SQL 查询中（037.php:13），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/037.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/037.php' \
  -H 'Cookie: id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-7c3e001d0900`
- 执行状态：未执行（`executed=False`）

**影响**

未授权攻击者可读取/推断数据库中 users 表全部记录（用户名、口令哈希等），并可能进一步通过 UNION/堆叠查询访问其他表，造成敏感数据泄露。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部可达（HTTP Cookie 直接进入查询），无需认证，source→sink 链路在 CODE PACK 内逐行闭合（第 5→11→13 行），无任何转义或参数化。

**修复建议**

使用预处理语句（mysqli_prepare / PDO::prepare）绑定参数；对 $id 做类型强转（如 (int)$id）；避免将用户输入直接拼接进 SQL。

**验证说明**

需确认部署环境 $_DVWA['SQLI_DB'] 取值与数据库连接是否可用；页面是否直接回显查询结果（当前代码仅回显存在性，UNION 数据回显需结合 DVWA 前端逻辑，布尔/时间盲注不受影响）。
模型 POC 要点：通过 Cookie 注入闭合单引号并追加 UNION/布尔条件，观察页面返回的 User ID exists/MISSING 差异进行数据提取。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /037.php）：符合 CWE-89（SQL 注入）。漏洞位于 037.php:13，外部输入来自 Cookie `id`，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符，仅限授权测试。原始确定性 POC 的请求结构（GET /037.php + Cookie: id）予以保留，仅补充基线与验证步骤说明。禁止使用 DROP/破坏性语句。

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
| safety_guard | 安全防护 | 4.83 | 是 |
| surface_mapper | 攻击面测绘 | 8.52 | 是 |
| deep_finder | LLM 深挖 | 8.91 | 是 |
| candidate_screener | 候选筛选 | 3.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.12 | 是 |
| coordinator | 管线协调 | 5.72 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
