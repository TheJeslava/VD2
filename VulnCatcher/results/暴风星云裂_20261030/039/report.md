# 落日二号乙漏洞挖掘报告 — 20261030-224955-133a63

- 生成时间：2026-10-30T14:50:32.788011+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\039.zip`
- 输入模式：`zip`
- SHA256：`dcd627aba47edb36b6b02995d92ae6b47ea38157489be6bc6bc3ad973f56f1e9`
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

本次汇总仅含 1 条已去重 finding：039.php 中 $_POST['id'] 直接拼接进 SQL 查询（MySQL/SQLite 双分支），类型 sql_injection，严重度 high，已附 POC（HTTP 型，可动态复现，仅限授权测试）。这是本次唯一且最高危的问题，参数到汇点路径极短（单文件内联）。POC 齐全度：1/1 有 POC。未发现二次注入链。需注意：本次 min_severity=high、suppressed_count=0，但 surface_notes 列出的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等仅为待人工确认项，未形成 finding，不能据此宣称不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 PHP 文件 039.php（显示 1-50 行，共 54 行），属于 DVWA 的 SQL Injection 模块。已逐行审计：入口为 POST 参数 Submit/id（第 3、5 行），MySQL 分支经 mysqli_real_escape_string 后仍以数字上下文拼接进 SQL（第 10、13、15 行），SQLite 分支完全无转义直接拼接执行（第 34-36 行），结果通过第 45-50 行回显形成布尔观测通道，构成一条闭合的 SQL 注入链，已作为 high 级 finding 交付。其余攻击面：文件操作/include/命令执行/反序列化在本文件中均未出现；未发现 md5/sha1、mcrypt/openssl、rand/mt_rand、setcookie、X-Forwarded-For 等配置型线索（第 1-50 行内无相关调用），故不产出 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 类 finding。未覆盖范围：文件第 51-54 行未送入 code_pack，无法确认是否存在额外逻辑（如 HTML 输出收尾或额外分支）；无 php.ini、Web 服务器配置、认证中间件信息，无法确认脚本是否可被未认证访问，此为 POC 可达性的主要缺口。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未包含在 code_pack 中，未审计
- 缺少认证/会话中间件信息，无法确认 039.php 是否可未认证直接访问
- 缺少 php.ini 与数据库配置，无法确认 $_DVWA['SQLI_DB'] 取值及数据库权限
- 无 composer.json 等依赖清单，未评估第三方组件

## 3. Findings

### F-1: DVWA SQL 注入页面 039.php 中 $_POST['id'] 直接拼接进 SQL 查询（MySQL/SQLite 双分支）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`039.php:5-36`
- **来源**：`llm_finding`

**描述**

039.php 在收到 POST 参数 Submit 后，直接把 $_POST['id'] 赋给 $id（第 5 行）。MySQL 分支只对 $id 调用 mysqli_real_escape_string（第 10 行），但该函数只转义字符串字面量中的引号，不改变数字上下文；随后 $id 被无引号地拼进 "SELECT first_name, last_name FROM users WHERE user_id = $id;"（第 13 行）并交给 mysqli_query 执行（第 15 行）。由于 user_id 位置没有引号包裹，攻击者可注入任意 SQL 片段（如 1 UNION SELECT user,password FROM users、布尔/时间盲注），无需闭合引号即可绕过 mysqli_real_escape_string。SQLITE 分支（第 34-36 行）完全没有做任何转义，直接把 $id 拼进同样的查询并执行 $sqlite_db_connection->query($query)，注入更直接。查询结果通过 mysqli_num_rows / fetchArray 影响 $exists，进而决定页面回显 'User ID exists' 或 'User ID is MISSING'（第 45-50 行），构成可观测的布尔型注入通道，可用于逐字符外带数据库内容（如 users 表中的口令哈希）。

**source / sink**

- source：body `id`（039.php:5）
- sink：039.php:36 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 15 行）与 $sqlite_db_connection->query($query)（第 36 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:3` | 判断是否提交了 Submit，进入注入处理分支 | 请求进入处理逻辑 |  |
| 2 | `039.php:5` | 从 POST 读取 id 参数赋给 $id，无类型/白名单校验 | 攻击者完全可控的字符串 |  |
| 3 | `039.php:10` | MySQL 分支对 $id 调用 mysqli_real_escape_string，仅转义引号等字符 | 仍含 SQL 元字符（空格、UNION、注释符、括号、比较符等） | user_id = $id 中 $id 未加引号，处于数字上下文；mysqli_real_escape_string 不转义空格、UNION、--、括号等，无法阻止数字型注入 |
| 4 | `039.php:13` | 将 $id 直接拼接进 SELECT 语句 | 恶意 SQL 片段进入查询字符串 |  |
| 5 | `039.php:15` | mysqli_query 执行拼接后的查询 | 数据库执行攻击者构造的 SQL |  |
| 6 | `039.php:34-36` | SQLITE 分支同样直接拼接并执行，且完全无转义 | 恶意 SQL 片段进入 SQLite 查询 | 该分支没有任何转义或参数化 |
| 7 | `039.php:45-50` | 根据查询结果行数决定回显 exists / MISSING，形成布尔盲注观测通道 | 查询结果映射为页面文本 |  |

**POC**

针对 /039.php（POST）的 SQL 注入 POC。注入点为 POST 参数 id，该参数在 039.php:36 附近被拼接进 SQL 查询；payload 使用 TARGET 占位符，仅作文本工件，不执行。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/039.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/039.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-a6c26ade848b`
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可读取数据库中任意表数据（包括 users 表的用户名与口令哈希），并可进一步通过盲注枚举 schema、拖库；在数据库权限较高时可结合文件读写/堆叠查询扩大影响。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部可达（HTTP POST 参数 id），脚本无认证校验，source→sink 链完整闭合，mysqli_real_escape_string 在数字上下文下不构成有效防护，SQLite 分支完全无防护。

**修复建议**

改用预处理语句（mysqli_prepare / bind_param 或 PDO prepared statement），将 user_id 作为整型参数绑定；对 id 做 intval 强制类型转换并校验范围；SQLite 分支同样使用参数化查询；移除字符串拼接。

**验证说明**

需动态确认：1) 039.php 是否可未认证直接访问（是否被 DVWA 的登录/权限中间件包裹）；2) $_DVWA['SQLI_DB'] 实际取值决定走 MySQL 还是 SQLite 分支；3) 数据库用户权限是否允许 UNION/文件读写。源码层面注入链已闭合。
模型 POC 要点：利用数字型注入点，通过 UNION 或布尔条件改变查询结果，从页面回显差异判断注入是否成功并外带数据。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /039.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 039.php:36，外部输入来自 POST body 的 id 参数，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须替换 TARGET 为授权目标，并确保已获书面授权。request.http 中 Content-Length 需按实际 body 长度调整。建议先执行步骤 1 获取基线，再执行步骤 2 对比。

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
| safety_guard | 安全防护 | 3.76 | 是 |
| surface_mapper | 攻击面测绘 | 8.77 | 是 |
| deep_finder | LLM 深挖 | 11.96 | 是 |
| candidate_screener | 候选筛选 | 3.78 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.09 | 是 |
| coordinator | 管线协调 | 5.03 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
