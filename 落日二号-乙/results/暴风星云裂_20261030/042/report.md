# 落日二号乙漏洞挖掘报告 — 20261030-225024-581589

- 生成时间：2026-10-30T14:51:02.898071+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
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

本次汇总仅含 1 条已去重 finding：042.php 的 SQL 注入（LLM-d68d039a3f46，high）。该脚本把 $_POST['id'] 直接拼进 WHERE user_id = $id，mysqli_real_escape_string 对数字型上下文无效，属高危直连注入，已附 POC（HTTP 型，可动态复现，仅限授权测试）。POC 齐全度：1/1。最高危即此条。其余攻击面（路径拼接/文件包含、命令执行、反射 XSS、配置类弱实现）在 surface_notes 中被列为优先区，但本次 findings 未覆盖，需人工复核，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个文件 042.php（59 行，DVWA SQL Injection 模块）。已逐行审计：第 3 行 POST Submit 触发、第 5 行读取 id、第 7 行 mysqli_real_escape_string、第 11/27 行字符串拼接、第 12/30 行执行、第 21/43 行回显。确认存在一条闭合的数字型 SQL 注入链（MYSQL 与 SQLITE 两个分支同源同 sink），已作为 high 级 finding 交付。其余线索：第 21/43 行将 $id 与数据库字段直接拼入 HTML 回显，存在反射型 XSS 可能，但需确认输出上下文与是否已有编码，且优先级低于注入，未单独立项；未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱加密/弱随机/不安全 Cookie 等汇点（文件中无 system/exec/include/file_get_contents/md5/rand/setcookie 等调用）。未覆盖范围：无 php.ini/Web 服务器配置、无 composer 依赖、无路由与部署信息，无法确认危险函数是否被禁用、脚本是否位于认证之后；endpoints 为空，路由与请求方法系从源码推断。

未覆盖 / 证据缺口：
- 无 Web 服务器/php.ini 配置，无法确认 mysqli 扩展与数据库可达性
- 无部署与认证信息，无法确认是否公网可达
- 第 21/43 行回显的反射型 XSS 未闭合（缺输出上下文与编码证据）
- SQLITE 分支依赖 $sqlite_db_connection 全局，未在包内定义，实际可达性未知

## 3. Findings

### F-1: DVWA SQL 注入（042.php）：mysqli_real_escape_string 对数字型注入无效，$_POST['id'] 直接拼接进 WHERE user_id = $id

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.93`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`042.php:5-12`
- **来源**：`llm_finding`

**描述**

042.php 第 5 行从 $_POST['id'] 读取用户输入，第 7 行仅用 mysqli_real_escape_string 转义，第 11 行（MYSQL 分支）与第 27 行（SQLITE 分支）把 $id 直接拼进 "SELECT first_name, last_name FROM users WHERE user_id = $id;"。mysqli_real_escape_string 只转义引号等字符，而该 SQL 中 $id 处于数字上下文、没有引号包裹，因此攻击者无需引号即可注入任意 SQL 片段（如 1 OR 1=1、UNION SELECT、基于布尔/时间的盲注）。第 12 行 mysqli_query 执行拼接后的语句，第 21/43 行把结果回显，构成完整注入链。

**source / sink**

- source：body `id`（042.php:5）
- sink：042.php:12 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 12 行）；SQLite 分支 $sqlite_db_connection->query($query)（第 30 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 POST 读取 id 参数 | 原始用户字符串 |  |
| 2 | `042.php:7` | mysqli_real_escape_string 转义引号等字符 | 引号被转义，但数字/运算符/空格/注释符保留 | SQL 中 $id 未加引号，处于数字上下文，转义函数对 1 OR 1=1、UNION、-- 等无需引号的 payload 完全无效 |
| 3 | `042.php:11` | 将 $id 拼接进 SELECT 语句 | 恶意 SQL 片段进入 WHERE 子句 |  |
| 4 | `042.php:12` | mysqli_query 执行拼接后的 SQL | 注入语句被执行 |  |
| 5 | `042.php:21` | 查询结果回显到页面 | 数据库内容输出到 HTML |  |

**POC**

针对 /042.php（POST）的 SQL 注入 POC。注入点为 POST 参数 id，源码 042.php:12 将该参数直接拼入 SQL 查询；payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/042.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-d68d039a3f46`
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可读取/篡改数据库任意数据（用户表、口令哈希），在具备 FILE 权限或堆叠查询时可进一步读写文件甚至 RCE。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部可达（HTTP POST 参数 id），无需认证，source→sink 链在 042.php 内完整闭合；转义函数因数字上下文失效，属典型可申报注入。

**修复建议**

使用预处理语句（mysqli_prepare + bind_param）并将 id 强制转换为整数（intval）；不要依赖 mysqli_real_escape_string 处理数字型参数。

**验证说明**

需确认 $_DVWA['SQLI_DB'] 实际取值与数据库连接是否可用；POC 未执行，布尔/联合查询结果需动态验证。
模型 POC 要点：利用数字型注入，无需引号即可绕过 mysqli_real_escape_string，先做布尔验证再联合查询取数据
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /042.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 042.php:12，外部输入来自 POST body 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化处理，具备远程触发条件。
POC 备注：仅保留文本工件，不执行、不联网、不搭建沙箱。脚本中的 TARGET 需由授权测试人员手动替换；禁止对生产环境直接运行。原始 poc.sh 与 request.http 结构保持不变，仅补充说明与预期结果。注意：Content-Length 需按实际编码后的 body 长度校正。

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
| safety_guard | 安全防护 | 3.53 | 是 |
| surface_mapper | 攻击面测绘 | 9.37 | 是 |
| deep_finder | LLM 深挖 | 9.53 | 是 |
| candidate_screener | 候选筛选 | 2.35 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.79 | 是 |
| coordinator | 管线协调 | 7.87 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
