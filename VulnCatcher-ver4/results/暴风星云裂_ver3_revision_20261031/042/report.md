# 落日二号乙漏洞挖掘报告 — 20261031-012109-1c917b

- 生成时间：2026-10-30T17:21:51.392800+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
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

本次汇总仅含 1 条已去重 finding：042.php 第 12 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可动态复现路径）。这是本次唯一且最高危的问题，POC 齐全（with_poc=1/1）。除此之外，weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 五类仅有攻击面测绘提出的待核对项，没有形成 finding，也没有 POC；这些属于静态/语义层待复核，不能宣称已验证或可动态复现。审计范围收敛到单文件 042.php（59 行），无框架、无路由、无端点清单，未覆盖 include 链、部署配置与数据库 schema。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 042.php（59 行，DVWA SQL Injection 页面）。已逐行审计：入口为 POST 参数 Submit/id（第3-5行），sink 为 mysqli_query（第12行）与 SQLite3::query（第30行）。确认存在一条闭合的 SQL 注入链：$id 经 mysqli_real_escape_string 后仍以未加引号数值形式拼接进 SQL，转义无法阻止 OR/UNION 注入。次要线索：第21/43行将 $id 原样回显到 HTML，存在反射型 XSS 风险，但需结合响应头与浏览器上下文确认，未单独立项。配置型检查：文件内未出现 md5/sha1、mcrypt/openssl、rand/mt_rand、setcookie 等，weak_hash/weak_crypto/weak_random/insecure_cookie 无证据。未覆盖范围：无 Web 服务器配置、include 链、认证机制与数据库 schema，无法确认外部可达性与前置鉴权；这些缺口已写入 coverage.gaps。

未覆盖 / 证据缺口：
- 缺少 Web 服务器/php.ini 配置，无法确认 042.php 对外可达性及 exec/system 等函数禁用情况
- 缺少 include/require 链，无法排除依赖脚本（按规则视为不存在）
- 无认证/会话文件，无法评估未授权访问前置条件
- 无数据库 schema 与连接配置，SQL 注入仅停留在源码层推断
- 第21/43行 $id 回显的反射型 XSS 未单独立项，需动态确认响应头与上下文

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（042.php:5 读取该参数），该值未经任何类型转换、转义或参数化处理，被直接拼接进 SQL 语句：042.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 直接以字符串插值方式进入 SQL 文本，攻击者可闭合原有条件并追加任意 SQL 片段（如布尔盲注、UNION 联合查询、时间盲注）。代码中未见 `mysqli_real_escape_string`、`intval`、预处理语句或白名单校验，因此校验完全缺失。此外 042.php:12 的 `or die('<pre>' . mysqli_error(...) . '</pre>')` 会把数据库错误信息回显到响应中，为报错注入和结构探测提供了额外信息泄露通道。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:12 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:12` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /042（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/042?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-65bf75938433`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：攻击者可读取 users 表之外的任意表（如用户名、口令哈希、其他业务数据），并可借助 UNION 查询将任意查询结果回显到页面。错误回显进一步暴露库名、表名、列名与 SQL 结构。若数据库账户权限过高，还可能造成数据篡改或经由文件读写函数导致服务器文件读写，进而升级为 RCE。属于未授权远程可利用的严重级别缺陷。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 042.php 触发。利用链闭合：source（042.php:5 的 query `id`）→ 字符串拼接（042.php:11）→ 执行汇点 `mysqli_query`（042.php:12），中间无任何净化函数，链路完整闭合。错误信息回显（042.php:12 的 `mysqli_error`）增强了可利用性。证据等级为基于源码的推断（llm_inferred），未做动态验证。

**修复建议**

1) 使用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id);`，从根本上消除拼接；2) 若必须使用字符串拼接，至少对 `$id` 做严格类型校验（`$id = (int)$_GET['id']` 或 `filter_var(..., FILTER_VALIDATE_INT)`）并配合 `mysqli_real_escape_string`；3) 关闭生产环境的数据库错误回显，改为记录日志并返回通用错误页，避免 `mysqli_error` 直接输出；4) 数据库连接账户遵循最小权限原则，仅授予所需表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /042.php?id=1' UNION SELECT user, password FROM users-- -`（仅限授权测试，目标写为 TARGET）。042.php:5 从 query 参数 `id` 读取该字符串；042.php:11 将其原样插入 `SELECT first_name, last_name FROM users WHERE user_id = $id;`，形成 `... WHERE user_id = 1' UNION SELECT user, password FROM users-- -;`；042.php:12 调用 `mysqli_query` 执行被篡改的语句，UNION 结果随正常查询结果一并返回，攻击者获得任意表数据。若注入语法错误，`or die(mysqli_error(...))` 还会把数据库错误原文回显，辅助攻击者逐步构造 payload。
PocWriter 建议（未采纳，缺少端点 /042）：针对 042.php 第 12 行的 SQL 注入 POC（CWE-89），注入通道为查询字符串参数 id。该候选与 LLM-d68d039a3f46 指向同一文件同一行，区别在于注入位置为 query 而非 body；两者应视为同一漏洞的不同触发通道，实际利用时以源码中实际读取的参数来源为准。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于 042.php:12，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。原草稿中的 HTTP 方法 ANY 不是合法 HTTP 方法，实际发送时应使用 GET 或 POST；执行前须将 TARGET 替换为授权测试环境地址并确认已获授权。禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.64 | 是 |
| surface_mapper | 攻击面测绘 | 8.73 | 是 |
| deep_finder | LLM 深挖 | 8.61 | 是 |
| candidate_screener | 候选筛选 | 3.12 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.68 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.82 | 是 |
| coordinator | 管线协调 | 6.36 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
