# 落日二号乙漏洞挖掘报告 — 20261031-012040-091ee0

- 生成时间：2026-10-30T17:21:22.972737+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\039.zip`
- 输入模式：`zip`
- SHA256：`dcd627aba47edb36b6b02995d92ae6b47ea38157489be6bc6bc3ad973f56f1e9`
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

本次审计范围是单文件 PHP 脚本 039.php（54 行，无框架、无路由配置、无端点清单）。已交付 1 条 finding：039.php 第 15 行附近，基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，仅限授权测试，目标用 TARGET 占位）。这是本次唯一且最高危的问题，POC 齐全。除此之外，weak_hash、weak_crypto、weak_random、insecure_cookie、trust_boundary 五类仅作为人工复核项登记，均无静态证据 POC，也未做动态验证；二次注入链不可判定（存储写点、读点、汇点三者均不可见）。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 039.php（显示 1-50 行，共 54 行），无框架、无路由、无端点清单。审计确认第 5 行读取 POST 参数 id，第 13/34 行字符串拼接构造 SQL，第 15/36 行执行，构成完整 SQL 注入链；MYSQL 分支的 mysqli_real_escape_string 对数值型注入无效，SQLITE 分支完全无转义。第 47/50 行回显存在性可作为布尔盲注信道。未发现命令执行、文件包含、反序列化、SSRF、弱随机、弱哈希、insecure_cookie 或信任可伪造头部的证据；文件第 51-54 行未送入，无法确认结尾是否有额外逻辑。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未在 code_pack 中显示，结尾逻辑未审计
- 无部署配置（php.ini、$_DVWA 配置、Web 服务器映射），无法确认 SQLI_DB 取值与是否需要认证
- endpoints 为空，实际 URL 路径与 HTTP 方法依赖服务器直接映射
- 无数据库 schema，UNION 列数需动态确认

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.73`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该输入在 039.php:5 被读取后未做任何类型转换、转义或参数化，直接在 039.php:13 被字符串拼接进 SQL 语句 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 039.php:15 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 SQL 语句的数值比较位置且未加引号包裹，攻击者可构造如 `1 UNION SELECT user, password FROM users` 或布尔/报错型载荷改变查询语义；代码中仅用 try/catch 抑制了 MySQL 错误输出（注释“Removed 'or die' to suppress mysql errors”），这属于错误处理而非输入校验，无法阻断注入。校验无效的根本原因是整条链路不存在预处理语句、白名单或转义函数（如 mysqli_real_escape_string / intval），污点从 source 到 sink 全程未净化。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /039（任意方法）的 SQL 注入 POC。注入点为查询字符串参数 id，源码 039.php:15 将该参数直接拼入 SQL 查询，未做有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/039'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/039?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-22ffdf9a5620`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询语句可被攻击者任意改写，导致越权读取 users 表中的口令哈希等敏感数据（数据泄露）、绕过业务查询条件，并可能通过 UNION/子查询进一步枚举库表结构；若数据库账户权限过高，还可造成数据篡改。属于高危数据泄露类影响。

**CVE / CWE 论证**

对应 CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：039.php:5 读取 `id` → 039.php:13 字符串拼接 → 039.php:15 `mysqli_query` 执行，中间无净化点，攻击者完全控制 SQL 片段，满足注入成立的全部条件。

**修复建议**

改用参数化查询：使用 `mysqli_prepare` 配合 `bind_param('i', $id)` 或 PDO 预处理，将 `id` 作为绑定参数而非拼接；若必须拼接，先以 `intval($id)` 强制转换为整数并校验范围；同时遵循最小权限原则，为应用数据库账户仅授予必要的 SELECT 权限，并避免将数据库错误信息回显给客户端。

**验证说明**

静态证据：入口 ANY /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者向 039.php 发送请求并携带 query 参数 `id`（如 `?id=1 UNION SELECT user,password FROM users`）→ 039.php:5 读取该参数进入变量 `$id` → 039.php:13 将 `$id` 直接拼接进 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 039.php:15 调用 `mysqli_query` 执行被篡改的语句 → 查询结果被页面输出，攻击者获得任意数据读取能力。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89（SQL 注入）。漏洞位于 039.php:15，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：保留原确定性 POC 的请求结构，仅补充说明与预期结果。原草稿使用 -X ANY 非标准方法，实际执行时建议改用 GET 或按部署实际方法；脚本为文本工件，需人工替换 TARGET 后在授权环境手动执行。

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
| safety_guard | 安全防护 | 3.19 | 是 |
| surface_mapper | 攻击面测绘 | 8.9 | 是 |
| deep_finder | LLM 深挖 | 8.84 | 是 |
| candidate_screener | 候选筛选 | 3.84 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.51 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 5.83 | 是 |
| coordinator | 管线协调 | 5.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
