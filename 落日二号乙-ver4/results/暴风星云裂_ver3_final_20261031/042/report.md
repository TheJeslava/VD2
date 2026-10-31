# 落日二号乙漏洞挖掘报告 — 20261031-014316-33bdb1

- 生成时间：2026-10-30T17:43:56.644485+00:00
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

本次汇总仅含 1 条已去重 finding：042.php 中基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可动态复现方向）。这是本次最高危且唯一交付项。POC 齐全度为 1/1，但该 POC 尚未经动态验证，仅为文本工件。攻击面高度集中在单文件 042.php（59 行），无框架、无路由清单、无端点声明，认证与部署方式无证据。surface_notes 中列出的 path_traversal/文件包含、命令执行、反射型 XSS 以及 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 等方向均未被 findings 覆盖，已转入人工复核，不能视为已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 042.php（59 行，DVWA SQL Injection 模块）。已逐行审计：入口为第 3 行 `$_POST['Submit']` 判定与第 5 行 `$_POST['id']`；汇点为第 12 行 mysqli_query 与第 30 行 SQLite query。确认存在数字型 SQL 注入（第 11/27 行拼接，mysqli_real_escape_string 对数字上下文无效），已给出闭合利用链与 POC。第 21/43 行将 `$id` 与数据库字段回显到 HTML，理论上存在反射型 XSS，但 `$id` 已经 mysqli_real_escape_string 处理（不转义 `<`/`>`），仍可注入 HTML；不过该点与 SQL 注入同源同参数，且 XSS 价值低于 SQLi，未单独立项，作为线索记录。未发现命令执行、文件包含、反序列化、SSRF、弱哈希/弱随机/不安全 Cookie/硬编码密钥等证据（脚本中无 md5/sha1/rand/setcookie/exec/include 调用）。未覆盖范围：无路由清单、无 php.ini/Web 服务器配置、无认证文件、无 composer 依赖，无法评估部署暴露面与第三方组件 CVE；这些缺口不影响上述 SQL 注入结论。

未覆盖 / 证据缺口：
- 无 HTTP 端点清单与路由定义，endpoint 依据脚本路径推断为 /042.php
- 无认证/会话文件，无法确认是否需登录
- 无 php.ini/Web 服务器配置，无法确认危险函数禁用与错误回显
- 无依赖清单，无法评估第三方组件 CVE
- 第 21/43 行 `$id` 回显存在反射型 XSS 线索，因与 SQLi 同源且价值较低未单独立项

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（042.php:5 读取该参数），该值未经任何类型校验、转义或参数化，被直接拼接进 SQL 语句：042.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 SQL 语句的数值上下文且无引号包裹，攻击者可注入 `1 OR 1=1`、`1 UNION SELECT ...` 等片段改变查询语义；同时 042.php:12 的 `or die('<pre>' . mysqli_error(...) . '</pre>')` 会把数据库错误信息回显到响应中，为报错型注入和结构探测提供便利。校验无效的原因：代码路径中不存在 `intval()`、`mysqli_real_escape_string()`、预处理语句或白名单，污点从 source 到 sink 全程未净化。

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

数据库数据泄露：可 UNION 查询拖取 users 表及其他表（如用户名、口令哈希）内容；可绕过 `user_id` 条件枚举全部记录；结合错误回显可推断库名、表名、列结构。若数据库账户权限过高，还可能读写文件或进一步影响数据库服务，属于高危数据泄露与完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 042.php 触发；利用链闭合：042.php:5 读取 `id` → 042.php:11 字符串拼接进 `$query` → 042.php:12 `mysqli_query` 执行，且 042.php:12 的错误回显进一步降低利用门槛。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须拼接，先对 `$id` 做严格整数校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval()`）并拒绝非法值；关闭向客户端回显数据库错误（记录到服务端日志，返回通用错误页）；数据库账户遵循最小权限，禁用 FILE 权限。

**验证说明**

静态证据：入口 ANY /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `042.php?id=1 UNION SELECT user, password FROM users`（仅限授权测试，目标写 TARGET）。042.php:5 从 query 读取 `id`，未净化即进入 042.php:11 的字符串拼接，形成 `SELECT first_name, last_name FROM users WHERE user_id = 1 UNION SELECT user, password FROM users;`，在 042.php:12 由 `mysqli_query` 执行，查询结果随页面返回；若语法错误，`mysqli_error` 内容经 `die('<pre>...</pre>')` 回显，辅助攻击者迭代 payload。
PocWriter 建议（未采纳，缺少端点 /042）：针对 042.php 第 12 行的 SQL 注入 POC（CWE-89）。注入点为查询字符串参数 id（GET/ANY 方法），该参数值未经有效净化即拼接进 SQL 查询。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于 042.php:12，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。执行前须将 TARGET 替换为授权测试目标，并确保已获书面授权。禁止使用 DROP/TRUNCATE 等破坏性语句。

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
| safety_guard | 安全防护 | 2.81 | 是 |
| surface_mapper | 攻击面测绘 | 7.9 | 是 |
| deep_finder | LLM 深挖 | 9.07 | 是 |
| candidate_screener | 候选筛选 | 3.53 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.56 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.52 | 是 |
| coordinator | 管线协调 | 4.76 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
