# 落日二号乙漏洞挖掘报告 — 20261031-010332-2ba162

- 生成时间：2026-10-30T17:04:12.859637+00:00
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

本次汇总仅含 1 条已去重 finding：039.php 第 15 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现方向）。这是本次唯一且最高危的问题，攻击面窄但集中：source 热点 2 处、sink 热点 1 处均落在同一文件，污点路径短、可达性高。POC 齐全度为 1/1，但仅覆盖该 SQL 注入；其余攻击面（文件路径拼接/包含、输出回显 XSS、命令执行、配置类弱哈希/弱加密/弱随机/Cookie 标志、信任边界）在本次 findings 中均无对应条目，属未覆盖而非已排除。所有结论均为源码/规则层面的静态判断，未经动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 039.php（显示 1-50 行，共 54 行，第 51-54 行未在 code_pack 中，视为不可见）。逐行审计确认：唯一外部输入为 $_POST['id']（039.php:5），流向两处 SQL 执行汇点——MYSQL 分支 mysqli_query（039.php:15）与 SQLITE 分支 $sqlite_db_connection->query（039.php:36）。MYSQL 分支仅用 mysqli_real_escape_string 转义，在未加引号的数值上下文中不构成有效防护；SQLITE 分支完全无转义。构成闭合的 SQL 注入链，已作为 high 级 finding 交付。其余攻击面：文件包含/读取、命令执行（system/exec 等）、输出回显 XSS、弱哈希/弱加密/弱随机、setcookie 标志、信任 X-Forwarded-* 等，在可见的 1-50 行中均未出现对应调用，故不报告。第 51-54 行（可能含 $html 输出与 HTML 模板）未覆盖，若其中存在未编码回显则可能有反射型 XSS，但无证据不报告。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未在 code_pack 中，无法确认 $html 最终输出是否编码（潜在反射型 XSS 未闭合）
- 无 php.ini/Web 服务器配置，无法确认全局过滤与部署方式
- 无端点清单与鉴权前置信息，无法确认 039.php 是否需登录
- 无 composer/依赖与 PHP 版本信息

## 3. Findings

### F-1: 039.php 中基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（039.php:5 读取该参数），该值未经任何类型转换、转义或参数化，被直接拼接进 SQL 语句：039.php:13 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 039.php:15 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于 SQL 语句的数值上下文且无引号包裹，攻击者可注入 `1 OR 1=1`、`1 UNION SELECT ...` 等片段改变查询语义。代码中未见 mysqli_real_escape_string、intval 强制转换、预处理语句或白名单校验，因此校验完全缺失。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /039（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

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

数据库查询逻辑可被任意篡改：可绕过 user_id 条件读取 users 表全部记录（first_name、last_name），并通过 UNION 注入读取其他表（如用户名/口令散列），造成敏感数据泄露；在数据库账户权限较高时还可结合堆叠/文件写入能力扩大影响。属于未授权即可触发的数据泄露类漏洞。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：039.php:5 读取参数 → 039.php:13 字符串拼接 → 039.php:15 mysqli_query 执行，中间无净化函数，攻击者输入直达 SQL 解析器。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须动态拼接，先对 `$id` 做 `intval()`/严格数字白名单校验，并使用 `mysqli_real_escape_string` 作为纵深防御；同时为数据库账户配置最小权限，关闭详细错误回显。

**验证说明**

静态证据：入口 ANY /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /039.php?id=1 OR 1=1`（仅限授权测试，目标写 TARGET）→ 039.php:5 从 query 读取 `id` 得到 `1 OR 1=1` → 039.php:13 拼接为 `SELECT first_name, last_name FROM users WHERE user_id = 1 OR 1=1;` → 039.php:15 `mysqli_query` 执行被篡改的语句 → 返回 users 表全部行，攻击者从响应中获取数据。
PocWriter 建议（未采纳，缺少端点 /039）：针对 039.php 第 15 行的 SQL 注入 POC（查询字符串方式）。外部输入来自 URL 查询参数 id，未经过有效净化即拼接进 SQL 查询，构成 CWE-89。目标地址统一使用 TARGET 占位符，POC 仅为文本工件，不执行、不联网。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89（SQL 注入）。漏洞位于 039.php 第 15 行，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：仅限授权测试。所有请求中的目标地址均为 TARGET 占位符，需替换为授权实例后手动执行；POC 为文本工件，管线不执行、不联网、不搭建沙箱。SQL 注入载荷避免使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.38 | 是 |
| surface_mapper | 攻击面测绘 | 6.92 | 是 |
| deep_finder | LLM 深挖 | 9.47 | 是 |
| candidate_screener | 候选筛选 | 3.47 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.55 | 是 |
| coordinator | 管线协调 | 6.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
