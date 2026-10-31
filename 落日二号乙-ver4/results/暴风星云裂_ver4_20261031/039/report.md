# 落日二号乙漏洞挖掘报告 — 20261031-164558-71aa21

- 生成时间：2026-10-31T08:46:41.216387+00:00
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

本次汇总仅含 1 条已去重发现：039.php 第 15 行附近，query 参数 id 直接进入 SQL 查询，判定为 sql_injection（CWE-89），严重度 critical，来源为规则匹配，已附带 POC（HTTP 型，可动态复现路径最短）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 发现均有 POC，无缺失。二次注入链：本次未提供任何存储写点/读点/汇点三元组，故不涉及二次注入结论。需强调：本次仅审计 1 个 PHP 文件、0 个端点，覆盖面极窄，结论不能外推为“该应用整体安全”。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入单个 PHP 文件 039.php（显示 1-50 行，共 54 行，末尾 51-54 行为 HTML 输出未展示）。审计确认：POST 参数 id 经 mysqli_real_escape_string 后仍以字符串插值拼入 SELECT 并执行（第 13/15 行），SQLite 分支完全无转义（第 34/36 行），构成数值型 SQL 注入，链闭合。未发现命令执行、文件包含、反序列化、SSRF 等其它汇点；第 47/50 行 $html 拼接为固定字符串，无参数回显，不构成 XSS。未发现 md5/sha1、rand/mt_rand、硬编码密钥或信任 X-Forwarded-* 的证据（采集缺失，非确认不存在）。51-54 行未展示，可能含输出逻辑，但不足以改变结论。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未在 code_pack 中展示
- 无部署配置，无法确认 URL 前缀与是否外网可达
- 未提供 PHP 版本与数据库类型运行时配置

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该输入在 039.php:5 被读取后未做任何类型校验、转义或参数化，直接以字符串拼接方式进入 039.php:13 构造的 SQL 语句：`SELECT first_name, last_name FROM users WHERE user_id = $id;`，随后在 039.php:15 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被原样嵌入 SQL 文本，攻击者可闭合/改写 WHERE 条件（如布尔盲注、UNION 联合查询、时间盲注），校验无效的根本原因是全程缺少 `intval()`/`mysqli_real_escape_string()`/预处理语句等任何净化手段，且代码注释显示已移除 `or die` 以抑制错误回显，进一步降低攻击者探测成本。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 039（无扩展名路由）第 15 行的 SQL 注入 POC（CWE-89）。注入点为 POST 表单参数 id，源码在该行将外部输入拼接进 SQL 查询且未见有效净化。请求使用 POST 方法并携带触发按钮字段 Submit，目标地址统一使用 TARGET 占位符。注意：本条与 LLM-840421309649 指向同一源码位置（039.php:15），差异仅在路由写法（/039 与 /039.php），需按实际部署确认哪个路由生效。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/039'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/039' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-22ffdf9a5620`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑可被任意篡改：可越权读取 users 表及其他表的数据（如凭据、个人信息），可借助 UNION/布尔/时间盲注逐字节提取数据；若数据库账户权限过高，还可能读写文件或进一步影响底层主机。属于数据泄露与数据库层面的越权访问。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：039.php:5 读取输入 → 039.php:13 字符串拼接进 SQL → 039.php:15 `mysqli_query` 执行，中间无任何过滤或参数化，攻击者完全控制 SQL 片段。

**修复建议**

改用预处理语句与参数绑定（`mysqli_prepare` + `bind_param('i', $id)`），或将 `$id` 强制转换为整数（`$id = (int)$_GET['id']`）并配合白名单校验；禁止将外部输入直接拼接进 SQL 文本；为数据库账户授予最小权限，关闭详细错误回显。

**验证说明**

静态证据：入口 POST /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?id=1 UNION SELECT user,password FROM users`（或布尔/时间盲注载荷）→ 039.php:5 读取 query 参数 `id` → 039.php:13 将 `$id` 原样拼入 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 039.php:15 `mysqli_query` 执行被篡改的语句 → 查询结果被返回/渲染，攻击者据此获取任意表数据。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 039.php:15，外部输入来自 POST body 参数 id，source→sink 链在给定代码范围内静态闭合，未发现参数化查询或转义等有效净化，具备远程触发条件。
POC 备注：仅保留文本请求结构，不生成可自动执行脚本；执行前须将 TARGET 替换为授权目标并人工确认。原草稿 cve_justification 中写为 query 参数，与 POST body 实际注入通道不一致，此处按源码 POST 参数 id 更正。

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
| safety_guard | 安全防护 | 3.34 | 是 |
| surface_mapper | 攻击面测绘 | 7.41 | 是 |
| deep_finder | LLM 深挖 | 8.66 | 是 |
| candidate_screener | 候选筛选 | 4.37 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.13 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.07 | 是 |
| coordinator | 管线协调 | 5.69 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
