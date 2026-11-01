# 落日二号乙漏洞挖掘报告 — 20261031-014237-0dfb5a

- 生成时间：2026-10-30T17:43:19.795525+00:00
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

本次汇总仅包含 1 条已去重 finding：039.php 第 15 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC，是本次唯一且最高危的问题。该 POC 属于 HTTP 型（参数 id 注入），但输入未给出实际端点 URL 与参数名，复现路径需人工补齐。其余攻击面（文件包含/路径拼接、命令执行、反射型 XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界）在 surface_notes 中被列为优先核查区或 medium_review_items，但均未形成 finding，属于覆盖缺口而非已排除。所有结论均为源码/攻击面层面的静态判断，未做任何动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1788 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅审计了 code_pack 中唯一文件 039.php 的第 1-50 行（共 54 行，末尾 4 行未送入）。该文件是 DVWA 的 SQL 注入练习页：第 5 行读取 $_POST['id']，第 13/34 行直接拼接进 SQL，第 15/36 行执行。MySQL 分支的 mysqli_real_escape_string 因数值上下文而失效，构成可利用的 SQL 注入（CWE-89），已作为唯一闭合链交付。SQLite 分支（第 34 行）同样存在未转义拼接，属同一根因，未重复报告。未发现命令执行、文件包含、反序列化、SSRF、XSS 等其它 sink；weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置型线索在可见代码中均无对应证据。输入中未出现诱导性文本。

未覆盖 / 证据缺口：
- 039.php 第 51-54 行未送入 code_pack，结果渲染/输出部分未完整审计
- 无 php.ini、Web 服务器配置，无法确认 allow_url_include、display_errors 等设置
- 无 endpoints 清单，实际 URL 与参数名需人工确认
- $_DVWA['SQLI_DB'] 取值未知，无法确定实际执行分支

## 3. Findings

### F-1: 039.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`039.php:13-15`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该输入在 039.php:5 被读取后未做任何类型转换、转义或参数化，直接以字符串拼接方式进入 039.php:13 构造的 SQL 语句：`$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`。由于 `$id` 被原样嵌入 SQL 文本，攻击者可闭合/改写 WHERE 条件（如 `1 OR 1=1`、`1 UNION SELECT ...`）。039.php:14-15 将该拼接后的 `$query` 交给 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行，代码中仅用 try/catch 抑制错误回显（注释“Removed 'or die' to suppress mysql errors”），并未做任何输入校验或参数绑定，因此校验完全无效，污点直达 SQL 执行汇点。

**source / sink**

- source：query `id`（039.php:5）
- sink：039.php:15 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `039.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `039.php:15` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /039（任意方法）的 SQL 注入 POC。注入点为查询字符串参数 id，源码 039.php:15 将外部输入直接拼入 SQL 查询。目标地址统一使用 TARGET 占位符，仅限授权测试。注意：源码中实际入口文件为 039.php，本 POC 的 /039 路径需以部署环境实际路由为准，若路由不匹配应回退到 /039.php。

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

数据库查询逻辑可被任意篡改：可绕过 user_id 条件读取 users 表全部记录（first_name、last_name），并通过 UNION 注入进一步读取其他表/库中的敏感数据（如凭据、个人信息），造成数据泄露；在数据库账户权限过高时还可能读写文件或影响数据完整性。属于未授权即可远程触发的数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 039.php 触发；利用链闭合：039.php:5 读取 `id` → 039.php:13 字符串拼接进 `$query` → 039.php:15 `mysqli_query` 执行，链路上不存在转义、白名单或参数化，攻击者输入直接决定 SQL 语义。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = mysqli_prepare($link, "SELECT first_name, last_name FROM users WHERE user_id = ?"); mysqli_stmt_bind_param($stmt, 'i', $id); mysqli_stmt_execute($stmt);`，并对 `id` 做整数类型强校验（如 `filter_var($id, FILTER_VALIDATE_INT)`，失败即拒绝）。禁止将外部输入拼接进 SQL 文本；数据库账户遵循最小权限，关闭详细错误回显。

**验证说明**

静态证据：入口 ANY /039；source=query/id；sink=039.php:15；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `039.php?id=1 OR 1=1`（或 `039.php?id=1 UNION SELECT ...`）→ 039.php:5 从 query 读取 `id` → 039.php:13 将 `$id` 原样拼入 `SELECT first_name, last_name FROM users WHERE user_id = $id;` → 039.php:15 `mysqli_query` 执行被篡改的语句 → 返回超出预期的数据集，实现数据泄露。
PocWriter 建议（未采纳，缺少端点 /039）：符合 CWE-89（SQL 注入）。漏洞位于 039.php:15，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：脚本仅为文本参考，不自动执行；执行前须替换 TARGET 并确认授权。禁止使用 DROP 等破坏性语句。参考请求：curl -sS -i 'http://TARGET:8080/039?id=%27%20OR%20%271%27%3D%271'（仅限授权测试）。

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
| safety_guard | 安全防护 | 2.62 | 是 |
| surface_mapper | 攻击面测绘 | 9.88 | 是 |
| deep_finder | LLM 深挖 | 8.71 | 是 |
| candidate_screener | 候选筛选 | 2.6 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.0 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.02 | 是 |
| coordinator | 管线协调 | 6.39 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
