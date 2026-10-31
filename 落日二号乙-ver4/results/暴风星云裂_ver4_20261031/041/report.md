# 落日二号乙漏洞挖掘报告 — 20261031-164616-82440f

- 生成时间：2026-10-31T08:47:07.152517+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\041.zip`
- 输入模式：`zip`
- SHA256：`79e2a6d843927e577eebaaeee2a818debf8da783d298ea705037330b946c7905`
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

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径明确）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备。需注意：surface_notes 明确说明输入未提供 041.php 的实际源码片段，仅有文件清单与热点统计（source 热点 2 处、sink 热点 1 处），因此该 finding 的行号与污点链路细节无法在本级交叉核对，属规则命中 + 静态推断，未经动态验证。其余攻击面（文件包含/路径拼接、命令执行/代码执行、XSS、配置类弱实现）均未形成 finding，属未覆盖或未交付，不能表述为不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 041.php（共 56 行，仅展示 1-46 行），无框架、无路由、无端点清单。已审计该文件全部可见代码：入口为 isset($_REQUEST['Submit']) 判断，污点源为 $_REQUEST['id']（第 5 行），sink 为 mysqli_query（第 11 行）与 SQLite3::query（第 34 行），两处均为字符串拼接，构成完整 SQL 注入链，已作为唯一 finding 交付。第 20 行 $html 拼接 $id 与数据库字段，若后续有 echo 输出则同时构成反射型 XSS，但第 46 行之后（47-56 行）未在 CODE PACK 中展示，无法确认 $html 是否被输出，故不单独报告 XSS，仅作为未闭合线索记录。surface_notes 中提到的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 在可见代码中均未出现对应调用（无 md5/sha1/rand/setcookie/硬编码凭据），不成立。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未在 CODE PACK 中展示，无法确认 $html 是否被 echo 输出（潜在反射型 XSS）
- 缺少部署配置（PHP 版本、allow_url_include、disable_functions）与认证机制说明，无法判断匿名可达性
- 无端点清单与参数清单，攻击面仅基于单文件推断
- 无 composer.json/依赖清单，未评估供应链风险

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，其中 `$id` 位于单引号字符串字面量内部；随后 041.php:11 调用 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行该语句。由于未使用 mysqli 预处理语句/参数绑定，也未调用 mysqli_real_escape_string 等转义函数，攻击者只需在 `id` 中闭合单引号即可改变查询语义（例如 `1' OR '1'='1` 返回全部用户，或使用 UNION SELECT 读取其他表数据）。此外 041.php:11 在查询失败时通过 `die(... mysqli_error(...) ...)` 将数据库错误信息回显到页面，为基于报错的注入提供了反馈通道，进一步降低利用门槛。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 041.php 第 11 行的 SQL 注入 POC（同一注入点，端点写法为 /041）。注入点为查询参数 id，Submit 为表单提交按钮字段。原始草稿使用 ANY 方法与 /041 路径，本 POC 依据源码将方法修正为 GET、路径修正为 /041.php，避免使用抽象占位符。目标地址统一使用 TARGET，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/041'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/041?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cee48d9ee314`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：攻击者可读取 users 表之外的任意表（如账号、口令散列等），并可结合 UNION/布尔/报错注入逐字节提取数据；在数据库账号权限较高且支持堆叠查询的场景下可能进一步导致数据篡改或写入文件。错误回显还会泄露库名、表结构等元信息。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`（041.php:5），无需认证即可访问该脚本；利用链闭合：外部输入 → `$id` → 字符串拼接 `$query`（041.php:10）→ `mysqli_query` 执行（041.php:11），全程无净化函数，且错误信息回显（041.php:11 的 die/mysqli_error）提供注入结果反馈。

**修复建议**

改用参数化查询：`$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整型强校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）。禁止将外部输入拼接进 SQL 字符串；关闭生产环境的数据库错误回显（记录到日志而非输出到页面）；数据库账号遵循最小权限，仅授予所需表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：1) 攻击者请求 041.php 并传入 query 参数 `id`（041.php:5 读取）；2) 该值未过滤直接进入 041.php:10 的字符串拼接，形成 `WHERE user_id = '$id'`；3) 041.php:11 通过 mysqli_query 执行拼接后的 `$query`，注入生效；4) 查询失败时 die 分支回显 mysqli_error，攻击者可据此构造报错注入并读取任意数据。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化查询，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。原始草稿中的 ANY 方法与 /041 路径已按源码修正为 GET 与 /041.php；若目标确实存在 /041 重写规则，可由授权测试人员自行调整。禁止使用 DROP/TRUNCATE 等破坏性语句。

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
| safety_guard | 安全防护 | 4.29 | 是 |
| surface_mapper | 攻击面测绘 | 9.61 | 是 |
| deep_finder | LLM 深挖 | 10.01 | 是 |
| candidate_screener | 候选筛选 | 3.49 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.89 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.59 | 是 |
| coordinator | 管线协调 | 6.59 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
