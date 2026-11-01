# 落日二号乙漏洞挖掘报告 — 20261031-173148-19fe5f

- 生成时间：2026-10-31T09:32:35.459832+00:00
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

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近、基于 query 参数 id 的 SQL 注入（CWE-89，critical，origin=rule），已附带 POC，属可动态复现的 HTTP 类 POC。最高危即此条，也是唯一交付项。其余攻击面（命令执行、文件包含/路径遍历、反射型 XSS、Cookie 标志、弱哈希/弱随机、硬编码凭据、信任边界）在 surface_notes 中被列为待确认优先级或 medium_review_items，但均未形成 finding，也无 POC，需人工读源码复核。整体样本仅 1 个 PHP 文件、56 行，覆盖面极窄，结论不可外推到其他文件。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 041.php（共 56 行，仅展示 1-46 行），已审计其全部可见逻辑：入口为 `$_REQUEST['Submit']` 与 `$_REQUEST['id']`，sink 为 MySQL 分支的 `mysqli_query`（第 11 行）与 SQLite 分支的 `SQLite3::query`（第 34 行）。确认存在一条闭合的 SQL 注入链（`id` 参数直接拼接），已作为 finding 交付。第 46 行之后（47-56 行）未展示，推测为 SQLite 分支的结果回显与 HTML 输出收尾，未发现新的独立 source/sink；若其中存在额外输出点，可能补充反射型 XSS，但当前证据不足，不单独报告。清单中提到的 weak_hash/weak_random/insecure_cookie/hardcoded_secret 等配置型线索在可见代码中均无对应实现，未发现证据。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未在 CODE PACK 中展示，无法确认 SQLite 分支的完整回显逻辑与是否存在额外输出点
- 缺少 php.ini / Web 服务器配置，无法判断 display_errors、open_basedir 等对利用的影响
- 无端点清单与部署信息，实际可访问 URL 与认证要求需人工确认
- 未做动态验证，注入可利用性依赖数据库配置

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该值在 041.php:5 被读取后，于 041.php:10 直接以字符串拼接方式嵌入 SQL 语句：`$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`，随后在 041.php:11 交由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。代码中未对 `$id` 做类型转换（如 intval）、转义（如 mysqli_real_escape_string）或参数化处理，单引号闭合即可改变查询语义，因此校验无效。此外 041.php:11 的 `or die(... mysqli_error(...) ...)` 会把数据库错误信息回显到响应中，为报错型注入和盲注提供反馈通道。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 041.php 第 11 行的 SQL 注入 POC（与 LLM-d2344e4ce96f 为同一注入点，此处按源码确认为 GET 方法）。注入点为查询参数 id，源码将其拼接进 SQL 语句（CWE-89）。原草稿中的 ANY 方法与路径 /041 已按源码修正为 GET 与 /041.php，并保留触发字段 Submit=Submit。

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

数据库查询语句可被任意篡改：可 UNION 查询同库其他表（如 users 表的 user/password 字段）导致凭据等敏感数据泄露；可基于布尔/时间盲注逐字节提取数据；在数据库账户权限较高且支持堆叠查询的环境下可能进一步写入或破坏数据。错误信息回显降低了利用门槛。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：source（041.php:5 的 `id`）→ 字符串拼接（041.php:10）→ 执行汇点 `mysqli_query`（041.php:11），中间无任何净化函数，攻击者仅需构造 `id=1' OR '1'='1` 之类的值即可改变查询逻辑。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('i', $id);`，并对 `id` 做整型强校验（如 `filter_var($id, FILTER_VALIDATE_INT)`）。禁止将用户输入拼接进 SQL；关闭数据库错误详情回显（生产环境记录日志而非 `die(mysqli_error())`）；数据库账户遵循最小权限，仅授予所需表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `GET /041.php?id=1' UNION SELECT user, password FROM users-- -`（目标地址以 TARGET 占位，仅限授权测试）。041.php:5 读取 `id`，041.php:10 将其拼入 `WHERE user_id = '$id'`，单引号闭合后注入 UNION 子句，041.php:11 执行该语句并把结果集返回页面，从而泄露 users 表数据。若注入语法错误，`or die(mysqli_error(...))` 会回显错误信息辅助构造。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自 GET 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化处理，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：原草稿使用 ANY 方法与 /041 路径，与源码不符，已修正为 GET 与 /041.php；不生成可自动执行脚本，仅保留文本请求结构。仅限授权测试。

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
| safety_guard | 安全防护 | 4.06 | 是 |
| surface_mapper | 攻击面测绘 | 9.77 | 是 |
| deep_finder | LLM 深挖 | 9.07 | 是 |
| candidate_screener | 候选筛选 | 3.24 | 是 |
| vulnerability_analyzer | 漏洞分析 | 7.04 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.5 | 是 |
| coordinator | 管线协调 | 6.19 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
