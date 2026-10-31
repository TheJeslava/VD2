# 落日二号乙漏洞挖掘报告 — 20261031-214812-44cde4

- 生成时间：2026-10-31T13:49:00.417685+00:00
- 输入：`$WORKSPACE\暴风星云裂\041.zip`
- 输入模式：`zip`
- SHA256：`79e2a6d843927e577eebaaeee2a818debf8da783d298ea705037330b946c7905`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近，查询参数 id 直接拼接进 SQL 语句，类型 sql_injection，严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径最短）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备，但 POC 为文本工件，未执行、未做动态验证。其余攻击面（反射型 XSS、路径拼接/文件包含、配置实现类问题）在 surface_notes 中被标为待确认，未形成 finding，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 041.php（共 56 行，仅展示 1-46 行），无路由/框架/端点清单。已审计该文件全部可见行：确认第 3 行以 $_REQUEST['Submit'] 为入口，第 5 行取 $_REQUEST['id']，第 10/31 行字符串拼接构造 SQL，第 11/34 行执行，构成完整 SQL 注入链（MYSQL 与 SQLITE 两个分支同源同 sink，合并为一条 finding）。第 20 行 $html 拼接 $id 与查询结果，但该片段在展示范围内未见 echo 输出点（第 46 行后内容被截断，47-56 行未提供），因此反射型 XSS 链路不闭合，未报告。未发现命令执行、文件包含、反序列化、SSRF 等其它 sink。weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置类线索在可见代码中无对应实现（无 md5/sha1/rand/setcookie/HTTP_X_FORWARDED_FOR 使用），不报告。输入中未出现诱导性文本。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未包含在 code_pack 中，无法确认 $html 是否被 echo 输出（潜在反射型 XSS 未闭合）
- 无 Web 服务器/PHP 版本/php.ini 配置，无法评估错误回显与文件读写可利用性
- 无认证与会话机制信息，无法判断该页面是否需登录
- 无数据库连接配置，无法确认 ___mysqli_ston 与 $_DVWA['SQLI_DB'] 的实际取值

## 3. Findings

### F-1: 041.php 查询参数 id 直接拼接进 SQL 语句导致 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 字符串：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 041.php:11 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 位于单引号字符串字面量内部且未调用 mysqli_real_escape_string 等转义函数、也未使用预处理语句/参数绑定，攻击者可闭合单引号并注入任意 SQL 片段（如 `1' OR '1'='1`、`1' UNION SELECT ...`），校验完全失效。执行结果或错误信息还会经 041.php:11 的 `die(... mysqli_error(...) ...)` 回显，进一步为报错注入与数据回显提供通道。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /041（原草稿标注 ANY 方法）的 SQL 注入 POC。注入点为参数 id，源码 041.php:11 直接拼接该参数。由于源码未确认接受任意方法，本 POC 统一采用 GET 方法（与同文件 LLM-d2344e4ce96f 一致），并保留 Submit=Submit 触发字段。payload 使用 TARGET 占位符，仅限授权测试。

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

数据库数据泄露：可读取 users 表及其他表的任意数据（如用户名、口令哈希），可结合 UNION 查询跨表窃取；可造成认证绕过与数据完整性破坏（修改/删除记录）；错误回显（mysqli_error）暴露数据库结构与版本信息，便于进一步利用。若数据库账户权限过高，影响可扩展至整个数据库实例。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素未正确中和）。外部可达性：注入点为 HTTP query 参数 `id`，任何能访问该页面的远程用户均可触发；无需认证（代码片段中未见任何鉴权/会话校验）；利用链闭合：041.php:5 读取参数 → 041.php:10 字符串拼接 → 041.php:11 mysqli_query 执行，全程无净化，且错误信息回显增强可利用性。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整型强制转换（如 `$id = (int)$_GET['id'];`）。若必须拼接，至少使用 mysqli_real_escape_string 并加单引号包裹，但优先参数化。生产环境关闭详细数据库错误回显（移除 die(mysqli_error(...))），统一返回通用错误页；数据库账户遵循最小权限，仅授予所需表的 SELECT 权限。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?id=1' OR '1'='1` → 041.php:5 读取 query 参数 `id` 得到污点值 → 041.php:10 将污点值直接插入 `WHERE user_id = '$id'` 形成 `WHERE user_id = '1' OR '1'='1'` → 041.php:11 mysqli_query 执行被篡改的查询，返回全部用户记录；若注入 UNION/报错载荷，则通过页面或 mysqli_error 回显泄露数据。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89。漏洞位于 041.php:11，外部输入来自参数 id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网。已将原草稿中的抽象方法 ANY 修正为 GET，避免使用不可确认的方法；目标地址统一使用 TARGET 占位符，仅限授权测试。

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
| `blind_sql_injection` | CWE-89 |  | 0 |
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
| safety_guard | 安全防护 | 4.73 | 是 |
| surface_mapper | 攻击面测绘 | 8.73 | 是 |
| deep_finder | LLM 深挖 | 10.12 | 是 |
| candidate_screener | 候选筛选 | 4.07 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.21 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.73 | 是 |
| coordinator | 管线协调 | 6.74 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
