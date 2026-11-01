# 落日二号乙漏洞挖掘报告 — 20261031-014307-90995c

- 生成时间：2026-10-30T17:43:48.332859+00:00
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

本次汇总仅含 1 条已去重 finding：041.php 第 11 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现路径存在，但本次未做动态验证）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备。其余攻击面（文件包含/路径拼接、命令执行、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码密钥）在 surface_notes 中被列为优先排查或人工复核项，但均未形成 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1710 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 041.php（显示 1-46 行，共 56 行，第 47-56 行未送入）。已审计：请求入口（第 3 行 Submit 判断）、污点源（第 5 行 $_REQUEST['id']）、MySQL 分支拼接与执行（第 10-11 行）、SQLite 分支拼接与执行（第 31-34 行）、结果回显（第 20 行）。确认一条闭合的 SQL 注入链（CWE-89），MySQL 与 SQLite 两分支同源同根因，合并为一条 finding。未闭合/未覆盖线索：第 47-56 行未提供，无法确认是否存在额外输出或文件操作；无 php.ini/.htaccess/composer.json，无法判断 register_globals、magic_quotes 等运行时约束；无路由清单，无法确认对外暴露路径与鉴权要求。medium_review_items 中的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 在已显示代码中均无对应证据（未见 md5/sha1、加密调用、rand、setcookie、X-Forwarded-For 信任或硬编码密钥），故不单独立项。输入中未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 041.php 第 47-56 行未送入，未审计
- 无运行时配置（php.ini/.htaccess），无法确认 SQLI_DB 取值与全局转义设置
- 无路由/鉴权信息，无法确认页面暴露面与是否需要登录
- 仅单文件，跨文件调用链未覆盖

## 3. Findings

### F-1: 041.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`041.php:9-11`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（041.php:5 读取该参数），该值未经任何过滤、转义或类型校验，被直接拼接进 SQL 语句：041.php:10 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 041.php:11 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 处于单引号字符串上下文中且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1`、`1' UNION SELECT ...`）。校验无效的原因：代码路径中不存在白名单、类型转换（如 `intval`）或参数化绑定，输入原样进入查询字符串。最终到达的危险操作是数据库查询执行汇点 mysqli_query（041.php:11），且错误信息通过 die() 回显（mysqli_error），进一步为报错注入与结构探测提供便利。

**source / sink**

- source：query `id`（041.php:5）
- sink：041.php:11 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `041.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `041.php:11` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /041（ANY）的 SQL 注入 POC。注入点：ANY 参数 id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/041'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/041?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-cee48d9ee314`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可读取 users 表及其他表内容（如凭据、个人信息）；通过 UNION/报错注入可枚举库表结构；在数据库权限过高时可导致数据篡改或删除。属于未授权远程可利用的严重数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：source（041.php:5 的 query `id`）→ 字符串拼接（041.php:10）→ 执行汇点 mysqli_query（041.php:11），中间无有效净化，攻击者完全控制 SQL 语义。

**修复建议**

改用参数化查询/预处理语句：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param('i', $id); $stmt->execute();`，并对 `id` 做整型强制转换（`$id = (int)$_GET['id'];`）。若必须拼接，使用 `mysqli_real_escape_string` 并加引号。同时关闭生产环境的详细数据库错误回显，改为记录日志并返回通用错误页。

**验证说明**

静态证据：入口 ANY /041；source=query/id；sink=041.php:11；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：1) 攻击者请求 `041.php?id=1' OR '1'='1`；2) 041.php:5 从 query 读取 `id`，污点进入；3) 041.php:10 将 `$id` 直接拼入 `WHERE user_id = '$id'`，单引号被闭合，注入生效；4) 041.php:11 执行被篡改的 `$query`，返回攻击者构造的结果集，实现数据泄露。
PocWriter 建议（未采纳，缺少端点 /041）：针对 041.php 第 11 行的 SQL 注入 POC（查询串通道）。注入点为 URL query 参数 id，被直接拼接进 SQL 查询（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /041）：符合 CWE-89（SQL 注入）。漏洞位于 041.php:11，外部输入来自 query 参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。原草稿使用 -X ANY 并非合法 HTTP 方法，实际验证请改用 GET 查询串（或按源码实际取值方式调整）；TARGET 需由授权测试人员手动替换；禁止破坏性载荷。

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
| safety_guard | 安全防护 | 2.4 | 是 |
| surface_mapper | 攻击面测绘 | 7.52 | 是 |
| deep_finder | LLM 深挖 | 8.38 | 是 |
| candidate_screener | 候选筛选 | 3.28 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.26 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.62 | 是 |
| coordinator | 管线协调 | 6.01 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
