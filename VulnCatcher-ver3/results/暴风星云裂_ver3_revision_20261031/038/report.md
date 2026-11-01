# 落日二号乙漏洞挖掘报告 — 20261031-012026-4fb15b

- 生成时间：2026-10-30T17:21:08.365107+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\038.zip`
- 输入模式：`zip`
- SHA256：`c09d22cf17e0571866be3b8075d761031599ef920bd9e7aa6bd584dbd9a3cd5a`
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

本次汇总仅含 1 条已去重 finding：038.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），定级 critical，且已附带 POC（HTTP 型，可动态复现路径明确）。这是本次最高危且唯一交付项。POC 齐全度为 1/1，但需注意该 POC 属 HTTP 请求型，尚未经动态验证，仅为文本工件。其余攻击面（文件包含/路径拼接、反射型 XSS、配置类弱算法/弱随机/不安全 Cookie、信任边界）在 surface_notes 中被标为待确认，未形成 finding，不能据此判定不存在。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅含单文件 038.php（57 行，DVWA 低安全级别 SQL 注入模块）。已逐行审计：入口为 `isset($_GET['Submit'])`，污点源为 `$_GET['id']`（第 5 行），在 MySQL 分支（第 11-13 行）与 SQLite 分支（第 32-34 行）均以字符串拼接方式进入 SQL 执行汇点，无任何转义/参数化/白名单，构成闭合的 SQL 注入链，已作为唯一 finding 交付。其余攻击面核查结论：第 46、52 行 `$html .=` 为固定字符串拼接，不含用户输入，不构成 XSS；第 49 行 `header()` 使用 `$_SERVER['SERVER_PROTOCOL']` 属服务端变量，非攻击者可控；文件中无 exec/system/include/file 操作、无 md5/sha1/rand/setcookie/session 调用，故 command_injection、path_traversal、file_upload、weak_hash、weak_random、insecure_cookie、weak_crypto 均无证据，不报告。未覆盖范围：无 php.ini/Web 服务器配置、无路由与认证配置、无依赖清单，无法评估部署层利用条件与第三方组件风险；`$_DVWA` 与 `$GLOBALS["___mysqli_ston"]` 的定义位于 CODE PACK 之外，按契约视为不存在，其初始化正确性需人工确认。

未覆盖 / 证据缺口：
- $_DVWA['SQLI_DB'] 与数据库连接对象的初始化代码不在 CODE PACK 内，无法确认运行时分支
- 无 Web 服务器/php.ini 配置，无法确认 allow_url_include、open_basedir 等部署条件
- 无认证/会话文件，无法确认该脚本是否位于登录后目录
- 无依赖清单，无法评估第三方组件 CVE

## 3. Findings

### F-1: 038.php 中基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（038.php:5 读取该参数）。该值未经任何过滤、转义或类型转换，被直接拼接进 SQL 语句：038.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"`，随后在 038.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 位于单引号字符串字面量内部且未使用 `mysqli_real_escape_string` 或预处理语句，攻击者可用单引号闭合字面量并注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。代码中仅移除了 `or die` 以抑制错误回显，这并不构成任何安全校验，因此校验完全无效。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 038.php 第 13 行的 SQL 注入 POC（端点记为 /038，方法记为 ANY）。注入点为查询参数 id，外部输入未经有效净化进入 SQL 语句。目标地址统一使用 TARGET 占位符，仅限授权测试。注意：源码文件为 038.php，实际请求路径应以部署配置为准，此处保留输入给出的 /038 结构。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/038?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-5bc99d7a2891`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库内容泄露：攻击者可读取 users 表及其他表的数据（如凭据、个人信息）；通过 UNION 注入可跨表提取数据；在数据库权限较高时还可能读写文件或进一步影响数据库服务。属于未授权远程数据泄露，严重级别 critical。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 038.php；利用链闭合：038.php:5 读取参数 → 038.php:11 字符串拼接 → 038.php:13 `mysqli_query` 执行，全程无净化或参数化，攻击者输入直接决定 SQL 语义。

**修复建议**

改用参数化查询：使用 `mysqli_prepare` 配合 `bind_param('s', $id)` 或 PDO 预处理语句，将 `$id` 作为绑定参数而非字符串拼接；若必须拼接，至少使用 `mysqli_real_escape_string` 并对 `id` 做整数白名单校验（如 `ctype_digit` 或 `intval`）；同时遵循最小权限原则，限制数据库账号权限，并避免向客户端回显数据库错误。

**验证说明**

静态证据：入口 ANY /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者在请求中设置 `id=1' OR '1'='1`（或 UNION 载荷）→ 038.php:5 读取 query 参数 `id` → 038.php:11 将 `$id` 直接拼入 `SELECT first_name, last_name FROM users WHERE user_id = '$id';` → 038.php:13 `mysqli_query` 执行被篡改的 SQL → 返回非预期结果集，实现数据泄露。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89（SQL 注入）。漏洞位于 038.php 第 13 行，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。主机名使用 TARGET 占位符。ANY 方法在文本中以 GET 呈现以便复现，实际可按部署支持的方法调整。禁止使用 DROP 等破坏性语句。仅限授权测试。

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
| safety_guard | 安全防护 | 2.51 | 是 |
| surface_mapper | 攻击面测绘 | 7.61 | 是 |
| deep_finder | LLM 深挖 | 9.91 | 是 |
| candidate_screener | 候选筛选 | 4.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.01 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.01 | 是 |
| coordinator | 管线协调 | 5.7 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
