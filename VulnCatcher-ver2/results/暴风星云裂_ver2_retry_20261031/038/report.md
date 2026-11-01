# 落日二号乙漏洞挖掘报告 — 20261031-002236-b57659

- 生成时间：2026-10-30T16:23:20.698189+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\038.zip`
- 输入模式：`zip`
- SHA256：`c09d22cf17e0571866be3b8075d761031599ef920bd9e7aa6bd584dbd9a3cd5a`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总基于已去重的 2 条 findings，全部集中在唯一源文件 038.php 的 SQL 注入：规则命中 GEN-5bc99d7a2891（critical，038.php 第 13 行附近，GET 参数 id 拼接进查询）与 LLM 命中 LLM-b7203a166ab9（high，038.php 第 34 行附近，同一参数进入 mysqli/SQLite 查询），两条均带 POC，属同一注入点的规则/模型双证据，最高危为 critical 级 SQL 注入。POC 齐全度：2/2 有 POC，但均为静态文本 POC（HTTP 请求样例），未做动态验证，不能宣称可动态复现。覆盖面上仅审计了 1 个 PHP 文件、0 个端点、无框架；surface_notes 提出的文件包含/路径穿越、命令执行、反射型 XSS、弱哈希/弱加密/弱随机/Cookie 标志、信任边界等攻击面均无对应 finding，属未覆盖而非已排除。

共 **2** 条 finding；**2** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已逐行审计唯一文件 038.php（1-57 行）。确认存在一条闭合的 SQL 注入链：$_GET['id']（第 5 行）未经任何过滤拼入 SQL（第 11/32 行），经 mysqli_query（第 13 行）/SQLite query（第 34 行）执行，并通过第 44-52 行回显构成布尔盲注信道。该文件为 DVWA 教学靶场代码，属已知注入点。其余攻击面：第 49 行 header() 使用 $_SERVER['SERVER_PROTOCOL'] 拼接响应头，但该值由服务器/客户端协议决定，未发现可闭合的响应头注入链；未发现 include/exec/eval/文件读写等其它 sink；未发现硬编码凭据、弱哈希/弱加密、弱随机或 Cookie 标志问题（文件中无相关调用）。输入未提供 php.ini/部署信息，无法判断公网暴露面。

未覆盖 / 证据缺口：
- 无端点清单与路由信息，无法确认实际访问路径与是否需要认证
- 无运行环境配置（php.ini、allow_url_include 等），无法评估其它利用条件
- 未提供 $_DVWA 配置来源，SQLI_DB 分支实际取值需运行时确认

## 3. Findings

### F-1: 038.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该输入在 038.php:5 被读取后未做任何类型校验、转义或参数化，直接以字符串拼接方式进入 038.php:11 构造的 SQL 语句：`SELECT first_name, last_name FROM users WHERE user_id = '$id';`。由于 `$id` 被单引号包裹但未经过 mysqli_real_escape_string 或预处理语句绑定，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询）。拼接完成的 `$query` 在 038.php:13 传入 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行，构成完整的 source→sink 污点链。代码中仅移除了 `or die` 以抑制错误回显，并未引入任何净化逻辑，因此校验完全缺失。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 038.php（路由 /038，方法 ANY）的 SQL 注入 POC。注入点为查询参数 id，源码位置 038.php:13，外部输入未经有效净化进入 SQL 查询汇点（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。

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

数据库查询逻辑被攻击者完全控制：可绕过 user_id 条件读取 users 表全部记录（first_name、last_name 等），并通过 UNION SELECT 进一步读取当前数据库其他表（如账号、口令散列）乃至 information_schema 元数据，造成敏感数据泄露；在数据库账号权限较高时还可结合堆叠/文件写入能力扩大影响。属于未授权远程数据泄露风险。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，任何能访问 038.php 的远程用户均可触发，无需认证；利用链闭合：038.php:5 读取输入 → 038.php:11 字符串拼接进 SQL → 038.php:13 mysqli_query 执行，中间无白名单、无转义、无参数化，攻击者可控输入直达 SQL 解析器。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id); $stmt->execute();`，并将 `$id` 强制转换为整数（`$id = (int)$_GET['id']`）作为纵深防御；若必须拼接，使用 mysqli_real_escape_string 并配合类型白名单校验；同时为数据库账号授予最小权限，关闭详细错误回显。

**验证说明**

静态证据：入口 ANY /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `038.php?id=1' OR '1'='1` → 038.php:5 从 query 参数 `id` 读取该字符串 → 038.php:11 直接拼入 `WHERE user_id = '$id'`，单引号闭合使条件恒真 → 038.php:13 mysqli_query 执行被篡改的 SQL，返回 users 表全部行，实现未授权数据读取。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 038.php:13，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。ANY 方法在文本中保留，但手工验证建议使用 GET 以避免副作用；请将 TARGET 替换为已获授权的测试实例，禁止破坏性语句。

### F-2: DVWA SQL 注入（038.php）：GET 参数 id 直接拼接进 mysqli/SQLite 查询

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.88`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`038.php:5-34`
- **来源**：`llm_finding`

**描述**

038.php 在 isset($_GET['Submit']) 时读取 $_GET['id']（第 5 行），未做任何类型转换、转义或参数化，直接以单引号包裹拼入 SQL 语句（第 11 行 MySQL 分支、第 32 行 SQLite 分支），随后分别交给 mysqli_query（第 13 行）与 $sqlite_db_connection->query（第 34 行）执行。攻击者可通过闭合单引号注入任意 SQL，读取 users 表以外的数据（如用户名口令哈希），并借助第 44-52 行的布尔回显（存在/不存在）与 404 状态差异做布尔盲注。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:34 mysqli_query($GLOBALS["___mysqli_ston"], $query)（第 13 行）；$sqlite_db_connection->query($query)（第 34 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:3` | 检测到 Submit 参数后进入注入分支 | 请求进入处理逻辑 |  |
| 2 | `038.php:5` | 直接读取 $_GET['id'] 赋给 $id，无过滤 | 原始攻击者字符串 |  |
| 3 | `038.php:11` | 将 $id 以单引号包裹拼入 SQL 语句 | 字符串拼接，单引号可闭合 |  |
| 4 | `038.php:13` | 拼接后的语句交给 mysqli_query 执行 | 注入后的 SQL 被执行 |  |
| 5 | `038.php:44` | 根据查询结果是否存在返回不同回显/404，构成布尔盲注信道 | 布尔结果回显 |  |

**POC**

针对 038.php（GET 路由 /038.php）的 SQL 注入 POC。注入点为 GET 查询参数 id，源码位置 038.php:34，外部输入未经有效净化即进入 SQL 查询汇点（CWE-89）。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/038.php?id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-b7203a166ab9`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

可读取数据库任意数据（含用户口令哈希），并可作为进一步攻击的跳板；布尔盲注可在无回显情况下逐字符提取数据。

**CVE / CWE 论证**

CWE-89。外部 GET 参数直达 SQL 汇点，无认证要求（脚本本身无鉴权逻辑），链路在 CODE PACK 内完整闭合。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param 或 PDO 参数绑定），并对 id 做整型强制转换（(int)$id）。

**验证说明**

需确认 $_DVWA['SQLI_DB'] 实际取值与数据库连接可用性；布尔回显依赖 $exists 分支，动态验证可确认注入生效。
模型 POC 要点：利用 id 参数闭合单引号注入 UNION/布尔条件，通过回显差异判断注入结果。仅限授权测试。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /038.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 038.php:34，外部输入来自 GET 查询参数 id，source→sink 链在给定代码范围内静态闭合，未发现有效净化或参数化查询；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。手工验证时请将 TARGET 替换为已获授权的测试实例地址，并优先使用只读载荷；禁止使用 DROP/TRUNCATE 等破坏性语句。

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
| `sql_injection` | CWE-89 | 是 | 2 |
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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.25 | 是 |
| surface_mapper | 攻击面测绘 | 9.42 | 是 |
| deep_finder | LLM 深挖 | 7.67 | 是 |
| candidate_screener | 候选筛选 | 4.05 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.69 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.29 | 是 |
| coordinator | 管线协调 | 7.06 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
