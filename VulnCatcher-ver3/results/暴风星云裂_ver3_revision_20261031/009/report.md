# 落日二号乙漏洞挖掘报告 — 20261031-011446-3938c6

- 生成时间：2026-10-30T17:15:34.878760+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次汇总基于单文件 PHP 脚本 009.php（79 行）的源码审计结果，共交付 3 条去重后的发现，全部为 sql_injection（CWE-89），严重度均为 critical，且 3 条均附带 POC 文本（静态构造，未执行、未动态验证）。最高危的是 009.php 中由请求参数直接拼接进 SQL 语句形成的注入链：用户存在性检查（约第 22 行）、用户信息查询（约第 29 行）、日志写入（约第 73 行）三处汇点，源码层面未见预处理语句或转义证据，属可直接利用的高危面。POC 齐全度为 3/3，但均为 HTTP 型 POC 文本（TARGET 占位，仅限授权测试），尚未经任何动态复现。配置类面（weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary）在本次输入中仅有攻击面测绘提示，未形成 findings，需人工按代码与会话语义复核。

共 **3** 条 finding；**3** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：仅审计 009.php 第 1-61 行（code_pack 截断至 61 行，共 79 行，62-79 行未提供）。发现第 21/28 行 SQL 拼接，但第 14 行数字正则对 user_id 做了强校验，非数字输入被拒，注入链未闭合，故不作为 finding 交付。第 26 行 token 硬编码 'user_token' 属弱访问控制，但仅影响资料查看，未形成越权读取敏感数据（资料本身为公开字段），不单独立项。第 7 行 dvwaCurrentUser() 拼接进 SQL，但该函数返回值来源未在 code_pack 中，无法确认可控。第 33-40 行将数据库字段回显到 HTML，若 first_name/last_name/avatar 含 XSS payload 则为存储型 XSS，但写入点不在 code_pack 内，链未闭合。未发现命令执行、文件包含、反序列化、SSRF 汇点。配置类（weak_hash/weak_crypto/weak_random/insecure_cookie）在可见 61 行内未出现。

未覆盖 / 证据缺口：
- 009.php 第 62-79 行未提供
- dvwaCurrentUser() 实现未知
- users 表写入点未知，存储型 XSS 链未闭合
- 无部署/鉴权信息

## 3. Findings

### F-1: 009.php 用户存在性检查 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:20-22`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求参数 user_id 输入（009.php:17 读取 query `user_id` 到变量 $id），该值未经任何转义或参数化即被拼接进 SQL 字符串：009.php:21 `$check_query = "SELECT user_id FROM users WHERE user_id = '$id'"`，随后在 009.php:22 通过 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 执行。由于 $id 被直接放入单引号字符串字面量内，攻击者可闭合引号并注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询），校验无效的原因是代码仅做了字符串拼接，未使用 mysqli_real_escape_string、预处理语句或类型强制转换（如 intval）。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:22 $check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 check_query |  |
| 2 | `009.php:22` | 危险汇点：$check_result = mysqli_query($GLOBALS["___mysqli_ston"], $check_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-769728152047`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库查询逻辑被完全控制：可绕过用户存在性判断、通过 UNION 读取 users 表及其他表的任意数据（口令哈希、个人信息），并可结合堆叠/报错注入进一步获取数据库结构，造成敏感数据泄露与认证逻辑绕过。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP 请求参数 user_id，属于远程可访问入口；无需认证即可触发该查询路径；利用链闭合：source（009.php:17 的 user_id）→ 拼接（009.php:21）→ 危险汇点 mysqli_query（009.php:22），中间无有效净化，攻击者输入可直接改变 SQL 语义。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT user_id FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须使用字符串拼接，至少对 $id 做 intval 强制类型转换或 mysqli_real_escape_string 转义，并对 user_id 做数字白名单校验；同时为数据库账户配置最小权限。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:22；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求参数 user_id=1' OR '1'='1，009.php:17 读取该参数到 $id；009.php:21 将 $id 拼入 `SELECT user_id FROM users WHERE user_id = '$id'`，形成 `WHERE user_id = '1' OR '1'='1'`；009.php:22 执行该查询，条件恒真，用户存在性检查被绕过，后续逻辑基于伪造的查询结果继续执行。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 22 行 SQL 注入汇点的 POC。注入通道为 HTTP 查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。外部输入来自查询参数 user_id，在 009.php:22 处进入 SQL 语句，静态链路闭合且未见有效净化。
POC 备注：仅文本工件，不执行、不联网；替换 TARGET 后由授权人员手动验证。

### F-2: 009.php 用户信息查询 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:27-29`
- **来源**：`rule`

**描述**

同一外部输入 user_id（009.php:17 读取到 $id）在通过存在性检查后，被再次拼接进第二条 SQL：009.php:28 `$query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = '$id';"`，并在 009.php:29 由 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。$id 仍处于单引号字面量内且未转义，攻击者可闭合引号注入 UNION SELECT 等语句，直接控制返回的列数据。校验无效的原因与上一条一致：无参数化、无转义、无类型约束。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:29 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 query |  |
| 2 | `009.php:29` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-1f0233ec126f`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可读取 users 表任意列（first_name、last_name、avatar 等）乃至通过 UNION 读取其他表数据，导致用户个人信息泄露；返回结果还会被后续页面逻辑使用，可能进一步影响展示与业务判断。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入源为 HTTP 参数 user_id，远程可达；无需认证；利用链闭合：source（009.php:17）→ 拼接（009.php:28）→ 汇点 mysqli_query（009.php:29），无有效净化。

**修复建议**

使用预处理语句绑定参数（bind_param('i', $id)）；对 user_id 做整数强制转换与白名单校验；禁止将外部输入直接拼入 SQL；数据库账户遵循最小权限原则。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:29；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者提交 user_id=1' UNION SELECT username,password,1,1 FROM users-- -；009.php:17 读取到 $id；009.php:28 拼接为 `... WHERE user_id = '1' UNION SELECT username,password,1,1 FROM users-- -'`；009.php:29 执行后返回攻击者指定的列数据，实现数据窃取。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 29 行 SQL 注入汇点的 POC。注入通道为 HTTP 查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。外部输入来自查询参数 user_id，在 009.php:29 处进入 SQL 语句，静态链路闭合且未见有效净化。
POC 备注：仅文本工件，不执行、不联网；替换 TARGET 后由授权人员手动验证。

### F-3: 009.php 日志写入 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.63`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`009.php:71-73`
- **来源**：`rule`

**描述**

009.php:71-72 构造日志插入语句 `INSERT INTO bac_log (user_id, target_id, ip_address) VALUES ({$current_user_id}, {$target_id}, '{$ip}')`，其中 {$current_user_id} 与 {$target_id} 以无引号形式直接拼接，'{$ip}' 以单引号包裹但未转义，随后在 009.php:73 由 mysqli_query($GLOBALS["___mysqli_ston"], $log_query) 执行。候选标注的 source 为 query `user_id`（009.php:17），该输入经业务逻辑流转到 $current_user_id/$target_id 等变量后进入日志语句；由于这些值均未做类型转换或转义，攻击者可注入任意 SQL。校验无效的原因是拼接式构造且无参数化。

**source / sink**

- source：query `user_id`（009.php:17）
- sink：009.php:73 mysqli_query($GLOBALS["___mysqli_ston"], $log_query);

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:17` | 从 query `user_id` 读取外部输入 | 污点进入 log_query |  |
| 2 | `009.php:73` | 危险汇点：mysqli_query($GLOBALS["___mysqli_ston"], $log_query); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 /009（ANY）的 SQL 注入 POC。注入点：ANY 参数 user_id；payload 使用 TARGET 占位符。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X ANY 'http://TARGET:8080/009?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-07807b8ead6b`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可向日志表写入任意数据或通过注入改变 INSERT 语义，造成数据污染、日志伪造，并可能借助报错/堆叠注入进一步探测或篡改数据库内容。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入源为 HTTP 参数 user_id，远程可达；无需认证；利用链闭合：source（009.php:17）→ 变量流转至 $current_user_id/$target_id/$ip → 拼接（009.php:71-72）→ 汇点 mysqli_query（009.php:73）。注意：本候选置信度较低（0.63），$current_user_id/$target_id 的具体赋值位置未在给定片段中展示，变量流转细节属推断。

**修复建议**

使用预处理语句绑定 user_id、target_id、ip_address 三个参数；对 user_id/target_id 做整数强制转换，对 $ip 使用 mysqli_real_escape_string 或参数绑定；对 IP 来源做格式校验（如 filter_var FILTER_VALIDATE_IP）。

**验证说明**

静态证据：入口 ANY /009；source=query/user_id；sink=009.php:73；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者通过 user_id 参数注入恶意片段，该值经业务逻辑赋给 $current_user_id 或 $target_id；009.php:71-72 将其无引号拼入 INSERT 语句；009.php:73 执行后写入被篡改的日志记录或触发注入副作用。由于赋值链未在片段中完整呈现，此链条为基于源码的推断。
PocWriter 建议（未采纳，缺少端点 /009）：针对 009.php 第 73 行 SQL 注入汇点的 POC。注入通道为 HTTP 查询参数 user_id，payload 使用 TARGET 占位符，仅限授权测试。
PocWriter 建议（未采纳，缺少端点 /009）：符合 CWE-89。外部输入来自查询参数 user_id，在 009.php:73 处进入 SQL 语句，静态链路闭合且未见有效净化。
POC 备注：仅文本工件，不执行、不联网；替换 TARGET 后由授权人员手动验证。

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
| `sql_injection` | CWE-89 | 是 | 3 |
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
| safety_guard | 安全防护 | 2.46 | 是 |
| surface_mapper | 攻击面测绘 | 10.75 | 是 |
| deep_finder | LLM 深挖 | 7.75 | 是 |
| candidate_screener | 候选筛选 | 4.8 | 是 |
| vulnerability_analyzer | 漏洞分析 | 10.08 | 是 |
| second_order_analyzer | 二次注入分析 | 0.01 | 否 |
| poc_writer | POC 生成 | 6.19 | 是 |
| coordinator | 管线协调 | 6.34 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
