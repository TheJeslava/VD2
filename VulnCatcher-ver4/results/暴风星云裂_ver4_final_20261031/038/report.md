# 落日二号乙漏洞挖掘报告 — 20261031-173118-dc6093

- 生成时间：2026-10-31T09:32:04.073823+00:00
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

本次汇总仅含 1 条已去重 finding：038.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89，critical，origin=rule），已附带 POC，属 HTTP 可复现类型。最高危即该条 SQL 注入，为唯一交付项。POC 齐全度：1/1 有 POC，无静态-only 类型交付。二次注入链：输入未提供，无。需注意：surface_notes 明确说明本次输入未提供 038.php 源码正文，仅有文件清单与热点计数（source 热点 3、sink 热点 1），因此该 finding 的行号与参数名无法在本级复核，属规则产出、未经动态验证。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 038.php（57 行，已完整审计 1-57 行）。确认一条闭合的 SQL 注入链：$_GET['id']（第 5 行）→ 字符串拼接（第 11/32 行）→ mysqli_query（第 13 行）/ SQLite query（第 34 行），无任何过滤或参数化，且第 22 行与第 44-53 行的 200/404 差异提供布尔盲注信道。其余攻击面：文件/包含类调用、命令执行、输出型 XSS 在该文件中均未出现（无 include/fopen/system/exec/echo 拼接用户输入），故不报告。配置类线索（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）在本文件中无对应代码（无 md5/sha1、无加密调用、无 setcookie、无 X-Forwarded-* 信任），不成立。未提供 php.ini/部署/认证信息，无法评估 allow_url_include、open_basedir 等对可利用性的影响；未提供 policy 抑制信息，未列出不代表不存在。

未覆盖 / 证据缺口：
- 无端点/路由清单，038.php 对外 URL 与 HTTP 方法需人工确认
- 无 DVWA 配置（$_DVWA['SQLI_DB']）与数据库 schema，无法确认实际走 MYSQL 还是 SQLITE 分支
- 无认证/会话信息，无法确认是否需登录
- 无 php.ini/Web 服务器配置，无法评估 open_basedir、错误回显等运行时条件

## 3. Findings

### F-1: 038.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（038.php:5 读取），该值未经任何过滤、类型转换或参数化，被直接拼接进 SQL 语句：038.php:11 `$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";`，随后在 038.php:13 通过 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 位于单引号字符串字面量内部且未做 `mysqli_real_escape_string` 转义、未使用预处理语句，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询），校验完全缺失。代码注释显示已移除 'or die' 以抑制 MySQL 错误回显，但这只影响报错可见性，不构成任何防护。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 038.php（GET）的 SQL 注入 POC（端点写作 /038）。注入点为 GET 参数 id，源码 038.php:13 将外部输入直接拼入 SQL 查询，未发现有效净化。目标地址统一使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/038'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/038?id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-5bc99d7a2891`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可读取 users 表及其他表的任意数据（如凭据、个人信息）；可进一步通过 UNION/子查询枚举数据库结构；在数据库账户权限较高时可能导致数据篡改或删除。属于机密性与完整性破坏。

**CVE / CWE 论证**

CWE-89（SQL 注入）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问该脚本；利用链闭合：038.php:5 读取参数 → 038.php:11 字符串拼接 → 038.php:13 mysqli_query 执行，全程无净化或参数化，攻击者输入直接控制 SQL 语义。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须动态拼接，至少对 `$id` 做整型强制转换 `(int)$id` 或 `mysqli_real_escape_string` 转义，并对输入做白名单校验；同时遵循最小权限原则，为应用数据库账户仅授予必要的 SELECT 权限，避免使用高权限账户。

**验证说明**

静态证据：入口 GET /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求 `?id=1' OR '1'='1` → 038.php:5 读取 query 参数 `id` 得到污点值 → 038.php:11 将污点值直接插入单引号字符串形成 `SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';` → 038.php:13 mysqli_query 执行被篡改的语句，返回全表数据，注入完成。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 038.php:13，外部输入来自 GET 参数 id，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。所有请求使用 TARGET 占位符，需替换为授权测试目标后手动执行；禁止使用 DROP 等破坏性语句。

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
| safety_guard | 安全防护 | 2.95 | 是 |
| surface_mapper | 攻击面测绘 | 10.14 | 是 |
| deep_finder | LLM 深挖 | 9.76 | 是 |
| candidate_screener | 候选筛选 | 3.34 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.14 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.87 | 是 |
| coordinator | 管线协调 | 7.41 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
