# 落日二号乙漏洞挖掘报告 — 20261031-014231-f1505b

- 生成时间：2026-10-30T17:43:14.637674+00:00
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

本次汇总仅含 1 条已去重 finding：038.php 第 13 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，可动态复现，仅限授权测试）。最高危即此条，也是唯一交付项。POC 齐全度：1/1 有 POC，无缺失。二次注入链：输入未提供任何二次注入链，故不涉及存储写点/读点/汇点三要素的判定。需说明：本次审计范围严格限定为 code_pack 中的 038.php（57 行、约 1.4KB、无框架无路由），surface_notes 中列出的文件包含/路径穿越、命令执行、弱哈希/弱加密/弱随机/Cookie 标志、信任边界等攻击面均未形成 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1722 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅含单文件 038.php（57 行，DVWA SQL Injection 页面）。已完整审计该文件：入口为第 3 行 `isset($_GET['Submit'])`，source 为第 5 行 `$_GET['id']`，sink 为第 13 行 mysqli_query 与第 34 行 SQLite query，两处均为字符串拼接 SQL，构成闭合的 SQL 注入链，已作为唯一 finding 交付。其余攻击面：文件包含/命令执行/反序列化/SSRF 在该文件中均不存在；weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 等配置型候选经核对未出现（无 md5/sha1、无 rand 令牌、无 setcookie、无 X-Forwarded-* 信任）。第 49 行使用 $_SERVER['SERVER_PROTOCOL'] 仅用于设置状态行，非鉴权/跳转判断，不构成信任边界漏洞。未发现 prompt_injection 诱导文本。未覆盖范围：无 php.ini/Web 服务器配置、无路由与认证信息、无依赖清单，无法确认部署暴露面与数据库实际配置。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认 allow_url_include、open_basedir 等
- 无端点/路由与认证信息，无法确认实际访问路径与是否公网暴露
- 无数据库配置，无法确认 $_DVWA['SQLI_DB'] 实际取值与连接可用性
- 无依赖清单与 PHP 版本信息

## 3. Findings

### F-1: 038.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.83`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`038.php:11-13`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入，该值在 038.php:5 被读入变量 $id，随后在 038.php:11 被直接字符串拼接进 SQL 语句：$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";，未做任何类型转换、转义或参数化处理。038.php:12-13 将该拼接后的 $query 交给 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行。由于 $id 被包裹在单引号内且未经过 mysqli_real_escape_string 或预处理语句绑定，攻击者可闭合单引号注入任意 SQL 片段（如 `1' OR '1'='1` 或 UNION 查询），校验完全缺失，污点从 source 到 sink 链路闭合。

**source / sink**

- source：query `id`（038.php:5）
- sink：038.php:13 $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `038.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `038.php:13` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 038.php 的 SQL 注入 POC（路由写作 /038，方法标注为 ANY）。注入点为查询参数 id，源码 038.php:13 直接拼接该参数。注意：源码文件名为 038.php，实际请求路径应以部署配置为准，此处保留输入给出的 /038 结构；payload 使用 TARGET 占位符，仅限授权测试。

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

可读取 users 表全部数据（first_name、last_name 及通过 UNION 扩展的任意表/列），造成敏感数据泄露；结合数据库权限还可能读取系统信息或进一步扩大影响。属于未认证即可远程触发的数据泄露类漏洞。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 038.php 触发；利用链闭合：038.php:5 读取参数 → 038.php:11 字符串拼接 → 038.php:13 mysqli_query 执行，中间无有效净化，满足远程未认证 SQL 注入的判定条件。

**修复建议**

改用预处理语句与参数绑定：$stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?"); $stmt->bind_param("i", $id); $stmt->execute();。若必须拼接，至少对 $id 做整型强制转换 (int)$id 或使用 mysqli_real_escape_string 转义，并遵循最小数据库权限原则，避免应用账户具备跨库读取权限。

**验证说明**

静态证据：入口 ANY /038；source=query/id；sink=038.php:13；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：攻击者构造请求参数 id=1' OR '1'='1，038.php:5 将其读入 $id；038.php:11 直接拼入 WHERE user_id = '$id' 形成 `WHERE user_id = '1' OR '1'='1'`；038.php:13 通过 mysqli_query 执行，条件恒真返回全部用户记录，实现数据泄露。
PocWriter 建议（未采纳，缺少端点 /038）：符合 CWE-89。漏洞位于 038.php:13，外部输入来自查询参数 id，source→sink 链在给定代码范围内静态闭合，未见有效净化。证据等级：llm_inferred（静态推断，未动态验证）。
POC 备注：POC 仅为文本工件，不执行、不联网。输入中方法标注为 ANY，实际测试建议使用 GET（查询参数注入）；执行前须将 TARGET 替换为授权目标，禁止用于未授权系统。

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
| safety_guard | 安全防护 | 3.18 | 是 |
| surface_mapper | 攻击面测绘 | 10.28 | 是 |
| deep_finder | LLM 深挖 | 8.01 | 是 |
| candidate_screener | 候选筛选 | 2.78 | 是 |
| vulnerability_analyzer | 漏洞分析 | 4.42 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.32 | 是 |
| coordinator | 管线协调 | 6.68 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
