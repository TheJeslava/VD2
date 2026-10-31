# 落日二号乙漏洞挖掘报告 — 20261031-173206-4913d3

- 生成时间：2026-10-31T09:32:55.218948+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\042.zip`
- 输入模式：`zip`
- SHA256：`56c6109a46f6b0f847124698111455904f6d936639464da066a8713062e29119`
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

本次汇总仅包含 1 条已去重 finding：042.php 第 12 行附近、基于 query 参数 id 的 SQL 注入（CWE-89），严重度 critical，来源为规则命中，已附带 POC（HTTP 型，目标以 TARGET 占位，仅限授权测试）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 已具备，但该 POC 属静态构造、未经动态验证，不能宣称可动态复现。其余攻击面（命令执行、路径穿越/文件包含、SSRF、XSS、配置类弱点）在 surface_notes 中被列为待验证方向，均未形成 finding，属覆盖缺口而非“不存在”。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 2271 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 CODE PACK 仅包含单文件 042.php（59 行，DVWA SQL Injection 模块源码），已逐行审计全部 59 行。确认存在一处闭合的 SQL 注入链：POST 参数 id 经 mysqli_real_escape_string 后拼接进数字上下文 SQL 并执行（第 5/7/11/12 行，SQLite 分支第 27/30 行同理）。第 21/43 行将 $id 与查询结果回显到 HTML，理论上存在反射型 XSS，但 $id 已经过 mysqli_real_escape_string 处理（会转义引号与部分字符），且该脚本为 DVWA 教学模块，XSS 证据不足以构成独立 CVE 级发现，故未单独立项。未发现命令执行、文件操作、反序列化、SSRF、弱加密/弱哈希/弱随机、硬编码密钥等其它攻击面证据（文件中无 system/exec、无文件函数、无 md5/sha1、无 setcookie）。输入中未出现诱导性指令文本，未记录 prompt_injection 证据。所有结论为 llm_inferred，未做动态验证。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置证据，无法判断 allow_url_include、open_basedir 等开关
- 无端点清单与路由信息，无法确认脚本实际访问路径与是否需要认证
- 无依赖清单，无法评估第三方库 CVE
- 无部署方式与运行用户信息，无法判断数据库权限边界
- 第 21/43 行 $id 回显的 XSS 风险因转义处理证据不足未单独立项，需人工确认转义是否覆盖所有 XSS 相关字符

## 3. Findings

### F-1: 042.php 基于 query 参数 id 的 SQL 注入（CWE-89）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `rule_verified+llm`
- **位置**：`042.php:10-12`
- **来源**：`rule`

**描述**

攻击者通过 HTTP 请求的 query 参数 `id` 提供输入（042.php:5 读取），该值未经任何类型转换、转义或参数化，直接以字符串拼接方式进入 SQL 语句：042.php:11 构造 `$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`，随后在 042.php:12 由 `mysqli_query($GLOBALS["___mysqli_ston"], $query)` 执行。由于 `$id` 被直接插入到 `user_id = $id` 的数值位置且无引号包裹，攻击者可提交如 `1 UNION SELECT user, password FROM users` 或布尔/时间盲注载荷改变查询语义。代码中未见 mysqli_real_escape_string、intval、预处理语句或白名单校验，校验完全缺失。此外 042.php:12 的 `or die('<pre>' . mysqli_error(...) . '</pre>')` 会把数据库错误信息回显到响应中，为报错注入与结构探测提供便利。

**source / sink**

- source：query `id`（042.php:5）
- sink：042.php:12 $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `042.php:5` | 从 query `id` 读取外部输入 | 污点进入 query |  |
| 2 | `042.php:12` | 危险汇点：$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' ); | 污点进入 sql_injection 汇点 | 未发现有效净化/参数化 |

**POC**

针对 042.php 第 12 行的 SQL 注入 POC（CWE-89），入口路径记为 /042。注入点为 POST 请求体参数 id，被直接拼接进 SQL 查询；请求携带触发按钮字段 Submit=Submit。目标地址统一使用 TARGET 占位符，仅限授权测试。注意：源码文件名为 042.php，若实际路由为 /042.php 而非 /042，需按部署配置修正路径（见 preconditions）。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/042'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X POST 'http://TARGET:8080/042' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'id=%27%20OR%20%271%27%3D%271&Submit=Submit'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/GEN-65bf75938433`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

数据库数据泄露：可读取 users 表之外的任意表（如凭据、口令哈希），并通过 UNION/报错注入将数据回显至页面；在数据库账户权限较高且支持堆叠查询时可能进一步导致数据篡改甚至通过文件写入原语影响服务器。错误信息回显还降低了盲注门槛。

**CVE / CWE 论证**

CWE-89（SQL 命令中特殊元素的不当中和）。外部可达性：注入点为 HTTP query 参数 `id`，无需认证即可访问 042.php 触发；利用链闭合：source（042.php:5 的 `id`）→ 字符串拼接（042.php:11）→ 执行汇点 `mysqli_query`（042.php:12），中间无有效净化，构成完整污点链。证据等级为源码推断（llm_inferred），未做动态验证。

**修复建议**

改用预处理语句与参数绑定：`$stmt = $mysqli->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->bind_param('i', $id); $stmt->execute();`；若必须拼接，先对 `$id` 做严格整数校验（如 `filter_var($id, FILTER_VALIDATE_INT)` 或 `intval`）并拒绝非数字输入；移除向客户端回显的 `mysqli_error` 详细信息，改为记录到服务端日志；数据库账户遵循最小权限，禁用 FILE 权限与堆叠查询。

**验证说明**

静态证据：入口 POST /042；source=query/id；sink=042.php:12；规则 php-sql。未执行 POC、未搭建沙箱；建议在授权环境人工复核。
链叙事：1) 攻击者向 042.php 发送请求，携带 query 参数 `id`（042.php:5 读取，污点进入）。2) 该值未做任何过滤/转义，在 042.php:11 被直接拼入 `SELECT first_name, last_name FROM users WHERE user_id = $id;`。3) 042.php:12 调用 `mysqli_query` 执行拼接后的语句，注入载荷生效；错误分支通过 `mysqli_error` 将数据库报错回显，辅助注入。
PocWriter 建议（未采纳，缺少端点 /042）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 042.php:12，外部输入来自 POST 请求体参数 id，source→sink 链静态闭合，未发现参数化查询或有效转义，具备远程触发条件。
POC 备注：仅文本工件，不执行、不联网。执行前将 TARGET 替换为授权测试实例地址；Content-Length 需按实际请求体字节数调整。入口路径 /042 与源码文件名 042.php 存在差异，需按实际部署确认后再执行。

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
| safety_guard | 安全防护 | 4.02 | 是 |
| surface_mapper | 攻击面测绘 | 11.93 | 是 |
| deep_finder | LLM 深挖 | 9.36 | 是 |
| candidate_screener | 候选筛选 | 3.06 | 是 |
| vulnerability_analyzer | 漏洞分析 | 5.61 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 9.17 | 是 |
| coordinator | 管线协调 | 5.91 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
