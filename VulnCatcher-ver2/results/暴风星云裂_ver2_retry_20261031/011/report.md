# 落日二号乙漏洞挖掘报告 — 20261031-001812-fd605c

- 生成时间：2026-10-30T16:18:57.378091+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\011.zip`
- 输入模式：`zip`
- SHA256：`3a159dc6461698f5f7e43da6633e753a69f633ebb87ffaf30a0c927910d78d0e`
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

本次汇总仅包含 1 条已去重发现：011.php 登录接口的 username 参数被直接拼接进 SQL，类型为 sql_injection，严重度 critical，且已附带 POC（HTTP 型，可动态复现路径清晰）。这是本次最高危项，也是唯一交付项。POC 齐全度为 1/1，但该 POC 属静态源码推导产物，尚未做任何动态验证。覆盖面上仅覆盖 PHP 单文件的一次性污点流（注入类），其余攻击面（文件包含/路径穿越、命令执行、配置类弱实现、信任边界）均无 findings 落地，需人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 011.php（1-32 行）。确认第 5 行 $_GET['username'] 未过滤直接拼接进第 12 行 SQL 并在第 13 行 mysqli_query 执行，构成可绕过认证的 SQL 注入（critical，链闭合）；第 21 行 username 未编码回显构成反射型 XSS（medium，需借助 SQL 注入进入成功分支）。password 经 md5() 处理，属 weak_hash 线索但单独不构成可利用链，未单独立项。未发现命令执行、文件包含、SSRF 汇点。无配置文件、无端点清单、无外部 DAST 证据，PHP 版本与 php.ini 设置未知。

未覆盖 / 证据缺口：
- 无 php.ini/Web 服务器配置，无法确认错误回显与 mysqli 扩展行为
- 无 users 表数据证据，恒真绕过需动态确认
- 无外部 AWVS/DAST 证据
- 仓库仅单文件，无法判断调用关系

## 3. Findings

### F-1: 011.php 登录接口 username 参数直接拼接 SQL 导致 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行判断 $_GET['Login'] 存在后，第 5 行直接读取 $_GET['username'] 到 $user，未做任何转义或参数化；第 8-9 行对 password 做了 md5() 处理，但 username 完全未处理；第 12 行将 $user 直接拼接进 SELECT 语句，第 13 行通过 mysqli_query 执行。攻击者可在 username 中注入 SQL 片段，构造恒真条件绕过登录校验（第 15 行 mysqli_num_rows == 1 即视为登录成功），也可通过报错回显（第 13 行 die 输出 mysqli_error）进行报错注入读取数据库内容。

**source / sink**

- source：query `username`（011.php:5）
- sink：011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行拼接后的 SQL

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 判断 $_GET['Login'] 是否设置，作为进入登录逻辑的开关 | 外部请求参数存在性判断 |  |
| 2 | `011.php:5` | 直接读取 $_GET['username'] 赋值给 $user，无任何过滤/转义 | 原始攻击者可控字符串 |  |
| 3 | `011.php:12` | 将 $user 用单引号包裹拼接进 SELECT 语句，未使用预处理或 mysqli_real_escape_string | 注入片段进入 SQL 文本 |  |
| 4 | `011.php:13` | mysqli_query 执行拼接后的 SQL，失败时 die 输出 mysqli_error 造成报错回显 | SQL 被执行，错误信息回显 |  |
| 5 | `011.php:15` | mysqli_num_rows($result)==1 判定登录成功，恒真注入可绕过认证 | 查询结果行数决定认证结果 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username，源码 011.php:13 将该参数直接拼入 SQL 查询，未做参数化或有效转义。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/011.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/011.php?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-c969ca7950b6`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

未认证攻击者可直接绕过登录进入受保护区域，并通过报错注入读取数据库中的用户、密码哈希等敏感数据，可能导致全库数据泄露。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数 username 未经转义直接拼接进 SQL 并由 mysqli_query 执行，链路在单文件内闭合，无需认证即可触发，属典型高危 SQL 注入。

**修复建议**

使用 mysqli 预处理语句（prepare/bind_param）绑定 username 与 password；对输入做类型与长度校验；关闭错误信息回显，避免 die(mysqli_error) 泄露数据库结构。

**验证说明**

需动态确认 users 表存在数据以验证恒真绕过；报错注入依赖 MySQL 版本支持 extractvalue/updatexml。
模型 POC 要点：利用 username 参数注入恒真条件绕过登录，或使用报错注入读取数据库信息。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89。漏洞位于可交付代码 011.php:13，外部输入来自查询参数 username，source→sink 链静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭沙箱。request.http 中 Content-Length 仅对带 body 的请求有意义，GET 无 body 时可省略。执行前须替换 TARGET 并确认授权。

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
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.05 | 是 |
| surface_mapper | 攻击面测绘 | 9.2 | 是 |
| deep_finder | LLM 深挖 | 10.44 | 是 |
| candidate_screener | 候选筛选 | 3.27 | 是 |
| vulnerability_analyzer | 漏洞分析 | 6.07 | 是 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.74 | 是 |
| coordinator | 管线协调 | 6.38 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
