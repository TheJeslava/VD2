# 落日二号乙漏洞挖掘报告 — 20261030-224608-c3ff03

- 生成时间：2026-10-30T14:46:47.815963+00:00
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

本次汇总仅包含 1 条已去重 finding：011.php 登录接口 username 参数 SQL 注入（LLM-c969ca7950b6，critical，llm_finding），污点路径为 011.php 第 3 行附近读取请求参数、第 1 行附近流向查询汇点，路径极短且无中间净化层，属最高危项，可绕过认证。该条已附带 POC（has_poc=true），但 POC 为基于源码推断的静态文本工件，未做动态验证，不能宣称可动态复现。其余攻击面（命令执行、文件包含/路径穿越、反射型 XSS、弱哈希/弱加密/弱随机、不安全 Cookie、信任边界、硬编码凭据）在 surface_notes 中被列为优先复核区，但均未形成 finding，属未覆盖而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1212 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 011.php（1-32 行全部可见）。确认两条闭合链：1) username 参数 SQL 注入（第 5→12→13 行），可绕过认证并读取 users 表，高危；2) 登录成功页 username 反射型 XSS（第 5→21 行），需结合 SQL 注入触发，中危。另注意到第 9 行 md5($pass) 用于口令散列，属 weak_hash（CWE-328），但单独不构成可申报 CVE 的利用链，仅作线索记录；第 13 行 die 回显 mysqli_error 放大了 SQL 注入的信息泄露。未覆盖：无 php.ini/Web 配置，无法确认 allow_url_include、display_errors 等；无路由清单，端点路径按文件名推断为 /011.php；无认证机制信息。

未覆盖 / 证据缺口：
- 缺少 php.ini/服务器配置，无法确认错误回显与安全开关
- 无路由/部署信息，端点路径为推断
- md5 口令散列（weak_hash）未单独立项，仅作线索

## 3. Findings

### F-1: 011.php 登录接口 username 参数 SQL 注入（可绕过认证）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`critical`
- **置信度**：`0.9`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`011.php:5-13`
- **来源**：`llm_finding`

**描述**

011.php 第 3 行通过 $_GET['Login'] 触发登录逻辑，第 5 行直接读取 $_GET['username'] 到 $user，未做任何转义/参数化；第 12 行将 $user 直接拼接进 SQL 语句 "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"，第 13 行 mysqli_query 执行。攻击者可在 username 中注入闭合单引号并构造恒真条件，绕过密码校验以任意已知用户（如 admin）身份登录，或通过报错注入/联合查询读取 users 表全部数据（含口令散列）。

**source / sink**

- source：query `username`（011.php）
- sink：011.php:13 011.php:13 mysqli_query($GLOBALS["___mysqli_ston"], $query)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `011.php:3` | 检测到 $_GET['Login'] 存在即进入登录分支 | 攻击者控制请求参数存在性 |  |
| 2 | `011.php:5` | 将 $_GET['username'] 原样赋给 $user，无过滤 | 原始字符串，未转义 |  |
| 3 | `011.php:12` | 字符串拼接构造 SQL，$user 位于单引号内 | 注入 payload 进入 SQL 文本 |  |
| 4 | `011.php:13` | mysqli_query 执行拼接后的 SQL，错误信息经 die 回显 | SQL 被执行，可返回任意行 |  |

**POC**

针对 /011.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username，该参数在 011.php:13 处被直接拼接进 SQL 查询，未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

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
- 执行状态：未执行（`executed=False`）

**影响**

未授权攻击者可绕过登录认证进入受保护区域，并可读取 users 表全部记录（用户名与 MD5 口令散列），为进一步爆破/横向移动提供条件。

**CVE / CWE 论证**

CWE-89。外部 GET 参数 username 未经参数化直接拼接进 SQL 并由 mysqli_query 执行，链路在单个文件内闭合，无需认证即可触发。

**修复建议**

使用 mysqli 预处理语句（prepare + bind_param）或 PDO 参数化查询；对输入做类型/白名单校验；关闭 die(mysqli_error) 的详细错误回显。

**验证说明**

需在授权环境确认 users 表存在 admin 记录及 mysqli 连接可用；报错注入是否回显取决于 display_errors 与 die 分支。
模型 POC 要点：利用 username 注入恒真条件绕过密码校验，以 admin 身份登录；同时可借助 die 回显的 mysqli_error 做报错注入读取数据。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /011.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 011.php:13，外部输入来自 GET 查询参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留输入中确定性 POC 的请求结构，仅补充说明与预期结果。poc.sh 与 request.http 为文本参考，不自动执行；目标地址统一使用 TARGET 占位符；仅限授权测试。

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
| safety_guard | 安全防护 | 3.44 | 是 |
| surface_mapper | 攻击面测绘 | 10.65 | 是 |
| deep_finder | LLM 深挖 | 11.06 | 是 |
| candidate_screener | 候选筛选 | 3.29 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.11 | 是 |
| coordinator | 管线协调 | 6.45 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
