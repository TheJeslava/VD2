# 落日二号乙漏洞挖掘报告 — 20261030-224634-0fb0f8

- 生成时间：2026-10-30T14:47:09.525864+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\012.zip`
- 输入模式：`zip`
- SHA256：`7d0f14e9e50a789482797f77e065c290c2d802a158b47977aa68ab1f199bfbd3`
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

本次汇总仅含 1 条已去重 finding：012.php 登录接口 username 参数在经 mysqli_real_escape_string 处理后仍被拼接进 SQL，判定为 sql_injection（high，LLM-0f1e01503c6f），且已附带 POC（has_poc=true，属 HTTP 型 POC 文本，未做动态验证）。最高危即此条，也是唯一交付项。POC 齐全度为 1/1，但仅为静态构造文本，未经执行验证。整体攻击面极小且集中：单文件 PHP 脚本（35 行），无框架、无路由、无端点清单，入口即脚本本身。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1830 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 012.php 全部 35 行。发现 username 参数经 mysqli_real_escape_string 后拼接进 SQL（宽字节绕过风险）与登录成功后的反射型 XSS。password 经 md5 处理属 weak_hash 线索但未形成独立可利用链，未单列。未提供部署/字符集/认证信息，SQL 注入置信度受字符集条件限制。

未覆盖 / 证据缺口：
- 数据库连接字符集未知，宽字节注入需确认
- 无部署与认证配置
- 无端点清单

## 3. Findings

### F-1: 012.php 登录接口 username 参数经 mysqli_real_escape_string 后仍拼接进 SQL 导致注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`012.php:5-15`
- **来源**：`llm_finding`

**描述**

012.php 第 3 行判断 $_GET['Login'] 存在即进入登录逻辑；第 5 行从 $_GET['username'] 取用户输入，第 6 行调用 mysqli_real_escape_string 转义，第 14 行将 $user 直接拼接进 SELECT 语句，第 15 行 mysqli_query 执行。转义函数本身依赖连接字符集（$GLOBALS['___mysqli_ston']），在 GBK 等宽字节字符集下可被 %df%27 类宽字节注入绕过；同时第 9-11 行 password 被 md5 处理，但 username 未做参数化，仍构成注入点。攻击者可通过构造 username 闭合引号，绕过登录校验或读取 users 表数据。

**source / sink**

- source：query `username`（012.php:5）
- sink：012.php:15 mysqli_query($GLOBALS["___mysqli_ston"], $query) 执行拼接后的 SELECT

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `012.php:3` | 判断 $_GET['Login'] 存在，进入登录分支 | 外部请求进入 |  |
| 2 | `012.php:5` | 读取 $_GET['username'] 到 $user | 原始用户输入 |  |
| 3 | `012.php:6` | mysqli_real_escape_string 转义，但依赖连接字符集，宽字节字符集下可绕过 | 转义后字符串 | 宽字节（GBK）字符集下 %df%27 可吃掉反斜杠，转义失效 |
| 4 | `012.php:14` | $user 拼接进 SELECT 语句 | SQL 片段 |  |
| 5 | `012.php:15` | mysqli_query 执行拼接 SQL | 执行 |  |

**POC**

针对 /012.php（GET）的 SQL 注入 POC。注入点为 GET 参数 username（源码 012.php:15 将该参数拼入 SQL 查询，未做有效净化），payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/012.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/012.php?username=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-0f1e01503c6f`
- 执行状态：未执行（`executed=False`）

**影响**

绕过登录认证、读取 users 表数据（含口令哈希与 avatar）

**CVE / CWE 论证**

CWE-89：外部 GET 参数直达 SQL 拼接，转义依赖字符集可被宽字节绕过，无需认证即可触发

**修复建议**

使用预处理语句（mysqli_prepare/bind_param）替代字符串拼接，并显式设置连接字符集为 utf8mb4

**验证说明**

需确认数据库连接字符集；若为 utf8mb4 则宽字节绕过不成立，需另找转义绕过条件
模型 POC 要点：通过 username 参数注入，闭合单引号绕过登录或读取数据
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /012.php）：符合 CWE-89。漏洞位于可交付代码 012.php:15，外部输入来自 query 参数 username，source→sink 链已静态闭合，未发现有效净化，具备远程触发条件。
POC 备注：保留原确定性 POC 的请求结构（GET /012.php?username=%27%20OR%20%271%27%3D%271），仅补充说明与预期结果。目标统一使用 TARGET 占位符；POC 仅为文本工件，不执行、不联网、不搭建沙箱，仅限授权测试。

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
| safety_guard | 安全防护 | 3.81 | 是 |
| surface_mapper | 攻击面测绘 | 8.93 | 是 |
| deep_finder | LLM 深挖 | 8.68 | 是 |
| candidate_screener | 候选筛选 | 4.03 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.06 | 是 |
| coordinator | 管线协调 | 5.79 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
