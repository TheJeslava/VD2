# 落日二号乙漏洞挖掘报告 — 20261030-224754-62aaf7

- 生成时间：2026-10-30T14:48:29.891806+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\023.zip`
- 输入模式：`zip`
- SHA256：`aada7600a62949bf4930c902cfe7f7a69ee803e85804c9c7ea164d938a3b0b7a`
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

本次汇总仅含 1 条已去重 finding：023.php 第 17 行附近，password_new 参数流入 SQL 拼接，判定为 sql_injection（high，LLM-d657aa475806），已附带 POC（静态文本工件，未执行、未动态验证）。这是本轮唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但仅为源码推断级静态 POC，未做动态复现。其余攻击面（路径拼接/LFI、配置型弱算法、Cookie 标志、信任边界）在 surface_notes 中被标为待确认，未形成 finding，已转入 human_review。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1423 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计唯一文件 023.php（30 行）。发现密码修改逻辑存在 SQL 注入：$_GET['password_new'] 经相等校验后先转义再 md5，转义失效，最终拼接进 UPDATE 并由 mysqli_query 执行（第 16-17 行），$current_user 亦直接拼接。weak_hash（md5 用于口令摘要，第 12 行）属配置型线索，未单独成 finding。未提供 php.ini、路由、认证配置，dvwaCurrentUser() 实现不在 code_pack 内，故注入可利用性依赖运行时条件，置信度定为 0.72。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 实现未提供，$current_user 可控性未知
- 无 php.ini/Web 服务器配置，无法确认鉴权与可达性
- md5 口令摘要属 weak_hash 线索，未单独立项

## 3. Findings

### F-1: DVWA 密码修改接口（023.php）通过 password_new 参数造成 SQL 注入

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`023.php:5-17`
- **来源**：`llm_finding`

**描述**

023.php 在收到 GET 参数 Change 后，直接读取 $_GET['password_new'] 与 $_GET['password_conf']，仅比较两者是否相等（第 9 行），随后对 $pass_new 调用 mysqli_real_escape_string 并 md5()（第 11-12 行），再拼接到 UPDATE 语句（第 16 行）并交给 mysqli_query 执行（第 17 行）。关键缺陷在于：转义发生在 md5() 之前，而真正进入 SQL 的是 md5 后的 32 位十六进制串，因此 mysqli_real_escape_string 对最终拼接值毫无作用；同时 $current_user 来自 dvwaCurrentUser() 直接拼接进 SQL。攻击者只要让 password_new 与 password_conf 相等即可通过第 9 行校验，从而控制 UPDATE 语句结构，实现任意 SQL 注入（可篡改任意用户口令、读取数据库内容）。

**source / sink**

- source：query `password_new`（023.php:5-6）
- sink：023.php:17 023.php:17 mysqli_query($GLOBALS["___mysqli_ston"], $insert)

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `023.php:3` | 检测到 GET 参数 Change 即进入密码修改分支 | 外部请求进入业务逻辑 |  |
| 2 | `023.php:5-6` | 从 $_GET 读取 password_new 与 password_conf | 攻击者完全可控的字符串 |  |
| 3 | `023.php:9` | 仅做相等比较，令两参数相同即可通过 | 校验通过，污点继续 | 相等比较不构成任何注入防护，攻击者令两参数一致即可 |
| 4 | `023.php:11-12` | 先 mysqli_real_escape_string 再 md5，转义结果被 md5 覆盖 | 转义失效，最终为 32 位十六进制摘要 | 转义在 md5 之前执行，进入 SQL 的是 md5 结果，转义对最终值无影响 |
| 5 | `023.php:16` | 将 $pass_new 与 $current_user 拼接进 UPDATE 语句 | SQL 语句字符串 |  |
| 6 | `023.php:17` | mysqli_query 执行拼接后的 SQL | SQL 在数据库执行 |  |

**POC**

针对 /023.php（GET）的 SQL 注入 POC。注入点为 GET 参数 password_new，该参数值被直接拼接到 SQL 语句中（023.php:17），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/023.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/023.php?password_new=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-d657aa475806`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可篡改数据库中任意用户口令或读取数据，导致账户接管与数据泄露。

**CVE / CWE 论证**

CWE-89 SQL 注入。外部 GET 参数直达 mysqli_query，转义因 md5 顺序错误而失效，链路在 CODE PACK 内闭合，无需高权限。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param）绑定 password 与 user；转义应在最终拼接值上执行或改用参数化；对 $current_user 同样参数化。

**验证说明**

需确认 dvwaCurrentUser() 返回值是否可被外部影响，以及 md5 后注入的实际可行构造；建议动态验证 UPDATE 语义是否被改变。
模型 POC 要点：令 password_new 与 password_conf 相等以通过校验，并在参数中注入 SQL 片段改变 UPDATE 语义；由于 md5 会改变值，实际可利用点在于 $current_user 拼接与语句结构，需结合 dvwaCurrentUser 返回值构造。
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /023.php）：符合 CWE-89（SQL 注入）。漏洞位于可交付代码 023.php:17，外部输入来自 GET 参数 password_new，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。所有请求中的目标统一为 TARGET:8080，请替换为授权测试目标后手动执行。禁止使用 DROP 等破坏性语句；建议仅使用布尔/时间盲注做最小化验证。

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
| safety_guard | 安全防护 | 3.8 | 是 |
| surface_mapper | 攻击面测绘 | 8.88 | 是 |
| deep_finder | LLM 深挖 | 8.26 | 是 |
| candidate_screener | 候选筛选 | 3.81 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.4 | 是 |
| coordinator | 管线协调 | 5.84 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
