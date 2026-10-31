# 落日二号乙漏洞挖掘报告 — 20261030-224559-fb9bd5

- 生成时间：2026-10-30T14:46:36.796955+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\009.zip`
- 输入模式：`zip`
- SHA256：`541554841eafd869888c6f913c00fe17c4ae258598cf3ee74def3c3f80990814`
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

本次仅覆盖单个 PHP 文件 009.php（79 行，无框架、无路由配置），交付 1 条高危发现：LLM-a078cd46dacc，009.php 第 29 行附近 user_id 参数 SQL 注入，且 token 硬编码可绕过，已附 POC（HTTP 型，仅限授权测试，目标用 TARGET 占位）。这是本次唯一交付项，也是最高危项。POC 齐全度：1/1 有 POC，但均为静态源码推断（llm_inferred），未做动态验证。其余攻击面（命令执行、路径穿越/文件包含、反射型 XSS、弱哈希/弱加密/弱随机、Cookie 标志、信任边界、硬编码凭据）在 surface_notes 中被列为待核查优先级，但未形成 findings，需人工打开文件确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 3211 字符；截断 0 个
- 模型新增候选：1 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次仅送入 009.php 前 61 行（共 79 行，第 62-79 行未覆盖）。已审计入口（第 13 行 $_GET 取参）、token 校验（第 26 行硬编码 'user_token'）、SQL 拼接汇点（第 21、28 行 mysqli_query）。发现一条闭合的 SQL 注入链：user_id 经弱正则校验后直接拼接执行，token 硬编码可绕过。第 7 行 dvwaCurrentUser() 拼接亦为潜在注入点，但其返回值来源不在 code_pack 内，未闭合，未单独立项。第 33-40 行将数据库字段回显到 HTML，若 avatar/first_name 含恶意内容可构成存储型 XSS，但写入点不在 code_pack 内，未闭合。第 50-61 行日志表创建逻辑未涉及外部可控输入。未发现命令执行、文件包含、反序列化汇点。

未覆盖 / 证据缺口：
- 009.php 第 62-79 行未送入，日志写入逻辑（bac_log 插入）未审计
- dvwaCurrentUser() 实现不在 code_pack，第 7 行注入点无法闭合
- avatar/first_name 的写入点不在 code_pack，存储型 XSS 无法确认
- 无认证/会话代码，无法判断脚本是否位于鉴权之后
- 无 php.ini/部署配置，无法确认运行环境

## 3. Findings

### F-1: DVWA 009.php 用户资料查询 user_id 参数 SQL 注入（token 硬编码可绕过）

- **类型**：`sql_injection` / CWE-89
- **严重度**：`high`
- **置信度**：`0.4`
- **结论**：`candidate` / 证据等级 `llm_inferred`
- **位置**：`009.php:13-29`
- **来源**：`llm_finding`

**描述**

009.php 第 13-17 行从 $_GET['user_id'] 取参，仅用 preg_match('/^\d+$/') 做纯数字校验；第 21 行将 $id 直接拼接进 SELECT 语句并 mysqli_query 执行，第 28 行再次拼接执行。虽然第 14 行有数字白名单，但第 26 行的 token 校验使用硬编码字符串 'user_token'（源码注释亦提示不安全），攻击者可直接携带 token=user_token 通过。由于第 14 行正则要求纯数字，普通字符串注入被阻断，但 MySQL 在数字上下文中会把 '1 OR 1=1' 之类解析为表达式，且更关键的是第 21 行 $id 未做 mysqli_real_escape_string/参数化，纯数字约束下仍可通过布尔/时间盲注（如 1 AND SLEEP(5)、1 AND (SELECT ...)）实施注入，读取 users 表任意数据。

**source / sink**

- source：query `user_id`（009.php）
- sink：009.php:29 mysqli_query($GLOBALS["___mysqli_ston"], $check_query) 与 mysqli_query(..., $query)（第 22、29 行）

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `009.php:13` | 入口判断 action 与 user_id 是否设置 | 原始 GET 参数 |  |
| 2 | `009.php:14` | preg_match('/^\d+$/') 仅允许纯数字，构成弱防护 | 字符串经正则校验 | 纯数字仍可在 SQL 数字上下文构造布尔/时间盲注表达式，且 token 校验为硬编码可绕过 |
| 3 | `009.php:17` | $id 赋值 | $id = $_GET['user_id'] |  |
| 4 | `009.php:21` | 拼接进 SELECT 语句 | 字符串拼接进 SQL |  |
| 5 | `009.php:22` | mysqli_query 执行 | SQL 执行 |  |
| 6 | `009.php:26` | token 硬编码校验 'user_token'，可被直接满足 | 攻击者提供 token=user_token | 硬编码常量，非秘密 |
| 7 | `009.php:28` | 再次拼接 $id 执行查询 | SQL 执行 |  |

**POC**

针对 /009.php（GET）的 SQL 注入 POC。注入点为 GET 参数 user_id，该参数值被直接拼接到 SQL 查询中（009.php:29），未做有效净化。payload 使用 TARGET 占位符，仅限授权测试。

1. **确认目标可达且已获授权**

```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 SQL 注入 载荷**

```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?user_id=%27%20OR%20%271%27%3D%271'
```
预期：布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**
预期：出现与基线不同的内容、状态码、延迟或副作用

- payload：`' OR '1'='1`
- POC 目录：`poc/LLM-a078cd46dacc`
- 执行状态：未执行（`executed=False`）

**影响**

攻击者可绕过 token 校验并注入 SQL，读取 users 表任意用户资料（姓名、头像等），进一步可枚举数据库内容。

**CVE / CWE 论证**

CWE-89。外部 GET 可达，token 为硬编码可绕过，source→sink 链在 009.php 内闭合。

**修复建议**

使用预处理语句（mysqli_prepare/bind_param）替代字符串拼接；移除硬编码 token，改用服务端会话与随机令牌；对 user_id 做 intval 强类型转换。

**验证说明**

需确认 MySQL 对纯数字正则下注入表达式的实际解析行为，以及 users 表结构；token 硬编码绕过已由源码直接确认。
模型 POC 要点：携带硬编码 token 与数字型盲注 payload 访问 009.php，观察响应差异/延时
LLM 深挖（AutoCVE Finding 风格）：单次调用、无工具；文件与行号已校验，代码片段由真实源码回填。
PocWriter 建议（未采纳，缺少端点 /009.php）：符合 CWE-89（SQL 注入）。漏洞位于 009.php:29，外部输入来自 GET 参数 user_id，source→sink 链在给定代码范围内静态闭合，未发现有效净化；具备远程触发条件。证据等级：llm_inferred（基于源码推断，未做动态验证）。
POC 备注：POC 仅为文本工件，管线不执行、不联网、不搭建沙箱。所有请求中的目标统一为 TARGET:8080 占位符，执行前需替换为授权测试目标。禁止使用 DROP 等破坏性语句；建议仅使用布尔/时间盲注等非破坏性验证方式。

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
| safety_guard | 安全防护 | 3.64 | 是 |
| surface_mapper | 攻击面测绘 | 10.34 | 是 |
| deep_finder | LLM 深挖 | 8.75 | 是 |
| candidate_screener | 候选筛选 | 3.46 | 是 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 4.24 | 是 |
| coordinator | 管线协调 | 6.55 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
