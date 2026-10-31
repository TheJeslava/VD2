# 落日二号乙漏洞挖掘报告 — 20261031-214958-6e2651

- 生成时间：2026-10-31T13:50:28.262687+00:00
- 输入：`$WORKSPACE\暴风星云裂\049.zip`
- 输入模式：`zip`
- SHA256：`275c9aa49fd32c5baf3a69c1b9199d20f6edf4b8d28cdf1a0598ae6adf1e2b16`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

共发现 1 条候选 finding，覆盖 1 种漏洞类型；1 条已生成 POC。管线未执行 POC、未搭建沙箱，所有结论均为 candidate，需人工/授权环境复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 480 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单文件 049.php（20 行，已完整展示 1-20 行）。审计结论：该脚本唯一外部输入为 $_GET['default']（第 4 行 array_key_exists 检查、第 7 行 switch 读取），随后进入 switch 白名单分支（French/English/German/Spanish），命中则 break，未命中则执行 header("location: ?default=English") 并 exit（第 14-16 行）。该值从未被拼接进 SQL、命令、文件路径、include/require、模板或 HTML 输出，不存在 source→sink 污点链；header 的 Location 值为硬编码常量，不构成开放重定向。脚本无认证、会话、Cookie、加密、反序列化、文件操作或命令执行代码，因此无 sql_injection / command_injection / path_traversal / xss / ssrf / deserialization / weak_crypto 等可申报候选。surface_notes 中提到的 source 热点（第 3 行）实为注释，参数读取实际在第 4/7 行，且已被 switch 白名单严格约束。未发现任何满足 CVE 级别、链闭合的漏洞，按“宁可漏报不可误报”原则返回空结果。未覆盖范围：无部署配置（Web 服务器、PHP 版本、disable_functions）、无路由/端点清单、无依赖清单，无法评估该脚本在真实环境中的暴露方式；但这些缺口不影响本文件内部不存在可利用污点链的结论。

未覆盖 / 证据缺口：
- 缺少部署配置与 Web 服务器暴露方式，无法确认脚本实际访问路径与前置鉴权
- 无依赖清单（composer.json 等），无法评估第三方组件攻击面
- code_pack 仅含 1 个文件，其余项目文件未送入，无法确认是否存在其它入口

## 3. Findings

### F-1: AWVS: Cross-site Scripting (XSS)

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/049.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed unsafe DOM sink. baseline HTTP 200 (5092 bytes); attack HTTP 200 (5092 bytes); marker='DOM source/sink'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/049.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/049.php` | AWVS 报告 Cross-site Scripting (XSS) |  |  |

**POC**

AWVS 外部扫描报告在 http://127.0.0.1:18081/049.php 发现 Cross-site Scripting (XSS)（CWE-79）。本次输入只提供了 AWVS 回灌的请求骨架（GET /049.php），没有提供该页面的源码、参数名、DOM source/sink 位置或注入点字段，因此无法确认具体注入参数与触发路径。以下 POC 保留 AWVS 原始请求结构，并给出可复现的探测步骤；具体注入参数需补充源码/路由后确认。

1. **重放 AWVS 记录的请求**

```http
GET /049.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-ff307d817e12`
- 风险提示：POC 叙述未明确标注 source→sink 注入点
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed unsafe DOM sink. baseline HTTP 200 (5092 bytes); attack HTTP 200 (5092 bytes); marker='DOM source/sink'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-79；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：POC 仅为文本工件，不执行、不联网、不搭建沙箱。目标地址统一使用 TARGET 占位符。原始 AWVS 请求 GET /049.php 已保留；由于输入未提供 049.php 源码，注入参数名与 DOM source/sink 位置标注为“需补充源码/路由”，未伪造字段。若后续补齐源码，应按 getParameter("X")/getHeader("X")/location.hash 等真实读取点替换 <REAL_PARAM>。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `AWVS-ff307d817e12` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/049.php | external_only |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.94 | 是 |
| surface_mapper | 攻击面测绘 | 6.33 | 是 |
| deep_finder | LLM 深挖 | 4.47 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.19 | 是 |
| coordinator | 管线协调 | 7.92 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
