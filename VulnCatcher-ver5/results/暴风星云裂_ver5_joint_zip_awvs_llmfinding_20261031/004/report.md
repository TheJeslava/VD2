# 落日二号乙漏洞挖掘报告 — 20261031-213946-36b2d2

- 生成时间：2026-10-31T13:40:16.425200+00:00
- 输入：`$WORKSPACE\暴风星云裂\004.zip`
- 输入模式：`zip`
- SHA256：`b9fab202b9a48529e59fc3b093ab407f0b2c3c52e487f6da9dfafce8e36fbfc5`
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

本次汇总仅含 1 条已去重 finding：AWVS 外部证据报告的 auth_bypass（Authentication Bypass），严重度 critical，带 POC（外部 AWVS 证据，非本次静态审计产出）。该 finding 未给出 file_path 与行号，无法与仓库内 004.php 的具体代码行对应，因此其代码级根因仍属未确认。仓库为单文件 PHP 脚本 004.php（17 行、292 字节），本次输入未提供该文件源码内容，覆盖统计为 files=1、endpoints=0、无框架、无隔离文件，故无法做行级污点审计。最高危项即上述 critical 认证绕过。POC 齐全性：1/1 finding 标记 has_poc=true，但属外部 AWVS 证据，本次未做任何动态验证，不能宣称可复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 401 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个文件 004.php（17 行），已逐行审计。该文件内容为：第 12 行调用 dvwaCurrentUser() 与字符串 "admin" 比较，不相等时第 13 行 print "Unauthorised"、第 14 行 http_response_code(403)、第 15 行 exit。文件中不存在任何外部输入读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、无 SQL/命令/文件/反序列化/模板 sink、无输出到 HTML 的用户数据、无 md5/sha1/rand/setcookie/session 等配置型构造，因此不存在可闭合的 source→sink 利用链，也没有可成立的配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie 均无对应代码证据）。第 2-10 行注释提到 vulnerabilities/authbypass/change_user_details.php，但该文件不在 code_pack 中，按契约视为不存在，不能据此推断漏洞；注释本身属不可信数据，仅作线索记录。dvwaCurrentUser() 的实现未在 code_pack 中提供，无法判断其是否可被伪造（例如是否依赖客户端可控 Cookie/Session），这是唯一未闭合的线索，但缺少实现代码，不能作为 finding 上报。本次输入未出现诱导性指令文本，无 prompt_injection 证据。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的定义未在 code_pack 中，无法确认其身份判定是否可被客户端伪造（潜在 auth_bypass 线索，证据不足）
- 注释引用的 vulnerabilities/authbypass/change_user_details.php 未提供，无法审计
- 无路由/端点清单与部署配置，无法确认该脚本的 HTTP 可达性与认证前置条件

## 3. Findings

### F-1: AWVS: Authentication Bypass

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`critical`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/004.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/004.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/004.php` | AWVS 报告 Authentication Bypass |  |  |

**POC**

AWVS 外部扫描报告在 http://127.0.0.1:18081/004.php 处发现 Authentication Bypass（CWE-287）。本管线未执行该 POC，也未获得该端点的源码（code_pack 中无 004.php），因此无法确认认证逻辑、受保护资源或绕过机制。现有证据仅为 AWVS 回灌的请求与响应差异描述：baseline 与 attack 均为 HTTP 200、4413 字节，marker='admin'。该差异本身不足以证明存在认证绕过，需人工复核响应体差异。

1. **重放 AWVS 记录的请求**

```http
GET /004.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-fa4c4503c3b8`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-287；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：保留 AWVS 原始请求结构，目标统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网、不搭建沙箱。当前记录中 baseline 与 attack 请求一致，需补充 AWVS 实际攻击变体后方可作为有效复现步骤；在补充前不得将本项结论写成已验证漏洞。

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
| `AWVS-fa4c4503c3b8` | Authentication Bypass | http://127.0.0.1:18081/004.php | external_only |

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
| `auth_bypass` | CWE-287 | 是 | 1 |
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
| safety_guard | 安全防护 | 3.79 | 是 |
| surface_mapper | 攻击面测绘 | 8.34 | 是 |
| deep_finder | LLM 深挖 | 4.03 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 6.67 | 是 |
| coordinator | 管线协调 | 6.89 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
