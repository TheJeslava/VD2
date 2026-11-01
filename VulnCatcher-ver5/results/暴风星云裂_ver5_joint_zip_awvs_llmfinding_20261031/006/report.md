# 落日二号乙漏洞挖掘报告 — 20261031-214028-a3adb5

- 生成时间：2026-10-31T13:40:59.099627+00:00
- 输入：`$WORKSPACE\暴风星云裂\006.zip`
- 输入模式：`zip`
- SHA256：`aa7e574db02480da83ab6d50b22ba2a55070da964e165c1e99e0e0f5a60fccd3`
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

本次输入仅包含 1 个 PHP 文件（006.php，18 行 / 346 字节），无端点清单、无 source/sink 标注、无框架与依赖信息。去重后仅 1 条 finding：AWVS-394e02cac5b9（auth_bypass，critical，origin=awvs，带 POC），是本次唯一且最高危的结论；该结论来自外部 AWVS 证据，未在本次源码审计中由静态证据独立确认。POC 齐全度为 1/1（仅此一条），但属于外部扫描器产出的 HTTP 类 POC，本次未做任何动态验证。源码侧未产出任何 llm_inferred 级注入类结论，原因是文件过小且无污点标注，属覆盖不足而非已排除。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 460 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个 18 行 PHP 文件 006.php（DVWA 的 authbypass 示例页）。已通读全部 18 行：文件只做一件事——调用 dvwaCurrentUser() 与字符串 "admin" 比较，不等则打印 Unauthorised、返回 403 并 exit；通过后直接结束 PHP 块，没有任何请求参数读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、没有 SQL/文件/命令/模板/反序列化 sink、没有输出拼接、没有 md5/sha1/rand/setcookie/session 配置。注释中提到的 vulnerabilities/authbypass/get_user_data.php 与 change_user_details.php 不在 code_pack 内，按契约视为不存在，无法审计其鉴权逻辑，因此本文件本身不构成可闭合的 source→sink 利用链。dvwaCurrentUser() 的实现未在 code_pack 中给出，无法判断其是否可被伪造（例如依赖客户端 Cookie 判定身份），这是唯一未闭合的线索，但缺少实现证据，不足以申报。

未覆盖 / 证据缺口：
- dvwaCurrentUser() 的定义不在 code_pack 中，无法确认身份判定是否信任客户端可控数据（Cookie/Header），因此 auth_bypass 线索无法闭合
- 注释引用的 get_user_data.php、change_user_details.php 未提供，无法审计其参数处理与鉴权
- 无路由/部署配置，无法确认该脚本的外部可达性与调用前置条件
- 无数据库、上传目录、模板等外部资源信息，注入/SSRF/文件类面无法评估

## 3. Findings

### F-1: AWVS: Authentication Bypass

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`critical`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/006.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/006.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/006.php` | AWVS 报告 Authentication Bypass |  |  |

**POC**

AWVS 外部扫描报告在 GET /006.php 上观察到认证绕过（CWE-287）：未携带任何认证凭据的请求返回 HTTP 200（4413 字节），响应中出现标记 'admin'，与基线响应一致，说明该页面在未认证状态下直接返回了特权内容。本 POC 为文本工件，仅用于授权测试环境复现该响应差异，未执行、未联网。

1. **重放 AWVS 记录的请求**

```http
GET /006.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-394e02cac5b9`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-287；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：保留 AWVS 原始请求结构（GET /006.php，Host 使用 TARGET 占位符）。补充了基线/攻击/状态确认三步对比逻辑与预期响应判据。未生成任何可自动执行的脚本；所有请求仅为文本，需人工在授权环境重放。若后续提供 /006.php 源码，应据实补充鉴权字段（如具体 Cookie 名或 Authorization 头）并修正前置条件。

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
| `AWVS-394e02cac5b9` | Authentication Bypass | http://127.0.0.1:18081/006.php | external_only |

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
| safety_guard | 安全防护 | 5.11 | 是 |
| surface_mapper | 攻击面测绘 | 8.0 | 是 |
| deep_finder | LLM 深挖 | 3.81 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.23 | 是 |
| coordinator | 管线协调 | 6.61 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
