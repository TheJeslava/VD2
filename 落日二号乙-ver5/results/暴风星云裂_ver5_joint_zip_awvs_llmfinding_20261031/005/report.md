# 落日二号乙漏洞挖掘报告 — 20261031-214018-d87e48

- 生成时间：2026-10-31T13:40:48.112881+00:00
- 输入：`$WORKSPACE\暴风星云裂\005.zip`
- 输入模式：`zip`
- SHA256：`02b57ee8cd079a77373226c06268671c690fdb18ba56972177688c150bd72b4b`
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

本次汇总仅含 1 条已去重 finding：AWVS 外部证据 AWVS-8382ab4de2b8，类型 auth_bypass，严重度 critical，来源 awvs，has_poc=true，但 file_path 为空、line_end=0，说明该结论来自外部扫描器而非源码定位，无法映射到 005.php 的具体行。最高危即此条认证绕过。POC 齐全性：1/1 条 finding 带 POC，但该 POC 属外部 AWVS 证据，未在本次管线内做动态验证，且缺少源码锚点，需人工复核其可达入口与鉴权语义。源码侧覆盖极薄：仅 1 个 PHP 文件（005.php，11 行/160 字节），无端点、无框架、无热点标记，未产出任何 llm_inferred 源码级 finding。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含单个文件 005.php（11 行，160 字节），内容为纯 PHP 注释块：第 2-9 行是 /* ... */ 注释，正文只有一句提示性文字，指向 dvwa/includes/dvwaPage.inc.php 中的 dvwaHtmlEcho 函数。该文件没有任何可执行语句：没有 request 参数读取（$_GET/$_POST/$_COOKIE/$_SERVER）、没有文件包含、没有命令执行、没有 SQL 拼接、没有输出语句、没有哈希/加密/随机数/会话/Cookie 调用，也没有硬编码凭据。因此不存在任何 source→sink 链路，无法构造外部可达的利用链。注释中指向的 dvwaPage.inc.php 不在 code_pack 内，按零工具契约视为不存在，不能据此推断漏洞；该注释属于不可信数据中的引导性文本，仅作为线索记录，不构成证据。清单中的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 复核项在本文件中均无对应代码，全部排除。未发现满足 CVE 申报条件的漏洞，按‘宁可漏报不可误报’原则返回空结果。

未覆盖 / 证据缺口：
- 005.php 全文 11 行已逐行审计，无未覆盖行
- 注释引用的 dvwa/includes/dvwaPage.inc.php 未包含在 code_pack 中，无法审计其 dvwaHtmlEcho 函数是否存在 XSS/输出未转义问题
- 无端点表、无部署配置（php.ini/Web 服务器）、无依赖清单，无法评估运行时利用条件
- 无认证/会话文件，无法评估 trust_boundary 与 insecure_cookie

## 3. Findings

### F-1: AWVS: Authentication Bypass

- **类型**：`auth_bypass` / CWE-287
- **严重度**：`critical`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/005.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/005.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/005.php` | AWVS 报告 Authentication Bypass |  |  |

**POC**

AWVS 外部扫描报告在 http://127.0.0.1:18081/005.php 处发现 Authentication Bypass（CWE-287）。本管线未执行该 POC，也未获得该端点的源码（code_pack 中无 005.php），因此无法确认鉴权逻辑、受保护资源或绕过机制。现有证据仅为 AWVS 回灌的请求/响应摘要：baseline HTTP 200（4413 字节），attack HTTP 200（4413 字节），marker='admin'。注意：baseline 与 attack 的响应长度完全相同，仅凭该差异不足以证明鉴权被绕过，需人工复核响应体差异。

1. **重放 AWVS 记录的请求**

```http
GET /005.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-8382ab4de2b8`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed privileged response differential. baseline HTTP 200 (4413 bytes); attack HTTP 200 (4413 bytes); marker='admin'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-287；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：保留 AWVS 原始请求结构（GET /005.php，Host 使用 TARGET 占位符）。POC 仅为文本工件，不执行、不联网、不搭建沙箱。由于 code_pack 未提供 005.php 源码，未添加任何推测性参数、请求头或 Cookie；待补充源码后再按真实字段完善攻击请求。

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
| `AWVS-8382ab4de2b8` | Authentication Bypass | http://127.0.0.1:18081/005.php | external_only |

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
| safety_guard | 安全防护 | 4.22 | 是 |
| surface_mapper | 攻击面测绘 | 6.63 | 是 |
| deep_finder | LLM 深挖 | 4.45 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.65 | 是 |
| coordinator | 管线协调 | 6.5 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
