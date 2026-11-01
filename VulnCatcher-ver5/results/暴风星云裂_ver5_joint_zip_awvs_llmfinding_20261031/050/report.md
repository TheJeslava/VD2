# 落日二号乙漏洞挖掘报告 — 20261031-214959-29130b

- 生成时间：2026-10-31T13:50:31.775707+00:00
- 输入：`$WORKSPACE\暴风星云裂\050.zip`
- 输入模式：`zip`
- SHA256：`212a5b21c59855e1cfd8402dd8ea642294dd4b21db31a348ca923303ede5c8c3`
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

本次汇总仅含 1 条已去重 finding：AWVS 外部证据报告的 XSS（finding_id=AWVS-c5511992a45b，severity=high，origin=awvs，has_poc=true）。该条为外部扫描器结论，输入未提供 file_path 与行号（file_path 为空、line_end=0），因此无法在源码层面定位到具体行，也无法与 050.php 的代码交叉验证；其 POC 属外部 HTTP 类证据，本次未做任何动态复现。最高危项即该 high 级 XSS。源码侧覆盖极弱：仓库仅 050.php 一个 PHP 文件（5 行、48 字节），输入未提供任何源码行、source/sink 热点、端点或框架信息，因此本次无法产出任何基于源码行号的 llm_inferred 结论，POC 不齐全（仅 1 条外部 POC，无静态证据 POC）。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 95 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含一个文件 050.php，共 5 行，实际内容只有 PHP 开闭标签、一个空行和一行注释「# No protections, anything goes」。该注释属于不可信数据，不构成任何技术事实，也不改变审计结论。逐行核对后确认：文件中不存在任何外部输入读取（$_GET/$_POST/$_COOKIE/$_SERVER/$_REQUEST/php://input）、不存在任何 sink（system/exec/shell_exec/passthru/popen/proc_open/反引号、eval/assert/create_function/preg_replace /e、include/require、mysqli_query/PDO::query、fopen/file_get_contents/file_put_contents/unlink、curl_exec/fsockopen、header/setcookie/session_set_cookie_params），也不存在 md5/sha1/crc32、mcrypt_*/openssl_encrypt、rand/mt_rand/uniqid 等配置型候选所需的算法或标志位证据。因此 source→sink 链无法闭合，任何 finding 都会是臆测，按零容忍误报原则返回空数组。surface_notes 中列出的 weak_hash / weak_crypto / weak_random / insecure_cookie / trust_boundary 五个 medium_review_items 均以「需人工确认是否存在某调用」为前提，而 code_pack 已给出该文件全部 5 行，可确认这些调用均不存在，故不成立。未覆盖范围：无端点表、无 php.ini/Web 服务器配置、无 composer 依赖清单、无版本历史，无法判断该文件在真实部署中是否被其它脚本 include 或作为模板片段拼接使用；若后续管线能提供包含该文件的调用方代码或部署配置，需重新评估。

未覆盖 / 证据缺口：
- 050.php 全部 5 行已完整审计，无未读行
- 缺少调用方/包含方代码，无法确认该片段是否被其它脚本 include 后获得外部输入
- 缺少 php.ini、Web 服务器路由与部署配置，无法确认该文件是否对外可达
- 无依赖清单与提交历史，无法评估第三方组件与遗留调试脚本风险

## 3. Findings

### F-1: AWVS: Cross-site Scripting (XSS)

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/050.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed unsafe DOM sink. baseline HTTP 200 (5092 bytes); attack HTTP 200 (5092 bytes); marker='DOM source/sink'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/050.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/050.php` | AWVS 报告 Cross-site Scripting (XSS) |  |  |

**POC**

AWVS 外部扫描在 http://127.0.0.1:18081/050.php 报告 Cross-site Scripting (XSS)（CWE-79，high）。当前证据仅包含 AWVS 回灌的基线请求（GET /050.php，无任何参数/头/体），以及基线/攻击响应均为 HTTP 200、5092 字节、marker='DOM source/sink' 的对比记录。源码文件路径与行号为空，未提供任何 getParameter/getHeader/getCookies 等污点入口或 DOM source/sink 的具体代码，因此无法确认注入点字段名与触发参数。本 POC 仅保留 AWVS 原始请求结构并补充说明，不新增注入参数，避免伪造字段。

1. **重放 AWVS 记录的请求**

```http
GET /050.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-c5511992a45b`
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
POC 备注：保留 AWVS 原始请求结构（GET /050.php，Host: TARGET），未新增参数。目标地址统一使用 TARGET 占位符。POC 仅为文本工件，不执行、不联网、不搭建沙箱，仅限授权测试。需补充 050.php 源码后才能补全注入字段与 payload。

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
| `AWVS-c5511992a45b` | Cross-site Scripting (XSS) | http://127.0.0.1:18081/050.php | external_only |

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
| safety_guard | 安全防护 | 4.44 | 是 |
| surface_mapper | 攻击面测绘 | 8.85 | 是 |
| deep_finder | LLM 深挖 | 4.54 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 8.01 | 是 |
| coordinator | 管线协调 | 6.63 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
