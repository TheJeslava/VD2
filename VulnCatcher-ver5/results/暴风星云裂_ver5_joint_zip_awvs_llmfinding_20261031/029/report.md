# 落日二号乙漏洞挖掘报告 — 20261031-214557-c411ae

- 生成时间：2026-10-31T13:46:25.867020+00:00
- 输入：`$WORKSPACE\暴风星云裂\029.zip`
- 输入模式：`zip`
- SHA256：`9e8e31208f33c79ace21df8e9eb6797c2b16fced272a55592f6c0fe21cce86fa`
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

本次汇总仅含 1 条已去重 finding：AWVS 外部证据命中的 path_traversal（高危，finding_id=AWVS-7c46a9703b5e），带 POC，属外部扫描器证据而非源码审计确认。最高危即该条路径穿越。源码侧覆盖极弱：项目为单文件 PHP 脚本 029.php（6 行、73 字节），管线未提供代码正文，sink_hot_files 为空，仅标记第 1 行为 source 热点，因此无法在源码层确认 source→sink 链路、参数名与行号，也无法判断该 path_traversal 的具体触发点。POC 齐全度：1/1 条 finding 有 POC，但该 POC 为外部 AWVS 证据，未做动态验证，不能宣称已复现。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 125 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 029.php（共 6 行，已全量展示）。该文件仅从 $_GET['page'] 读取参数并赋值给 $file（第 4 行），随后脚本结束（第 6 行 ?>），CODE PACK 中不存在任何 include/require、file_get_contents、fopen、echo/print 等 sink，也不存在后续使用 $file 的代码。因此 source→sink 链路在给定代码内不闭合：无法确认文件包含、路径穿越或反射型 XSS 的实际危险操作。surface_notes 中提到的 include/路径拼接/输出回显均为方向性推测，缺少代码证据，按零容忍误报原则不产出 finding。若完整文件确实只有这 6 行，则该脚本本身不构成可利用漏洞；若真实部署版本在 ?> 之后或通过其他被省略的包含文件继续使用 $file，则需补充该部分源码后再评估 LFI/path_traversal。

未覆盖 / 证据缺口：
- CODE PACK 中 029.php 仅 6 行且无 sink，$file 变量未被任何危险函数使用，无法闭合利用链
- 无端点清单、无部署配置（php.ini、allow_url_include、open_basedir），无法评估运行时文件包含风险
- 无 composer.json 等依赖清单，未评估第三方组件
- 若存在被省略的后续代码或其他包含文件，需补充后重新审计

## 3. Findings

### F-1: AWVS: Path Traversal

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/029.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed path traversal response. baseline HTTP 200 (5188 bytes); attack HTTP 200 (4726 bytes); marker='/tmp/sunset_probe'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/029.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/029.php` | AWVS 报告 Path Traversal |  |  |

**POC**

AWVS 外部扫描报告在 http://127.0.0.1:18081/029.php 观察到路径穿越（Path Traversal，CWE-22）迹象：基线请求返回 HTTP 200（5188 字节），带穿越探测的请求返回 HTTP 200（4726 字节），探测标记为 '/tmp/sunset_probe'。本管线未执行该请求，也未获得 029.php 源码，因此无法确认具体参数名、注入通道（参数/请求头/Cookie）与文件读取汇点；以下 POC 仅保留 AWVS 记录的请求结构并补充复现说明，参数名需由源码补齐。

1. **重放 AWVS 记录的请求**

```http
GET /029.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-7c46a9703b5e`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed path traversal response. baseline HTTP 200 (5188 bytes); attack HTTP 200 (4726 bytes); marker='/tmp/sunset_probe'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-22；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：保留 AWVS 原始请求结构（GET /029.php，Host: TARGET）。未执行、未联网、未搭建沙箱。请求中的 <PATH_FIELD> 为待源码补齐的占位说明，不是可发送的真实字段；在补齐源码前不得将步骤 2/3 视为可复现 POC。目标地址统一使用 TARGET 占位符。

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
| `AWVS-7c46a9703b5e` | Path Traversal | http://127.0.0.1:18081/029.php | external_only |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 1 |
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
| safety_guard | 安全防护 | 4.17 | 是 |
| surface_mapper | 攻击面测绘 | 5.52 | 是 |
| deep_finder | LLM 深挖 | 3.77 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.78 | 是 |
| coordinator | 管线协调 | 6.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
