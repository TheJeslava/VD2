# 落日二号乙漏洞挖掘报告 — 20261030-225119-2bca7b

- 生成时间：2026-10-30T14:51:36.371098+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\048.zip`
- 输入模式：`zip`
- SHA256：`7be45c1a53974d969c5fea706096bfd9b3d27604468af7e49423890e14859d57`
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

本次审计范围实质只有一个 PHP 文件 048.php（9 行、145 字节），属于片段级/最小示例代码。已去重的 findings 为空（type_counts 为空、with_poc=0），因此没有任何已确认漏洞，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。最高危项无法确定：048.php 被攻击面测绘标记为 source 热点（第 1 行），但 sink 热点为空，污点是否到达危险汇点无证据，不能据此判定无漏洞，也不能判定存在漏洞。整体结论是证据不足，需人工通读 048.php 全文后再定级。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 212 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 048.php（共 9 行，已完整展示）。该脚本仅在 POST 请求时以 time() 生成 dvwaSession Cookie 并通过 setcookie 下发，无任何请求参数读取（无 $_GET/$_POST/$_REQUEST/$_COOKIE 取值）、无输出拼接、无 include/require/eval/exec/file 等危险汇点，不存在可闭合的 source→sink 利用链。关于会话 Cookie 的弱随机性（time() 秒级可预测，CWE-330/CWE-340）与缺失 HttpOnly/Secure/SameSite 标志：本文件未展示任何基于 dvwaSession 的会话校验或鉴权逻辑，无法证明可导致会话预测/劫持的实际影响，且当前 policy 的 min_severity=high 下不足以单独立项，故仅作为线索记录于 coverage.gaps，不产出 finding。未发现 prompt_injection 诱导文本。

未覆盖 / 证据缺口：
- 048.php:6-7 使用 time() 作为会话 Cookie 值，属秒级可预测弱随机（CWE-330），但 code_pack 中无任何读取/校验 dvwaSession 的代码，无法闭合会话预测→身份冒用的利用链，需人工确认配套会话校验逻辑。
- setcookie 未设置 HttpOnly/Secure/SameSite（048.php:7），但缺少传输层与前端上下文证据，影响无法评估。
- 无端点清单、无配置文件、无依赖与 PHP 版本信息，无法确认实际暴露 URL、HTTP 方法与部署环境。
- code_pack 仅含 1 个文件，无调用方与其它源码可交叉验证，审计范围实质限于 048.php 全文。

## 3. Findings

未发现满足阈值的候选。

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
| `sql_injection` | CWE-89 | 是 | 0 |
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
| safety_guard | 安全防护 | 3.76 | 是 |
| surface_mapper | 攻击面测绘 | 4.64 | 是 |
| deep_finder | LLM 深挖 | 3.71 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.94 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
