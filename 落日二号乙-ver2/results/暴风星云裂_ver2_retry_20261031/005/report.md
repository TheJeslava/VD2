# 落日二号乙漏洞挖掘报告 — 20261031-001745-036814

- 生成时间：2026-10-30T16:18:05.328943+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\005.zip`
- 输入模式：`zip`
- SHA256：`02b57ee8cd079a77373226c06268671c690fdb18ba56972177688c150bd72b4b`
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

本次汇总未收到任何已去重的 findings（findings 为空数组，type_counts 为空，with_poc=0），因此没有可交付的漏洞结论，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仅 1 个文件（005.php，PHP，11 行约 160 字节），endpoints=0，无框架、无被隔离文件。攻击面测绘明确指出：输入只提供了文件清单与语言统计，未提供 005.php 的源码内容，因此无法确认任何 source/sink、参数名、SQL/文件/命令调用或加密逻辑；surface_notes 中的 priority_areas 与 medium_review_items 均为基于文件类型与体量的测绘假设，不构成证据。最高危项无法判定——不是因为确认无风险，而是因为缺少代码内容导致审计无法落地。POC 不齐全（0/0）。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 005.php（11 行），内容为一段 PHP 注释块：第 2-9 行是 /* ... */ 注释，第 1 行 <?php、第 11 行 ?>，注释文本指向 dvwa/includes/dvwaPage.inc.php 中的 dvwaHtmlEcho 函数。该文件不含任何可执行语句：没有 $_GET/$_POST/$_REQUEST 取值、没有 include/require、没有 SQL/文件/命令/模板/反序列化调用、没有 setcookie/session 配置、没有哈希或随机数调用。因此不存在可闭合的 source→sink 利用链，也没有配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary）的算法或标志位证据。注释中“Nothing to see here for this vulnerability, have a look instead at ...”属于不可信数据中的引导性文本，按规则仅作为数据记录，不改变审计结论；它指向的 dvwa/includes/dvwaPage.inc.php 不在 code_pack 内，按零工具契约视为不存在，无法审计。未闭合线索：若后续把 dvwaPage.inc.php 的 dvwaHtmlEcho 纳入 code_pack，应重点核查其输出拼接是否构成反射型/存储型 XSS。

未覆盖 / 证据缺口：
- 005.php 全部 11 行已审阅，无可执行代码，无 source/sink
- 注释指向的 dvwa/includes/dvwaPage.inc.php 未在 code_pack 中，按契约视为不存在，未审计
- 无端点清单、无 Web 服务器/php.ini 配置、无依赖清单，无法评估部署层利用条件

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
| safety_guard | 安全防护 | 2.94 | 是 |
| surface_mapper | 攻击面测绘 | 8.15 | 是 |
| deep_finder | LLM 深挖 | 3.69 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.46 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
