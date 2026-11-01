# 落日二号乙漏洞挖掘报告 — 20261031-011425-c3aa32

- 生成时间：2026-10-30T17:14:42.131615+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\005.zip`
- 输入模式：`zip`
- SHA256：`02b57ee8cd079a77373226c06268671c690fdb18ba56972177688c150bd72b4b`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总未收到任何已去重的 findings（findings 为空数组，type_counts 为空，with_poc=0），因此没有可交付的漏洞结论，也没有任何 POC（既无 HTTP POC，也无静态证据 POC）。覆盖统计显示仓库仅含 1 个 PHP 文件 005.php（11 行、160 字节），无框架、无端点清单、无 source/sink 热点、无隔离文件；更关键的是 code_pack 未提供 005.php 的实际代码内容，只有路径与元数据，因此本次只能完成范围测绘，无法做行号级源码审计。最高危项无法判定——不是因为确认安全，而是因为缺少代码证据。surface_notes 已列出 6 类需人工复核的候选（weak_hash、weak_crypto、weak_random、insecure_cookie、trust_boundary、hardcoded_secret），这些均未形成 findings，已转入 human_review，不得表述为“不存在”。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 005.php（11 行，160 字节），实际内容为一段 PHP 注释：第 2-9 行是块注释，第 1 行是 <?php，第 11 行是 ?>，中间没有任何可执行语句。文件中没有超全局变量读取（$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER）、没有 echo/print、没有 include/require、没有 system/exec/shell_exec、没有数据库调用、没有文件操作、没有反序列化、没有 md5/sha1/rand/setcookie 等配置类调用，因此不存在任何 source→sink 链路，也不存在可确认的配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary/hardcoded_secret 均无对应代码行）。注释文本（第 4-7 行）指向 dvwa/includes/dvwaPage.inc.php 的 dvwaHtmlEcho 函数，但该文件不在 code_pack 中，按零工具契约视为不存在，不能据此推断漏洞；该注释属于不可信数据，仅作为线索记录，不构成证据。surface_notes 中列出的 medium_review_items 全部是“需人工确认”的假设，没有任何代码行支撑，故不产出 finding。未发现 prompt_injection 诱导性指令。

未覆盖 / 证据缺口：
- 005.php 全部 11 行已完整审计，无未覆盖行
- 注释引用的 dvwa/includes/dvwaPage.inc.php 未包含在 code_pack 中，无法审计 dvwaHtmlEcho 函数
- 缺少端点/路由清单、Web 服务器配置、composer.json，无法判断外部可达性与依赖 CVE
- 无法确认 005.php 是否被其他文件 include 或作为 CLI 运行

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
| safety_guard | 安全防护 | 3.5 | 是 |
| surface_mapper | 攻击面测绘 | 5.64 | 是 |
| deep_finder | LLM 深挖 | 2.82 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.09 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
