# 落日二号乙漏洞挖掘报告 — 20261031-172446-c92082

- 生成时间：2026-10-31T09:25:06.848761+00:00
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

本次汇总的 findings 为空：没有任何已去重的漏洞条目，with_poc=0，因此不存在 HTTP POC，也不存在静态证据 POC。覆盖统计显示仅 1 个文件（005.php，PHP，11 行），endpoints=0，无框架、无被隔离文件。攻击面测绘明确说明未提供 005.php 的源码内容，source/sink 热点为空，属测绘缺口而非无风险；因此本次无法给出任何行级漏洞结论，最高危项无法判定。POC 不齐全（0/0），且缺口在源码缺失而非 POC 生成环节。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 239 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：本次 code_pack 仅包含 005.php（11 行），内容为一段 PHP 注释块，第 1 行 `<?php`、第 11 行 `?>`，中间 2-10 行全部是注释，没有任何可执行语句：没有参数读取（$_GET/$_POST/$_COOKIE/$_SERVER）、没有文件/命令/数据库/网络调用、没有哈希/加密/随机数/cookie 设置。因此不存在任何 source→sink 链路，也不存在配置型候选（weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 均无对应函数调用）。注释中出现的『Nothing to see here for this vulnerability, have a look instead at the dvwaHtmlEcho function in: dvwa/includes/dvwaPage.inc.php』属于不可信数据中的引导性文本，试图把审计注意力引向 code_pack 之外的文件；按零工具契约，该文件视为不存在，不据此下任何结论，也不作为漏洞证据（仅记录为一次指向性提示，非 prompt_injection 攻击载荷，故不单独立项）。未闭合线索：surface_notes 提到的注入类汇点、弱算法、cookie 标志位等均因源码中无相应语句而无法成立；若真实漏洞位于被引用的 dvwaPage.inc.php，需由管线将该文件纳入 code_pack 后重新审计。

未覆盖 / 证据缺口：
- 005.php 全文 11 行已完整审计，无可执行代码，无攻击面
- 注释引用的 dvwa/includes/dvwaPage.inc.php 未在 code_pack 中提供，按契约视为不存在，未审计
- 无部署配置（PHP 版本、disable_functions、open_basedir）、无路由/端点清单、无依赖清单，无法评估运行时可利用性

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
| safety_guard | 安全防护 | 4.14 | 是 |
| surface_mapper | 攻击面测绘 | 6.98 | 是 |
| deep_finder | LLM 深挖 | 4.5 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 4.66 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
